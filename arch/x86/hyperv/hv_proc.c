// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/clockchips.h>
#include <linux/hyperv.h>
#include <linux/slab.h>
#include <linux/cpuhotplug.h>
#include <linux/minmax.h>
#include <asm/hypervisor.h>
#include <asm/mshyperv.h>
#include <asm/apic.h>

#include <asm/trace/hyperv.h>

int hv_status_to_errno(u64 hv_status)
{
	switch (hv_result(hv_status)) {
	case HV_STATUS_SUCCESS:
		return 0;
	case HV_STATUS_INVALID_PARAMETER:
	case HV_STATUS_UNKNOWN_PROPERTY:
	case HV_STATUS_PROPERTY_VALUE_OUT_OF_RANGE:
	case HV_STATUS_INVALID_VP_INDEX:
	case HV_STATUS_INVALID_REGISTER_VALUE:
	case HV_STATUS_INVALID_LP_INDEX:
		return -EINVAL;
	case HV_STATUS_ACCESS_DENIED:
	case HV_STATUS_OPERATION_DENIED:
		return -EACCES;
	case HV_STATUS_NOT_ACKNOWLEDGED:
	case HV_STATUS_INVALID_VP_STATE:
	case HV_STATUS_INVALID_PARTITION_STATE:
		return -EBADFD;
	}
	return -ENOTRECOVERABLE;
}
EXPORT_SYMBOL_GPL(hv_status_to_errno);

const char *hv_status_to_string(u64 hv_status)
{
	switch (hv_result(hv_status)) {
	__HV_STATUS_DEF(__HV_MAKE_HV_STATUS_CASE)
	default : return "Unknown";
	}
}
EXPORT_SYMBOL_GPL(hv_status_to_string);

/*
 * See struct hv_deposit_memory. The first u64 is partition ID, the rest
 * are GPAs.
 */
#define HV_DEPOSIT_MAX (HV_HYP_PAGE_SIZE / sizeof(u64) - 1)

/* Deposits exact number of pages. Must be called with interrupts enabled.  */
int hv_call_deposit_pages(int node, u64 partition_id, u32 num_pages)
{
	struct page **pages, *page;
	int *counts;
	int num_allocations;
	int i, j, page_count;
	int order;
	u64 status;
	int ret;
	u64 base_pfn;
	struct hv_deposit_memory *input_page;
	unsigned long flags;

	if (num_pages > HV_DEPOSIT_MAX)
		return -E2BIG;
	if (!num_pages)
		return 0;

	/* One buffer for page pointers and counts */
	page = alloc_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;
	pages = page_address(page);

	counts = kcalloc(HV_DEPOSIT_MAX, sizeof(int), GFP_KERNEL);
	if (!counts) {
		free_page((unsigned long)pages);
		return -ENOMEM;
	}

	/* Allocate all the pages before disabling interrupts */
	i = 0;

	while (num_pages) {
		/* Find highest order we can actually allocate */
		order = 31 - __builtin_clz(num_pages);

		while (1) {
			pages[i] = alloc_pages_node(node, GFP_KERNEL, order);
			if (pages[i])
				break;
			if (!order) {
				ret = -ENOMEM;
				num_allocations = i;
				goto err_free_allocations;
			}
			--order;
		}

		split_page(pages[i], order);
		counts[i] = 1 << order;
		num_pages -= counts[i];
		i++;
	}
	num_allocations = i;

	local_irq_save(flags);

	input_page = *this_cpu_ptr(hyperv_pcpu_input_arg);

	input_page->partition_id = partition_id;

	/* Populate gpa_page_list - these will fit on the input page */
	for (i = 0, page_count = 0; i < num_allocations; ++i) {
		base_pfn = page_to_pfn(pages[i]);
		for (j = 0; j < counts[i]; ++j, ++page_count)
			input_page->gpa_page_list[page_count] = base_pfn + j;
	}
	status = hv_do_rep_hypercall(HVCALL_DEPOSIT_MEMORY,
				     page_count, 0, input_page, NULL);
	local_irq_restore(flags);
	if (!hv_result_success(status)) {
		pr_err("Failed to deposit pages: %s\n", hv_status_to_string(status));
		ret = hv_status_to_errno(status);
		goto err_free_allocations;
	}

	ret = 0;
	goto free_buf;

err_free_allocations:
	for (i = 0; i < num_allocations; ++i) {
		base_pfn = page_to_pfn(pages[i]);
		for (j = 0; j < counts[i]; ++j)
			__free_page(pfn_to_page(base_pfn + j));
	}

free_buf:
	free_page((unsigned long)pages);
	kfree(counts);
	return ret;
}
EXPORT_SYMBOL_GPL(hv_call_deposit_pages);

int hv_call_add_logical_proc(int node, u32 lp_index, u32 apic_id)
{
	struct hv_add_logical_processor_in *input;
	struct hv_add_logical_processor_out *output;
	u64 status;
	unsigned long flags;
	int ret = HV_STATUS_SUCCESS;

	/*
	 * When adding a logical processor, the hypervisor may return
	 * HV_STATUS_INSUFFICIENT_MEMORY. When that happens, we deposit more
	 * pages and retry.
	 */
	do {
		local_irq_save(flags);

		input = *this_cpu_ptr(hyperv_pcpu_input_arg);
		/* We don't do anything with the output right now */
		output = *this_cpu_ptr(hyperv_pcpu_output_arg);

		input->lp_index = lp_index;
		input->apic_id = apic_id;
		input->flags = 0;
		input->proximity_domain_info =
			numa_node_to_proximity_domain_info(node);
		status = hv_do_hypercall(HVCALL_ADD_LOGICAL_PROCESSOR,
					 input, output);
		local_irq_restore(flags);

		if (hv_result(status) != HV_STATUS_INSUFFICIENT_MEMORY) {
			if (!hv_result_success(status)) {
				pr_err("%s: cpu %u apic ID %u, %s\n", __func__,
				       lp_index, apic_id, hv_status_to_string(status));
				ret = hv_status_to_errno(status);
			}
			break;
		}
		ret = hv_call_deposit_pages(node, hv_current_partition_id, 1);
	} while (!ret);

	return ret;
}

int hv_call_create_vp(int node, u64 partition_id, u32 vp_index, u32 flags)
{
	struct hv_create_vp *input;
	u64 status;
	unsigned long irq_flags;
	int ret = HV_STATUS_SUCCESS;

	/* Root VPs don't seem to need pages deposited */
	if (partition_id != hv_current_partition_id) {
		/* The value 90 is empirically determined. It may change. */
		ret = hv_call_deposit_pages(node, partition_id, 90);
		if (ret)
			return ret;
	}

	do {
		local_irq_save(irq_flags);

		input = *this_cpu_ptr(hyperv_pcpu_input_arg);

		input->partition_id = partition_id;
		input->vp_index = vp_index;
		input->flags = flags;
		input->subnode_type = HvSubnodeAny;
		input->proximity_domain_info =
			numa_node_to_proximity_domain_info(node);
		status = hv_do_hypercall(HVCALL_CREATE_VP, input, NULL);
		local_irq_restore(irq_flags);

		if (hv_result(status) != HV_STATUS_INSUFFICIENT_MEMORY) {
			if (!hv_result_success(status)) {
				pr_err("%s: vcpu %u, lp %u, %s\n", __func__,
				       vp_index, flags, hv_status_to_string(status));
				ret = hv_status_to_errno(status);
			}
			break;
		}
		ret = hv_call_deposit_pages(node, partition_id, 1);

	} while (!ret);

	return ret;
}
EXPORT_SYMBOL_GPL(hv_call_create_vp);

static char log_buf[PAGE_SIZE] __aligned(PAGE_SIZE);
#define LOG_CACHE_SIZE (5 * PAGE_SIZE)
static char log_cache[LOG_CACHE_SIZE] __aligned(PAGE_SIZE);
static size_t num_chars_cached = 0;
void hv_log(char *buf, size_t size)
{
	u16 completed;
	u64 hypercall_status;
	int status;
	int i;

	// If the hypercall page has not been setup yet, then
	// we cannot issue the hypercall. Just cache the messages
	// for now.
	if (!hv_hypercall_pg) {
		size_t bytes_avail = LOG_CACHE_SIZE - num_chars_cached;
		size_t copy_bytes;

		copy_bytes = min(size, bytes_avail);

		// If there is not enough space in the cache,
		// not much we can do. Bail out.
		if (copy_bytes == 0)
			return;
		memcpy(&log_cache[num_chars_cached], buf, copy_bytes);
		num_chars_cached += copy_bytes;
		return;
	}

	// Data in the cache, flush it now.
	if (num_chars_cached) {
		for (i = 0; i < num_chars_cached; i++) {
			log_buf[0] = log_cache[i];
			hypercall_status = hv_do_rep_hypercall(
				HVCALL_OUTPUT_DEBUG_CHAR, 0, 0, log_buf, NULL);
			completed = (hypercall_status & HV_HYPERCALL_REP_COMP_MASK) >>
				     HV_HYPERCALL_REP_COMP_OFFSET;
			status = hypercall_status & HV_HYPERCALL_RESULT_MASK;
		}
		num_chars_cached = 0;
	}

	for (i = 0; i < size; i++) {
		log_buf[0] = buf[i];
		hypercall_status = hv_do_rep_hypercall(
			HVCALL_OUTPUT_DEBUG_CHAR, 0, 0, log_buf, NULL);
		completed = (hypercall_status & HV_HYPERCALL_REP_COMP_MASK) >>
			     HV_HYPERCALL_REP_COMP_OFFSET;
		status = hypercall_status & HV_HYPERCALL_RESULT_MASK;

		// cannot do anything here on error.
		//if (status != HV_STATUS_SUCCESS) {
	}
}
EXPORT_SYMBOL_GPL(hv_log);

