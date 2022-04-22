// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021, Microsoft Corporation.
 *
 * Authors:
 *   Nuno Das Neves <nudasnev@microsoft.com>
 *   Lillian Grassin-Drake <ligrassi@microsoft.com>
 *   Vineeth Pillai <viremana@linux.microsoft.com>
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/hyperv.h>
#include <asm/mshyperv.h>

#include "mshv.h"

int hv_call_withdraw_memory(u64 count, int node, u64 partition_id)
{
	struct hv_withdraw_memory_in *input_page;
	struct hv_withdraw_memory_out *output_page;
	struct page *page;
	u16 completed;
	unsigned long remaining = count;
	u64 status;
	int i;
	unsigned long flags;

	page = alloc_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;
	output_page = page_address(page);

	while (remaining) {
		local_irq_save(flags);

		input_page = (struct hv_withdraw_memory_in *)(*this_cpu_ptr(
			hyperv_pcpu_input_arg));

		input_page->partition_id = partition_id;
		input_page->proximity_domain_info.as_uint64 = 0;
		status = hv_do_rep_hypercall(
			HVCALL_WITHDRAW_MEMORY,
			min(remaining, HV_WITHDRAW_BATCH_SIZE), 0, input_page,
			output_page);

		local_irq_restore(flags);

		completed = hv_repcomp(status);

		for (i = 0; i < completed; i++)
			__free_page(pfn_to_page(output_page->gpa_page_list[i]));

		if (!hv_result_success(status)) {
			if (hv_result(status) == HV_STATUS_NO_RESOURCES)
				status = HV_STATUS_SUCCESS;
			else
				pr_err("%s: %s\n", __func__,
				       hv_status_to_string(status));
			break;
		}

		remaining -= completed;
	}
	free_page((unsigned long)output_page);

	return hv_status_to_errno(status);
}


int hv_call_create_partition(
		u64 flags,
		struct hv_partition_creation_properties creation_properties,
		u64 *partition_id)
{
	struct hv_create_partition_in *input;
	struct hv_create_partition_out *output;
	u64 status;
	int ret;
	unsigned long irq_flags;
	int i;

	do {
		local_irq_save(irq_flags);
		input = (struct hv_create_partition_in *)(*this_cpu_ptr(
			hyperv_pcpu_input_arg));
		output = (struct hv_create_partition_out *)(*this_cpu_ptr(
			hyperv_pcpu_output_arg));

		input->flags = flags;
		input->proximity_domain_info.as_uint64 = 0;
		input->compatibility_version = HV_COMPATIBILITY_20_H1;
		for (i = 0; i < HV_PARTITION_PROCESSOR_FEATURE_BANKS; ++i)
			input->partition_creation_properties
				.disabled_processor_features.as_uint64[i] = 0;
		input->partition_creation_properties
			.disabled_processor_xsave_features.as_uint64 = 0;
		input->isolation_properties.as_uint64 = 0;

		status = hv_do_hypercall(HVCALL_CREATE_PARTITION,
					 input, output);

		if (hv_result(status) != HV_STATUS_INSUFFICIENT_MEMORY) {
			if (hv_result_success(status))
				*partition_id = output->partition_id;
			else
				pr_err("%s: %s\n",
				       __func__, hv_status_to_string(status));
			local_irq_restore(irq_flags);
			ret = hv_status_to_errno(status);
			break;
		}
		local_irq_restore(irq_flags);
		ret = hv_call_deposit_pages(NUMA_NO_NODE,
					    hv_current_partition_id, 1);
	} while (!ret);

	return ret;
}

int hv_call_initialize_partition(u64 partition_id)
{
	struct hv_initialize_partition input;
	u64 status;
	int ret;

	input.partition_id = partition_id;

	ret = hv_call_deposit_pages(
				NUMA_NO_NODE,
				partition_id,
				HV_INIT_PARTITION_DEPOSIT_PAGES);
	if (ret)
		return ret;

	do {
		status = hv_do_fast_hypercall8(
				HVCALL_INITIALIZE_PARTITION,
				*(u64 *)&input);

		if (hv_result(status) != HV_STATUS_INSUFFICIENT_MEMORY) {
			if (!hv_result_success(status))
				pr_err("%s: %s\n",
				       __func__, hv_status_to_string(status));
			ret = hv_status_to_errno(status);
			break;
		}
		ret = hv_call_deposit_pages(NUMA_NO_NODE, partition_id, 1);
	} while (!ret);

	return ret;
}

int hv_call_finalize_partition(u64 partition_id)
{
	struct hv_finalize_partition input;
	u64 status;

	input.partition_id = partition_id;
	status = hv_do_fast_hypercall8(
			HVCALL_FINALIZE_PARTITION,
			*(u64 *)&input);

	if (!hv_result_success(status))
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));

	return hv_status_to_errno(status);
}

int hv_call_delete_partition(u64 partition_id)
{
	struct hv_delete_partition input;
	u64 status;

	input.partition_id = partition_id;
	status = hv_do_fast_hypercall8(HVCALL_DELETE_PARTITION, *(u64 *)&input);

	if (!hv_result_success(status))
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));

	return hv_status_to_errno(status);
}

int hv_call_map_gpa_pages(
		u64 partition_id,
		u64 gpa_target,
		u64 page_count, u32 flags,
		struct page **pages)
{
	struct hv_map_gpa_pages *input_page;
	u64 status;
	int i;
	struct page **p;
	u32 completed = 0;
	unsigned long remaining = page_count;
	int rep_count;
	unsigned long irq_flags;
	int ret = 0;

	while (remaining) {

		rep_count = min(remaining, HV_MAP_GPA_BATCH_SIZE);

		local_irq_save(irq_flags);
		input_page = (struct hv_map_gpa_pages *)(*this_cpu_ptr(
			hyperv_pcpu_input_arg));

		input_page->target_partition_id = partition_id;
		input_page->target_gpa_base = gpa_target;
		input_page->map_flags = flags;

		for (i = 0, p = pages; i < rep_count; i++, p++)
			input_page->source_gpa_page_list[i] = page_to_pfn(*p);
		status = hv_do_rep_hypercall(
			HVCALL_MAP_GPA_PAGES, rep_count, 0, input_page, NULL);
		local_irq_restore(irq_flags);

		completed = hv_repcomp(status);

		if (hv_result(status) == HV_STATUS_INSUFFICIENT_MEMORY) {
			ret = hv_call_deposit_pages(NUMA_NO_NODE,
						    partition_id,
						    HV_MAP_GPA_DEPOSIT_PAGES);
			if (ret)
				break;
		} else if (!hv_result_success(status)) {
			pr_err("%s: completed %llu out of %llu, %s\n",
			       __func__,
			       page_count - remaining, page_count,
			       hv_status_to_string(status));
			ret = hv_status_to_errno(status);
			break;
		}

		pages += completed;
		remaining -= completed;
		gpa_target += completed;
	}

	if (ret && remaining < page_count) {
		pr_err("%s: Partially succeeded; mapped regions may be in invalid state",
		       __func__);
		ret = -EBADFD;
	}

	return ret;
}

int hv_call_unmap_gpa_pages(
		u64 partition_id,
		u64 gpa_target,
		u64 page_count, u32 flags)
{
	struct hv_unmap_gpa_pages *input_page;
	u64 status;
	int ret = 0;
	u32 completed = 0;
	unsigned long remaining = page_count;
	int rep_count;
	unsigned long irq_flags;

	while (remaining) {
		local_irq_save(irq_flags);
		input_page = (struct hv_unmap_gpa_pages *)(*this_cpu_ptr(
			hyperv_pcpu_input_arg));

		input_page->target_partition_id = partition_id;
		input_page->target_gpa_base = gpa_target;
		input_page->unmap_flags = flags;
		rep_count = min(remaining, HV_MAP_GPA_BATCH_SIZE);
		status = hv_do_rep_hypercall(
			HVCALL_UNMAP_GPA_PAGES, rep_count, 0, input_page, NULL);
		local_irq_restore(irq_flags);

		completed = hv_repcomp(status);
		if (!hv_result_success(status)) {
			pr_err("%s: completed %llu out of %llu, %s\n",
			       __func__,
			       page_count - remaining, page_count,
			       hv_status_to_string(status));
			ret = hv_status_to_errno(status);
			break;
		}

		remaining -= completed;
		gpa_target += completed;
	}

	if (ret && remaining < page_count) {
		pr_err("%s: Partially succeeded; mapped regions may be in invalid state",
		       __func__);
		ret = -EBADFD;
	}

	return ret;
}

int hv_call_get_vp_registers(
		u32 vp_index,
		u64 partition_id,
		u16 count,
		struct hv_register_assoc *registers)
{
	struct hv_get_vp_registers *input_page;
	union hv_register_value *output_page;
	u16 completed = 0;
	unsigned long remaining = count;
	int rep_count, i;
	u64 status;
	unsigned long flags;

	local_irq_save(flags);

	input_page = (struct hv_get_vp_registers *)(*this_cpu_ptr(
		hyperv_pcpu_input_arg));
	output_page = (union hv_register_value *)(*this_cpu_ptr(
		hyperv_pcpu_output_arg));

	input_page->partition_id = partition_id;
	input_page->vp_index = vp_index;
	input_page->input_vtl = 0;
	input_page->rsvd_z8 = 0;
	input_page->rsvd_z16 = 0;

	while (remaining) {
		rep_count = min(remaining, HV_GET_REGISTER_BATCH_SIZE);
		for (i = 0; i < rep_count; ++i)
			input_page->names[i] = registers[i].name;

		status = hv_do_rep_hypercall(HVCALL_GET_VP_REGISTERS, rep_count,
					     0, input_page, output_page);
		if (!hv_result_success(status)) {
			pr_err("%s: completed %li out of %u, %s\n",
			       __func__,
			       count - remaining, count,
			       hv_status_to_string(status));
			break;
		}
		completed = hv_repcomp(status);
		for (i = 0; i < completed; ++i)
			registers[i].value = output_page[i];

		registers += completed;
		remaining -= completed;
	}
	local_irq_restore(flags);

	return hv_status_to_errno(status);
}

int hv_call_set_vp_registers(
		u32 vp_index,
		u64 partition_id,
		u16 count,
		struct hv_register_assoc *registers)
{
	struct hv_set_vp_registers *input_page;
	u16 completed = 0;
	unsigned long remaining = count;
	int rep_count;
	u64 status;
	unsigned long flags;

	local_irq_save(flags);
	input_page = (struct hv_set_vp_registers *)(*this_cpu_ptr(
		hyperv_pcpu_input_arg));

	input_page->partition_id = partition_id;
	input_page->vp_index = vp_index;
	input_page->input_vtl = 0;
	input_page->rsvd_z8 = 0;
	input_page->rsvd_z16 = 0;

	while (remaining) {
		rep_count = min(remaining, HV_SET_REGISTER_BATCH_SIZE);
		memcpy(input_page->elements, registers,
			sizeof(struct hv_register_assoc) * rep_count);

		status = hv_do_rep_hypercall(HVCALL_SET_VP_REGISTERS, rep_count,
					     0, input_page, NULL);
		if (!hv_result_success(status)) {
			pr_err("%s: completed %li out of %u, %s\n",
			       __func__,
			       count - remaining, count,
			       hv_status_to_string(status));
			break;
		}
		completed = hv_repcomp(status);
		registers += completed;
		remaining -= completed;
	}

	local_irq_restore(flags);

	return hv_status_to_errno(status);
}

int hv_call_install_intercept(
		u64 partition_id,
		u32 access_type,
		enum hv_intercept_type intercept_type,
		union hv_intercept_parameters intercept_parameter)
{
	struct hv_install_intercept *input;
	unsigned long flags;
	u64 status;
	int ret;

	do {
		local_irq_save(flags);
		input = (struct hv_install_intercept *)(*this_cpu_ptr(
					hyperv_pcpu_input_arg));
		input->partition_id = partition_id;
		input->access_type = access_type;
		input->intercept_type = intercept_type;
		input->intercept_parameter = intercept_parameter;
		status = hv_do_hypercall(
				HVCALL_INSTALL_INTERCEPT, input, NULL);

		local_irq_restore(flags);
		if (hv_result(status) != HV_STATUS_INSUFFICIENT_MEMORY) {
			if (!hv_result_success(status))
				pr_err("%s: %s\n", __func__,
				       hv_status_to_string(status));
			ret = hv_status_to_errno(status);
			break;
		}

		ret = hv_call_deposit_pages(NUMA_NO_NODE, partition_id, 1);
	} while (!ret);

	return ret;
}

int hv_call_assert_virtual_interrupt(
		u64 partition_id,
		u32 vector,
		u64 dest_addr,
		union hv_interrupt_control control)
{
	struct hv_assert_virtual_interrupt *input;
	unsigned long flags;
	u64 status;

	local_irq_save(flags);
	input = (struct hv_assert_virtual_interrupt *)(*this_cpu_ptr(
			hyperv_pcpu_input_arg));
	memset(input, 0, sizeof(*input));
	input->partition_id = partition_id;
	input->vector = vector;
	input->dest_addr = dest_addr;
	input->control = control;
	status = hv_do_hypercall(HVCALL_ASSERT_VIRTUAL_INTERRUPT, input, NULL);
	local_irq_restore(flags);

	if (!hv_result_success(status)) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		return hv_status_to_errno(status);
	}

	return 0;
}

int hv_call_get_vp_state(
		u32 vp_index,
		u64 partition_id,
		enum hv_get_set_vp_state_type type,
		struct hv_vp_state_data_xsave xsave,
		/* Choose between pages and ret_output */
		u64 page_count,
		struct page **pages,
		union hv_get_vp_state_out *ret_output)
{
	struct hv_get_vp_state_in *input;
	union hv_get_vp_state_out *output;
	u64 status;
	int i;
	u64 control;
	unsigned long flags;
	int ret = 0;

	if (page_count > HV_GET_VP_STATE_BATCH_SIZE)
		return -EINVAL;

	if (!page_count && !ret_output)
		return -EINVAL;

	do {
		local_irq_save(flags);
		input = (struct hv_get_vp_state_in *)
				(*this_cpu_ptr(hyperv_pcpu_input_arg));
		output = (union hv_get_vp_state_out *)
				(*this_cpu_ptr(hyperv_pcpu_output_arg));
		memset(input, 0, sizeof(*input));
		memset(output, 0, sizeof(*output));

		input->partition_id = partition_id;
		input->vp_index = vp_index;
		input->state_data.type = type;
		memcpy(&input->state_data.xsave, &xsave, sizeof(xsave));
		for (i = 0; i < page_count; i++)
			input->output_data_pfns[i] = page_to_pfn(pages[i]);

		control = (HVCALL_GET_VP_STATE) |
			  (page_count << HV_HYPERCALL_VARHEAD_OFFSET);

		status = hv_do_hypercall(control, input, output);

		if (hv_result(status) != HV_STATUS_INSUFFICIENT_MEMORY) {
			if (!hv_result_success(status))
				pr_err("%s: %s\n", __func__,
				       hv_status_to_string(status));
			else if (ret_output)
				memcpy(ret_output, output, sizeof(*output));

			local_irq_restore(flags);
			ret = hv_status_to_errno(status);
			break;
		}
		local_irq_restore(flags);

		ret = hv_call_deposit_pages(NUMA_NO_NODE,
					    partition_id, 1);
	} while (!ret);

	return ret;
}

int hv_call_set_vp_state(
		u32 vp_index,
		u64 partition_id,
		enum hv_get_set_vp_state_type type,
		struct hv_vp_state_data_xsave xsave,
		/* Choose between pages and bytes */
		u64 page_count,
		struct page **pages,
		u32 num_bytes,
		u8 *bytes)
{
	struct hv_set_vp_state_in *input;
	u64 status;
	int i;
	u64 control;
	unsigned long flags;
	int ret = 0;
	u16 varhead_sz;

	if (page_count > HV_SET_VP_STATE_BATCH_SIZE)
		return -EINVAL;
	if (sizeof(*input) + num_bytes > HV_HYP_PAGE_SIZE)
		return -EINVAL;

	if (num_bytes)
		/* round up to 8 and divide by 8 */
		varhead_sz = (num_bytes + 7) >> 3;
	else if (page_count)
		varhead_sz =  page_count;
	else
		return -EINVAL;

	do {
		local_irq_save(flags);
		input = (struct hv_set_vp_state_in *)
				(*this_cpu_ptr(hyperv_pcpu_input_arg));
		memset(input, 0, sizeof(*input));

		input->partition_id = partition_id;
		input->vp_index = vp_index;
		input->state_data.type = type;
		memcpy(&input->state_data.xsave, &xsave, sizeof(xsave));
		if (num_bytes) {
			memcpy((u8 *)input->data, bytes, num_bytes);
		} else {
			for (i = 0; i < page_count; i++)
				input->data[i].pfns = page_to_pfn(pages[i]);
		}

		control = (HVCALL_SET_VP_STATE) |
			  (varhead_sz << HV_HYPERCALL_VARHEAD_OFFSET);

		status = hv_do_hypercall(control, input, NULL);

		if (hv_result(status) != HV_STATUS_INSUFFICIENT_MEMORY) {
			if (!hv_result_success(status))
				pr_err("%s: %s\n", __func__,
				       hv_status_to_string(status));

			local_irq_restore(flags);
			ret = hv_status_to_errno(status);
			break;
		}
		local_irq_restore(flags);

		ret = hv_call_deposit_pages(NUMA_NO_NODE,
					    partition_id, 1);
	} while (!ret);

	return ret;
}

int hv_call_map_vp_state_page(
		u32 vp_index,
		u64 partition_id,
		struct page **state_page)
{
	struct hv_map_vp_state_page_in *input;
	struct hv_map_vp_state_page_out *output;
	u64 status;
	int ret;
	unsigned long flags;

	do {
		local_irq_save(flags);
		input = (struct hv_map_vp_state_page_in *)(*this_cpu_ptr(
			hyperv_pcpu_input_arg));
		output = (struct hv_map_vp_state_page_out *)(*this_cpu_ptr(
			hyperv_pcpu_output_arg));

		input->partition_id = partition_id;
		input->vp_index = vp_index;
		input->type = HV_VP_STATE_PAGE_REGISTERS;
		status = hv_do_hypercall(HVCALL_MAP_VP_STATE_PAGE,
						   input, output);

		if (hv_result(status) != HV_STATUS_INSUFFICIENT_MEMORY) {
			if (hv_result_success(status))
				*state_page = pfn_to_page(output->map_location);
			else
				pr_err("%s: %s\n", __func__,
				       hv_status_to_string(status));
			local_irq_restore(flags);
			ret = hv_status_to_errno(status);
			break;
		}
		local_irq_restore(flags);

		ret = hv_call_deposit_pages(NUMA_NO_NODE, partition_id, 1);
	} while (!ret);

	return ret;
}

int hv_call_get_partition_property(
		u64 partition_id,
		u64 property_code,
		u64 *property_value)
{
	u64 status;
	unsigned long flags;
	struct hv_get_partition_property_in *input;
	struct hv_get_partition_property_out *output;

	local_irq_save(flags);
	input = (struct hv_get_partition_property_in *)(*this_cpu_ptr(
			hyperv_pcpu_input_arg));
	output = (struct hv_get_partition_property_out *)(*this_cpu_ptr(
			hyperv_pcpu_output_arg));
	memset(input, 0, sizeof(*input));
	input->partition_id = partition_id;
	input->property_code = property_code;
	status = hv_do_hypercall(HVCALL_GET_PARTITION_PROPERTY, input,
			output);

	if (!hv_result_success(status)) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		local_irq_restore(flags);
		return hv_status_to_errno(status);
	}
	*property_value = output->property_value;

	local_irq_restore(flags);

	return 0;
}

int hv_call_set_partition_property(
		u64 partition_id,
		u64 property_code,
		u64 property_value)
{
	u64 status;
	unsigned long flags;
	struct hv_set_partition_property *input;

	local_irq_save(flags);
	input = (struct hv_set_partition_property *)(*this_cpu_ptr(
			hyperv_pcpu_input_arg));
	memset(input, 0, sizeof(*input));
	input->partition_id = partition_id;
	input->property_code = property_code;
	input->property_value = property_value;
	status = hv_do_hypercall(HVCALL_SET_PARTITION_PROPERTY, input, NULL);
	local_irq_restore(flags);

	if (!hv_result_success(status))
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));

	return hv_status_to_errno(status);
}

int hv_call_translate_virtual_address(
		u32 vp_index,
		u64 partition_id,
		u64 flags,
		u64 gva,
		u64 *gpa,
		union hv_translate_gva_result *result)
{
	u64 status;
	unsigned long irq_flags;
	struct hv_translate_virtual_address_in *input;
	struct hv_translate_virtual_address_out *output;

	local_irq_save(irq_flags);

	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	output = *this_cpu_ptr(hyperv_pcpu_output_arg);

	memset(input, 0, sizeof(*input));
	memset(output, 0, sizeof(*output));

	input->partition_id = partition_id;
	input->vp_index = vp_index;
	input->control_flags = flags;
	input->gva_page = gva >> HV_HYP_PAGE_SHIFT;

	status = hv_do_hypercall(HVCALL_TRANSLATE_VIRTUAL_ADDRESS, input, output);

	if (!hv_result_success(status)) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		goto out;
	}

	*result = output->translation_result;
	*gpa = (output->gpa_page << HV_HYP_PAGE_SHIFT) + offset_in_hvpage(gva);

out:
	local_irq_restore(irq_flags);

	return hv_status_to_errno(status);
}


int
hv_call_create_port(u64 port_partition_id, union hv_port_id port_id,
		    u64 connection_partition_id,
		    struct hv_port_info *port_info,
		    u8 port_vtl, u8 min_connection_vtl, int node)
{
	struct hv_create_port *input;
	unsigned long flags;
	int ret = 0;
	int status;

	do {
		local_irq_save(flags);
		input = (struct hv_create_port *)(*this_cpu_ptr(
				hyperv_pcpu_input_arg));
		memset(input, 0, sizeof(*input));

		input->port_partition_id = port_partition_id;
		input->port_id = port_id;
		input->connection_partition_id = connection_partition_id;
		input->port_info = *port_info;
		input->port_vtl = port_vtl;
		input->min_connection_vtl = min_connection_vtl;
		input->proximity_domain_info =
			numa_node_to_proximity_domain_info(node);
		status = hv_do_hypercall(HVCALL_CREATE_PORT, input,
					NULL) & HV_HYPERCALL_RESULT_MASK;
		local_irq_restore(flags);
		if (status == HV_STATUS_SUCCESS)
			break;

		if (status != HV_STATUS_INSUFFICIENT_MEMORY) {
			pr_err("%s: %s\n",
			       __func__, hv_status_to_string(status));
			ret = hv_status_to_errno(status);
			break;
		}
		ret = hv_call_deposit_pages(NUMA_NO_NODE,
				port_partition_id, 1);

	} while (!ret);

	return ret;
}

int
hv_call_delete_port(u64 port_partition_id, union hv_port_id port_id)
{
	union hv_delete_port input = { 0 };
	unsigned long flags;
	int status;

	local_irq_save(flags);
	input.port_partition_id = port_partition_id;
	input.port_id = port_id;
	status = hv_do_fast_hypercall16(HVCALL_DELETE_PORT,
					input.as_uint64[0],
					input.as_uint64[1]) &
			HV_HYPERCALL_RESULT_MASK;
	local_irq_restore(flags);

	if (status != HV_STATUS_SUCCESS) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		return hv_status_to_errno(status);
	}

	return 0;
}

int
hv_call_connect_port(u64 port_partition_id, union hv_port_id port_id,
		     u64 connection_partition_id,
		     union hv_connection_id connection_id,
		     struct hv_connection_info *connection_info,
		     u8 connection_vtl, int node)
{
	struct hv_connect_port *input;
	unsigned long flags;
	int ret = 0, status;

	do {
		local_irq_save(flags);
		input = (struct hv_connect_port *)(*this_cpu_ptr(
				hyperv_pcpu_input_arg));
		memset(input, 0, sizeof(*input));
		input->port_partition_id = port_partition_id;
		input->port_id = port_id;
		input->connection_partition_id = connection_partition_id;
		input->connection_id = connection_id;
		input->connection_info = *connection_info;
		input->connection_vtl = connection_vtl;
		input->proximity_domain_info =
			numa_node_to_proximity_domain_info(node);
		status = hv_do_hypercall(HVCALL_CONNECT_PORT, input,
					NULL) & HV_HYPERCALL_RESULT_MASK;

		local_irq_restore(flags);
		if (status == HV_STATUS_SUCCESS)
			break;

		if (status != HV_STATUS_INSUFFICIENT_MEMORY) {
			pr_err("%s: %s\n",
			       __func__, hv_status_to_string(status));
			ret = hv_status_to_errno(status);
			break;
		}
		ret = hv_call_deposit_pages(NUMA_NO_NODE,
				connection_partition_id, 1);
	} while (!ret);

	return ret;
}

int
hv_call_disconnect_port(u64 connection_partition_id,
			union hv_connection_id connection_id)
{
	union hv_disconnect_port input = { 0 };
	unsigned long flags;
	int status;

	local_irq_save(flags);
	input.connection_partition_id = connection_partition_id;
	input.connection_id = connection_id;
	input.is_doorbell = 1;
	status = hv_do_fast_hypercall16(HVCALL_DISCONNECT_PORT,
					input.as_uint64[0],
					input.as_uint64[1]) &
			HV_HYPERCALL_RESULT_MASK;
	local_irq_restore(flags);

	if (status != HV_STATUS_SUCCESS) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		return hv_status_to_errno(status);
	}

	return 0;
}

int
hv_call_notify_port_ring_empty(u32 sint_index)
{
	union hv_notify_port_ring_empty input = { 0 };
	unsigned long flags;
	int status;

	local_irq_save(flags);
	input.sint_index = sint_index;
	status = hv_do_fast_hypercall8(HVCALL_NOTIFY_PORT_RING_EMPTY,
					input.as_uint64) &
			HV_HYPERCALL_RESULT_MASK;
	local_irq_restore(flags);

	if (status != HV_STATUS_SUCCESS) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		return hv_status_to_errno(status);
	}

	return 0;
}
