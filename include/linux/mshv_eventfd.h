/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *
 * irqfd: Allows an fd to be used to inject an interrupt to the guest.
 * ioeventfd: Allow an fd to be used to receive a signal from the guest.
 * All credit goes to kvm developers.
 */

#ifndef __LINUX_MSHV_EVENTFD_H
#define __LINUX_MSHV_EVENTFD_H

#include <linux/mshv.h>
#include <linux/poll.h>

void mshv_eventfd_init(struct mshv_partition *partition);
void mshv_eventfd_release(struct mshv_partition *partition);

void mshv_register_irq_ack_notifier(struct mshv_partition *partition,
				    struct mshv_irq_ack_notifier *mian);
void mshv_unregister_irq_ack_notifier(struct mshv_partition *partition,
			struct mshv_irq_ack_notifier *mian);
bool mshv_notify_acked_gsi(struct mshv_partition *partition, int gsi);

struct mshv_kernel_irqfd_resampler {
	struct mshv_partition *partition;
	/*
	 * List of irqfds sharing this gsi.
	 * Protected by irqfds.resampler_lock
	 * and irq_srcu.
	 */
	struct list_head list;
	struct mshv_irq_ack_notifier notifier;
	/*
	 * Entry in the list of partition->irqfd.resampler_list.
	 * Protected by irqfds.resampler_lock
	 *
	 */
	struct list_head link;
};

struct mshv_kernel_irqfd {
	struct mshv_partition     *partition;
	struct eventfd_ctx        *eventfd;
	u32                        gsi;
	struct mshv_lapic_irq      lapic_irq;
	struct list_head           list;
	poll_table                 pt;
	wait_queue_head_t         *wqh;
	wait_queue_entry_t         wait;
	struct work_struct         shutdown;

	/* Resampler related */
	struct mshv_kernel_irqfd_resampler *resampler;
	struct eventfd_ctx *resamplefd;
	struct list_head resampler_link;
};

int mshv_irqfd(struct mshv_partition *partition,
		struct mshv_irqfd *args);

int mshv_irqfd_wq_init(void);
void mshv_irqfd_wq_cleanup(void);

struct kernel_mshv_ioeventfd {
	struct list_head     list;
	u64                  addr;
	int                  length;
	struct eventfd_ctx  *eventfd;
	u64                  datamatch;
	int                  doorbell_id;
	bool                 wildcard;
};

int mshv_ioeventfd(struct mshv_partition *kvm, struct mshv_ioeventfd *args);

#endif /* __LINUX_MSHV_EVENTFD_H */
