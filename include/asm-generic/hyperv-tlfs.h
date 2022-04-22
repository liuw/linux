/* SPDX-License-Identifier: GPL-2.0 */

/*
 * This file contains definitions from Hyper-V Hypervisor Top-Level Functional
 * Specification (TLFS):
 * https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/reference/tlfs
 */

#ifndef _ASM_GENERIC_HYPERV_TLFS_H
#define _ASM_GENERIC_HYPERV_TLFS_H

#include <linux/types.h>
#include <linux/bits.h>
#include <linux/time64.h>
#include <uapi/asm-generic/hyperv-tlfs.h>

/*
 * While not explicitly listed in the TLFS, Hyper-V always runs with a page size
 * of 4096. These definitions are used when communicating with Hyper-V using
 * guest physical pages and guest physical page addresses, since the guest page
 * size may not be 4096 on all architectures.
 */
#define HV_HYP_PAGE_SHIFT		12
#define HV_HYP_PAGE_SIZE		BIT(HV_HYP_PAGE_SHIFT)
#define HV_HYP_PAGE_MASK		(~(HV_HYP_PAGE_SIZE - 1))

/*
 * Hyper-V provides two categories of flags relevant to guest VMs.  The
 * "Features" category indicates specific functionality that is available
 * to guests on this particular instance of Hyper-V. The "Features"
 * are presented in four groups, each of which is 32 bits. The group A
 * and B definitions are common across architectures and are listed here.
 * However, not all flags are relevant on all architectures.
 *
 * Groups C and D vary across architectures and are listed in the
 * architecture specific portion of hyperv-tlfs.h. Some of these flags exist
 * on multiple architectures, but the bit positions are different so they
 * cannot appear in the generic portion of hyperv-tlfs.h.
 *
 * The "Enlightenments" category provides recommendations on whether to use
 * specific enlightenments that are available. The Enlighenments are a single
 * group of 32 bits, but they vary across architectures and are listed in
 * the architecture specific portion of hyperv-tlfs.h.
 */

/*
 * Group A Features.
 */

/* VP Runtime register available */
#define HV_MSR_VP_RUNTIME_AVAILABLE		BIT(0)
/* Partition Reference Counter available*/
#define HV_MSR_TIME_REF_COUNT_AVAILABLE		BIT(1)
/* Basic SynIC register available */
#define HV_MSR_SYNIC_AVAILABLE			BIT(2)
/* Synthetic Timer registers available */
#define HV_MSR_SYNTIMER_AVAILABLE		BIT(3)
/* Virtual APIC assist and VP assist page registers available */
#define HV_MSR_APIC_ACCESS_AVAILABLE		BIT(4)
/* Hypercall and Guest OS ID registers available*/
#define HV_MSR_HYPERCALL_AVAILABLE		BIT(5)
/* Access virtual processor index register available*/
#define HV_MSR_VP_INDEX_AVAILABLE		BIT(6)
/* Virtual system reset register available*/
#define HV_MSR_RESET_AVAILABLE			BIT(7)
/* Access statistics page registers available */
#define HV_MSR_STAT_PAGES_AVAILABLE		BIT(8)
/* Partition reference TSC register is available */
#define HV_MSR_REFERENCE_TSC_AVAILABLE		BIT(9)
/* Partition Guest IDLE register is available */
#define HV_MSR_GUEST_IDLE_AVAILABLE		BIT(10)
/* Partition local APIC and TSC frequency registers available */
#define HV_ACCESS_FREQUENCY_MSRS		BIT(11)
/* AccessReenlightenmentControls privilege */
#define HV_ACCESS_REENLIGHTENMENT		BIT(13)
/* AccessTscInvariantControls privilege */
#define HV_ACCESS_TSC_INVARIANT			BIT(15)

/*
 * Group B features.
 */
#define HV_CREATE_PARTITIONS			BIT(0)
#define HV_ACCESS_PARTITION_ID			BIT(1)
#define HV_ACCESS_MEMORY_POOL			BIT(2)
#define HV_ADJUST_MESSAGE_BUFFERS		BIT(3)
#define HV_POST_MESSAGES			BIT(4)
#define HV_SIGNAL_EVENTS			BIT(5)
#define HV_CREATE_PORT				BIT(6)
#define HV_CONNECT_PORT				BIT(7)
#define HV_ACCESS_STATS				BIT(8)
#define HV_DEBUGGING				BIT(11)
#define HV_CPU_MANAGEMENT			BIT(12)
#define HV_ENABLE_EXTENDED_HYPERCALLS		BIT(20)
#define HV_ISOLATION				BIT(22)

/*
 * TSC page layout.
 */
struct ms_hyperv_tsc_page {
	volatile u32 tsc_sequence;
	u32 reserved1;
	volatile u64 tsc_scale;
	volatile s64 tsc_offset;
} __packed;

/*
 * The guest OS needs to register the guest ID with the hypervisor.
 * The guest ID is a 64 bit entity and the structure of this ID is
 * specified in the Hyper-V specification:
 *
 * msdn.microsoft.com/en-us/library/windows/hardware/ff542653%28v=vs.85%29.aspx
 *
 * While the current guideline does not specify how Linux guest ID(s)
 * need to be generated, our plan is to publish the guidelines for
 * Linux and other guest operating systems that currently are hosted
 * on Hyper-V. The implementation here conforms to this yet
 * unpublished guidelines.
 *
 *
 * Bit(s)
 * 63 - Indicates if the OS is Open Source or not; 1 is Open Source
 * 62:56 - Os Type; Linux is 0x100
 * 55:48 - Distro specific identification
 * 47:16 - Linux kernel version number
 * 15:0  - Distro specific identification
 *
 *
 */

#define HV_LINUX_VENDOR_ID              0x8100

/*
 * Crash notification flags.
 */
#define HV_CRASH_CTL_CRASH_NOTIFY_MSG		BIT_ULL(62)
#define HV_CRASH_CTL_CRASH_NOTIFY		BIT_ULL(63)

/* Declare the various hypercall operations. */
#define HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE	0x0002
#define HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST	0x0003
#define HVCALL_NOTIFY_LONG_SPIN_WAIT		0x0008
#define HVCALL_SEND_IPI				0x000b
#define HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE_EX	0x0013
#define HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST_EX	0x0014
#define HVCALL_SEND_IPI_EX			0x0015
#define HVCALL_CREATE_PARTITION			0x0040
#define HVCALL_INITIALIZE_PARTITION		0x0041
#define HVCALL_FINALIZE_PARTITION		0x0042
#define HVCALL_DELETE_PARTITION			0x0043
#define HVCALL_GET_PARTITION_PROPERTY		0x0044
#define HVCALL_SET_PARTITION_PROPERTY		0x0045
#define HVCALL_GET_PARTITION_ID			0x0046
#define HVCALL_DEPOSIT_MEMORY			0x0048
#define HVCALL_WITHDRAW_MEMORY			0x0049
#define HVCALL_MAP_GPA_PAGES			0x004b
#define HVCALL_UNMAP_GPA_PAGES			0x004c
#define HVCALL_INSTALL_INTERCEPT		0x004d
#define HVCALL_CREATE_VP			0x004e
#define HVCALL_GET_VP_REGISTERS			0x0050
#define HVCALL_SET_VP_REGISTERS			0x0051
#define HVCALL_TRANSLATE_VIRTUAL_ADDRESS	0x0052
#define HVCALL_CLEAR_VIRTUAL_INTERRUPT		0x0056
#define HVCALL_DELETE_PORT			0x0058
#define HVCALL_DISCONNECT_PORT			0x005b
#define HVCALL_POST_MESSAGE			0x005c
#define HVCALL_SIGNAL_EVENT			0x005d
#define HVCALL_POST_DEBUG_DATA			0x0069
#define HVCALL_RETRIEVE_DEBUG_DATA		0x006a
#define HVCALL_RESET_DEBUG_SESSION		0x006b
#define HVCALL_ADD_LOGICAL_PROCESSOR		0x0076
#define HVCALL_MAP_DEVICE_INTERRUPT		0x007c
#define HVCALL_UNMAP_DEVICE_INTERRUPT		0x007d
#define HVCALL_RETARGET_INTERRUPT		0x007e
#define HVCALL_NOTIFY_PORT_RING_EMPTY		0x008b
#define HVCALL_ASSERT_VIRTUAL_INTERRUPT		0x0094
#define HVCALL_CREATE_PORT			0x0095
#define HVCALL_CONNECT_PORT			0x0096
#define HVCALL_FLUSH_GUEST_PHYSICAL_ADDRESS_SPACE 0x00af
#define HVCALL_FLUSH_GUEST_PHYSICAL_ADDRESS_LIST 0x00b0
#define HVCALL_GET_GPA_PAGES_ACCESS_STATES 0x00c9
#define HVCALL_MAP_VP_STATE_PAGE			0x00e1
#define HVCALL_GET_VP_STATE				0x00e3
#define HVCALL_SET_VP_STATE				0x00e4

/* Extended hypercalls */
#define HV_EXT_CALL_QUERY_CAPABILITIES		0x8001
#define HV_EXT_CALL_MEMORY_HEAT_HINT		0x8003

#define HV_FLUSH_ALL_PROCESSORS			BIT(0)
#define HV_FLUSH_ALL_VIRTUAL_ADDRESS_SPACES	BIT(1)
#define HV_FLUSH_NON_GLOBAL_MAPPINGS_ONLY	BIT(2)
#define HV_FLUSH_USE_EXTENDED_RANGE_FORMAT	BIT(3)

/* Extended capability bits */
#define HV_EXT_CAPABILITY_MEMORY_COLD_DISCARD_HINT BIT(8)

enum HV_GENERIC_SET_FORMAT {
	HV_GENERIC_SET_SPARSE_4K,
	HV_GENERIC_SET_ALL,
};

#define HV_PARTITION_ID_SELF		((u64)-1)
#define HV_VP_INDEX_SELF		((u32)-2)

#define HV_HYPERCALL_RESULT_MASK	GENMASK_ULL(15, 0)
#define HV_HYPERCALL_FAST_BIT		BIT(16)
#define HV_HYPERCALL_VARHEAD_OFFSET	17
#define HV_HYPERCALL_REP_COMP_OFFSET	32
#define HV_HYPERCALL_REP_COMP_1		BIT_ULL(32)
#define HV_HYPERCALL_REP_COMP_MASK	GENMASK_ULL(43, 32)
#define HV_HYPERCALL_REP_START_OFFSET	48
#define HV_HYPERCALL_REP_START_MASK	GENMASK_ULL(59, 48)

/* hypercall status code */
#define __HV_STATUS_DEF(OP) \
	OP(HV_STATUS_SUCCESS,				0x0) \
	OP(HV_STATUS_INVALID_HYPERCALL_CODE,		0x2) \
	OP(HV_STATUS_INVALID_HYPERCALL_INPUT,		0x3) \
	OP(HV_STATUS_INVALID_ALIGNMENT,			0x4) \
	OP(HV_STATUS_INVALID_PARAMETER,			0x5) \
	OP(HV_STATUS_ACCESS_DENIED,			0x6) \
	OP(HV_STATUS_INVALID_PARTITION_STATE,		0x7) \
	OP(HV_STATUS_OPERATION_DENIED,			0x8) \
	OP(HV_STATUS_UNKNOWN_PROPERTY,			0x9) \
	OP(HV_STATUS_PROPERTY_VALUE_OUT_OF_RANGE,	0xA) \
	OP(HV_STATUS_INSUFFICIENT_MEMORY,		0xB) \
	OP(HV_STATUS_INVALID_PARTITION_ID,		0xD) \
	OP(HV_STATUS_INVALID_VP_INDEX,			0xE) \
	OP(HV_STATUS_NOT_FOUND,				0x10) \
	OP(HV_STATUS_INVALID_PORT_ID,			0x11) \
	OP(HV_STATUS_INVALID_CONNECTION_ID,		0x12) \
	OP(HV_STATUS_INSUFFICIENT_BUFFERS,		0x13) \
	OP(HV_STATUS_NOT_ACKNOWLEDGED,			0x14) \
	OP(HV_STATUS_INVALID_VP_STATE,			0x15) \
	OP(HV_STATUS_NO_RESOURCES,			0x1D) \
	OP(HV_STATUS_INVALID_LP_INDEX,			0x41) \
	OP(HV_STATUS_INVALID_REGISTER_VALUE,		0x50)

#define __HV_MAKE_HV_STATUS_ENUM(NAME, VAL) NAME = (VAL),
#define __HV_MAKE_HV_STATUS_CASE(NAME, VAL) case (NAME): return (#NAME);

enum hv_status {
	__HV_STATUS_DEF(__HV_MAKE_HV_STATUS_ENUM)
};

/*
 * The Hyper-V TimeRefCount register and the TSC
 * page provide a guest VM clock with 100ns tick rate
 */
#define HV_CLOCK_HZ (NSEC_PER_SEC/100)

/* Define the number of synthetic interrupt sources. */
#define HV_SYNIC_SINT_COUNT		(16)
/* Define the expected SynIC version. */
#define HV_SYNIC_VERSION_1		(0x1)
/* Valid SynIC vectors are 16-255. */
#define HV_SYNIC_FIRST_VALID_VECTOR	(16)

/* Hyper-V defined statically assigned SINTs */
#define HV_SYNIC_INTERCEPTION_SINT_INDEX 0x00000000
#define HV_SYNIC_IOMMU_FAULT_SINT_INDEX  0x00000001
#define HV_SYNIC_VMBUS_SINT_INDEX        0x00000002
#define HV_SYNIC_HAL_HV_TIMER_SINT_INDEX 0x00000003
#define HV_SYNIC_HVL_SHARED_SINT_INDEX   0x00000004
#define HV_SYNIC_FIRST_UNUSED_SINT_INDEX 0x00000005

/* mshv assigned SINT for doorbell */
#define HV_SYNIC_DOORBELL_SINT_INDEX     HV_SYNIC_FIRST_UNUSED_SINT_INDEX

#define HV_SYNIC_CONTROL_ENABLE		(1ULL << 0)
#define HV_SYNIC_SIMP_ENABLE		(1ULL << 0)
#define HV_SYNIC_SIEFP_ENABLE		(1ULL << 0)
#define HV_SYNIC_SINT_MASKED		(1ULL << 16)
#define HV_SYNIC_SINT_AUTO_EOI		(1ULL << 17)
#define HV_SYNIC_SINT_VECTOR_MASK	(0xFF)

#define HV_SYNIC_STIMER_COUNT		(4)

/* Define the synthetic interrupt message page layout. */
struct hv_message_page {
	struct hv_message sint_message[HV_SYNIC_SINT_COUNT];
} __packed;

/* Define timer message payload structure. */
struct hv_timer_message_payload {
	__u32 timer_index;
	__u32 reserved;
	__u64 expiration_time;	/* When the timer expired */
	__u64 delivery_time;	/* When the message was delivered */
} __packed;

/*
 * Message format for notifications delivered via
 * intercept message(as_intercept=1)
 */
struct hv_notification_message_payload {
	u32 sint_index;
} __packed;

/* Define the synthentic interrupt controller event ring format */
#define HV_SYNIC_EVENT_RING_MESSAGE_COUNT 63

struct hv_synic_event_ring {
	u8  signal_masked;
	u8  ring_full;
	u16 reserved_z;
	u32 data[HV_SYNIC_EVENT_RING_MESSAGE_COUNT];
} __packed;

struct hv_synic_event_ring_page {
	volatile struct hv_synic_event_ring sint_event_ring[HV_SYNIC_SINT_COUNT];
};

/* Define synthetic interrupt controller flag constants. */
#define HV_EVENT_FLAGS_COUNT		(256 * 8)
#define HV_EVENT_FLAGS_BYTE_COUNT	(256)
#define HV_EVENT_FLAGS_LONG_COUNT	(256 / sizeof(unsigned long))

/*
 * Synthetic timer configuration.
 */
union hv_stimer_config {
	u64 as_uint64;
	struct {
		u64 enable:1;
		u64 periodic:1;
		u64 lazy:1;
		u64 auto_enable:1;
		u64 apic_vector:8;
		u64 direct_mode:1;
		u64 reserved_z0:3;
		u64 sintx:4;
		u64 reserved_z1:44;
	} __packed;
};


/* Define the synthetic interrupt controller event flags format. */
union hv_synic_event_flags {
	unsigned char flags8[HV_EVENT_FLAGS_BYTE_COUNT];
	unsigned long flags[HV_EVENT_FLAGS_LONG_COUNT];
};

struct hv_synic_event_flags_page {
	volatile union hv_synic_event_flags event_flags[HV_SYNIC_SINT_COUNT];
};

/* Define SynIC control register. */
union hv_synic_scontrol {
	u64 as_uint64;
	struct {
		u64 enable:1;
		u64 reserved:63;
	} __packed;
};

/* Define synthetic interrupt source. */
union hv_synic_sint {
	u64 as_uint64;
	struct {
		u64 vector:8;
		u64 reserved1:8;
		u64 masked:1;
		u64 auto_eoi:1;
		u64 polling:1;
		u64 as_intercept: 1;
		u64 proxy: 1;
		u64 reserved2:43;
	} __packed;
};

/* Define the format of the SIMP register */
union hv_synic_simp {
	u64 as_uint64;
	struct {
		u64 simp_enabled:1;
		u64 preserved:11;
		u64 base_simp_gpa:52;
	} __packed;
};

/* Define the format of the SIEFP register */
union hv_synic_siefp {
	u64 as_uint64;
	struct {
		u64 siefp_enabled:1;
		u64 preserved:11;
		u64 base_siefp_gpa:52;
	} __packed;
};

union hv_synic_sirbp {
	u64 as_uint64;
	struct {
		u64 sirbp_enabled:1;
		u64 preserved:11;
		u64 base_sirbp_gpa:52;
	} __packed;
};

struct hv_vpset {
	u64 format;
	u64 valid_bank_mask;
	u64 bank_contents[];
} __packed;

/* HvCallSendSyntheticClusterIpi hypercall */
struct hv_send_ipi {
	u32 vector;
	u32 reserved;
	u64 cpu_mask;
} __packed;

/* HvCallSendSyntheticClusterIpiEx hypercall */
struct hv_send_ipi_ex {
	u32 vector;
	u32 reserved;
	struct hv_vpset vp_set;
} __packed;

/* HvFlushGuestPhysicalAddressSpace hypercalls */
struct hv_guest_mapping_flush {
	u64 address_space;
	u64 flags;
} __packed;

/*
 *  HV_MAX_FLUSH_PAGES = "additional_pages" + 1. It's limited
 *  by the bitwidth of "additional_pages" in union hv_gpa_page_range.
 */
#define HV_MAX_FLUSH_PAGES (2048)
#define HV_GPA_PAGE_RANGE_PAGE_SIZE_2MB		0
#define HV_GPA_PAGE_RANGE_PAGE_SIZE_1GB		1

/* HvFlushGuestPhysicalAddressList, HvExtCallMemoryHeatHint hypercall */
union hv_gpa_page_range {
	u64 address_space;
	struct {
		u64 additional_pages:11;
		u64 largepage:1;
		u64 basepfn:52;
	} page;
	struct {
		u64 reserved:12;
		u64 page_size:1;
		u64 reserved1:8;
		u64 base_large_pfn:43;
	};
};

/*
 * All input flush parameters should be in single page. The max flush
 * count is equal with how many entries of union hv_gpa_page_range can
 * be populated into the input parameter page.
 */
#define HV_MAX_FLUSH_REP_COUNT ((HV_HYP_PAGE_SIZE - 2 * sizeof(u64)) /	\
				sizeof(union hv_gpa_page_range))

struct hv_guest_mapping_flush_list {
	u64 address_space;
	u64 flags;
	union hv_gpa_page_range gpa_list[HV_MAX_FLUSH_REP_COUNT];
};

/* HvFlushVirtualAddressSpace, HvFlushVirtualAddressList hypercalls */
struct hv_tlb_flush {
	u64 address_space;
	u64 flags;
	u64 processor_mask;
	u64 gva_list[];
} __packed;

/* HvFlushVirtualAddressSpaceEx, HvFlushVirtualAddressListEx hypercalls */
struct hv_tlb_flush_ex {
	u64 address_space;
	u64 flags;
	struct hv_vpset hv_vp_set;
	u64 gva_list[];
} __packed;

/* HvGetPartitionId hypercall (output only) */
struct hv_get_partition_id {
	u64 partition_id;
} __packed;

/* HvDepositMemory hypercall */
struct hv_deposit_memory {
	u64 partition_id;
	u64 gpa_page_list[];
} __packed;

struct hv_proximity_domain_flags {
	u32 proximity_preferred : 1;
	u32 reserved : 30;
	u32 proximity_info_valid : 1;
} __packed;

/* Not a union in windows but useful for zeroing */
union hv_proximity_domain_info {
	struct {
		u32 domain_id;
		struct hv_proximity_domain_flags flags;
	};
	u64 as_uint64;
} __packed;

struct hv_withdraw_memory_in {
	u64 partition_id;
	union hv_proximity_domain_info proximity_domain_info;
} __packed;

struct hv_withdraw_memory_out {
	/* Hack - compiler doesn't like empty array size in struct with no other members */
	u64 gpa_page_list[0];
} __packed;

struct hv_lp_startup_status {
	u64 hv_status;
	u64 substatus1;
	u64 substatus2;
	u64 substatus3;
	u64 substatus4;
	u64 substatus5;
	u64 substatus6;
} __packed;

/* HvAddLogicalProcessor hypercall */
struct hv_add_logical_processor_in {
	u32 lp_index;
	u32 apic_id;
	union hv_proximity_domain_info proximity_domain_info;
	u64 flags;
} __packed;

struct hv_add_logical_processor_out {
	struct hv_lp_startup_status startup_status;
} __packed;

enum HV_SUBNODE_TYPE
{
    HvSubnodeAny = 0,
    HvSubnodeSocket = 1,
    HvSubnodeAmdNode = 2,
    HvSubnodeL3 = 3,
    HvSubnodeCount = 4,
    HvSubnodeInvalid = -1
};

/* HvCreateVp hypercall */
struct hv_create_vp {
	u64 partition_id;
	u32 vp_index;
	u8 padding[3];
	u8 subnode_type;
	u64 subnode_id;
	union hv_proximity_domain_info proximity_domain_info;
	u64 flags;
} __packed;

enum hv_interrupt_source {
	HV_INTERRUPT_SOURCE_MSI = 1, /* MSI and MSI-X */
	HV_INTERRUPT_SOURCE_IOAPIC,
};

union hv_ioapic_rte {
	u64 as_uint64;

	struct {
		u32 vector:8;
		u32 delivery_mode:3;
		u32 destination_mode:1;
		u32 delivery_status:1;
		u32 interrupt_polarity:1;
		u32 remote_irr:1;
		u32 trigger_mode:1;
		u32 interrupt_mask:1;
		u32 reserved1:15;

		u32 reserved2:24;
		u32 destination_id:8;
	};

	struct {
		u32 low_uint32;
		u32 high_uint32;
	};
} __packed;

struct hv_interrupt_entry {
	u32 source;
	u32 reserved1;
	union {
		union hv_msi_entry msi_entry;
		union hv_ioapic_rte ioapic_rte;
	};
} __packed;

/*
 * flags for hv_device_interrupt_target.flags
 */
#define HV_DEVICE_INTERRUPT_TARGET_MULTICAST		1
#define HV_DEVICE_INTERRUPT_TARGET_PROCESSOR_SET	2

struct hv_device_interrupt_target {
	u32 vector;
	u32 flags;
	union {
		u64 vp_mask;
		struct hv_vpset vp_set;
	};
} __packed;

struct hv_retarget_device_interrupt {
	u64 partition_id;		/* use "self" */
	u64 device_id;
	struct hv_interrupt_entry int_entry;
	u64 reserved2;
	struct hv_device_interrupt_target int_target;
} __packed __aligned(8);

/* HvGetVpRegisters hypercall with variable size reg name list*/
struct hv_get_vp_registers {
	u64 partition_id;
	u32 vp_index;
	u8  input_vtl;
	u8  rsvd_z8;
	u16 rsvd_z16;
	u32 names[];
} __packed;

/* HvGetVpRegisters returns an array of register values */
struct hv_get_vp_registers_output {
	union {
		struct {
			u32 a;
			u32 b;
			u32 c;
			u32 d;
		} as32 __packed;
		struct {
			u64 low;
			u64 high;
		} as64 __packed;
	};
} __packed;

/* HvSetVpRegisters hypercall with variable size reg name/value list*/
struct hv_set_vp_registers {
	u64 partition_id;
	u32 vp_index;
	u8  input_vtl;
	u8  rsvd_z8;
	u16 rsvd_z16;
	struct hv_register_assoc elements[];
} __packed;

enum hv_device_type {
	HV_DEVICE_TYPE_LOGICAL = 0,
	HV_DEVICE_TYPE_PCI = 1,
	HV_DEVICE_TYPE_IOAPIC = 2,
	HV_DEVICE_TYPE_ACPI = 3,
};

typedef u16 hv_pci_rid;
typedef u16 hv_pci_segment;
typedef u64 hv_logical_device_id;
union hv_pci_bdf {
	u16 as_uint16;

	struct {
		u8 function:3;
		u8 device:5;
		u8 bus;
	};
} __packed;

union hv_pci_bus_range {
	u16 as_uint16;

	struct {
		u8 subordinate_bus;
		u8 secondary_bus;
	};
} __packed;

union hv_device_id {
	u64 as_uint64;

	struct {
		u64 reserved0:62;
		u64 device_type:2;
	};

	/* HV_DEVICE_TYPE_LOGICAL */
	struct {
		u64 id:62;
		u64 device_type:2;
	} logical;

	/* HV_DEVICE_TYPE_PCI */
	struct {
		union {
			hv_pci_rid rid;
			union hv_pci_bdf bdf;
		};

		hv_pci_segment segment;
		union hv_pci_bus_range shadow_bus_range;

		u16 phantom_function_bits:2;
		u16 source_shadow:1;

		u16 rsvdz0:11;
		u16 device_type:2;
	} pci;

	/* HV_DEVICE_TYPE_IOAPIC */
	struct {
		u8 ioapic_id;
		u8 rsvdz0;
		u16 rsvdz1;
		u16 rsvdz2;

		u16 rsvdz3:14;
		u16 device_type:2;
	} ioapic;

	/* HV_DEVICE_TYPE_ACPI */
	struct {
		u32 input_mapping_base;
		u32 input_mapping_count:30;
		u32 device_type:2;
	} acpi;
} __packed;

enum hv_interrupt_trigger_mode {
	HV_INTERRUPT_TRIGGER_MODE_EDGE = 0,
	HV_INTERRUPT_TRIGGER_MODE_LEVEL = 1,
};

struct hv_device_interrupt_descriptor {
	u32 interrupt_type;
	u32 trigger_mode;
	u32 vector_count;
	u32 reserved;
	struct hv_device_interrupt_target target;
} __packed;

struct hv_input_map_device_interrupt {
	u64 partition_id;
	u64 device_id;
	u64 flags;
	struct hv_interrupt_entry logical_interrupt_entry;
	struct hv_device_interrupt_descriptor interrupt_descriptor;
} __packed;

struct hv_output_map_device_interrupt {
	struct hv_interrupt_entry interrupt_entry;
} __packed;

struct hv_input_unmap_device_interrupt {
	u64 partition_id;
	u64 device_id;
	struct hv_interrupt_entry interrupt_entry;
} __packed;

#define HV_SOURCE_SHADOW_NONE               0x0
#define HV_SOURCE_SHADOW_BRIDGE_BUS_RANGE   0x1

/*
 * The whole argument should fit in a page to be able to pass to the hypervisor
 * in one hypercall.
 */
#define HV_MEMORY_HINT_MAX_GPA_PAGE_RANGES  \
	((HV_HYP_PAGE_SIZE - sizeof(struct hv_memory_hint)) / \
		sizeof(union hv_gpa_page_range))

/* HvExtCallMemoryHeatHint hypercall */
#define HV_EXT_MEMORY_HEAT_HINT_TYPE_COLD_DISCARD	2
struct hv_memory_hint {
	u64 type:2;
	u64 reserved:62;
	union hv_gpa_page_range ranges[];
} __packed;

union hv_partition_isolation_properties {
	u64 as_uint64;
	struct {
		u64 isolation_type: 5;
		u64 rsvd_z: 7;
		u64 shared_gpa_boundary_page_number: 52;
	};
} __packed;

/* Non-userspace-visible partition creation flags */
#define HV_PARTITION_CREATION_FLAG_EXO_PARTITION                    BIT(8)

#define HV_MAKE_COMPATIBILITY_VERSION(major_, minor_)	\
	((u32)((major_) << 8 | (minor_)))

#define HV_COMPATIBILITY_19_H1		HV_MAKE_COMPATIBILITY_VERSION(0X6, 0X5)
#define HV_COMPATIBILITY_20_H1		HV_MAKE_COMPATIBILITY_VERSION(0X6, 0X7)
#define HV_COMPATIBILITY_PRERELEASE	HV_MAKE_COMPATIBILITY_VERSION(0XFE, 0X0)
#define HV_COMPATIBILITY_EXPERIMENT	HV_MAKE_COMPATIBILITY_VERSION(0XFF, 0X0)

struct hv_create_partition_in {
	u64 flags;
	union hv_proximity_domain_info proximity_domain_info;
	u32 compatibility_version;
	u32 padding;
	struct hv_partition_creation_properties partition_creation_properties;
	union hv_partition_isolation_properties isolation_properties;
} __packed;

struct hv_create_partition_out {
	u64 partition_id;
} __packed;

struct hv_initialize_partition {
	u64 partition_id;
} __packed;

struct hv_finalize_partition {
	u64 partition_id;
} __packed;

struct hv_delete_partition {
	u64 partition_id;
} __packed;

struct hv_map_gpa_pages {
	u64 target_partition_id;
	u64 target_gpa_base;
	u32 map_flags;
	u32 padding;
	u64 source_gpa_page_list[];
} __packed;

struct hv_unmap_gpa_pages {
	u64 target_partition_id;
	u64 target_gpa_base;
	u32 unmap_flags;
	u32 padding;
} __packed;

struct hv_install_intercept {
	u64 partition_id;
	u32 access_type; /* mask */
	u32 intercept_type;
	union hv_intercept_parameters intercept_parameter;
} __packed;

struct hv_assert_virtual_interrupt {
	u64 partition_id;
	union hv_interrupt_control control;
	u64 dest_addr; /* cpu's apic id */
	u32 vector;
	u8 target_vtl;
	u8 rsvd_z0;
	u16 rsvd_z1;
} __packed;

struct hv_vp_state_data {
	u32 type;
	u32 rsvd;
	struct hv_vp_state_data_xsave xsave;
} __packed;

struct hv_get_vp_state_in {
	u64 partition_id;
	u32 vp_index;
	u8 input_vtl;
	u8 rsvd0;
	u16 rsvd1;
	struct hv_vp_state_data state_data;
	u64 output_data_pfns[];
} __packed;

union hv_get_vp_state_out {
	struct hv_local_interrupt_controller_state interrupt_controller_state;
	/* Not supported yet */
	/* struct hv_synthetic_timers_state synthetic_timers_state; */
} __packed;

union hv_input_set_vp_state_data {
	u64 pfns;
	u8 bytes;
} __packed;

struct hv_set_vp_state_in {
	u64 partition_id;
	u32 vp_index;
	u8 input_vtl;
	u8 rsvd0;
	u16 rsvd1;
	struct hv_vp_state_data state_data;
	union hv_input_set_vp_state_data data[];
} __packed;

struct hv_map_vp_state_page_in {
	u64 partition_id;
	u32 vp_index;
	u32 type; /* enum hv_vp_state_page_type */
} __packed;

struct hv_map_vp_state_page_out {
	u64 map_location; /* page number */
} __packed;

struct hv_get_partition_property_in {
	u64 partition_id;
	u32 property_code; /* enum hv_partition_property_code */
	u32 padding;
} __packed;

struct hv_get_partition_property_out {
	u64 property_value;
} __packed;

struct hv_set_partition_property {
	u64 partition_id;
	u32 property_code; /* enum hv_partition_property_code */
	u32 padding;
	u64 property_value;
} __packed;

struct hv_translate_virtual_address_in {
	u64 partition_id;
	u32 vp_index;
	u32 padding;
	u64 control_flags;
	u64 gva_page;
} __packed;

struct hv_translate_virtual_address_out {
	union hv_translate_gva_result translation_result;
	u64 gpa_page;
} __packed;

struct hv_port_info {
	u32 port_type;
	u32 padding;
	union {
		struct {
			u32 target_sint;
			u32 target_vp;
			u64 rsvdz;
		} message_port_info;
		struct {
			u32 target_sint;
			u32 target_vp;
			u16 base_flag_number;
			u16 flag_count;
			u32 rsvdz;
		} event_port_info;
		struct {
			u64 monitor_address;
			u64 rsvdz;
		} monitor_port_info;
		struct {
			u32 target_sint;
			u32 target_vp;
			u64 rsvdz;
		} doorbell_port_info;
	};
} __packed;

struct hv_create_port {
	u64 port_partition_id;
	union hv_port_id port_id;
	u8 port_vtl;
	u8 min_connection_vtl;
	u16 padding;
	u64 connection_partition_id;
	struct hv_port_info port_info;
	union hv_proximity_domain_info proximity_domain_info;
} __packed;

union hv_delete_port {
	u64 as_uint64[2];
	struct {
		u64 port_partition_id;
		union hv_port_id port_id;
		u32 reserved;
	};
} __packed;

union hv_notify_port_ring_empty {
	u64 as_uint64;
	struct {
		u32 sint_index;
		u32 reserved;
	};
} __packed;

struct hv_connection_info {
	u32 port_type;
	u32 padding;
	union {
		struct {
			u64 rsvdz;
		} message_connection_info;
		struct {
			u64 rsvdz;
		} event_connection_info;
		struct {
			u64 monitor_address;
		} monitor_connection_info;
		struct {
			u64 gpa;
			u64 trigger_value;
			u64 flags;
		} doorbell_connection_info;
	};
} __packed;

struct hv_connect_port {
	u64 connection_partition_id;
	union hv_connection_id connection_id;
	u8 connection_vtl;
	u8 rsvdz0;
	u16 rsvdz1;
	u64 port_partition_id;
	union hv_port_id port_id;
	u32 reserved2;
	struct hv_connection_info connection_info;
	union hv_proximity_domain_info proximity_domain_info;
} __packed;

union hv_disconnect_port {
	u64 as_uint64[2];
	struct {
		u64 connection_partition_id;
		union hv_connection_id connection_id;
		u32 is_doorbell: 1;
		u32 reserved: 31;
	};
} __packed;
#endif
