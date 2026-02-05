#ifndef TSM_H_
#define TSM_H_

#include <linux/types.h>

#define PCI_TSM_REQ_INFO 0
#define PCI_TSM_REQ_STATE_CHANGE 1

#define RHI_DA_SUCCESS				0x0
#define RHI_DA_INCOMPLETE			0x1
#define RHI_DA_ERROR_DATA_NOT_AVAILABLE		0x2
#define RHI_DA_ERROR_INVALID_VDEV_ID		0x3
#define RHI_DA_ERROR_INVALID_OBJECT		0x4
#define RHI_DA_ERROR_INPUT			0x5
#define RHI_DA_ERROR_DEVICE			0x6
#define RHI_DA_ERROR_INVALID_OFFSET		0x7
#define RHI_DA_ERROR_ACCESS_FAILED		0x8
#define RHI_DA_ERROR_BUSY			0x9

#define RHI_DA_TDI_CONFIG_UNLOCKED		0x0
#define RHI_DA_TDI_CONFIG_LOCKED		0x1
#define RHI_DA_TDI_CONFIG_RUN			0x2

/* guest request operation nr */
#define __RHI_DA_OBJECT_SIZE		0x1
#define __RHI_DA_OBJECT_READ		0x2
#define __RHI_DA_VDEV_GET_INTERFACE_REPORT 0x3
#define __RHI_DA_VDEV_GET_MEASUREMENTS	0x4
#define __REC_EXIT_DA_VDEV_REQUEST	0x5
#define __REC_EXIT_DA_VDEV_MAP		0x6
#define __RHI_DA_VDEV_SET_TDI_STATE	0x7

struct arm64_vdev_set_tdi_state_guest_req {
	__u32 req_type;
	__u32 tdi_state;
};

struct arm64_vdev_object_size_guest_req {
	__u32 req_type;
	__u32 object_type;
};

struct arm64_vdev_object_read_guest_req {
	__u32 req_type;
	__u32 object_type;
	__aligned_u64 offset;
};

struct arm64_vdev_device_measurement_guest_req {
	__u32 req_type;
	__aligned_u64 flags;
	__u8 *indices;
	__u8 *nonce;
};

struct arm64_vdev_device_idmap_guest_req {
	__u32 req_type;
	__s32 vcpu_fd;
};

struct arm64_vdev_device_memmap_guest_req {
	__u32 req_type;
	__s32 vcpu_fd;
	__aligned_u64 gpa_base;
	__aligned_u64 gpa_top;
	__aligned_u64 pa_base;
};

#endif // TSM_H_
