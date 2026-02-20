/*
 * rtp_mgr_ioctl.h — Shared IOCTL ABI for RTP Manager Kernel Module
 *
 * This header is included by both kernel module and user-space utilities.
 */
#ifndef RTP_MGR_IOCTL_H
#define RTP_MGR_IOCTL_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#define RTPM_IOCTL_MAGIC      0xB7
#define RTPM_ABI_VERSION      0x00010001u  /* major.minor */

#define RTPM_MAX_NAME         32

/* Slot state */
enum rtpm_slot_state {
	RTPM_SLOT_FREE = 0,
	RTPM_SLOT_READY = 1,
	RTPM_SLOT_INUSE = 2,
};

/* Runtime config */
struct rtpm_config {
#ifdef __KERNEL__
	u32 abi_version;
	u32 ring_order;      /* slots = 2^ring_order */
	u32 slot_payload;    /* bytes per slot payload */
	u32 reserved;
#else
	uint32_t abi_version;
	uint32_t ring_order;      /* slots = 2^ring_order */
	uint32_t slot_payload;    /* bytes per slot payload */
	uint32_t reserved;
#endif
};

/* Slot descriptor (shared; user reads/writes payload via mmap) */
struct rtpm_slot_desc {
#ifdef __KERNEL__
	u32 index;           /* ring slot index */
	u32 payload_len;     /* bytes valid */
	u32 rtp_seq;         /* optional: RTP sequence (user fills) */
	u32 rtp_ts;          /* optional: RTP timestamp (user fills) */
#else 
	uint32_t index;           /* ring slot index */
	uint32_t payload_len;     /* bytes valid */
	uint32_t rtp_seq;         /* optional: RTP sequence (user fills) */
	uint32_t rtp_ts;          /* optional: RTP timestamp (user fills) */
#endif
};

/* Statistics */
struct rtpm_stats {
#ifdef __KERNEL__
	u64 pkts_pushed;
	u64 pkts_popped;
	u64 bytes_pushed;
	u64 bytes_popped;
	u64 drops_ring_full;
	u64 drops_no_ready;
#else
	uint64_t pkts_pushed;
	uint64_t pkts_popped;
	uint64_t bytes_pushed;
	uint64_t bytes_popped;
	uint64_t drops_ring_full;
	uint64_t drops_no_ready;
#endif
};

#ifdef __KERNEL__
#include <linux/ioctl.h>
#else
#include <sys/ioctl.h>
#endif

/* IOCTLs */
#ifdef __KERNEL__
#define RTPM_IOCTL_GET_ABI        _IOR(RTPM_IOCTL_MAGIC, 0x00, u32)
#else
#define RTPM_IOCTL_GET_ABI        _IOR(RTPM_IOCTL_MAGIC, 0x00, uint32_t)
#endif
#define RTPM_IOCTL_SET_CONFIG     _IOW(RTPM_IOCTL_MAGIC, 0x01, struct rtpm_config)
#define RTPM_IOCTL_GET_CONFIG     _IOR(RTPM_IOCTL_MAGIC, 0x02, struct rtpm_config)

#define RTPM_IOCTL_START          _IO(RTPM_IOCTL_MAGIC,  0x03)
#define RTPM_IOCTL_STOP           _IO(RTPM_IOCTL_MAGIC,  0x04)

#define RTPM_IOCTL_GET_STATS      _IOR(RTPM_IOCTL_MAGIC, 0x05, struct rtpm_stats)

/*
 * Push/Pop workflow:
 * - PUSH_SLOT: user indicates a FREE slot is now READY (payload already written via mmap)
 * - POP_SLOT:  user requests next READY slot; kernel returns a descriptor (index, len, optional fields)
 * - RELEASE_SLOT: user returns slot to FREE after consuming it.
 */
#define RTPM_IOCTL_PUSH_SLOT      _IOW(RTPM_IOCTL_MAGIC, 0x06, struct rtpm_slot_desc)
#define RTPM_IOCTL_POP_SLOT       _IOR(RTPM_IOCTL_MAGIC, 0x07, struct rtpm_slot_desc)
#define RTPM_IOCTL_RELEASE_SLOT   _IOW(RTPM_IOCTL_MAGIC, 0x08, struct rtpm_slot_desc)

#endif /* RTP_MGR_IOCTL_H */
