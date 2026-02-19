#ifndef RTP_MGR_RING_H
#define RTP_MGR_RING_H

#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include "../include/rtp_mgr_ioctl.h"

/* Per-slot metadata stored in kernel (payload resides in shared vmalloc region) */
struct rtpm_slot_meta {
    u32 state;          /* enum rtpm_slot_state */
    u32 payload_len;
    u32 rtp_seq;
    u32 rtp_ts;
};

struct rtpm_ring {
    u32 ring_order;
    u32 ring_size;      /* 2^order */
    u32 slot_payload;
    u32 slot_stride;    /* meta+payload aligned stride in shared buffer */

    /* Kernel metadata array (ring_size entries) */
    struct rtpm_slot_meta *meta;

    /* Indices */
    u32 head_free;      /* producer writes FREE -> READY */
    u32 head_ready;     /* consumer reads READY -> INUSE/FREE */

    spinlock_t lock;

    /* Stats */
    atomic64_t pkts_pushed;
    atomic64_t pkts_popped;
    atomic64_t bytes_pushed;
    atomic64_t bytes_popped;
    atomic64_t drops_ring_full;
    atomic64_t drops_no_ready;
};

static inline u32 rtpm_mask(u32 ring_size) { return ring_size - 1; }

int rtpm_ring_init(struct rtpm_ring *r, u32 order, u32 slot_payload);
void rtpm_ring_destroy(struct rtpm_ring *r);

int rtpm_ring_push_ready(struct rtpm_ring *r, const struct rtpm_slot_desc *d);
int rtpm_ring_pop_ready(struct rtpm_ring *r, struct rtpm_slot_desc *out);
int rtpm_ring_release(struct rtpm_ring *r, const struct rtpm_slot_desc *d);

#endif /* RTP_MGR_RING_H */
