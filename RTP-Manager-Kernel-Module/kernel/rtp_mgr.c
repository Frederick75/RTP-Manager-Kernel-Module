// SPDX-License-Identifier: MIT
/*
 * rtp_mgr.c — RTP Manager kernel module
 *
 * Exposes /dev/rtp_mgr
 *  - mmap(): maps shared vmalloc buffer region into user space for zero-copy payload access
 *  - ioctl(): config/start/stop/stats + ring slot workflow
 *
 * This module is a reference implementation focusing on the mmap + ring control plane.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/slab.h>

#include "../include/rtp_mgr_ioctl.h"
#include "rtp_mgr_ring.h"

#define RTPM_DEVICE_NAME "rtp_mgr"

static unsigned int ring_order = 10;
module_param(ring_order, uint, 0444);
MODULE_PARM_DESC(ring_order, "Ring order: ring size is 2^order (default 10 => 1024 slots)");

static unsigned int slot_payload = 2048;
module_param(slot_payload, uint, 0444);
MODULE_PARM_DESC(slot_payload, "Slot payload bytes (default 2048)");

struct rtpm_dev {
    dev_t devno;
    struct cdev cdev;
    struct class *cls;
    struct device *dev;

    /* mmap shared buffer */
    void *shared;
    size_t shared_len;

    struct rtpm_ring ring;
    struct rtpm_config cfg;

    atomic_t started;
};

static struct rtpm_dev g_dev;

/* ---------------- Ring implementation ---------------- */

static size_t rtpm_calc_stride(u32 payload)
{
    /* room for a small header region if needed later; align to 64 bytes */
    size_t stride = sizeof(struct rtpm_slot_desc) + payload;
    stride = (stride + 63) & ~((size_t)63);
    return stride;
}

int rtpm_ring_init(struct rtpm_ring *r, u32 order, u32 payload)
{
    u32 ring_size = 1u << order;

    if (order < 4 || order > 20)
        return -EINVAL;
    if (payload < 64 || payload > (1024u * 1024u))
        return -EINVAL;

    memset(r, 0, sizeof(*r));
    r->ring_order = order;
    r->ring_size = ring_size;
    r->slot_payload = payload;
    r->slot_stride = (u32)rtpm_calc_stride(payload);

    r->meta = kcalloc(ring_size, sizeof(*r->meta), GFP_KERNEL);
    if (!r->meta)
        return -ENOMEM;

    spin_lock_init(&r->lock);

    for (u32 i = 0; i < ring_size; i++) {
        r->meta[i].state = RTPM_SLOT_FREE;
        r->meta[i].payload_len = 0;
    }

    atomic64_set(&r->pkts_pushed, 0);
    atomic64_set(&r->pkts_popped, 0);
    atomic64_set(&r->bytes_pushed, 0);
    atomic64_set(&r->bytes_popped, 0);
    atomic64_set(&r->drops_ring_full, 0);
    atomic64_set(&r->drops_no_ready, 0);

    r->head_free = 0;
    r->head_ready = 0;

    return 0;
}

void rtpm_ring_destroy(struct rtpm_ring *r)
{
    kfree(r->meta);
    r->meta = NULL;
}

static bool rtpm_has_free_locked(struct rtpm_ring *r)
{
    /* ring full if next slot is not FREE at head_free */
    return (r->meta[r->head_free].state == RTPM_SLOT_FREE);
}

static bool rtpm_has_ready_locked(struct rtpm_ring *r)
{
    return (r->meta[r->head_ready].state == RTPM_SLOT_READY);
}

int rtpm_ring_push_ready(struct rtpm_ring *r, const struct rtpm_slot_desc *d)
{
    unsigned long flags;
    int ret = 0;

    if (!d || d->payload_len > r->slot_payload)
        return -EINVAL;

    spin_lock_irqsave(&r->lock, flags);

    if (!rtpm_has_free_locked(r)) {
        atomic64_inc(&r->drops_ring_full);
        ret = -ENOSPC;
        goto out;
    }

    /* Require that user pushes the current head_free index (simple policy). */
    if (d->index != r->head_free) {
        ret = -EINVAL;
        goto out;
    }

    r->meta[d->index].payload_len = d->payload_len;
    r->meta[d->index].rtp_seq = d->rtp_seq;
    r->meta[d->index].rtp_ts  = d->rtp_ts;
    r->meta[d->index].state = RTPM_SLOT_READY;

    r->head_free = (r->head_free + 1) & rtpm_mask(r->ring_size);

    atomic64_inc(&r->pkts_pushed);
    atomic64_add(d->payload_len, &r->bytes_pushed);

out:
    spin_unlock_irqrestore(&r->lock, flags);
    return ret;
}

int rtpm_ring_pop_ready(struct rtpm_ring *r, struct rtpm_slot_desc *out)
{
    unsigned long flags;
    int ret = 0;

    if (!out)
        return -EINVAL;

    spin_lock_irqsave(&r->lock, flags);

    if (!rtpm_has_ready_locked(r)) {
        atomic64_inc(&r->drops_no_ready);
        ret = -EAGAIN;
        goto out_unlock;
    }

    out->index = r->head_ready;
    out->payload_len = r->meta[out->index].payload_len;
    out->rtp_seq = r->meta[out->index].rtp_seq;
    out->rtp_ts  = r->meta[out->index].rtp_ts;

    r->meta[out->index].state = RTPM_SLOT_INUSE;

    r->head_ready = (r->head_ready + 1) & rtpm_mask(r->ring_size);

    atomic64_inc(&r->pkts_popped);
    atomic64_add(out->payload_len, &r->bytes_popped);

out_unlock:
    spin_unlock_irqrestore(&r->lock, flags);
    return ret;
}

int rtpm_ring_release(struct rtpm_ring *r, const struct rtpm_slot_desc *d)
{
    unsigned long flags;

    if (!d)
        return -EINVAL;
    if (d->index >= r->ring_size)
        return -EINVAL;

    spin_lock_irqsave(&r->lock, flags);

    if (r->meta[d->index].state != RTPM_SLOT_INUSE) {
        spin_unlock_irqrestore(&r->lock, flags);
        return -EINVAL;
    }

    r->meta[d->index].state = RTPM_SLOT_FREE;
    r->meta[d->index].payload_len = 0;

    spin_unlock_irqrestore(&r->lock, flags);
    return 0;
}

/* ---------------- Char device ops ---------------- */

static int rtpm_open(struct inode *inode, struct file *filp)
{
    filp->private_data = &g_dev;
    return 0;
}

static int rtpm_release(struct inode *inode, struct file *filp)
{
    return 0;
}

static long rtpm_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct rtpm_dev *d = (struct rtpm_dev *)filp->private_data;

    switch (cmd) {
    case RTPM_IOCTL_GET_ABI: {
        uint32_t v = RTPM_ABI_VERSION;
        if (copy_to_user((void __user *)arg, &v, sizeof(v)))
            return -EFAULT;
        return 0;
    }
    case RTPM_IOCTL_SET_CONFIG: {
        struct rtpm_config cfg;
        if (copy_from_user(&cfg, (void __user *)arg, sizeof(cfg)))
            return -EFAULT;
        if (cfg.abi_version != RTPM_ABI_VERSION)
            return -EINVAL;
        /* Disallow config changes while started */
        if (atomic_read(&d->started))
            return -EBUSY;

        /* Re-init ring and shared buffer */
        return -EOPNOTSUPP; /* keep ABI stable; use module params for now */
    }
    case RTPM_IOCTL_GET_CONFIG: {
        if (copy_to_user((void __user *)arg, &d->cfg, sizeof(d->cfg)))
            return -EFAULT;
        return 0;
    }
    case RTPM_IOCTL_START:
        atomic_set(&d->started, 1);
        return 0;
    case RTPM_IOCTL_STOP:
        atomic_set(&d->started, 0);
        return 0;

    case RTPM_IOCTL_GET_STATS: {
        struct rtpm_stats s;
        s.pkts_pushed = atomic64_read(&d->ring.pkts_pushed);
        s.pkts_popped = atomic64_read(&d->ring.pkts_popped);
        s.bytes_pushed = atomic64_read(&d->ring.bytes_pushed);
        s.bytes_popped = atomic64_read(&d->ring.bytes_popped);
        s.drops_ring_full = atomic64_read(&d->ring.drops_ring_full);
        s.drops_no_ready = atomic64_read(&d->ring.drops_no_ready);

        if (copy_to_user((void __user *)arg, &s, sizeof(s)))
            return -EFAULT;
        return 0;
    }

    case RTPM_IOCTL_PUSH_SLOT: {
        struct rtpm_slot_desc sd;
        if (!atomic_read(&d->started))
            return -EPIPE;
        if (copy_from_user(&sd, (void __user *)arg, sizeof(sd)))
            return -EFAULT;
        return rtpm_ring_push_ready(&d->ring, &sd);
    }
    case RTPM_IOCTL_POP_SLOT: {
        struct rtpm_slot_desc sd;
        int ret;
        if (!atomic_read(&d->started))
            return -EPIPE;
        memset(&sd, 0, sizeof(sd));
        ret = rtpm_ring_pop_ready(&d->ring, &sd);
        if (ret)
            return ret;
        if (copy_to_user((void __user *)arg, &sd, sizeof(sd)))
            return -EFAULT;
        return 0;
    }
    case RTPM_IOCTL_RELEASE_SLOT: {
        struct rtpm_slot_desc sd;
        if (!atomic_read(&d->started))
            return -EPIPE;
        if (copy_from_user(&sd, (void __user *)arg, sizeof(sd)))
            return -EFAULT;
        return rtpm_ring_release(&d->ring, &sd);
    }

    default:
        return -ENOTTY;
    }
}

static int rtpm_mmap(struct file *filp, struct vm_area_struct *vma)
{
    struct rtpm_dev *d = (struct rtpm_dev *)filp->private_data;
    unsigned long size = vma->vm_end - vma->vm_start;

    if (size > d->shared_len)
        return -EINVAL;

    vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);

    /* Map vmalloc'ed pages into user space */
    return remap_vmalloc_range(vma, d->shared, 0);
}

static const struct file_operations rtpm_fops = {
    .owner = THIS_MODULE,
    .open = rtpm_open,
    .release = rtpm_release,
    .unlocked_ioctl = rtpm_ioctl,
    .mmap = rtpm_mmap,
};

/* ---------------- Module init/exit ---------------- */

static int __init rtpm_init(void)
{
    int ret;
    size_t stride;
    size_t total;

    memset(&g_dev, 0, sizeof(g_dev));

    g_dev.cfg.abi_version = RTPM_ABI_VERSION;
    g_dev.cfg.ring_order = ring_order;
    g_dev.cfg.slot_payload = slot_payload;

    ret = rtpm_ring_init(&g_dev.ring, ring_order, slot_payload);
    if (ret) {
        pr_err("rtp_mgr: ring init failed: %d\n", ret);
        return ret;
    }

    stride = rtpm_calc_stride(slot_payload);
    total = (size_t)g_dev.ring.ring_size * stride;

    g_dev.shared_len = total;
    g_dev.shared = vmalloc_user(total);
    if (!g_dev.shared) {
        pr_err("rtp_mgr: vmalloc_user failed\n");
        rtpm_ring_destroy(&g_dev.ring);
        return -ENOMEM;
    }
    memset(g_dev.shared, 0, total);

    /* Allocate char device */
    ret = alloc_chrdev_region(&g_dev.devno, 0, 1, RTPM_DEVICE_NAME);
    if (ret) {
        pr_err("rtp_mgr: alloc_chrdev_region failed: %d\n", ret);
        vfree(g_dev.shared);
        rtpm_ring_destroy(&g_dev.ring);
        return ret;
    }

    cdev_init(&g_dev.cdev, &rtpm_fops);
    ret = cdev_add(&g_dev.cdev, g_dev.devno, 1);
    if (ret) {
        pr_err("rtp_mgr: cdev_add failed: %d\n", ret);
        unregister_chrdev_region(g_dev.devno, 1);
        vfree(g_dev.shared);
        rtpm_ring_destroy(&g_dev.ring);
        return ret;
    }

    #if LINUX_VERSION_CODE < KERNEL_VERSION(6,4,0)
       g_dev.cls = class_create(THIS_MODULE, RTPM_DEVICE_NAME);
    #else
       g_dev.cls = class_create(RTPM_DEVICE_NAME);
    #endif

    if (IS_ERR(g_dev.cls)) {
        ret = PTR_ERR(g_dev.cls);
        pr_err("rtp_mgr: class_create failed: %d\n", ret);
        cdev_del(&g_dev.cdev);
        unregister_chrdev_region(g_dev.devno, 1);
        vfree(g_dev.shared);
        rtpm_ring_destroy(&g_dev.ring);
        return ret;
    }

    g_dev.dev = device_create(g_dev.cls, NULL, g_dev.devno, NULL, RTPM_DEVICE_NAME);
    if (IS_ERR(g_dev.dev)) {
        ret = PTR_ERR(g_dev.dev);
        pr_err("rtp_mgr: device_create failed: %d\n", ret);
        class_destroy(g_dev.cls);
        cdev_del(&g_dev.cdev);
        unregister_chrdev_region(g_dev.devno, 1);
        vfree(g_dev.shared);
        rtpm_ring_destroy(&g_dev.ring);
        return ret;
    }

    atomic_set(&g_dev.started, 0);

    pr_info("rtp_mgr: loaded (major=%d minor=%d) ring=%u slots payload=%u shared=%zu bytes\n",
            MAJOR(g_dev.devno), MINOR(g_dev.devno), g_dev.ring.ring_size, g_dev.ring.slot_payload, g_dev.shared_len);

    return 0;
}

static void __exit rtpm_exit(void)
{
    device_destroy(g_dev.cls, g_dev.devno);
    class_destroy(g_dev.cls);
    cdev_del(&g_dev.cdev);
    unregister_chrdev_region(g_dev.devno, 1);

    vfree(g_dev.shared);
    rtpm_ring_destroy(&g_dev.ring);

    pr_info("rtp_mgr: unloaded\n");
}

module_init(rtpm_init);
module_exit(rtpm_exit);

MODULE_AUTHOR("Bouncestone Technologies (Frederick Swartz)");
MODULE_DESCRIPTION("RTP Manager Kernel Module (zero-copy mmap + ring control)");
MODULE_AUTHOR("OpenAI-generated reference implementation");
MODULE_LICENSE("GPL");
