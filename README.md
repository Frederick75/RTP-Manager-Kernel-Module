# RTP Manager Kernel Module (LKM) — Zero‑Copy RTP Streaming Framework

This repository contains a **production-oriented reference implementation** of an **RTP Manager** built as a Linux
Loadable Kernel Module (LKM) plus a **user‑space RTP streaming application**.

The design targets **low-latency, high-throughput real-time media streaming** by combining:

- **Zero‑copy user↔kernel data sharing** via `mmap()` (kernel exports a shared buffer to user space).
- **Kernel ring-buffer manager** for deterministic packet queuing (preventing underruns/overruns).
- **IOCTL control plane** to configure/start/stop, query stats, and tune runtime parameters.
- **Simple hardware / DMA‑friendly layout** (page-aligned buffers, linear regions).

> Note: This is a reference implementation meant to be **buildable and testable** on modern Linux kernels.
> Hardware-specific DMA/NIC offload hooks are represented as extension points.

## What problem does this solve?

Typical RTP pipelines in user-space suffer from:

- Multiple copies (socket buffers → user buffers → device buffers)
- Context switch overhead and scheduling jitter
- Inefficient buffering under bursty traffic

This module reduces jitter and CPU overhead by:
- using **shared memory** (`mmap`) for payload movement
- using a **kernel-managed ring** for ordered packet staging
- keeping control & statistics in kernel for consistent timing

## Repository layout

- `kernel/` — Kernel module (char device `/dev/rtp_mgr`)
- `user/` — User-space RTP app and utilities
- `include/` — Shared headers (IOCTL ABI)
- `docs/` — Project explanation, build/deploy, architecture diagram
- `scripts/` — Helper scripts (load/unload, setup)

## Quick start (TL;DR)

```bash
# 1) Build module + app
make -C kernel
make -C user

# 2) Load module
sudo insmod kernel/rtp_mgr.ko ring_order=10   # 2^10 = 1024 slots
sudo mknod /dev/rtp_mgr c $(cat /proc/devices | awk '/rtp_mgr/ {print $1}') 0
sudo chmod 666 /dev/rtp_mgr

# 3) Run a local loopback test (TX -> RX)
# Terminal A (receiver)
./user/rtp_app --mode rx --bind 127.0.0.1 --port 5004

# Terminal B (transmitter)
./user/rtp_app --mode tx --dst 127.0.0.1 --port 5004 --rate 50 --payload 1200
```

For full details, see:
- `docs/RTP-Manager-Project-Explanation.md`
- `docs/BUILD-DEPLOY-GUIDE.md`
- `docs/architecture_carrier_grade.svg`

## License

MIT (see `LICENSE`).
