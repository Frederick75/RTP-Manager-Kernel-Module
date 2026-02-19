# RTP Manager Kernel Module — Project Explanation

## Overview

The **RTP Manager Kernel Module** is a Linux Loadable Kernel Module (LKM) that provides a **low‑latency, high‑performance**
data plane for real-time **RTP media streaming** in embedded and telecom systems. It combines:

- **Kernel-space RTP buffering** using a **circular ring buffer** to absorb bursts while keeping deterministic timing.
- **Zero‑copy shared memory** using `mmap()` so user space can write/read RTP payloads directly without extra copying.
- **IOCTL-based control plane** for configuration, start/stop, and statistics, suitable for production instrumentation.

This architecture reduces:
- CPU overhead (fewer copies, fewer syscalls per packet)
- jitter (stable buffering and consistent kernel timing)
- latency (direct user→kernel buffer access)

## Why kernel module?

A pure user-space RTP pipeline often suffers from:
- multiple copies between kernel socket buffers and user buffers
- scheduling jitter under load
- inefficient buffer management with bursty media traffic

By providing a kernel-managed ring and memory-mapped buffers, the system can enforce buffer policy closer to the hardware
and provide consistent control/stats.

## Key components

### 1) Character device: `/dev/rtp_mgr`

The module exposes a char device with:
- `open()/release()` — session lifecycle
- `unlocked_ioctl()` — control plane
- `mmap()` — export shared buffer region

### 2) Shared memory (zero-copy) via `mmap()`

User space calls:

- `mmap(fd, ...)` to map the module's shared buffer region
- writes/reads RTP frames to/from that region

The module uses:
- `vmalloc()` to allocate a contiguous virtual region
- `remap_vmalloc_range()` to map those pages into user space

### 3) Kernel ring buffer manager

The kernel maintains a ring of **slots**, each slot contains metadata and a payload region:

- slot state transitions (FREE → READY → CONSUMED)
- sequence tracking and simple drop policy
- stats counters (drops, overruns, underruns, bytes, packets)

### 4) IOCTL control plane

User space configures runtime behavior:
- ring order (number of slots = 2^order)
- max payload size
- start/stop streaming
- query stats

The IOCTL ABI is stable and versioned in `include/rtp_mgr_ioctl.h`.

### 5) User-space RTP application

A production-style user-space program demonstrates:
- multi-threaded design (RX thread, TX thread, controller thread)
- kernel control via IOCTL
- zero-copy buffer access via `mmap`
- RTP header generation and UDP sockets for network I/O

## Data flow

### Receive path (network → ring)

1. User-space RX thread reads UDP packets (RTP).
2. It writes payload into the shared mmap buffer at the next FREE slot.
3. It notifies kernel via IOCTL (`RTPM_IOCTL_PUSH_SLOT`) that the slot is READY.
4. Kernel updates ring state and stats; a real deployment would forward to a device/DMA engine.

### Transmit path (ring → network)

1. User-space TX thread requests the next READY slot via IOCTL (`RTPM_IOCTL_POP_SLOT`).
2. It reads payload from shared mmap buffer and sends it over UDP.
3. It returns the slot to FREE state via IOCTL (`RTPM_IOCTL_RELEASE_SLOT`).

> The reference implementation keeps heavy packet processing in user space while demonstrating the
> **zero-copy shared memory + kernel ring control** mechanism. Hardware offload can be added by consuming
> READY slots directly in kernel (e.g., DMA enqueue) and returning CONSUMED slots.

## Reliability & performance practices

- **Page-aligned buffers** and fixed-size slots for predictable performance.
- **Atomic counters** and lock-minimized fast paths.
- **Bounded ring** prevents unbounded memory growth.
- **Stats and debugging hooks** to validate latency and drop behavior.

## Deployment contexts

- IPTV/OTT set-top boxes
- Embedded multimedia servers
- Telecom media gateways / RTP relays
- VoIP/SBC adjunct pipelines

## Deliverables in this repo

- Kernel module source: `kernel/rtp_mgr.c`, `kernel/rtp_mgr_ring.h`
- Shared ABI: `include/rtp_mgr_ioctl.h`
- User application: `user/rtp_app.c`
- Build and deployment guide: `docs/BUILD-DEPLOY-GUIDE.md`
- Carrier-grade architecture diagram: `docs/architecture_carrier_grade.svg`
