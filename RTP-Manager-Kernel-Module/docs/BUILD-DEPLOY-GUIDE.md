# Build & Deployment Guide — RTP Manager Kernel Module

## Prerequisites

### Build host packages

Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install -y build-essential linux-headers-$(uname -r) pkg-config
```

RHEL/Fedora:
```bash
sudo dnf install -y @development-tools kernel-devel-$(uname -r)
```

### Kernel headers

The module builds against the **running kernel**:
- Ensure `linux-headers-$(uname -r)` (Debian/Ubuntu) or `kernel-devel` (RHEL/Fedora) is installed.

## Build

From repo root:

### Build kernel module
```bash
make -C kernel
```

Outputs:
- `kernel/rtp_mgr.ko`

### Build user-space app
```bash
make -C user
```

Outputs:
- `user/rtp_app`

## Load / unload module

### Load
```bash
sudo insmod kernel/rtp_mgr.ko ring_order=10 slot_payload=2048
```

Parameters:
- `ring_order` : ring slots = 2^ring_order (default 10 → 1024 slots)
- `slot_payload`: max payload bytes per slot (default 2048)

### Create device node

The module registers a dynamic major. Create a node:

```bash
MAJOR=$(awk '$2=="rtp_mgr" {print $1}' /proc/devices)
sudo mknod /dev/rtp_mgr c "$MAJOR" 0
sudo chmod 666 /dev/rtp_mgr
```

### Unload
```bash
sudo rmmod rtp_mgr
```

## Run: local loopback test

### Terminal A — Receiver (RX mode)
```bash
./user/rtp_app --mode rx --bind 127.0.0.1 --port 5004
```

### Terminal B — Transmitter (TX mode)
```bash
./user/rtp_app --mode tx --dst 127.0.0.1 --port 5004 --rate 50 --payload 1200
```

- `--rate 50` means ~50 RTP packets/sec
- `--payload 1200` sets payload size bytes (fits typical MTU with RTP/UDP/IP headers)

## Operational notes

### mmap buffer sizing

The shared region is:
- `ring_slots * (slot_hdr + slot_payload)` (aligned)
- `ring_slots = 2^ring_order`

If you increase `slot_payload` or `ring_order`, the mapping grows accordingly.

### Performance tuning (recommended)

- Pin user threads:
  ```bash
  taskset -c 2 ./user/rtp_app ...
  ```
- Use `SCHED_FIFO` if permitted (requires CAP_SYS_NICE).
- Increase socket buffers:
  ```bash
  sysctl -w net.core.rmem_max=134217728
  sysctl -w net.core.wmem_max=134217728
  ```

### Debugging & stats

Read stats via user app:
```bash
./user/rtp_app --mode ctl --stats
```

Or use `dmesg` for module logs:
```bash
dmesg --follow
```

## Production hardening checklist

- Replace demo UDP path with:
  - NIC/XDP path, or
  - DMA enqueue to media hardware, or
  - kernel TLS/DTLS offload where applicable
- Add:
  - per-session isolation (multiple device minors)
  - netlink async event notifications (optional)
  - rate limiting and drop policy controls
  - robust SELinux/AppArmor rules for `/dev/rtp_mgr`

## Clean

```bash
make -C kernel clean
make -C user clean
```
