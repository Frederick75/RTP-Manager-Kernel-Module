#!/usr/bin/env bash
set -euo pipefail
MOD="$(dirname "$0")/../kernel/rtp_mgr.ko"

sudo insmod "$MOD" ring_order="${1:-10}" slot_payload="${2:-2048}" || true

MAJOR=$(awk '$2=="rtp_mgr" {print $1}' /proc/devices)
if [[ -z "${MAJOR}" ]]; then
  echo "Could not find rtp_mgr in /proc/devices"
  exit 1
fi

if [[ ! -e /dev/rtp_mgr ]]; then
  sudo mknod /dev/rtp_mgr c "$MAJOR" 0
fi
sudo chmod 666 /dev/rtp_mgr
echo "Loaded rtp_mgr (major=$MAJOR). Device: /dev/rtp_mgr"
