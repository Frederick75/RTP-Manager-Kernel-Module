#!/usr/bin/env bash
set -euo pipefail
sudo rmmod rtp_mgr || true
echo "Unloaded rtp_mgr"
