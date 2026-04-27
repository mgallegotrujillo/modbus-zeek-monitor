#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <interface>"
  echo "Example: $0 eth0"
  exit 1
fi

IFACE="$1"

echo "[*] Starting Zeek Modbus monitor on interface: ${IFACE}"
cd "$(dirname "$0")"

zeek -i "${IFACE}" modbus_monitor.zeek
