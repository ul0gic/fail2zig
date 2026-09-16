#!/usr/bin/env bash

set -euo pipefail

[ $# -lt 1 ] && { echo "Usage: $0 <target-ip> [attempts=5]" >&2; exit 2; }
target="$1"
attempts="${2:-5}"

echo "ssh_brute.sh: $attempts invalid-user attempts against $target"


for i in $(seq 1 "$attempts"); do
    ssh -o BatchMode=yes \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=3 \
        "probe$i-$$@$target" true 2>&1 | head -1 || true
    sleep 0.1
done
