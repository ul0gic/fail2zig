#!/usr/bin/env bash
# scripts/hammer/reset.sh — return the lab box to a clean testable state.
#
# Stops the daemon, wipes persistent state, flushes the nftables table,
# truncates the watched log files, and starts the daemon again. Used
# between scenarios to guarantee a deterministic starting point.
#
# Usage: reset.sh [--no-start]
#
# Exits 0 on success. Safe to run when the daemon is already stopped
# (systemctl stop is idempotent) or when the nftables table doesn't
# exist (DELTABLE returns ENOENT which we swallow).

set -euo pipefail

start_after=1
while [ $# -gt 0 ]; do
    case "$1" in
        --no-start) start_after=0; shift ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

echo "reset: stopping daemon"
sudo systemctl stop fail2zig || true

echo "reset: wiping state file"
sudo rm -f /var/lib/fail2zig/state.bin

echo "reset: flushing nftables table"
sudo nft delete table inet fail2zig 2>/dev/null || true

# Truncate any log files that jails watch. Truncation preserves file
# perms + ownership + inode (unlike rm-and-recreate which would race
# rsyslog + reset the rotation tracking state). rsyslog reopens the
# file automatically on subsequent writes.
for f in /var/log/auth.log \
         /var/log/nginx/error.log \
         /var/log/nginx/access.log \
         /var/log/mail.log \
         /var/log/apache2/error.log; do
    if [ -f "$f" ]; then
        sudo truncate -s 0 "$f"
    fi
done

if [ "$start_after" = "1" ]; then
    echo "reset: starting daemon"
    sudo systemctl start fail2zig
    # Wait up to 5s for the IPC socket to become ready — that's the
    # moment after which subsequent injections will be observed.
    for _ in $(seq 1 50); do
        if sudo /usr/local/bin/fail2zig-client status >/dev/null 2>&1; then
            echo "reset: daemon ready"
            exit 0
        fi
        sleep 0.1
    done
    echo "reset: daemon did not become ready within 5s" >&2
    exit 1
fi
