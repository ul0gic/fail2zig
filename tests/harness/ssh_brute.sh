#!/usr/bin/env bash
# tests/harness/ssh_brute.sh — real SSH bruteforce from an attacker host.
#
# Runs *on the attacker VM*, pointed at the fail2zig-protected target.
# Generates real SSH connection attempts so the full network-level
# detection path exercises end-to-end —
# inotify → parser → state → nftables → kernel DROP.
#
# Usage: ssh_brute.sh <target-ip> [attempts=5]
#
# Requires a password-rejecting SSH target (OpenSSH default). Uses
# `hydra` when available for realism + speed; falls back to a serial
# `ssh`-with-bogus-credentials loop that produces the same auth-log
# pattern.
#
# Exits 0 after all attempts are submitted, regardless of whether
# any succeeded (we don't expect any to succeed — this is a bruteforce
# simulation).

set -euo pipefail

[ $# -lt 1 ] && { echo "Usage: $0 <target-ip> [attempts=5]" >&2; exit 2; }
target="$1"
attempts="${2:-5}"

echo "ssh_brute.sh: $attempts invalid-user attempts against $target"

# The invalid-user path is more portable than password-based hydra.
# OpenSSH servers with `PasswordAuthentication no` refuse password
# attempts early enough that no `Invalid user` log line is emitted,
# so hydra-style password spraying silently produces no matches. The
# ssh-with-random-username approach instead reaches the point where
# sshd logs `Invalid user X from <attacker> port N`, which fail2zig's
# sshd filter matches regardless of the target's auth-method policy.
#
# For operators who want realistic credential-spray traffic against a
# password-auth-enabled test target, uncomment the hydra branch below.

for i in $(seq 1 "$attempts"); do
    ssh -o BatchMode=yes \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=3 \
        "probe$i-$$@$target" true 2>&1 | head -1 || true
    sleep 0.1
done

# --- optional hydra-based credential spray (target must accept password auth) ---
# if command -v hydra >/dev/null 2>&1; then
#     users=(root admin test ubuntu debian)
#     passes=(password 12345 admin letmein toor)
#     tmp_users=$(mktemp)
#     tmp_passes=$(mktemp)
#     trap 'rm -f "$tmp_users" "$tmp_passes"' EXIT
#     printf '%s\n' "${users[@]}" > "$tmp_users"
#     printf '%s\n' "${passes[@]}" > "$tmp_passes"
#     hydra -L "$tmp_users" -P "$tmp_passes" -t 4 -f -q \
#         -o /dev/null "ssh://$target" \
#         2>&1 | head -$(( attempts + 2 )) || true
# fi
