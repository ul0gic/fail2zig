#!/usr/bin/env bash
# tests/e2e/run-remote.sh — build locally, push the repo + binaries to a
# clean systemd box, and run deploy_regression.sh there over SSH. Transport
# only: zero assertion logic (all assertions live in deploy_regression.sh).
#
# The ReleaseSafe static-musl binaries are cross-compiled HERE (the dev box)
# and rsync'd to the target; the remote harness then installs them via
# `--local-bin`. This is deliberate: the lab target (f2z-target) has no zig
# toolchain — only the dev box builds. (deploy_regression.sh still supports
# `--build` for hosts that DO have zig; this driver just never needs it.)
#
# The self-ban guard flags are MANDATORY — without them ssh offers agent
# keys and trips fail2zig's own sshd jail, banning the operator IP. Do not
# remove them. `accept-new` lets a first run against a fresh host proceed
# without an interactive host-key prompt.
#
# Usage:
#   tests/e2e/run-remote.sh [user@host] [-- <deploy_regression.sh args>]
#
# Example:
#   tests/e2e/run-remote.sh ul0gic@172.16.150.253 -- --purge
#
# Environment overrides:
#   F2Z_SSH_KEY   SSH identity file (default: ~/.ssh/id_ed25519_p33ker).
#
# Exit code mirrors the remote deploy_regression.sh result.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

TARGET="${1:-ul0gic@172.16.150.253}"
if [ $# -gt 0 ]; then shift; fi
if [ "${1:-}" = "--" ]; then shift; fi
REMOTE_ARGS=("$@")

TGT_TRIPLE="x86_64-linux-musl"
SSH_KEY="${F2Z_SSH_KEY:-$HOME/.ssh/id_ed25519_p33ker}"
# Self-ban guard — never offer agent keys to the lab VM, or fail2zig's sshd
# jail bans the operator. IdentitiesOnly + publickey-only is mandatory;
# accept-new avoids a host-key prompt on the first run against a fresh box.
SSH_OPTS=(-i "$SSH_KEY" -o IdentitiesOnly=yes -o PreferredAuthentications=publickey -o StrictHostKeyChecking=accept-new)

REMOTE_DIR="/tmp/fail2zig-e2e"

# 1. Build the ReleaseSafe static-musl artifact HERE (the target has no zig).
echo "run-remote: building ReleaseSafe ${TGT_TRIPLE} on the dev box" >&2
( cd "$REPO_ROOT" && zig build -Dtarget="$TGT_TRIPLE" -Doptimize=ReleaseSafe )
[ -x "${REPO_ROOT}/zig-out/bin/fail2zig" ] || { echo "run-remote: build produced no fail2zig binary" >&2; exit 1; }
[ -x "${REPO_ROOT}/zig-out/bin/fail2zig-client" ] || { echo "run-remote: build produced no fail2zig-client binary" >&2; exit 1; }

# 2. Sync the repo + freshly built binaries to the target. Exclude only the
#    VCS dir and the build cache — zig-out IS shipped so the remote can
#    install via --local-bin without a toolchain on the target.
echo "run-remote: syncing repo + zig-out to ${TARGET}:${REMOTE_DIR}" >&2
rsync -az --delete \
  -e "ssh ${SSH_OPTS[*]}" \
  --exclude '.git' --exclude '.zig-cache' --exclude 'zig-cache' \
  "${REPO_ROOT}/" "${TARGET}:${REMOTE_DIR}/"

# 3. Run the harness on the target against the pre-built binaries — NOT
#    --build (the target has no zig). Any extra args (e.g. --purge, --force)
#    are forwarded verbatim.
echo "run-remote: running deploy_regression.sh --local-bin on target" >&2
ssh "${SSH_OPTS[@]}" "$TARGET" \
  "sudo bash ${REMOTE_DIR}/tests/e2e/deploy_regression.sh --local-bin ${REMOTE_DIR}/zig-out/bin ${REMOTE_ARGS[*]}"
