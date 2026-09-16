#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
TARGET="${1:-ul0gic@172.16.150.253}"
[ $# -eq 0 ] || shift
[ "${1:-}" != -- ] || shift
[[ "$TARGET" != -* ]] || exit 2
HOLD_SECONDS=0
while [ $# -gt 0 ]; do
    case "$1" in
        --force) shift ;;
        --hold-seconds) HOLD_SECONDS="${2:?missing hold duration}"; shift 2 ;;
        *) echo "usage: run-remote.sh [user@host] [-- --hold-seconds N]" >&2; exit 2 ;;
    esac
done
[[ "$HOLD_SECONDS" =~ ^[0-9]+$ ]] && [ "$HOLD_SECONDS" -le 120 ] || exit 2
SSH_KEY="${F2Z_SSH_KEY:-$HOME/.ssh/id_ed25519_p33ker}"
SSH_OPTS=(-i "$SSH_KEY" -o IdentitiesOnly=yes -o PreferredAuthentications=publickey -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new)
BUILD_DIR="$(mktemp -d /tmp/fail2zig-gate-build.XXXXXX)"
(cd "$REPO_ROOT" && zig build -Dtarget=x86_64-linux-musl -Doptimize=ReleaseSafe --prefix "$BUILD_DIR")
(cd "$REPO_ROOT" && zig build test-release-lifecycle -Dtarget=x86_64-linux-musl -Doptimize=ReleaseSafe --prefix "$BUILD_DIR")
REMOTE_DIR="$(ssh "${SSH_OPTS[@]}" "$TARGET" 'mktemp -d /tmp/fail2zig-e2e.XXXXXX')"
[[ "$REMOTE_DIR" =~ ^/tmp/fail2zig-e2e\.[a-zA-Z0-9]+$ ]] || exit 1
printf 'run-remote: artifacts=%s target=%s:%s\n' "$BUILD_DIR" "$TARGET" "$REMOTE_DIR"
tar -C "$REPO_ROOT" -czf - deploy scripts tests/e2e -C "$BUILD_DIR" bin |
    ssh "${SSH_OPTS[@]}" "$TARGET" "tar -xzf - -C '$REMOTE_DIR'"
ssh "${SSH_OPTS[@]}" "$TARGET" "sudo bash '$REMOTE_DIR/tests/e2e/release_gate.sh' '$REMOTE_DIR/bin' '$HOLD_SECONDS'"
