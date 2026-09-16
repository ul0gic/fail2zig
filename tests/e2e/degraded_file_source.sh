#!/usr/bin/env bash
set -euo pipefail
ORIGINAL_ARGS=("$@")

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

TARGET="x86_64-linux-musl"
DO_BUILD=0
LOCAL_BIN="zig-out/bin"
KEEP=0

ATTACKER="203.0.113.200"

log()  { printf 'e2e: %s\n' "$*" >&2; }
pass() { printf 'e2e: PASS  %s\n' "$*" >&2; }
fail() { printf 'e2e: FAIL  %s\n' "$*" >&2; dump_daemon_log; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --build)     DO_BUILD=1; shift ;;
    --local-bin) [ $# -ge 2 ] || { echo "e2e: --local-bin needs arg" >&2; exit 2; }
                 LOCAL_BIN="$2"; shift 2 ;;
    --keep)      KEEP=1; shift ;;
    -h|--help)   printf '%s\n' 'Usage: sudo tests/e2e/degraded_file_source.sh [--build] [--local-bin DIR] [--keep]'; exit 0 ;;
    *)           echo "e2e: unknown arg: $1" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "e2e: must run as root (enforcing jail needs CAP_NET_ADMIN)" >&2; exit 2; }

if [ "$(readlink /proc/self/ns/net)" = "$(readlink /proc/1/ns/net)" ]; then
  exec unshare --net bash -c 'ip link set lo up; exec bash "$@"' _ "$0" "${ORIGINAL_ARGS[@]}"
fi

if [ "$DO_BUILD" -eq 1 ]; then
  command -v zig >/dev/null 2>&1 || { echo "e2e: --build needs zig on PATH" >&2; exit 2; }
  log "building ReleaseSafe ${TARGET}"
  ( cd "$REPO_ROOT" && zig build -Dtarget="$TARGET" -Doptimize=ReleaseSafe )
  LOCAL_BIN="${REPO_ROOT}/zig-out/bin"
fi
DAEMON="${LOCAL_BIN}/fail2zig"
CLIENT="${LOCAL_BIN}/fail2zig"
[ -x "$DAEMON" ] || { echo "e2e: missing ${DAEMON}" >&2; exit 2; }
[ -x "$CLIENT" ] || { echo "e2e: missing ${CLIENT}" >&2; exit 2; }

WORK="$(mktemp -d /tmp/f2z-rotation.XXXXXX)"
SOCK="${WORK}/fail2zig.sock"
STATE="${WORK}/state.bin"
CONF="${WORK}/config.toml"
DLOG="${WORK}/daemon.log"
LOG_ROTATING="${WORK}/rotating.log"
DPID=""

dump_daemon_log() {
  if [ -f "$DLOG" ]; then
    log "----- daemon log -----"
    sed 's/^/e2e:   /' "$DLOG" >&2 || true
  fi
}

cleanup() {
  set +e
  if [ -n "$DPID" ] && kill -0 "$DPID" 2>/dev/null; then
    kill -TERM "$DPID" 2>/dev/null
    for _ in $(seq 1 20); do kill -0 "$DPID" 2>/dev/null || break; sleep 0.1; done
    kill -KILL "$DPID" 2>/dev/null
  fi
  if [ "$KEEP" -eq 1 ]; then
    log "kept workdir: $WORK"
  else
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

cat > "$CONF" <<EOF
[global]
socket_path = "${SOCK}"
state_file  = "${STATE}"
metrics_enabled = false

[defaults]
banaction = "nftables"
maxretry  = 3
findtime  = 600
bantime   = 600

[jails.rotating]
enabled = true
filter  = "sshd"
source  = "file"
timestamp = "undated"
logpath = ["${LOG_ROTATING}"]
EOF

: > "$LOG_ROTATING"

csock() { "$CLIENT" --socket "$SOCK" "$@"; }
status_field() { csock status --output plain 2>/dev/null | awk -F'\t' -v k="$1" '$1==k{print $2; exit}'; }
jail_field() { csock jails --output plain 2>/dev/null | awk -F'\t' -v j="$1" -v n="$2" '$1==j{print $n; exit}'; }

inject_failures() {
  local logfile="$1" ip="$2" n="$3" port=20000
  for _ in $(seq 1 "$n"); do
    printf 'Failed password for root from %s port %d ssh2\n' "$ip" "$port" >> "$logfile"
    port=$((port + 1))
  done
}

settle_ready() {
  for _ in $(seq 1 100); do
    if [ "$(status_field protection)" = "active" ]; then return 0; fi
    sleep 0.1
  done
  return 1
}

log "starting daemon (foreground) on throwaway socket ${SOCK}"
"$DAEMON" --config "$CONF" --foreground >"$DLOG" 2>&1 &
DPID=$!
settle_ready || fail "daemon did not become ready (check daemon log — firewall backend may be unavailable)"
pass "daemon ready"

[ "$(jail_field rotating 9)" = "file" ] || fail "rotating jail did not report typed source 'file'"
[ "$(jail_field rotating 10)" = "healthy" ] || fail "rotating jail was not healthy before rotation"
pass "file source active and healthy before rotation"

log "rotating file and writing failures to the replacement"
mv "$LOG_ROTATING" "${LOG_ROTATING}.1"
: > "$LOG_ROTATING"
inject_failures "$LOG_ROTATING" "$ATTACKER" 5

reopened=0
for _ in $(seq 1 60); do
  active="$(jail_field rotating 3)"
  healthy="$(jail_field rotating 10)"
  if [ -n "$active" ] && [ "$active" -ge 1 ] 2>/dev/null && [ "$healthy" = "healthy" ]; then
    reopened=1
    break
  fi
  sleep 0.2
done
[ "$reopened" -eq 1 ] || fail "replacement file was not reopened and enforced"
csock list --output json | grep -q '"confirmed":true' || fail "post-rotation ban was not confirmed"
[ "$(status_field protection)" = "active" ] || fail "protection not active after rotation/reopen"
pass "rotation/reopen consumed replacement records and confirmed enforcement"

log "ALL FILE ROTATION/REOPEN ASSERTIONS PASSED"
exit 0
