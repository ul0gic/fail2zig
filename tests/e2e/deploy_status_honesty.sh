#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

UNIT="fail2zig.service"
CLIENT="/usr/local/bin/fail2zig"
GRP="fail2zig"
TARGET="x86_64-linux-musl"

JAIL="sshd"
ATTACKER="203.0.113.171"

DO_BUILD=0
SKIP_INSTALL=0
LOCAL_BIN="zig-out/bin"
DO_PURGE=0
FORCE=0
CREATED_GROUP=0

log()  { printf 'e2e: %s\n' "$*" >&2; }
pass() { printf 'e2e: PASS  %s\n' "$*" >&2; }
fail() { printf 'e2e: FAIL  %s\n' "$*" >&2; dump_journal; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --build)      DO_BUILD=1; shift ;;
    --local-bin)  [ $# -ge 2 ] || { echo "e2e: --local-bin needs arg" >&2; exit 2; }
                  LOCAL_BIN="$2"; shift 2 ;;
    --skip-install) SKIP_INSTALL=1; shift ;;
    --jail)       [ $# -ge 2 ] || { echo "e2e: --jail needs arg" >&2; exit 2; }
                  JAIL="$2"; shift 2 ;;
    --purge)      DO_PURGE=1; shift ;;
    --force)      FORCE=1; shift ;;
    -h|--help)    printf '%s\n' 'Usage: sudo tests/e2e/deploy_status_honesty.sh [--build] [--local-bin DIR] [--skip-install] [--jail NAME] [--purge] [--force]'; exit 0 ;;
    *)            echo "e2e: unknown arg: $1" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "e2e: must run as root" >&2; exit 2; }
command -v systemctl  >/dev/null 2>&1 || { echo "e2e: no systemctl — not a systemd host" >&2; exit 2; }
command -v journalctl >/dev/null 2>&1 || { echo "e2e: journalctl required (journald target)" >&2; exit 2; }

arch="$(uname -m)"
if [ "$arch" != "x86_64" ] && [ "$arch" != "amd64" ]; then
  echo "e2e: harness targets x86_64 (${TARGET}); host is $arch" >&2
  exit 2
fi

if systemctl is-active --quiet "$UNIT" && [ "$FORCE" -ne 1 ]; then
  echo "e2e: $UNIT already active — refusing to clobber (use --force)" >&2
  exit 2
fi

if ! getent group "$GRP" >/dev/null 2>&1; then
  CREATED_GROUP=1
fi

current_invocation() { systemctl show -p InvocationID --value "$UNIT" 2>/dev/null; }

dump_journal() {
  local inv; inv="$(current_invocation)"
  if [ -n "$inv" ]; then
    log "----- journal for invocation $inv -----"
    journalctl _SYSTEMD_INVOCATION_ID="$inv" --no-pager 2>/dev/null | sed 's/^/e2e:   /' >&2 || true
  fi
}

cleanup() {
  set +e
  systemctl stop "$UNIT" >/dev/null 2>&1
  if [ "$DO_PURGE" -eq 1 ]; then
    systemctl disable "$UNIT" >/dev/null 2>&1
    rm -f /usr/local/bin/fail2zig /usr/local/bin/fail2zig-client
    rm -f /etc/systemd/system/fail2zig.service
    rm -rf /run/fail2zig /var/lib/fail2zig
    if [ "$CREATED_GROUP" -eq 1 ]; then groupdel "$GRP" >/dev/null 2>&1; fi
    systemctl daemon-reload >/dev/null 2>&1
    log "purged installed artifacts"
  fi
}
trap cleanup EXIT


status_field() { "$CLIENT" status --output plain 2>/dev/null | awk -F'\t' -v k="$1" '$1==k{print $2; exit}'; }

jail_source() { "$CLIENT" jails --output plain 2>/dev/null | awk -F'\t' -v j="$1" '$1==j{print $9; exit}'; }

jail_active() { "$CLIENT" jails --output plain 2>/dev/null | awk -F'\t' -v j="$1" '$1==j{print $3; exit}'; }

wait_for_ban() {
  local jail="$1"
  for _ in $(seq 1 60); do
    local a; a="$(jail_active "$jail")"
    if [ -n "$a" ] && [ "$a" -ge 1 ] 2>/dev/null; then return 0; fi
    sleep 0.5
  done
  return 1
}

settle_ready() {
  for _ in $(seq 1 50); do
    if systemctl is-active --quiet "$UNIT" && "$CLIENT" status >/dev/null 2>&1; then return 0; fi
    sleep 0.1
  done
  return 1
}

if [ "$DO_BUILD" -eq 1 ]; then
  command -v zig >/dev/null 2>&1 || { echo "e2e: --build needs zig on PATH" >&2; exit 2; }
  log "building ReleaseSafe ${TARGET}"
  ( cd "$REPO_ROOT" && zig build -Dtarget="$TARGET" -Doptimize=ReleaseSafe )
  LOCAL_BIN="${REPO_ROOT}/zig-out/bin"
fi
[ -x "${LOCAL_BIN}/fail2zig" ]        || { echo "e2e: missing ${LOCAL_BIN}/fail2zig" >&2; exit 2; }

if [ "$SKIP_INSTALL" -eq 0 ]; then
  log "installing via scripts/install.sh --local-bin ${LOCAL_BIN}"
  "${REPO_ROOT}/scripts/install.sh" --local-bin "$LOCAL_BIN"
else
  log "using the release gate's existing candidate installation"
fi
if ! cmp -s "${REPO_ROOT}/deploy/fail2zig.service" /etc/systemd/system/fail2zig.service; then
  fail "installed unit differs from deploy/fail2zig.service (drop-in or edit detected)"
fi

systemctl daemon-reload
log "starting $UNIT"
systemctl start "$UNIT" || fail "systemctl start failed"
settle_ready || fail "service active but IPC never became ready"
pass "service active, IPC ready"

SRC_COL="$(jail_source "$JAIL")"
[ -n "$SRC_COL" ] || fail "jail '${JAIL}' missing from 'jails' output"
printf '%s' "$SRC_COL" | grep -qx "journal" || \
  fail "configured journald jail ${JAIL} reports SOURCE '${SRC_COL}' instead of 'journal'"
case "$SRC_COL" in
  /*) fail "SOURCE for journald-configured ${JAIL} is a file path '${SRC_COL}' — config logpath leaked" ;;
esac
pass "SOURCE for ${JAIL} reports journal, no config-path leak"

log "applying a typed manual ban on ${JAIL}"
"$CLIENT" ban "$ATTACKER" --jail "$JAIL" --duration 60 >/dev/null || fail "manual ban failed"
wait_for_ban "$JAIL" || fail "manual ban did not become active on ${JAIL}"
pass "drove a typed ban on ${JAIL}"

TOTAL_PRE="$(status_field total_bans)"
ACTIVE_PRE="$(status_field active_bans)"
JAILS_PRE="$(status_field jails_active)"
[ -n "$TOTAL_PRE" ]  || fail "status 'total_bans' missing/empty (rollup not populated — SYS-017 repro)"
[ -n "$JAILS_PRE" ]  || fail "status 'jails_active' missing/empty (rollup not populated — SYS-017 repro)"
[ "$JAILS_PRE" -ge 1 ] 2>/dev/null || fail "jails_active=${JAILS_PRE} (expected >=1)"
[ "$TOTAL_PRE" -ge 1 ] 2>/dev/null || fail "total_bans=${TOTAL_PRE} after a ban (expected >=1)"
pass "rollups populated: total_bans=${TOTAL_PRE} active_bans=${ACTIVE_PRE} jails_active=${JAILS_PRE}"

log "restarting $UNIT (BUG-006: Total must persist and stay >= Active)"
systemctl restart "$UNIT" || fail "systemctl restart failed"
settle_ready || fail "service did not become ready after restart"
sleep 1

TOTAL_POST="$(status_field total_bans)"
ACTIVE_POST="$(status_field active_bans)"
[ -n "$TOTAL_POST" ]  || fail "status 'total_bans' missing after restart"
[ -n "$ACTIVE_POST" ] || fail "status 'active_bans' missing after restart"
[ "$ACTIVE_POST" -ge 1 ] 2>/dev/null || fail "active_bans=${ACTIVE_POST} after restart (ban not restored?)"
if [ "$TOTAL_POST" -lt "$ACTIVE_POST" ] 2>/dev/null; then
  fail "BUG-006 regression: total_bans=${TOTAL_POST} < active_bans=${ACTIVE_POST} after restart"
fi
[ "$TOTAL_POST" -ge 1 ] 2>/dev/null || fail "total_bans reset to ${TOTAL_POST} on restart (BUG-006)"
pass "after restart: total_bans=${TOTAL_POST} >= active_bans=${ACTIVE_POST}, lifetime persisted"

log "ALL STATUS-HONESTY ASSERTIONS PASSED"
exit 0
