#!/usr/bin/env bash
# tests/e2e/deploy_status_honesty.sh — status-HONESTY-surface regression
# harness (SYS-017 #35, BUG-006 #36).
#
# The sibling of deploy_regression.sh. Where that script asserts the
# DEPLOYMENT invariants (ownership / socket / group auth — the SYS-018/019
# surface), THIS script asserts the STATUS-HONESTY surface that both
# SYS-017 and BUG-006 reached a live box without anything catching:
#
#   A. `Total bans` and `Jails` rollups are POPULATED (real numbers, not "-").
#   B. Per-jail SOURCE matches the daemon's OWN resolved `source=` log line —
#      a jail the daemon resolved to journald shows `journald (...)` in the
#      status surface and NEVER its config file logpath (the SYS-017
#      source-label divergence: config guessed /var/log/auth.log, runtime
#      resolved journald on a journald-only box).
#   C. After `systemctl restart`, `Total bans >= Active bans` — the BUG-006
#      reset (process counter zeroed on restart while restored bans count as
#      Active) is gone; the persisted lifetime keeps Total >= Active.
#
# Why this exists: zig fmt / zig build / zig build test NEVER drive a real
# ban through a real journald round-trip, never restart a real daemon, and
# never read the rendered status surface. Both bugs were invisible to them
# and to deploy_regression.sh (which never bans or restarts). Only a real
# systemd box running the real unit, driven through a real ban + restart,
# exercises this. This harness is that.
#
# MUST run as root on a real systemd host with journald (a journald-only
# box is the highest-fidelity target — that is where SYS-017 surfaced).
# NOT part of `zig build test` — HARNESS ONLY (run on f2z-target by Lead),
# like deploy_regression.sh and tests/harness/. See tests/e2e/README.md.
#
# Usage:
#   sudo tests/e2e/deploy_status_honesty.sh [--build] [--local-bin DIR]
#                                           [--jail NAME] [--purge] [--force]
#
#   --build        Cross-build ReleaseSafe musl into zig-out/bin first.
#   --local-bin D  Directory holding prebuilt binaries (default: zig-out/bin).
#   --jail NAME    The journald-resolved jail to drive a ban on
#                  (default: sshd — the shipped config's auto/journald jail).
#   --purge        On exit, remove installed artifacts + the test user/group.
#   --force        Run even if a fail2zig service is already active.
#
# Exit 0 = all status-honesty assertions passed. Non-zero = first failure.

set -euo pipefail

# --- config -------------------------------------------------------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

UNIT="fail2zig.service"
CLIENT="/usr/local/bin/fail2zig-client"
GRP="fail2zig"
TARGET="x86_64-linux-musl"

# The jail we drive a ban on. The shipped config's sshd jail is source=auto
# with a file logpath; on a journald-only box it RESOLVES to journald — the
# exact SYS-017 divergence subject.
JAIL="sshd"
# A test attacker IP outside any local/lab range — never a real client.
ATTACKER="203.0.113.171"

DO_BUILD=0
LOCAL_BIN="zig-out/bin"
DO_PURGE=0
FORCE=0
CREATED_GROUP=0

log()  { printf 'e2e: %s\n' "$*" >&2; }
pass() { printf 'e2e: PASS  %s\n' "$*" >&2; }
fail() { printf 'e2e: FAIL  %s\n' "$*" >&2; dump_journal; exit 1; }

# --- args ---------------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --build)      DO_BUILD=1; shift ;;
    --local-bin)  [ $# -ge 2 ] || { echo "e2e: --local-bin needs arg" >&2; exit 2; }
                  LOCAL_BIN="$2"; shift 2 ;;
    --jail)       [ $# -ge 2 ] || { echo "e2e: --jail needs arg" >&2; exit 2; }
                  JAIL="$2"; shift 2 ;;
    --purge)      DO_PURGE=1; shift ;;
    --force)      FORCE=1; shift ;;
    -h|--help)    sed -n '2,49p' "$0"; exit 0 ;;
    *)            echo "e2e: unknown arg: $1" >&2; exit 2 ;;
  esac
done

# --- preflight ----------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || { echo "e2e: must run as root" >&2; exit 2; }
command -v systemctl  >/dev/null 2>&1 || { echo "e2e: no systemctl — not a systemd host" >&2; exit 2; }
command -v journalctl >/dev/null 2>&1 || { echo "e2e: journalctl required (journald target)" >&2; exit 2; }
command -v logger     >/dev/null 2>&1 || { echo "e2e: logger required to inject journald events" >&2; exit 2; }

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

# --- journal scoping (CURRENT invocation only, never -b) ---------------------
current_invocation() { systemctl show -p InvocationID --value "$UNIT" 2>/dev/null; }
journal_slice()      { journalctl _SYSTEMD_INVOCATION_ID="$(current_invocation)" --no-pager 2>/dev/null || true; }

dump_journal() {
  local inv; inv="$(current_invocation)"
  if [ -n "$inv" ]; then
    log "----- journal for invocation $inv -----"
    journalctl _SYSTEMD_INVOCATION_ID="$inv" --no-pager 2>/dev/null | sed 's/^/e2e:   /' >&2 || true
  fi
}

# --- teardown -----------------------------------------------------------------
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

# --- helpers ------------------------------------------------------------------

# Inject N failed-sshd auth lines into journald under SYSLOG_IDENTIFIER=sshd
# (one of the identifiers the daemon's journald reader matches). This is a
# REAL journald round-trip: the daemon's `journalctl --after-cursor` poll
# picks these up exactly as it would real sshd failures.
inject_sshd_failures() {
  local ip="$1" n="$2" port=20000
  for _ in $(seq 1 "$n"); do
    logger -t sshd "Failed password for root from ${ip} port ${port} ssh2"
    port=$((port + 1))
  done
}

# `fail2zig-client status --output plain` field by key (tab-separated).
status_field() { "$CLIENT" status --output plain 2>/dev/null | awk -F'\t' -v k="$1" '$1==k{print $2; exit}'; }

# The SOURCE (log_source) column for a jail from `jails --output plain`.
# Plain jail columns: name enabled active maxretry findtime bantime action
#                     enforcing LOG_SOURCE source_healthy lines_seen
jail_source() { "$CLIENT" jails --output plain 2>/dev/null | awk -F'\t' -v j="$1" '$1==j{print $9; exit}'; }

# Active bans for a jail (3rd plain column).
jail_active() { "$CLIENT" jails --output plain 2>/dev/null | awk -F'\t' -v j="$1" '$1==j{print $3; exit}'; }

# Wait (bounded) for the named jail to show >=1 active ban.
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

# --- build (optional) + install ----------------------------------------------
if [ "$DO_BUILD" -eq 1 ]; then
  command -v zig >/dev/null 2>&1 || { echo "e2e: --build needs zig on PATH" >&2; exit 2; }
  log "building ReleaseSafe ${TARGET}"
  ( cd "$REPO_ROOT" && zig build -Dtarget="$TARGET" -Doptimize=ReleaseSafe )
  LOCAL_BIN="${REPO_ROOT}/zig-out/bin"
fi
[ -x "${LOCAL_BIN}/fail2zig" ]        || { echo "e2e: missing ${LOCAL_BIN}/fail2zig" >&2; exit 2; }
[ -x "${LOCAL_BIN}/fail2zig-client" ] || { echo "e2e: missing ${LOCAL_BIN}/fail2zig-client" >&2; exit 2; }

log "installing via scripts/install.sh --local-bin ${LOCAL_BIN}"
"${REPO_ROOT}/scripts/install.sh" --local-bin "$LOCAL_BIN"
if ! cmp -s "${REPO_ROOT}/deploy/fail2zig.service" /etc/systemd/system/fail2zig.service; then
  fail "installed unit differs from deploy/fail2zig.service (drop-in or edit detected)"
fi

systemctl daemon-reload
log "starting $UNIT"
systemctl start "$UNIT" || fail "systemctl start failed"
settle_ready || fail "service active but IPC never became ready"
pass "service active, IPC ready"

# === ASSERTION B: per-jail SOURCE matches the daemon's resolved source= line ==
# Read the daemon's OWN resolution decision for $JAIL from its journal, then
# require the status SOURCE column to agree. This is the SYS-017 divergence
# guard: the surface must follow RESOLVED truth, not the config guess.
INV_LINE="$(journal_slice | grep -E "jail: enabled '${JAIL}' source=" | tail -1)"
[ -n "$INV_LINE" ] || fail "no 'jail: enabled ${JAIL} source=' resolution line in journal"
SRC_COL="$(jail_source "$JAIL")"
[ -n "$SRC_COL" ] || fail "jail '${JAIL}' missing from 'jails' output"

if printf '%s' "$INV_LINE" | grep -q "source=journald"; then
  # Daemon resolved journald → SOURCE must say journald, and must NOT be a
  # config file logpath (the auth.log divergence).
  printf '%s' "$SRC_COL" | grep -q "journald" || \
    fail "daemon resolved ${JAIL} to journald but SOURCE column is '${SRC_COL}' (divergence)"
  case "$SRC_COL" in
    /*) fail "SOURCE for journald-resolved ${JAIL} is a file path '${SRC_COL}' — config logpath leaked" ;;
  esac
  pass "SOURCE for ${JAIL} follows resolved journald ('${SRC_COL}'), no config-path leak"
elif printf '%s' "$INV_LINE" | grep -q "source=file"; then
  # Daemon resolved a file source → SOURCE must be a path, never "unknown".
  [ "$SRC_COL" != "unknown" ] || fail "file-resolved ${JAIL} shows SOURCE 'unknown' (should be its path)"
  [ "$SRC_COL" != "-" ]       || fail "file-resolved ${JAIL} shows empty SOURCE"
  pass "SOURCE for file-resolved ${JAIL} is a path ('${SRC_COL}'), not unknown"
else
  fail "could not classify ${JAIL} resolution from journal line: ${INV_LINE}"
fi

# === drive a real ban through a real journald round-trip ======================
log "injecting ${JAIL} auth failures for ${ATTACKER} (real journald round-trip)"
inject_sshd_failures "$ATTACKER" 8
wait_for_ban "$JAIL" || fail "no active ban on ${JAIL} after injecting failures (source not reading?)"
pass "drove a real ban on ${JAIL}"

# === ASSERTION A: Total bans / Jails rollups are POPULATED ====================
TOTAL_PRE="$(status_field total_bans)"
ACTIVE_PRE="$(status_field active_bans)"
JAILS_PRE="$(status_field jails_active)"
[ -n "$TOTAL_PRE" ]  || fail "status 'total_bans' missing/empty (rollup not populated — SYS-017 repro)"
[ -n "$JAILS_PRE" ]  || fail "status 'jails_active' missing/empty (rollup not populated — SYS-017 repro)"
[ "$JAILS_PRE" -ge 1 ] 2>/dev/null || fail "jails_active=${JAILS_PRE} (expected >=1)"
[ "$TOTAL_PRE" -ge 1 ] 2>/dev/null || fail "total_bans=${TOTAL_PRE} after a ban (expected >=1)"
pass "rollups populated: total_bans=${TOTAL_PRE} active_bans=${ACTIVE_PRE} jails_active=${JAILS_PRE}"

# === ASSERTION C: after systemctl restart, Total bans >= Active bans ==========
# BUG-006: the process ban counter zeroed on restart while restored bans
# counted as Active → Total < Active. The persisted lifetime must keep
# Total >= Active across the restart.
log "restarting $UNIT (BUG-006: Total must persist and stay >= Active)"
systemctl restart "$UNIT" || fail "systemctl restart failed"
settle_ready || fail "service did not become ready after restart"
# Give the state-load path a brief moment.
sleep 1

TOTAL_POST="$(status_field total_bans)"
ACTIVE_POST="$(status_field active_bans)"
[ -n "$TOTAL_POST" ]  || fail "status 'total_bans' missing after restart"
[ -n "$ACTIVE_POST" ] || fail "status 'active_bans' missing after restart"
# The restored ban must still be active …
[ "$ACTIVE_POST" -ge 1 ] 2>/dev/null || fail "active_bans=${ACTIVE_POST} after restart (ban not restored?)"
# … and the headline invariant: Total >= Active (the BUG-006 fix).
if [ "$TOTAL_POST" -lt "$ACTIVE_POST" ] 2>/dev/null; then
  fail "BUG-006 regression: total_bans=${TOTAL_POST} < active_bans=${ACTIVE_POST} after restart"
fi
# … and lifetime did not reset to zero.
[ "$TOTAL_POST" -ge 1 ] 2>/dev/null || fail "total_bans reset to ${TOTAL_POST} on restart (BUG-006)"
pass "after restart: total_bans=${TOTAL_POST} >= active_bans=${ACTIVE_POST}, lifetime persisted"

log "ALL STATUS-HONESTY ASSERTIONS PASSED"
exit 0
