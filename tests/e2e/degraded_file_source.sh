#!/usr/bin/env bash
# tests/e2e/degraded_file_source.sh — ENH-004 file-source DEGRADED-flip
# regression harness (ENH-004 #?? / v0.2.2).
#
# The third status-surface e2e harness. deploy_regression.sh asserts the
# DEPLOYMENT invariants; deploy_status_honesty.sh asserts the rollup /
# resolved-source / persisted-lifetime surface (SYS-017, BUG-006). THIS
# script asserts the one thing neither covers and that `zig build test`
# can only approximate in-process: a real, ENFORCING, FILE-source jail
# whose log breaks AFTER it was reading flips the live status surface to
# DEGRADED and drops its Prometheus health gauge to 0 — without
# false-flagging a quiet-but-healthy file jail or flashing DEGRADED for a
# log that never appeared.
#
#   (a) a tailing file jail whose logpath is MOVED AWAY after it read →
#       `protection` flips to `degraded` and
#       `fail2zig_jail_log_source_healthy{jail=breakable} 0`, AFTER the
#       ~2s detach debounce.
#   (b) a quiet healthy file jail (attached, never written) stays NOT
#       degraded and its gauge stays 1 — no false flag.
#   (c) rotation flicker (move-away then same-name recreate within the
#       debounce) does NOT flip degraded.
#   (d) a never-appeared (boot/late) logpath does NOT flash degraded and
#       does NOT count as a hard-unhealthy source.
#
# Why this exists: the ENH-004 verdict is proven in isolation by inline
# `healthForJail` tests, and the in-process end-to-end chain (real watcher
# → adapter → computeOverallState → metrics) is proven by the engine
# `ENH-004 e2e:` tests. But neither runs the SHIPPED binary, against a
# REAL inotify break, through the REAL IPC + HTTP surfaces, under the 2s
# wall-clock debounce. Only this does. f2z-target is journald-only, so the
# file jail is configured EXPLICITLY here with throwaway logpaths.
#
# SELF-CONTAINED: this harness does NOT use systemd, does NOT touch
# /etc/fail2zig, /run/fail2zig, or /var/lib/fail2zig. It runs the real
# binary in --foreground on a throwaway socket / state / config under a
# temp dir, so it never clobbers operator state and runs on ANY Linux root
# box (not only a systemd host). It DOES require CAP_NET_ADMIN (root): a
# DEGRADED flip needs an ENFORCING jail, and an enforcing jail fails
# closed without a usable firewall backend (principle #5).
#
# Usage:
#   sudo tests/e2e/degraded_file_source.sh [--build] [--local-bin DIR] [--keep]
#
#   --build        Cross-build ReleaseSafe musl into zig-out/bin first.
#   --local-bin D  Directory holding prebuilt binaries (default: zig-out/bin).
#   --keep         Leave the temp workdir in place on exit (for debugging).
#
# Exit 0 = all ENH-004 file-source assertions passed. Non-zero = first failure.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

TARGET="x86_64-linux-musl"
DO_BUILD=0
LOCAL_BIN="zig-out/bin"
KEEP=0

# A test attacker IP outside any local/lab range — never a real client.
ATTACKER="203.0.113.200"
# HTTP metrics endpoint the harness config binds.
METRICS_BIND="127.0.0.1"
METRICS_PORT="19199"
# Debounce is 2s (detach_debounce_s in log_watcher.zig); wait past it.
DEBOUNCE_WAIT=4

log()  { printf 'e2e: %s\n' "$*" >&2; }
pass() { printf 'e2e: PASS  %s\n' "$*" >&2; }
fail() { printf 'e2e: FAIL  %s\n' "$*" >&2; dump_daemon_log; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --build)     DO_BUILD=1; shift ;;
    --local-bin) [ $# -ge 2 ] || { echo "e2e: --local-bin needs arg" >&2; exit 2; }
                 LOCAL_BIN="$2"; shift 2 ;;
    --keep)      KEEP=1; shift ;;
    -h|--help)   sed -n '2,57p' "$0"; exit 0 ;;
    *)           echo "e2e: unknown arg: $1" >&2; exit 2 ;;
  esac
done

# --- preflight ----------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || { echo "e2e: must run as root (enforcing jail needs CAP_NET_ADMIN)" >&2; exit 2; }
command -v curl >/dev/null 2>&1 || { echo "e2e: curl required to read /metrics" >&2; exit 2; }

# --- build (optional) ---------------------------------------------------------
if [ "$DO_BUILD" -eq 1 ]; then
  command -v zig >/dev/null 2>&1 || { echo "e2e: --build needs zig on PATH" >&2; exit 2; }
  log "building ReleaseSafe ${TARGET}"
  ( cd "$REPO_ROOT" && zig build -Dtarget="$TARGET" -Doptimize=ReleaseSafe )
  LOCAL_BIN="${REPO_ROOT}/zig-out/bin"
fi
DAEMON="${LOCAL_BIN}/fail2zig"
CLIENT="${LOCAL_BIN}/fail2zig-client"
[ -x "$DAEMON" ] || { echo "e2e: missing ${DAEMON}" >&2; exit 2; }
[ -x "$CLIENT" ] || { echo "e2e: missing ${CLIENT}" >&2; exit 2; }

# --- throwaway workdir --------------------------------------------------------
WORK="$(mktemp -d /tmp/f2z-enh004.XXXXXX)"
SOCK="${WORK}/fail2zig.sock"
STATE="${WORK}/state.bin"
CONF="${WORK}/config.toml"
DLOG="${WORK}/daemon.log"
LOG_BREAK="${WORK}/breakable.log"
LOG_QUIET="${WORK}/quiet.log"
LOG_LATE="${WORK}/late.log"   # deliberately NOT created — never-appeared
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

# --- config: enforcing FILE-source jails -------------------------------------
# breakable + quiet are enforcing file jails (banaction nftables). late points
# at a logpath that never appears. The sshd filter matches the lines we write.
cat > "$CONF" <<EOF
[global]
socket_path = "${SOCK}"
state_file  = "${STATE}"
metrics_bind = "${METRICS_BIND}"
metrics_port = ${METRICS_PORT}

[defaults]
banaction = "nftables"
maxretry  = 3
findtime  = 600
bantime   = 600

[jails.breakable]
enabled = true
filter  = "sshd"
source  = "file"
logpath = ["${LOG_BREAK}"]

[jails.quiet]
enabled = true
filter  = "sshd"
source  = "file"
logpath = ["${LOG_QUIET}"]

[jails.late]
enabled = true
filter  = "sshd"
source  = "file"
logpath = ["${LOG_LATE}"]
EOF

# breakable + quiet exist at startup; late does NOT.
: > "$LOG_BREAK"
: > "$LOG_QUIET"

# --- client / metrics helpers -------------------------------------------------
csock() { "$CLIENT" --socket "$SOCK" "$@"; }
status_field() { csock status --output plain 2>/dev/null | awk -F'\t' -v k="$1" '$1==k{print $2; exit}'; }
metrics() { curl -fsS "http://${METRICS_BIND}:${METRICS_PORT}/metrics" 2>/dev/null || true; }
gauge() { metrics | awk -v j="fail2zig_jail_log_source_healthy{jail=\"$1\"}" '$1==j{print $2; exit}'; }
protection() { status_field protection; }

inject_failures() {
  local logfile="$1" ip="$2" n="$3" port=20000
  for _ in $(seq 1 "$n"); do
    printf 'Failed password for root from %s port %d ssh2\n' "$ip" "$port" >> "$logfile"
    port=$((port + 1))
  done
}

settle_ready() {
  for _ in $(seq 1 100); do
    if csock status >/dev/null 2>&1; then return 0; fi
    sleep 0.1
  done
  return 1
}

# --- start the daemon ---------------------------------------------------------
log "starting daemon (foreground) on throwaway socket ${SOCK}"
"$DAEMON" --config "$CONF" --foreground >"$DLOG" 2>&1 &
DPID=$!
settle_ready || fail "daemon did not become ready (check daemon log — firewall backend may be unavailable)"
pass "daemon ready"

# === confirm the file jails resolved to FILE (not journald) ===================
for j in breakable quiet late; do
  src="$(csock jails --output plain 2>/dev/null | awk -F'\t' -v jj="$j" '$1==jj{print $9; exit}')"
  case "$src" in
    /*) : ;; # a path — good, a file source
    *)  fail "jail '${j}' SOURCE is '${src}', expected a file path (did it resolve to journald?)" ;;
  esac
done
pass "breakable / quiet / late all resolved to file sources"

# === ASSERTION (d): a never-appeared logpath is NOT degraded ===================
# At startup, none of the jails has broken; `late` has never attached. The host
# must NOT be degraded purely from a not-yet-appeared log (no false flash).
sleep "$DEBOUNCE_WAIT"   # well past the debounce; a false flash would show now
PROT0="$(protection)"
if [ "$PROT0" = "degraded" ]; then
  fail "host is DEGRADED at startup with no broken source (late-log false flash — ENH-004 case d)"
fi
pass "no false DEGRADED flash from a never-appeared log (protection=${PROT0})"

# === drive a read on breakable, then break it =================================
# Write failures into breakable: a real attach+read (was_ever_attached) AND
# enough to ban (proves the jail is genuinely live before we break it).
log "writing failures into breakable.log (real attach + read)"
inject_failures "$LOG_BREAK" "$ATTACKER" 5

# Wait until breakable is confirmed reading (gauge 1) before breaking it.
ok=0
for _ in $(seq 1 60); do
  if [ "$(gauge breakable)" = "1" ]; then ok=1; break; fi
  sleep 0.2
done
[ "$ok" -eq 1 ] || fail "breakable never reported healthy (gauge 1) — file source not reading?"
pass "breakable confirmed reading (gauge 1)"

# === ASSERTION (c): rotation flicker does NOT flip degraded ===================
# Move the log away and recreate the SAME name immediately (the rotation
# recovery path). Within the debounce this must NOT read as degraded.
log "rotation flicker: move-away + same-name recreate within the debounce"
mv "$LOG_BREAK" "${LOG_BREAK}.rotated"
: > "$LOG_BREAK"   # same basename → reopenAfterRotation re-attaches
# Check quickly, INSIDE the debounce window (no long sleep).
sleep 1
PROT_FLICK="$(protection)"
if [ "$PROT_FLICK" = "degraded" ]; then
  fail "rotation flicker flipped DEGRADED within the debounce (ENH-004 case c)"
fi
# Give the reopen a moment, then confirm breakable recovered to healthy.
inject_failures "$LOG_BREAK" "$ATTACKER" 1
ok=0
for _ in $(seq 1 40); do
  if [ "$(gauge breakable)" = "1" ]; then ok=1; break; fi
  sleep 0.2
done
[ "$ok" -eq 1 ] || fail "breakable did not recover to healthy after same-name rotation (gauge stuck 0)"
pass "rotation flicker did not flip DEGRADED, source recovered (gauge 1)"

# === ASSERTION (a): a real, sticky break flips DEGRADED + gauge 0 =============
# Move the active log out under a NON-matching name so the parent-dir watch
# does NOT reopen it — a genuine was-healthy-then-broken source.
log "sticky break: move breakable.log away under a non-matching name"
mv "$LOG_BREAK" "${LOG_BREAK}.gone"
# Wait PAST the debounce; the verdict must now be a hard unhealthy.
sleep "$DEBOUNCE_WAIT"

GAUGE_BREAK="$(gauge breakable)"
[ "$GAUGE_BREAK" = "0" ] || fail "breakable gauge is '${GAUGE_BREAK}' after a sticky break past the debounce (expected 0) — ENH-004 case a"
PROT_BROKEN="$(protection)"
[ "$PROT_BROKEN" = "degraded" ] || fail "protection is '${PROT_BROKEN}' after a sticky file break (expected degraded) — ENH-004 case a"
pass "sticky file break → protection=degraded, breakable gauge 0"

# === ASSERTION (b): the quiet healthy jail was NEVER false-flagged ============
# quiet has been attached the whole run with zero traffic. Its gauge must read
# 1 (confirmed reading) throughout — a healthy quiet jail is never unhealthy.
GAUGE_QUIET="$(gauge quiet)"
[ "$GAUGE_QUIET" = "1" ] || fail "quiet (attached, no traffic) gauge is '${GAUGE_QUIET}' (expected 1) — false flag of a healthy quiet jail (ENH-004 case b)"
pass "quiet healthy file jail never false-flagged (gauge 1)"

log "ALL ENH-004 FILE-SOURCE DEGRADED ASSERTIONS PASSED"
exit 0
