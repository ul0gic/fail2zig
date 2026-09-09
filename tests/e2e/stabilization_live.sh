#!/usr/bin/env bash
# tests/e2e/stabilization_live.sh — Phase 11 stabilization scenario on the
# installed shipped binary + unit (config diagnostics, SEC-012, SYS-021,
# DBT-005). Root, systemd host. Restores the box to its pre-run state on
# every exit path.
#
# Usage:
#   sudo tests/e2e/stabilization_live.sh [--force] [--keep]
#
#   --force   Run even if fail2zig.service is active (it is stopped and
#             restarted by this script; pre-run active state is restored).
#   --keep    Leave the scratch workdir in place on exit.
#
# Exit 0 = all assertions passed. Non-zero = first failure.

set -euo pipefail

UNIT="fail2zig.service"
DAEMON="/usr/local/bin/fail2zig"
LIVE_CONF="/etc/fail2zig/config.toml"
FORCE=0
KEEP=0

log()  { printf 'e2e: %s\n' "$*" >&2; }
pass() { printf 'e2e: PASS  %s\n' "$*" >&2; }
fail() { printf 'e2e: FAIL  %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --force)   FORCE=1; shift ;;
    --keep)    KEEP=1; shift ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *)         echo "e2e: unknown arg: $1" >&2; exit 2 ;;
  esac
done

# --- preflight ----------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || { echo "e2e: must run as root" >&2; exit 2; }
command -v systemctl  >/dev/null 2>&1 || { echo "e2e: no systemctl — not a systemd host" >&2; exit 2; }
command -v journalctl >/dev/null 2>&1 || { echo "e2e: journalctl required" >&2; exit 2; }
[ -x "$DAEMON" ] || { echo "e2e: missing ${DAEMON} (install first)" >&2; exit 2; }
[ -f "$LIVE_CONF" ] || { echo "e2e: missing ${LIVE_CONF} (install first)" >&2; exit 2; }
systemctl cat "$UNIT" >/dev/null 2>&1 || { echo "e2e: ${UNIT} not installed" >&2; exit 2; }

WAS_ACTIVE=0
if systemctl is-active --quiet "$UNIT"; then
  [ "$FORCE" -eq 1 ] || { echo "e2e: $UNIT is active — this script bounces it (use --force)" >&2; exit 2; }
  WAS_ACTIVE=1
fi

# --- pre-run state + teardown -------------------------------------------------
WORK="$(mktemp -d /tmp/f2z-stab.XXXXXX)"
ORIG_MODE="$(stat -c '%a' "$LIVE_CONF")"
ORIG_OWNER="$(stat -c '%u:%g' "$LIVE_CONF")"
cp -p "$LIVE_CONF" "${WORK}/config.orig"

cleanup() {
  set +e
  systemctl stop "$UNIT" >/dev/null 2>&1
  if ! cmp -s "${WORK}/config.orig" "$LIVE_CONF"; then
    cp "${WORK}/config.orig" "$LIVE_CONF"
  fi
  chown "$ORIG_OWNER" "$LIVE_CONF"
  chmod "$ORIG_MODE" "$LIVE_CONF"
  systemctl reset-failed "$UNIT" >/dev/null 2>&1
  if [ "$WAS_ACTIVE" -eq 1 ]; then
    systemctl start "$UNIT" >/dev/null 2>&1 || log "WARNING: could not restart ${UNIT} on teardown"
  fi
  if [ "$KEEP" -eq 1 ]; then
    log "kept workdir: $WORK"
  else
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

# --- helpers ------------------------------------------------------------------
# Zig error-return-trace frames look like "path:line:col: 0xADDR in fn (bin)".
TRACE_RE='error return trace|0x[0-9a-f]+ in [A-Za-z_]'

assert_no_trace() {
  local label="$1" file="$2"
  if grep -Eq "$TRACE_RE" "$file"; then
    sed 's/^/e2e:   /' "$file" >&2
    fail "${label}: error-return-trace present"
  fi
}

current_invocation() { systemctl show -p InvocationID --value "$UNIT" 2>/dev/null; }
journal_of() { journalctl _SYSTEMD_INVOCATION_ID="$1" --no-pager -o cat 2>/dev/null || true; }

validate() {
  local conf="$1" out="$2" err="$3"
  set +e
  "$DAEMON" --validate-config --config "$conf" >"$out" 2>"$err"
  local rc=$?
  set -e
  return "$rc"
}

# Rewrite the [jails.sshd] section of a config copy: drop any explicit
# `source` key (backend + source in one jail is a conflict) and add backend.
add_backend_systemd() {
  awk '
    /^\[/ { in_sshd = ($0 ~ /^\[jails\.sshd\]/) }
    in_sshd && /^[[:space:]]*source[[:space:]]*=/ { next }
    { print }
    in_sshd && /^\[jails\.sshd\]/ { print "backend = \"systemd\"" }
  ' "$1"
}

grep -Eq '^\[jails\.sshd\]' "$LIVE_CONF" || fail "live config has no [jails.sshd] section"

# === (1) backend = "systemd" validates, resolves to journald, warns ===========
CONF1="${WORK}/backend_systemd.toml"
add_backend_systemd "$LIVE_CONF" > "$CONF1"
chmod 0640 "$CONF1"
validate "$CONF1" "${WORK}/1.out" "${WORK}/1.err" || fail "(1) --validate-config exited non-zero on backend = \"systemd\""
grep -Eq "^config: jail 'sshd' .*source=journald" "${WORK}/1.out" || { cat "${WORK}/1.out" >&2; fail "(1) sshd jail did not resolve to source=journald"; }
grep -q "^config: OK" "${WORK}/1.out" || fail "(1) no 'config: OK' line"
grep -q "\[jails.sshd\] 'backend' is a deprecated" "${WORK}/1.err" || { cat "${WORK}/1.err" >&2; fail "(1) deprecation warning missing"; }
assert_no_trace "(1)" "${WORK}/1.err"
pass "(1) backend = \"systemd\" → exit 0, source=journald, deprecation warning"

# === (2) unknown key at a known line → file:line:col ==========================
CONF2="${WORK}/unknown_key.toml"
cp "$LIVE_CONF" "$CONF2"
chmod 0640 "$CONF2"
[ -z "$(tail -c1 "$CONF2")" ] || printf '\n' >> "$CONF2"
BAD_LINE=$(( $(wc -l < "$CONF2") + 1 ))
printf 'stabilization_bogus_key = 1\n' >> "$CONF2"
if validate "$CONF2" "${WORK}/2.out" "${WORK}/2.err"; then
  fail "(2) --validate-config accepted an unknown key"
fi
grep -q "^config: ${CONF2}:${BAD_LINE}:1: UnknownKey (key 'stabilization_bogus_key'" "${WORK}/2.err" \
  || { cat "${WORK}/2.err" >&2; fail "(2) expected ${CONF2}:${BAD_LINE}:1: UnknownKey"; }
assert_no_trace "(2)" "${WORK}/2.err"
pass "(2) unknown key reported at ${CONF2}:${BAD_LINE}:1"

# === (3) SEC-012: 0666 live config → unit fails closed with the cause =========
systemctl stop "$UNIT"
systemctl reset-failed "$UNIT" >/dev/null 2>&1 || true
chmod 0666 "$LIVE_CONF"
systemctl start "$UNIT" || true
INV_BAD="$(current_invocation)"
[ -n "$INV_BAD" ] || fail "(3) no InvocationID after start"
# Type=simple: `systemctl start` returns before the daemon exits; wait for
# the main process to leave, inside the RestartSec=5 window.
exited=0
for _ in $(seq 1 40); do
  if [ "$(systemctl show -p ExecMainStatus --value "$UNIT")" = "1" ]; then exited=1; break; fi
  sleep 0.1
done
chmod 0640 "$LIVE_CONF"
systemctl stop "$UNIT" >/dev/null 2>&1 || true
systemctl reset-failed "$UNIT" >/dev/null 2>&1 || true
[ "$exited" -eq 1 ] || fail "(3) daemon did not exit 1 with a world-writable config (ExecMainStatus=$(systemctl show -p ExecMainStatus --value "$UNIT"))"
journal_of "$INV_BAD" > "${WORK}/3.journal"
grep -q "world-writable (mode 0666)" "${WORK}/3.journal" || { sed 's/^/e2e:   /' "${WORK}/3.journal" >&2; fail "(3) journal lacks the SEC-012 cause"; }
grep -q "chmod 0640" "${WORK}/3.journal" || fail "(3) journal lacks the chmod 0640 fix hint"
assert_no_trace "(3 failed start)" "${WORK}/3.journal"
pass "(3a) 0666 config → daemon exit 1, SEC-012 cause in journal"

systemctl start "$UNIT"
INV_GOOD="$(current_invocation)"
# Past one RestartSec: a crash loop would have bumped NRestarts by now.
sleep 7
systemctl is-active --quiet "$UNIT" || { journal_of "$INV_GOOD" | sed 's/^/e2e:   /' >&2; fail "(3) unit not active after restoring 0640"; }
NRESTARTS="$(systemctl show -p NRestarts --value "$UNIT")"
[ "$NRESTARTS" = "0" ] || fail "(3) NRestarts=${NRESTARTS} after restoring 0640 (expected 0)"
pass "(3b) 0640 restored → active, NRestarts=0"

# === (4) SYS-021: state_file under /run warns ================================
CONF4="${WORK}/state_on_run.toml"
sed -E 's#^([[:space:]]*state_file[[:space:]]*=[[:space:]]*).*#\1"/run/fail2zig-e2e-scratch/state.bin"#' "$LIVE_CONF" > "$CONF4"
grep -q '/run/fail2zig-e2e-scratch/state.bin' "$CONF4" || fail "(4) live config has no state_file key to rewrite"
chmod 0640 "$CONF4"
validate "$CONF4" "${WORK}/4.out" "${WORK}/4.err" || { cat "${WORK}/4.err" >&2; fail "(4) --validate-config exited non-zero"; }
grep -q "will not survive" "${WORK}/4.err" || { cat "${WORK}/4.err" >&2; fail "(4) SYS-021 tmpfs/run warning missing"; }
grep -q "/run/fail2zig-e2e-scratch/state.bin" "${WORK}/4.err" || fail "(4) warning does not name the state_file path"
assert_no_trace "(4)" "${WORK}/4.err"
pass "(4) state_file under /run → SYS-021 warning names path + consequence"

# === (5) no error-return-trace in the healthy invocation's journal ===========
journal_of "$INV_GOOD" > "${WORK}/5.journal"
assert_no_trace "(5 healthy start)" "${WORK}/5.journal"
pass "(5) no error-return-trace in either invocation's journal"

log "ALL STABILIZATION ASSERTIONS PASSED"
exit 0
