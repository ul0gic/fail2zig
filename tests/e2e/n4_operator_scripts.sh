#!/usr/bin/env bash
# Representative operator-script workflows against the one executable: monitoring,
# completions, lifecycle (reload, SIGHUP, SIGUSR1, TERM) and ban history. Runs unprivileged
# with a temporary log-only configuration; asserts the frozen exit classes and the JSON
# field names scripts are allowed to depend on. Not part of `zig build test`.
#
# Usage: tests/e2e/n4_operator_scripts.sh [--bin zig-out/bin/fail2zig]
set -euo pipefail

cd "$(dirname "$0")/../.."
BIN=zig-out/bin/fail2zig
while [ $# -gt 0 ]; do
    case "$1" in
    --bin) BIN="$2"; shift ;;
    *) echo "usage: $0 [--bin <path>]" >&2; exit 2 ;;
    esac
    shift
done
[ -x "$BIN" ] || { echo "executable missing: $BIN (build with zig build -Doptimize=ReleaseSafe)" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 is required for JSON assertions" >&2; exit 2; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/f2z-ops.XXXXXX")
SOCK_DIR="$WORK/run"
STATE_DIR="$WORK/state"
mkdir -m 0750 "$SOCK_DIR" "$STATE_DIR"
CONFIG="$WORK/config.toml"
LOG="$WORK/auth.log"
DAEMON_LOG="$WORK/daemon.log"
SOCKET="$SOCK_DIR/fail2zig.sock"
DAEMON_PID=""
PASS=0; FAIL=0

cleanup() {
    if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill -TERM "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

write_config() {
    local bantime="$1"
    cat > "$CONFIG" <<CFG
[global]
native_ingestion = true
log_level = "info"
log_target = "$DAEMON_LOG"
state_file = "$STATE_DIR/state.bin"
socket_path = "$SOCKET"
metrics_enabled = false
[defaults]
banaction = "log-only"
maxretry = 3
findtime = 600
bantime = $bantime
[jails.sshd]
filter = "sshd"
source = "file"
timestamp = "undated"
logpath = ["$LOG"]
CFG
    chmod 0640 "$CONFIG"
}

f2z() { "$BIN" --socket "$SOCKET" --timeout 4000 "$@"; }

check() {
    local name="$1"
    if "${@:2}"; then PASS=$((PASS + 1)); printf 'PASS %s\n' "$name"; else FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$name"; fi
}

# expect_rc <want> <cmd...>: runs the command, captures stdout into OUT, compares the exit class.
OUT=""
expect_rc() {
    local want="$1"; shift
    local rc=0
    OUT=$("$@" 2>/dev/null) || rc=$?
    if [ "$rc" != "$want" ]; then echo "  rc=$rc want=$want: $*; stdout: $OUT" >&2; return 1; fi
}

# json <expr>: evaluates a python expression over the parsed OUT (bound as `j`), fails when false.
json() {
    python3 -c 'import json,sys; j=json.loads(sys.stdin.read()); sys.exit(0 if eval(sys.argv[1]) else 1)' "$1" <<<"$OUT" && return 0
    echo "  assertion failed: $1; document: $OUT" >&2
    return 1
}

wait_for() {
    local _i
    for _i in $(seq 1 200); do
        "$@" >/dev/null 2>&1 && return 0
        sleep 0.05
    done
    return 1
}

# Protection reports `degraded` until every source is admitted; wait for the settled state.
daemon_ready() { f2z --output json status | grep -q '"protection":"log-only"'; }

start_daemon() {
    "$BIN" --foreground --config "$CONFIG" 2>>"$WORK/stderr.log" &
    DAEMON_PID=$!
    wait_for test -S "$SOCKET" || { echo "socket never appeared" >&2; return 1; }
    wait_for daemon_ready || { echo "daemon never reached log-only protection" >&2; return 1; }
}

# Case bodies run in child shells so one failing assertion cannot abort the run.
export BIN SOCKET WORK LOG DAEMON_LOG CONFIG
export -f f2z expect_rc json wait_for daemon_ready

echo "executable=$BIN work=$WORK"
: > "$LOG"
write_config 60
start_daemon
export DAEMON_PID

# --- monitoring ----------------------------------------------------------------------------
check "status json fields" bash -c '
    expect_rc 0 f2z --output json status &&
    json "j[\"protection\"]==\"log-only\" and j[\"storage\"]==\"healthy\" and isinstance(j[\"active_bans\"],int) and isinstance(j[\"total_bans\"],int) and len(j[\"generation\"])==64 and \"backend\" in j"'
check "status plain is tab separated" bash -c 'expect_rc 0 f2z --output plain status && grep -q "^protection	log-only$" <<<"$OUT"'
check "jails json fields" bash -c '
    expect_rc 0 f2z --output json jails &&
    json "j[0][\"name\"]==\"sshd\" and j[0][\"enabled\"] is True and j[0][\"paused\"] is False and j[0][\"enforcing\"] is False and j[0][\"action\"]==\"log-only\" and j[0][\"maxretry\"]==3 and j[0][\"bantime\"]==60 and j[0][\"source\"]==\"file\""'
check "list is an empty array" bash -c 'expect_rc 0 f2z --output json list && json "j==[]"'
check "version reports client and daemon" bash -c 'expect_rc 0 f2z --output json version && json "j[\"client_version\"]==j[\"daemon\"][\"daemon_version\"]"'
check "config carries schema and generation" bash -c '
    expect_rc 0 f2z --output json config &&
    json "j[\"schema_version\"]==1 and len(j[\"generation\"])==64 and j[\"jails\"][0][\"filter\"]==\"sshd\" and j[\"global\"][\"metrics_enabled\"] is False"'
check "local version needs no daemon" bash -c 'expect_rc 0 "$BIN" --version && grep -q "^fail2zig " <<<"$OUT"'
check "help is local" bash -c 'expect_rc 0 "$BIN" help && grep -q "USAGE" <<<"$OUT"'

# --- completions ---------------------------------------------------------------------------
for sh in bash zsh fish; do
    check "completions $sh" bash -c "expect_rc 0 \"\$BIN\" completions $sh && [ -n \"\$OUT\" ] && ! grep -q fail2zig-client <<<\"\$OUT\""
done
check "completions rejects unknown shell" bash -c 'expect_rc 2 "$BIN" completions ksh'

# --- exit classes --------------------------------------------------------------------------
check "usage: ban without ip is 2" bash -c 'expect_rc 2 f2z ban'
check "usage: ban without --jail is 2" bash -c 'expect_rc 2 f2z ban 203.0.113.9'
check "usage: unknown command is 2" bash -c 'expect_rc 2 f2z bogus'
check "unavailable: absent socket is 3" bash -c 'expect_rc 3 "$BIN" --socket "$WORK/absent.sock" status'
check "rejected: manual ban on a log-only jail is 1 with reasons" bash -c '
    expect_rc 1 f2z --output json ban 203.0.113.9 --jail sshd --duration 60 &&
    json "j[\"schema_version\"]==1 and j[\"kind\"]==\"ban\" and j[\"outcome\"]==\"rejected\" and j[\"enforced\"] is False and len(j[\"reasons\"])>=1"'
check "rejected: unban on a log-only jail is 1" bash -c 'expect_rc 1 f2z --output json unban 203.0.113.9 --jail sshd && json "j[\"kind\"]==\"unban\" and j[\"outcome\"]==\"rejected\""'

# --- history and jail lifecycle --------------------------------------------------------------
check "history page shape" bash -c '
    expect_rc 0 f2z --output json history --jail sshd --limit 5 &&
    json "j[\"schema_version\"]==1 and isinstance(j[\"items\"],list) and \"next_cursor\" in j and len(j[\"generation\"])==64"'
check "history reset requires exactly one scope" bash -c 'expect_rc 2 f2z history reset 203.0.113.9'
check "history reset applies" bash -c '
    expect_rc 0 f2z --output json history reset 203.0.113.9 --jail sshd &&
    json "j[\"kind\"]==\"history_reset\" and j[\"outcome\"]==\"applied\" and isinstance(j[\"mutation_revision\"],int)"'
check "jail pause then resume" bash -c '
    expect_rc 0 f2z --output json jail pause sshd && json "j[\"kind\"]==\"group_pause\" and j[\"outcome\"]==\"applied\"" &&
    expect_rc 0 f2z --output json jails && json "j[0][\"paused\"] is True" &&
    expect_rc 0 f2z --output json jail resume sshd && json "j[\"kind\"]==\"group_resume\" and j[\"outcome\"]==\"applied\"" &&
    expect_rc 0 f2z --output json jails && json "j[0][\"paused\"] is False"'
check "jail disable then enable" bash -c '
    expect_rc 0 f2z --output json jail disable sshd && json "j[\"kind\"]==\"group_disable\" and j[\"outcome\"]==\"applied\"" &&
    expect_rc 0 f2z --output json jail enable sshd && json "j[\"kind\"]==\"group_enable\" and j[\"outcome\"]==\"applied\""'
check "detected failures appear as unenforced decisions on a log-only jail" bash -c '
    for i in 1 2 3; do echo "Failed password for root from 203.0.113.77 port 22 ssh2" >> "$LOG"; done
    for i in $(seq 1 100); do
        expect_rc 0 f2z --output json list --jail sshd && json "any(b[\"ip\"]==\"203.0.113.77\" and b[\"jail\"]==\"sshd\" and b[\"enforced\"] is False and b[\"confirmed\"] is False for b in j)" 2>/dev/null && exit 0
        sleep 0.1
    done
    echo "  decision never listed" >&2
    exit 1'
check "history stays empty without confirmed bans" bash -c '
    expect_rc 0 f2z --output json history --jail sshd --limit 20 && json "j[\"items\"]==[]"'

# --- reload ----------------------------------------------------------------------------------
check "reload noop" bash -c 'expect_rc 0 f2z --output json reload && json "j[\"schema_version\"]==1 and j[\"outcome\"]==\"noop\" and len(j[\"generation\"])==64"'
G0=$(f2z --output json status | python3 -c 'import json,sys; print(json.load(sys.stdin)["generation"])')
write_config 120
check "reload applies a live bantime change" bash -c '
    expect_rc 0 f2z --output json reload && json "j[\"outcome\"]==\"applied\"" &&
    expect_rc 0 f2z --output json jails && json "j[0][\"bantime\"]==120"'
G1=$(f2z --output json status | python3 -c 'import json,sys; print(json.load(sys.stdin)["generation"])')
check "generation changed after applied reload" test "$G0" != "$G1"
printf 'bogus_key = 1\n' >> "$CONFIG"
check "reload rejects an unknown key and keeps the generation" bash -c '
    expect_rc 1 f2z --output json reload && json "j[\"outcome\"]==\"rejected\" and any(\"UnknownKey\" in r for r in j[\"reasons\"])"'
G2=$(f2z --output json status | python3 -c 'import json,sys; print(json.load(sys.stdin)["generation"])')
check "generation retained after rejected reload" test "$G1" = "$G2"
write_config 120
check "SIGHUP no-op reload is logged" bash -c '
    kill -HUP "$DAEMON_PID" && wait_for grep -q "native reload (SIGHUP): outcome=noop" "$DAEMON_LOG"'

# --- log reopen and stop -----------------------------------------------------------------------
mv "$DAEMON_LOG" "$DAEMON_LOG.1"
kill -USR1 "$DAEMON_PID"
sleep 0.5
kill -HUP "$DAEMON_PID"
check "SIGUSR1 reopens the log target after rotation" bash -c '
    wait_for test -f "$DAEMON_LOG" && wait_for grep -q "outcome=noop" "$DAEMON_LOG" && [ "$(stat -c %a "$DAEMON_LOG")" = 640 ]'
kill -TERM "$DAEMON_PID"
RC=0; wait "$DAEMON_PID" || RC=$?
DAEMON_PID=""
check "SIGTERM exits 0 and removes the socket" bash -c "[ \"$RC\" = 0 ] && [ ! -e \"$SOCKET\" ]"
check "commands after stop are unavailable (3)" bash -c 'expect_rc 3 f2z status'

echo "summary pass=$PASS fail=$FAIL"
[ "$FAIL" = 0 ]
