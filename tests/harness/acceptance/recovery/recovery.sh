#!/usr/bin/env bash
# Adapted from BUG-075 b2/b3/b8 and load_repro rig/restart; namespace owned by parent.
set -euo pipefail
umask 077
[[ $# == 4 ]] || { echo 'usage: recovery.sh MODE BIN WORK ORACLE' >&2; exit 64; }
MODE=$1 BIN=$2 W=$3 ORACLE=$4
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
CHECK="$HERE/recovery_check.py"
[[ $BIN == /* && $W == /* && $ORACLE == /* && -x $BIN && -x $ORACLE && -d $W ]] || exit 64
# Paths are embedded in TOML. Reject rather than incorrectly escape a supplied path.
case "$W" in *'"'*|*'\'*|*$'\n'*|*$'\r'*) exit 64;; esac
case "$MODE" in restart-populate|restart-check|source-repair|counters) ;; *) exit 64;; esac
TARGET=${TARGET:-400}; HOLD_SECONDS=${HOLD_SECONDS:-600}; READY_SECONDS=${READY_SECONDS:-60}
[[ $TARGET =~ ^[0-9]+$ && $HOLD_SECONDS =~ ^[0-9]+$ && $READY_SECONDS =~ ^[0-9]+$ ]] || exit 64
(( TARGET > 0 && TARGET <= 64000 && HOLD_SECONDS <= 3600 && READY_SECONDS > 0 && READY_SECONDS <= 600 )) || exit 64
# Only the runner may invoke this driver, inside its disposable network namespace.
[[ -n ${F2Z_NATIVE_PARENT_NETNS:-} && $(readlink /proc/self/ns/net) != "$F2Z_NATIVE_PARENT_NETNS" ]] || {
    echo 'distinct runner-owned network namespace required' >&2
    exit 65
}
S=$(mktemp -d /tmp/f2z-recovery.XXXXXXXX)
D=; RUN=0; LOG="$W/portsentry.log"; OTHER="$W/other.log"
DB="$W/state/fail2zig.sqlite"
fail() { echo "recovery: $*" >&2; exit 1; }
alive() { [[ -n $D ]] && kill -0 "$D" 2>/dev/null; }
cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    if alive; then
        kill -TERM "$D" 2>/dev/null || :
        for ((i=0;i<100;i++)); do alive || break; sleep .1; done
        if alive; then kill -KILL "$D" 2>/dev/null || :; fi
    fi
    if [[ -n $D ]]; then wait "$D" 2>/dev/null || :; fi
    # Only the socket directory created by this process is removed.
    rm -rf -- "$S"
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
check() { python3 -B "$CHECK" "$DB" "$@"; }
config() {
cat > "$W/config-$MODE.toml" <<EOF
[global]
native_ingestion = true
log_level = "info"
log_target = "$W/daemon-$MODE.log"
socket_path = "$S/f.sock"
state_file = "$DB"
metrics_enabled = false
firewall = "nftables"
[defaults]
enforce = true
maxretry = 5
findtime = 600
bantime = 3600
[jails.sshd]
enabled = true
filter = "sshd"
source = "file"
timestamp = "undated"
logpath = ["$OTHER"]
[jails.portsentry]
enabled = true
filter = "portsentry"
source = "file"
timestamp = "iso8601"
logpath = ["$LOG"]
maxretry = 1
EOF
}
start() {
    RUN=$((RUN+1))
    BASE=$(wc -l < "$W/daemon-$MODE.log")
    "$BIN" --config "$W/config-$MODE.toml" >> "$W/stdout-$MODE.log" 2>&1 & D=$!
}
episode() { tail -n +$((BASE+1)) "$W/daemon-$MODE.log"; }
ready() {
    local end=$((SECONDS+READY_SECONDS))
    while (( SECONDS < end )); do
        alive || fail 'daemon exited before READY'
        if episode | grep -q 'native: ready'; then return; fi
        sleep .1
    done
    fail 'READY deadline exceeded'
}
stop() {
    alive || fail 'daemon exited unexpectedly'
    kill -TERM "$D"
    local end=$((SECONDS+30))
    while alive && (( SECONDS < end )); do sleep .1; done
    alive && fail 'daemon ignored TERM for 30 seconds'
    local rc=0; wait "$D" || rc=$?; D=
    (( rc == 0 )) || fail "daemon exit=$rc"
}
status() {
    timeout 8 "$BIN" --socket "$S/f.sock" --timeout 5000 --output json status > "$W/status-$MODE.json"
    check status "$W/status-$MODE.json"
}
inventory() { timeout 10 "$ORACLE" > "$1"; }
elems() {
    local count=$1 end=$((SECONDS+READY_SECONDS))
    while (( SECONDS < end )); do
        alive || fail 'daemon exited waiting for elements'
        inventory "$W/kernel-current.txt"
        if check count "$W/kernel-current.txt" "$count" quiet; then return; fi
        sleep .2
    done
    fail "kernel element count did not reach $count"
}
line() {
    printf '%s Scan from: [%s] (%s) protocol: [TCP] port: [23] type: [Connect] IP opts: [unknown] ignored: [false] triggered: [true] noblock: [true] blocked: [false]\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%S.%3N+0000)" "$1" "$1" >> "$LOG"
}
seed_three() {
    start; ready
    # Populate the unaffected source too, so continuity comparison isn't vacuous.
    printf 'Failed password for root from 198.19.0.1 port 22 ssh2\n' >> "$OTHER"
    line 198.18.0.1; line 198.18.0.2; line 198.18.0.3
    elems 3; status; stop
}
ip link set lo up
if [[ $MODE == restart-check ]]; then
    [[ -f $W/restart-baseline.json && -f $W/kernel-before.txt && -f $DB ]] || fail 'missing populate result'
    check continuity "$W/restart-baseline.json" "$LOG" "$OTHER"
else
    [[ -z $(find "$W" -mindepth 1 -maxdepth 1 -print -quit) ]] || fail 'WORK must be empty'
    mkdir "$W/state"; : > "$LOG"; : > "$OTHER"
fi
config
: > "$W/daemon-$MODE.log"
case "$MODE" in
restart-populate)
    start; ready
    for ((n=0;n<TARGET;n++)); do line "198.18.$((n/250)).$((n%250+1))"; sleep .25; done
    elems "$TARGET"; status
    inventory "$W/kernel-before.txt"
    stop
    check snapshot "$W/restart-baseline.json" "$LOG" "$OTHER"
    printf '%s\n' "$TARGET" > "$W/target-count"
    ;;
restart-check)
    TARGET=$(cat "$W/target-count")
    start; ready; elems "$TARGET"; status
    check owners "$W/restart-baseline.json"
    inventory "$W/kernel-after.txt"
    check deadlines "$W/kernel-before.txt" "$W/kernel-after.txt" "${DEADLINE_TOLERANCE_MS:-1000}"
    end=$((SECONDS+HOLD_SECONDS))
    while (( SECONDS < end )); do
        status; inventory "$W/kernel-hold.txt"; check count "$W/kernel-hold.txt" "$TARGET"
        sleep 1
    done
    stop; check owners "$W/restart-baseline.json"
    ;;
source-repair)
    seed_three
    check snapshot "$W/repair-before.json" "$LOG" "$OTHER"
    : > "$LOG"
    start
    end=$((SECONDS+30))
    while alive && (( SECONDS < end )); do sleep .1; done
    alive && fail 'truncated source did not refuse startup'
    rc=0; wait "$D" || rc=$?; D=
    (( rc != 0 )) || fail 'truncated startup returned success'
    episode > "$W/refusal.log"
    grep -q 'ResumeLost' "$W/refusal.log" || fail 'startup failed for a cause other than continuity'
    if grep -q 'native: ready' "$W/refusal.log"; then fail 'refused start claimed READY'; fi
    timeout 30 "$BIN" repair-source --config "$W/config-$MODE.toml" --jail portsentry --source "$LOG" --token acceptance-repair-1 --acknowledge-truncation > "$W/repair-first.out" 2>&1
    check repaired "$W/repair-before.json" "$LOG"
    check dump > "$W/repair-first.dump"
    timeout 30 "$BIN" repair-source --config "$W/config-$MODE.toml" --jail portsentry --source "$LOG" --token acceptance-repair-1 --acknowledge-truncation > "$W/repair-replay.out" 2>&1
    grep -q 'replayed; nothing changed now' "$W/repair-replay.out" || fail 'token replay was not reported'
    check dump > "$W/repair-replay.dump"
    cmp "$W/repair-first.dump" "$W/repair-replay.dump"
    start; ready; elems 3; check owners "$W/repair-before.json"
    line 198.18.0.9; elems 4; status; stop
    ;;
counters)
    seed_three
    for expected in 1 2 0; do
        if (( expected > 0 )); then check drift; fi
        start; ready
        episode > "$W/counter-$expected.log"
        check counter "$expected" "$W/counter-$expected.log"
        status; stop
    done
    ;;
esac
echo "recovery: PASS $MODE"
