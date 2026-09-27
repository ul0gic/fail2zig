#!/usr/bin/env bash
# B4: independent populated restart and stalled Type=notify startup.
# Run outside any test network namespace, as the lab user with sudo -n.
set -euo pipefail
umask 077
[[ $# == 3 ]] || { echo 'usage: notify.sh BIN WORK ORACLE' >&2; exit 64; }
BIN=$1 W=$2 ORACLE=$3
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
RECOVERY_DIR="$HERE/../recovery"
[[ $EUID != 0 && -x $BIN && -x $ORACLE && -d $W ]] || exit 64
for path in "$BIN" "$W" "$ORACLE"; do
    [[ $path =~ ^/[a-zA-Z0-9_./-]+$ ]] || { echo 'unsupported path characters' >&2; exit 64; }
done
[[ -z $(find "$W" -mindepth 1 -maxdepth 1 -print -quit) ]] || { echo 'WORK must be empty' >&2; exit 64; }
[[ -f $RECOVERY_DIR/recovery.sh && -f $RECOVERY_DIR/recovery_check.py ]] || { echo 'missing sibling recovery helpers' >&2; exit 64; }
sudo -n true
LAB_UID=$(id -u)
SOCKDIR=$(mktemp -d /tmp/f2z-notify.XXXXXXXX)
TOKEN=${SOCKDIR##*.}
UNITS=() NAMESPACES=()
fail() { echo "notify: $*" >&2; exit 1; }
unqualified() { echo "notify: UNQUALIFIED: $*" >&2; exit 77; }
property() { timeout 5 systemctl show "$1" --property="$2" --value; }
journal() { timeout 10 sudo -n journalctl --unit="$1" --no-pager -o short-precise > "$W/$2.journal"; }
cleanup() {
    local rc=$? cleanup_failed=0 unit ns
    trap - EXIT INT TERM
    for unit in "${UNITS[@]}"; do
        # A stopped startup must be continued before normal termination can run.
        timeout 5 sudo -n systemctl kill --kill-who=main --signal=CONT "$unit" 2>/dev/null || :
        if ! timeout 20 sudo -n systemctl stop "$unit" 2>/dev/null; then
            if [[ $(property "$unit" LoadState 2>/dev/null || :) != not-found ]]; then
                timeout 5 sudo -n systemctl kill --kill-who=all --signal=KILL "$unit" 2>/dev/null || :
                timeout 10 sudo -n systemctl stop "$unit" 2>/dev/null || cleanup_failed=1
            fi
        fi
        case $(property "$unit" ActiveState 2>/dev/null || :) in
            active|activating|deactivating) cleanup_failed=1 ;;
        esac
        journal "$unit" "$unit-cleanup" || cleanup_failed=1
        timeout 5 sudo -n systemctl reset-failed "$unit" 2>/dev/null || :
    done
    for ns in "${NAMESPACES[@]}"; do
        if [[ -e /run/netns/$ns ]]; then
            timeout 5 sudo -n ip netns del "$ns" || cleanup_failed=1
        fi
    done
    if (( cleanup_failed == 0 )); then rm -rf -- "$SOCKDIR"; fi
    if (( cleanup_failed )); then echo 'notify: cleanup failed; inspect owned units/namespaces' >&2; rc=1; fi
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Rootless user+network namespace keeps generated files owned by the lab user.
# No source files move after population: inode continuity is preserved.
TARGET=400 READY_SECONDS=120 timeout --signal=TERM --kill-after=15 480 \
    unshare --user --map-root-user --net -- bash "$RECOVERY_DIR/recovery.sh" restart-populate "$BIN" "$W" "$ORACLE"
[[ $(cat "$W/target-count") == 400 ]] || fail 'population did not retain 400 subjects'

make_run() {
    RUN=$1
    UNIT="f2z-notify-$TOKEN-$RUN.service"
    NS="f2z-notify-$TOKEN-$RUN"
    CFG="$W/notify-$RUN.toml"
    LOG="$W/notify-$RUN.log"
    [[ $(property "$UNIT" LoadState 2>/dev/null || :) == not-found ]] || fail "unit already exists: $UNIT"
    [[ ! -e /run/netns/$NS ]] || fail "namespace already exists: $NS"
    # ip netns add and transient unit creation both refuse existing names.
    NAMESPACES+=("$NS")
    timeout 15 sudo -n ip netns add "$NS"
    timeout 15 sudo -n ip netns exec "$NS" ip link set lo up
    awk -v socket="$SOCKDIR/$RUN.sock" -v log_path="$LOG" '
        /^socket_path = / { print "socket_path = \"" socket "\""; next }
        /^log_target = / { print "log_target = \"" log_path "\""; next }
        { print }
    ' "$W/config-restart-populate.toml" > "$CFG"
    : > "$LOG"
    START=$SECONDS
    UNITS+=("$UNIT")
    timeout 20 sudo -n systemd-run --unit="$UNIT" --no-block \
        -p Type=notify -p NotifyAccess=main -p TimeoutStartSec=20 -p TimeoutStopSec=10 \
        -p "User=$LAB_UID" -p AmbientCapabilities=CAP_NET_ADMIN -p CapabilityBoundingSet=CAP_NET_ADMIN \
        -p "NetworkNamespacePath=/run/netns/$NS" "$BIN" --config "$CFG"
}
record_state() {
    timeout 5 systemctl show "$UNIT" -p ActiveState -p SubState -p Result -p MainPID -p StatusText \
        >> "$W/notify-$RUN-states.log"
}

make_run progress
end=$((SECONDS+150))
while (( SECONDS < end )); do
    record_state
    ACTIVE=$(property "$UNIT" ActiveState)
    case $ACTIVE in
        active) break ;;
        failed|inactive) fail "progressing startup ended: $ACTIVE" ;;
    esac
    sleep .2
done
[[ ${ACTIVE:-} == active ]] || fail 'progressing startup exceeded 150 seconds'
ELAPSED=$((SECONDS-START))
[[ $(property "$UNIT" SubState) == running ]] || fail 'unit did not reach running'
timeout 10 sudo -n ip netns exec "$NS" "$ORACLE" > "$W/notify-kernel.txt"
python3 -B "$RECOVERY_DIR/recovery_check.py" "$W/state/fail2zig.sqlite" count "$W/notify-kernel.txt" 400
journal "$UNIT" progress
printf 'notify: progressing READY=%ss kernel=400\n' "$ELAPSED" | tee "$W/notify-progress-result.txt"
timeout 20 sudo -n systemctl stop "$UNIT"
[[ $(property "$UNIT" ActiveState) == inactive ]] || fail 'progressing unit did not stop cleanly'
grep -q 'native: ready' "$LOG" || fail 'active service lacks READY log'
# A fast startup cannot qualify timeout extension; still exercise stalled startup.
FAST=0
(( ELAPSED > 20 )) || FAST=1

make_run stalled
end=$((SECONDS+10))
while (( SECONDS < end )); do
    ACTIVE=$(property "$UNIT" ActiveState)
    PID=$(property "$UNIT" MainPID)
    [[ $ACTIVE == activating ]] || fail "cannot stall startup in state $ACTIVE"
    if [[ $PID =~ ^[1-9][0-9]*$ ]]; then break; fi
    sleep .1
done
[[ ${PID:-0} =~ ^[1-9][0-9]*$ ]] || fail 'owned unit has no MainPID'
[[ $(property "$UNIT" ActiveState) == activating ]] || unqualified 'startup became ready before stall'
sudo -n systemctl kill --kill-who=main --signal=STOP "$UNIT"
[[ $(property "$UNIT" ActiveState) == activating ]] || unqualified 'READY raced with STOP'
if grep -q 'native: ready' "$LOG"; then unqualified 'startup claimed READY before STOP'; fi
end=$((SECONDS+120))
while (( SECONDS < end )); do
    record_state
    ACTIVE=$(property "$UNIT" ActiveState)
    case $ACTIVE in
        failed|inactive) break ;;
        active) fail 'stalled startup reached active' ;;
    esac
    sleep .2
done
[[ $(property "$UNIT" Result) == timeout ]] || fail 'stalled startup did not end with Result=timeout'
if grep -q 'native: ready' "$LOG"; then fail 'stalled startup claimed READY'; fi
journal "$UNIT" stalled
printf 'notify: stalled Result=timeout READY=absent\n' | tee "$W/notify-stalled-result.txt"
(( FAST == 0 )) || unqualified 'progressing startup finished within 20 seconds; timeout extension was not exercised'
printf 'notify: PASS (progressing extension and stalled timeout)\n'
