#!/usr/bin/env bash
# B6 host-ban/restart/expiry, plus existing campaign TCP controls. Parent owns netns.
set -euo pipefail
umask 077
[[ $# == 4 ]] || { echo 'usage: backend.sh BIN WORK ORACLE BACKEND' >&2; exit 64; }
BIN=$1 W=$2 ORACLE=$3 BACKEND=$4
case "$BACKEND" in nftables|iptables|ipset) ;; *) exit 64;; esac
[[ $BIN == /* && -x $BIN && $W == /* && -d $W && $ORACLE == /* && -x $ORACLE ]] || exit 64
READY_WINDOW=60 BANTIME=120
if [[ $BACKEND == ipset ]]; then READY_WINDOW=120; BANTIME=240; fi
case "$W" in *'"'*|*'\'*|*$'\n'*|*$'\r'*) exit 64;; esac
[[ -z $(find "$W" -mindepth 1 -maxdepth 1 -print -quit) ]] || exit 64
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
HELPER="$HERE/backend_check.py"
# Only the runner may invoke this driver, inside its disposable network namespace.
[[ -n ${F2Z_NATIVE_PARENT_NETNS:-} && $(readlink /proc/self/ns/net) != "$F2Z_NATIVE_PARENT_NETNS" ]] || {
    echo 'distinct runner-owned network namespace required' >&2
    exit 65
}
S=$(mktemp -d /tmp/f2z-backend.XXXXXXXX)
D=; L=; BASE=0
fail() { echo "backend[$BACKEND]: $*" >&2; exit 1; }
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
    if [[ -n $L ]]; then kill -TERM "$L" 2>/dev/null || :; wait "$L" 2>/dev/null || :; fi
    rm -rf -- "$S"
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$W/state"
: > "$W/portsentry.log"; : > "$W/other.log"; : > "$W/daemon.log"
cat > "$W/config.toml" <<CONFIG
[global]
native_ingestion = true
log_level = "info"
log_target = "$W/daemon.log"
socket_path = "$S/f.sock"
state_file = "$W/state/fail2zig.sqlite"
metrics_enabled = false
firewall = "$BACKEND"
[defaults]
enforce = true
maxretry = 5
findtime = 600
bantime = $BANTIME
[jails.sshd]
enabled = true
filter = "sshd"
source = "file"
timestamp = "undated"
logpath = ["$W/other.log"]
[jails.portsentry]
enabled = true
filter = "portsentry"
source = "file"
timestamp = "iso8601"
logpath = ["$W/portsentry.log"]
maxretry = 1
CONFIG
start() {
    BASE=$(wc -l < "$W/daemon.log")
    "$BIN" --config "$W/config.toml" >> "$W/daemon.stdout" 2>&1 & D=$!
    local end=$((SECONDS+READY_WINDOW))
    while (( SECONDS < end )); do
        alive || fail 'daemon exited before READY'
        if tail -n +$((BASE+1)) "$W/daemon.log" | grep -q 'native: ready'; then return; fi
        sleep .1
    done
    fail 'READY deadline exceeded'
}
stop() {
    alive || fail 'daemon exited unexpectedly'
    kill -TERM "$D"
    local end=$((SECONDS+15))
    while alive && (( SECONDS < end )); do sleep .1; done
    alive && fail 'daemon ignored TERM'
    local rc=0; wait "$D" || rc=$?; D=
    (( rc == 0 )) || fail "daemon exit=$rc"
}
check() { python3 -B "$HELPER" "$@"; }
kernel() {
    case "$BACKEND" in
        nftables) timeout 10 "$ORACLE" > "$W/kernel-current.txt";;
        iptables) timeout 10 iptables-save > "$W/kernel-current.txt";;
        ipset) timeout 10 ipset save > "$W/kernel-current.txt";;
    esac
}
wait_members() {
    local wanted=$1 end=$((SECONDS+READY_WINDOW))
    while (( SECONDS < end )); do
        alive || fail 'daemon exited waiting for membership'
        kernel
        if check members "$BACKEND" "$W/kernel-current.txt" "$wanted"; then return; fi
        sleep .2
    done
    fail "membership never reached $wanted"
}
assert_members() { kernel; check members "$BACKEND" "$W/kernel-current.txt" "$1"; }
status() {
    timeout 8 "$BIN" --socket "$S/f.sock" --timeout 5000 --output json status > "$W/status.json"
    check status "$W/status.json"
}
tcp() {
    kill -0 "$L" 2>/dev/null || fail 'TCP listener exited'
    check tcp "$W/listener.port" "$1"
}
ip link set lo up
for addr in 198.18.0.1 198.18.0.2 198.18.0.3 198.19.0.1 198.19.0.254; do ip addr add "$addr/32" dev lo; done
python3 -B "$HELPER" listen "$W/listener.port" > "$W/listener.log" 2>&1 & L=$!
for ((i=0;i<50;i++)); do [[ -s $W/listener.port ]] && break; kill -0 "$L" || fail 'listener failed'; sleep .1; done
[[ -s $W/listener.port ]] || fail 'listener readiness timed out'
assert_members absent; tcp open
start
for n in 1 2 3; do
    printf '%s Scan from: [198.18.0.%s] (198.18.0.%s) protocol: [TCP] port: [23] type: [Connect] IP opts: [unknown] ignored: [false] triggered: [true] noblock: [true] blocked: [false]\n' "$(date -u +%Y-%m-%dT%H:%M:%S.%3N+0000)" "$n" "$n" >> "$W/portsentry.log"
done
wait_members present; status; tcp blocked
cp "$W/kernel-current.txt" "$W/kernel-banned.txt"
check snapshot "$W/state/fail2zig.sqlite" "$W/owners.json"
stop; assert_members absent; tcp open
start; wait_members present; status; tcp blocked
check deadlines "$W/state/fail2zig.sqlite" "$W/owners.json"
cp "$W/kernel-current.txt" "$W/kernel-restart.txt"
# Original deadlines control expiry; a restart must not grant another ban interval.
expiry_end=$(check expiry_end "$W/owners.json")
while (( $(date +%s) < expiry_end )); do alive || fail 'daemon exited before expiry'; sleep .2; done
wait_members absent; status; tcp open
cp "$W/kernel-current.txt" "$W/kernel-expired.txt"
stop; assert_members absent
echo "backend: PASS $BACKEND host IPv4 ban/restart/expiry"
