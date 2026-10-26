#!/usr/bin/env bash
# Load reproduction rig: drives distinct PortSentry-style bans through a real nftables netlink backend in a rootless network namespace.
set -uo pipefail
umask 077
BIN="$1"; WORK="$2"; TARGET="$3"; RATE="$4"; BANTIME="${5:-600}"
DPID=""; GPID=""
cleanup() {
  if [ -n "$GPID" ]; then kill "$GPID" 2>/dev/null || true; wait "$GPID" 2>/dev/null || true; fi
  if [ -n "$DPID" ]; then
    kill -TERM "$DPID" 2>/dev/null || true
    for i in $(seq 1 100); do kill -0 "$DPID" 2>/dev/null || break; sleep 0.1; done
    if kill -0 "$DPID" 2>/dev/null; then kill -KILL "$DPID" 2>/dev/null || true; result=1; fi
    wait "$DPID" 2>/dev/null || true
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
SOCKDIR="${XDG_RUNTIME_DIR:-/tmp}/b75/$(basename "$WORK")"; rm -rf "$SOCKDIR"; mkdir -p "$WORK/state" "$SOCKDIR"; chmod 700 "$WORK/state"
SOCK="$SOCKDIR/f.sock"
LOG="$WORK/portsentry.log"; OTHER="$WORK/other.log"
: > "$LOG"; : > "$OTHER"
cat > "$WORK/config.toml" <<EOF
[global]
native_ingestion = true
log_level = "info"
log_target = "$WORK/daemon.log"
socket_path = "$SOCK"
state_file = "$WORK/state/fail2zig.sqlite"
metrics_enabled = false
firewall = "nftables"
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
logpath = ["$OTHER"]
[jails.portsentry]
enabled = true
filter = "portsentry"
source = "file"
timestamp = "iso8601"
logpath = ["$LOG"]
maxretry = 1
EOF
# attach needs a daemon-written checkpoint per jail, so each extra jail ingests one line before the run.
for j in $(seq 2 "${JAILS:-1}"); do
  : > "$WORK/portsentry-$j.log"
  cat >> "$WORK/config.toml" <<EOF
[jails.portsentry-$j]
enabled = true
filter = "portsentry"
source = "file"
timestamp = "iso8601"
logpath = ["$WORK/portsentry-$j.log"]
maxretry = 1
EOF
done
ip link set lo up
echo "rig: starting daemon $BIN" | tee -a "$WORK/rig.log"
"$BIN" --config "$WORK/config.toml" > "$WORK/daemon.stdout" 2>&1 &
DPID=$!
echo "$DPID" > "$WORK/daemon.pid"
T0=$(date +%s.%N)
ready=0
for i in $(seq 1 300); do
  if [ -S "$SOCK" ] && grep -q "native: ready" "$WORK/daemon.log" 2>/dev/null; then ready=1; break; fi
  if ! kill -0 "$DPID" 2>/dev/null; then echo "rig: daemon died during startup" | tee -a "$WORK/rig.log"; cat "$WORK/daemon.stdout"; exit 2; fi
  sleep 0.1
done
if [ "$ready" != 1 ]; then echo "rig: startup did not reach ready" | tee -a "$WORK/rig.log"; exit 2; fi
T1=$(date +%s.%N)
echo "rig: ready after $(awk -v a="$T0" -v b="$T1" 'BEGIN{printf "%.2f", b-a}') s" | tee -a "$WORK/rig.log"
if [ "${JAILS:-1}" -gt 1 ]; then
  for j in $(seq 2 "$JAILS"); do
    ts=$(date -u +%Y-%m-%dT%H:%M:%S.%3N+0000)
    echo "$ts Scan from: [192.0.2.$j] (192.0.2.$j) protocol: [TCP] port: [23] type: [Connect] IP opts: [unknown] ignored: [false] triggered: [true] noblock: [true] blocked: [false]" >> "$WORK/portsentry-$j.log"
  done
  want=$(( $(wc -l < "$LOG") + JAILS - 1 ))
  seeded=0
  for i in $(seq 1 300); do
    active=$("$BIN" --socket "$SOCK" --timeout 5000 --output json status 2>/dev/null | tr -d '\n' | sed -n 's/.*"active_bans":\([0-9]*\).*/\1/p')
    [ "$active" = "$want" ] && seeded=1 && break
    sleep 0.1
  done
  if [ "$seeded" != 1 ]; then echo "rig: extra jails not seeded (active_bans=$active, want $want)" | tee -a "$WORK/rig.log"; kill -TERM "$DPID" 2>/dev/null; exit 2; fi
  echo "rig: seeded $((JAILS - 1)) extra jails, active_bans=$active" | tee -a "$WORK/rig.log"
fi
CLK=$(getconf CLK_TCK)
cpu_ticks() { awk '{print $14+$15}' /proc/$DPID/stat 2>/dev/null || echo 0; }
sample() {
  local now cpu st
  now=$(date +%s.%N); cpu=$(cpu_ticks)
  st=$("$BIN" --socket "$SOCK" --timeout 5000 --output json status 2>/dev/null | tr -d '\n')
  echo "$now $cpu $st" >> "$WORK/samples.log"
  echo "$st"
}
python3 "$(dirname "$0")/feed.py" "$LOG" "$TARGET" "$RATE" >> "$WORK/rig.log" 2>&1 &
GPID=$!
# sampler: 1 Hz until storage leaves healthy or generator done + settle window
last_cpu=$(cpu_ticks); last_t=$(date +%s.%N)
settle=0
result=0
while true; do
  st=$(sample)
  now=$(date +%s.%N); cpu=$(cpu_ticks)
  pct=$(awk -v c="$cpu" -v l="$last_cpu" -v k="$CLK" -v n="$now" -v t="$last_t" 'BEGIN{printf "%.1f", (c-l)*100/k/(n-t)}')
  last_cpu=$cpu; last_t=$now
  active=$(echo "$st" | sed -n 's/.*"active_bans":\([0-9]*\).*/\1/p')
  total=$(echo "$st" | sed -n 's/.*"total_bans":\([0-9]*\).*/\1/p')
  storage=$(echo "$st" | sed -n 's/.*"storage":"\([a-z]*\)".*/\1/p')
  cause=$(echo "$st" | sed -n 's/.*"cause":"\([A-Za-z]*\)".*/\1/p')
  prot=$(echo "$st" | sed -n 's/.*"protection":"\([a-z-]*\)".*/\1/p')
  busy=$(echo "$st" | sed -n 's/.*"worker_busy_age_ms":\([0-9]*\).*/\1/p')
  lines=$(wc -l < "$LOG")
  echo "t=$(awk -v a="$T1" -v b="$now" 'BEGIN{printf "%.0f", b-a}')s lines=$lines active=$active total=$total storage=$storage cause=$cause protection=$prot cpu=${pct}% busy_ms=$busy" | tee -a "$WORK/rig.log"
  if [ "$storage" != "healthy" ] && [ -n "$storage" ]; then
    echo "rig: storage left healthy: $storage cause=$cause" | tee -a "$WORK/rig.log"
    kill $GPID 2>/dev/null
    result=1
    break
  fi
  if ! kill -0 $GPID 2>/dev/null; then
    settle=$((settle+1))
    [ $settle -ge ${SETTLE_SECONDS:-30} ] && break
  fi
  if ! kill -0 "$DPID" 2>/dev/null; then echo "rig: daemon exited" | tee -a "$WORK/rig.log"; result=1; break; fi
  sleep 1
done
if [ "$result" != 0 ]; then kill "$GPID" 2>/dev/null || true; fi
if ! wait "$GPID"; then echo "rig: generator failed" | tee -a "$WORK/rig.log"; result=1; fi
GPID=""
expected=$((TARGET + ${JAILS:-1} - 1))
if [ "$storage" != healthy ] || [ -z "$total" ] || [ "${total:-0}" -lt "$expected" ]; then
  echo "rig: incomplete: storage=$storage total=$total expected=$expected" | tee -a "$WORK/rig.log"
  result=1
fi
echo "rig: final status:" | tee -a "$WORK/rig.log"
"$BIN" --socket "$SOCK" --timeout 5000 status --details 2>&1 | tee -a "$WORK/rig.log"
"$BIN" --socket "$SOCK" --timeout 5000 jails --details 2>&1 | tee -a "$WORK/rig.log"
echo "rig: daemon log tail:" | tee -a "$WORK/rig.log"
grep -v "would-ban" "$WORK/daemon.log" | tail -n 25 | tee -a "$WORK/rig.log"
if [ "${KEEP_RUNNING:-0}" = "1" ] && [ "$result" = 0 ]; then
  echo "rig: leaving daemon running pid $DPID" | tee -a "$WORK/rig.log"
  wait $DPID
else
  cleanup
  DPID=""
  echo "rig: daemon stopped" | tee -a "$WORK/rig.log"
fi
exit "$result"
