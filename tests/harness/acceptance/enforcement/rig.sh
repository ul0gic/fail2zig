#!/usr/bin/env bash
# Load reproduction rig: drives distinct PortSentry-style bans through a real nftables netlink backend in a rootless network namespace.
set -euo pipefail
umask 077
BIN="$1"; WORK="$2"; TARGET="$3"; RATE="$4"; BANTIME="${5:-600}"
case "$WORK" in *[!a-zA-Z0-9_./-]*) echo 'unsafe TOML work path' >&2; exit 65;; esac
SOCKDIR=${F2Z_SCENARIO_SOCKET_DIR:?parent-owned socket directory required}
case "$SOCKDIR" in *[!a-zA-Z0-9_./-]*) echo 'unsafe TOML socket path' >&2; exit 65;; esac
mkdir "$WORK/state"; chmod 700 "$WORK/state"
DPID=; GPID=
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  for pid in "$GPID" "$DPID"; do
    [ -n "$pid" ] || continue
    if [ -e "/proc/$pid/status" ]; then
      [ "$(awk '/^PPid:/{print $2}' "/proc/$pid/status")" = "$$" ] || { rc=1; continue; }
      kill -TERM "$pid" 2>/dev/null || true
      for _ in $(seq 1 100); do kill -0 "$pid" 2>/dev/null || break; sleep .1; done
      if kill -0 "$pid" 2>/dev/null; then kill -KILL "$pid" 2>/dev/null || true; rc=1; fi
    fi
    wait "$pid" 2>/dev/null || true
  done
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
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
ip link set lo up
echo "rig: starting daemon $BIN" | tee -a "$WORK/rig.log"
"$BIN" --config "$WORK/config.toml" > "$WORK/daemon.stdout" 2>&1 &
DPID=$!
echo "$DPID" > "$WORK/daemon.pid"
T0=$(date +%s.%N)
for _ in $(seq 1 300); do
  [ -S "$SOCK" ] && grep -q "native: ready" "$WORK/daemon.log" 2>/dev/null && break
  if ! kill -0 "$DPID" 2>/dev/null; then echo "rig: daemon died during startup" | tee -a "$WORK/rig.log"; cat "$WORK/daemon.stdout"; exit 2; fi
  sleep 0.1
done
[ -S "$SOCK" ] && grep -q "native: ready" "$WORK/daemon.log" || exit 1
T1=$(date +%s.%N)
echo "rig: ready after $(awk -v a="$T0" -v b="$T1" 'BEGIN{printf "%.2f", b-a}') s" | tee -a "$WORK/rig.log"
CLK=$(getconf CLK_TCK)
cpu_ticks() { awk '{print $14+$15}' /proc/$DPID/stat 2>/dev/null || echo 0; }
sample() {
  local now cpu st
  now=$(date +%s.%N); cpu=$(cpu_ticks)
  st=$("$BIN" --socket "$SOCK" --timeout 5000 --output json status 2>/dev/null | tr -d '\n')
  echo "$now $cpu $st" >> "$WORK/samples.log"
  echo "$st"
}
# generator in background: distinct IPs 198.18.A.B
(
  n=0
  interval=$(awk -v r="$RATE" 'BEGIN{printf "%.4f", 1/r}')
  while [ $n -lt $TARGET ]; do
    a=$(( (n / 250) % 256 )); b=$(( n % 250 + 1 ))
    ts=$(date -u +%Y-%m-%dT%H:%M:%S.%3N+0000)
    echo "$ts Scan from: [198.18.$a.$b] (198.18.$a.$b) protocol: [TCP] port: [23] type: [Connect] IP opts: [unknown] ignored: [false] triggered: [true] noblock: [true] blocked: [false]" >> "$LOG"
    n=$((n+1))
    sleep "$interval"
  done
  echo "rig: generator done ($n lines)" >> "$WORK/rig.log"
) &
GPID=$!
# sampler: 1 Hz until storage leaves healthy or generator done + settle window
last_cpu=$(cpu_ticks); last_t=$(date +%s.%N)
settle=0
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
    exit 1
  fi
  if ! kill -0 $GPID 2>/dev/null; then
    settle=$((settle+1))
    [ $settle -ge ${SETTLE_SECONDS:-30} ] && break
  fi
  if ! kill -0 "$DPID" 2>/dev/null; then echo "rig: daemon exited" | tee -a "$WORK/rig.log"; exit 1; fi
  sleep 1
done
echo "rig: final status:" | tee -a "$WORK/rig.log"
"$BIN" --socket "$SOCK" --timeout 5000 status --details 2>&1 | tee -a "$WORK/rig.log"
"$BIN" --socket "$SOCK" --timeout 5000 jails --details 2>&1 | tee -a "$WORK/rig.log"
echo "rig: daemon log tail:" | tee -a "$WORK/rig.log"
grep -v "would-ban" "$WORK/daemon.log" | tail -n 25 | tee -a "$WORK/rig.log"
if [ "${KEEP_RUNNING:-0}" = "1" ]; then
  echo "rig: leaving daemon running pid $DPID" | tee -a "$WORK/rig.log"
  generator_rc=0; wait "$GPID" || generator_rc=$?; GPID=
  [ "$generator_rc" -eq 0 ] || exit "$generator_rc"
  daemon_rc=0; wait "$DPID" || daemon_rc=$?; DPID=
  exit "$daemon_rc"
else
  kill -TERM "$DPID" 2>/dev/null
  for _ in $(seq 1 100); do kill -0 "$DPID" 2>/dev/null || break; sleep 0.1; done
  echo "rig: daemon stopped" | tee -a "$WORK/rig.log"
fi
