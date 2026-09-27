#!/usr/bin/env bash
# Restart timing phase: starts the daemon on a PRESERVED state directory inside a fresh
# network namespace (no nftables scaffold, like a host reboot) and records how long the
# worker needs to re-dispatch every stored effect before readiness.
# Run INSIDE: unshare --user --map-root-user --net bash restart.sh <bin> <work> [max_seconds]
set -u
umask 077
BIN="$1"; WORK="$2"; MAX="${3:-300}"
SOCKDIR="${XDG_RUNTIME_DIR:-/tmp}/b75/$(basename "$WORK")-restart"; rm -rf "$SOCKDIR"; mkdir -p "$SOCKDIR"
SOCK="$SOCKDIR/f.sock"
sed -e "s|^socket_path = .*|socket_path = \"$SOCK\"|" -e "s|^log_target = .*|log_target = \"$WORK/restart.log\"|" "$WORK/config.toml" > "$WORK/config-restart.toml"
ip link set lo up
: > "$WORK/restart.log"
echo "restart: starting $BIN on preserved state" | tee -a "$WORK/rig.log"
T0=$(date +%s.%N)
"$BIN" --config "$WORK/config-restart.toml" > "$WORK/restart.stdout" 2>&1 &
DPID=$!
CLK=$(getconf CLK_TCK)
ready=""
for i in $(seq 1 "$MAX"); do
  now=$(date +%s.%N)
  el=$(awk -v a="$T0" -v b="$now" 'BEGIN{printf "%.0f", b-a}')
  if grep -q "native: ready" "$WORK/restart.log" 2>/dev/null; then ready=$el; fi
  st=$("$BIN" --socket "$SOCK" --timeout 3000 --output json status 2>/dev/null | tr -d '\n')
  active=$(echo "$st" | sed -n 's/.*"active_bans":\([0-9]*\).*/\1/p')
  storage=$(echo "$st" | sed -n 's/.*"storage":"\([a-z]*\)".*/\1/p')
  prot=$(echo "$st" | sed -n 's/.*"protection":"\([a-z-]*\)".*/\1/p')
  cpu=$(awk -v k="$CLK" '{printf "%.1f", ($14+$15)/k}' /proc/$DPID/stat 2>/dev/null)
  echo "restart: t=${el}s active=$active storage=$storage protection=$prot cpu_s=$cpu ready_at=${ready:-pending}" | tee -a "$WORK/rig.log"
  if [ -n "$ready" ]; then break; fi
  if ! kill -0 "$DPID" 2>/dev/null; then echo "restart: daemon exited" | tee -a "$WORK/rig.log"; break; fi
  sleep 1
done
# Optional hold: keep sampling after readiness until storage leaves healthy or HOLD_SECONDS pass.
hold=0
while [ "${HOLD_SECONDS:-0}" -gt 0 ] && [ $hold -lt "${HOLD_SECONDS:-0}" ]; do
  st=$("$BIN" --socket "$SOCK" --timeout 3000 --output json status 2>/dev/null | tr -d '\n')
  active=$(echo "$st" | sed -n 's/.*"active_bans":\([0-9]*\).*/\1/p')
  total=$(echo "$st" | sed -n 's/.*"total_bans":\([0-9]*\).*/\1/p')
  storage=$(echo "$st" | sed -n 's/.*"storage":"\([a-z]*\)".*/\1/p')
  cause=$(echo "$st" | sed -n 's/.*"cause":"\([A-Za-z]*\)".*/\1/p')
  code=$(echo "$st" | sed -n 's/.*"sqlite_code":\([0-9]*\).*/\1/p')
  cpu=$(awk -v k="$CLK" '{printf "%.1f", ($14+$15)/k}' /proc/$DPID/stat 2>/dev/null)
  echo "hold: t=${hold}s active=$active total=$total storage=$storage cause=$cause sqlite_code=$code cpu_s=$cpu" | tee -a "$WORK/rig.log"
  if [ -n "$storage" ] && [ "$storage" != "healthy" ]; then echo "hold: storage left healthy" | tee -a "$WORK/rig.log"; break; fi
  if ! kill -0 "$DPID" 2>/dev/null; then echo "hold: daemon exited" | tee -a "$WORK/rig.log"; break; fi
  hold=$((hold+1)); sleep 1
done
echo "restart: log tail (non-ban lines):" | tee -a "$WORK/rig.log"
grep -v "would-ban" "$WORK/restart.log" | tail -n 12 | tee -a "$WORK/rig.log"
tail -n 5 "$WORK/restart.stdout" | tee -a "$WORK/rig.log"
kill -TERM "$DPID" 2>/dev/null
for i in $(seq 1 150); do kill -0 "$DPID" 2>/dev/null || break; sleep 0.1; done
echo "restart: daemon stopped" | tee -a "$WORK/rig.log"
