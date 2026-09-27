#!/usr/bin/env bash
# B5 sustained lifecycle (run inside unshare --user --map-root-user --net), adapted from rig.sh:
# a permanent oldest owner, RATE new distinct scopes/s for LOAD_S seconds, one hot subject
# re-appearing every HOT_S seconds, then DRAIN_S seconds of drain and idle. Samples kernel,
# daemon CPU/RSS, DB+WAL size and row counts.
set -euo pipefail
umask 077
[ "$#" -eq 3 ] || { echo "usage: load.sh BIN WORK ORACLE" >&2; exit 64; }
BIN=$(realpath "$1"); W=$(realpath "$2"); ORACLE=$(realpath "$3")
case "$W" in *[!a-zA-Z0-9_./-]*) echo 'unsafe TOML work path' >&2; exit 65;; esac
HERE=$(cd "$(dirname "$0")" && pwd)
[ -x "$BIN" ] && [ -x "$ORACLE" ] && [ -d "$W" ] || exit 65
[ -z "$(find "$W" -mindepth 1 -maxdepth 1 -print -quit)" ] || { echo "work directory must be empty" >&2; exit 65; }
for tool in python3 ip timeout getconf sha256sum; do command -v "$tool" >/dev/null || exit 65; done
# Parent must establish isolation and independently verify expected candidate hash.
[ -n "${F2Z_NATIVE_PARENT_NETNS:-}" ] && [ "$(readlink /proc/self/ns/net)" != "$F2Z_NATIVE_PARENT_NETNS" ] || { echo "distinct network namespace required" >&2; exit 65; }
DPID=; GPID=; HPID=; SOCKDIR=; EVALUATED=0
stop_child() {
  local pid=$1 require_success=${2:-0}
  [ "$pid" -gt 1 ] || return 1
  if [ -e "/proc/$pid/status" ]; then
    [ "$(awk '/^PPid:/{print $2}' "/proc/$pid/status")" = "$$" ] || return 1
    kill -TERM "$pid" 2>/dev/null || true
  fi
  for _ in $(seq 1 100); do
    if ! kill -0 "$pid" 2>/dev/null; then
      if wait "$pid"; then return 0; else
        local child_rc=$?
        [ "$require_success" -eq 0 ] && return 0
        return "$child_rc"
      fi
    fi
    sleep 0.1
  done
  kill -KILL "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
  return 1
}
cleanup() {
  local rc=$? cleanup_failed=0
  trap - EXIT INT TERM
  for pid in "$GPID" "$HPID" "$DPID"; do [ -z "$pid" ] || stop_child "$pid" || cleanup_failed=1; done
  [ -z "$SOCKDIR" ] || { rm -f "$SOCKDIR/f.sock"; rmdir "$SOCKDIR" || cleanup_failed=1; }
  if [ "$cleanup_failed" -ne 0 ]; then rc=1; fi
  if [ "$rc" -ne 0 ]; then
    echo "driver failed rc=$rc cleanup_failed=$cleanup_failed" >> "$W/driver-failure.txt"
    # Preserve an evaluator's incomplete verdict; only a cleanup failure overrides it.
    if [ "$EVALUATED" -eq 0 ] || [ "$cleanup_failed" -ne 0 ]; then
      python3 "$HERE/evaluate.py" failed "$W" "$rc" || true
    fi
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
RATE=${RATE:-3}; LOAD_S=${LOAD_S:-1800}; HOT_S=${HOT_S:-2}; DRAIN_S=${DRAIN_S:-900}; BANTIME=${BANTIME:-600}
mkdir "$W/state" "$W/kernel"; chmod 700 "$W" "$W/state"
SOCKDIR=$(mktemp -d /tmp/f2z-load.XXXXXXXX); SOCK=$SOCKDIR/f.sock
python3 "$HERE/evaluate.py" metadata "$W" "$BIN" "$RATE" "$LOAD_S" "$HOT_S" "$DRAIN_S" "$BANTIME" "$(getconf CLK_TCK)"
LOG="$W/portsentry.log"; PERM="$W/perm.log"; : > "$LOG"; : > "$PERM"; : > "$W/other.log"
cat > "$W/config.toml" <<EOF
[global]
native_ingestion = true
log_level = "info"
log_target = "$W/daemon.log"
socket_path = "$SOCK"
state_file = "$W/state/fail2zig.sqlite"
metrics_enabled = false
firewall = "nftables"
[defaults]
enforce = true
maxretry = 5
findtime = 600
bantime = $BANTIME
[jails.portsentry]
enabled = true
filter = "portsentry"
source = "file"
timestamp = "iso8601"
logpath = ["$LOG"]
maxretry = 1
[jails.perm]
enabled = true
filter = "portsentry"
source = "file"
timestamp = "iso8601"
logpath = ["$PERM"]
maxretry = 1
bantime = "permanent"
EOF
line() { echo "$(date -u +%Y-%m-%dT%H:%M:%S.%3N+0000) Scan from: [$1] ($1) protocol: [TCP] port: [23] type: [Connect] IP opts: [unknown] ignored: [false] triggered: [true] noblock: [true] blocked: [false]"; }
ip link set lo up
"$BIN" --config "$W/config.toml" > "$W/daemon.stdout" 2>&1 & DPID=$!
for _ in $(seq 1 600); do grep -q "native: ready" "$W/daemon.log" 2>/dev/null && break; kill -0 $DPID 2>/dev/null || { echo "daemon died"; exit 2; }; sleep 0.1; done
grep -q "native: ready" "$W/daemon.log" || { echo "readiness timeout" >&2; exit 1; }
T0=$(date +%s.%N); echo "b5: ready; start $T0 rate=$RATE load=$LOAD_S hot=$HOT_S drain=$DRAIN_S" | tee -a "$W/b5.log"
line 198.19.9.9 >> "$PERM"
( n=0; iv=$(awk -v r="$RATE" 'BEGIN{printf "%.4f", 1/r}'); end=$(awk -v a="$T0" -v l="$LOAD_S" 'BEGIN{printf "%d", a+l}')
  while [ "$(date +%s)" -lt "$end" ]; do a=$(( (n / 250) % 200 )); b=$(( n % 250 + 1 )); line "198.18.$a.$b" >> "$LOG"; n=$((n+1)); sleep "$iv"; done
  echo "b5: generator done ($n lines)" >> "$W/b5.log" ) & GPID=$!
( end=$(awk -v a="$T0" -v l="$LOAD_S" 'BEGIN{printf "%d", a+l}')
  while [ "$(date +%s)" -lt "$end" ]; do line 198.18.250.1 >> "$LOG"; sleep "$HOT_S"; done ) & HPID=$!
i=0
stop_at=$(awk -v a="$T0" -v l="$LOAD_S" -v d="$DRAIN_S" 'BEGIN{printf "%d", a+l+d}')
while [ "$(date +%s)" -lt "$stop_at" ] && kill -0 $DPID 2>/dev/null; do
  i=$((i+1)); f=$(printf '%s/kernel/%05d.txt' "$W" "$i")
  now=$(date +%s.%N); timeout 10 "$ORACLE" > "$f" 2> "$f.err"
  cpu=$(awk '{print $14+$15}' /proc/$DPID/stat); rss=$(awk '/VmRSS/{print $2}' /proc/$DPID/status)
  db=$(stat -c %s "$W/state/fail2zig.sqlite"); wal=0; if [ -e "$W/state/fail2zig.sqlite-wal" ]; then wal=$(stat -c %s "$W/state/fail2zig.sqlite-wal"); fi
  st=$("$BIN" --socket "$SOCK" --timeout 3000 --output json status 2>/dev/null | tr -d '\n')
  echo "$now cpu=$cpu rss_kb=$rss db=$db wal=$wal elems=$(grep -c '^elem' "$f" || true) lines=$(( $(wc -l < "$LOG") + $(wc -l < "$PERM") )) | $st" >> "$W/samples.log"
  [[ $rss =~ ^[0-9]+$ && $db =~ ^[0-9]+$ && $wal =~ ^[0-9]+$ ]] || {
    echo 'missing resource sample' >&2; exit 1;
  }
  (( rss <= 150 * 1024 && db + wal <= 272 * 1024 * 1024 )) || {
    echo 'resource ceiling exceeded' >&2; exit 1;
  }
  python3 "$HERE/evaluate.py" sample "$W" "$f" <<< "$st"
  if [ $((i % 30)) -eq 0 ]; then
    python3 -B -c "
import sqlite3,time,sys
from pathlib import Path
c=sqlite3.connect(Path(sys.argv[1]).as_uri()+'?mode=ro',uri=True,timeout=2)
q=lambda s:c.execute(s).fetchone()[0]
print(time.time(),'owners',q('select count(*) from effect_owners'),'live',q('select count(*) from effect_owners where lease_kind<>0'),'effects',q('select count(*) from native_effects'),'revisions',q('select count(*) from effect_owner_revisions'),'intents',q('select count(*) from effect_intents'),'observations',q('select count(*) from effect_observations'),'targets',q('select count(*) from action_targets'),'events',q('select count(*) from confirmed_effect_events'),'details',q('select count(*) from confirmed_event_details'),'retry_states',q('select count(*) from retry_states where jail=\x27portsentry\x27'),'retired',q('select count(*) from retry_retired'),'retirable',q('select count(*) from retry_states where jail=\x27portsentry\x27 and (lease_kind=0 or deadline_us<=%d) and last_processed_us<%d'%(int(time.time()*1e6),int(time.time()*1e6)-600000000)),'expired_pending',q('select count(*) from effect_owners o where o.lease_kind=1 and o.deadline_us<=%d'%int(time.time()*1e6)))" "$W/state/fail2zig.sqlite" >> "$W/counts.log" 2>&1
  fi
  sleep 2
done
echo "b5: sampling ended; daemon alive=$(kill -0 $DPID 2>/dev/null && echo yes || echo no)" | tee -a "$W/b5.log"
kill -0 "$DPID" || { echo "daemon exited before drain completed" >&2; exit 1; }
generator_rc=0
wait "$GPID" || generator_rc=$?; GPID=
wait "$HPID" || generator_rc=$?; HPID=
[ "$generator_rc" -eq 0 ] || exit "$generator_rc"
"$BIN" --socket "$SOCK" --timeout 5000 --output json status > "$W/status-final.json" 2>&1
stop_rc=0
stop_child "$DPID" 1 || stop_rc=$?; DPID=
[ "$stop_rc" -eq 0 ] || exit "$stop_rc"
timeout 10 "$ORACLE" > "$W/kernel-after-stop.txt"
echo "b5: stopped" | tee -a "$W/b5.log"
if python3 "$HERE/evaluate.py" evaluate "$W"; then
  EVALUATED=1
else
  EVALUATED=1
  exit 1
fi
