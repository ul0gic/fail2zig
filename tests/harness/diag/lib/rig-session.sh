#!/usr/bin/env bash
# Rig side of diag-run, inside `unshare --user --map-root-user --net`: rig-session.sh BIN WORK SOCKDIR SCENARIO CHECK SECONDS NLMON RUN_DIR
set -u
umask 077
BIN="$1"; WORK="$2"; SOCKDIR="$3"; SCENARIO="$4"; CHECK="$5"; SECS="$6"; NLMON="$7"; RUN="$8"
HARNESS=$(cd "$(dirname "$0")/.." && pwd)
export PATH="$PATH:/usr/sbin:/sbin"
SOCK="$SOCKDIR/f.sock"; LOG="$WORK/portsentry.log"; OTHER="$WORK/other.log"
mkdir -p "$WORK/state" "$WORK/diag" "$RUN/check"
: > "$LOG"; : > "$OTHER"
if [ "$SCENARIO" != empty ]; then
  cp -p "$SCENARIO"/fail2zig.sqlite* "$WORK/state/" || { echo "rig: no fail2zig.sqlite in $SCENARIO" | tee "$RUN/check/result.txt"; exit 2; }
fi
cat > "$WORK/config.toml" <<EOF
[global]
native_ingestion = true
log_level = "info"
log_target = "$WORK/daemon.log"
socket_path = "$SOCK"
state_file = "$WORK/state/fail2zig.sqlite"
metrics_enabled = true
metrics_bind = "127.0.0.1"
metrics_port = 9108
firewall = "nftables"
[defaults]
enforce = true
maxretry = 5
findtime = 600
bantime = 600
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
diag=0; "$BIN" --version | grep -q '+diag' && diag=1
FWD=""
if [ "$diag" = 1 ]; then
  export FAIL2ZIG_DIAG_DIR="$WORK/diag"
  if [ -n "${F2Z_DSN:-}" ]; then
    # Only loopback exists here: 127.0.0.1:18000 reaches GlitchTip through the Unix socket diag-run bridges outside.
    socat TCP-LISTEN:18000,bind=127.0.0.1,reuseaddr,fork "UNIX-CONNECT:$SOCKDIR/dsn.sock" &
    FWD=$!
    export FAIL2ZIG_DIAG_DSN; FAIL2ZIG_DIAG_DSN=$(echo "$F2Z_DSN" | sed -E 's#^(https?://[^@/]+@)[^/]+#\1127.0.0.1:18000#')
  fi
fi
unset F2Z_DSN
STARTED_AT=$EPOCHREALTIME
"$BIN" --config "$WORK/config.toml" > "$WORK/daemon.stdout" 2>&1 &
DPID=$!
for _ in $(seq 1 300); do
  [ -S "$SOCK" ] && grep -q "native: ready" "$WORK/daemon.log" 2>/dev/null && break
  kill -0 "$DPID" 2>/dev/null || break
  sleep 0.1
done
READY_AT=$EPOCHREALTIME
unset FAIL2ZIG_DIAG_DSN
if ! kill -0 "$DPID" 2>/dev/null; then
  echo "fail: daemon exited during startup: $(tail -n 3 "$WORK/daemon.stdout" | tr '\n' ' ')" | tee "$RUN/check/result.txt"
  cp "$WORK/daemon.log" "$WORK/daemon.stdout" "$RUN/" 2>/dev/null
  exit 2
fi
echo "rig: ready after $(awk -v a="$STARTED_AT" -v b="$READY_AT" 'BEGIN{printf "%.2f", b-a}') s, diag=$diag"
F2Z_MODE=rig F2Z_SCENARIO="$SCENARIO" F2Z_SECONDS="$SECS" F2Z_NLMON="$NLMON" F2Z_BIN="$BIN" F2Z_SOCK="$SOCK" \
F2Z_CONFIG="$WORK/config.toml" F2Z_UNIT="" F2Z_PID="$DPID" F2Z_NS_EXEC="" F2Z_OUT="$RUN/check" F2Z_HARNESS="$HARNESS" \
F2Z_PORTSENTRY_LOG="$LOG" F2Z_STARTED_AT="$STARTED_AT" F2Z_READY_AT="$READY_AT" F2Z_DIAG_DIR="$WORK/diag" \
  timeout $((SECS + 120)) "$HARNESS/checks/$CHECK" > "$RUN/check.console" 2>&1
echo "rig: check exit $?"
"$BIN" --socket "$SOCK" --timeout 5000 --output json status > "$RUN/status.json" 2>&1
"$BIN" --socket "$SOCK" --timeout 5000 --output json jails > "$RUN/jails.json" 2>&1
python3 -I -c 'import sys, urllib.request; sys.stdout.write(urllib.request.urlopen("http://127.0.0.1:9108/metrics", timeout=5).read().decode())' > "$RUN/metrics.txt" 2>&1
"$BIN" support-bundle --config "$WORK/config.toml" --socket "$SOCK" --out - > "$RUN/support-bundle.json" 2> "$RUN/support-bundle.err"
echo "exit $?" >> "$RUN/support-bundle.err"
T0=$EPOCHREALTIME
kill -TERM "$DPID" 2>/dev/null
for _ in $(seq 1 300); do kill -0 "$DPID" 2>/dev/null || break; sleep 0.1; done
echo "rig: daemon stopped after $(awk -v a="$T0" -v b="$EPOCHREALTIME" 'BEGIN{printf "%.2f", b-a}') s"
[ -n "$FWD" ] && kill "$FWD" 2>/dev/null
cp "$WORK/daemon.log" "$RUN/daemon.log"
[ -f "$WORK/diag/fail2zig-diag.jsonl" ] && cp "$WORK/diag/fail2zig-diag.jsonl" "$RUN/"
exit 0
