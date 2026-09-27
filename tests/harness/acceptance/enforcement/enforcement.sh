#!/usr/bin/env bash
# Existing B1: 210 distinct subjects at 4/s, 600s bans, independent kernel/TCP controls.
set -euo pipefail
umask 077
[ "$#" -eq 3 ] || exit 64
BIN=$(realpath "$1"); W=$(realpath "$2"); ORACLE=$(realpath "$3")
case "$W" in *[!a-zA-Z0-9_./-]*) echo 'unsafe TOML work path' >&2; exit 65;; esac
HERE=$(cd "$(dirname "$0")" && pwd)
[ -x "$BIN" ] && [ -x "$ORACLE" ] && [ -d "$W" ] || exit 65
[ -z "$(find "$W" -mindepth 1 -maxdepth 1 -print -quit)" ] || exit 65
[ -n "${F2Z_NATIVE_PARENT_NETNS:-}" ] && [ "$(readlink /proc/self/ns/net)" != "$F2Z_NATIVE_PARENT_NETNS" ] || exit 65
for tool in python3 socat ip timeout ss sha256sum; do command -v "$tool" >/dev/null || exit 65; done
R=; L=; SOCKET_DIR=; EVALUATED=0
cleanup() {
  local rc=$? cleanup_failed=0
  trap - EXIT INT TERM
  for pid in "$R" "$L"; do
    [ -n "$pid" ] || continue
    if [ -e "/proc/$pid/status" ]; then
      [ "$(awk '/^PPid:/{print $2}' "/proc/$pid/status")" = "$$" ] || { cleanup_failed=1; continue; }
      kill -TERM "$pid" 2>/dev/null || true
      for _ in $(seq 1 250); do kill -0 "$pid" 2>/dev/null || break; sleep .1; done
      if kill -0 "$pid" 2>/dev/null; then kill -KILL "$pid" 2>/dev/null || true; cleanup_failed=1; fi
    fi
    wait "$pid" 2>/dev/null || true
  done
  [ -z "$SOCKET_DIR" ] || { rm -f "$SOCKET_DIR/f.sock"; rmdir "$SOCKET_DIR" || cleanup_failed=1; }
  if [ "$cleanup_failed" -ne 0 ]; then rc=1; fi
  if [ "$rc" -ne 0 ] && { [ "$EVALUATED" -eq 0 ] || [ "$cleanup_failed" -ne 0 ]; }; then
    python3 "$HERE/evaluate.py" failed "$W" "$rc" || true
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$W/kernel"
sha256sum "$BIN" > "$W/candidate.sha256"
SOCKET_DIR=$(mktemp -d /tmp/f2z-enforce.XXXXXXXX)
ip link set lo up
# Explicit bindable addresses; a route through lo is not sufficient.
for addr in 10.99.0.1 198.19.0.1 198.18.0.1; do ip addr add "$addr/32" dev lo; done
# One owned listener process, no forked children to escape cleanup.
python3 -u -c 'import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("10.99.0.1",18080)); s.listen(128)
while True:
 c,_=s.accept(); c.close()
' > "$W/listener.log" 2>&1 & L=$!
probe() {
  local rc=0
  timeout 3 socat -u OPEN:/dev/null "TCP:10.99.0.1:18080,bind=$1,connect-timeout=1" >/dev/null 2>&1 || rc=$?
  echo "$(date +%s.%N) source=$1 rc=$rc" >> "$W/probes.log"
  return "$rc"
}
for _ in $(seq 1 50); do ss -Hltn 'sport = :18080' | grep -q . && break; sleep .1; done
probe 198.19.0.1; probe 198.18.0.1
KEEP_RUNNING=1 SETTLE_SECONDS=60 F2Z_SCENARIO_SOCKET_DIR="$SOCKET_DIR" \
  bash "$HERE/rig.sh" "$BIN" "$W" 210 4 600 > "$W/rig.stdout" 2>&1 & R=$!
for _ in $(seq 1 400); do grep -q 'rig: ready after' "$W/rig.log" 2>/dev/null && break; kill -0 "$R" || exit 1; sleep .1; done
grep -q 'rig: ready after' "$W/rig.log" || exit 1
start=$SECONDS; i=0; post_until=-1
while [ $((SECONDS-start)) -lt 360 ]; do
  kill -0 "$R" || exit 1
  i=$((i+1)); path=$(printf '%s/kernel/%05d.txt' "$W" "$i")
  timeout 10 "$ORACLE" > "$path"
  "$BIN" --socket "$SOCKET_DIR/f.sock" --timeout 3000 --output json status > "$W/status.json"
  python3 "$HERE/evaluate.py" sample "$W" "$path"
  probe 198.19.0.1
  if grep -q '^elem 198\.18\.0\.1/32 ' "$path"; then
    blocked_rc=0; probe 198.18.0.1 || blocked_rc=$?
    [ "$blocked_rc" -eq 1 ] || { echo "expected blocked connect rc1, got $blocked_rc" >&2; exit 1; }
    kill -0 "$L" || exit 1
    echo "$i blocked" >> "$W/tcp.log"
  fi
  # Original R3 campaign: 60s settle plus 120s post window.
  if [ "$post_until" -lt 0 ] && grep -q 'leaving daemon running' "$W/rig.log"; then post_until=$((SECONDS+120)); fi
  if [ "$post_until" -ge 0 ] && [ "$SECONDS" -ge "$post_until" ]; then break; fi
  sleep 1
done
[ "$post_until" -ge 0 ] && [ "$SECONDS" -ge "$post_until" ] || exit 1
D=$(cat "$W/daemon.pid")
[ "$D" -gt 1 ] && [ "$(awk '/^PPid:/{print $2}' "/proc/$D/status")" = "$R" ] || exit 1
kill -TERM "$D"
for _ in $(seq 1 300); do kill -0 "$R" 2>/dev/null || break; sleep .1; done
kill -0 "$R" 2>/dev/null && { echo 'daemon stop timeout' >&2; exit 1; }
rig_rc=0; wait "$R" || rig_rc=$?; R=
[ "$rig_rc" -eq 0 ] || exit "$rig_rc"
timeout 10 "$ORACLE" > "$W/kernel-after-stop.txt"
probe 198.19.0.1; probe 198.18.0.1
if python3 "$HERE/evaluate.py" evaluate "$W"; then
  EVALUATED=1
else
  EVALUATED=1
  exit 1
fi
