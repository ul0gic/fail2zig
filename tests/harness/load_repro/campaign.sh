#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig contributors
#
# Runs one daemon case in a rootless user + network namespace with an independent kernel
# oracle (kernel_oracle) and a TCP oracle, reusing rig.sh / restart.sh for the workload.
#
#   campaign.sh load    <bin> <work> <targets> <rate> <bantime>   fresh work dir, rig.sh workload
#   campaign.sh restart <bin> <work> [max_seconds]                preserved work dir, restart.sh
#
# Required env: EXPECT_SHA256 (binary hash), ORACLE (built kernel_oracle path).
# Optional env: POST_SECONDS (90) sampling after rig.sh stops sampling, SAMPLE_INTERVAL (2),
# CONNECT_TIMEOUT (1), RUN_LIMIT (1200) wall bound, SETTLE_SECONDS / HOLD_SECONDS passed to
# rig.sh / restart.sh, PROBE_BANNED (space-separated generator addresses to probe).
#
# TCP path: the listener and every probe source are local addresses on lo, so each probe SYN
# traverses the inet input hook the daemon's chain uses. A probe from 198.19.0.1 is never
# generated and is the unbanned control on the same path.
set -u
umask 077

HERE="$(cd "$(dirname "$0")" && pwd)"
MODE="${1:-}"; BIN="${2:-}"; WORK="${3:-}"
LISTEN_ADDR=10.99.0.1
LISTEN_PORT=18080
CONTROL_ADDR=198.19.0.1

usage() { echo "usage: campaign.sh load <bin> <work> <targets> <rate> <bantime> | restart <bin> <work> [max]" >&2; exit 64; }
[ -n "$MODE" ] && [ -n "$BIN" ] && [ -n "$WORK" ] || usage
case "$MODE" in load) [ $# -eq 6 ] || usage ;; restart) [ $# -ge 3 ] && [ $# -le 4 ] || usage ;; *) usage ;; esac

if [ "${CAMPAIGN_IN_NS:-0}" != "1" ]; then
  # Environment prerequisites are checked before the run so they are never reported as
  # product failures.
  fail_env() { echo "campaign: environment prerequisite failed: $*" >&2; exit 65; }
  [ -n "${EXPECT_SHA256:-}" ] || fail_env "EXPECT_SHA256 unset"
  [ -x "${ORACLE:-}" ] || fail_env "ORACLE is not an executable kernel_oracle"
  for tool in socat ip unshare timeout sha256sum awk; do command -v "$tool" >/dev/null || fail_env "missing $tool"; done
  BIN="$(realpath "$BIN")"; WORK="$(realpath -m "$WORK")"; ORACLE="$(realpath "$ORACLE")"
  actual="$(sha256sum "$BIN" | cut -d' ' -f1)"
  [ "$actual" = "$EXPECT_SHA256" ] || fail_env "binary hash $actual != $EXPECT_SHA256"
  if [ "$MODE" = "load" ]; then
    [ ! -e "$WORK" ] || fail_env "work directory $WORK already exists"
    mkdir -p "$WORK"
  else
    [ -f "$WORK/config.toml" ] && [ -f "$WORK/state/fail2zig.sqlite" ] || fail_env "no preserved state in $WORK"
  fi
  fstype="$(stat -f -c %T "$WORK")"
  case "$fstype" in tmpfs|ramfs) fail_env "work directory is on $fstype" ;; esac
  unshare --user --map-root-user --net "$ORACLE" > /dev/null || fail_env "kernel_oracle cannot read nftables in a namespace"
  echo "campaign: mode=$MODE bin=$BIN sha256=$actual work=$WORK fs=$fstype kernel=$(uname -r)" | tee -a "$WORK/campaign.log"
  CAMPAIGN_IN_NS=1 ORACLE="$ORACLE" exec timeout --kill-after=30 "${RUN_LIMIT:-1200}" \
    unshare --user --map-root-user --net bash "$0" "$@"
fi

BIN="$(realpath "$BIN")"; WORK="$(realpath "$WORK")"
INTERVAL="${SAMPLE_INTERVAL:-2}"; CTO="${CONNECT_TIMEOUT:-1}"
OUT="$WORK/campaign-$MODE"
rm -rf "$OUT"; mkdir -p "$OUT/kernel"
LOG="$WORK/campaign.log"
note() { echo "campaign: $*" | tee -a "$LOG"; }
now() { date +%s.%N; }

PIDS=()
DPID=""
FAIL=0
# stop_daemon <pid>: a daemon still alive 30 s after TERM is killed and fails the case.
stop_daemon() {
  kill -TERM "$1" 2>/dev/null
  for _ in $(seq 1 300); do kill -0 "$1" 2>/dev/null || return 0; sleep 0.1; done
  note "daemon $1 ignored TERM for 30 s; sending KILL"
  kill -KILL "$1" 2>/dev/null
  FAIL=1
}
cleanup() {
  if [ -z "$DPID" ] && [ "$MODE" = "load" ] && [ -f "$WORK/daemon.pid" ]; then DPID="$(cat "$WORK/daemon.pid")"; fi
  [ -n "$DPID" ] && stop_daemon "$DPID"
  for pid in "${PIDS[@]}"; do kill -TERM "$pid" 2>/dev/null; done
  wait 2>/dev/null
}
trap 'note "interrupted"; cleanup; exit 70' TERM INT

ip link set lo up
ip addr add 198.18.255.254/16 dev lo
ip addr add "$CONTROL_ADDR/32" dev lo
ip addr add "$LISTEN_ADDR/32" dev lo

probe() { # probe <source> -> prints "rc latency_ms"
  local t0 t1 rc
  t0=$(now)
  socat -u OPEN:/dev/null "TCP:$LISTEN_ADDR:$LISTEN_PORT,bind=$1,connect-timeout=$CTO" 2>/dev/null
  rc=$?
  t1=$(now)
  echo "$rc $(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.0f", (b-a)*1000}')"
}

socat -u "TCP-LISTEN:$LISTEN_PORT,bind=$LISTEN_ADDR,reuseaddr,fork,backlog=128" OPEN:/dev/null &
LPID=$!; PIDS+=("$LPID")
for _ in $(seq 1 50); do ss -Hltn "sport = :$LISTEN_PORT" | grep -q . && break; sleep 0.1; done

PROBE_BANNED="${PROBE_BANNED:-198.18.0.1}"
SOURCES="$PROBE_BANNED $CONTROL_ADDR"

# Pre-daemon positive control: every probe source reaches the listener with no ruleset.
for src in $SOURCES; do note "pre-daemon probe $src -> $(probe "$src")"; done
"$ORACLE" > "$OUT/kernel/pre-daemon.txt"; note "pre-daemon kernel rc=$? $(tail -n 1 "$OUT/kernel/pre-daemon.txt")"

# The socket path is whatever rig.sh / restart.sh wrote into the config they started.
if [ "$MODE" = "load" ]; then CONF="$WORK/config.toml"; else CONF="$WORK/config-restart.toml"; rm -f "$CONF"; fi
sock() { sed -n 's/^socket_path = "\(.*\)"$/\1/p' "$CONF" 2>/dev/null; }

tcp_sampler() {
  local i=0 src r
  while [ ! -e "$OUT/stop" ]; do
    for src in $SOURCES; do
      r=$(probe "$src"); echo "$(now) $src $r" >> "$OUT/tcp.log"
    done
    i=$((i+1)); sleep "$INTERVAL"
  done
  echo "samples=$i interval_s=$INTERVAL connect_timeout_s=$CTO sources=$(echo "$SOURCES" | wc -w)" > "$OUT/tcp-cpu.txt"
  times >> "$OUT/tcp-cpu.txt"
}

kernel_sampler() {
  local i=0 t rc st f
  while [ ! -e "$OUT/stop" ]; do
    i=$((i+1)); f=$(printf '%s/kernel/%05d.txt' "$OUT" "$i")
    t=$(now); "$ORACLE" > "$f" 2> "$f.err"; rc=$?
    [ -s "$f.err" ] || rm -f "$f.err"
    st=$("$BIN" --socket "$(sock)" --timeout 3000 --output json status 2>/dev/null | tr -d '\n')
    echo "$t rc=$rc $(tail -n 1 "$f") | $st" >> "$OUT/kernel.log"
    sleep "$INTERVAL"
  done
  echo "samples=$i interval_s=$INTERVAL" > "$OUT/kernel-cpu.txt"
  times >> "$OUT/kernel-cpu.txt"
}

tcp_sampler & PIDS+=("$!")
kernel_sampler & PIDS+=("$!")
T0=$(now)

if [ "$MODE" = "load" ]; then
  KEEP_RUNNING=1 bash "$HERE/rig.sh" "$BIN" "$WORK" "$4" "$5" "$6" > "$OUT/rig.stdout" 2>&1 &
  RPID=$!; PIDS+=("$RPID")
  # rig.sh stops its own sampling when storage leaves healthy or its settle window ends.
  while kill -0 "$RPID" 2>/dev/null && ! grep -q "leaving daemon running" "$WORK/rig.log" 2>/dev/null; do sleep 1; done
  if ! kill -0 "$RPID" 2>/dev/null; then note "rig.sh exited before the post window (daemon not running)"; fi
  note "rig sampling ended at t=$(awk -v a="$T0" -v b="$(now)" 'BEGIN{printf "%.0f", b-a}')s; post window ${POST_SECONDS:-90}s"
  "$BIN" --socket "$(sock)" --timeout 5000 --output json list > "$OUT/list-at-rig-end.json" 2>&1
  sleep "${POST_SECONDS:-90}"
  "$BIN" --socket "$(sock)" --timeout 5000 --output json list > "$OUT/list-final.json" 2>&1
  "$BIN" --socket "$(sock)" --timeout 5000 --output json status > "$OUT/status-final.json" 2>&1
  "$ORACLE" > "$OUT/kernel/final-running.txt"; note "final running kernel rc=$? $(tail -n 1 "$OUT/kernel/final-running.txt")"
  touch "$OUT/stop"
  DPID="$(cat "$WORK/daemon.pid")"
  note "daemon cpu_s=$(awk -v k="$(getconf CLK_TCK)" '{printf "%.1f", ($14+$15)/k}' "/proc/$DPID/stat" 2>/dev/null)"
  stop_daemon "$DPID"
  wait "$RPID" 2>/dev/null
else
  HOLD_SECONDS="${HOLD_SECONDS:-0}" bash "$HERE/restart.sh" "$BIN" "$WORK" "${4:-900}" > "$OUT/restart.stdout" 2>&1 &
  RPID=$!; PIDS+=("$RPID")
  for _ in $(seq 1 100); do
    for child in $(pgrep -P "$RPID"); do
      [ "$(readlink "/proc/$child/exe" 2>/dev/null)" = "$BIN" ] && DPID="$child"
    done
    [ -n "$DPID" ] && break
    kill -0 "$RPID" 2>/dev/null || break
    sleep 0.1
  done
  [ -n "$DPID" ] || note "restart daemon pid not found"
  wait "$RPID"
  # restart.sh waits 15 s after TERM and does not escalate.
  if [ -n "$DPID" ] && kill -0 "$DPID" 2>/dev/null; then stop_daemon "$DPID"; fi
  touch "$OUT/stop"
fi

"$ORACLE" > "$OUT/kernel/after-stop.txt"; note "after-stop kernel rc=$? $(tail -n 1 "$OUT/kernel/after-stop.txt")"
wait "${PIDS[1]}" "${PIDS[2]}" 2>/dev/null
for src in $SOURCES; do note "after-stop probe $src -> $(probe "$src")"; done
kill -TERM "$LPID" 2>/dev/null
wait 2>/dev/null
note "done elapsed=$(awk -v a="$T0" -v b="$(now)" 'BEGIN{printf "%.0f", b-a}')s fail=$FAIL"
exit "$FAIL"
