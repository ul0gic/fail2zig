#!/usr/bin/env bash
# Target side of diag-run, run as root on f2z-target: lock RUN_ID | prepare MODE STAGE SCENARIO SECONDS NLMON (DSN on stdin) | collect STAGE
set -euo pipefail
export PATH="$PATH:/usr/sbin:/sbin"
LOCK=/run/f2z-diag-run.lock
NS=f2z-diag
LIBEXEC=/usr/local/libexec/f2z-diag
ETC=/etc/f2z-diag
FWD=/run/f2z-diag-fwd
METRICS_ADDR=172.16.150.253
METRICS_PORT=9108
DSN_PORT=18000
INSTALLED_CONFIG=/etc/fail2zig/config.toml

log() { echo "target: $*"; }

start_unit() {
  STARTED_AT=$EPOCHREALTIME
  systemctl "$1" "$2" && return 0
  log "$2 failed to $1"
  journalctl -u "$2" -n 30 --no-pager -o short-iso-precise
  exit 4
}

toml() { sed -n "/^\[global\]/,/^\[/ s/^$1 *= *\"\{0,1\}\([^\"]*\)\"\{0,1\} *$/\1/p" "$2" | head -n1; }

forward() { systemd-run --quiet --collect --unit="$1" "${@:2}"; }

wait_ready() {
  local bin=$1 sock=$2
  for _ in $(seq 1 1200); do
    "$bin" --socket "$sock" --timeout 3000 --output json status >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

dsn_env() {
  local dsn=$1 dir=$2 netns=$3
  install -d -m 0755 "$ETC"
  install -d -o fail2zig -g fail2zig -m 0700 "$dir"
  { echo "FAIL2ZIG_DIAG_DIR=$dir"; [ -n "$dsn" ] && echo "FAIL2ZIG_DIAG_DSN=$dsn"; } > "$ETC/diag.env"
  chmod 0600 "$ETC/diag.env"
  [ -n "$dsn" ] || return 0
  if [ "$netns" = 1 ]; then
    # The candidate namespace has only loopback: bridge 127.0.0.1:18000 inside it to GlitchTip through a Unix socket.
    local upstream; upstream=$(echo "$dsn" | sed -E 's#^https?://[^@/]+@([^/]+)/.*#\1#')
    install -d -m 0700 "$FWD"
    forward f2z-diag-dsn-host socat "UNIX-LISTEN:$FWD/dsn.sock,fork,mode=600" "TCP:$upstream"
    forward f2z-diag-dsn-ns ip netns exec "$NS" socat "TCP-LISTEN:$DSN_PORT,bind=127.0.0.1,reuseaddr,fork" "UNIX-CONNECT:$FWD/dsn.sock"
    sed -i -E "s#^(FAIL2ZIG_DIAG_DSN=https?://[^@/]+@)[^/]+#\1127.0.0.1:$DSN_PORT#" "$ETC/diag.env"
  fi
}

prepare_candidate() {
  local stage=$1 dsn=$2 diag=$3
  install -d -m 0755 "$LIBEXEC" "$ETC"
  install -o root -g root -m 0755 "$stage/fail2zig" "$LIBEXEC/fail2zig"
  ip netns add "$NS"
  ip -n "$NS" link set lo up
  install -d -o fail2zig -g fail2zig -m 0750 /var/lib/f2z-diag
  local state; state=$(toml state_file "$INSTALLED_CONFIG")
  # Freeze the baseline so the database, WAL and shared-memory files are copied as one consistent set.
  systemctl freeze fail2zig
  for f in "$state" "$state-wal" "$state-shm"; do [ -e "$f" ] && cp -p "$f" /var/lib/f2z-diag/; done
  systemctl thaw fail2zig
  local base; base=$(basename "$state")
  sed -E -e "s#^state_file *=.*#state_file = \"/var/lib/f2z-diag/$base\"#" \
         -e "s#^socket_path *=.*#socket_path = \"/run/f2z-diag/fail2zig.sock\"#" \
         -e "s#^pid_file *=.*#pid_file = \"/run/f2z-diag/fail2zig.pid\"#" \
         -e '/^metrics_(enabled|bind|port) *=/d' \
         "$INSTALLED_CONFIG" | awk -v port="$METRICS_PORT" '{print} /^\[global\]/{print "metrics_enabled = true\nmetrics_bind = \"127.0.0.1\"\nmetrics_port = " port}' > "$ETC/config.toml"
  chown root:fail2zig "$ETC/config.toml"; chmod 0640 "$ETC/config.toml"
  sed -E -e 's#^Description=.*#Description=fail2zig diag-run candidate#' \
         -e "s#^ExecStart=.*#ExecStart=$LIBEXEC/fail2zig --config $ETC/config.toml#" \
         -e 's#^Restart=.*#Restart=no#' -e '/^RestartSec=/d' \
         -e 's#^TimeoutStopSec=.*#TimeoutStopSec=900#' \
         -e 's#^ReadWritePaths=.*#ReadWritePaths=/var/lib/f2z-diag /run/f2z-diag#' \
         -e 's#^RuntimeDirectory=.*#RuntimeDirectory=f2z-diag#' \
         -e 's#^StateDirectory=.*#StateDirectory=f2z-diag#' \
         -e "s#^\[Service\]#[Service]\nNetworkNamespacePath=/run/netns/$NS\nEnvironmentFile=-$ETC/diag.env#" \
         -e '/^\[Install\]/,$d' \
         "$(systemctl show -P FragmentPath fail2zig)" > /run/systemd/system/f2z-diag.service
  if [ "$diag" = 1 ]; then dsn_env "$dsn" /var/lib/f2z-diag/diag 1; fi
  systemctl daemon-reload
  start_unit start f2z-diag
  install -d -m 0700 "$FWD"
  forward f2z-diag-metrics-ns ip netns exec "$NS" socat "UNIX-LISTEN:$FWD/metrics.sock,fork,mode=600" "TCP:127.0.0.1:$METRICS_PORT"
  forward f2z-diag-metrics-host socat "TCP-LISTEN:$METRICS_PORT,bind=$METRICS_ADDR,reuseaddr,fork" "UNIX-CONNECT:$FWD/metrics.sock"
  UNIT=f2z-diag; BIN=$LIBEXEC/fail2zig; CONFIG=$ETC/config.toml; SOCK=/run/f2z-diag/fail2zig.sock
  DIAG_DIR=/var/lib/f2z-diag/diag; NS_EXEC="ip netns exec $NS"
}

prepare_upgrade() {
  local stage=$1 dsn=$2 diag=$3
  cp -p /usr/local/bin/fail2zig /usr/local/bin/fail2zig.diag-run-prev
  install -o root -g root -m 0755 "$stage/fail2zig" /usr/local/bin/fail2zig
  local dropin=/run/systemd/system/fail2zig.service.d/diag-run.conf
  install -d /run/systemd/system/fail2zig.service.d
  printf '[Service]\n' > "$dropin"
  if [ "$diag" = 1 ]; then
    dsn_env "$dsn" /var/lib/fail2zig/diag 0
    printf 'EnvironmentFile=-%s/diag.env\n' "$ETC" >> "$dropin"
  fi
  local mbind mport
  if [ "$(toml metrics_enabled "$INSTALLED_CONFIG")" = true ]; then
    mbind=$(toml metrics_bind "$INSTALLED_CONFIG"); mport=$(toml metrics_port "$INSTALLED_CONFIG")
  else
    install -d -m 0755 "$ETC"
    sed -E '/^metrics_(enabled|bind|port) *=/d' "$INSTALLED_CONFIG" \
      | awk -v port="$METRICS_PORT" '{print} /^\[global\]/{print "metrics_enabled = true\nmetrics_bind = \"127.0.0.1\"\nmetrics_port = " port}' > "$ETC/config.toml"
    chown root:fail2zig "$ETC/config.toml"; chmod 0640 "$ETC/config.toml"
    printf 'ExecStart=\nExecStart=/usr/local/bin/fail2zig --config %s/config.toml\n' "$ETC" >> "$dropin"
    mbind=127.0.0.1; mport=$METRICS_PORT
  fi
  systemctl daemon-reload
  start_unit restart fail2zig
  log "restart took $(awk -v a="$STARTED_AT" -v b="$EPOCHREALTIME" 'BEGIN{printf "%.1f", b-a}') s"
  forward f2z-diag-metrics-host socat "TCP-LISTEN:$METRICS_PORT,bind=$METRICS_ADDR,reuseaddr,fork" "TCP:$mbind:$mport"
  UNIT=fail2zig; BIN=/usr/local/bin/fail2zig; CONFIG=$INSTALLED_CONFIG; SOCK=$(toml socket_path "$INSTALLED_CONFIG")
  DIAG_DIR=/var/lib/fail2zig/diag; NS_EXEC=""
}

case "$1" in
  lock)
    if ! mkdir "$LOCK" 2>/dev/null; then
      echo "target: held by $(cat "$LOCK/owner" 2>/dev/null || echo unknown)" >&2
      exit 3
    fi
    echo "$2" > "$LOCK/owner"
    ;;
  prepare)
    MODE=$2; STAGE=$3; SCENARIO=$4; SECS=$5; NLMON=$6
    IFS= read -r DSN || true
    diag=0; "$STAGE/fail2zig" --version | grep -q '+diag' && diag=1
    install -d -m 0700 "$STAGE/out" "$STAGE/check"
    "prepare_$MODE" "$STAGE" "$DSN" "$diag"
    wait_ready "$BIN" "$SOCK" || { log "daemon not ready within 1200 s"; systemctl status "$UNIT" --no-pager | tail -n 20; exit 4; }
    READY_AT=$EPOCHREALTIME
    log "$UNIT ready after $(awk -v a="$STARTED_AT" -v b="$READY_AT" 'BEGIN{printf "%.1f", b-a}') s, diag=$diag"
    {
      printf 'F2Z_MODE=%q\nF2Z_SCENARIO=%q\nF2Z_SECONDS=%q\nF2Z_NLMON=%q\n' "target-$MODE" "$SCENARIO" "$SECS" "$NLMON"
      printf 'F2Z_BIN=%q\nF2Z_SOCK=%q\nF2Z_CONFIG=%q\nF2Z_UNIT=%q\n' "$BIN" "$SOCK" "$CONFIG" "$UNIT"
      printf 'F2Z_PID=%q\nF2Z_NS_EXEC=%q\nF2Z_OUT=%q\nF2Z_HARNESS=%q\n' "$(systemctl show -P MainPID "$UNIT")" "$NS_EXEC" "$STAGE/check" "$STAGE"
      printf 'F2Z_PORTSENTRY_LOG=%q\nF2Z_STARTED_AT=%q\nF2Z_READY_AT=%q\nF2Z_DIAG_DIR=%q\n' \
        "$(sed -n '/^\[jails.portsentry\]/,/^\[/ s/^logpath *= *\["\([^"]*\)".*/\1/p' "$CONFIG")" "$STARTED_AT" "$READY_AT" "$DIAG_DIR"
    } > "$STAGE/check.env"
    ;;
  collect)
    STAGE=$2; O=$STAGE/out
    set -a; . "$STAGE/check.env"; set +a
    "$F2Z_BIN" --socket "$F2Z_SOCK" --timeout 5000 --output json status > "$O/status.json" 2>&1 || true
    "$F2Z_BIN" --socket "$F2Z_SOCK" --timeout 5000 --output json jails > "$O/jails.json" 2>&1 || true
    [ -f "$F2Z_DIAG_DIR/fail2zig-diag.jsonl" ] && cp "$F2Z_DIAG_DIR/fail2zig-diag.jsonl" "$O/"
    journalctl -u "$F2Z_UNIT" --since "@${F2Z_STARTED_AT%.*}" -o short-iso-precise --no-pager > "$O/daemon.log" 2>&1 || true
    set +e
    sudo -u fail2zig "$F2Z_BIN" support-bundle --config "$F2Z_CONFIG" --socket "$F2Z_SOCK" --out - > "$O/support-bundle.json" 2> "$O/support-bundle.err"
    echo "exit $?" >> "$O/support-bundle.err"
    set -e
    systemctl status "$F2Z_UNIT" --no-pager > "$O/unit-status.txt" 2>&1 || true
    sha256sum "$F2Z_BIN" > "$O/binary.sha256"
    ;;
  *) echo "usage: target.sh lock RUN_ID | prepare MODE STAGE SCENARIO SECONDS NLMON | collect STAGE" >&2; exit 2 ;;
esac
