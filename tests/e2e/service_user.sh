#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Run only in the authorized Debian lab. The published service is never stopped.
set -euo pipefail
BIN="${1:?usage: service_user.sh ABSOLUTE_BIN_DIR [--backends-only]}"
MODE="${2:-full}"
[ "$#" -le 2 ] || exit 2
case "$MODE" in full|--backends-only) ;; *) exit 2 ;; esac
[[ "$BIN" = /* ]] && [ -x "$BIN/fail2zig" ] && [ "$(id -u)" = 0 ] || exit 2
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
for cmd in systemctl ip unshare runuser useradd userdel getent nft iptables ipset timeout; do
    command -v "$cmd" >/dev/null || { echo "missing required lab tool: $cmd" >&2; exit 2; }
done
NAME="f2z-user-$$"
CURRENT_NS="$NAME"
NAMESPACES=()
WORK="/var/lib/$NAME"
RUNTIME="/run/$NAME"
UNIT="$NAME.service"
MONITOR="$NAME"
CREATED_USER=0
CREATED_GROUP=0
cleanup() {
    local result=$?
    trap - EXIT
    set +e
    systemctl stop "$UNIT"
    rm -f "/run/systemd/system/$UNIT"
    systemctl daemon-reload
    systemctl reset-failed "$UNIT" >/dev/null 2>&1
    for namespace in "${NAMESPACES[@]}"; do ip netns del "$namespace"; done
    userdel "$MONITOR" >/dev/null 2>&1
    if [ "$CREATED_USER" = 1 ]; then userdel fail2zig; fi
    if [ "$CREATED_GROUP" = 1 ]; then groupdel fail2zig; fi
    if [ "$result" = 0 ]; then rm -rf "$WORK"; else echo "service-user: retained failure material $WORK" >&2; fi
    exit "$result"
}
[ ! -e "$WORK" ] && [ ! -e "$RUNTIME" ] && ! getent passwd "$MONITOR" >/dev/null || exit 2
mkdir -m 0755 "$WORK"
trap cleanup EXIT
if ! getent group fail2zig >/dev/null; then groupadd --system fail2zig; CREATED_GROUP=1; fi
if ! getent passwd fail2zig >/dev/null; then
    useradd --system --gid fail2zig --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin fail2zig
    CREATED_USER=1
fi
useradd --system --gid fail2zig --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin "$MONITOR"
ip netns add "$NAME"
NAMESPACES+=("$NAME")
ip -n "$NAME" link set lo up
install -d -m 0750 "$WORK/state" "$WORK/config" "$WORK/install" "$WORK/stub"
install -o root -g root -m 0755 "$BIN/fail2zig" "$WORK/fail2zig"
printf '#!/bin/sh\nexit 0\n' > "$WORK/stub/systemctl"
chmod 0755 "$WORK/stub/systemctl"
: > "$WORK/auth.log"
chmod 0600 "$WORK/auth.log"
cat > "$WORK/config/config.toml" <<CONF
[global]
state_file = "/var/lib/fail2zig/state.bin"
metrics_enabled = false
[defaults]
banaction = "log-only"
CONF

# A private PID/mount namespace hides published writers and binds only the exact
# disposable state/config. The installer cannot reach published state or units.
installer() {
    local outer_pid
    outer_pid="$(systemctl show "$UNIT" -p MainPID --value 2>/dev/null || :)"
    case "$outer_pid" in 0|"") ;; *) echo "refusing installer while disposable unit has PID $outer_pid" >&2; return 1 ;; esac
    timeout --kill-after=5 30 unshare --mount --pid --fork --mount-proc bash -eu -c '
        mount --make-rprivate /
        mount --bind "$1/state" /var/lib/fail2zig
        mount --bind "$1/config" /etc/fail2zig
        export PATH="$1/stub:$PATH"
        export FAIL2ZIG_PREFIX="$1/install" FAIL2ZIG_SYSTEMD_DIR="$1/install/units"
        exec bash "$2/scripts/install.sh" --local-bin "$3"
    ' _ "$WORK" "$ROOT" "$BIN"
}
if [ "$MODE" = full ]; then
installer
[ "$(stat -c %U "$WORK/state")" = fail2zig ]
[ "$(stat -c %U "$WORK/install/bin/fail2zig")" = root ]
printf 'service-user: PASS fresh disposable install\n'
fi

write_config() {
    local backend="$1" state_file="$WORK/state/state.bin"
    if [ "$backend" != nftables ]; then state_file="$WORK/state/$backend.bin"; fi
    cat > "$WORK/live.toml" <<CONF
[global]
state_file = "$state_file"
socket_path = "$RUNTIME/fail2zig.sock"
firewall_namespace = "/run/netns/$CURRENT_NS"
firewall = "$backend"
metrics_enabled = false
log_target = "stderr"
[defaults]
maxretry = 1
findtime = 600
bantime = 600
[jails.sshd]
filter = "sshd"
source = "file"
timestamp = "undated"
logpath = ["$WORK/auth.log"]
CONF
    chown root:fail2zig "$WORK/live.toml"
    chmod 0640 "$WORK/live.toml"
}
write_unit() {
    local identity="$1"
    sed -e "s|^User=.*|User=$identity|" -e "s|^Group=.*|Group=$identity|" \
        -e "s|^ExecStart=.*|ExecStart=$WORK/fail2zig --config $WORK/live.toml|" \
        -e "s|^ReadWritePaths=.*|ReadWritePaths=$WORK/state $RUNTIME|" \
        -e "s|^RuntimeDirectory=.*|RuntimeDirectory=$NAME|" \
        -e "s|^StateDirectory=.*|StateDirectory=$NAME/state|" \
        "$ROOT/deploy/fail2zig.service" > "/run/systemd/system/$UNIT"
    # Network namespace is the only additional isolation setting.
    sed -i "/^\[Service\]/a NetworkNamespacePath=/run/netns/$CURRENT_NS" "/run/systemd/system/$UNIT"
    systemctl daemon-reload
}
cli() { timeout --kill-after=2 8 "$WORK/fail2zig" --socket "$RUNTIME/fail2zig.sock" "$@"; }
ready() {
    timeout --kill-after=2 15 systemctl start "$UNIT"
    for ((i=0;i<50;i++)); do
        if cli status --output json > "$WORK/status.json" 2>/dev/null && grep -q '"protection":"active"' "$WORK/status.json"; then return; fi
        sleep .1
    done
    journalctl -u "$UNIT" --no-pager -n 40 >&2
    return 1
}
readback() {
    case "$1" in
        nftables) ip netns exec "$CURRENT_NS" nft list ruleset ;;
        iptables) ip netns exec "$CURRENT_NS" iptables-save ;;
        ipset) ip netns exec "$CURRENT_NS" ipset save ;;
    esac | grep -F '192.0.2.42' >/dev/null
}
wait_readback() { for ((i=0;i<50;i++)); do if readback "$1"; then return; fi; sleep .1; done; return 1; }
if [ "$MODE" = full ]; then
write_config nftables
write_unit root
chown root:root "$WORK/state"
ready
cli ban 192.0.2.42 --jail sshd --duration 600
wait_readback nftables
cli list --output json > "$WORK/before.json"
EXPIRY="$(sed -n 's/.*"expiry_us":\([0-9]*\).*/\1/p' "$WORK/before.json")"
[ -n "$EXPIRY" ]
systemctl kill --signal=SIGKILL --kill-whom=main "$UNIT"
systemctl stop "$UNIT"
sha256sum "$WORK/config/config.toml" > "$WORK/before.sha256"
for path in "$WORK/state/state.bin" "$WORK/state/state.bin-wal" "$WORK/state/state.bin-shm"; do
    [ ! -e "$path" ] || sha256sum "$path" >> "$WORK/before.sha256"
done
installer
sha256sum --check "$WORK/before.sha256"
for path in "$WORK/state" "$WORK/state/state.bin" "$WORK/state/state.bin-wal" "$WORK/state/state.bin-shm"; do
    [ ! -e "$path" ] || [ "$(stat -c %U "$path")" = fail2zig ]
done
write_unit fail2zig
ready
PID="$(systemctl show "$UNIT" -p MainPID --value)"
[ "$(stat -c %u "/proc/$PID")" = "$(id -u fail2zig)" ]
[ "$(id -u fail2zig)" -ne 0 ]
# CAP_DAC_READ_SEARCH (2), CAP_NET_ADMIN (12), CAP_NET_RAW (13).
[ "$(awk '/^Gid:/ { print $2 }' "/proc/$PID/status")" = "$(id -g fail2zig)" ]
grep -Eq '^CapEff:[[:space:]]+0000000000003004$' "/proc/$PID/status"
cli list --output json | grep -F "\"expiry_us\":$EXPIRY" >/dev/null
wait_readback nftables
runuser -u "$MONITOR" -- "$WORK/fail2zig" --socket "$RUNTIME/fail2zig.sock" status >/dev/null
if runuser -u "$MONITOR" -- "$WORK/fail2zig" --socket "$RUNTIME/fail2zig.sock" ban 192.0.2.43 --jail sshd; then exit 1; fi
if runuser -u nobody -- "$WORK/fail2zig" --socket "$RUNTIME/fail2zig.sock" status; then exit 1; fi
systemctl restart "$UNIT"
ready
cli list --output json | grep -F "\"expiry_us\":$EXPIRY" >/dev/null
wait_readback nftables
cli unban 192.0.2.42 --jail sshd
systemctl restart "$UNIT"
ready
[ "$(cli list --output json)" = '[]' ]
printf 'service-user: PASS root-native upgrade, unchanged state/config bytes, finite expiry, READY, UID/caps, IPC authorization\n'
# Exercise unreadable root-owned log access with the shipped DAC capability.
printf 'Failed password for invalid user probe from 192.0.2.42 port 33333 ssh2\n' >> "$WORK/auth.log"
wait_readback nftables
cli unban 192.0.2.42 --jail sshd
else
    chown fail2zig:fail2zig "$WORK/state"
    write_unit fail2zig
    printf 'service-user: SKIP previously accepted installer/upgrade/nftables prefix (--backends-only)\n'
fi
for backend in iptables ipset; do
    systemctl stop "$UNIT"
    CURRENT_NS="$NAME-$backend"
    ip netns add "$CURRENT_NS"
    NAMESPACES+=("$CURRENT_NS")
    ip -n "$CURRENT_NS" link set lo up
    : > "$WORK/auth.log"
    write_config "$backend"
    write_unit fail2zig
    ready
    cli ban 192.0.2.42 --jail sshd --duration 600
    wait_readback "$backend"
    cli unban 192.0.2.42 --jail sshd
    for ((i=0;i<50;i++)); do if ! readback "$backend"; then break; fi; sleep .1; done
    ! readback "$backend"
done
printf 'service-user: PASS dedicated-user iptables and ipset lifecycles\n'
printf 'service-user: genuine journal-source visibility and recovery require the separately scheduled journal/storage checks\n'
