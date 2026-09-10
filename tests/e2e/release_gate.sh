#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_BIN="${1:?usage: release_gate.sh ABSOLUTE_BIN_DIR [hold-seconds]}"
HOLD_SECONDS="${2:-0}"
[[ "$HOLD_SECONDS" =~ ^[0-9]+$ ]] && [ "$HOLD_SECONDS" -le 120 ] || exit 2
[ "$(id -u)" -eq 0 ] || { echo 'release gate requires root' >&2; exit 2; }
[ -x /usr/local/bin/fail2zig ] || { echo 'release gate requires an existing baseline installation' >&2; exit 2; }
[ -x "$LOCAL_BIN/fail2zig" ] && [ -x "$LOCAL_BIN/fail2zig-client" ] || exit 2
BACKUP="$(mktemp -d /var/backups/fail2zig-release-gate.XXXXXX)"
chmod 0700 "$BACKUP"
WAS_ACTIVE=0
systemctl is-active --quiet fail2zig && WAS_ACTIVE=1
cp -a /usr/local/bin/fail2zig /usr/local/bin/fail2zig-client "$BACKUP/"
cp -a /etc/systemd/system/fail2zig.service "$BACKUP/"
cp -a /etc/fail2zig "$BACKUP/config"

restore() {
    local result=$?
    trap - EXIT
    set +e
    systemctl stop fail2zig
    install -o root -g root -m 0755 "$BACKUP/fail2zig" /usr/local/bin/fail2zig || result=1
    install -o root -g root -m 0755 "$BACKUP/fail2zig-client" /usr/local/bin/fail2zig-client || result=1
    cp -a "$BACKUP/fail2zig.service" /etc/systemd/system/fail2zig.service || result=1
    cp -a "$BACKUP/config/." /etc/fail2zig/ || result=1
    if [ -d "$BACKUP/state" ]; then
        cp -a "$BACKUP/state/." /var/lib/fail2zig/ || result=1
    fi
    systemctl daemon-reload || result=1
    if [ "$WAS_ACTIVE" -eq 1 ]; then
        systemctl start fail2zig || result=1
        local ipc_ready=0
        for _ in $(seq 1 30); do
            if fail2zig-client --output json version; then ipc_ready=1; break; fi
            sleep 0.2
        done
        [ "$ipc_ready" -eq 1 ] || result=1
        systemctl is-active --quiet fail2zig || result=1
        local restored_pid
        restored_pid="$(systemctl show fail2zig -p MainPID --value)"
        cmp "/proc/$restored_pid/exe" "$BACKUP/fail2zig" || result=1
    fi
    cmp /usr/local/bin/fail2zig "$BACKUP/fail2zig" || result=1
    cmp /usr/local/bin/fail2zig-client "$BACKUP/fail2zig-client" || result=1
    printf 'release-gate: baseline restored; backup=%s; result=%s\n' "$BACKUP" "$result"
    exit "$result"
}
trap restore EXIT
for backend in nftables iptables ipset; do
    printf 'release-gate: backend=%s\n' "$backend"
    unshare --net timeout 60 python3 "$SCRIPT_DIR/ban_lifecycle.py" "$LOCAL_BIN" "$backend"
done
systemctl stop fail2zig
cp -a /var/lib/fail2zig "$BACKUP/state"
printf 'release-gate: backup=%s\n' "$BACKUP"
bash "$SCRIPT_DIR/deploy_regression.sh" --local-bin "$LOCAL_BIN" --force
bash "$SCRIPT_DIR/deploy_status_honesty.sh" --local-bin "$LOCAL_BIN" --force
systemctl start fail2zig
bash "$SCRIPT_DIR/stabilization_live.sh" --force
unshare --net bash -c 'ip link set lo up; exec bash "$1" --local-bin "$2"' _ "$SCRIPT_DIR/degraded_file_source.sh" "$LOCAL_BIN"
systemctl start fail2zig
pid="$(systemctl show fail2zig -p MainPID --value)"
cmp "/proc/$pid/exe" "$LOCAL_BIN/fail2zig"
sha256sum "/proc/$pid/exe" "$LOCAL_BIN/fail2zig-client"
fail2zig-client --output json version
printf 'release-gate: READY_FOR_CONNECTIVITY pid=%s hold=%s\n' "$pid" "$HOLD_SECONDS"
for _ in $(seq 1 "$HOLD_SECONDS"); do sleep 1; done
test "$(systemctl show fail2zig -p NRestarts --value)" = 0
fail2zig-client --output json status
printf 'release-gate: PASS candidate deployment gates\n'
