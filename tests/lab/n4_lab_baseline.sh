#!/bin/bash
# Record or recheck the read-only baseline of the authorized lab target before and after a
# disposable rehearsal. Never mutates the target. Usage:
#   n4_lab_baseline.sh record <out.txt>      # capture
#   n4_lab_baseline.sh compare <before.txt>  # capture again and diff against the recording
set -eu
TARGET="${F2Z_LAB_TARGET:-ul0gic@172.16.150.253}"
KEY="${F2Z_LAB_KEY:-$HOME/.ssh/id_ed25519_p33ker}"
SSH="ssh -i $KEY -o IdentitiesOnly=yes -o PreferredAuthentications=publickey -o BatchMode=yes -o ConnectTimeout=10 $TARGET"

capture() {
    $SSH 'set +e
        echo "host=$(hostname) kernel=$(uname -r)"
        pid=$(systemctl show fail2zig -p MainPID --value)
        echo "service=$(systemctl show fail2zig -p ActiveState -p SubState -p FragmentPath --value | tr "\n" " ")"
        echo "main_pid=$pid"
        [ -n "$pid" ] && [ "$pid" != 0 ] && echo "exe_sha256=$(sudo -n sha256sum /proc/$pid/exe | cut -d" " -f1)"
        echo "installed_sha256=$(sha256sum /usr/local/bin/fail2zig | cut -d" " -f1)"
        echo "unit_sha256=$(sha256sum /etc/systemd/system/fail2zig.service | cut -d" " -f1)"
        echo "socket_unit=$(ls /etc/systemd/system/fail2zig.socket 2>/dev/null || echo absent)"
        echo "config_sha256=$(sudo -n sha256sum /etc/fail2zig/config.toml | cut -d" " -f1)"
        echo "nft_sha256=$(sudo -n nft list ruleset 2>/dev/null | sha256sum | cut -d" " -f1)"
        echo "iptables_sha256=$(sudo -n iptables -S 2>/dev/null | sha256sum | cut -d" " -f1)"
        echo "ipset_sha256=$(sudo -n ipset list -n 2>/dev/null | sha256sum | cut -d" " -f1)"
        echo "netns=$(sudo -n ip netns list | tr "\n" ";")"
        echo "transient_units=$(systemctl list-units "f2z-n4-*" --all --no-legend --plain | wc -l)"
        echo "fail2ban_procs=$(pgrep -c fail2ban-server || true)"
        echo "tmp_dirs=$(ls -d /tmp/f2z-n4-* 2>/dev/null | wc -l)"
        echo "disk_root=$(df --output=avail -k / | tail -1)"
    '
}

case "${1:-}" in
record)
    capture > "$2"
    echo "recorded $(wc -l < "$2") baseline lines to $2"
    ;;
compare)
    tmp=$(mktemp)
    capture > "$tmp"
    # Free disk and the process count are informational; identities, hashes and residue must match.
    if diff <(grep -v -E '^(disk_root|fail2ban_procs)=' "$2") <(grep -v -E '^(disk_root|fail2ban_procs)=' "$tmp"); then
        echo "baseline unchanged"
        rc=0
    else
        echo "BASELINE CHANGED" >&2
        rc=1
    fi
    rm -f "$tmp"
    exit $rc
    ;;
*)
    echo "usage: $0 record <out> | compare <before>" >&2
    exit 2
    ;;
esac
