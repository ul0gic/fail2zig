#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_BIN="${1:?usage: release_gate.sh ABSOLUTE_BIN_DIR [hold-seconds] [full|service|journal]}"
HOLD_SECONDS="${2:-0}"
PROFILE="${3:-full}"
PROBE_IP="${RELEASE_GATE_PROBE_IP:-}"
[[ "$HOLD_SECONDS" =~ ^[0-9]+$ ]] && [ "$HOLD_SECONDS" -le 120 ] || exit 2
case "$PROFILE" in full|service|journal) ;; *) exit 2 ;; esac
if [ -n "$PROBE_IP" ]; then
    [ "$PROFILE" = journal ] || exit 2
    [[ "$PROBE_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || exit 2
    IFS=. read -r probe_a probe_b probe_c probe_d <<< "$PROBE_IP"
    for probe_octet in "$probe_a" "$probe_b" "$probe_c" "$probe_d"; do
        [ "$probe_octet" -le 255 ] || exit 2
    done
    [ "$probe_a" -ne 0 ] && [ "$probe_a" -ne 127 ] || exit 2
fi
[ "${LOCAL_BIN#/}" != "$LOCAL_BIN" ] || { echo 'release gate requires an absolute binary directory' >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo 'release gate requires root' >&2; exit 2; }
[ -x /usr/local/bin/fail2zig ] || { echo 'release gate requires an existing baseline installation' >&2; exit 2; }
[ -x "$LOCAL_BIN/fail2zig" ] || exit 2
[ -x "$LOCAL_BIN/fail2zig-release-lifecycle" ] || { echo 'release gate requires the Zig lifecycle helper' >&2; exit 2; }
BACKUP="$(mktemp -d /var/backups/fail2zig-release-gate.XXXXXX)"
chmod 0700 "$BACKUP"
WAS_ACTIVE=0
systemctl is-active --quiet fail2zig && WAS_ACTIVE=1
cp -a /usr/local/bin/fail2zig "$BACKUP/"
cp -a /etc/systemd/system/fail2zig.service "$BACKUP/"
cp -a /etc/fail2zig "$BACKUP/config"
sha256sum /usr/local/bin/fail2zig /etc/systemd/system/fail2zig.service /etc/fail2zig/config.toml > "$BACKUP/baseline.sha256"
nft list ruleset | sha256sum > "$BACKUP/nft.sha256"
nft list tables | awk '$1 == "table" { print $2 " " $3 }' | sort > "$BACKUP/nft.tables"
HAD_CLIENT=0
if [ -e /usr/local/bin/fail2zig-client ]; then
    HAD_CLIENT=1
    cp -a /usr/local/bin/fail2zig-client "$BACKUP/"
fi
HAD_MAN1=0
if [ -e /usr/local/share/man/man1/fail2zig.1 ]; then
    HAD_MAN1=1
    cp -a /usr/local/share/man/man1/fail2zig.1 "$BACKUP/"
fi
HAD_MAN5=0
if [ -e /usr/local/share/man/man5/fail2zig.toml.5 ]; then
    HAD_MAN5=1
    cp -a /usr/local/share/man/man5/fail2zig.toml.5 "$BACKUP/"
fi
HAD_DOCS=0
if [ -d /usr/local/share/doc/fail2zig ]; then
    HAD_DOCS=1
    cp -a /usr/local/share/doc/fail2zig "$BACKUP/docs"
fi
HAD_SERVICE_USER=0
getent passwd fail2zig >/dev/null && HAD_SERVICE_USER=1
HAD_SERVICE_GROUP=0
getent group fail2zig >/dev/null && HAD_SERVICE_GROUP=1
INSTALL_ATTEMPTED=0

state_metadata() {
    (cd "$1" && find . -printf '%P %y %U %G %m %l\n' | LC_ALL=C sort)
}

verify_state_copy() {
    diff --no-dereference -r "$1" "$BACKUP/state" &&
        state_metadata "$1" > "$BACKUP/state-current.metadata" &&
        cmp "$BACKUP/state.metadata" "$BACKUP/state-current.metadata"
}

restore() {
    local result=$?
    trap - EXIT
    set +e
    if ! systemctl stop fail2zig; then
        printf 'release-gate: cannot stop candidate; retaining recovery backup %s\n' "$BACKUP" >&2
        exit 1
    fi
    nft list tables | awk '$1 == "table" { print $2 " " $3 }' | sort > "$BACKUP/current-nft.tables"
    comm -13 "$BACKUP/nft.tables" "$BACKUP/current-nft.tables" > "$BACKUP/added-nft.tables"
    while IFS= read -r added; do
        [ -n "$added" ] || continue
        if [[ ! "$added" =~ ^inet\ f2z_[0-9a-f]{24}$ ]]; then
            printf 'release-gate: refusing to delete unexpected added nftables table: %s\n' "$added" >&2
            result=1
            continue
        fi
        nft delete table "${added%% *}" "${added#* }" || result=1
    done < "$BACKUP/added-nft.tables"
    cp -a "$BACKUP/fail2zig" /usr/local/bin/fail2zig || result=1
    if [ "$HAD_CLIENT" -eq 1 ]; then
        cp -a "$BACKUP/fail2zig-client" /usr/local/bin/fail2zig-client || result=1
    else
        rm -f /usr/local/bin/fail2zig-client
    fi
    cp -a "$BACKUP/fail2zig.service" /etc/systemd/system/fail2zig.service || result=1
    rm -rf /etc/fail2zig
    cp -a "$BACKUP/config" /etc/fail2zig || result=1
    if [ -d "$BACKUP/original-state" ]; then
        if ! rm -rf /var/lib/fail2zig ||
            ! mv -T "$BACKUP/original-state" /var/lib/fail2zig ||
            ! verify_state_copy /var/lib/fail2zig; then
            printf 'release-gate: state restoration failed; service remains stopped; backup=%s\n' "$BACKUP" >&2
            exit 1
        fi
    fi
    if [ "$HAD_MAN1" -eq 1 ]; then cp -a "$BACKUP/fail2zig.1" /usr/local/share/man/man1/fail2zig.1 || result=1; else rm -f /usr/local/share/man/man1/fail2zig.1; fi
    if [ "$HAD_MAN5" -eq 1 ]; then cp -a "$BACKUP/fail2zig.toml.5" /usr/local/share/man/man5/fail2zig.toml.5 || result=1; else rm -f /usr/local/share/man/man5/fail2zig.toml.5; fi
    if [ "$HAD_DOCS" -eq 1 ]; then
        rm -rf /usr/local/share/doc/fail2zig
        cp -a "$BACKUP/docs" /usr/local/share/doc/fail2zig || result=1
    else
        rm -rf /usr/local/share/doc/fail2zig
    fi
    if [ "$INSTALL_ATTEMPTED" -eq 1 ]; then
        if [ "$HAD_SERVICE_USER" -eq 0 ] && getent passwd fail2zig >/dev/null; then
            userdel fail2zig || result=1
        fi
        if [ "$HAD_SERVICE_GROUP" -eq 0 ] && getent group fail2zig >/dev/null; then
            groupdel fail2zig || result=1
        fi
    fi
    systemctl daemon-reload || result=1
    if [ "$WAS_ACTIVE" -eq 1 ]; then
        systemctl start fail2zig || result=1
        local ipc_ready=0
        local baseline_client=/usr/local/bin/fail2zig
        if [ "$HAD_CLIENT" -eq 1 ]; then baseline_client=/usr/local/bin/fail2zig-client; fi
        for _ in $(seq 1 30); do
            if "$baseline_client" --output json version; then ipc_ready=1; break; fi
            sleep 0.2
        done
        [ "$ipc_ready" -eq 1 ] || result=1
        if [ -n "$PROBE_IP" ]; then
            local baseline_list
            for _ in $(seq 1 15); do
                baseline_list="$("$baseline_client" --output json list)"
                [ "$baseline_list" != "[]" ] && break
                sleep 0.2
            done
            if [ "$baseline_list" != "[]" ]; then
                local listed_count
                listed_count="$(printf '%s' "$baseline_list" | grep -o '"ip":' | wc -l)"
                if [ "$listed_count" -ne 1 ] || ! printf '%s' "$baseline_list" | grep -Fq "\"ip\":\"$PROBE_IP\"" || ! printf '%s' "$baseline_list" | grep -Fq '"jail":"sshd"'; then
                    printf 'release-gate: refusing to remove unexpected post-probe baseline ban: %s\n' "$baseline_list" >&2
                    result=1
                else
                    "$baseline_client" unban "$PROBE_IP" --jail sshd || result=1
                    [ "$("$baseline_client" --output json list)" = "[]" ] || result=1
                    printf 'release-gate: removed exact authorized journal probe ban %s after baseline replay\n' "$PROBE_IP"
                fi
            fi
        fi
        systemctl is-active --quiet fail2zig || result=1
        local restored_pid
        restored_pid="$(systemctl show fail2zig -p MainPID --value)"
        cmp "/proc/$restored_pid/exe" "$BACKUP/fail2zig" || result=1
    fi
    cmp /usr/local/bin/fail2zig "$BACKUP/fail2zig" || result=1
    if [ "$HAD_CLIENT" -eq 1 ]; then cmp /usr/local/bin/fail2zig-client "$BACKUP/fail2zig-client" || result=1; fi
    cmp /etc/systemd/system/fail2zig.service "$BACKUP/fail2zig.service" || result=1
    cmp /etc/fail2zig/config.toml "$BACKUP/config/config.toml" || result=1
    sha256sum --check "$BACKUP/baseline.sha256" >/dev/null || result=1
    nft list ruleset | sha256sum --check "$BACKUP/nft.sha256" >/dev/null || result=1
    printf 'release-gate: baseline restored; backup=%s; result=%s\n' "$BACKUP" "$result"
    if [ "$result" -eq 0 ]; then
        rm -rf "$BACKUP"
        printf 'release-gate: removed verified backup\n'
    fi
    exit "$result"
}
trap restore EXIT
if [ "$PROFILE" = full ]; then
    printf 'release-gate: backend=nftables profile=deep\n'
    unshare --net timeout --kill-after=5 90 \
        "$LOCAL_BIN/fail2zig-release-lifecycle" "$LOCAL_BIN/fail2zig" nftables
    for backend in iptables ipset; do
        printf 'release-gate: backend=%s profile=representative\n' "$backend"
        unshare --net timeout --kill-after=5 30 \
            "$LOCAL_BIN/fail2zig-release-lifecycle" "$LOCAL_BIN/fail2zig" "$backend" representative
    done
elif [ "$PROFILE" = service ]; then
    printf 'release-gate: reusing accepted backend lifecycles; profile=service\n'
else
    printf 'release-gate: reusing accepted backend and service checks; profile=journal\n'
fi
BASELINE_CLIENT=/usr/local/bin/fail2zig
if [ "$HAD_CLIENT" -eq 1 ]; then BASELINE_CLIENT=/usr/local/bin/fail2zig-client; fi
[ "$("$BASELINE_CLIENT" --output json list)" = "[]" ] || {
    echo 'release-gate: refusing cutover while the published daemon has active bans' >&2
    exit 1
}
systemctl stop fail2zig
# The legacy state must remain untouched while the candidate uses fresh native
# state. Reject foreground writers before copying or moving the baseline tree.
for proc in /proc/[0-9]*; do
    [ "$(cat "$proc/comm" 2>/dev/null || :)" != fail2zig ] || {
        echo "release-gate: foreground fail2zig still running: ${proc##*/}" >&2
        exit 1
    }
    for fd in "$proc"/fd/*; do
        for state in /var/lib/fail2zig/state.bin{,-wal,-shm}; do
            if [ -e "$state" ] && [[ "$fd" -ef "$state" ]]; then
                echo "release-gate: baseline state still open: ${proc##*/}" >&2
                exit 1
            fi
        done
    done
done
[ -d /var/lib/fail2zig ] && [ ! -L /var/lib/fail2zig ]
[ "$(stat -c %d /var/lib/fail2zig)" = "$(stat -c %d "$BACKUP")" ] || {
    echo 'release-gate: state and backup must share a filesystem for atomic state moves' >&2
    exit 1
}
cp -a /var/lib/fail2zig "$BACKUP/state"
state_metadata "$BACKUP/state" > "$BACKUP/state.metadata"
verify_state_copy /var/lib/fail2zig
mv -T /var/lib/fail2zig "$BACKUP/original-state"
nft list table inet fail2zig >/dev/null
nft delete table inet fail2zig
if nft list table inet fail2zig >/dev/null 2>&1; then
    echo 'release-gate: baseline nftables scaffold remained after exact delete' >&2
    exit 1
fi
printf 'release-gate: backup=%s\n' "$BACKUP"
INSTALL_ATTEMPTED=1
"$SCRIPT_DIR/../../scripts/install.sh" --local-bin "$LOCAL_BIN"
cmp /etc/fail2zig/config.toml "$BACKUP/config/config.toml"
verify_state_copy "$BACKUP/original-state"
UPGRADE_CONFIG="$BACKUP/upgrade-config.toml"
awk -v profile="$PROFILE" '
    /^\[jails\.sshd\]$/ { section="sshd"; print; next }
    /^\[jails\.recidive\]$/ { section="recidive"; print; next }
    /^\[jails\.nginx-http-auth\]$/ { section="nginx"; print; next }
    /^\[/ { section="other" }
    section == "sshd" && /^source[[:space:]]*=/ {
        print "source = \"journald\""
        print "journal_executables = [\"/usr/sbin/sshd\", \"/usr/lib/openssh/sshd-session\"]"
        next
    }
    section == "sshd" && /^(timestamp|logpath)[[:space:]]*=/ { next }
    section == "nginx" && /^enabled[[:space:]]*=/ { print "enabled = false"; next }
    { print }
' /etc/fail2zig/fail2zig.toml.example > "$UPGRADE_CONFIG"
grep -q '^state_file[[:space:]]*=[[:space:]]*"/var/lib/fail2zig/state.bin"' "$UPGRADE_CONFIG"
grep -A5 '^\[jails.sshd\]$' "$UPGRADE_CONFIG" | grep -q '^source[[:space:]]*=[[:space:]]*"journald"'
grep -A3 '^\[jails.recidive\]$' "$UPGRADE_CONFIG" | grep -q '^source[[:space:]]*=[[:space:]]*"internal"'
install -o root -g fail2zig -m 0640 "$UPGRADE_CONFIG" /etc/fail2zig/config.toml
rm -f "$UPGRADE_CONFIG"
verify_state_copy "$BACKUP/original-state"
if [ "$PROFILE" != journal ]; then
    bash "$SCRIPT_DIR/deploy_regression.sh" --local-bin "$LOCAL_BIN" --skip-install --force
    bash "$SCRIPT_DIR/deploy_status_honesty.sh" --local-bin "$LOCAL_BIN" --skip-install --force
    systemctl start fail2zig
    bash "$SCRIPT_DIR/stabilization_live.sh" --force
    unshare --net bash -c 'ip link set lo up; exec bash "$1" --local-bin "$2"' _ "$SCRIPT_DIR/degraded_file_source.sh" "$LOCAL_BIN"
fi
systemctl start fail2zig
pid="$(systemctl show fail2zig -p MainPID --value)"
cmp "/proc/$pid/exe" "$LOCAL_BIN/fail2zig"
sha256sum "/proc/$pid/exe" "$LOCAL_BIN/fail2zig"
fail2zig --output json version
printf 'release-gate: READY_FOR_CONNECTIVITY pid=%s hold=%s\n' "$pid" "$HOLD_SECONDS"
for _ in $(seq 1 "$HOLD_SECONDS"); do sleep 1; done
test "$(systemctl show fail2zig -p NRestarts --value)" = 0
test "$(fail2zig status --output plain | awk -F '\t' '$1 == "protection" { print $2; exit }')" = active
fail2zig --output json status
printf 'release-gate: PASS candidate deployment gates\n'
