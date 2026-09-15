#!/bin/bash
# Disposable systemd lifecycle rehearsal of one candidate on the authorized lab target.
# Every case runs as a root transient unit inside its own network namespace under a
# per-candidate /tmp directory; the published service, binary, config and persistent
# ruleset are never touched, and the read-only baseline must be identical afterwards.
# Root ignores file modes, so the denied-state case uses ReadOnlyPaths, and the transport
# absence case uses InaccessiblePaths on the fixed journalctl path.
#
# Usage:
#   n4_lifecycle_rehearsal.sh [--dry-run] [--candidate zig-out/bin/fail2zig]
# Environment (as n4_lab_baseline.sh): F2Z_LAB_TARGET, F2Z_LAB_KEY.
# Case bodies are single-quoted on purpose: they expand on the target, inside remote_case.
# shellcheck disable=SC2016,SC2029
set -eu

cd "$(dirname "$0")/../.."
TARGET="${F2Z_LAB_TARGET:-ul0gic@172.16.150.253}"
KEY="${F2Z_LAB_KEY:-$HOME/.ssh/id_ed25519_p33ker}"
SSH_OPTS=(-i "$KEY" -o IdentitiesOnly=yes -o PreferredAuthentications=publickey -o BatchMode=yes -o ConnectTimeout=10)
BASELINE=tests/lab/n4_lab_baseline.sh
UNIT_SRC=deploy/fail2zig.service
CANDIDATE=zig-out/bin/fail2zig
DRY_RUN=0

while [ $# -gt 0 ]; do
    case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --candidate) CANDIDATE="$2"; shift ;;
    *) echo "usage: $0 [--dry-run] [--candidate <path>]" >&2; exit 2 ;;
    esac
    shift
done

[ -f "$CANDIDATE" ] || { echo "candidate missing: $CANDIDATE" >&2; exit 2; }
SHA=$(sha256sum "$CANDIDATE" | cut -d' ' -f1)
SHA8=${SHA:0:8}
REMOTE_DIR="/tmp/f2z-n4-$SHA8"
REMOTE_BIN="$REMOTE_DIR/fail2zig"
UNIT_PREFIX="f2z-n4-$SHA8"
BASELINE_FILE=$(mktemp)
PASS=0; FAIL=0; SKIP=0

ssh_run() {
    if [ "$DRY_RUN" = 1 ]; then
        printf 'ssh %s %s -- %q\n' "${SSH_OPTS[*]}" "$TARGET" "$*"
        return 0
    fi
    ssh "${SSH_OPTS[@]}" "$TARGET" "$@"
}

scp_put() {
    if [ "$DRY_RUN" = 1 ]; then
        printf 'scp %s %q %s:%q\n' "${SSH_OPTS[*]}" "$1" "$TARGET" "$2"
        return 0
    fi
    scp "${SSH_OPTS[@]}" "$1" "$TARGET:$2"
}

result() {
    case "$1" in
    PASS) PASS=$((PASS + 1)) ;;
    FAIL) FAIL=$((FAIL + 1)) ;;
    SKIP) SKIP=$((SKIP + 1)) ;;
    esac
    printf '%-5s %-20s %s\n' "$1" "$2" "${3:-}"
}

# One remote script per case: the EXIT trap guarantees unit, netns and reset-failed cleanup
# even when a step fails or the connection drops mid-case.
remote_case() {
    local name="$1" body="$2" unit="$UNIT_PREFIX-$1"
    ssh_run "set -u
unit='$unit'; ns='$unit'; dir='$REMOTE_DIR'; bin='$REMOTE_BIN'; case_dir='$REMOTE_DIR/$name'
sock=\"\$case_dir/run/fail2zig.sock\"
cleanup() {
    sudo -n systemctl stop \"\$unit\" >/dev/null 2>&1 || true
    sudo -n systemctl kill -s KILL \"\$unit\" >/dev/null 2>&1 || true
    sudo -n systemctl reset-failed \"\$unit\" >/dev/null 2>&1 || true
    sudo -n ip netns delete \"\$ns\" >/dev/null 2>&1 || true
}
# Every nonzero exit passes through here so the summary carries the unit's own diagnostics.
diagnose() {
    local rc=\$?
    if [ \"\$rc\" != 0 ] && [ \"\$rc\" != 90 ]; then
        echo \"--- diagnostics for \$unit (step rc=\$rc) ---\"
        systemctl status \"\$unit\" --no-pager 2>&1 | head -15
        sudo -n journalctl -u \"\$unit\" --no-pager -q 2>&1 | tail -20
        echo \"--- end diagnostics ---\"
    fi
    cleanup
    exit \"\$rc\"
}
trap diagnose EXIT
sudo -n ip netns add \"\$ns\" || exit 90
sudo -n ip -n \"\$ns\" link set lo up || exit 90
sudo -n mkdir -p \"\$case_dir/state\" \"\$case_dir/run\" || exit 90
sudo -n chmod 0755 \"\$case_dir\" || exit 90
sudo -n chmod 0750 \"\$case_dir/state\" \"\$case_dir/run\" || exit 90
sudo -n tee \"\$case_dir/config.toml\" >/dev/null <<CFG
[global]
native_ingestion = true
log_level = \"info\"
log_target = \"stderr\"
firewall = \"nftables\"
firewall_namespace = \"/run/netns/\$ns\"
state_file = \"\$case_dir/state/state.bin\"
socket_path = \"\$sock\"
metrics_enabled = false
[defaults]
banaction = \"log-only\"
maxretry = 3
findtime = 600
bantime = 60
[jails.sshd]
filter = \"sshd\"
source = \"file\"
timestamp = \"undated\"
logpath = [\"\$case_dir/auth.log\"]
[jails.nft]
filter = \"sshd\"
source = \"file\"
timestamp = \"undated\"
banaction = \"nftables\"
logpath = [\"\$case_dir/nft.log\"]
CFG
sudo -n chmod 0640 \"\$case_dir/config.toml\" || exit 90
sudo -n touch \"\$case_dir/auth.log\" \"\$case_dir/nft.log\" || exit 90
group_prop=''
if getent group fail2zig >/dev/null; then group_prop='-p Group=fail2zig'; else echo 'note: group fail2zig absent; Group= omitted'; fi
start_unit() {
    local err
    # The case directory is root-owned, so stderr is captured in a variable, never a file.
    # shellcheck disable=SC2086
    err=\$(sudo -n systemd-run --unit \"\$unit\" --quiet -p Type=notify -p NotifyAccess=main \\
        -p NetworkNamespacePath=/run/netns/\$ns \$group_prop -p TimeoutStopSec=10 \\
        \"\$@\" \"\$bin\" --foreground --config \"\$case_dir/config.toml\" 2>&1 >/dev/null) && return 0
    echo \"start_unit failed: \$(printf '%s' \"\$err\" | tr '\\n' ' ')\"
    return 1
}
prop() { systemctl show \"\$unit\" -p \"\$1\" --value; }
main_pid() { prop MainPID; }
wait_active() {
    local i
    for i in \$(seq 1 60); do
        [ \"\$(prop ActiveState)\" = active ] && return 0
        [ \"\$(prop ActiveState)\" = failed ] && return 1
        sleep 0.25
    done
    return 1
}
wait_inactive() {
    local i
    for i in \$(seq 1 60); do
        case \"\$(prop ActiveState)\" in inactive|failed) return 0 ;; esac
        sleep 0.25
    done
    return 1
}
status_json() { sudo -n \"\$bin\" --socket \"\$sock\" --output json status; }
gen() { status_json | sed -n 's/.*\"generation\":\"\\([0-9a-f]*\\)\".*/\\1/p'; }
unit_log() { sudo -n journalctl -u \"\$unit\" --no-pager -q; }
$body"
}

run_case() {
    local name="$1" note="$2" body="$3"
    if [ "$DRY_RUN" = 1 ]; then
        remote_case "$name" "$body"
        result SKIP "$name" "dry-run"
        return
    fi
    local rc=0
    remote_case "$name" "$body" || rc=$?
    case "$rc" in
    0) result PASS "$name" "$note" ;;
    90) result SKIP "$name" "environment setup failed" ;;
    *) result FAIL "$name" "step rc=$rc ($note)" ;;
    esac
}

echo "candidate=$CANDIDATE sha256=$SHA target=$TARGET remote_dir=$REMOTE_DIR"

# --- baseline and candidate placement ---------------------------------------------------
if [ "$DRY_RUN" = 1 ]; then
    echo "$BASELINE record $BASELINE_FILE"
else
    "$BASELINE" record "$BASELINE_FILE"
fi
ssh_run "mkdir -p '$REMOTE_DIR' && chmod 0755 '$REMOTE_DIR'"
scp_put "$CANDIDATE" "$REMOTE_BIN"
scp_put "$UNIT_SRC" "$REMOTE_DIR/fail2zig.service"
if [ "$DRY_RUN" = 0 ]; then
    remote_sha=$(ssh_run "sha256sum '$REMOTE_BIN' | cut -d' ' -f1")
    if [ "$remote_sha" != "$SHA" ]; then echo "candidate hash mismatch on target" >&2; exit 1; fi
    ssh_run "chmod 0755 '$REMOTE_BIN'"
fi

# --- cases -------------------------------------------------------------------------------
run_case start-ready "Type=notify READY only after admission" '
start_unit || exit 1
wait_active || { systemctl status "$unit" --no-pager || true; exit 2; }
[ "$(prop NotifyAccess)" = main ] || exit 3
status_json | grep -q "\"storage\":\"healthy\"" || exit 4
unit_log | grep -q "native: ready" || exit 5
sudo -n systemctl stop "$unit" || exit 6
[ "$(prop Result)" = success ] || exit 7
'

run_case reload-valid "SIGHUP applies a new generation" '
start_unit || exit 1
wait_active || exit 2
g0=$(gen)
sudo -n sed -i "s/^bantime = 60/bantime = 120/" "$case_dir/config.toml" || exit 3
sudo -n kill -HUP "$(main_pid)" || exit 4
sleep 1
g1=$(gen)
[ -n "$g0" ] && [ -n "$g1" ] && [ "$g0" != "$g1" ] || exit 5
[ "$(prop ActiveState)" = active ] || exit 6
unit_log | grep -q "outcome=applied" || exit 7
'

run_case reload-invalid "invalid edit refused, generation retained" '
start_unit || exit 1
wait_active || exit 2
g0=$(gen)
printf "bogus_key = 1\n" | sudo -n tee -a "$case_dir/config.toml" >/dev/null || exit 3
sudo -n kill -HUP "$(main_pid)" || exit 4
sleep 1
g1=$(gen)
[ -n "$g0" ] && [ "$g0" = "$g1" ] || exit 5
[ "$(prop ActiveState)" = active ] || exit 6
unit_log | grep -q "outcome=rejected" || exit 7
'

run_case usr1-reopen "SIGUSR1 reopens the rotated log target" '
sudo -n sed -i "s|^log_target = \"stderr\"|log_target = \"$case_dir/daemon.log\"|" "$case_dir/config.toml" || exit 1
start_unit || exit 2
wait_active || exit 3
for i in $(seq 1 20); do sudo -n grep -q "native: ready" "$case_dir/daemon.log" 2>/dev/null && break; sleep 0.25; done
sudo -n mv "$case_dir/daemon.log" "$case_dir/daemon.log.1" || exit 4
old=$(sudo -n stat -c %s "$case_dir/daemon.log.1")
sudo -n kill -USR1 "$(main_pid)" || exit 5
sleep 0.5
sudo -n kill -HUP "$(main_pid)" || exit 6
for i in $(seq 1 20); do sudo -n grep -q "outcome=noop" "$case_dir/daemon.log" 2>/dev/null && break; sleep 0.25; done
sudo -n grep -q "outcome=noop" "$case_dir/daemon.log" || exit 7
[ "$(sudo -n stat -c %s "$case_dir/daemon.log.1")" = "$old" ] || exit 8
[ "$(sudo -n stat -c %a "$case_dir/daemon.log")" = 640 ] || exit 9
'

run_case term-stop "SIGTERM stops with a clean result and no socket left" '
start_unit || exit 1
wait_active || exit 2
sudo -n kill -TERM "$(main_pid)" || exit 3
wait_inactive || exit 4
[ "$(prop Result)" = success ] || exit 5
[ ! -e "$sock" ] || exit 6
'

run_case crash-restart "SIGSEGV restarts on-failure and re-admits" '
start_unit -p Restart=on-failure -p RestartSec=1 || exit 1
wait_active || exit 2
p0=$(main_pid)
sudo -n kill -SEGV "$p0" || exit 3
sleep 3
wait_active || exit 4
p1=$(main_pid)
[ -n "$p1" ] && [ "$p1" != 0 ] && [ "$p1" != "$p0" ] || exit 5
[ "$(prop NRestarts)" -ge 1 ] || exit 6
status_json | grep -q "\"storage\":\"healthy\"" || exit 7
'

run_case denied-state "read-only state dir refuses startup" '
start_unit -p ReadOnlyPaths="$case_dir/state" || true
sleep 2
[ "$(prop ActiveState)" = failed ] || exit 2
[ "$(prop ExecMainStatus)" = 1 ] || exit 3
unit_log | grep -q "refusing to start" || exit 4
unit_log | grep -q "ReadOnlyFileSystem" || exit 5
'

run_case missing-journalctl "journal jail without journalctl refuses" '
sudo -n sed -i "/^\[jails.sshd\]/,/^\[jails.nft\]/{s/^source = \"file\"/source = \"journald\"/;/^timestamp = /d;/^logpath = /d;/^filter = \"sshd\"/a journal_executables = [\"/usr/bin/true\"]
}" "$case_dir/config.toml" || exit 1
start_unit -p InaccessiblePaths=/usr/bin/journalctl || true
sleep 3
[ "$(prop ActiveState)" = failed ] || exit 3
[ "$(prop ExecMainStatus)" = 1 ] || exit 4
unit_log | grep -q "JournalExecutableUnavailable" || exit 5
'

run_case unit-lint "systemd-analyze verify on a rewritten copy" '
sed -e "s|^ExecStart=.*|ExecStart=$bin --config $case_dir/config.toml|" "$dir/fail2zig.service" | sudo -n tee "$case_dir/$unit.service" >/dev/null || exit 1
systemd-analyze verify "$case_dir/$unit.service" 2>&1 | sudo -n tee "$case_dir/lint.txt"
! grep -qiE "error|failed" "$case_dir/lint.txt" || exit 2
'

# --- cleanup and baseline check ---------------------------------------------------------
ssh_run "sudo -n rm -rf '$REMOTE_DIR'; for n in \$(sudo -n ip netns list | awk '/^$UNIT_PREFIX/{print \$1}'); do sudo -n ip netns delete \"\$n\"; done; true"
if [ "$DRY_RUN" = 1 ]; then
    echo "$BASELINE compare $BASELINE_FILE"
    rm -f "$BASELINE_FILE"
else
    if "$BASELINE" compare "$BASELINE_FILE"; then result PASS baseline "unchanged"; else result FAIL baseline "changed"; fi
    rm -f "$BASELINE_FILE"
fi

echo "summary pass=$PASS fail=$FAIL skip=$SKIP"
[ "$FAIL" = 0 ]
