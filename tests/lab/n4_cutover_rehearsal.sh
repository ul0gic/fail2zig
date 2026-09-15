#!/bin/bash
# Disposable migration cutover rehearsal on the authorized lab target: a pinned fail2ban 1.1.1
# reference tree acts as the source writer inside a private network namespace, the candidate
# stages and activates the migration there, and every persisted step boundary is interrupted
# and resumed. Nothing outside /var/tmp/f2z-n4-cut-<sha8> (disk, not tmpfs: staging must be
# nonvolatile) and the namespace is touched; the
# published service, binary, config and host ruleset are recorded before and rechecked after.
#
# Usage:
#   n4_cutover_rehearsal.sh [--dry-run] [--candidate zig-out/bin/fail2zig] [--reference DIR]
# Environment (as n4_lab_baseline.sh): F2Z_LAB_TARGET, F2Z_LAB_KEY.
# Output: one "PASS|FAIL|SKIP <case> <note>" line per case and a final summary; exit 1 on any FAIL.
set -eu

TARGET="${F2Z_LAB_TARGET:-ul0gic@172.16.150.253}"
KEY="${F2Z_LAB_KEY:-$HOME/.ssh/id_ed25519_p33ker}"
SSH_OPTS=(-i "$KEY" -o IdentitiesOnly=yes -o PreferredAuthentications=publickey -o BatchMode=yes -o ConnectTimeout=10)
CANDIDATE=zig-out/bin/fail2zig
REFERENCE=/tmp/fail2ban-parity-reference-1.1.1
DRY_RUN=0
while [ $# -gt 0 ]; do
    case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --candidate) CANDIDATE="$2"; shift ;;
    --reference) REFERENCE="$2"; shift ;;
    *) echo "usage: $0 [--dry-run] [--candidate <path>] [--reference <dir>]" >&2; exit 2 ;;
    esac
    shift
done
[ -x "$CANDIDATE" ] || { echo "candidate $CANDIDATE is not executable" >&2; exit 2; }
[ -f "$REFERENCE/bin/fail2ban-server" ] || { echo "reference tree $REFERENCE lacks bin/fail2ban-server" >&2; exit 2; }
SHA=$(sha256sum "$CANDIDATE" | cut -d' ' -f1)
SHA8=${SHA:0:8}
REMOTE_DIR=/var/tmp/f2z-n4-cut-$SHA8
NS=f2z-n4-cut-$SHA8
HERE=$(cd "$(dirname "$0")" && pwd)
echo "candidate=$CANDIDATE sha256=$SHA reference=$REFERENCE target=$TARGET remote_dir=$REMOTE_DIR ns=$NS"

pass=0; fail=0; skip=0
report() { echo "$1  $(printf '%-20s' "$2") $3"; case "$1" in PASS) pass=$((pass + 1)) ;; FAIL) fail=$((fail + 1)) ;; SKIP) skip=$((skip + 1)) ;; esac; }
ssh_run() {
    if [ "$DRY_RUN" = 1 ]; then echo "ssh ${SSH_OPTS[*]} $TARGET -- <remote script ${#1} bytes>"; return 0; fi
    ssh "${SSH_OPTS[@]}" "$TARGET" -- "$1"
}
scp_to() {
    if [ "$DRY_RUN" = 1 ]; then echo "scp ${SSH_OPTS[*]} $1 $TARGET:$2"; return 0; fi
    scp -q "${SSH_OPTS[@]}" "$1" "$TARGET:$2"
}

# Remote function library. Every helper runs as root through sudo -n; namespace-bound commands
# go through `ip netns exec`. Paths are fixed under $REMOTE_DIR.
REMOTE_LIB="set -u
D='$REMOTE_DIR'; NS='$NS'; BIN='$REMOTE_DIR/fail2zig'; REF='$REMOTE_DIR/ref'
F2B='$REMOTE_DIR/f2b'; F2Z='$REMOTE_DIR/f2z'
inns() { sudo -n ip netns exec \"\$NS\" \"\$@\"; }
f2bc() { inns env PYTHONPATH=\"\$REF\" python3 \"\$REF/bin/fail2ban-client\" -c \"\$F2B/conf\" -s \"\$F2B/run/fail2ban.sock\" \"\$@\"; }
writer_start() {
    # Fully detached: an inherited ssh stdio would keep the remote session open until it exits.
    sudo -n setsid -f ip netns exec \"\$NS\" sh -c \"exec env PYTHONPATH=\$REF python3 \$REF/bin/fail2ban-server -f -x -c \$F2B/conf -s \$F2B/run/fail2ban.sock >\$F2B/server.out 2>&1\" </dev/null >/dev/null 2>&1
    local i; for i in \$(seq 1 80); do [ -S \"\$F2B/run/fail2ban.sock\" ] && f2bc ping >/dev/null 2>&1 && return 0; sleep 0.25; done
    return 1
}
writer_stop() {
    f2bc stop >/dev/null 2>&1 || true
    local i; for i in \$(seq 1 80); do pgrep -f \"\$REF/bin/fail2ban-server\" >/dev/null || return 0; sleep 0.25; done
    sudo -n pkill -KILL -f \"\$REF/bin/fail2ban-server\" || true
    return 0
}
daemon_start() {
    sudo -n setsid -f ip netns exec \"\$NS\" sh -c \"exec \$BIN --foreground --config \$F2Z/config.toml >>\$F2Z/daemon.log 2>&1\" </dev/null >/dev/null 2>&1
    local i; for i in \$(seq 1 80); do sudo -n \"\$BIN\" --socket \"\$F2Z/run/fail2zig.sock\" --output json status 2>/dev/null | grep -q '\"storage\":\"healthy\"' && return 0; sleep 0.25; done
    sudo -n tail -5 \"\$F2Z/daemon.log\"; return 1
}
daemon_stop() {
    local pid; pid=\$(pgrep -f \"\$BIN --foreground --config \$F2Z/config.toml\" | head -1)
    [ -n \"\$pid\" ] || return 0
    sudo -n kill -TERM \"\$pid\" 2>/dev/null || true
    local i; for i in \$(seq 1 80); do sudo -n kill -0 \"\$pid\" 2>/dev/null || return 0; sleep 0.25; done
    sudo -n kill -KILL \"\$pid\" 2>/dev/null || true
}
daemon_reset_state() { daemon_stop; sudo -n rm -f \"\$F2Z/state/state.bin\"* ; daemon_start && daemon_stop; }
ruleset() { inns nft list ruleset 2>/dev/null; }
cutover_cmd() { sudo -n env \${FAULT:+F2Z_MIGRATE_FAULT=\$FAULT} \"\$BIN\" migrate cutover --plan \"\$D/plan.json\" --state-file \"\$F2Z/state/state.bin\" --staging-dir \"\$D/staging\" --backend nftables --socket \"\$F2Z/run/fail2zig.sock\" \"\$@\"; }
run_id_of() { sed -n 's/^migrate cutover: run \\([0-9a-f]\\{64\\}\\).*/\\1/p' \"\$1\" | head -1; }
wait_healthy() { local i; for i in \$(seq 1 80); do sudo -n \"\$BIN\" --socket \"\$F2Z/run/fail2zig.sock\" --output json status 2>/dev/null | grep -q '\"storage\":\"healthy\"' && return 0; sleep 0.25; done; return 1; }
rb() { sudo -n env \${FAULT:+F2Z_MIGRATE_FAULT=\$FAULT} \"\$BIN\" migrate rollback --plan \"\$D/plan.json\" --state-file \"\$F2Z/state/state.bin\" --staging-dir \"\$D/staging\" --backend nftables --socket \"\$F2Z/run/fail2zig.sock\" \"\$@\"; }
bips() { sudo -n python3 -c \"import sqlite3; c=sqlite3.connect('file:\$F2B/db/fail2ban.sqlite3?mode=ro',uri=True); print(sorted(c.execute('select ip,bantime from bips where jail=\\\"sshd\\\"').fetchall()))\"; }
live_owners() { sudo -n python3 -c \"import sqlite3; c=sqlite3.connect('file:\$F2Z/state/state.bin?mode=ro',uri=True); print(c.execute('select count(*) from effect_owners where lease_kind!=0').fetchone()[0])\"; }
replan() { sudo -n \"\$BIN\" migrate plan --source-dir \"\$F2B/conf\" --source-db \"\$F2B/db/fail2ban.sqlite3\" --staging-dir \"\$D/staging\" --out \"\$D/plan.json\" --replay-window 600 --runtime-socket \"\$F2B/run/fail2ban.sock\" >\"\$D/plan.out\" || { cat \"\$D/plan.out\"; return 1; }; }
full_cutover() { daemon_reset_state || return 1; replan || return 1; cutover_cmd >\"\$D/fc.out\" 2>\"\$D/fc.err\"; [ \$? = 3 ] || { cat \"\$D/fc.err\"; return 1; }; RUN=\$(run_id_of \"\$D/fc.err\"); daemon_start || return 1; cutover_cmd --run-id \"\$RUN\" >\"\$D/fc2.out\" 2>\"\$D/fc2.err\" || { cat \"\$D/fc2.err\"; return 1; }; echo \"\$RUN\"; }
"

setup_ok=1
phase() {
    local name="$1" note="$2" body="$3" rc=0
    if [ "$DRY_RUN" = 1 ]; then echo "phase $name: $note"; ssh_run "$REMOTE_LIB$body"; return 0; fi
    if [ "$setup_ok" = 0 ]; then report SKIP "$name" "setup failed"; return 0; fi
    ssh_run "$REMOTE_LIB$body" || rc=$?
    if [ "$rc" = 0 ]; then report PASS "$name" "$note"; else report FAIL "$name" "$note (rc=$rc)"; [ "$name" = setup ] && setup_ok=0; fi
    return 0
}

cleanup_remote() {
    ssh_run "$REMOTE_LIB
daemon_stop || true
writer_stop || true
sudo -n ip netns delete \"\$NS\" >/dev/null 2>&1 || true
sudo -n rm -rf \"\$D\"
" || true
}

BASELINE=$(mktemp)
trap 'cleanup_remote; rm -f "$BASELINE" "$REF_TAR"' EXIT
REF_TAR=$(mktemp --suffix=.tar.gz)
tar -C "$(dirname "$REFERENCE")" -czf "$REF_TAR" "$(basename "$REFERENCE")"
if [ "$DRY_RUN" = 1 ]; then echo "$HERE/n4_lab_baseline.sh record $BASELINE"; else "$HERE/n4_lab_baseline.sh" record "$BASELINE"; fi

ssh_run "mkdir -p '$REMOTE_DIR' && chmod 0755 '$REMOTE_DIR'"
scp_to "$CANDIDATE" "$REMOTE_DIR/fail2zig"
scp_to "$REF_TAR" "$REMOTE_DIR/ref.tar.gz"

phase setup "namespace, reference writer tree, disposable configs" "
echo \"$SHA  \$BIN\" | sha256sum -c --quiet || exit 3
chmod 0755 \"\$BIN\"
mkdir -p \"\$REF\" && tar -C \"\$D\" -xzf \"\$D/ref.tar.gz\" && mv \"\$D/$(basename "$REFERENCE")\"/* \"\$REF\"/ || exit 4
sudo -n ip netns add \"\$NS\" || exit 5
sudo -n ip -n \"\$NS\" link set lo up || exit 5
mkdir -p \"\$F2B/conf/jail.d\" \"\$F2B/run\" \"\$F2B/db\" \"\$F2B/log\" \"\$F2Z/run\" \"\$F2Z/state\" \"\$D/staging\" || exit 6
cp -r \"\$REF/config/\"* \"\$F2B/conf/\" || exit 6
sed -i \"s#^socket = .*#socket = \$F2B/run/fail2ban.sock#; s#^pidfile = .*#pidfile = \$F2B/run/fail2ban.pid#; s#^dbfile = .*#dbfile = \$F2B/db/fail2ban.sqlite3#; s#^logtarget = .*#logtarget = \$F2B/log/fail2ban.log#\" \"\$F2B/conf/fail2ban.conf\" || exit 6
cat >\"\$F2B/conf/jail.d/lab.conf\" <<CFG
[DEFAULT]
backend = polling
banaction = nftables
banaction_allports = nftables-allports
[sshd]
enabled = true
backend = polling
logpath = \$F2B/log/auth.log
maxretry = 2
findtime = 600
bantime = 3600
CFG
touch \"\$F2B/log/auth.log\"
sudo -n chown -R root:root \"\$F2Z\" \"\$D/staging\" && sudo -n chmod 0750 \"\$F2Z/run\" \"\$F2Z/state\" && sudo -n chmod 0700 \"\$D/staging\" || exit 7
sudo -n tee \"\$F2Z/config.toml\" >/dev/null <<CFG
[global]
native_ingestion = true
log_level = \"info\"
state_file = \"\$F2Z/state/state.bin\"
socket_path = \"\$F2Z/run/fail2zig.sock\"
metrics_enabled = false
firewall = \"nftables\"
firewall_namespace = \"/run/netns/\$NS\"
[defaults]
enforce = true
maxretry = 3
findtime = 600
bantime = 3600
[jails.sshd]
filter = \"sshd\"
source = \"file\"
timestamp = \"syslog\"
timezone_offset_minutes = 0
logpath = [\"\$F2B/log/auth.log\"]
CFG
sudo -n chmod 0640 \"\$F2Z/config.toml\" || exit 7
"

phase writer "fail2ban 1.1.1 writer bans live in the namespace, records a permanent ban, then stops" "
writer_start || { sudo -n tail -20 \"\$F2B/log/fail2ban.log\"; exit 1; }
for i in 1 2 3; do echo \"\$(date '+%b %e %H:%M:%S') lab sshd[1]: Failed password for root from 203.0.113.77 port 1 ssh2\" >>\"\$F2B/log/auth.log\"; done
for i in \$(seq 1 80); do ruleset | grep -q '203.0.113.77' && break; sleep 0.25; done
ruleset | grep -q '203.0.113.77' || { sudo -n tail -20 \"\$F2B/log/fail2ban.log\"; exit 2; }
f2bc set sshd bantime -1 >/dev/null || exit 3
f2bc set sshd banip 198.51.100.7 >/dev/null || exit 3
for i in \$(seq 1 40); do ruleset | grep -q '198.51.100.7' && break; sleep 0.25; done
ruleset | grep -q '198.51.100.7' || exit 4
f2bc status sshd | grep -q 'Currently banned:.*2' || exit 5
writer_stop
sudo -n python3 - <<PY || exit 6
import sqlite3
c = sqlite3.connect('\$F2B/db/fail2ban.sqlite3')
rows = c.execute('select ip, bantime from bips where jail=\"sshd\" order by ip').fetchall()
assert ('198.51.100.7', -1) in rows and any(r[0] == '203.0.113.77' and r[1] == 3600 for r in rows), rows
assert c.execute('select count(*) from logs where jail=\"sshd\" and firstlinemd5 is not null').fetchone()[0] == 1
PY
ruleset | grep -q '203.0.113.77' && { echo 'writer stop left its rules in place'; exit 7; }
exit 0
"

phase prepare "inspect, plan with snapshot and validate against the writer's tree and database" "
sudo -n \"\$BIN\" migrate inspect --source-dir \"\$F2B/conf\" --output table >\"\$D/inspect.out\" 2>&1 || { cat \"\$D/inspect.out\"; exit 1; }
replan || exit 2
sudo -n \"\$BIN\" migrate validate --plan \"\$D/plan.json\" >\"\$D/validate.out\" || { cat \"\$D/validate.out\"; exit 3; }
grep -q '\"outcome\":\"valid\"' \"\$D/validate.out\" || exit 3
"

phase cutover "stage offline with the daemon stopped, resume against the enforcing daemon, restored owners readable in the kernel" "
daemon_reset_state || exit 1
cutover_cmd >\"\$D/cut1.out\" 2>\"\$D/cut1.err\"; rc=\$?; [ \"\$rc\" = 3 ] || { cat \"\$D/cut1.err\"; exit 2; }
grep -q '\"state\":\"staged\"' \"\$D/cut1.out\" || exit 2
RUN=\$(run_id_of \"\$D/cut1.err\"); [ -n \"\$RUN\" ] || exit 2
echo \"\$RUN\" >\"\$D/run.id\"
ruleset | grep -q '198.51.100.7' && exit 3
daemon_start || exit 4
ruleset | grep -q '198.51.100.7' && exit 5
cutover_cmd --run-id \"\$RUN\" >\"\$D/cut2.out\" 2>\"\$D/cut2.err\"; rc=\$?; [ \"\$rc\" = 0 ] || { cat \"\$D/cut2.err\"; exit 6; }
grep -q '\"state\":\"complete\"' \"\$D/cut2.out\" || exit 6
ruleset | grep -q '198.51.100.7' || { ruleset; cat \"\$D/cut1.out\" \"\$D/cut2.out\" \"\$D/cut2.err\"; sudo -n tail -20 \"\$F2Z/daemon.log\"; exit 7; }
ruleset | grep -q '203.0.113.77' || { ruleset; cat \"\$D/cut2.out\"; exit 7; }
for i in \$(seq 1 40); do sudo -n \"\$BIN\" --socket \"\$F2Z/run/fail2zig.sock\" --output json status | grep -q '\"state\":\"enforcing\"' && break; sleep 0.25; done
sudo -n \"\$BIN\" --socket \"\$F2Z/run/fail2zig.sock\" --output json status | grep -q '\"state\":\"enforcing\"' || { sudo -n \"\$BIN\" --socket \"\$F2Z/run/fail2zig.sock\" --output json status; sudo -n tail -30 \"\$F2Z/daemon.log\"; exit 8; }
sudo -n \"\$BIN\" migrate status --plan \"\$D/plan.json\" --state-file \"\$F2Z/state/state.bin\" --staging-dir \"\$D/staging\" --backend nftables --run-id \"\$RUN\" | grep -q '\"outcome\":\"success\"' || exit 9
cutover_cmd --run-id \"\$RUN\" >/dev/null 2>&1 || exit 10
ruleset >\"\$D/ruleset.reference\"
# N3.5.4: a non-destructive stop removes only the realized rules; restart restores the owners
# from durable authority with their original leases and no fresh confirmation.
owner_view() { sudo -n python3 -c \"import sqlite3,sys; c=sqlite3.connect('file:\$F2Z/state/state.bin?mode=ro',uri=True); print(c.execute('select jail,hex(scope_key),lease_kind,deadline_us,decided_us,hex(decision_id) from effect_owners where lease_kind!=0 order by 1,2').fetchall()); print('revisions',c.execute('select count(*) from effect_owner_revisions').fetchone()[0]); print('confirmed',c.execute('select count(*) from confirmed_effect_events').fetchone()[0]); print(c.execute('select jail,hex(decision_id),confirmed_us from confirmed_effect_events order by confirmed_us').fetchall()); print('records',c.execute('select count(*) from records').fetchone()[0], 'retry',[tuple(r) for r in c.execute('select name from sqlite_master where name like \\\"retry%\\\"')])\"; }
# The newest record stays pending until a later line arrives; a benign line commits the third
# failure so its decision (absorbed by the live migrated owner, which keeps its lease) lands before the digest.
echo \"\$(date '+%b %e %H:%M:%S') lab sshd[1]: Accepted publickey for ops from 198.51.100.9 port 5000 ssh2\" | sudo -n tee -a \"\$F2B/log/auth.log\" >/dev/null
for i in \$(seq 1 80); do sudo -n \"\$BIN\" --socket \"\$F2Z/run/fail2zig.sock\" --output json status | grep -q '\"committed_records\":[3-9]' && break; sleep 0.25; done
sudo -n \"\$BIN\" --socket \"\$F2Z/run/fail2zig.sock\" --output json status | grep -q '\"committed_records\":[3-9]' || { echo 'writer lines not fully ingested before the digest'; sudo -n \"\$BIN\" --socket \"\$F2Z/run/fail2zig.sock\" --output json status; exit 11; }
sleep 3
owner_view >\"\$D/owners.before\" || exit 11
daemon_stop
pgrep -f \"\$BIN --foreground --config \$F2Z/config.toml\" >/dev/null && { echo 'daemon still running after stop'; exit 11; }
for i in \$(seq 1 40); do ruleset | grep -q '198.51.100.7\\|203.0.113.77' || break; sleep 0.25; done
ruleset | grep -q '198.51.100.7\\|203.0.113.77' && { echo 'realized rules still present 10 s after the daemon exited'; ruleset; exit 11; }
daemon_start || exit 12
ruleset | grep -q '198.51.100.7' || { ruleset; exit 13; }
ruleset | grep -q '203.0.113.77' || { ruleset; exit 13; }
owner_view >\"\$D/owners.after\" || exit 13
diff \"\$D/owners.before\" \"\$D/owners.after\" || { echo 'owners, revisions or confirmations changed across restart'; sudo -n tail -40 \"\$F2Z/daemon.log\"; sudo -n python3 -c \"import sqlite3; c=sqlite3.connect('file:\$F2Z/state/state.bin?mode=ro',uri=True); print(c.execute('select jail,hex(decision_id),lease_kind,deadline_us,decided_us,revision from effect_owners').fetchall())\"; exit 14; }
daemon_stop
"

for step in validate_plan check_drift capture_recovery_point quiesce_source stage_destination; do
    phase "interrupt-$step" "crash after the $step intent, resume by run id, complete with the same kernel state" "
daemon_reset_state || exit 1
FAULT=$step cutover_cmd >\"\$D/int.out\" 2>\"\$D/int.err\"; rc=\$?; [ \"\$rc\" = 137 ] || { cat \"\$D/int.err\"; exit 2; }
RUN=\$(run_id_of \"\$D/int.err\"); [ -n \"\$RUN\" ] || exit 2
cutover_cmd --run-id \"\$RUN\" >\"\$D/res.out\" 2>\"\$D/res.err\"; rc=\$?; [ \"\$rc\" = 3 ] || { cat \"\$D/res.err\"; exit 3; }
grep -q '\"state\":\"staged\"' \"\$D/res.out\" || exit 3
grep -q '\"step\":\"$step\",\"outcome\":\"success\"' \"\$D/res.out\" || exit 4
daemon_start || exit 5
cutover_cmd --run-id \"\$RUN\" >\"\$D/fin.out\" 2>\"\$D/fin.err\"; rc=\$?; [ \"\$rc\" = 0 ] || { cat \"\$D/fin.err\"; exit 6; }
ruleset | grep -q '198.51.100.7' || exit 7
ruleset | grep -q '203.0.113.77' || exit 7
daemon_stop
"
done

phase rollback "restore the source with carried-back deltas, then release the destination only after the writer protects again" "
RUN=\$(cat \"\$D/run.id\")
daemon_start || exit 1
sudo -n \"\$BIN\" --socket \"\$F2Z/run/fail2zig.sock\" --output json ban 203.0.113.99 --jail sshd >/dev/null || exit 1
rb --run-id \"\$RUN\" >\"\$D/rb1.out\" 2>\"\$D/rb1.err\"; rc=\$?; [ \"\$rc\" = 3 ] || { cat \"\$D/rb1.err\"; exit 2; }
grep -q 'source database restored' \"\$D/rb1.err\" || { cat \"\$D/rb1.err\"; exit 2; }
bips >\"\$D/bips.restored\" || exit 3
grep -q \"('198.51.100.7', -1)\" \"\$D/bips.restored\" || { cat \"\$D/bips.restored\"; exit 3; }
grep -q \"'203.0.113.99'\" \"\$D/bips.restored\" || { cat \"\$D/bips.restored\"; exit 3; }
grep -q \"'203.0.113.77'\" \"\$D/bips.restored\" || { cat \"\$D/bips.restored\"; exit 3; }
ls \"\$F2B/db/\"fail2ban.sqlite3.pre-rollback-* >/dev/null 2>&1 || exit 4
rb --run-id \"\$RUN\" >/dev/null 2>\"\$D/rb1b.err\"; [ \$? = 3 ] || exit 5
grep -q 'destination ownership is still held' \"\$D/rb1b.err\" || { cat \"\$D/rb1b.err\"; exit 5; }
rb --run-id \"\$RUN\" --source-verified >/dev/null 2>\"\$D/rb1c.err\"; [ \$? = 3 ] || exit 5
grep -q 'control socket' \"\$D/rb1c.err\" || { cat \"\$D/rb1c.err\"; exit 5; }
writer_start || { sudo -n tail -20 \"\$F2B/log/fail2ban.log\"; exit 6; }
for i in \$(seq 1 80); do f2bc status sshd 2>/dev/null | grep -q 'Currently banned:.*3' && break; sleep 0.25; done
f2bc status sshd | grep -q 'Currently banned:.*3' || { f2bc status sshd; exit 6; }
wait_healthy || exit 7
rb --run-id \"\$RUN\" --source-verified >\"\$D/rb2.out\" 2>\"\$D/rb2.err\"; rc=\$?; [ \"\$rc\" = 0 ] || { cat \"\$D/rb2.err\"; exit 7; }
grep -q '\"state\":\"rolled_back\"' \"\$D/rb2.out\" || exit 7
[ \"\$(live_owners)\" = 1 ] || { echo \"live destination owners after release: \$(live_owners)\"; exit 8; }
f2bc status sshd | grep -q 'Currently banned:.*3' || exit 9
rb --run-id \"\$RUN\" --source-verified >/dev/null 2>&1 || exit 10
writer_stop; daemon_stop
"

phase rollback-changed-source "a source that changed after quiescence is refused and nothing is replaced" "
RUN=\$(full_cutover) || exit 1
sudo -n python3 -c \"import sqlite3,time; c=sqlite3.connect('\$F2B/db/fail2ban.sqlite3'); now=int(time.time()); c.execute('insert into bans(jail,ip,timeofban,bantime,bancount,data) values(?,?,?,?,1,NULL)',('sshd','198.51.100.200',now,600)); c.execute('insert or replace into bips(jail,ip,timeofban,bantime,bancount,data) values(?,?,?,?,1,NULL)',('sshd','198.51.100.200',now,600)); c.commit()\" || exit 2
before=\$(sudo -n sha256sum \"\$F2B/db/fail2ban.sqlite3\" | cut -d' ' -f1)
rb --run-id \"\$RUN\" >\"\$D/rbc.out\" 2>\"\$D/rbc.err\"; rc=\$?; [ \"\$rc\" = 4 ] || { cat \"\$D/rbc.err\"; exit 3; }
grep -q 'changed since' \"\$D/rbc.err\" || { cat \"\$D/rbc.err\"; exit 3; }
[ \"\$(sudo -n sha256sum \"\$F2B/db/fail2ban.sqlite3\" | cut -d' ' -f1)\" = \"\$before\" ] || exit 4
grep -q '\"outcome\":\"rollback_failed\"' \"\$D/rbc.out\" || exit 5
daemon_stop
sudo -n rm -f \"\$F2B/db/\"fail2ban.sqlite3.pre-rollback-*
"

phase rollback-interrupt "a rollback killed after its intent resumes by run id and still restores" "
sudo -n cp \"\$D/staging/\"recovery-point-* /dev/null 2>/dev/null || true
daemon_stop
sudo -n cp \"\$D/bips.restored\" /dev/null 2>/dev/null || true
RUN=\$(full_cutover) || exit 1
FAULT=rollback rb --run-id \"\$RUN\" >/dev/null 2>\"\$D/rbi.err\"; [ \$? = 137 ] || { cat \"\$D/rbi.err\"; exit 2; }
rb --run-id \"\$RUN\" >\"\$D/rbi2.out\" 2>\"\$D/rbi2.err\"; rc=\$?; [ \"\$rc\" = 3 ] || { cat \"\$D/rbi2.err\"; exit 3; }
grep -q 'source database restored' \"\$D/rbi2.err\" || { cat \"\$D/rbi2.err\"; exit 3; }
grep -q '\"step\":\"rollback\",\"outcome\":\"pending\"' \"\$D/rbi2.out\" || exit 4
daemon_stop
"

phase rollback-interrupt-swap "a rollback killed between the two renames resumes by completing the swap, then releases after the writer protects" "
RUN=\$(full_cutover) || exit 1
FAULT=rollback_swap rb --run-id \"\$RUN\" >/dev/null 2>\"\$D/rbs.err\"; [ \$? = 137 ] || { cat \"\$D/rbs.err\"; exit 2; }
sudo -n test -e \"\$F2B/db/fail2ban.sqlite3\" && { echo 'source still present after the first rename'; exit 3; }
rb --run-id \"\$RUN\" >\"\$D/rbs2.out\" 2>\"\$D/rbs2.err\"; rc=\$?; [ \"\$rc\" = 3 ] || { cat \"\$D/rbs2.err\"; exit 4; }
grep -q 'completed the interrupted swap' \"\$D/rbs2.err\" || { cat \"\$D/rbs2.err\"; exit 4; }
bips | grep -q \"('198.51.100.7', -1)\" || exit 5
writer_start || exit 6
for i in \$(seq 1 80); do f2bc status sshd 2>/dev/null | grep -q 'Currently banned:.*[1-9]' && break; sleep 0.25; done
wait_healthy || exit 7
rb --run-id \"\$RUN\" --source-verified >\"\$D/rbs3.out\" 2>\"\$D/rbs3.err\"; rc=\$?; [ \"\$rc\" = 0 ] || { cat \"\$D/rbs3.err\"; exit 7; }
grep -q '\"state\":\"rolled_back\"' \"\$D/rbs3.out\" || exit 7
writer_stop; daemon_stop
sudo -n rm -f \"\$F2B/db/\"fail2ban.sqlite3.pre-rollback-* \"\$D/staging/\"restored-*
"

phase stale-plan "a jail tree edited after planning is refused before any mutation" "
daemon_reset_state || exit 1
echo '# edited after planning' >>\"\$F2B/conf/jail.d/lab.conf\"
cutover_cmd >\"\$D/stale.out\" 2>\"\$D/stale.err\"; rc=\$?; [ \"\$rc\" = 1 ] || { cat \"\$D/stale.err\"; exit 2; }
grep -q 'drifted\\|file-changed' \"\$D/stale.err\" || { cat \"\$D/stale.err\"; exit 3; }
grep -q '\"step\":\"validate_plan\",\"outcome\":\"validation_failed\"' \"\$D/stale.out\" || exit 4
sed -i '/# edited after planning/d' \"\$F2B/conf/jail.d/lab.conf\"
"

phase denied-staging "a permissive staging directory is refused before anything is written" "
sudo -n mkdir -p \"\$D/loose\" && sudo -n chmod 0755 \"\$D/loose\"
sudo -n \"\$BIN\" migrate cutover --plan \"\$D/plan.json\" --state-file \"\$F2Z/state/state.bin\" --staging-dir \"\$D/loose\" --backend nftables --socket \"\$F2Z/run/fail2zig.sock\" >/dev/null 2>\"\$D/loose.err\"; rc=\$?; [ \"\$rc\" = 2 ] || { cat \"\$D/loose.err\"; exit 2; }
[ -z \"\$(ls -A \"\$D/loose\")\" ] || exit 3
"

phase writer-active "an active source writer blocks quiescence and the run stays resumable" "
daemon_reset_state || exit 1
writer_start || exit 2
cutover_cmd >\"\$D/active.out\" 2>\"\$D/active.err\"; rc=\$?; writer_stop; [ \"\$rc\" = 1 ] || { cat \"\$D/active.err\"; exit 3; }
grep -q 'source writer is still active\\|changed since the plan\\|runtime-state-changed' \"\$D/active.err\" || { cat \"\$D/active.err\"; exit 4; }
grep -q '\"outcome\":\"operational_failure\"\\|\"outcome\":\"validation_failed\"' \"\$D/active.out\" || exit 5
"

cleanup_remote
trap 'rm -f "$BASELINE" "$REF_TAR"' EXIT
if [ "$DRY_RUN" = 1 ]; then
    echo "$HERE/n4_lab_baseline.sh compare $BASELINE"
else
    if "$HERE/n4_lab_baseline.sh" compare "$BASELINE"; then report PASS baseline unchanged; else report FAIL baseline changed; fi
fi
echo "summary pass=$pass fail=$fail skip=$skip"
[ "$fail" = 0 ]
