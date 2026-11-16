---
title: Migrating from fail2ban
description: Inspect supported configuration, transfer schema-4 SQLite state and plan continuity, cutover and rollback.
sidebar_position: 2
category: Getting Started
audience: operator
last_verified: 2026-11-16
---

fail2ban configuration inspection and state migration are separate operations.
Review supported protection before switching: a matching filter name does not
prove equivalent detection, and unsupported enabled protection blocks activation.
Legacy fail2zig 0.3.0 binary state has no converter; see the
[upgrade guide](upgrading.md).

## Before you start

Use the current release's executable and retain the fail2ban source installation
for its migration rollback. Rollback to any pre-v0.4.7 fail2zig release is unsupported.

The legacy same-named Fail2ban `portsentry` filter does not map to the new
PortSentry v2.0.7 history integration. Set it up separately using the
[qualified recipe](portsentry.md). Upgrading an existing native fail2zig
installation follows the [upgrade guide](upgrading.md).
Selected live qualification used Debian 13 x86_64; other release architectures
have build/static/QEMU smoke evidence. Ubuntu and non-x86 hardware enforcement
remain untested. A kernel version alone does not establish support.

Journal input needs journald and journalctl. nftables uses direct netlink;
iptables/ipset require their host tools. Native destination state and private
staging must belong to the service UID. Read the complete workflow before stopping
protection, including the temporary privileges needed for offline rollback.

## What transfers

The supported schema-4 SQLite workflow can transfer admitted protection owners,
original deadlines and confirmed history. It inspects scope and continuity,
records blockers and journals cutover/rollback. It does not point the native
daemon at the foreign live database.

## What does not transfer

- Arbitrary fail2ban regexes, filter definitions, Python extensions, mail actions
  and shell action templates are not executed by fail2zig. Use reviewed built-ins
  or [bounded native JSON rules](../reference/filters.md#custom-native-rules).
- In-memory partial matches, in-window failure counters and multiline correlation
  state are absent from fail2ban's database and cannot be transferred.
- fail2ban has no saved journal cursor. Journal migration needs an explicit reset/replay
  disposition; it cannot claim lossless log-position continuity.
- fail2ban's socket protocol and runtime mutation API are not supported. Use
  [native administration](../reference/cli-fail2zig-client.md).
- Arbitrary bantime formulas are not evaluated. Review native linear/exponential
  multiplier, factor, cap, scope and jitter semantics rather than assuming equivalence.

## Inspect and project configuration

```bash
sudo fail2zig migrate inspect --source-dir /etc/fail2ban
sudo fail2zig --import-config /etc/fail2ban --import-output /tmp/fail2zig-review.toml
sudo fail2zig --validate-config --config /tmp/fail2zig-review.toml
```

The separate review path avoids replacing a working configuration. Projection
alone transfers no state and proves no live protection. Review all warnings,
disabled or blocked jails, log paths, source origins, timestamp contracts, ignore
policy and action scope. Unsupported protection needs an explicit replacement or
disposition before activation, not a silent loss of coverage.

`global.firewall` chooses the daemon backend. Jail `enforce` selects enforcement
or log-only policy, not an independent backend. Use log-only operation with separate
state to compare representative inputs while fail2ban retains protection; do not
assume identical decisions from a short observation window.

Quoted native durations such as `"1h"` are valid in the duration fields listed in
the [configuration reference](../reference/config.md#duration-strings), which also
gives exact keys and inheritance.

## Migration workflow

This workflow accepts supported **fail2ban schema-4 SQLite** input. It does not convert
fail2zig v0.3.0 binary state. For an existing native database's service-account transition,
follow [upgrading fail2zig state](upgrading.md).

The offline preparation commands never touch the running fail2ban service, its database or
the firewall:

```
fail2zig migrate inspect  --source-dir /etc/fail2ban [--output json|table]
fail2zig migrate snapshot --source-db /var/lib/fail2ban/fail2ban.sqlite3 --staging-dir <dir>
fail2zig migrate plan     --source-dir /etc/fail2ban --source-db <db> --staging-dir <dir> \
                          --out plan.json [--continuity lossless|reset-replay] [--replay-window <s>] \
                          [--runtime-socket <path>]
fail2zig migrate validate --plan plan.json [--source-dir <dir>] [--snapshot <file>]
```

`--staging-dir` must be a private (0700), non-volatile directory; `reset-replay` continuity
needs `--replay-window`, otherwise the plan records a `replay-window-missing` blocker.
`--runtime-socket` records the source service's control socket for a later rollback
(default `/var/run/fail2ban/fail2ban.sock`).

Run preparation and native destination operations as the same UID that will own the native
daemon store. A root-created destination database is not reopenable by the `fail2zig` service
until a safe offline ownership transition. With the account installed, prepare a private,
persistent staging directory owned by it, and invoke commands with the required capabilities:

The source file and its ancestors must also grant the service UID ordinary read/search
permission: the source admission check uses the real UID, so capabilities alone do not satisfy
it. If the source already has a restricted reader group, grant that group only to the offline
command with `-p 'SupplementaryGroups=<existing-source-reader-group>'`. Do not add that membership
to the shipped daemon or make the source writable/world-readable to bypass the check.

```bash
sudo install -d -o fail2zig -g fail2zig -m 0700 /var/lib/fail2zig-migration
sudo systemd-run --wait --pipe --uid=fail2zig --gid=fail2zig \
  -p 'AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH' \
  /usr/local/bin/fail2zig migrate snapshot \
  --source-db /var/lib/fail2ban/fail2ban.sqlite3 \
  --staging-dir /var/lib/fail2zig-migration
```

Use this invocation prefix for `plan`, `validate`, native `cutover` and `status` as well,
with absolute paths. Substitute the configured service group if it differs. Staging must
belong to the invoking UID, and the native destination parent/database must belong to the
daemon UID; configuration and executable files remain administrator-owned. The capability
grant does not make an inaccessible source path writable or bypass systemd mount restrictions.
Keep the destination daemon stopped while creating/staging native state. The commands below
show the migration arguments; apply the account/capability prefix above for destination access.

The cutover is journaled and resumable:

```
systemctl stop fail2ban
fail2zig migrate cutover --plan plan.json --state-file /var/lib/fail2zig/state.bin \
                         --staging-dir <dir> --backend nftables|ipset|iptables [--socket <path>]
fail2zig migrate status  --plan plan.json --state-file <db> --staging-dir <dir> \
                         --backend nftables|ipset|iptables --run-id <hex>
```

Staging happens offline with the daemon stopped; activation and kernel verification run
inside the daemon over the socket. Without `--socket`, `migrate` uses the `socket_path`
set in `/etc/fail2zig/config.toml`. When the socket is unreachable the command exits 3 and
prints the exact `--run-id` command to resume; a rerun with `--run-id` classifies the journal
and the store instead of replaying. Exit mapping: before any mutation every failure is 1;
after a mutation, incomplete protection is 4 (`partial`) and an unestablished outcome is 5
(`uncertain`); `pending` is 3.

The disclosed protection gap is the interval between stopping fail2ban and the daemon's
activation. Start the destination service explicitly after offline staging, then use the
printed resume command against its socket to complete activation. The installer does not
perform this handoff.

### Rollback

Source restoration must write beside the original fail2ban database and restore its original
UID, GID and mode. The ordinary service capabilities are insufficient. Stop **both** source
and destination writers, preserve their current coherent databases, and run the offline restore
as the native service UID with a temporary capability grant. For a root-owned source:

```bash
# RUN_ID is the recorded migration run ID. Use the original backend and paths.
sudo systemctl stop fail2ban fail2zig
sudo systemd-run --wait --pipe --uid=fail2zig --gid=fail2zig \
  -p 'AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE CAP_CHOWN CAP_FOWNER' \
  -p 'CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE CAP_CHOWN CAP_FOWNER' \
  /usr/local/bin/fail2zig migrate rollback \
  --plan /var/lib/fail2zig-migration/plan.json \
  --state-file /var/lib/fail2zig/state.bin \
  --staging-dir /var/lib/fail2zig-migration --backend nftables --run-id "$RUN_ID"
```

Substitute the configured group and, if needed, the transient source-reader group described
above. These additional capabilities belong only to this operator-launched offline command;
do not add them to `fail2zig.service`. The original source parent ownership is retained, and
the restored database receives the source's original ownership and mode. Read-only mounts or
other filesystem restrictions still require operator repair.

After the restore reports its next step, start fail2ban and verify source protection, then
start the destination daemon so the second `--source-verified` operation can release its
owners through IPC. That second operation uses the ordinary migration invocation prefix;
the extra restore capabilities are unnecessary. Keep the source serving until rollback
completion is confirmed. The general arguments are:

```
fail2zig migrate rollback --plan plan.json --state-file <db> --staging-dir <dir> \
                          --backend nftables|ipset|iptables --run-id <hex> [--socket <path>]
fail2zig migrate rollback ... --run-id <hex> --source-verified
```

Only an activated run needs rollback; a staged run is discarded by not activating it, and
a run whose cutover step is still open must first be resumed with `migrate cutover --run-id`.
The rollback is journaled under the same run in two phases:

1. **Restore the source.** The recovery point `recovery-point-<run16>.sqlite3` in the staging
   directory is validated against the plan's snapshot, and the live source database is
   fingerprinted through the SQLite backup API (WAL-aware). A recovery-point or source
   fingerprint mismatch finishes the step as `rollback_failed` with nothing written (exit 4).
   Environment failures (unreadable recovery point or source, no space, a failed rename
   after which the original is put back) are `operational_failure`, exit 1, and the run stays
   resumable. Otherwise the post-cutover deltas are carried back: native bans into
   `bans`/`bips`, released or expired staged owners removed from `bips`, and scopes with
   protocol or port restrictions reported as `unsupported`. The derived database is written
   beside the source, fsync'd and given the original's owner and mode; the original moves to
   `<source>.pre-rollback-<run16>` together with its `-wal`/`-shm` siblings (nothing is
   deleted); the derived file is renamed into place and the directory is synced; a durable
   marker `restored-<run16>` in the staging directory records the completed swap. The command
   then exits 3 and prints the next command.
2. **Release the destination.** Requires `--source-verified`, the source control socket
   recorded in the plan, and a running `fail2ban-server` process (a stale socket is refused).
   The daemon accepts the release only while the rollback step is open; native owners stay.
   `applied` sets the run state to `rolled_back` and exits 0. A partial (4), uncertain (5) or
   refused (1) release leaves the step open for a rerun; an unreachable daemon or a rejected
   request exits 3.

A rerun with `--run-id` classifies by the marker and the files: marker present, release only;
source missing with the derived file present, the swap is completed; source missing with only
the kept copy, it is moved back and the restore repeats; source unchanged, the restore repeats;
source changed with no marker, `rollback_failed`. Not lab-exercised: bans that expire during
the outage window, and a rename failure after the original has been moved aside.

## Continuity and replay

The continuity check decides whether cutover may proceed; it does not carry
fail2ban's log positions into fail2zig. With `lossless`, a file whose recorded
position and identity checks fail, and every journal group, blocks activation.
Cutover writes no source position, so after cutover each timestamped file source
reads its current file from the start, each undated file source starts at the end
of its current file, and each journal source starts at the time its session
starts. A timestamped line older than the jail's `findtime` does not count; a
newer one counts, including a failure fail2ban already counted.

With reset/replay the planner requires a replay window, and cutover reports the
outcome as not lossless. The window is an acknowledgement; neither cutover nor
the daemon reads from its start. Imported active bans are reconciled by the
importer. Nothing suppresses a line fail2ban counted and fail2zig reads again.

Review the [continuity contract](../operations/migration-continuity.md)
for per-file decisions and duplicate boundaries.

## Verify protection

After activation or rollback, check the running version, source health, storage
and installed owners. Inspect the selected backend and exercise a controlled
external test path; a successful command or open HTTP connection is insufficient.

```bash
sudo fail2zig version
sudo fail2zig status
sudo fail2zig jails
sudo fail2zig list
sudo fail2zig history
sudo fail2zig firewall show --details
sudo nft list tables | grep ' f2z_'
```

The final command applies to nftables: the daemon owns one table named
`f2z_<hash>` after its installation, and `sudo nft list table inet f2z_<hash>`
prints it. Use the appropriate backend inspection for iptables/ipset. Read owned
set and rule names from the actual backend; do not assume them from an older
release. Keep default loopback ignores,
and verify packet behavior from a controlled external path.

This guide follows the [command migration contract](../operations/command-migration.md).
Rehearse the selected source, scope and failure/rollback cases before a production
transition. Qualification does not cover every installation or every interruption.
