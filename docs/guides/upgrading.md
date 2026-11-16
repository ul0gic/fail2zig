---
title: 'Upgrading fail2zig'
description: 'Reach the current release from v0.4.9, v0.4.8 or v0.4.7, with the state backups the first start writes, the settings to review, rollback and the checks to run afterwards.'
sidebar_position: 3
category: Getting Started
audience: operator
last_verified: 2026-11-16
---

This page covers what changes for an existing installation when you move to
0.4.10. The [installation guide](../operations/installation.md) has the install
steps, and the [release notes](../../RELEASE_NOTES.md) list every change.

## Which releases can upgrade

| State last written by | Path to 0.4.10                                                                  |
| --------------------- | ------------------------------------------------------------------------------- |
| v0.4.9 (schema 28)    | Install 0.4.10 and start it. One step, to schema 29.                            |
| v0.4.8 (schema 26)    | Install 0.4.10 and start it. Two steps in the same start: schema 28, then 29.   |
| v0.4.7 (schema 25)    | Install 0.4.10 and start it. Three steps in the same start: 26, 28, then 29.    |
| v0.4.6 (schema 24)    | Install v0.4.7 first and start it once, then upgrade to 0.4.10.                 |
| v0.4.5 or earlier     | No supported path. Start from a fresh state and plan the protection gap.        |
| v0.3.0 binary state   | No converter. The installer refuses to reinterpret it; start from fresh state.  |

v0.4.7 is the minimum supported release. Releases, downloads and Git tags before
it are retired, and installing or rolling back to them is unsupported.

For a v0.4.6 state, install the
[v0.4.7 release](https://github.com/ul0gic/fail2zig/releases/tag/v0.4.7) and
start it once. That start upgrades schema 24 to 25 after writing
`<state_file>.pre25-backup`. Confirm `fail2zig version` reports 0.4.7 and
`fail2zig status` shows healthy storage before you continue.

## Before you upgrade

1. Stop the daemon and every other process that writes the state file.
2. Keep the current executable, the configuration, and a copy of the database
   together with its `-wal` and `-shm` files.
3. Check free space beside the state file. Each upgrade step copies the whole
   database to its backup and refuses to start without free space of twice the
   database size plus 32 MiB. The size is the file's allocated size, so a state
   file of 1 GiB needs 2 GiB plus 32 MiB free. The backups of earlier steps stay on
   disk, so a v0.4.8 or v0.4.7 state needs room for each copy in turn.
4. Check that no backup from an earlier upgrade is in the way. The daemon
   refuses to start if the backup file it is about to write already exists. Move
   an old backup aside only when it is not your only copy of earlier state.

## What the first start does

The first start of 0.4.10 upgrades the state in place and logs the result and the
backup path.

| Step            | Backup written first        | What it changes                                                         |
| --------------- | --------------------------- | ----------------------------------------------------------------------- |
| Schema 25 to 26 | `<state_file>.pre26-backup` | Ban origins, ignore-entry deadlines and timed configuration entries.    |
| Schema 26 to 28 | `<state_file>.pre27-backup` | The records that let a removed or disabled jail be cleaned up in steps. |
| Schema 28 to 29 | `<state_file>.pre29-backup` | Drops the table that kept one row for every log line read, and adds the counters the state-file page budget reads. |

A v0.4.9 state takes only the last step, a v0.4.8 state the last two. Each step
commits in one transaction, so an interrupted upgrade leaves the state at the
schema it last committed.

The schema 29 step takes longer as the file grows. It copies, verifies and hashes
the whole database under the temporary name `<state_file>.pre29-backup.partial`,
then drops the per-line table in the schema transaction, renames the copy to
`<state_file>.pre29-backup` and commits. The pages the dropped table held are free
for reuse as soon as the step commits; the file does not shrink. A start killed
while the copy is being made deletes the temporary file at the next start and
copies again, with no action from you.

A state that 0.4.9 filled to its limit upgrades the same way. The daemon starts,
keeps the installed bans enforced, and admits new work again once the state file
has room below its capacity.

### If the start was killed between the rename and the commit

One short window needs you. If the daemon dies after the backup has its final name
and before the schema step commits, the state is still at schema 28 and
`<state_file>.pre29-backup` exists. Every later start refuses: the log says the
schema 29 migration was refused because that backup already exists, and the start
fails with `SchemaBackupExists`. The daemon never adopts a backup it did not just
write.

The backup is a complete, verified copy of the schema 28 state. Keep it, and give
the daemon room to write a new one:

1. Stop the service so the unit does not keep restarting it:
   `sudo systemctl stop fail2zig`.
2. Move the existing backup out of the way under a new name, for example
   `sudo mv /var/lib/fail2zig/state.bin.pre29-backup /var/lib/fail2zig/state.bin.pre29-backup.kept`.
   Do not delete it. If it stays on the same filesystem, the next start still needs
   free space of twice the database plus 32 MiB besides it; move it to another
   filesystem if there is not enough room.
3. Start the daemon: `sudo systemctl start fail2zig`. It copies the state again,
   writes a new `<state_file>.pre29-backup` and completes the step.
4. Check `fail2zig status` and `fail2zig jails` as below. When nothing else wrote
   the state between the kill and this start, both backups hold the same schema 28
   state; keep at least one until you no longer need to roll back.

Use your own `state_file` path in place of `/var/lib/fail2zig/state.bin`.

## Settings to review

Coming from v0.4.9:

- `bantime_increment_decay = 0` still means escalation memory is never reset by
  time. The memory for each jail and address is now capped at 65,536 rows per
  table, and at the cap the least recently written address without a live ban is
  forgotten, so a returning address can start again at the base `bantime`.
- `state_file_max_pages` and the `State file:` line now report SQLite's limit of
  278,528 pages, 16,384 above the capacity of 262,144 pages that new work is
  measured against. An alert that compares `fail2zig_state_file_pages` with
  262,144 should use `fail2zig_state_file_used_pages` instead.
- When the state file reaches its capacity, a manual `ban`, `ignore add` and a
  new `reload` are rejected with `StorageCapacity`, and sources show
  `waiting (StorageCapacity)`. Scripts that call these commands should treat that
  rejection as temporary.

Coming from v0.4.8, also review what 0.4.9 changed:

- `/api/bans` on the HTTP listener now returns 403. Monitoring that read it
  must use `fail2zig list` as an administrator.
- Members of the `fail2zig` group can no longer list bans, history or the
  firewall inventory through the socket. They keep aggregate status, statistics
  and the redacted configuration.
- `native_fd_ceiling` now defaults to 8192, so more than ten jails start under
  the shipped unit. A configuration that sets the key keeps its value.
- Above about twenty jails the default `native_memory_ceiling_mb` (512) refuses
  startup with `NativeMemoryAdmission`. Raise it for larger configurations.
- A custom `state_file` or `socket_path` directory under the shipped unit needs
  a unit override. The installer prints the override for your configuration and
  never edits the unit; see the
  [custom state directory procedure](../operations/installation.md#custom-state-directory-under-systemd).

Coming from v0.4.7, also review what 0.4.8 changed:

- `native_memory_ceiling_mb` defaults to 512. A configuration that sets 256
  explicitly must raise it or the daemon refuses with `NativeMemoryAdmission`.
- The state file limit was raised from 256 MiB; 0.4.10 measures new work against
  262,144 used pages (1 GiB). It never shrinks; freed pages are reused inside it.
- Rotation under `on_truncation = "restart"` no longer pauses the jail, and a
  missing log is reported as `missing (FileNotFound)`, not as a truncation.
  See the [log file lifecycle](log-lifecycle.md).
- `ignoreself` defaults to `true`: the host's own addresses join every jail's
  ignore list with source `self`. `ban` refuses a loopback, host or SSH-peer
  address unless `--force` is given.
- A healthy `systemctl stop` leaves installed rules in the kernel with their
  timeouts, and the next start reconciles them with durable state. A stop no
  longer unbans anyone. To stop with an empty table, run
  `sudo fail2zig firewall withdraw` first; `status` then reports
  `DEGRADED (FirewallWithdrawn)` until the next start.

## Check protection after starting

```bash
sudo fail2zig version
sudo fail2zig status --details
sudo fail2zig jails
sudo fail2zig list --details
sudo fail2zig firewall show
```

`version` reports the running daemon, which must read 0.4.10. `status` shows the
state file's allocated pages and, on the `Used pages:` line, the pages in use;
the tracking pool against its limits; each paused, waiting, broken or missing
source; and retained loss events. `jails` shows source health per jail and agrees
with `status` on protection; `missing (FileNotFound)` is a healthy state.
`list --details` shows each ban's origin and the log line that triggered it. A
retained firewall observation is not proof of current packet reachability; use a
controlled external check. See the
[administration reference](../reference/cli-fail2zig-client.md).

## Roll back

An older binary refuses a newer state with `UnsupportedSchema`, so rollback
restores the backup; swapping the executable alone does not work. After the
schema 29 step, the `.pre29-backup` is the only way back to 0.4.9.

1. Stop the daemon.
2. Restore the backup over the state file: `.pre29-backup` to return to v0.4.9,
   `.pre27-backup` to return to v0.4.8, `.pre26-backup` to return to v0.4.7.
3. Remove the upgraded database's `-wal` and `-shm` files.
4. Reinstall the binary that last wrote that state and start it.

Everything written after the backup is lost: bans, expiries, history and source
positions. If you copied the backup into place instead of moving it, move the
backup file aside before the next upgrade, because an existing backup file
refuses the start.
