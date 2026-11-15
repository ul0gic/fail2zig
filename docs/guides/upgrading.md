---
title: 'Upgrading fail2zig'
description: 'Reach the current release from v0.4.8 or v0.4.7, with the state backups the first start writes, the settings to review, rollback and the checks to run afterwards.'
sidebar_position: 3
category: Getting Started
audience: operator
last_verified: 2026-11-15
---

This page covers what changes for an existing installation when you move to
0.4.9. The [installation guide](../operations/installation.md) has the install
steps, and the [release notes](../../RELEASE_NOTES.md) list every change.

## Which releases can upgrade

| State last written by | Path to 0.4.9                                                                 |
| --------------------- | ----------------------------------------------------------------------------- |
| v0.4.8 (schema 26)    | Install 0.4.9 and start it. One step, to schema 28.                           |
| v0.4.7 (schema 25)    | Install 0.4.9 and start it. Two steps in the same start: schema 26, then 28.  |
| v0.4.6 (schema 24)    | Install v0.4.7 first and start it once, then upgrade to 0.4.9.                |
| v0.4.5 or earlier     | No supported path. Start from a fresh state and plan the protection gap.      |
| v0.3.0 binary state   | No converter. The installer refuses to reinterpret it; start from fresh state. |

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
3. Check free space beside the state file: each upgrade step needs twice the
   database size plus 32 MiB for its backup.
4. Check that no backup from an earlier upgrade is in the way. The daemon
   refuses to start if the backup file it is about to write already exists. Move
   an old backup aside only when it is not your only copy of earlier state.

## What the first start does

The first start of 0.4.9 upgrades the state in place and logs the result and the
backup path.

| Step            | Backup written first        | What it adds                                                          |
| --------------- | --------------------------- | --------------------------------------------------------------------- |
| Schema 25 to 26 | `<state_file>.pre26-backup` | Ban origins, ignore-entry deadlines and timed configuration entries.  |
| Schema 26 to 28 | `<state_file>.pre27-backup` | The records that let a removed or disabled jail be cleaned up in steps. |

A v0.4.8 state takes only the second step. Each step commits in one transaction,
so an interrupted upgrade leaves the state at the schema it last committed. The
schema 28 step adds columns and tables only, so its time does not grow with the
state. The schema 26 step also rebuilds the bounded table of administrative
requests by copying it. In the schema 26 step every existing ban gets origin
`detection`, and saved detection generations are rekeyed once.

## Settings to review

Coming from v0.4.8:

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
- The state file may grow to 1 GiB (was 256 MiB). It never shrinks; freed pages
  are reused inside it. A file already past 1 GiB is refused at start.
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

`version` reports the running daemon, which must read 0.4.9. `status` shows the
state file size against the 1 GiB ceiling, the tracking pool against its limits,
each paused or missing source and retained loss events. `jails` shows source
health per jail; `missing (FileNotFound)` is a healthy state. `list --details`
shows each ban's origin and the log line that triggered it. A retained firewall
observation is not proof of current packet reachability; use a controlled
external check. See the
[administration reference](../reference/cli-fail2zig-client.md).

## Roll back

An older binary refuses a newer state with `UnsupportedSchema`, so rollback
restores the backup; swapping the executable alone does not work.

1. Stop the daemon.
2. Restore the backup over the state file: `.pre27-backup` to return to v0.4.8,
   `.pre26-backup` to return to v0.4.7.
3. Remove the upgraded database's `-wal` and `-shm` files.
4. Reinstall the binary that last wrote that state and start it.

Decisions made after the backup are lost. If you copied the backup into place
instead of moving it, move the backup file aside before the next upgrade, because
an existing backup file refuses the start.
