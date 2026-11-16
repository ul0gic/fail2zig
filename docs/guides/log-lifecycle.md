---
title: 'Log file lifecycle'
description: 'How a file source records its position and what happens on rotation, truncation, replacement and a missing log, with the on_truncation policy and repair-source.'
sidebar_position: 4
category: Getting Started
audience: operator
last_verified: 2026-10-22
---

A file source has one job: read every record once and lose none it has
acknowledged. This page describes how fail2zig keeps that promise through the
ordinary life of a log file, what each view shows, and the one decision the
operator makes per jail. The [fail2zig(1)](../man/fail2zig.1) and
[fail2zig.toml(5)](../man/fail2zig.toml.5) pages are the exact reference.

## Reading position

The daemon records a checkpoint per log file: the inode and the committed
offset. A restart resumes at that checkpoint. A record is acknowledged only after
its receipt is committed, so nothing is counted twice and nothing acknowledged is
lost. Records written after the committed offset and then removed from the file
before they were read were never read; the policies below record that loss, they
do not recover those records.

## Rotation

A rotated-out file that was read to its end is retired when the writer moves on,
and the current file resumes at its committed offset. A rotated file that still
exists in the directory is followed, never skipped. A rotated file removed while
it still held unread bytes is a continuity loss with reason
`rotated_unread_removed`, recorded as an event and shown by `status`. Under
`on_truncation = "restart"` the jail no longer pauses on rotation.

## Truncation in place

Same inode, size below the committed offset: reason `truncated`. Under `refuse`,
the default, the source pauses, the daemon keeps running and every other jail
keeps enforcing. `status` shows a `Paused:` block with the jail, path and cause,
then the exact `repair-source` command. The `Repair:` line reads `stop fail2zig,
then run:`, but stopping is not required: the command also works while the daemon
is running. Under
`restart` the source resumes at offset 0 of the file and records the event.

## Replacement

The writer recreated the file, so a different file sits at the path and the
previous one exists nowhere in its directory. PortSentry does this at every start.
Reason `replaced`; the same policy split as truncation. Under `restart` the
source resumes at offset 0 of the replacement.

## Missing file

A log that is absent at start, or deleted while the daemon runs, is reported by
`jails` as `missing (FileNotFound)`. The source stays healthy, protection is not
degraded, one warning goes to the daemon log, and reading resumes when a file
appears at the path. A deleted file that was read to its end is released after
five quiet minutes with nothing lost; one info line records it, and the jail
stays `missing` until a file comes back. `status` shows a `Missing:` row with
the jail and path (JSON `missing_sources`), and the
`fail2zig_jail_source_state` metric reports value `2`. A missing log is not an
error.

## What the views show

`jails` reports SOURCE HEALTH per jail:

| Value             | Meaning                                                                        |
| ----------------- | ------------------------------------------------------------------------------ |
| `ok`              | Reading at the committed offset.                                               |
| `missing (cause)` | No file at the path; healthy, resumes when one appears. JSON `source_missing`. |
| `waiting (cause)` | Waiting for room, for example `RetryCapacity` when the tracking pool is full.  |
| `paused (cause)`  | A continuity loss under `refuse`; `repair-source` acknowledges it.             |
| `broken (cause)`  | The source failed; the cause in parentheses names why.                         |

`status` adds `Sources: N unhealthy`, one `Paused:` block per paused source with
its `Repair:` command, a `Waiting:` or `Broken:` row with the cause for a jail whose
source is unhealthy but not paused, a `Missing:` row per configured path with no file, and a
`Loss events:` row for every source that resumed
under `restart`. `--details` lists each retained event, newest first, up to 256
per source. In JSON, `paused_sources` counts the paused sources and `sources[]`
carries, per source, `state`, `cause`, `inode`, `committed_offset`,
`observed_size`, `repair`, `loss_events` and `last_loss`. Use
`status --output json`; there is no `--json` flag.

## `on_truncation` rules

The key is per jail only and is rejected in `[defaults]`, so accepting loss is
chosen for each source and never inherited. It applies to file sources only and
covers every `logpath` of the jail. `"refuse"` is the default; `"restart"`
accepts the loss, resumes and records a continuity-loss event. The diagnostics
are `InvalidTruncationPolicy`, `TruncationPolicyNotFileSource` and
`TruncationPolicyNotAllowedInDefaults`. A change is restart-only; `reload`
reports `restart_required` naming the key. Neither value recovers lost records.

```toml
[jails.portsentry]
filter = "portsentry"
source = "file"
timestamp = "iso8601"
logpath = ["/var/log/portsentry.log"]
on_truncation = "restart"
```

## `repair-source`

`repair-source` acknowledges one loss for one configured file source. The online
form runs through the daemon's socket while it is running, with no jail's rules
withdrawn; it is a mutation and writes an audit line. The offline form runs on a
stopped daemon's state when the socket is absent, and is the path for a daemon
that cannot start. Both print the same text and use the same exit status.

The token identifies the repair. The daemon proposes one of the form
`ack-<inode>-<committed_offset>-<detected_unix_seconds>`, so the printed command
can be copied as it is. Repeating the same command replays the committed outcome.
The newest 256 outcomes are kept; an older token stays reserved and is refused,
and a different token after a successful repair is refused because the source is
no longer truncated. The repair refuses a source with nothing to acknowledge, a
pending receipt, or a checkpoint changed since observation. Exit 0 on success or
replay, 1 on refusal, 2 on usage errors. Through a running daemon it can also exit
3 when the daemon cannot serve the repair, and 5 when the connection fails after
the request was sent; after a 5 the outcome is unknown, so repeat the same command.

```bash
sudo fail2zig repair-source --jail portsentry \
  --source /var/log/portsentry.log --token r1 --acknowledge-truncation
```

Use the command `status` prints; it carries the proposed token.
