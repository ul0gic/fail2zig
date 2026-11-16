# Migration continuity boundary

## Upgrading fail2zig state

The filename `state.bin` does not identify its format. Keep these three cases distinct:

| Existing state | Supported path |
|---|---|
| Released fail2zig v0.3.0 binary state (including its format v4) | Unsupported. No automatic converter exists; a fresh native database does not carry this state forward. Do not install or roll back to a pre-v0.4.0 release. |
| Current native fail2zig SQLite state | Reopen the same compatible database after an offline ownership transition to the service UID. Preserve the database and any WAL/SHM siblings as one coherent set. |
| fail2ban schema-4 SQLite state | Use the supported inspect/snapshot/plan/validate/cutover workflow. It is foreign input, never the native daemon database. |

For an existing **native SQLite** installation using `/var/lib/fail2zig/state.bin`:

1. Stop fail2zig and every other state writer. Record the executable/configuration and preserve
   a coherent offline backup of the database and any WAL/SHM siblings. Keep all writers stopped
   throughout installation; a process check alone cannot prevent a later writer from starting.
2. Run the installer. It creates the non-login `fail2zig` account, preserves operator config,
   checks the configured `state_file` and its parent and refuses an active writer. Only that
   parent directory, the state file and its `-wal` and `-shm` siblings receive automatic state
   ownership changes.
   It neither converts database contents nor resets original finite expiry/history.
3. Review and validate configuration, then explicitly start fail2zig. Check `status`, `list`
   and `history` for the expected protection and continuity. The installer never starts or
   restarts services. Keep rollback backups until the new installation has been checked.

The installer accepts a custom `state_file` and applies its checks to that path, but it does
not edit the unit. Follow the
[custom state directory procedure](installation.md#custom-state-directory-under-systemd)
for the stopped SQLite backup/copy, exact ownership and narrow systemd drop-in.
The native database and its dedicated real parent must belong to the service UID;
changing TOML or proving shell writability does not change the unit's filesystem
namespace. Clearing the inherited `StateDirectory` prevents systemd recreating an
unused default directory without deleting existing rollback state.

For **released v0.3.0 binary state**, installation deliberately refuses to reinterpret the file
as SQLite. Pre-v0.4.0 releases are unsupported and no longer distributed; do not install or
roll back to them. Plan an explicit protection transition. A fresh native database loses saved
bans, counters/history and source positions;
the daemon does not adopt arbitrary legacy firewall rules as native owners. Review and record
old protection, remove only verified old-owned effects during the planned cutover and verify
the new daemon's protection independently. Do not run both authorities against the same state
or assume source continuity. If this reset/gap is unacceptable, defer cutover until an acceptable
migration path is available; the fail2ban converter does not provide one for this binary format.

## Persistence failures

Missing directories, wrong parent/database ownership, permissions, read-only mounts and service
filesystem restrictions can prevent saves or startup. Check the actual configured path, its
owner and mount, the effective service UID and systemd write restrictions before diagnosing a
host. An old state/cursor save warning alone does not establish which of these occurred.

Native startup refuses unusable required persistence before healthy admission or enforcement.
A runtime storage failure pauses affected ingestion and reports degraded health while retaining
protection. Restore the original state and access under the same service identity, then inspect
`status` and the reported recovery cause; operator intervention may require a controlled restart
after repair. Never delete state, reset checkpoints or make it world-writable to suppress an
error. Recovery must re-establish ownership and source continuity before healthy admission.

## Supported fail2ban continuity

`fail2zig migrate` evaluates source continuity from three inputs only: the plan
document, the `logs` table of the captured fail2ban snapshot, and the live
filesystem. Evaluation is read-only and bounded (first line up to 64 KiB, a
64-byte prefix fingerprint per file). It never starts the daemon.

## What is not transferable

fail2ban keeps the following only in process memory. They are never written to
its SQLite database, so no migration can read them:

- pending records that a filter has read but not yet matched or discarded,
- in-window failure counters (`findtime` accumulation per address),
- multiline correlation state.

The boundary output lists these under `not_transferable`. Failures already
counted but not yet banned at cutover restart from zero in fail2zig.

fail2ban's log positions are not carried over either. Cutover imports bans and
ban history; it writes no source position into the native state. The continuity
decisions below decide whether cutover may proceed and how its outcome is
labelled. They do not set where the daemon starts reading.

## Where the daemon starts reading after cutover

The migrated state holds no position for any source, so every source starts as a
new one:

- A file source in a jail with a timestamp format reads its current file from
  offset 0. A line older than the jail's `findtime` is read and does not count. A
  newer line counts, including a line fail2ban already counted before cutover.
  A file source in a jail with `timestamp = "undated"` starts at the end of its
  current file and counts only lines written after it starts.
- A journal source starts at the time its session starts and reads nothing
  written before it. The plan's `replay_window_s` is not applied.

From then on the daemon's own committed source checkpoint is the only record of
what has been read: a record, its receipt and the source position commit in one
transaction, and a restart resumes after the last committed record. The daemon
keeps no separate table of lines already seen, so nothing suppresses a line that
fail2ban counted and fail2zig reads again.

## Per-file decisions

For every selected file-backed group and each of its log paths:

| Condition | `lossless` | `reset_replay` |
|---|---|---|
| `logs` row present, first-line digest matches, `lastfilepos` ≤ size | `resume_at_offset` | `resume_at_offset` |
| file grew past `lastfilepos` | `resume_at_offset` | same |
| no `logs` row, digest unrecorded or unrecognised, first line without terminator | `blocked` | `replay_window`; without a window the plan records a `replay-window-missing` blocker |
| digest mismatch (rotation or replacement), offset beyond size (truncation) | `blocked` | `replay_window` |
| file missing or unreadable | `blocked` | `replay_window` |

The first-line digest is computed exactly as fail2ban 1.1.1 does: over the
first line including its terminator, only when a terminator is present. The
`logs.firstlinemd5` column name is historical: fail2ban 1.1.x running on
Python 3 records a 40-hex SHA-1 there (its MD5 availability probe fails on
every Python 3 and falls back to SHA-1), while Python 2 era rows carry a 32-hex
MD5. fail2zig selects the algorithm from the recorded length; any other length is
`first-line-digest-unrecognised` and treated like an unrecorded digest. For a
`resume_at_offset` file the boundary output shows the checkpoint it computed
(device, inode, offset, prefix length, prefix hash); cutover does not store it.

## Journal groups

fail2ban stores no journal cursor. fail2zig never derives one from a timestamp.

- `lossless`: every journal-backed selected group is `blocked`
  (`journal-cursor-unavailable`).
- `reset_replay` with a window: the group is `replay_window` and the outcome is
  `non_lossless`.
- `reset_replay` without a window: the planner records a `replay-window-missing` blocker.

## Replay window

With `reset_replay`, the boundary records `replay.from_us = cutover_us −
replay_window_s × 10⁶` and cutover prints that continuity is not lossless. The
window is a required acknowledgement in the plan; neither cutover nor the daemon
reads the journal or a file from `from_us`. Imported active bans are reconciled
by the ban importer; a line read again after cutover can still count toward a
new ban.

## Outcome

- `lossless`: every file decision is `resume_at_offset` and no journal group is selected.
- `non_lossless`: at least one `replay_window` or `start_at_tail` decision.
- `blocked`: at least one `blocked` decision; activation must not proceed.

For a non-lossless boundary, cutover prints:

```text
migrate cutover: continuity is not lossless; the accepted replay window applies (see docs/operations/migration-continuity.md)
```
