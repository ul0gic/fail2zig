# Migration continuity boundary

## Upgrading fail2zig state

The filename `state.bin` does not identify its format. Keep these three cases distinct:

| Existing state | 0.4.0 path |
|---|---|
| Released fail2zig v0.3.0 binary state (including its format v4) | No automatic converter. Preserve it for rollback; a fresh native database does not carry its state forward. |
| Current native fail2zig SQLite state | Reopen the same compatible database after an offline ownership transition to the service UID. Preserve the database and any WAL/SHM siblings as one coherent set. |
| fail2ban schema-4 SQLite state | Use the supported inspect/snapshot/plan/validate/cutover workflow. It is foreign input, never the native daemon database. |

For an existing **native SQLite** installation using `/var/lib/fail2zig/state.bin`:

1. Stop fail2zig and every other state writer. Record the executable/configuration and preserve
   a coherent offline backup of the database and any WAL/SHM siblings. Keep all writers stopped
   throughout installation; a process check alone cannot prevent a later writer from starting.
2. Run the installer. It creates the non-login `fail2zig` account, preserves operator config,
   checks the default parent/files and refuses an active writer. Only `/var/lib/fail2zig`,
   `state.bin`, `state.bin-wal` and `state.bin-shm` receive automatic state ownership changes.
   It neither converts database contents nor resets original finite expiry/history.
3. Review and validate configuration, then explicitly start fail2zig. Check `status`, `list`
   and `history` for the expected protection and continuity. The installer never starts or
   restarts services. Keep rollback backups until the new installation has been checked.

Custom `state_file` paths are refused by the automatic installer. Handle them manually with
all writers stopped: verify a dedicated real parent directory, regular single-link database
and existing WAL/SHM files; reject symlinks and unexpected owners. Change ownership of only those
exact objects to `fail2zig:<service-group>`, keep the parent non-group/world-writable and files
private, and grant that parent through a matching systemd `ReadWritePaths` override. Do not
recursively chown `/var`, a shared directory, log trees or arbitrary configuration paths.
The native database and its parent must belong to the UID that will run the daemon.

For **released v0.3.0 binary state**, installation deliberately refuses to reinterpret the file
as SQLite. Preserve the complete old installation for rollback and plan an explicit protection
transition. A fresh native database loses saved bans, counters/history and source positions;
the daemon does not adopt arbitrary legacy firewall rules as native owners. Review and record
old protection, remove only verified old-owned effects during the planned cutover and verify
the new daemon's protection independently. Do not run both authorities against the same state
or assume source continuity. If this reset/gap is unacceptable, retain 0.3.0 until an acceptable
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

The boundary output lists these under `not_transferable`. A migration that
reports `lossless` is lossless for the *log position* only; failures already
counted but not yet banned at cutover restart from zero in fail2zig.

## Per-file decisions

For every selected file-backed group and each of its log paths:

| Condition | `lossless` | `reset_replay` |
|---|---|---|
| `logs` row present, first-line digest matches, `lastfilepos` ≤ size | `resume_at_offset` | `resume_at_offset` |
| file grew past `lastfilepos` | `resume_at_offset` (unread tail is read on start) | same |
| no `logs` row, digest unrecorded or unrecognised, first line without terminator | `blocked` | `replay_window` (or `start_at_tail` without a window) |
| digest mismatch (rotation or replacement), offset beyond size (truncation) | `blocked` | `replay_window` / `start_at_tail` |
| file missing or unreadable | `blocked` | `replay_window` / `start_at_tail` |

The first-line digest is computed exactly as fail2ban 1.1.1 does: over the
first line including its terminator, only when a terminator is present. The
`logs.firstlinemd5` column name is historical: fail2ban 1.1.x running on
Python 3 records a 40-hex SHA-1 there (its MD5 availability probe fails on
every Python 3 and falls back to SHA-1), while Python 2 era rows carry a 32-hex
MD5. fail2zig selects the algorithm from the recorded length; any other length is
`first-line-digest-unrecognised` and treated like an unrecorded digest. A resumable
file yields a native checkpoint (device, inode, offset, prefix length, prefix
hash) that the daemon verifies again before reading.

## Journal groups

fail2ban stores no journal cursor. fail2zig never derives one from a timestamp.

- `lossless`: every journal-backed selected group is `blocked`
  (`journal-cursor-unavailable`).
- `reset_replay` with a window: the daemon tails the journal at cutover and
  replays the last `replay_window_s` seconds through `journalctl --since`.
- `reset_replay` without a window: tail only (`start_at_tail`).

## Replay window and duplicates

With `reset_replay`, `replay.from_us = cutover_us − replay_window_s × 10⁶`.
Lines in `[from_us, cutover_us]` are read again. A line fail2ban already
counted may therefore be counted again by fail2zig, and an address fail2ban
already banned may be re-banned; imported active bans are reconciled by the
ban importer, and the daemon's replay guards suppress exact duplicate records
within one source. This is why the outcome is reported as `non_lossless`.

## Outcome

- `lossless`: every file decision is `resume_at_offset` and no journal group is selected.
- `non_lossless`: at least one `replay_window` or `start_at_tail` decision.
- `blocked`: at least one `blocked` decision; activation must not proceed.

Exact operator wording for a non-lossless boundary: *"Continuity is not
lossless: log positions are reset for the listed sources and the last N seconds
are replayed; in-window failure counters and pending records are not carried
over."*
