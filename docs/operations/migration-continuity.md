# Migration continuity boundary

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
