# Source foundations and native replacement obligations

Updated 2026-09-11. These are current component findings and retained invariants. New sessions
are not selected by the active daemon and still use Python/dynamic libraries. The selected
architecture replaces those dependencies while keeping useful source capability and recovery.
See [component status](p2-components.md) and [runtime contract](runtime-contract.md).

## Occurrences, commit and retry

source_record.zig distinguishes data from a baseline checkpoint and carries source/occurrence
identity, cursor, raw hash, optional path and authoritative journal microseconds. Borrowed
record lifetime and checkpoint acknowledgment are separate from merely discovering a position.
A source cursor is acknowledged only after disposition, relevant state and intent commit.

record_pipeline stages processing, record_store checks revisions/commits, then the processor
publishes. Current schema 2 supports named shared checkpoints alongside jail state: an expected
revision on a read is still a transaction dependency; null payload does not waive validation.
Revision zero depends on absence. Stale shared state invalidates readiness; retry reloads it.
Committed occurrence replay does not rewrite shared state. Preserve rollback/dedup/CAS tests.

Replace helper serialization/state with native versioned checkpoints. Preserve immutable
source/configuration generation bindings and reject stale prepared work. Embedded SQLite
retains the durable boundary. No Python ABI or exact timestamp bit identity is required to
retain correct source time/occurrence behavior.

## Files

Preserve per-file incarnation identity, discovery, hardlink alias handling, bounded fair polling,
explicit startup/live/head/tail semantics, partial records, rotation and truncation detection.
A candidate position must not be mistaken for a durable cursor. Permission, delayed-file,
size/capacity and read errors must remain visible source health, with defined retry behavior.

Framing must return complete supported character/code-unit boundaries and raw byte offsets,
including BOM and incremental decoding. Malformed/unsupported encodings need an explicit
outcome, not guessed cursor advancement. Keep valid partial tails for later data. State
restart/tail baseline reset behavior explicitly and reject unsupported checkpoint versions.

Document limitations: polling/stat observations cannot detect every truncate-and-regrow event
that occurs entirely between observations. Do not market an absolute no-loss guarantee beyond
the source/filesystem contract. Actual source-to-native-decision/restart tests remain required.

## Journal

Keep meaningful selectors, occurrence/cursor identity, field/priority/time extraction,
rotation/reopen, cursor-not-found and permissions/error handling. Extraction/read/format/size
errors are distinct from a callback failing to commit. Identical journal text does not identify
the same occurrence. Preserve journal microseconds and explicit timezone/receipt provenance.

The current component Reader dynamically opens libsystemd; the old daemon path starts
journalctl. Neither satisfies the target standalone transport contract. Prove the selected
transport across intended systems, formats/compression, cursor semantics and recovery before
replacing it. Keep journal-only deployments in scope; file input is not a substitute. Any
additional embedded library needs an explicit review, not an inferred SQLite exemption.

## Reviewed reference differences

Original file input consisting of Ċ followed by CR/LF, b/newline and a partial tail exposes
misaligned reference offsets in little-endian Unicode. In UTF-16 LE the reference position
is 5 after the first record, while the candidate preserves 6 then reads b to position 10.
For UTF-32 LE the reference leaves 9, while the candidate preserves 12 then reaches 20.
The reference misses the second valid record. Retain the candidate's code-unit alignment.

The original source comparison has 22 agreements and these two reviewed differences across
24 cases. Separate generic framing records 30 agreements/34 cases across 14 codecs; its
additional two differences concern BOM re-encoding offset calculation. For BOM-prefixed
first/newline/second/newline/partial, the candidate ends the second record at byte 28 for
UTF-16 and 56 for UTF-32; reference offsets 30/60 consume bytes from the partial record.
These are explicit correctness differences, not identical-result passes.

Preserve original receipts and separately test native expected outcomes. Wider encodings,
source lifecycle, daemon coordination and real standalone targets remain qualification work.
No old Python-backed comparison or static build proves the replacement ingestion path.
