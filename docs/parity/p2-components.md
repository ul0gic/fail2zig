# Current P2 components and native transformation

Updated 2026-09-11. This describes the preserved development code, not an approved Python
architecture, release announcement or passed native gate. Published 0.3.0 and unpublished
0.3.1-dev remain distinct. No implementation was changed by the plan reconciliation.

## Actual integration boundary

New effective configuration preparation is used by the import command and validation.
The default daemon still uses its existing compiled-filter/state/lifecycle path. An explicit
[native ingestion preview](native-runtime.md), added 2026-09-12, now selects native file/journal
sessions, schema-9 retry decisions and a storage worker in the actual daemon. Its admitted
policy is log-only; full N2 integration remains open. The legacy SourceProcessor/session
foundations remain separately. The earlier component table below records their transformation
work; the preview page gives current activation limits. The ordinary test registration includes
dependency-bearing foundations. Passing a static build does not prove their runtime support.

| Current component | Useful work to preserve | Required transformation |
|---|---|---|
| engine/config/fail2ban.zig and migration.zig | Layer/include/interpolation/parameter/provenance preparation and actual import admission | Keep supported foreign semantics at the boundary; native schema and unsupported reporting stay explicit. |
| engine/config/native.zig | Protected compatibility manifest and pending-activation validation | Preserve guard behavior while native capabilities replace only proven supported projections. |
| durable_file_source.zig, file_session.zig | Source identity, discovery/modes, hardlinks/rotation, acknowledged cursors and bounded polling | Replace helper processing/checkpoints and integrate native daemon path. |
| systemd_reader.zig, journal_session.zig, journal_policy.zig | Selectors, fields/cursors, retry/reopen and health distinctions | Preserve useful invariants through the retained OS journalctl transport; qualify durable integration. The staged dynamic reader is not selected and no embedded reader is required. |
| record_store.zig and record_pipeline.zig | Embedded SQLite, dedup/revisions, transaction atomicity and opt-in durable receipt capture/recovery with explicit schema-3 activation | Replace Python payloads; connect pending-source recovery, native decisions and daemon coordination. |
| source_processor.zig and compat_worker.zig | Staged prepare/commit/publish boundary and useful resource/error findings | Remove CPython worker transport; do not mechanically port its private ABI. |
| native_source_processor.zig, native_file_session.zig, native_time_record.zig | Actual native decoder/time consumer, fixed source checkpoint, schema-4 integer time rows and pending-source validation | Connect source configuration, native journalctl/detector consumers and daemon coordination; retire legacy adapters at cutover. |
| event_time.zig, line_context.zig, source_record.zig | Time provenance, bounded context and source occurrence identity | Revalidate under native policy; remove incidental Python equality behavior. |
| native_journal_transport.zig, native_journal_session.zig | Bounded OS journalctl reads, explicit baseline, exact cursor/pending recovery and native receipt/time commits | Connect public source configuration, trusted detector consumers, scheduling and daemon recovery; qualify live OS/service behavior. |
| year_inference.zig | Opt-in receipt-bound syslog inference with explicit fixed offset, ambiguous-year rejection and durable selected-year provenance | Connect public configuration; settle named-zone/DST support before admitting those sources. |
| native_time.zig, source_text.zig, source_time_policy.zig, FileSource.setNativeFraming | Integer timestamps, strict codecs, bound framing and approved rejection/undated/future admission with staged counters/health | Connect native processor/checkpoints to durable receipt ownership; settle named-timezone/clock recovery before daemon activation. |
| engine/compat Python files | Useful date/codec/ignore/framing behavior and tests | Rewrite retained functionality in Zig; retire protocol/private ActionInfo-only machinery. |

## Configuration findings

Preparation resolves base conf, ordered conf fragments, base local and local fragments with
before/after includes and supported parameter contexts. It preserves original bytes, paths,
assignments, origins and effective observations. File/asset identity and symlink changes feed
the generation. Successful preparation is not evidence that every filter/action is runnable.

The current native TOML projection includes a schema-versioned protected compatibility_manifest
with prepared admission state. Disabled groups and unsupported assets remain visible. Output
may contain secrets and uses a restrictive temporary-file publication path; normal diagnostics
must not dump it. A supplied custom filter named sshd is not silently replaced with the builtin.
Unsupported scope/actions/settings stay pending and fail activation validation.

Keep reviewed INI/include and checked-duration fixes. Later native rule/time/source/action
support must replace guards only with actual acceptance. Retained foreign option names in a
manifest do not imply the daemon uses foreign runtime objects or supports every option.

## Transactions and source sessions

A prepared record cannot publish state before durable commit. Current schema 2 atomically
stores occurrence identity, cursor, jail checkpoint, optional shared checkpoints and intents;
shared expected revisions are validated even on cached reads. Replaying a committed occurrence
does not rewrite state. Failed commits and stale revisions prevent publication. Preserve these
invariants while changing the processor.

The record store now links the pinned SQLite 3.53.4 amalgamation statically; extension loading
is disabled. Transaction/replay/shared-revision/upgrade and killed-writer recovery tests execute
on native Linux and static musl. Native file-to-store pipeline tests also pass on both.
This removes the store's dynamic loader and static-musl rejection, not the remaining Python
source processors. The staged journal reader still loads libsystemd and rejects static musl.
Active daemon journalctl is the accepted OS integration; existing firewall transports are
retained. Native checkpoint schemas, daemon coordination and durable journalctl ingestion remain work.

The staged store also distinguishes SQLite capacity, read-only, I/O, corruption, allocation,
value-limit, interruption, access and lock errors. Numeric causes survive cleanup; a failed
rollback blocks reads and writes until close/reopen. Component checks cover capacity failure,
locking, read-only rejection, malformed input, retry and injected rollback failure. These do
not establish total disk/WAL limits, real device failure recovery or daemon health behavior.
Restored values now enforce the corresponding write-size limits before caller copying or
callback delivery, with a SQLite row/value limit as an additional bound. These store checks
also execute under QEMU for the four other shipped architectures; emulation is not device
certification. Separate heap/work experiments remain test-only feasibility, not a new daemon
memory setting or an end-to-end processing deadline.

The staged pipeline now supports a shared storage admission gate with detached health,
bounded retry scheduling and ordered recovery generations. A failed store operation
blocks its participating owners; source decoder failures remain local. Restore stages
state, rechecks its durable revision and publishes only after validation. File recovery
can verify retained descriptors without resetting a lost position. Native and static-musl
component tests cover these paths. The gate is not yet connected to daemon IPC, a disk
worker or actual firewall reconciliation/expiry, and does not replace binary persistence.

The staged event-time normalizer also preserves valid past timestamps across processing
modes and excludes out-of-window records from fresh-attempt eligibility. Its policy version
participates in source configuration/framing hashes, so prior-policy snapshots/cursors fail
validation. Native file/SQLite fixtures cover aging during commit failure and reopen. This
does not replace the helper decoder, floating-point interface or remaining timestamp policy,
and the active daemon still uses processing time for its existing detection path.

## Recorded verification, not new acceptance

The retained final P2 receipt records 1,026 suite passes/nine skips and later 82/82 focused
local and Debian lab runtime tests. It identifies exact artifacts and limits. Original
configuration regressions SYS-026/027 now agree without changing the oracle; all five SYS-029
ticket observations remain for native-policy review. Those historical counts are separate
from the new focused embedded-storage checks described above.

Preserve independently reviewed Unicode source-boundary improvements: reference agreement is
not required when it would reproduce data loss. [Source details](source-runtime.md) explain
the evidence. Stock preparation, source comparisons and model controls are scoped component
results, not detection catalog coverage, real enforcement, migration or platform certification.

The [native contracts](README.md), [harness transition](harness.md) and
[delivery contract](profile-contract.md) define subsequent work. Historical P/G gates and
Python command receipts remain evidence, not the active implementation schedule or tooling goal.
