# Current P2 components and native transformation

Updated 2026-09-11. This describes the preserved development code, not an approved Python
architecture, release announcement or passed native gate. Published 0.3.0 and unpublished
0.3.1-dev remain distinct. No implementation was changed by the plan reconciliation.

## Actual integration boundary

New effective configuration preparation is used by the import command and validation.
The main daemon still uses its existing compiled-filter/state/lifecycle path. New file/journal
sessions, SourceProcessor and SQLite pipeline remain independently executable component
foundations; they are not general daemon ingestion. The ordinary test registration includes
dependency-bearing foundations. Passing a static build does not prove their runtime support.

| Current component | Useful work to preserve | Required transformation |
|---|---|---|
| engine/config/fail2ban.zig and migration.zig | Layer/include/interpolation/parameter/provenance preparation and actual import admission | Keep supported foreign semantics at the boundary; native schema and unsupported reporting stay explicit. |
| engine/config/native.zig | Protected compatibility manifest and pending-activation validation | Preserve guard behavior while native capabilities replace only proven supported projections. |
| durable_file_source.zig, file_session.zig | Source identity, discovery/modes, hardlinks/rotation, acknowledged cursors and bounded polling | Replace helper processing/checkpoints and integrate native daemon path. |
| systemd_reader.zig, journal_session.zig, journal_policy.zig | Selectors, fields/cursors, retry/reopen and health distinctions | Resolve standalone transport; dynamic libsystemd/musl rejection is not the final path. |
| record_store.zig and record_pipeline.zig | SQLite transactions, dedup, revisions, cursor/checkpoint/shared-state/intent atomicity | Statically embed upstream SQLite, replace Python payloads and integrate real native decisions. |
| source_processor.zig and compat_worker.zig | Staged prepare/commit/publish boundary and useful resource/error findings | Remove CPython worker transport; do not mechanically port its private ABI. |
| event_time.zig, line_context.zig, source_record.zig | Time provenance, bounded context and source occurrence identity | Revalidate under native policy; remove incidental Python equality behavior. |
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
invariants while changing the processor and embedding SQLite.

Current source sessions exercise real helper processes and dynamic SQLite. The journal reader
loads libsystemd; these new SQLite/journal paths reject some musl runtime modes. Active daemon
journalctl and legacy firewall command use also remain. Static linking, native checkpoint
schemas, actual daemon coordination and standalone journal transport remain work.

## Recorded verification, not new acceptance

The retained final P2 receipt records 1,026 suite passes/nine skips and later 82/82 focused
local and Debian lab runtime tests. It identifies exact artifacts and limits. Original
configuration regressions SYS-026/027 now agree without changing the oracle; all five SYS-029
ticket observations remain for native-policy review. No new runtime tests ran for this doc update.

Preserve independently reviewed Unicode source-boundary improvements: reference agreement is
not required when it would reproduce data loss. [Source details](source-runtime.md) explain
the evidence. Stock preparation, source comparisons and model controls are scoped component
results, not detection catalog coverage, real enforcement, migration or platform certification.

The [native contracts](README.md), [harness transition](harness.md) and
[delivery contract](profile-contract.md) define subsequent work. Historical P/G gates and
Python command receipts remain evidence, not the active implementation schedule or tooling goal.
