# Native runtime, time and durable-state contract

Target architecture, reconciled 2026-09-11; not a claim about released 0.3.0 or completed
0.3.1-dev behavior. The former CPython/full-profile contract is superseded. See
[present component state](p2-components.md) and [dependency contract](profile-contract.md).

## Processing and acknowledgment

A bounded native pipeline prepares a source record, decodes it, determines event time,
evaluates exclusions and detection, updates policy, and commits the resulting state.
Track source identity/occurrence, configuration generation and record identity separately.
A file offset alone or identical journal text is not globally unique. Configuration changes
must not cause an old prepared record to publish state into a new generation accidentally.

Commit deduplication, relevant matcher/policy/shared state, source cursor and generated action
intents atomically. Publish the new in-memory revision and acknowledge consumption only after
commit succeeds. Failed transactions preserve the last acknowledged revision/cursor. Recover
by replaying committed state and reconciling intent, not by assuming a worker response equals
persistence. Bound pending records, decoded bytes, correlation state, queues and retries;
exhaustion produces visible backpressure/health outcomes, never silent loss of live protection.

## Native time and policy

Specify accepted timestamp formats/timezones, year rollover, missing/malformed timestamps,
event-versus-receipt time, replay age, future skew and late/out-of-order handling. Use checked
native representations and explicit units. Wall-clock timestamps support logs/history and
absolute expiry; monotonic scheduling handles elapsed runtime intervals. State how restart
and clock steps translate deadlines. Do not preserve Python float/truthiness/truncation
quirks solely to reproduce an oracle.

The retry policy must define window endpoints, duplicate suppression, out-of-order insertion,
maximum supported counts and behavior when capacity is reached. Separate count correctness
from retained example text. Never allow an older event to move a last-seen time backward
unless the documented policy explicitly requires that different meaning. Preserve the five
SYS-029 observations for classification; the current native configuration rejects maxretry
above 128, so a component test at 129 is not a demonstrated valid-config bypass.

Define finite/permanent bans, overflow rejection, expiry boundary, escalation factor/cap/order,
and recurrence from confirmed native ban events. Restore/replay must not create a new ban
history event or send a fresh notification by accident. Manual unban and history reset are
separate operator intentions. Native duration/rule grammars do not execute arbitrary Python
expressions and must report unsupported foreign formulas during import.

## Embedded SQLite and recovery

Use upstream SQLite linked statically into the executable; no installed database service,
libsqlite3 shared object or SQLite CLI. Retain useful transaction/schema/revision logic from
the current record store. Replace dynamically loaded calls and Python checkpoint payloads.
Pin/version/disclose the embedded component; the application remains Zig. Storage-engine
selection is settled. No custom append-log database or experimental SQLite port is planned.

Design a versioned schema for source occurrences/cursors, native checkpoints and shared
cache revisions, policy/ownership, action intents/outcomes, required ban history and optional
observability data. One serialized writer owns mutations; read APIs obtain coherent snapshots
without blocking protection indefinitely. Define transaction limits and checkpoint/maintenance
budgets. Confirm actual build options, journal/sync mode and filesystem failure assumptions
with crash/reopen testing. Current WAL/FULL settings are useful foundations, not blanket
qualification of the future embedded build.

A database commit and kernel mutation cannot be one atomic transaction. Persist intent before
attempting an effect; record a verified outcome afterward. A crash in between leaves an
uncertain outcome requiring inspection/reconciliation. Never report an external operation as
successful solely because a command or transport returned success.

Handle disk-full, I/O errors, corrupt/truncated data, lock contention, revision conflicts,
unsupported schema and interrupted upgrade explicitly. Preserve usable prior state or enter a
visible degraded mode with a documented recovery path. Never silently reset active protection.
Test upgrading existing binary snapshots and candidate SQLite schemas, backing up/restoring
at a defined boundary. Remove dual authority only after the migration/recovery path passes.

## Retention and read access

Protection-critical ownership, expiry, pending intent and required policy history are not
subject to arbitrary dashboard cleanup. Detailed events have configurable age/size budgets.
Long-lived aggregates can support charts at a different retention/resolution; decide defaults
from actual workload and disk budgets. Log volume under attack is not assumed tiny.

Expose bounded paginated application queries with explicit time ranges and schema versions.
Existing live status/bans/metrics/events remain useful. A possible optional 0.4.0 dashboard is
not yet specified or implemented and does not justify a generic SQL or database-admin API.

## Acceptance

Native unit/component tests must cover semantics and resource bounds. Actual daemon tests
must cover source-to-decision acknowledgment, crashes before/after commit and kernel effect,
replay/dedup, generation changes, retention, expiry, corruption and disk exhaustion. Execute
real storage/source paths on qualified target classes; builds with skipped/rejected paths do
not count. Preserve old reference receipts separately and rerun useful cases against Zig.
