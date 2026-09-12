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

The accepted age policy preserves recognized past event timestamps in startup, live and
replay processing. An event older than the configured retry window commits an obsolete
disposition and source progress without becoming a fresh attempt or ban intent. Processing
delay does not rejuvenate its timestamp. Report backlog/obsolete counts so operators can
see reduced timely coverage. The staged normalizer now applies this correction; active
daemon integration remains unfinished. Native missing/future-time component behavior is
specified below.

The native_time component now represents signed integer microseconds and parses bounded
complete timestamp fields without a worker or float conversion. It requires missing year/
timezone context explicitly and reports future time separately. Its integer age check and
file/SQLite fixture tests do not replace the daemon's current timestamp behavior.

Missing/malformed timestamp policy is approved: timestamped sources commit an explicit
rejected outcome and counter with the cursor, without fresh detection evidence, then process
later valid records. Receipt time requires an explicitly undated source policy. The native
policy and staged normalizer implement this distinction; rejected records cannot enter
retained matching context. SourceProcessor now checkpoints counters, publishes independent
health after commit and exposes bounded notices. Staged sessions wire monotonic warning
emission, but full session/daemon execution remains unqualified. Year/timezone policies
remain open; missing configuration context is not an ordinary rejected log record.

The approved native future tolerance is 60 seconds inclusive, measured against the
occurrence's original receipt time. Within tolerance, retain the original timestamp and
use receipt time for detection; beyond it, reject with a distinct counter and bounded
warning. Retries retain the comparison boundary and cannot extend the detection window or
eventually admit an excessive future date. Native policy implements and component-tests
this behavior. Native pipeline opt-in now durably records receipt before preparation and
recovers it across failed outcomes/restart using explicit schema-3 storage. Coordinator/journal
receipt ownership, original/effective historical timestamps and replacing the staged
float normalizer's future branch remain integration work; backward wall-clock recovery
is a separate unresolved condition.

The native source processor/file session now implements those time and decoder consumers
with a bounded native checkpoint and explicit schema-4 typed time rows. Approved opt-in
syslog inference now uses the durable receipt with an explicit fixed UTC offset, selects
the nearest valid adjacent/current local year and rejects equal-distance ambiguity. Schema 5
is separately activated to persist the inferred year, including future rejections. A future
rejection cannot trigger selection of another year. No host timezone or DST is inferred.
Session receipt and processing clocks are sampled in order, preserving
the original receipt while applying event age at actual preparation time. Source configuration,
journal transport and daemon activation remain incomplete.

The native journal component now connects complete journalctl records to durable receipts,
native time outcomes and exact cursor checkpoints. Fresh tail/empty-time baselines commit
explicitly, and saved anchors/pending occurrences must verify before resume. This is still
component integration; the active daemon, public configuration and native detector consumers
have not switched over. Operator IPC and the full recovery/scheduling coordinator remain open.

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
the current record store. The dynamic loader is now replaced by the pinned static amalgamation;
Python checkpoint payload replacement and active daemon integration remain outstanding.
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
