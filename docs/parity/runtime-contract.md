# Runtime compatibility and continuity contract

Status: P0 architecture decision for D1–D5/D8; implementation and certification are
P1–P7 work. This is a versioned design, not a claim that the current daemon implements
these interfaces. Reference: fail2ban 1.1.1,
`f60978618a101427b06924fc932b44350fec2b63`. See the
[action contract](action-contract.md) for observed dispatch behavior and section 6
below for the source-state capture and cutover guarantees.

## 1. Process and dependency boundary

The native daemon owns configuration generations, ingestion order, durable state,
policy decisions and operator IPC. A separate unprivileged, pinned CPython worker owns
Python-compatible decoding/date/filter expressions, multiline correlation and trusted
policy expressions for the compatibility profile. It never receives firewall privileges.
The initial development semantics profile is CPython 3.13.5; distribution profiles pin
actual packages independently. Interpreter upgrades invalidate that profile's comparison
receipt until rerun. Vendor or separately package the precisely pinned upstream helper
subset with its license notices and corresponding source; package/license review is a
release gate. A hash of an entire module closure, interpreter and options identifies a
worker semantics implementation. Do not select a fast path by filter filename alone.

A native enforcement broker accepts typed, allowlisted scope operations. Administrator
shell/Python actions execute in a distinct trusted extension service, never through an
unprivileged matcher message interpreted as a command. Activating that service is an
explicit effective-configuration decision. Arbitrary expressions and extensions execute
only at trusted activation/runtime, never during migration inspection or planning.
No promise of a dependency-free full compatibility profile follows from a static daemon.

One logical mailbox per jail orders source processing and action scheduling. Different
jails may progress independently. An action instance receives serialized lifecycle calls;
a blocked instance cannot reorder later calls around it. Cross-jail operations acquire
scope locks in canonical key order. Admin mutations and reloads enter the same ordered
journal as source decisions, with an immutable configuration generation. Parallel native
matching is permitted only when it preserves this committed ordering and correlation.

## 2. Worker protocol v1

Use an inherited private Unix socket pair, not a public command endpoint. Validate peer
credentials and supervisor-issued worker identity. A four-byte unsigned big-endian length
precedes UTF-8 JSON. Maximum frame size is 1 MiB in the initial profile. Reject duplicate
JSON keys, non-finite numbers, invalid UTF-8, unknown message versions, unknown required
capabilities and oversized frames before dispatch. Optional fields require explicit
negotiated capabilities; silently ignoring an operation field is prohibited. No pickle,
Python object references, code snippets, secret callbacks or filesystem paths supplied
by a log record cross the action dispatch boundary.

Every frame contains `wire_version=1`, `kind`, `request_id`, `daemon_epoch`,
`worker_epoch`, `config_generation`, `jail_id`, `sequence`, `capabilities` and `payload`.
Epochs are fresh unpredictable IDs, not wall-clock values. Sequence is a decimal unsigned
integer string; timestamps and large counters also avoid JSON number precision loss.
Handshake binds effective config hash, dependency profile hash and resource limits.
Operations are `hello`, `configure`, `record`, `decision`, `action`, `result`, `checkpoint`,
`restore`, `barrier`, `cancel`, `health` and `close`. The action payload uses the separate
action contract. The native daemon rejects jail/config/epoch mismatches and duplicate or
out-of-order sequence claims before state mutation. Request IDs permit delivery tracking;
they do not establish exactly-once external effects.

Outcomes are `complete`, `no_match`, `invalid_input`, `unsupported`, `resource_limit`,
`deadline`, `cancelled` and `internal_error`. Each carries structured stage/reason and
bounded diagnostics. A deadline, invalid input or dead worker never becomes `no_match`.
An incomplete decision does not advance the committed source position. Quarantine the
record with its stable identity, expose degraded protection and require the profile's
explicit retry/quarantine policy. Repeated failure cannot silently discard evidence.

Initial matcher profile: one active call per jail worker, 1 s wall deadline, 1 s per-call CPU soft
budget, 2 s per-call CPU hard budget, 256 MiB address-space limit and 64 KiB combined diagnostic
output per call. The prototype does not establish these budgets' production sufficiency.
Limit inputs are configurable, validated and fingerprinted; legitimate configurations
exceeding these defaults require a larger certified profile, not altered semantics.
Measure CPU against the call's process-CPU baseline; a stateful worker's lifetime CPU limit
is not a fresh per-call budget. The supervisor owns these timers and the lifetime ceiling.
Input frames can refer to a private, hashed chunk stream for larger retained data;
chunked total size also has an explicit profile bound. Private input bytes remain available
until their decision and source position commit, or until a quarantined record is explicitly
resolved; file rotation cannot erase the only recovery copy. No truncation is implicit.

Action limits preserve effective imported action timeout. A timeout of unlimited/unknown
requires an explicitly selected trusted profile; substituting the matcher timeout is
incorrect. Queues use durable backpressure, with an initial 10,000 pending operations per
jail and a configured disk quota. At quota, pause ingestion and report degradation; do
not advance the source cursor or discard the oldest intent. Output truncation is labeled
and independent of action success. Secrets are excluded from diagnostic payloads.

The Linux supervisor places each invocation and descendants in a dedicated cgroup v2
subtree before exec, denies migration out of that subtree, and uses a monotonic timer.
On cancellation/deadline: mark result pending reconciliation, send TERM, allow a configured
250 ms grace, kill the subtree, reap descendants and record cleanup completion. Process
group kill alone does not contain descendants that create new sessions. Without delegated
cgroup containment, the profile cannot claim complete process-tree cancellation; block
that profile rather than describe best-effort cleanup as complete. The
extension cannot write the cgroup hierarchy or use host namespace administration to escape
it; a trusted action requiring those powers needs a different explicitly uncontained
profile, which cannot satisfy the complete-cleanup gate. Stopping a worker cannot undo a
provider request or rule already installed.

## 3. Python extension and jail-context ABI v1

Reuse the pinned Python `ActionBase`, `CallingMap` and `ActionInfo` semantics inside the
trusted service. Each jail has one process-local adapter object graph shared by its action
instances, retaining object identity and ordered mutation where the reference does.
Do not reconstruct a fresh fake jail for every call. The native daemon remains the owner
of committed state; the adapter mirrors one explicit sequence boundary. Nested callbacks
use typed synchronous RPC with a parent request ID and a bounded call depth. A callback
requiring the currently held transaction to complete fails with an explicit reentrancy
error; never deadlock or invent a result. Compatibility for such a callback remains open.

| ABI family | Selected implementation direction | Required acceptance |
|---|---|---|
| `Action(jail, name, **Init)` and lifecycle methods | Pinned loader and base classes, original assets and keyword values | Loading, constructor errors, reload and lifecycle order fixtures |
| `ActionInfo` mapping, lazy values and copy/reset | Pinned mapping code backed by immutable ticket/history snapshots | Getter order, caching, nested mutation and failure fixtures |
| `jail.name`, `database`, `filter`, `actions`, `idle`, `status` | Stable adapter objects; explicit typed reads/mutations into the owner | Each accessed public member's return type, exceptions and mutation ordering |
| Database history queries used by action info | Snapshot query service at dispatch boundary; exact retention and cross-jail scope | History/DNS-derived values independently compared |
| `putFailTicket`, `getFailTicket`, ban-manager changes | Transactional callback operations with reference ordering | Manual attempts, callbacks, observer and queue traces |
| Private attributes, monkeypatching, identity/type checks, external imports | Original assets retained; compatibility evaluation at trusted activation | Extension-specific fixtures or a blocking unsupported ABI diagnostic |

This selects an ABI strategy, not universal compatibility with arbitrary Python programs.
An extension can inspect private thread/database objects or depend on process globals,
class identity, timing and unrestricted filesystem/network access. A remote adapter cannot
generally preserve all such observations. Static inspection cannot prove their absence.
The full migration manifest retains each extension and requires measured compatibility;
unsupported access remains an applicable blocking gap, never an excluded requirement.
A future profile may co-locate more of the pinned object graph to satisfy a proven need,
but retaining the whole upstream daemon as the permanent decision engine is not the
selected architecture. This feasibility risk must be resolved before claiming arbitrary
extension compatibility at P4/P7, or the architecture/claim must be revisited explicitly.

Privileges are per action instance's declared activation profile: uid/gid, capabilities,
namespace, root directory, working directory, environment allowlist, readable/writable
paths, network destinations and dependency/asset hashes. Secret material uses inherited
restricted descriptors or private credential files. A trusted legacy action requiring
root or unrestricted network receives that explicit profile and a clear activation
record; do not imply it is sandboxed like the matcher. There is no generic privileged
RPC to evaluate Python or a shell string supplied by the matcher. Broker native methods
validate generation, ownership and exact scope independently of extension code.

## 4. Identity and scope v1

Failure identity is tagged `address`, `network` or `raw`. Address bytes use canonical
family and packed bytes; network additionally carries an explicit prefix including /0.
IPv4-mapped IPv6 remains IPv6 unless the selected reference profile proves a conversion.
Raw identifiers preserve exact decoded code points plus codec/source provenance: no
case-folding, trimming, DNS resolution or Unicode normalization. Enforcement subject is
separate and may be absent for a raw identity or be a provider resource identifier.
Do not equate the reference display strings for a network /0 and a host /32.

A native scope key serializes version, backend/provider account/resource, subject tag,
family, network prefix, direction, namespace identity, table, chain/hook, interface,
verdict and an ordered protocol-to-port-set map. Ports are validated 0–65535 numeric
closed intervals, sorted and merged when adjacent; protocol numbers are validated 0–255.
Protocol/port pairs remain paired: TCP 22 plus UDP 53 does not become both ports for both
protocols. An absent selector is distinct from explicit all ports. Empty, absent, wildcard
and any backend default remain distinct until effective semantics resolve them.

Service names resolve against a snapshotted protocol-specific services database. Store
original spelling, resolved values and resolver hash. Ambiguous/unavailable resolution
blocks activation; runtime host `/etc/services` changes cannot broaden scope silently.
Chain/interface names are exact backend strings. Network namespace uses a durable
configured namespace identity, with boot/inode handles recorded as observations rather
than assumed portable identities. Custom selector expressions that cannot be represented
remain hashed, typed compatibility selectors; no speculative native normalization.

Owners are `(jail_id, action_instance_id, owner_id)`. Sharing is permitted only for equal
canonical scope and an action-specific sharing contract. Deleting one owner cannot remove
a realization another owner still desires. Notification/provider side effects are not
shareable merely because enforcement addresses coincide. Request identity, failure
identity, scope identity, realization identity and owner identity are separate keys.

## 5. Durable state and time v1

Choose a versioned native SQLite state store for the full profile, with WAL and
`synchronous=FULL`, foreign keys and one ordered writer. This adds an explicit full-profile
dependency. A future alternative backend must satisfy the same transactional/durability
contract. The current daemon's persistence format requires a transactional migration,
backup and rollback receipt; never reinterpret an old global-IP set as known scoped owners.
Legacy global entries need configuration-backed scope reconstruction or a blocker.

| Entity | Required data |
|---|---|
| `metadata` | Schema/semantics/profile versions, config generation, daemon epoch, journal sequence |
| `sources` | Source identity/incarnation, mode, codec, timestamp origin, last-date context, committed resume token |
| `records` | Unique source occurrence key, arrival time, raw/effective timestamp, raw-data hash/private retained bytes, decode result, disposition |
| `filter_state` | Per jail/source/filter generation correlation lines, caches, captures, date state and replay boundary |
| `tickets` | Tagged failure ID, first/last/effective time, retry/attempt counts, retained matches, captures, history-weighting context |
| `scheduled_events` | Ordered observer/timer events, due wall time, callback kind/data, originating sequence and generation |
| `ban_history` | Retained events and latest policy records separately; counts, durations and retention provenance |
| `owners` / `scopes` | Exact scope, owner, desired generation, absolute expiry or permanent duration, legacy ticket status |
| `operations` | Request/parent IDs, sequence, action instance, intent, dispatch state, result and observations separately |
| `handover` | Plan/source fingerprints, barrier epoch, component acknowledgments, manifest hash and ownership phase |

Wall timestamps preserve the exact finite binary64 value used by the pinned Python
reference, encoded as IEEE-754 binary64 hexadecimal bits, with raw textual timestamp and
origin kept separately. Do not convert through integer seconds or decimal milliseconds.
Reject non-finite values. A source with higher-resolution authoritative timestamps retains
that raw integer/string as well; reference normalization decides its effective value.
Monotonic deadlines are process-local and are recomputed after restart, never imported
as another host's clock. Durations are tagged `finite` with a signed checked numeric value,
`permanent`, or `legacy_unknown`; a negative finite value is invalid. Preserve legacy -2
history as unknown until source configuration/context resolves it, not as permanent.

Store the actual reference-equivalent retry estimate and retained matches, not only a
fixed event ring. SYS-029 demonstrates that reconstructing this estimate from the last
findtime window can change threshold decisions. Cleanup, history weighting, out-of-order
updates and scheduler boundaries require P5 differential traces. Startup/replay/live modes,
60-second truncation boundary, future clamp and last-date reuse remain separate operations.

For files, occurrence identity includes source incarnation plus byte range, decoder state
and record hash. For journald, use an actual available cursor; identical timestamps or
identical record contents never establish duplicate identity. If only a persisted time is
available, replay requires a verified occurrence disambiguation plan. File rotation/truncation
creates explicit incarnations; a same-path file is not necessarily the same stream.

One transaction atomically persists record disposition, filter/ticket deltas, decisions,
new action intents and committed source position. Commit before acknowledging consumption.
Before commit, restart replays the record; after commit, its occurrence key prevents duplicate
ticket mutation. Retained correlation state must commit at the same boundary. Worker checkpoint
state is a versioned data-only snapshot with size limits and checksums, never a pickle.

Dispatch intent is durable before an external action starts. A separate transaction records
its returned outcome and observed effect. A crash between effect and receipt produces
`uncertain`, even if the reference-facing ticket is banned. Restart reconciles the latest
desired generation; stale receipts remain audit records and cannot overwrite newer intent.
Observable idempotent effects may converge by scoped readback; unobservable effects require
an action-specific receipt or explicit operator resolution. Exactly-once arbitrary actions
are not promised. Clock jumps trigger expiry re-evaluation without rewriting original expiry.

## 6. Achievable full-state handover and its admission boundary

Select a version-pinned **cooperative source adapter** for full live-state migration. Its
export ABI is data-only and includes the actual transient object state, not a guess from
SQLite. The adapter must run inside a source instance equipped with synchronization hooks
at all writer boundaries: source callbacks, filter state, failure manager, jail ticket queue,
action dispatcher, observer/timer queue and admin mutation handling. Each acknowledges the
same barrier epoch only after its active operation has finished or yielded a serializable
continuation. New admin mutations are held behind the barrier. Pending external actions
must settle or be exported as explicitly uncertain with an action-specific transfer plan.

Use a small, maintained patch/integration for the exact supported fail2ban version to add
these hooks. Do not use debugger injection, copy a live Python heap, depend on the GIL as a
cross-component transaction, or claim the existing `idle` flag proves quiescence. The pinned
`Jail.idle` setter merely sets filter/actions flags (`server/jail.py:175–184`); the jail
queue and observer queue are distinct (`server/jail.py:205–220`,
`server/observer.py:158–173`). Individual manager locks are not a global snapshot barrier.

The exported schema contains effective config/runtime overrides, source resume/last-date
state, multiline and correlation caches, complete failure tickets and estimated retries,
active ban-manager tickets, counters/history, timer/observer events, queued decisions,
action epochs/context, owner/scope observations and external-operation uncertainty. Each
component supplies its sequence and schema fingerprint. Unknown Python extension state
needs an extension snapshot/restore contract or a blocker. Object addresses are not export
identities. After all acknowledgments, obtain the consistent read-only database snapshot
while the source is still fenced, and bind both exports to one manifest digest.

Target validation restores state offline, compares normalized values and stages independently
owned protection. It records `prepared` durably, verifies required effects, then commits a
single ownership lease generation to `target_active`. Source ingress remains fenced until
that receipt is durable. Resume target from the exact source occurrence boundary. Before
ownership commit, rollback releases the source barrier with its original state unchanged;
after commit, recovery uses the target's current journal and the migration rollback contract.
Lease expiry alone never activates both writers. Lost coordination requires explicit recovery
from the durable ownership receipt. Source stop hooks run only after checking they cannot
remove target-owned resources. External provider transfers remain backend-specific.

**Existing uninstrumented running installations are a real admission blocker.** Installing
the adapter with a restart can discard precisely the transient state being preserved. P7
must either demonstrate safe, supported live installation with acknowledged hooks and
unchanged behavior, or establish that the source already has the adapter before the state
being migrated is created. A normal restart, fixed-window replay, waiting one findtime or
an unacknowledged idle command is not a full-state migration workaround. Inspect/plan remains
available, but full-state apply stays blocked for that source until this is resolved.
This does not remove full migration from the goal or certify current-source coverage.

This protocol is implementable for an instrumented reference and gives P7 a concrete proof
obligation; universal live installation and arbitrary extension state are unresolved
feasibility risks. Their cost is a maintained reference-version adapter, runtime integration
fixtures, packaging, process coordination and backend-specific rollback certification.
P0 can settle the design and expose these risks; only P7 evidence can remove the blockers.

## 7. Prototype and phase acceptance

Run the original synthetic contract probe:

```sh
python3 -I -B tests/parity/runtime_contract_probe.py \
  --output /tmp/p0-runtime-contract-probe.json
```

It tests data-boundary rejection, scope/owner separation, exact finite time round trips,
duration tags, same-timestamp source occurrences, SQLite commit/rollback ordering, stale
result rejection, uncertain effects and handover acknowledgments. It runs no upstream
code, daemon, action, network request or shell command. It is a model/schema feasibility
probe, not the production IPC encoder, scheduler, database implementation or source adapter.

| Phase | Gate evidence required beyond this design |
|---|---|
| P1 | Reusable traces, schema validation, negative/malformed frames, deterministic clocks and fault injection |
| P2/P3 | Effective config closure, worker/filter/correlation restoration, actual process limits and ordering |
| P4 | Native broker, real descendant cleanup, action ABI fixtures, privilege/dependency packaging and outcome reconciliation |
| P5 | Full ticket/scheduler/date/history comparisons and actual crash/replay database recovery |
| P6 | Typed runtime/admin mutations, legacy adapter errors and ordered barrier interaction |
| P7 | Live source adapter, transient export/restore, concurrent writers, WAL/permissions/interruption, provider transfer and current-state rollback |

Blocking later acceptance is preferable to a false full-parity claim. No open applicable
requirement becomes not-applicable because this design has a difficult boundary.
