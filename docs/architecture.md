# Runtime architecture

fail2zig 0.4.4 is one native executable containing the daemon, administration commands, rule
testing and migration tools. Zig application code statically embeds pinned upstream SQLite C.
Runtime installation does not require Python, a SQLite service, the SQLite CLI or a shared SQLite
library.

Selected live release qualification passed on Debian 13 x86_64 using the stripped
`x86_64-linux-musl` executable before the version-only change from the unpublished 0.3.1
candidate to 0.4.0. Rebuilt artifacts passed cross-build and native/emulated command checks. ARM64, ARMv7
hard float and both MIPS32r2 soft-float byte orders have cross-build/static-inspection/QEMU
smoke tiers, with no real-hardware or kernel-enforcement claim. Journal input uses journald and `journalctl`; iptables
and ipset enforcement use those host tools with fixed argument arrays; nftables enforcement talks
directly to the kernel through netlink. The 0.4.1 SSH-default repair passed isolated log-only journal-origin and restart checks
on Debian 13 and Ubuntu 24.04, covering split-session and single-executable SSH layouts.
These checks do not qualify Ubuntu kernel enforcement or a full platform release.

## Processing and durable state

File and journal records enter bounded native ingestion. A complete record receives a durable
receipt before processing. Detection, policy, retry state, source progress and enforcement intent
are committed consistently; in-memory publication and source acknowledgement follow the commit.
Original event and receipt times survive retry and restart.

SQLite stores source checkpoints, retry state, policy state, active ownership, enforcement intent
and confirmed history. One daemon owns the state lock. Incompatible state, corrupt state, missing
required consumers or unsafe semantic generations cause startup refusal rather than a silent reset.
Storage failure pauses affected ingestion while retained protection and administrative health
remain observable.

## Sources and detection

File sources preserve exact saved positions and source identity across restart and rotation.
Operators select an explicit timestamp contract appropriate to the log format. Lost continuity or
unsafe replay becomes visible intervention rather than an invented position.

The v0.4.3 malformed-file repair replaces invalid encoding sequences and embedded
NUL/CR with U+FFFD for matching, while preserving the original raw hash, byte range,
receipt and source generation. Damaged address tokens cannot supply a ban target;
an intact address can still match when another field contains replacement text.
Decoded output remains bounded: overflow rejects the complete record instead of
matching a truncated prefix. Disposition, diagnostic counters and cursor movement
commit together, and encoding warnings are rate-limited without printing raw payloads.
This behavior is not present in releases through v0.4.2.

The repair reads legacy processor checkpoints; older binaries cannot restore its
extended checkpoints. Later state uses SQLite schema 24, upgraded from schema 23 in
resumable steps after a coherent pre-upgrade backup. Reverting the binary alone is not a
supported rollback; restore the matching backup with the previous binary.

A file truncated in place below its saved position is refused rather than re-read. The
offline `repair-source` command acknowledges one such truncation under the state lock,
records a replayable token outcome and changes only that source's position.

Journal sources validate local machine identity, root UID, transport and an exact list of
root-owned executable paths. Built-in SSH jails can discover a bounded standard profile when
`journal_executables` is omitted; discovery verifies path components and resolves trusted
symlinks. Explicit profiles keep their configured spelling/order and custom journal rules
require one. A client-controlled journal tag alone cannot authorize a detection.
Effective paths and journal queries remain part of persistent source identity: changing a
profile or SSH layout can require intervention, never a silent reset of protection history.

Built-in and bounded custom rules produce typed subjects rather than executable command strings.
Ignore policy, DNS results, recurrence and finite, permanent or escalating bans are native state.
Attacker-controlled log content is data and is never evaluated as code or shell syntax.

Native duration strings normalize to seconds before policy construction. The four supported
fields are `bantime`, `findtime`, `bantime_increment_max_bantime` and
`bantime_increment_jitter`; integers remain seconds. Fixed month/year constants and checked
arithmetic preserve the existing field bounds and default/jail inheritance. This changes no
persisted schema or CLI duration syntax.

## Enforcement

A policy decision is not reported as installed protection. fail2zig persists typed effect intent,
dispatches it outside the record transaction and then inspects the selected backend. Confirmation
requires exact owned-kernel readback. Uncertain outcomes remain visible and are reconciled without
claiming success.

Multiple jails can own the same protected subject. Removing or expiring one owner does not release
another owner's protection. Scope includes the subject and address family plus protocol, ports,
interface and enforcement target where the backend supports them.

The enforcement view follows storage incrementally: a commit that changes one scope is
folded into the view in place, and only an unattributed change (for example a migration
activation) rebuilds it from storage. The kernel is read back as one coherent
observation per step: on nftables a single netlink pass whose coherence is the kernel's
own interrupted-dump flag (an interrupted dump is retried), on iptables and ipset the
two-pass agreement over tool output. The most recent readback is the inventory; a
readback that started after the daemon's last own mutation and shows every desired
entry confirms the set, and no second readback is taken to prove it. A confirmed view
is re-read on a 5 s cadence or as soon as a ban deadline passes. That cadence is not a
detection guarantee: external removal of a rule is noticed at the next complete
readback, which pass work, retries and storage pauses can delay, and status reports
the age of the last readback so the actual latency is visible.

A new ban is dispatched from the inventory (no separate pre-read on nftables; the tool
transports keep theirs because their mutations are several invocations), marked in
memory as sent, and settled by the readback that returns with the mutation. A mutation
whose acknowledgment times out is settled by the next readback that postdates the send;
a kernel-rejected nftables batch is a non-mutation retried from a fresh readback.
Transient readback and mutation signals (an interrupted dump, a two-pass disagreement,
a timeout) retry with bounded backoff and never pause ingestion. A scoped rule group
whose parts are missing, duplicated or dated inconsistently (an interrupted
multi-command mutation) is repaired by re-dispatch, bounded to rules that validate as
the daemon's own; anything else remains foreign. The durable intent is written at
ingest; each ban's outcome is one commit that records the dispatch time, the
observation, the confirmation and the action-target settlement together.

Expiry follows the entry's kernel representation. nftables set elements and ipset
entries carry the deadline as a kernel timeout, so the daemon prepares up to eight due
entries per commit and settles up to eight per commit from a readback that shows them
absent. Scoped rules on every backend and iptables host rules carry no timeout and are
deleted explicitly. Live dispatches keep at least every other selection; expiry work is
served at parity while its backlog exceeds the live backlog, otherwise once per four
live dispatches, and continuously when nothing live is pending; overdue removals
precede bookkeeping. Retry-subject retirement and spent-scope pruning each handle up to
eight subjects or scopes per commit. A quiet worker (confirmed view, caught-up history,
no maintenance progress, no new commits) publishes owners and runs maintenance once per
second; sources are still polled every 100 ms, and a source with waiting records is
drained up to four records per wake. Maintenance runs on a 250 ms cadence under load.
With `synchronous=FULL` every commit is an `fsync`, which bounds sustained throughput
by the storage's sync latency; no throughput figure is promised.

A healthy stop withdraws the daemon's realized rules and keeps owners and deadlines for the next
start. When storage is unhealthy at stop, durable intent cannot be confirmed, so the daemon neither
writes nor dispatches: installed rules stay in place, the log reports how many, and the next start
reconciles them. Restart reinstalls live bans with their original deadlines before READY.

Firewall effects are limited to the daemon's current network namespace. The daemon does not enter
another namespace, and custom namespace selectors or service overrides that move it between
namespaces remain unsupported.

## Administration and privileges

The local Unix socket uses peer credentials for authorization. Read-only monitoring remains
available to the configured service/monitor group; mutations require root or the daemon UID. Status distinguishes
policy decisions, installed protection, uncertainty and degraded dependencies.

Status separates what the daemon knows from what is installed. `active_bans` is what
the last complete readback showed; `knowledge` is `fresh` within the verification
cadence plus one wake, `stale` after it, and `none` before the first readback or under
a fatal backend cause, with `confirmed_at_us` and `knowledge_age_ms` alongside. A stale
readback keeps the last count and reports protection as `degraded`; no knowledge
reports the count as absent and protection as `unknown`, never as zero.
`pending_bans`, `overdue_removals`, `overdue_bookkeeping` and their oldest ages describe
work not yet confirmed; a served backlog does not degrade protection. Expiry is split by
what the kernel holds: an expired rule the last readback still shows installed
(`overdue_removals`, deletion-class entries) keeps blocking traffic and degrades
protection with cause `EffectRemovalOverdue`; an element the kernel already removed and
the daemon has not yet booked (`overdue_bookkeeping`) does not. Effect-changing
transactions still invalidate the expiry authority before commit and the next readback
restores it. Stalled workers, clock uncertainty and a fatal backend cause degrade
protection. Jail `source_healthy` describes the source independently of storage and
firewall health; it does not by itself establish enforcement.

The shipped systemd unit uses the non-login `fail2zig` user and group. It restricts filesystem
access, syscalls and capabilities while retaining the access required to read configured logs, own SQLite state and manage the selected firewall.
All-log-only configurations can run without firewall capability when started appropriately.
The service retains `CAP_NET_ADMIN` for enforcement and `CAP_DAC_READ_SEARCH` for protected
logs/journal reads. `CAP_NET_RAW` supports the iptables ipset extension and grants raw
IPv4/IPv6 socket authority; the unit excludes AF_PACKET. HTTP still shares these capabilities;
dedicated UID operation is not a separate monitoring process or privilege broker. Configuration and executable files remain
administrator-owned; the native state parent/database must belong to the daemon UID.

The installer refuses ownership changes with an active writer, and limits automatic transitions
to the default SQLite directory, database and WAL/SHM siblings. Custom state paths require explicit
operator handling and matching systemd write access. It does not start or restart services.

## Resource boundaries

Records, decoded text, queues, retry subjects, live source incarnations, database pages and
administrative frames have explicit limits. Critical receipts, active owners and unresolved effect
intent are not evicted to satisfy a ceiling. Exhaustion pauses new admission or reports degraded
health instead of silently losing protection.

Spent enforcement records are removed in bounded background steps: a banned scope qualifies once
its owners no longer hold a lease, the kernel entry is confirmed absent and no firewall work or
action outcome is unsettled. Confirmed history keeps its own copy of the scope and ban decision, so
it stays readable after the scope is removed and ages out on its own retention. Obsolete owner
revisions, intents and observations of a still-active scope are reclaimed the same way; each intent
keeps at most four observations. Active and permanent bans are kept.

Admission reserves room for every live ban to expire, be released or be confirmed, so terminal
transitions never meet a row limit. A request that would break that reserve, or that would
exceed a jail's retry-subject capacity (4,096 divided by the number of enabled jails), is
refused as retryable backpressure: the source keeps its receipt, nothing is evicted, the
jail reports its source unhealthy with the cause (`ReserveBackpressure` or
`RetryCapacity`) in `status` and `jails`, and ingestion resumes once expiry or retirement
frees space. Retry subjects whose lease and retry window have both lapsed are retired one
per maintenance turn regardless of load. At 58,982 confirmed
events, consumed history older than every consumer's checkpoint may be pruned before its retention
age, with a warning; history still pinned by a consumer or unsettled work is never removed.
Retry decision details are reclaimed separately once no current owner, retained
confirmed event or unsettled action needs them. Cleanup is bounded by rows and
stored bytes; the 65,536-row admission limit still applies to retained details.

The default configuration admits at most 64 enabled jails, eight file incarnations per jail and
4,096 live retry subjects across enabled jails. Native reservation checks cover configured memory
and descriptor budgets. SQLite uses a separate bounded heap and page limit; required history and
recovery anchors remain pinned.

The CLI inspection path uses an optional observation cache owned by the
coordinator and borrowed by the effect manager. Existing complete readbacks publish
at most 256 pointer-free entries; failures retain the prior sample and update attempt
metadata. A separate cache mutex bounds copying to one page/sample. IPC serializes
the copied page after unlocking and performs no kernel inspection. Cursors bind a
process and observation identity, page limit and a 60-second pagination lifetime.
Complete readback, sample truncation, inventory membership and durable confirmation
remain separate facts.

A fixed `exact_v1` structure proof is attached only after two complete matching
inspector passes establish the owned installation. The passes may differ only by
set elements whose kernel timeout could have elapsed between them; any other
difference is a change and leaves enforcement uncertain. Cache metadata carries that
proof with the observation; failures retain it and absent observations clear it.
The query projects only the validated scaffold (tables, chains, sets, attachment
and base rules), plus a chain/set placement for each sampled entry. Dynamic scope
rules retain their canonical protocol/port/network projection and are subject to
the existing sample/page bounds. The JSON additions are nullable `structure` and
per-item `placement`; no proof means no inferred structure. Backend-native set
key types are `ipv4_addr`/`ipv6_addr` for nftables and `hash:ip` for ipset, whose
family is reported separately. These are normalized observations, not general
host ruleset enumeration or assertions about packet reachability.

Cache and transient-page costs use actual Zig type sizes in resource admission.
Optional cache admission or allocation failure makes inspection unavailable while
preserving the baseline enforcement resource contract. It never evicts durable state
or changes readiness. This path adds no persistence schema or telemetry history.

## Migration boundary

Supported fail2ban migration uses `migrate inspect`, `snapshot`, `plan`, `validate`, `cutover`,
`status` and `rollback`. Unsupported enabled protection and unsafe continuity block activation
before mutation. The workflow does not point fail2zig at foreign live state or promise exact
compatibility with fail2ban's private Python APIs and extension behavior.

See [command migration](operations/command-migration.md) for the operator workflow and
[migration continuity](operations/migration-continuity.md) for the state that can and cannot be
carried across cutover.
