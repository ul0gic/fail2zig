# Runtime architecture

fail2zig 0.4.8 is one native executable containing the daemon, administration commands, rule
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

File records are committed in groups. The records that one poll turn of one file source
yields, up to 64, are written in one write transaction (`BEGIN IMMEDIATE`, one savepoint
per record, one `COMMIT`) with one `fsync`. The batch is also bounded by the source's
workspace: about 24 records of the maximum 2,048-byte line, or 63 typical lines. Each
record still gets its receipt, replay guard and retry step inside that transaction, and
the source is acknowledged for those records only after the `COMMIT` returns, so a
`kill -9` at any point never loses or re-reads an acknowledged record. There is no
latency floor: a lone record commits in its own turn without waiting for company. A
refused record is rolled back to its own savepoint, alone; the records before it commit,
and its cause is shown as today. Journal sources keep one commit per record.
`synchronous=FULL` and the single storage worker are unchanged.

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
extended checkpoints. Later state uses SQLite schema 26, upgraded in one transaction from a
state last written by v0.4.7 (schema 25) after a coherent `.pre26-backup`; v0.4.7 is the
minimum supported upgrade source, and states last written by earlier releases upgrade
through v0.4.7 first. Reverting the binary alone is not a
supported rollback; restore the matching backup with the previous binary.

A file truncated in place below its saved position is refused rather than re-read. The
`repair-source` command acknowledges one such truncation, records a replayable token
outcome and changes only that source's position. It asks the running daemon over the
administration socket first; the daemon runs the repair inside its storage worker on the
open state, so the state lock is never contended and every jail's rules stay installed,
then resumes the paused source. When the socket is absent or refuses the connection, the
same repair runs offline under the state lock.

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

A jail's effective ignore list joins its configured `ignoreip`, its runtime entries and,
with `ignoreself` (on by default), the host's own addresses with source `self`. The self
list is every IPv4 and IPv6 address of every interface, loopback included, read with one
`NETLINK_ROUTE` `RTM_GETADDR` dump at start and inside every reload; it is never refreshed
on a timer and `/proc` is never read. When the dump fails, the daemon logs a warning and
uses an empty self list. The administrative client reads the same list with the same code
for its lockout guard, which refuses `ban` of loopback, a host address, the caller's SSH
peer or a network containing one unless `--force` is given. The guard is a convenience;
authorization stays the socket's peer-credential check.

Timed `banip` and `ignoreip` entries, and undated `ignoreip` entries that take
`ignoretime`, keep their first-applied time and deadline in `config_timed_entries`,
keyed by list, jail, canonical address and duration. A ban lease or ignore deadline is
always read from that row and never computed again from the current time, so a reload or
restart never restarts a period, and a changed duration has no row and starts a fresh
one. An entry removed from the file loses its row at the next apply. The daemon rebuilds a
jail's ignore list when its earliest deadline passes and deletes expired runtime entries
once a second; an expired configured entry stays listed as `expired`.

Native duration strings normalize to seconds before policy construction. The four supported
fields are `bantime`, `findtime`, `bantime_increment_max_bantime` and
`bantime_increment_jitter`; integers remain seconds. Fixed month/year constants and checked
arithmetic preserve the existing field bounds and default/jail inheritance. This changes no
persisted schema or CLI duration syntax.

## Enforcement

A policy decision is not reported as installed protection. fail2zig persists typed effect intent,
dispatches it outside the record transaction and confirms it from the backend. On nftables the
confirmation is the kernel's acknowledgement of the atomic batch; on ipset and iptables it is an
exact owned-kernel readback. Uncertain outcomes remain visible and are reconciled without
claiming success.

Multiple jails can own the same protected subject. Removing or expiring one owner does not release
another owner's protection. Scope includes the subject and address family plus protocol, ports,
interface and enforcement target where the backend supports them.

Within one jail, every live ban has exactly one origin, stored on its owner row, every
owner revision and every confirmed history event: `detection`, `manual` or `config`. A
`banip` entry takes over any existing ban of its address in its jail as a `config` ban,
permanent or ending at the entry's stored deadline. `ban` takes over a detection ban as
`manual`, extended to the requested duration. A detection on a `manual` or `config` ban is
receipted and counted and changes no owner. `ban` and `unban` of a `config` ban are
refused. With one origin per ban, an unban is never hidden behind a second, longer ban of
another origin. Each takeover is one owner revision and one history event. The origin is
state, not firewall structure: the kernel holds one set per address family, shared by every
jail. States upgraded
from v0.4.7 give every existing ban origin `detection`.

The enforcement view follows storage incrementally: a commit that changes up to 64 scopes
(one ingest frame) is folded into the view in place, and only an unattributed change (for
example a migration activation) rebuilds it from storage. On nftables the kernel inventory
is a shadow: the last complete readback, kept current by the acknowledgements of the
daemon's own batches, by the kernel's own change events (the daemon subscribes to the
nf_tables notification group and reads every element added or removed in its table), and
by the daemon's own expiry schedule, since the kernel removes expired elements silently.
The daemon's own echo events are recognised by the port id of the socket that sent the
batch and skipped. The whole table is read back as one audit every 60 s, and at once after
the event socket overflows, after a gap in the kernel's generation ids, after an event the
daemon cannot decode, and at admission, reload, jail retirement and withdrawal; an
interrupted dump is retried. On iptables and ipset the inventory is the two-pass agreement
over tool output, re-read on a 5 s cadence or as soon as a ban deadline passes. A foreign
removal of a live ban's element, for example after `nft flush set`, is seen in the event
stream and the ban is dispatched again within the next effect slice; a foreign element
added to the owned set is reported as an unowned entry. Status reports the age of the
last audit and whether the event stream is healthy, so the actual detection latency is
visible.

Idle cost was measured on `f2z-target` (Debian 13, one vCPU, 4 GiB, kernel
6.12.111+deb13-amd64, nftables backend) with 2,000 installed bans. Over a 5 minute window
of 301 one-second intervals the daemon used a mean of 2.61 % CPU, a median of 2.0 % and a
maximum of 6.0 %, and its journal child processes a further 1.36 % mean. A clean
`systemctl stop` at that size took 1 s and withdrew the rules in 32 batched turns. On the
same host with 65,536 installed bans, a cold restart (every element reinstalled) reached
readiness in 373 s and idled at 12 % of one core over 3 minutes, against 371 s and 21 %
before installs were confirmed by acknowledgement and drift by events; with 20,000 bans the
daemon spent 3.5 % of one core over 2 minutes, 2.1 s of it per audit. Ingest through one
file source went from 5 to 79 records per second with bans enforced as they were decided.
These are the figures measured on that host, not a guarantee for other hosts.

A new ban is dispatched from the inventory (no separate pre-read on nftables; the tool
transports keep theirs because their mutations are several invocations) and marked in
memory as sent. On nftables pending host bans are installed together, up to 64 in one
atomic batch, and settled in one commit from the kernel's acknowledgement of the batch
end, which the kernel sends only after the whole batch committed; no readback is taken to
prove an acknowledged install. On ipset and iptables pending host bans are installed
together, up to 1,024 in one dispatch, checked by the one readback that follows and
settled in one commit. A mutation whose acknowledgment times out is settled by the next
readback that postdates the send;
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
second; sources are still polled every 100 ms, and a source with waiting records gets up
to four poll turns per wake, each turn of a file source being one group commit. Maintenance runs on a 250 ms cadence under load.
With `synchronous=FULL` every commit is an `fsync`, so sustained throughput is bounded by
the storage's sync latency; group commit spreads one `fsync` over the records of a file
source's poll turn.

A stop leaves the daemon's realized rules in the kernel, where they keep their timeouts, and keeps
owners and deadlines; the log reports how many rules stayed. The next start reconciles what it
finds, so a restart with the rules present keeps protection throughout and only reinstalls what is
missing before READY. The stop-time history drain is bounded to two seconds; the next start resumes
it. Withdrawal is an explicit operator act: `fail2zig firewall withdraw` removes every realized rule
in batches with a readback after each, while the daemon runs and whatever the storage health, and
holds enforcement off in memory until the next start. Owners and deadlines stay, `status` reports
protection degraded with cause `FirewallWithdrawn`, reload does not lift the hold, and a restart
reinstalls live bans.

Firewall effects are limited to the daemon's current network namespace. The daemon does not enter
another namespace, and custom namespace selectors or service overrides that move it between
namespaces remain unsupported.

## Administration and privileges

The local Unix socket uses peer credentials for authorization. Read-only monitoring remains
available to the configured service/monitor group; mutations require root or the daemon UID. Status distinguishes
policy decisions, installed protection, uncertainty and degraded dependencies.

Every mutation request writes one `info` log line with scope `audit` once its outcome is
known, carrying the command, target, jail, the peer uid from the socket credentials and
the outcome. The durable record of a mutation remains its `admin_requests` row; the audit
line adds nothing the status output does not already show. With `log_format = "json"`
(restart-only, default `text`) every log line is one JSON object with `ts`, `level`,
`scope` and `msg`, plus the audit keys as fields.

A reload validates the whole proposed configuration first; any failure rejects it and
the running generation is untouched. It then applies policy transitions, ignore lists
(including `ignoreself`, `ignoretime` and duration changes, rebuilt with a freshly read
self list), escalation decay, `banip` lists and added jails, commits the generation, and
removes jails last, so a failed reload never has to recreate a removed jail. An added jail
is built by the same per-jail construction as at start. A removed jail's owners are
released in one transaction, one owner revision each; its retry admission, consumer
manifests, checkpoints and timed entries are deleted; its confirmed history and retired
rows are kept, so `history` still shows its bans. Its elements are then withdrawn from
the shared kernel sets, which stay in place, and the daemon logs
`native: jail=<name> removed: <n> bans lifted`. A start that finds state for a jail the
configuration no longer names retires it the same way before validating owners, instead
of refusing with `UnconfiguredStateOwner`.

Status separates what the daemon knows from what is installed. `active_bans` is what
the kernel inventory holds: on nftables the shadow kept by acknowledgements and events,
on the tool transports the last complete readback. `knowledge` is `fresh` while the last
audit is within the verification cadence plus one wake (60 s on nftables with events, 5 s
otherwise) and, on nftables, while the event stream is healthy; `stale` after an overflow
or a missed audit; and `none` before the first readback or under a fatal backend cause,
with `confirmed_at_us` and `knowledge_age_ms` alongside. Stale knowledge keeps the last
count and reports protection as `degraded`; no knowledge reports the count as absent and
protection as `unknown`, never as zero.
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
exceed the daemon-wide retry-subject capacity when no idle subject can be evicted, is
refused as retryable backpressure: the source keeps its receipt, the
jail reports its source unhealthy with the cause (`ReserveBackpressure` or
`RetryCapacity`) in `status` and `jails`, and ingestion resumes once expiry or retirement
frees space. Retry capacity is three bounds on the shared `retry_states` rows: at most 131,072
rows in total, at most 65,536 rows without a live ban (tracked subjects and bans whose lease
has expired), and at most 65,536 rows with a live ban. A new subject is refused once the row
total is reached, whether or not it would ban at once; an existing row is never refused by the
total. Rows leave through retirement or eviction, so a lapsed ban keeps counting as tracked
until it is retired or evicted. Retry subjects whose lease and retry window have both lapsed
are retired one per maintenance turn regardless of load.

When a new subject needs a tracked row and the tracked bound is reached, the commit that
admits it first evicts the tracked subject with the oldest last activity whose lease is
not live, across all jails (a lapsed ban awaiting retirement counts), moving its decision
rows to the retired tables as retirement does. A subject with a live ban is never evicted,
and the live-ban bound keeps its backpressure. Evictions are counted per jail since start
and logged at most once per jail per 60 s. Escalation decay is a runtime parameter of the
retry admission, never part of the stored policy or any generation: when a subject's last
ban ended more than `bantime_increment_decay` ago (default 30 days, `0` disables), reading
its escalation history deletes the summary and starts its count at zero. A permanent or
live ban never ends, so a count never decays during a ban. After `unban`, the subject's
failure window and ban-decision state are cleared so new failures count from zero; its
escalation summary is kept. At 235,929 confirmed
events, consumed history older than every consumer's checkpoint may be pruned before its retention
age, with a warning; history still pinned by a consumer or unsettled work is never removed.
Retry decision details are reclaimed separately once no current owner, retained
confirmed event or unsettled action needs them. Cleanup is bounded by rows and
stored bytes; the 262,144-row admission limit still applies to retained details.

The default configuration admits at most 64 enabled jails, eight file incarnations per jail and
one shared pool of 65,536 tracked retry subjects and up to 65,536 live bans across all enabled jails;
a banned subject does not consume tracking capacity. Native reservation checks cover configured memory
and descriptor budgets. SQLite uses a separate bounded heap (64 MiB, counted in the admission
figure) with a 32 MiB page cache inside it and a page limit; required history and recovery anchors
remain pinned.

Startup sets `max_page_count` to 1 GiB divided by the page size, so the state file
cannot grow past 1 GiB (262,144 pages of 4 KiB), and a state file already past that
size is refused with `StorageLimit`. A settled ban is kept small so 65,536 live bans and
a day of history fit with headroom: once an intent is applied or expired only its latest
observation is kept, and the bounded maintenance walk clears the evidence text of retry
decisions and confirmed events whose ban ended more than `history_retention` ago. The
target is at most 4 KiB of state file per live ban. `status` and `/metrics` report the
file's bytes and pages. A commit that fails because the file is full
(SQLite "database or disk is full", `StorageFull`) is a retryable storage failure.
Ingestion pauses and the daemon retries after a delay that starts at 1 s and doubles
with each recovery attempt up to 30 s. A recovery attempt moves through storage, state,
ownership and sources, and storage returns to healthy when the last step completes; a
commit that is still refused pauses it again. Rules already in the kernel stay in place
while storage is paused, and `fail2zig status` shows the storage phase. The daemon runs
no VACUUM and does not enable `auto_vacuum`, so the file does not shrink. Committed receipts are guarded in sequence order and deleted once nothing holds
them; a receipt held by a live ban, an open retry window or an unsettled action is set aside
and does not block the receipts behind it, and a bounded pass deletes it once released. Rows
removed by that cleanup and by the retention described above free pages for reuse inside the file, with
`history_retention` (seconds, default 86400) as the retention setting, and an operator
should watch the state file size.

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
