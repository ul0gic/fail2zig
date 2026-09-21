# Runtime architecture

fail2zig 0.4.1 is one native executable containing the daemon, administration commands, rule
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

Firewall effects are limited to the daemon's current network namespace. The daemon does not enter
another namespace, and custom namespace selectors or service overrides that move it between
namespaces are not supported in 0.4.0.

## Administration and privileges

The local Unix socket uses peer credentials for authorization. Read-only monitoring remains
available to the configured service/monitor group; mutations require root or the daemon UID. Status distinguishes
policy decisions, installed protection, uncertainty and degraded dependencies.

In the development branch, routine worker activity retains the last verified protection
view. Effect-changing transactions invalidate that view before commit; coherent readback
restores confirmation. Overdue deadlines, stalled workers, clock uncertainty and failed
readback still degrade protection. Jail `source_healthy` describes the source independently
of storage and firewall health; it does not by itself establish enforcement.

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

The default configuration admits at most 64 enabled jails, eight file incarnations per jail and
4,096 live retry subjects across enabled jails. Native reservation checks cover configured memory
and descriptor budgets. SQLite uses a separate bounded heap and page limit; required history and
recovery anchors remain pinned.

The development CLI inspection path uses an optional observation cache owned by the
coordinator and borrowed by the effect manager. Existing complete readbacks publish
at most 256 pointer-free entries; failures retain the prior sample and update attempt
metadata. A separate cache mutex bounds copying to one page/sample. IPC serializes
the copied page after unlocking and performs no kernel inspection. Cursors bind a
process and observation identity, page limit and a 60-second pagination lifetime.
Complete readback, sample truncation, inventory membership and durable confirmation
remain separate facts.

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
