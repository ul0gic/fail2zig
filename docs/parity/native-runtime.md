# Native runtime development contract

This unpublished 0.3.1 development checkout uses the native SQLite runtime by default.
`global.native_ingestion = false` is refused. Existing binary state is neither imported
nor reset. Full N2 fault/platform qualification and release readiness remain open.
The published 0.3.0 behavior is separate from this development contract.

The assembled runtime supports file ingestion, origin-qualified SSH journal input,
bounded custom rules/correlation and their configured DNS/ignore dependencies. Policies
use constant finite bantime and maxretry from 1 through 128. Log-only operation and typed
host INPUT DROP enforcement have passed selected actual-daemon cases with nftables,
iptables and ipset for IPv4 and IPv6. Full service/policy/scope coverage remains later work;
escalation and internal recidive policies are refused at admission.

## State and protection

Each complete record obtains a durable receipt. Its final transaction commits consumer
results, retry state, decisions, checkpoints/cursor and receipt deletion together. Original
receipt/event times and occurrence identities survive retries and restarts. Active decisions
do not accumulate attempts or extend their original expiry. A decision is not proof that a
firewall effect was installed: effect intent is durable before dispatch, kernel readback
establishes confirmation, and confirmed history is consumed separately.

Use a state directory owned by the daemon UID without group/other write access. SQLite files
must belong to that UID with mode 0600. One daemon holds the state authority lock; enforcing
operation also holds the selected network-namespace authority. Incompatible stored state,
required consumers or semantic generations cause refusal. Supported migration/conversion
and transactional live reload remain unfinished; do not point the development daemon at
published binary state expecting automatic conversion.

## File configuration

```toml
[global]
state_file = "/var/lib/fail2zig-dev/state.sqlite"
socket_path = "/run/fail2zig-dev/control.sock"
metrics_enabled = false

[defaults]
enforce = false
maxretry = 3
findtime = 600
bantime = 60

[jails.sshd]
filter = "sshd"
source = "file"
timestamp = "iso8601"
logpath = ["/var/log/auth.log"]
```

Choose an explicit timestamp contract matching the input:

| Setting | Admitted file shape |
|---|---|
| `iso8601` | Timestamp with explicit offset; built-in detection expects a following syslog envelope |
| `syslog` | Classic 15-byte date/envelope, inferred year and explicit fixed offset or named zone |
| `undated` | Service bodies deliberately admitted using receipt time |
| `epoch_seconds` | Leading seconds field separated by a space |
| `common_log` | Bracketed common-log timestamp at its configured fixed position |

For classic syslog, select `timezone_offset_minutes` or `timezone` from the configured
`timezone_root`; a named zone may specify `timezone_ambiguity = "reject"`, `"earlier"`
or `"later"`. Zone bytes and policy participate in generation admission. Parser and
service combinations still require their respective qualification; accepting a date format
is not a claim of full service coverage.

New files start at the head; exact saved positions control restart. Records default to
UTF-8 with a 2 KiB bound. Transient source failures use bounded repair attempts. Lost
continuity or unsafe replay becomes visible intervention without guessing a new position.
A failed physical source can leave healthy sibling sources progressing on a healthy store.

## System journal

Use `source = "journald"`, omit file timestamp settings, and set `journal_executables`
to the actual SSH executables qualified for the host. Admission checks root ownership,
regular executable type and absence of group/other write permission. Detection separately
requires the local machine ID, root UID, an admitted executable and direct syslog transport;
client-supplied tags alone cannot authorize an event.

The runtime retains host `journalctl`, bounded complete records and exact cursor checks.
Selected private-journal tests cover real SSH origins, excluded logger origins, all three
backends, both address families, restart and continuity failures. Other origin/transport
profiles and full deployment/platform coverage are not inferred from those tests.

## Operations and resource limits

One worker owns source/database/effect work. Detached IPC/HTTP snapshots keep status
responsive when it stops making progress. Status reports storage/source causes, worker
heartbeat/busy age, clock uncertainty and overdue or uncertain committed expiry. The
five-second stall threshold is diagnostic; it is not a filesystem I/O timeout. Kernel timer
expiry is independent; iptables rules can remain installed while the worker is blocked.
Recovery preserves original deadlines, inspects effects and verifies source continuity
before healthy admission. Unknown ownership or time does not authorize new protection.

The separate client supports status, jails, version and list. Listed decisions retain
`expiry_us`; `enforced`/`confirmed` require a coherent verified view. Administrative
ban/unban/reload mutations remain explicitly refused without changing state.

Admission limits include 64 enabled jails, eight file incarnations per jail and 4,096 live
retry subjects shared across enabled jails. Native reservations default to 256 MiB and
2,048 descriptors, with checked aggregate admission including recovery overlap. These
are not process/helper RSS guarantees. SQLite has a separate 64 MiB heap ceiling, 2 MiB
advisory cache and 256 MiB main-page limit. Its 16 MiB WAL trigger precedes further writes;
a transaction may overshoot it, and a pinned/failed checkpoint pauses admission. VM work
budgets do not bound blocked kernel I/O or constitute a filesystem quota.

Maintenance first persists replay guards and a reject-below boundary, then deletes eligible
detail in separate bounded batches of at most 64 physical rows. Pending receipts, current
anchors, live retry/effect references and required consumer/history dependencies remain
pinned. Inactive subject compaction retains cumulative retry totals; reentry and restart
preserve them. Guards and required history still consume bounded database capacity.
Exhaustion pauses admission instead of discarding protection. Full fault, maximum-resource,
long-running and target qualification remain required before release.
