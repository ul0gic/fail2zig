# Native ingestion preview

The development daemon has an explicit SQLite ingestion path selected by
`global.native_ingestion = true`. This is an incomplete N2 implementation. Its admitted
policies are **log-only**, with constant finite bantime and maxretry from 1 through 128.
Enforcing policies, escalation, internal recidive, custom/correlated rules and DNS consumers
are not admitted. The default daemon path remains unchanged.

Native file ingestion, retry evidence, decisions and source progress use SQLite as their
authority. Each complete record first obtains a durable receipt; its final transaction
commits time/detection results, retry state, any decision, checkpoint/cursor and receipt
deletion together. Retry attempts preserve their individual times and occurrence identities.
Late attempts are counted only within the inclusive window relative to processing time.
Active decisions neither accumulate new attempts nor extend their committed expiry.
Decisions are not confirmed firewall effects.

## File configuration

Use a separate development state directory owned by the daemon UID, with no group/other
write access. SQLite files must be owned by that UID and mode 0600. An existing binary state
file is not imported or reset. Changing an admitted generation is refused; migration and
reload boundaries still need implementation.

```toml
[global]
native_ingestion = true
state_file = "/var/lib/fail2zig-preview/state.sqlite"
socket_path = "/run/fail2zig-preview/control.sock"
metrics_enabled = false

[defaults]
banaction = "log-only"
maxretry = 3
findtime = 600
bantime = 60

[jails.sshd]
filter = "sshd"
source = "file"
timestamp = "iso8601"
logpath = ["/var/log/auth.log"]
```

Select a timestamp contract matching the actual input:

| Setting | Admitted file shape |
|---|---|
| `timestamp = "iso8601"` | ISO timestamp with an explicit offset, followed by a syslog envelope |
| `timestamp = "syslog"` | Classic 15-byte syslog date/envelope; requires `timezone_offset_minutes` and infers the year from the durable receipt |
| `timestamp = "undated"` | Service message bodies deliberately admitted using receipt time; no implicit timestamp-parser fallback |

Named zones, DST transitions and additional file date layouts are not implemented by this
configuration projection. New files start at the head; saved positions control restart.
Records default to UTF-8 with a 2 KiB bound. Invalid decoding pauses the affected jail without
advancing it; other owners of a healthy store continue. Source repair/resumption is incomplete
and can require a validated restart. Missing continuity is never repaired by seeking to tail.

## System journal configuration

For the qualified SSH syslog profile, use `source = "journald"`, omit file timestamp settings,
and supply `journal_executables` containing the actual SSH executable paths qualified for
that host. Startup checks that the paths identify root-owned regular executables without
group/other write access. The coordinator reads `/etc/machine-id` locally. These checks do not
certify a deployment or establish that an arbitrary configured program is SSH.

The native OS journalctl session uses the existing SSH selectors as alternatives, a bounded
one-record batch, and exact cursor validation. Detection independently requires the configured
machine ID, root UID, an admitted executable and direct syslog transport. Client-supplied tags
cannot authorize a candidate. Other transports and missing executable metadata remain outside
this profile's detection coverage. Broad live-host qualification remains open.

## Operations and limits

One worker owns source/database work. IPC and HTTP status use detached snapshots, so they
continue responding when SQLite is blocked. The delivered client's status, jails, version
and list commands remain available. Native status includes storage phase, failure cause,
SQLite code, retry timing and decision totals. A log-only decision is listed with
`enforced=false`, `confirmed=false` and its original `expiry_us`; `ban_expiry` provides the
seconds projection for the existing client. Confirmed/installed ban totals remain zero.
Native administrative ban/unban/reload mutations are refused without changing state.

Runtime storage errors pause shared ingestion and use the approved 1–30 second recovery
schedule. Recovery reopens storage, restores state and validates source continuity. An
uncommitted first receipt retains its in-memory time during runtime retry. Committed receipt
and processing-time floors prevent a backward clock from silently shifting retry windows.
Unavailable startup storage is refused, including after an initial clock wait. Corrupt state
requires intervention. There is no native firewall recovery implementation in this preview.

Current admission ceilings are 64 enabled jails, eight file incarnations per jail and at most
4,096 retry subjects distributed across the enabled jails. A conservative per-jail memory
estimate limits admitted source plans to 64 MiB; this is not an allocator or process-RSS cap.
Aggregate source/scratch accounting still needs full qualification. Subject capacity refuses
new evidence rather than silently discarding protection history; state/ledger cleanup remains
unfinished, so these limits are not qualified long-running release defaults.

SQLite uses a process-wide 64 MiB heap ceiling, a 2 MiB advisory cache target, a 256 MiB main
database page limit and approximately one million VM instructions per transaction. Its worker
checks the WAL at a 16 MiB maintenance trigger before further admission. A failed or pinned
checkpoint pauses ingestion. These controls exclude OS/helper memory, do not bound a blocked
filesystem syscall, and do not constitute a total filesystem quota. Transactions can overshoot
the WAL trigger. No ledger deletion or binary-state conversion is implemented.

The preview establishes actual file-to-decision-to-restart behavior. It does not complete N2,
qualify enforcing operation, replace the default daemon, or establish release readiness.
