---
title: Configuration reference
description: Native TOML settings, durations, timed entries, sources, storage, enforcement and reload boundaries.
sidebar_position: 1
category: Reference
audience: operator
last_verified: 2026-11-16
---

<span id="a-complete-worked-example"></span>

The default file is `/etc/fail2zig/config.toml`. Use the
[worked example](../guides/example-jail-config.md) as a starting point and validate
before starting or reloading.

<span id="file-format"></span>
<span id="file-permissions"></span>

## File format and permissions

The parser accepts a strict TOML subset: `[global]`, `[defaults]` and
`[jails.<name>]`. Unknown keys/sections, duplicate keys, mixed array types and
invalid values are rejected. Use section headers, not dotted keys on the left.
Comments begin with `#`; strings must be quoted and accept only the escapes `\"`,
`\\`, `\n` and `\t`. Arrays hold strings only, may span lines and may contain
comments. A jail's name is the header text after `jails.` up to `]`, with
surrounding spaces trimmed. A name written as a quoted key, `[jails."my jail"]` or
`[jails.'my jail']`, is the text between the quotes; a double-quoted name may not
contain a backslash. Validation accepts any name
of 1 to 64 bytes and checks no character set; names of ASCII letters, digits,
hyphens and underscores are the ones that need no quoting in commands.

| Limit                         | Value                                   |
| ----------------------------- | --------------------------------------- |
| Configuration file size       | 16 MiB                                  |
| `[jails.<name>]` sections     | 256 (`TooManyJails`)                    |
| Enabled jails                 | At least 1, at most 64 (`NativeJailLimit`) |

Keep configuration administrator-owned and readable by the service. World-writable
or non-root-group-writable configuration is refused. A non-root owner warns.
The installer preserves existing operator configuration; check its permissions
when changing the service group.

## Duration strings

`bantime`, `findtime`, `bantime_increment_max_bantime`,
`bantime_increment_jitter`, `bantime_increment_decay` and `ignoretime` accept
integer seconds or quoted durations in both defaults and jail overrides.
`history_retention` is integer seconds only.

```toml
[defaults]
bantime = "1h30m"
findtime = "10m"
bantime_increment_max_bantime = "1w"
bantime_increment_jitter = "30s"
bantime_increment_decay = "30d"
```

| Unit             | Seconds    |
| ---------------- | ---------- |
| `s`              | 1          |
| `m`, `mm`, `min` | 60         |
| `h`              | 3,600      |
| `d`              | 86,400     |
| `w`              | 604,800    |
| `mo`             | 2,629,800  |
| `y`              | 31,557,600 |

Months and years are fixed intervals, not calendar arithmetic. Each term is a
nonnegative integer followed by a unit; terms can touch or have intervening
whitespace (`"1h 30m"`). Fractions, signed terms, arithmetic, unknown units and
overflow are rejected. Bare `24h` is not valid TOML.

Finite bantime, findtime and the escalation cap must be positive. Jitter permits
zero and must not exceed the cap. `0` disables `bantime_increment_decay` and makes
`ignoretime` permanent; `ignoretime` is at most 100 × 366 days. Only bantime
accepts `"permanent"`.

### Durations inside entries and on the command line

The duration of a `banip` or `ignoreip` entry is one word after the address, for
example `"198.51.100.0/24 1d"`. `ban --duration` and `ignore add --for` take the
same form. This form is wider than the key syntax above: besides the units in the
table it accepts a bare number of seconds (`"198.51.100.1 3600"`), longer unit
names such as `sec`, `minute`, `hour`, `day`, `week`, `month` and `year` in any
case, and fail2ban-style arithmetic. The result must be a whole number of seconds,
at least 1 and at most 100 × 366 days. `--timeout` and migration window arguments
remain plain integers.

## `[global]`

### Logging and administration

| Key                                         | Type / default                          | Meaning                                                                                                          |
| ------------------------------------------- | --------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| <span id="log_level"></span>`log_level`     | String, `"info"`                        | `debug`, `info`, `warn` or `err`. Live reload supported.                                                         |
| `log_target`                                | String, `"stderr"`                      | Stderr or an absolute log-file path. Changing the target requires restart; SIGUSR1 reopens it after rotation.    |
| <span id="log_format"></span>`log_format`   | String, `"text"`                        | `"json"` writes every daemon log line as one JSON object (`ts`, `level`, `scope`, message fields). Restart-only. |
| <span id="socket_path"></span>`socket_path` | String, `"/run/fail2zig/fail2zig.sock"` | Local administration and monitoring socket. Absolute path shorter than 108 bytes.                                |
| <span id="pid_file"></span>`pid_file`       | String, `"/run/fail2zig/fail2zig.pid"`  | Deprecated compatibility key; warns when explicitly set and is not written. Use systemd MainPID.                 |

The socket is mode `0660`. Members of the configured service/monitor group can
read aggregate status, metrics and the redacted configuration. Ban lists, history,
firewall inventory and every mutation require uid 0 or the daemon UID, verified
with peer credentials. Every mutation writes one `audit` line to the daemon log
with the command, target, caller UID and outcome.

The administrative commands and `migrate` read `socket_path` from
`/etc/fail2zig/config.toml` when `--socket` is not given, so a custom socket needs
no extra flag. Under the shipped systemd unit a custom `socket_path` or
`state_file` directory also needs a unit override; see the
[custom state directory procedure](../operations/installation.md#custom-state-directory-under-systemd).

### State and resource limits

| Key                                                     | Type / default                                 | Meaning                                                                                                                        |
| ------------------------------------------------------- | ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| <span id="state_file"></span>`state_file`               | Absolute path, `"/var/lib/fail2zig/state.bin"` | Native SQLite store for receipts, checkpoints, policy, retries, owners, effect intent, origins and confirmed history.          |
| <span id="memory_ceiling_mb"></span>`memory_ceiling_mb` | Integer, `64`, minimum `16`                    | Accepted and range-checked; nothing at startup or runtime reads it. `native_memory_ceiling_mb` is the budget the daemon enforces. |
| `native_memory_ceiling_mb`                              | Positive integer, `512`                        | Native admission budget in MiB. The plan for 65,536 live bans is about 337 MiB with two enforcing jails, 438 MiB with sixteen. |
| `native_fd_ceiling`                                     | Positive integer, `8192`                       | Most file descriptors the native plan may use; the default is enough for 64 file jails.                                        |
| `history_retention`                                     | Nonnegative integer seconds, `86400`           | Age policy for confirmed-history cleanup; required recovery anchors stay pinned.                                               |
| <span id="history_max_matches"></span>`history_max_matches` | Integer `0–1024`, `10`                    | Matched log lines kept per address across all jails. A jail can lower its own share.                                           |

The database and its parent must belong to the daemon UID. The historical
`.bin` extension does not make it the legacy binary format. Native startup
refuses corrupt, incompatible or inaccessible required state instead of starting
empty. New work (log records, manual bans, `banip` additions, `ignore add`, a new
reload) is admitted only while the file's used pages, plus the pages owed to work
already admitted, fit in 262,144 pages (1 GiB). At that line sources wait with
`StorageCapacity`, the manual commands are rejected with it, and expiry, unban and
cleanup keep writing; intake resumes by itself when room returns. SQLite's own limit
is 16,384 pages higher, so the file can reach 1 GiB plus 64 MiB; a file past that is
refused at startup. A full filesystem pauses ingestion with `StorageFull` and
retries while rules already in the kernel stay enforced. The file never shrinks;
rows removed by cleanup and retention free pages for reuse inside it, and `status`
shows allocated and used pages. There is no setting for the capacity; see the
[resource boundaries](../architecture.md#resource-boundaries).
A configuration that sets `native_memory_ceiling_mb = 256` explicitly must raise
it or the daemon refuses with `NativeMemoryAdmission`. Above about twenty jails
the default of 512 refuses startup the same way; raise it for larger
configurations. Storage failure pauses
affected ingestion and reports degraded health while retaining protection.
Preserve the database and WAL/SHM coherently; do not delete them to clear an error.
See [upgrades](../guides/upgrading.md) and the
[memory model](../architecture/memory-model.md).

At start the daemon raises its soft open-file limit to `native_fd_ceiling`, never
past the hard limit the service grants, then admits its plan against the lower of
the two. Each file jail is charged for eight sources; a plan that does not fit
refuses startup with `NativeFdAdmission`.

### Matched lines in history

Every confirmed event keeps the log line that triggered it, up to
`history_max_matches` lines per address across all jails. `history --details` and
`list --details` show them. A jail can set its own `history_max_matches`, listed
with the jail keys below, to keep fewer; its effective value is capped by the global
total. With global `10` and a jail value of `2`, that jail keeps at most two lines
for an address and all jails together keep at most ten.

`0` hides matched lines at once, and bounded cleanup removes the stored text
afterwards. Decisions and confirmed events stay. Raising the value later cannot
bring deleted lines back. A change applies on `reload` without resetting retry
state or source positions.

### HTTP listener

| Key                                                             | Type / default            | Meaning                                                                        |
| --------------------------------------------------------------- | ------------------------- | ------------------------------------------------------------------------------ |
| <span id="metrics_enabled"></span>`metrics_enabled`             | Boolean, `true`           | `false` removes the HTTP listener; the socket and protection remain available. |
| <span id="metrics_bind"></span>`metrics_bind`                   | IPv4 string, `"127.0.0.1"` | Listen address, IPv4 only. Loopback is not authentication.                     |
| <span id="metrics_port"></span>`metrics_port`                   | Integer `1–65535`, `9100` | Port remains validated even when disabled. Zero does not disable HTTP.         |
| <span id="websocket_max_clients"></span>`websocket_max_clients` | Integer                   | Deprecated: accepted and ignored with a warning. Remove it from the file.      |

Endpoints are `/metrics`, `/api/status` and `/api/health`. Health reports
readiness with HTTP 200/503. `/api/bans` returns 403: ban details are served only
to administrators through the local socket. The
[monitoring API reference](api.md) lists every endpoint, field and metric. HTTP shares the privileged daemon
process. Keep external access controlled or disable it if unused.

### Firewall

`firewall` is a global string, default `"auto"`.

| Value        | Selection behavior                                                                                          |
| ------------ | ----------------------------------------------------------------------------------------------------------- |
| `"auto"`     | Reuse the backend recorded for an existing installation; otherwise probe nftables, then ipset and iptables. |
| `"nftables"` | Probe only nftables; direct netlink.                                                                        |
| `"ipset"`    | Probe only ipset; needs both ipset and iptables tools.                                                      |
| `"iptables"` | Probe only iptables.                                                                                        |

An explicit backend never silently switches to another. With existing state,
`auto` keeps the recorded backend across restarts, including when no bans are active.
An explicit backend or namespace selector that conflicts with the saved installation
is rejected rather than migrating ownership. Restore the recorded setting or use
`auto`; do not delete the database to switch backends. Jail `enforce` selects
enforcement policy, not a backend. If every enabled jail is log-only, enforcement
backend detection is skipped.

<span id="on_no_backend"></span>

`on_no_backend` is `"fail-closed"` by default: unusable required enforcement causes
startup refusal. `"log-only"` explicitly permits degraded observe-only operation;
status reports the cause. It does not install protection.

`firewall_namespace` (default `/proc/self/ns/net`) is an ownership anchor, not a
request to enter another namespace. An explicit value must be an absolute path of
at most 256 bytes and may not contain `/self/` or `/thread-self/`, so the default
cannot be written out. Effects remain in the daemon's current network namespace. Custom
selectors and unit overrides that move the daemon between namespaces are
unsupported; leave this setting at its built-in default.

### DNS and timezone data

`dns_server` is an optional resolver IP literal; `dns_port` defaults to `53`,
accepts `1–65535` and must stay `53` unless `dns_server` is set. Native hostname rules use bounded resolution and retain retry state;
a hostname is not an arbitrary command. `timezone_root` defaults to
`"/usr/share/zoneinfo"` for named timezone data. Leave these defaults unless the
chosen input contract requires an explicit deployment setting.

## `[defaults]`

| Key                                       | Type / default                            | Meaning                                                                                                        |
| ----------------------------------------- | ----------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| <span id="bantime"></span>`bantime`       | Seconds/duration, `600`, or `"permanent"` | Initial ban duration.                                                                                          |
| <span id="findtime"></span>`findtime`     | Positive seconds/duration, `600`          | Window for repeated failures.                                                                                  |
| <span id="maxretry"></span>`maxretry`     | Integer `1–128`, `5`                      | Failures required within findtime.                                                                             |
| <span id="source"></span>`source`         | String, `"auto"`                          | `auto`, `file`, `journald` or `internal`.                                                                      |
| <span id="enforce"></span>`enforce`       | Boolean, `true`                           | `true` enforces through the selected global backend; `false` observes without enforcing.                       |
| <span id="banaction"></span>`banaction`   | Deprecated string, `"nftables"`           | Compatibility spelling; `nftables`, `iptables`, `ipset` mean enforce, and `log-only` means observe.            |
| <span id="ignoreip"></span>`ignoreip`     | String array, `[]`                        | IPs/CIDRs never banned, each optionally followed by a duration. The shipped example includes loopback ignores. |
| <span id="banip"></span>`banip`           | String array, `[]`                        | IPs/CIDRs banned while listed, permanent or timed (`"198.51.100.0/24 1d"`). Applied at start and on reload.    |
| <span id="ignoreself"></span>`ignoreself` | Boolean, `true`                           | Adds the host's own IPv4/IPv6 addresses, loopback included, to the effective ignore list with source `self`.   |
| <span id="ignoretime"></span>`ignoretime` | Seconds/duration, unset (`0`, permanent)  | Default life of an exclusion with no duration of its own, configured or `ignore add` without `--for`.          |

Prefer `enforce = true/false` in new configurations. `banaction` remains accepted
for compatibility and emits a deprecation warning when explicitly set. Do not
combine the two in one section. Neither setting selects the firewall backend or
enables arbitrary shell actions.

### Configured bans and exclusions

A `banip` entry is a live ban with origin `config` in that jail, permanent for a
permanent entry and ending at the stored deadline for a timed one. It takes over an
existing ban of the same address in the jail and replaces its expiry with its own.
Removing an entry and reloading lifts its ban at once. While a config ban is live,
`fail2zig ban` or `unban` of the address is refused with
`banned by config: edit banip`. A jail holds at most 1,024 effective `banip`
entries. Host names are not accepted.

An address in both the effective `ignoreip` and the effective `banip` of one jail,
as equal entries or one containing the other, is a configuration error: the daemon
refuses to start, and `reload` reports `rejected` naming the jail and the address.

`ignoreself` reads the host's addresses from the kernel at start and at every
reload; an address assigned later counts from the next reload. `self` entries do
not count against the 128-entry ignore limit. A jail list for `ignoreip` or
`banip` replaces, rather than appends to, the `[defaults]` list.

`ignoretime` is unset or `0` for permanent. A jail value overrides `[defaults]`,
and `0` in a jail restores permanent under a `[defaults]` value. A duration written
on the entry, or `ignore add --for`, wins. A non-zero value on a `rule_files` jail
is refused.

<span id="timed-entries"></span>

### Timed entries

A `banip` or `ignoreip` entry written with a duration, and an `ignoreip` entry that
takes `ignoretime`, is timed. The period starts when the daemon first applies the
entry, at start or at a reload, and runs once: a reload or a restart does not
restart it. Changing the entry's duration, or the `ignoretime` it takes, starts a
fresh period, as does removing the entry, reloading and adding it back. When the
period runs out the entry stays in the file and does nothing; `list` or
`ignore list` shows it as `expired` until it is removed from the file. A timed
`ignoreip` entry is refused on a jail with `rule_files`.

<span id="bantime-increment-settings"></span>

### Escalation

| Key                                                                             | Default      | Meaning                                                                               |
| ------------------------------------------------------------------------------- | ------------ | ------------------------------------------------------------------------------------- |
| <span id="bantime_increment_enabled"></span>`bantime_increment_enabled`         | `false`      | Enable escalating durations.                                                          |
| <span id="bantime_increment_multiplier"></span>`bantime_increment_multiplier`   | `1.0`        | Positive base multiplier.                                                             |
| <span id="bantime_increment_factor"></span>`bantime_increment_factor`           | `1.0`        | Nonnegative growth factor; integer or decimal.                                        |
| <span id="bantime_increment_formula"></span>`bantime_increment_formula`         | `"linear"`   | `linear` or `exponential`, not an arbitrary expression.                               |
| `bantime_increment_scope`                                                       | `"per-jail"` | `per-jail` or `overall` recurrence scope.                                             |
| <span id="bantime_increment_max_bantime"></span>`bantime_increment_max_bantime` | `604800`     | Positive seconds/duration cap.                                                        |
| `bantime_increment_jitter`                                                      | `0`          | Seconds/duration jitter bound, at most the cap.                                       |
| <span id="bantime_increment_decay"></span>`bantime_increment_decay`             | `2592000`    | Escalation resets to the base `bantime` when the last ban ended longer ago than this. |

Linear uses `bantime × multiplier × (1 + factor × n)`; exponential uses
`bantime × multiplier × factor^n`, where `n` is the prior ban count used by the
policy. For doubling with no jitter, set multiplier `1`, factor `2` and formula
`"exponential"`. A multiplier of `2` alone does not select doubling growth.

Decay is measured from the end of the last ban, not its start, so nothing decays
during a live ban and a permanent ban never decays. The reset is complete, never a
step down; `0` disables it. After a manual `unban`, failures count from zero again
while the escalation count is kept.

**Escalation settings inherit field by field.** A jail overrides only the keys it
explicitly sets; omitted keys retain `[defaults]` values.

## `[jails.<name>]`

A jail declares a source, matcher and policy. Enabled jails must have admitted
protection; unknown built-in filters without native rule files fail validation.

<span id="maxretry-1"></span>
<span id="findtime-1"></span>
<span id="bantime-1"></span>
<span id="banaction-1"></span>
<span id="enforce-1"></span>
<span id="ignoreip-1"></span>
<span id="per-jail-bantime_increment_"></span>

| Key                                             | Default / contract                                                                                                            |
| ----------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| <span id="enabled"></span>`enabled`             | `true`; disabled jails are not started.                                                                                       |
| <span id="filter"></span>`filter`               | Built-in service name, or the service name for a custom rule-file jail. Built-ins accept hyphen/underscore forms.             |
| <span id="logpath"></span>`logpath`             | Array of file paths, default empty. Write absolute paths that the service can read: unlike `rule_files`, `journal_executables` and `ignore_file`, entries are not checked for being absolute. |
| `source`                                        | Inherits defaults. Prefer explicit source selection for reviewed configurations.                                              |
| `maxretry`, `findtime`, `bantime`, `enforce`    | Override the corresponding default. `banaction` remains a deprecated compatibility input.                                     |
| `ignoreip`, `banip`                             | Each replaces, rather than appends to, the defaults list. Repeat loopback entries when overriding `ignoreip`.                 |
| `ignoreself`, `ignoretime`                      | Override the `[defaults]` values for this jail.                                                                               |
| <span id="on_truncation"></span>`on_truncation` | `"refuse"` (default) or `"restart"`; file sources only, rejected in `[defaults]`. See [log file lifecycle](../guides/log-lifecycle.md). |
| `bantime_increment_*`                           | Field-by-field overrides as described above.                                                                                  |
| `history_max_matches`                           | Optional integer `0–1024`; omitted inherits the global value. Jail-only: `[defaults]` does not define it. Applies on reload.  |

`on_truncation` applies to every `logpath` of the jail and covers a file truncated
in place, a rotated-out file removed with unread bytes, and a log replaced by a
different file. `refuse` pauses the source until `repair-source` acknowledges the
loss; the daemon keeps running and other jails enforce. `restart` resumes and
records a continuity-loss event. The diagnostics are `InvalidTruncationPolicy`,
`TruncationPolicyNotFileSource` and `TruncationPolicyNotAllowedInDefaults`. A
change is restart-only. Neither value recovers records that were never read.

<span id="source-1"></span>

### Source and time contracts

| Key                       | Contract                                                                                                                                   |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `timestamp`               | File inputs require an explicit format: `iso8601`, `syslog`, `epoch_seconds`, `common_log` or `undated`. Choose for the actual log format. |
| `timezone_offset_minutes` | Fixed offset from UTC, `-1439–1439`, for the selected timestamp contract.                                                                  |
| `timezone`                | Named timezone; cannot be combined with the fixed offset.                                                                                  |
| `timezone_ambiguity`      | `reject`, `earlier` or `later`; requires a named timezone.                                                                                 |
| `journal_executables`     | Optional exact origin profile. Built-in SSH jails discover trusted standard paths when omitted; custom journal rules require it.           |
| `rule_files`              | Up to eight distinct absolute paths to bounded native JSON rules.                                                                          |
| `ignore_file`             | Optional absolute path to an ignore-policy file, for jails with `rule_files` only; an enabled jail that sets it without `rule_files` is refused at start. Its contents and its path reload live. |

```toml
[jails.sshd]
filter = "sshd"
source = "journald"
journal_executables = ["/usr/sbin/sshd", "/usr/lib/openssh/sshd-session"]
```

`auto` resolves the configured source at startup. `file` reads declared paths;
`journald` requires journalctl and admitted origins; `internal` is the confirmed-ban
feed for recidive. Internal recidive does not use log paths or custom rule files.
A built-in SSH jail with no `journal_executables` setting discovers available
root-owned executables from a bounded catalog of standard SSH paths. Discovery
rejects unsafe path ownership or permissions. An explicit nonempty list remains an
exact override; an empty list is invalid, and custom journal rules require an explicit
profile.
A source is healthy only after its runtime checks pass; configuration validation
alone is not that check. A missing log file is reported as `missing (FileNotFound)`
by `jails` and is not a failure. See [log watching](../architecture/log-watching.md)
and the [log file lifecycle](../guides/log-lifecycle.md).

<span id="backend-deprecated"></span>
<span id="deprecated-and-reserved-keys"></span>

For PortSentry v2.0.7, use `filter = "portsentry"`, `source = "file"` and
`timestamp = "iso8601"` with the history file. Follow the
[sensor and jail setup](../guides/portsentry.md); this is not a generic syslog or
legacy PortSentry input. PortSentry recreates its history file at every start, so
choose `on_truncation` for that jail deliberately. File encoding replacement is
described under [log watching](../architecture/log-watching.md#malformed-file-encoding).

### Deprecated and migration-managed settings

`backend` is a deprecated source alias accepted in defaults/jails: `systemd`
maps to `journald`; `auto`, `polling`, `pyinotify` and `gamin` map to `auto`.
Using both `source` and `backend` in one section is an error. It never chooses
the firewall backend.

`native_ingestion` defaults to true; `false` fails validation with
`NativeIngestionRequired`. `compatibility_manifest` (`[global]`) and
`compatibility_pending` (`[global]` and jails) are migration-managed admission
metadata; an enabled jail with either set fails with `CompatibilityNotAdmitted`. Do not clear blockers by hand to force an
unsupported imported jail into service.

<span id="validation"></span>

## Validation and reload

```bash
sudo fail2zig --validate-config --config /etc/fail2zig/config.toml
```

Diagnostics identify file, line, column, section and key when available. Unreadable
files and permission failures can be positionless. Validation summarizes configured
sources and prints `on_truncation=<value>` for each file jail; an `auto` source is
resolved when the daemon starts. Inspect the actual source and readiness through
`fail2zig jails` and `fail2zig status`.

### What a reload applies

`fail2zig reload` applies these changes without a restart:

- `[global]`: `log_level` and `history_max_matches`. Every other global key is
  restart-required.
- Per jail: `maxretry`, `bantime`, every `bantime_increment_*` key, `ignoreip`,
  `ignoreself`, `ignoretime`, `banip` and `history_max_matches`.
- Adding a jail section and removing one.
- The contents of a custom jail's `ignore_file`.

These per-jail keys return `restart_required`: `enabled`, `findtime`, `source`,
`filter`, `logpath`, `timestamp`, `timezone`, `timezone_offset_minutes`,
`timezone_ambiguity`, `journal_executables`, `rule_files`, `on_truncation` and
`enforce`/`banaction`. A policy edit on a disabled jail or on an `internal`-source
jail is also restart-required. An `ignoreip` edit is rejected when the configured
entries plus the runtime entries of a jail exceed 128. See
[reload outcomes](cli-fail2zig-client.md#reload).

### Validation errors

| Error                                                       | Cause                                                              |
| ----------------------------------------------------------- | ------------------------------------------------------------------ |
| `ConfigWorldWritable`, `ConfigGroupWritable`                | The file's permissions let other users change it.                  |
| `InvalidValue`                                              | A value of the wrong type or outside its range; also `source` with `backend`, or `enforce` with `banaction`, in one section. |
| `InvalidMaxretry`, `InvalidIncrement`, `InvalidIgnoretime`  | The named policy key is out of range.                              |
| `InvalidBanip`, `InvalidEntryDuration`                      | A `banip` entry or the duration on an entry does not parse.        |
| `BanListConflict`, `BanListLimit`                           | An address is in both `ignoreip` and `banip`, or a jail has more than 1,024 `banip` entries. |
| `UnknownFilter`                                             | `filter` names no built-in and the jail has no `rule_files`.       |
| `InvalidNativeTimezone`, `InvalidNativeRules`, `InvalidNativePath`, `InvalidNativeDns` | A timezone, rule file, path or DNS setting is invalid. |
| `MemoryCeilingTooLow`                                       | `memory_ceiling_mb` is below its minimum.                          | Neither successful
syntax validation nor a reload request establishes installed firewall protection.

The [parser](../../engine/config/config.zig),
[shipped example](../../deploy/fail2zig.toml.example)
and [fail2zig.toml(5)](../man/fail2zig.toml.5)
define the accepted configuration.
