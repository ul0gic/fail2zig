---
title: 'fail2zig — administration'
description: 'Status, ban origins, matched lines, runtime exclusions, firewall observation and withdrawal, online source repair, support bundles and jail controls.'
sidebar_position: 4
category: Reference
audience: operator
last_verified: 2026-11-16
---

Administration uses the same `fail2zig` executable as the daemon. The separate
`fail2zig-client` was used before v0.4.0; those releases and their Git tags are
retired. See the [changelog](../../CHANGELOG.md) for the old release history.

## Synopsis

```text
fail2zig [--socket <path>] [--output table|json|plain] [--no-color] [--timeout <ms>] <command> [args]
```

Without `--socket` the commands use the `socket_path` set in
`/etc/fail2zig/config.toml`, else `/run/fail2zig/fail2zig.sock`. A missing or
unreadable configuration falls back to that default without a message. The
default timeout is 5000 ms; `firewall withdraw` uses at least 15000 ms.
`table` is for people, `json` for scripts and `plain` is tab-separated.
`ban --duration` and `ignore add --for` accept seconds or the configuration's
duration syntax (`2m`, `1h30m`); `--timeout` remains an integer.

The socket is mode `0660`, and the caller is identified through `SO_PEERCRED`.

| Caller                              | May                                                                                   |
| ----------------------------------- | ------------------------------------------------------------------------------------- |
| uid 0 or the daemon UID             | Everything: ban lists, history, firewall inventory, matched lines and every mutation. |
| Member of the service/monitor group | `status`, `jails`, `stats`, `version`, the redacted `config` and `ignore list` with addresses redacted. |

Group membership alone does not grant ban, unban, ignore or reload authority, and
it does not show ban lists, history or the firewall inventory. The shipped service uses `fail2zig:fail2zig`; the installer supports a
custom group. `ban`, `unban`, `ignore add`, `ignore remove`, the `jail` controls,
`history reset`, `reload` and the online `repair-source` each write one `audit`
line to the daemon log with the command, target, caller UID and outcome.
`firewall withdraw` writes no audit line.

Every command has a help page: `fail2zig help <command>` or `<command> --help`,
the offline tools included. `fail2zig <typo>` exits 2 and suggests the nearest
command when one is close; `help <typo>` exits 2 and points to `fail2zig help`. The daemon's `--help` and the client's `help` list the same commands.

## Status and inspection

```bash
fail2zig status
fail2zig status --details
fail2zig jails --details
fail2zig list --sort
fail2zig list --jail sshd --origin manual --sort
fail2zig list --origin config
sudo fail2zig list --details
sudo fail2zig history --jail sshd --details
fail2zig stats
fail2zig stats --details
fail2zig firewall show
fail2zig --output json history --jail sshd --limit 20
fail2zig config
fail2zig version
```

| Command                                                                          | What it reports                                                                                               |
| -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `status [--details]`                                                             | Version, protection, storage, backend, state file and tracking pool, paused sources, loss events, counters.   |
| `jails [--details]`                                                              | Enabled/paused state, source health, configured mode, observed protection and bans per jail.                  |
| `list [--jail <name>] [--origin detection\|manual\|config] [--details] [--sort]` | Active bans with their origin, optionally restricted to one jail or origin and sorted numerically by address. `--details` adds ban counts and the matched line. |
| `stats [--details]`                                                              | Published worker snapshot, snapshot/readback ages and daemon-start counters.                                  |
| `history [--jail <name>] [--limit 1..256] [--cursor <token>] [--details]`        | Confirmed history with bounded pagination; each event carries the ban's origin. `--details` adds the matched line. |
| `firewall show [--limit 1..256] [--cursor <token>] [--details]`                  | Latest retained observation of fail2zig-owned kernel protection, with the owning ban's origin per entry.      |
| `config`                                                                         | Effective configuration; paths and address lists are redacted for non-administrators.                         |
| `version`                                                                        | The client's version and the running daemon's (JSON `client_version` and `daemon`); exits 3 when the daemon is unreachable. `--version` reports only the local executable. |

A policy decision, installed protection and an uncertain effect are different
states. Inspect storage and enforcement causes when the daemon is degraded.
Check protection knowledge age, pending bans and overdue removals. A stale or
degraded status is not confirmation of current kernel protection.

`status` table output adds `State file: <bytes> (<pages> pages of <max_pages>)`,
where `<max_pages>` is SQLite's limit of 278,528 pages, `Used pages: <used_pages> of
<pages> allocated` (pages in use, excluding the free pages the file keeps for reuse;
new work waits when these, plus the pages owed to admitted work, reach 262,144) and `Tracking pool: <tracked> of <limit> tracked,
<banned> of <limit> banned` against the shared pool of 65,536 tracked addresses
and 65,536 live bans. A paused file source appears as a `Paused:` block with the
jail, path, cause and the exact `repair-source` command; a source that resumed
under `on_truncation = "restart"` shows a `Loss events:` row, and `--details`
lists each retained event. A source that is unhealthy but not paused appears as a
`Waiting:` or `Broken:` row with the jail, source kind and cause, and `Cause:`
names that error instead of `unknown`. JSON adds `state_file_bytes`, `state_file_pages`,
`state_file_max_pages`, `state_file_used_pages`, `pool_tracked`, `pool_banned`, `pool_tracking_limit`,
`pool_ban_limit`, `paused_sources` and a `sources` array. Use
`status --output json`; there is no `--json` flag.

A configured log path or glob with no file shows as a `Missing:` row with its jail
and path; JSON and plain output add `missing_sources`. It is an availability
notice, not a paused source, and the row clears when a matching file appears.

`jails` shows SOURCE HEALTH per jail: `ok`, `missing (FileNotFound)`,
`waiting (<cause>)`, `paused (<cause>)` or `broken (<cause>)`. `missing` is a
healthy state: the log is absent and reading resumes when it appears. `waiting
(RetryCapacity)` means the jail is waiting for room in the tracking pool and
resumes as room frees. `waiting (StorageCapacity)` means the state file has reached
its page capacity: the source keeps its position without pausing, rules stay
enforced, and reading resumes by itself when room returns. In `jails`, MODE is configured enforcement and PROTECTION
is observed protection. A plain-output ban count of `-` is unknown; `0` means
known empty. See the [log file lifecycle](../guides/log-lifecycle.md) for the
source states.

`Storage:` in `status` is the storage phase: `starting`, `healthy`, `paused`,
`recovering` or `intervention`. While storage is paused, `Cause:` names the failure
and `SQLite code:` shows SQLite's primary result code when there is one. These
causes pause ingestion and retry, after a delay that starts at 1 s and doubles up to
30 s and returns to 1 s when a record commits; rules already in the kernel stay in
place:

| Cause             | Meaning                                                                                       |
| ----------------- | --------------------------------------------------------------------------------------------- |
| `StorageFull`     | SQLite reported the database or disk full (code 13).                                          |
| `Busy`            | The database was busy or locked (codes 5 and 6).                                              |
| `StorageIo`       | A disk I/O error (code 10).                                                                   |
| `ReadOnly`        | The database could not be written (code 8).                                                   |
| `RestoreRequired` | A source could not continue while storage was healthy, or a batch of records failed with a cause that is not retryable (the daemon logs that cause by name). Recovery rebuilds the sources from committed state. |

A storage failure in the middle of a batch of records is reported with its own
cause when it is one of the four above. A source that stops for one of these causes
resumes after recovery without a restart. A cause that is not retryable outside a
record batch moves storage to `intervention`, which does not retry.

`--details` expands table output for `status`, `jails`, `stats` and
`firewall show`. For `stats` and `firewall show` plain and JSON output is
unchanged; `status --details` also adds the retained loss events to plain and JSON
output (`loss_events`). On `list` and `history` it adds the matched line in every
output format, described below. Detailed
jail output switches to complete stacked blocks on narrow terminals. History
counts retained confirmations, not every ban ever issued.

### Matched lines

```bash
sudo fail2zig history --details
sudo fail2zig list --details
sudo fail2zig history --jail sshd --details --output json
```

`history --details` shows the stored log line that triggered each confirmed
event; `list --details` shows the line behind each live ban's current decision.
Table output escapes control characters and wraps the complete line onto
continuation rows at the terminal width. Plain output truncates the line to 96
bytes and marks the cut with an ellipsis. JSON adds a `matches` array holding the
complete line, or an empty array when there is none.

There is no line for a `banip` entry, a log-only decision, text that retention
has pruned, or a jail whose `history_max_matches` is `0`. The confirmation itself
stays. How many lines are kept is set by
[`history_max_matches`](config.md#matched-lines-in-history). Matched lines are
log text, so detail queries need administrator access through the socket and are
not served over HTTP. A large `--limit` can exceed the 1 MiB response limit with
code 413; lower `--limit` and page with `--cursor`.

### Ban origins

Every ban carries one origin: `detection` (a filter matched), `manual` (`ban`) or
`config` (`banip`). `list`, `history` and `firewall show` show it in an ORIGIN
column and as JSON `origin`. `list --origin` keeps only bans of that origin;
`--origin config` also lists timed `banip` entries whose period has run out, with
`expired` set to true. History events written before 0.4.8 show `detection`.
`list --sort` is optional in table, plain and JSON output; it sorts addresses
numerically, IPv4 before IPv6. Without the flag, listing order is unchanged.

`stats` reads the worker's published snapshot without requesting a fresh firewall
inspection or database scan. Show snapshot age separately from firewall readback
age. Its counters accumulate since daemon start and reset on restart; they are not
rates or lifetime totals.

## Firewall observation

```bash
fail2zig firewall show
fail2zig firewall show --details
fail2zig --output json firewall show --limit 64
```

`firewall show` reads the daemon's latest retained observation of fail2zig-owned
kernel protection. It does not run a new inspection, repair rules or mutate firewall
state. Native nftables observation communicates directly with the kernel and does
not require the `nft` executable; that property does not apply to iptables or ipset.
On nftables the inventory is kept current by the kernel's acknowledgement of each
install batch and by nf_tables change events, with a full audit of the owned set
every 60 seconds; ipset and iptables keep their readback cadence.

`list` reports ban intent and confirmation. `firewall show` reports a sampled kernel
observation. Neither proves packet reachability through the complete host or network
ruleset. Inspection is limited to fail2zig-owned protection in the daemon's current
network namespace; it does not enumerate UFW, firewalld, container rules or another
application's firewall state.

Check observation age and the latest attempt together. A failed inspection retains
the previous observation and marks the latest attempt failed. Unavailable observation,
absent installation and a verified installation with zero entries are separate states.
A successful command exit means the query was answered, not that protection is healthy.

At most 256 entries are retained. Pages default to 64 entries, accept at most 256 and
use a 60-second cursor tied to the retained observation. `--details` adds verified
owned tables, chains, sets and attachment rules plus sampled-entry placement. Those
structures appear only for a complete, stable, exactly verified owned readback; older
or incomplete observations report them as unavailable. JSON exposes additive nullable
structure and placement fields independently of `--details`.

### Withdraw enforcement

```bash
sudo fail2zig firewall withdraw
```

A healthy stop leaves the daemon's installed rules in the kernel, where they keep
their timeouts; the next start reconciles them with durable state. A stop does not
unban anyone. `firewall withdraw` removes every rule the running daemon realized,
in batches with a kernel readback after each, and holds enforcement off until the
next start. Owners and ban deadlines are kept; new decisions are recorded but not
installed; `reload` does not lift the hold. While held, `status` reports
`DEGRADED (FirewallWithdrawn)` and the daemon logs a warning every hour. Run it
before stopping the daemon when the table must be empty. Outcomes are `applied`
with the count removed, `partial` when interrupted (run it again), `uncertain`
when a kernel failure leaves the remainder unknown, or `rejected`.

## Ban and unban

```bash
sudo fail2zig ban 203.0.113.7 --jail sshd --duration 1h
sudo fail2zig ban 203.0.113.7 --jail sshd --force
sudo fail2zig unban 203.0.113.7 --jail sshd
```

Both commands require exactly one jail. Without `--duration` a manual ban runs
for the jail's `bantime`; a duration must be more than 0 and at most 100 × 366
days. `ban` and `unban` both take `--scope`: `--scope host` is the default, and
`--scope net <cidr>` requires nftables or ipset and refuses a prefix length of 0. Unsupported scope is rejected. A manual ban on a
log-only jail is rejected rather than recorded as installed. Removing one jail's
owner does not remove protection still owned by another jail.

A manual ban has origin `manual`. `ban` on an address that holds a detection ban
extends it to the requested duration and marks it `manual`. `ban` or `unban` on
a config ban is refused with exit 1 and `banned by config: edit banip`; edit the
configuration and reload instead. After an `unban`, the address's failure count
starts from zero, so `maxretry` new failures inside `findtime` ban it again; its
escalation count is kept.

Before it opens the socket, `ban` refuses a target that is a loopback address, an
address of this host, or the client address of the SSH session it runs in, or a
`--scope net` network containing one. The refusal exits 1 and names the matched
address and `--force`. `--force` applies the ban; it is a guard against a typing
mistake, not a security boundary, and the daemon's own authorization is unchanged.
Manual bans are never checked against the ignore list; a ban of an ignored address
is applied with a warning naming the ignore source.

JSON mutation reports include `outcome`, `enforced`, generation/revision and
reasons. Exit 4 means partial and exit 5 means uncertain; neither is success.
There is no `unban --all` command. Review `list --output json` and unban specific
address/jail owners deliberately.

## Runtime exclusions

```bash
sudo fail2zig ignore add 198.51.100.20 --jail sshd
sudo fail2zig ignore add 203.0.113.0/24 --jail sshd --unban
sudo fail2zig ignore add 198.51.100.20 --jail sshd --for 2h
sudo fail2zig ignore remove 198.51.100.20 --jail sshd
fail2zig ignore list
fail2zig ignore list --jail sshd
```

`ignore add` records a runtime exclusion for one jail. The entry is stored in the
state database, survives restart and reload, and merges with the configured
`ignoreip`. From the next event after the commit a matching event counts as an
ignored detection. An existing ban stays until its deadline unless `--unban` is
given; the output names the ban and the exact command that lifts it. `--unban`
lifts that jail's bans inside the entry, at most 256, and never a wider network
ban or another jail's ban. `--for <duration>` gives the entry a life; at the
deadline the daemon deletes it. Without `--for` the entry takes the jail's
`ignoretime` when set and is permanent otherwise.

`ignore remove` removes runtime entries only. A configured entry is edited in
`ignoreip` and applied with `reload`; the refusal names the file. `ignore list`
shows JAIL, ADDRESS, SOURCE (`config`, `runtime`, `config+runtime` or `self`) and
EXPIRES (`-`, the time left, or `expired`). An expired runtime entry is removed;
an expired configured entry stays listed until it is removed from the file.
Monitoring-group members may run `ignore list` with addresses redacted.

Each jail holds at most 128 entries, configuration and runtime combined; `self`
entries do not count. A jail with custom rules (`rule_files`) keeps its exclusions
in `ignore_file`; the commands refuse it and name the file. An exclusion never
unbans anything by itself.

## Jail controls and history

```bash
sudo fail2zig jail pause sshd
sudo fail2zig jail resume sshd
sudo fail2zig jail disable sshd
sudo fail2zig jail enable sshd
sudo fail2zig history reset 203.0.113.7 --jail sshd
```

Use pause/resume for processing control and enable/disable for jail state.
Pausing keeps the jail's bans installed; disabling releases them. Inspect the
returned outcome and current owners.

`jail disable` releases a jail's bans in bounded steps. On a jail holding many
bans it may answer `partial`; the remaining cleanup then finishes on its own
while the jail stays disabled, including across a restart, so do not repeat the
command. Watch `jails` and `status` instead; `jails` JSON carries
`disable_cleanup_pending`. `jail enable` cancels the remaining work, and bans
already released stay released. A scope shared with another jail stays installed
while that jail owns it. A disabled jail creates no bans from detection or
`banip`, and a manual `ban` needs the jail enabled first; `unban` still works.
 `history reset <ip> --all` resets that address's history across jails.
History reset is separate from removing active protection.

## Repair a paused source

```bash
sudo fail2zig repair-source --jail portsentry \
  --source /var/log/portsentry.log --token r1 --acknowledge-truncation
```

Under `on_truncation = "refuse"` a file source that lost continuity pauses while
the daemon keeps running. `status` prints the exact command. The command runs
through the daemon's socket while it is running, with the same
token, refusals and durable outcome as the offline form, and no jail's rules are
withdrawn. The offline form runs on a stopped daemon's state when the socket is
absent. Repeating the command replays the committed outcome; the newest 256
outcomes are kept. Lost records are recorded, not recovered. See the
[log file lifecycle](../guides/log-lifecycle.md#repair-source).

## Support bundle

```bash
sudo fail2zig support-bundle
sudo fail2zig support-bundle --out - --include-addresses > bundle.json
```

`support-bundle` writes one redacted JSON file for a bug report: versions, `status`,
`jails` and `stats` payloads, retained loss events, the effective configuration and
the SHA-256 of the configuration file, state-file page and per-table sizes, kernel
readback counts, memory, host basics and the last warnings and errors from the
daemon log (default 200 lines, at most 2,000). Run it as root; it also works while
the daemon is stopped. Addresses become `v4-<hash>` or `v6-<hash>` unless
`--include-addresses` is given; paths other than configured log paths become
`<path>`; the bundle carries no ban list. The default output is
`./fail2zig-support-<UTC time>.json`, mode 0600, never overwritten. Exit 4 means
the bundle was written with sections that record an error. Read the file before
attaching it. See the [support-bundle guide](../operations/support-bundle.md).

## Reload

```bash
sudo fail2zig reload
```

Reload validates a complete proposed generation before publishing it. An invalid
proposal leaves the running generation intact. Outcomes are `noop`, `applied`,
`rejected` or `restart_required`, with reasons identifying the boundary;
`rejected` and `restart_required` exit 1. A reload that committed but could not
confirm every effect reports `partial` (exit 4) or `uncertain` (exit 5).

| Live changes                                                                                                                                                                                                                           | Require restart                                                                                                                             |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| Per-jail maxretry, bantime/permanent policy, escalation and decay; literal `ignoreip` and `banip` entries and their durations; `ignoreself` and `ignoretime`; `history_max_matches`; adding or removing a jail; global log level; a custom jail's ignore file | Jail `enabled`, findtime, `enforce`/`banaction`, source/filter/log paths, `on_truncation`, timestamp/timezone settings, journal executable list, rule files, and every `[global]` key except `log_level` and `history_max_matches` |

The [configuration reference](config.md#what-a-reload-applies) lists every key.
An `ignoreip` edit applies from the next event and never alters an existing ban;
a `banip` edit bans or lifts at once. An added enabled jail starts in the same
reload. A removed jail's bans are lifted and its elements removed last, after
every other change has committed; its history is kept, so `history --jail <name>`
still shows it. One jail that fails validation rejects the whole reload with a
message naming it, and every running jail is unchanged.

Edit configuration for policy changes. fail2ban's runtime `set` API, arbitrary
regex mutation and dynamic actions are not supported. `SIGHUP` uses the same
reload boundary. A restart-required outcome is not confirmation that your edit
has taken effect.

## Exit classes

| Code | Class       | Operator meaning                                                                         |
| ---- | ----------- | ---------------------------------------------------------------------------------------- |
| 0    | success     | The operation completed or the read-only query was answered; inspect the returned state. |
| 1    | rejected    | Valid request refused or object absent.                                                  |
| 2    | usage       | Invalid arguments or local validation failure.                                           |
| 3    | unavailable | Socket missing, refused or timed out.                                                    |
| 4    | partial     | Durable effect applied but confirmation incomplete.                                      |
| 5    | uncertain   | Effect may have applied; outcome not established.                                        |

Use JSON for automation and branch on these classes, not formatted table text.
Refusals that are not outcome objects are printed on standard error.

`list` exits 1 when the ban set or the configuration changes while it pages
through a long listing; run it again. `status --details` can exit 1 or 3 after
printing the status when the loss-event query fails.

## Prometheus and HTTP alternatives

The daemon also serves read-only monitoring over HTTP, by default on
`127.0.0.1:9100`: `/metrics` for Prometheus, `/api/status` and `/api/health`.
There is no authentication; the bind address is the only access control.
`/api/bans` returns 403, and `/events` returns 400 because this release serves no
WebSocket stream. `metrics_enabled = false` removes the listener while the socket
stays available.

```bash
curl --fail http://127.0.0.1:9100/api/health
```

The [monitoring API reference](api.md) lists every endpoint, status field and
metric, the request limits, and the JSON error contract of these commands.

## Shell completions

```bash
fail2zig completions bash
fail2zig completions zsh
fail2zig completions fish
```

These print completion scripts. Install the output in your shell's completion
location under the `fail2zig` name.
