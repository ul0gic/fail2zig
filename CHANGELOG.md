# Changelog

What changed in each fail2zig release, newest first. Each entry says what the
change means for someone running the daemon. The full notes for supported
releases, with upgrade steps, known limitations and verification scope, are in
[RELEASE_NOTES.md](RELEASE_NOTES.md).

v0.4.7 is the minimum supported release. Entries marked retired are kept as
history: their downloads and Git tags have been removed, and installing or
rolling back to them is unsupported. To move between releases, follow the
[upgrade guide](docs/guides/upgrading.md).

Each group heading ends with its type in braces: `{feat}`, `{perf}`, `{fix}` or
`{sec}`. The website uses it to colour the group.

## 0.4.10 — unreleased

**A state file that stays bounded and a source that resumes by itself**

A storage release. A log source picks up again by itself after a wait or a storage
failure, `jails`, `status` and the storage cause tell the truth, the state file no
longer grows with every log line read, and a full state file costs new bans for a
while instead of stopping protection. How bans are detected and enforced is unchanged.

### Fixed {fix}

- `sources` **A source resumes without a restart.** After an ordinary wait or a storage
  failure on a log that kept growing, the source reads on from where it stopped, keeps
  the time it first received the line and counts the line once. In 0.4.9 the jail
  admitted no new bans until the daemon was restarted.
- `jails` **`jails` agrees with `status` after a restart.** Both read the same clock, so
  `jails` no longer shows protection as unconfirmed while `status` shows it active.
- `status` **The real storage cause.** A storage failure in the middle of a batch of
  records is reported as `StorageFull`, `Busy`, `StorageIo` or `ReadOnly`, not as
  `RestoreRequired`. When a jail is unhealthy, `Cause:` names that jail's source error
  instead of `unknown`, and the source appears as a `Waiting:` or `Broken:` row.
- `storage` **The state file stops growing with log volume.** The table that kept one row
  for every log line read is gone. A record is kept only while something needs it, and
  the transaction that admits a source's next records deletes the ones before them.
- `docs` **Example escalation doubles.** `deploy/fail2zig.toml.example` sets
  `bantime_increment_factor = 2` with multiplier 1, so repeat bans double up to the
  one-week cap; before, every repeat ban was a constant two hours.
- `docs` **Documentation follows the code.** `migrate status` lists its required
  `--backend`, `repair-source` lists exits 3 and 5 of its online form, the jail-name
  and `logpath` rules state what validation accepts, and the migration continuity page
  states that cutover carries no log position.

### Added {feat}

- `status` **Used pages.** `status` adds `Used pages: <used> of <pages> allocated`, JSON
  adds `state_file_used_pages` and `/metrics` adds `fail2zig_state_file_used_pages`:
  the pages in use, without the free pages the file keeps for reuse.
- `storage` **A page budget for the state file.** New work waits once used pages, plus
  the pages owed to bans and actions already admitted, reach 262,144 pages (1 GiB).
  Sources show `waiting (StorageCapacity)` without pausing; a manual `ban`, `ignore add`
  and a new `reload` are rejected with that cause; expiry, unban and cleanup keep
  writing and installed rules stay enforced. Under pressure the daemon gives up
  consumed history and memory first, counts and logs it, starts on a full file and
  resumes intake by itself. SQLite's own limit is 64 MiB higher. [Read the resource
  boundaries](docs/architecture.md#resource-boundaries)
- `escalation` **Capped per-address memory.** Escalation memory and retired retry rows
  hold at most 65,536 rows each. At the cap the least recently written address without
  a live ban is forgotten and logged; a ban never waits for a memory row.
  `bantime_increment_decay = 0` still disables forgetting by time.

**Schema 29 upgrade** On first start, a v0.4.9 state (schema 28) upgrades to schema 29
after `<state_file>.pre29-backup` is written; v0.4.8 and v0.4.7 states take their
earlier steps first. The step copies the whole state once for the backup, needs free
disk of twice the file plus 32 MiB, and drops the per-line table, so a state 0.4.9
filled recovers its pages. A start killed during the copy heals by itself; a start
killed between the backup's rename and the commit needs the operator step in the
[upgrade guide](docs/guides/upgrading.md). v0.4.9 and older refuse schema 29 with
`UnsupportedSchema`; rollback restores the backup with the v0.4.9 binary.

**Known limits** New work waits before the file is physically full. Under page
pressure, history and escalation memory can be given up before `history_retention`
would remove them. A full filesystem is outside the page budget: the daemon pauses
with `StorageFull` and recovers when space returns, but does not start on a full
filesystem. With the per-line table gone, a line counts twice if a defect or a manual
edit moves a source position backwards.

## 0.4.9 — 2026-10-26

**Matched lines in history, configured paths and many-jail startup**

A hardening release. `history` and `list` show the log line that triggered each
ban, every tool takes its paths from the configuration, and configurations with
more than ten jails start under the shipped service unit. How bans are detected,
enforced and stored is unchanged.

### Added {feat}

- `history` **Show what triggered a ban.** `history --details` and `list --details` show
  the stored matched line for each event, wrapped onto continuation rows in the terminal
  and complete in JSON as `matches`. `history_max_matches` (default 10, global and per
  jail) sets how many lines are kept per address; `0` keeps none.
  ([#123](https://github.com/ul0gic/fail2zig/issues/123))
- `status` **Missing log sources in `status`.** A configured log path with no file
  appears as a `Missing:` row, and JSON adds `missing_sources`.

### Changed {feat}

- `paths` **Configured paths are used everywhere.** Administrative commands and `migrate`
  use the configured `socket_path` when `--socket` is not given. A start refused because
  the service cannot write a configured directory names the directory and the unit
  override that grants it. The installer accepts a custom `state_file` and `socket_path`
  and prints the exact unit override; no fail2zig tool edits the unit.
  ([#124](https://github.com/ul0gic/fail2zig/issues/124))
- `startup` **More than ten jails start under the shipped unit.** The daemon raises its
  open-file soft limit to the hard limit the service grants, up to `native_fd_ceiling`,
  whose default is now 8192. 0.4.8 refused such configurations with `NativeFdAdmission`.
- `jails` **Large jails are disabled and removed in bounded steps.** The release of a
  jail's bans resumes after a restart, so a jail holding tens of thousands of bans no
  longer stops startup or reports done early.

### Security {sec}

- `http` **`/api/bans` returns 403.** Ban lists, history and firewall inventory over the
  socket require uid 0 or the daemon's uid; `fail2zig` group members keep aggregate
  status and metrics. Monitoring that read `/api/bans` must use `fail2zig list` as root.
- `sshd` **The SSH client address comes only from the connection's own field.** An
  address inside a user name or other client-supplied text no longer selects who is
  banned.

### Fixed {fix}

- `dns` **DNS cache space is freed when results expire,** including across restarts, for
  custom rules that resolve host names.

**Schema 28 upgrade** On first start, a v0.4.8 state (schema 26) upgrades to schema 28
after `<state_file>.pre27-backup` is written; a v0.4.7 state takes the v0.4.8 step
first. The step adds columns and tables only, so its time does not grow with the state.
v0.4.8 and older binaries refuse schema 28 with `UnsupportedSchema`; rollback restores
the backup with the v0.4.8 binary.

**Known limits** Above about twenty jails the default `native_memory_ceiling_mb` (512)
refuses startup with `NativeMemoryAdmission`; raise it for larger configurations. A
file write refused near the state file's size cap can be reported as `RestoreRequired`
instead of `StorageFull`.

## 0.4.8 — 2026-10-22

**Capacity, log lifecycle and parity**

Built on the report of a production install whose PortSentry jail stalled at 2,048 bans.
All jails share one pool of 65,536 tracked addresses and 65,536 live bans, a missing log
is told apart from a truncated one, every ban carries a visible origin, and a healthy
stop leaves installed rules in the kernel.

### Capacity and log lifecycle {feat}

- `capacity` **One shared tracking pool.** 65,536 tracked addresses and 65,536 live bans
  across all enabled jails, not per jail. A live ban holds no tracking entry. A jail
  that reaches a limit shows `waiting (RetryCapacity)` in `jails` and resumes as room
  frees instead of pausing. ([#117](https://github.com/ul0gic/fail2zig/issues/117))
- `file input` **A missing log is not a truncation.** A log absent at start or deleted
  while the daemon runs shows `missing (FileNotFound)` in `jails`; the source stays
  healthy, protection is not degraded, and reading resumes when the file appears.
  Truncation and replacement remain continuity-loss events under `on_truncation`. [Read
  the log file lifecycle](docs/guides/log-lifecycle.md)
  ([#118](https://github.com/ul0gic/fail2zig/issues/118),
  [#107](https://github.com/ul0gic/fail2zig/issues/107))
- `storage` **State file ceiling raised to 1 GiB.** Was 256 MiB. `status` shows the file
  size and page use against the ceiling and the tracking pool against its limits. The
  file never shrinks; freed pages are reused inside it.

### Configured bans and origins {feat}

- `policy` **Configured ban lists with a visible origin.** `banip` in `[defaults]` and
  per jail bans addresses and CIDRs while they are listed, applied at start and on
  `reload`. Every ban carries one origin, `detection`, `manual` or `config`, shown by
  `list`, `history` and `firewall show`; `list --origin` filters on it. `ban` and
  `unban` on a config ban are refused.
  ([#103](https://github.com/ul0gic/fail2zig/discussions/103))
- `exclusions` **Timed entries and expiring exclusions.** `banip` and `ignoreip` entries
  take an optional duration (`"198.51.100.0/24 1d"`) that runs once from first apply.
  `ignore add --for` records an exclusion that lapses on its own, `ignore list` shows
  EXPIRES, and `ignoretime` sets the default life of an entry without one.
- `safety` **Lockout guard and `ignoreself`.** The host’s own addresses join every
  jail’s ignore list with source `self`. `ban` refuses a loopback, host or SSH-peer
  address before it opens the socket and names `--force` as the override. The guard is a
  client-side refusal, not an ignore rule.
- `escalation` **Escalation decays.** `bantime_increment_decay` (default 30 days,
  measured from the ban’s end) resets escalation to the base `bantime`; `0` disables it.
  After a manual `unban`, failures count from zero while escalation memory is kept.

### Operator commands {feat}

- `repair` **`repair-source` runs online.** Through the daemon’s socket while it is
  running, with the same token and durable outcome as the offline form, so acknowledging
  a loss no longer withdraws any jail’s rules.
- `reload` **Jails are added and removed on `reload`.** An added jail starts in the same
  reload; a removed jail’s bans are lifted, its elements removed and its history kept.
  One invalid jail rejects the whole reload and leaves every running jail unchanged.
- `firewall` **`firewall withdraw`.** Removes every rule the daemon realized and holds
  enforcement off until the next start; `status` reports `DEGRADED (FirewallWithdrawn)`.
  Run it before stopping when the table must be empty.
- `diagnostics` **`support-bundle` and per-jail metrics.** One redacted JSON file for a
  bug report, with addresses hashed unless `--include-addresses` is given. New series
  `fail2zig_jail_bans_active`, `fail2zig_jail_bans_total`,
  `fail2zig_jail_failures_counted_total`, `fail2zig_jail_ignored_detections_total`,
  `fail2zig_jail_source_state`, `fail2zig_jail_pool_evictions_total`,
  `fail2zig_state_file_bytes` and `fail2zig_state_file_pages`.
- `logging` **Audit lines, JSON logs and help everywhere.** One audit line per mutation
  with target, caller UID and outcome. `log_format = "json"` writes one JSON object per
  daemon log line. Every command has `help <command>` or `--help`; a mistyped command
  exits 2 with a suggestion. Refusals that are not outcome objects go to standard error.
- `security` **Threat model published with the source.** `docs/security/threat-model.md`
  records assets, trust boundaries and each threat with its control. [See the site
  threat model](docs/security/threat-model.md)

### Kernel-confirmed enforcement {perf}

- `nftables` **Installs confirmed by the kernel, drift by events.** Each install batch
  is confirmed by the kernel’s acknowledgement and drift is detected from nf_tables
  change events, with a full audit of the owned set every 60 seconds instead of a
  readback after every mutation. Measured on `f2z-target` (Debian 13, kernel 6.12, 8
  vCPU, 16 GiB): idle at 65,536 installed bans fell from 21 % to 12 % of one core; with
  20,000 bans, 3.5 %.
- `ingest` **Grouped commits and batched installs.** Admitted records commit in groups
  with one fsync and pending bans install in batches on all three backends. Ingest
  through one file source went from 5 to 79 records per second on the same host, with
  bans enforced inside the burst and no acknowledged record lost or re-read after `kill
  -9`.
- `restart` **Installed rules survive a healthy stop.** Every element carries its kernel
  timeout, so a stop at 65,536 bans takes about one second, and a restart reinstalls
  live bans in batches: readiness in 373 s at 65,536 bans on the same 8 vCPU host. These
  are measurements on that host, not guarantees.

**Schema 26 upgrade** On first start, schema 25 upgrades to 26 in one transaction after
`<state_file>.pre26-backup` is written; the backup needs free space of twice the
database size plus 32 MiB and an existing backup refuses the start. Every existing ban
gets origin `detection`. v0.4.7 is the only supported upgrade source; a v0.4.6 state
goes through v0.4.7 first. v0.4.7 and older binaries refuse schema 26 with
`UnsupportedSchema`; rollback restores the backup with the v0.4.7 binary. See the
[installation guide](docs/operations/installation.md) and [upgrade
guide](docs/guides/upgrading.md).

**Behavior changes** The default `native_memory_ceiling_mb` is now 512; a configuration
that sets 256 explicitly must raise it or the daemon refuses with
`NativeMemoryAdmission`. A healthy stop leaves installed rules in the kernel and no
longer unbans anyone; run `firewall withdraw` first for an empty table.

**Known limits** `status` does not yet list a missing log; `jails` and
`fail2zig_jail_source_state` do. The per-ban footprint did not shrink (about 6 to 7 KiB
of state per live ban). The full-pool eviction path is proven on the component rig only.
Event-driven drift detection is nftables-only; ipset and iptables keep their readback
cadence. Large curated lists are not a job for bans; a list loader is under design in
discussion #120. Live qualification is x86_64 only.

## 0.4.7 — 2026-10-14

**Stabilization at 2,000 bans**

Built on the reports from a production install running 2,000 bans. Idle CPU at that size
drops from about 56 % of one vCPU to under 3 %, a healthy stop takes one second instead
of 49, file sources that lose data on a reboot resume under a per-jail policy, and
per-jail exclusions are managed at runtime. v0.4.7 is the oldest supported release and
the required hop for a v0.4.6 state before v0.4.8.

### Steady-state cost {perf}

- `idle` **Idle CPU at 2,000 bans under 3 %.** The jail view is published only when it
  changes, effect owners are confirmed by key lookup, and the journal source waits one
  second after an empty poll instead of spawning `journalctl` seven times a second.
  Measured on a one-vCPU, 4 GiB Debian 13 host with 2,000 nftables bans: mean 2.61 %,
  maximum 6.0 % over five minutes.
  ([#99](https://github.com/ul0gic/fail2zig/discussions/99),
  [#108](https://github.com/ul0gic/fail2zig/issues/108))
- `stop` **A healthy stop takes one second.** Realized rules are withdrawn in batches:
  about one second in 32 turns instead of 49 seconds in 2,000 at 2,000 bans.
  ([#109](https://github.com/ul0gic/fail2zig/issues/109))

### Operator control {feat}

- `file input` **Per-jail `on_truncation` policy.** `refuse` (the default) pauses the
  source until `repair-source` acknowledges the loss while the daemon keeps running;
  `restart` resumes at the new start of the file and records a durable continuity-loss
  event. Both cover a log truncated in place and a log replaced after its previous file
  is gone, as PortSentry does at every start. `status` lists paused sources and loss
  events. ([#98](https://github.com/ul0gic/fail2zig/issues/98),
  [#112](https://github.com/ul0gic/fail2zig/issues/112))
- `exclusions` **Runtime exclusions.** `ignore add`, `ignore remove` and `ignore list`
  manage per-jail entries that survive restart and reload and merge with the configured
  `ignoreip`. An existing ban stays until its deadline unless `--unban` is given. Each
  jail holds at most 128 entries, configuration and runtime combined.
  ([#103](https://github.com/ul0gic/fail2zig/discussions/103))
- `reload` **`ignoreip` edits apply with a reload.** Literal ignore-list edits no longer
  return `restart_required`, and a jail can be added or enabled on an existing state
  without recreating it. ([#110](https://github.com/ul0gic/fail2zig/issues/110),
  [#113](https://github.com/ul0gic/fail2zig/issues/113))
- `portsentry` **Stealth and UDP detection qualified.** PortSentry 2.0.7 `--stealth -m
  pcap -i <interface>` detection for TCP SYN, FIN, NULL and XMAS scans and for UDP, in
  addition to `--connect`, each through ban, blocking while banned and expiry. Legacy
  1.2 and other 2.x versions stay unqualified. [Read the setup
  guide](docs/guides/portsentry.md)
  ([#75](https://github.com/ul0gic/fail2zig/discussions/75))

### Fixes {fix}

- `storage` **Committed receipts are cleaned behind held bans.** Held receipts are set
  aside and deleted once their ban and retry window end, and everything behind them is
  cleaned in order. Long or permanent bans previously retained every receipt behind the
  oldest live ban until the state cap paused ingestion.
  ([#104](https://github.com/ul0gic/fail2zig/issues/104))
- `enforcement` **An expired lease is never dispatched.** A ban whose lease had already
  ended was re-sent with a past deadline, refused by nftables and treated as backend
  uncertainty, which paused ingestion under short ban times. Such an owner now takes the
  expiry path. ([#111](https://github.com/ul0gic/fail2zig/issues/111))
- `file input` **A recreated log resumes.** A log recreated while the daemon runs is
  read without loss, and the old, unlinked file retires instead of counting against the
  source limit. ([#114](https://github.com/ul0gic/fail2zig/issues/114))
- `nftables` **Coherent set readback.** The set is read back as one coherent netlink
  observation and an interrupted dump is retried instead of trusted; `stats` reports the
  retries.

**Schema 25 upgrade** On first start, a state last written by v0.4.6 (schema 24)
upgrades to schema 25 after `<state_file>.pre25-backup` is written; the upgrade needs
free space of twice the database size plus 32 MiB and resumes if interrupted. v0.4.6 was
the only supported upgrade source for this release, and rollback restores the backup
with the v0.4.6 binary. Saved detection generations are rekeyed once at the first start.

**Known limits at 0.4.7** The state file was capped at 256 MiB (raised to 1 GiB in
v0.4.8) and never shrinks. A stopped daemon left its empty reserved nftables table, so a
second installation on the same host refused to start with `ForeignState`. At 2,000 bans
one status sample in 300 could report protection knowledge about five seconds old during
idle; stale status is not confirmation of current kernel protection. Admin refusals were
printed on standard output (moved to standard error in v0.4.8). Live qualification is
x86_64 only.

## 0.4.6 — 2026-09-28

**Clearer operator commands and output** (retired: downloads and tag removed)

Sort ban lists numerically, inspect published runtime statistics on demand, and
distinguish configured jail mode from observed protection. Command output and help are
clearer.

### Operator commands {feat}

- `ban lists` **Optional numeric IP sorting.** `fail2zig list --sort` orders IPv4 before
  IPv6 in table, plain and JSON output. The default order is unchanged.
- `diagnostics` **Runtime statistics on demand.** `fail2zig stats` and `stats --details`
  show the worker's published snapshot, its age and counters accumulated since daemon
  start.

### Output clarity {fix}

- `jails` **Configured mode and observed protection are separate.** Unknown ban counts
  remain unknown, and detailed jail information stays complete on narrow terminals.
- `logging` **Quieter routine logs.** Periodic effect-view diagnostics now log at debug
  level; use `stats` when needed.

**Upgrade** Upgrading from v0.4.5 keeps schema 24. Upgrade and restart the daemon to use
`stats`. See the [installation guide](docs/operations/installation.md) and [upgrade
guide](docs/guides/upgrading.md).

## 0.4.5 — 2026-09-27

**Storage recovery and protection continuity** (retired: downloads and tag removed)

Repairs load-triggered storage intervention, populated-state restart and recovery after
a truncated file source. Expiry cleanup and firewall readback handling improve under
load; reload and migration rollback preserve other protection owners. No new
integrations.

### Fixes {fix}

- `storage` **Ingestion continues through the reproduced load incident.** Bounded
  retention and recovery work repaired the 199-ban storage intervention. The final
  short-incident qualification covered 210 bans and packet controls; it does not
  establish sustained-load latency.
- `restart` **Populated state restores original ban deadlines.** Startup extends its
  systemd notification timeout while making progress, without reporting readiness early.
- `file input` **Truncated sources have an explicit recovery path.** Offline
  `repair-source` acknowledges a continuity break. It cannot recover log entries lost to
  truncation.
- `firewall` **Less repeated readback and settlement work.** Expiry and cleanup work
  improve under load, and transient backend uncertainty no longer pauses otherwise
  healthy ingestion. nftables, iptables and ipset remain supported.
- `ownership` **Reload and migration rollback retain other owners.** Generation-changing
  reload preserves live bans and absent-owner history; migration rollback releases only
  its own decisions.
- `CLI` **Firewall help lists `--details`.** The already-supported flag now appears in
  `firewall --help` usage.

**Schema 24 upgrade and rollback** On first start, native schema 23 upgrades to 24 after
a coherent pre-upgrade backup is created. Keep that backup with the matching old binary.
Older binaries refuse upgraded state; restoring the backup loses decisions made since it
was taken. Stop the daemon and follow the [installation and upgrade
guide](docs/operations/installation.md). For truncated file input, use the documented
[fail2zig(1) repair-source procedure](docs/man/fail2zig.1); missing logs cannot be
recovered.

**Known limits** A sustained workload on a small HDD-backed VM installed every subject
but had p95 append-to-kernel latency of 57 seconds. A separate 400-ban restart hold can
report stale protection knowledge and degraded status; observed runs retained 400
reported active bans and healthy storage, but the cause and full duration remain under
investigation. Stale status does not confirm current kernel protection. Live-kernel
release qualification is Debian 13 x86_64; the other four architectures have cross-build
and emulated checks.

## 0.4.4 — 2026-09-23

**Recovery, enforcement and retention fixes** (retired: downloads and tag removed)

A bug-fix release for startup on populated state, firewall expiry readback, prompt ban
reconciliation and bounded retry history. No new features or configuration options.

### Fixes {fix}

- `startup` **Populated state recovers at startup.** Removes a stale maintenance fence
  and page-at-a-time delay that could prevent the daemon from becoming ready.
  ([#84](https://github.com/ul0gic/fail2zig/issues/84))
- `firewall` **Expected element expiry stays transient.** Elements that expire between
  readback passes no longer put otherwise healthy enforcement into persistent
  intervention. Structural or foreign firewall changes remain unsafe.
  ([#83](https://github.com/ul0gic/fail2zig/issues/83))
- `enforcement` **New bans continue through reconciliation.** Advances reconciliation
  after full readback and reclaims spent effect records after their live work is
  settled. ([#85](https://github.com/ul0gic/fail2zig/issues/85))
- `storage` **Old retry detail can be reclaimed.** Eligible history is cleared before
  accumulated rows block new decisions. Current owners, retained confirmations and
  unsettled actions stay protected.
  ([#86](https://github.com/ul0gic/fail2zig/issues/86))

**Preserve a coherent rollback backup** Schema remains 23 and the stored record format
is unchanged. Older binaries cannot read checkpoint and marker data introduced in
v0.4.3. Restore a matching binary and coherent state backup for rollback; swapping only
the executable is insufficient. [Read the current upgrade
guide](docs/guides/upgrading.md)

## 0.4.3 — 2026-09-22

**PortSentry scan detection and more resilient ingestion** (retired: downloads and tag
removed)

Connect PortSentry’s scan events to durable fail2zig enforcement, keep processing
malformed file logs, and avoid cleanup failures that could stop affected ingestion.

### Features {feat}

- `portsentry` **A qualified scan-detection recipe.** PortSentry v2.0.7 history-file
  input supports TCP-connect scan detection with IPv4 and IPv6. The Debian 13
  qualification covered nftables bans, expiry and restored connectivity. Ignored,
  pre-threshold and sensor-blocked records are excluded. [Read the setup
  guide](docs/guides/portsentry.md)
  ([#81](https://github.com/ul0gic/fail2zig/issues/81))

### Fixes {fix}

- `storage` **Escalation history cleans up in the correct order.** Fixes SQLite
  foreign-key errors during escalation-history cleanup that could stop affected
  ingestion. ([#79](https://github.com/ul0gic/fail2zig/issues/79))
- `file input` **Malformed encoding no longer stalls file ingestion.** Invalid bytes are
  replaced and processing continues, with source progress preserved and replacements
  reported. Journal input remains strict.
  ([#80](https://github.com/ul0gic/fail2zig/issues/80))

**Preserve your rollback state** Schema remains 23, but older binaries cannot read the
extended processor checkpoints and marked dispositions. Rollback requires a coherent
pre-upgrade state backup and its matching binary. Swapping only the executable is
insufficient. [Read the current upgrade guide](docs/guides/upgrading.md)

## 0.4.2 — 2026-09-21

**Firewall observability and clearer operator diagnostics** (retired: downloads and tag
removed)

See what fail2zig intended to install, what its latest firewall inspection verified, and
where fail2zig-owned protection is attached.

### Features {feat}

- `firewall` **Read-only firewall observation.** `firewall show` reports the daemon’s
  latest retained inspection of fail2zig-owned kernel protection without refreshing,
  repairing or changing firewall state.
- `commands` **Expandable operator tables.** `--details` expands table output for
  `status`, `jails`, `list` and `firewall show` with identifiers, thresholds, counters
  and verified structure or placement when available. Plain and JSON output are
  unchanged by the flag.
- `nftables` **Native kernel inspection.** nftables observation communicates directly
  with the kernel and does not require the `nft` executable.

### Diagnostics and maintenance {fix}

- `health` **More stable protection-health reporting.** Routine worker activity retains
  the last verified protection view, while actual storage, source, clock, expiry and
  firewall-readback faults remain visible.
- `maintenance` **Focused cleanup and test fixes.** Matching client and daemon versions
  render more clearly, cleanup no longer treats ignored or unenforceable evidence as
  retry work, and startup/import test coverage is tighter.

**Observation boundary** This is a bounded retained snapshot of fail2zig-owned
protection in the daemon’s current network namespace—not a live ruleset scan or proof of
packet reachability. A successful query means the request was answered, not that
protection is healthy. [Read the command
reference](docs/reference/cli-fail2zig-client.md#firewall-observation)

## 0.4.1 — 2026-09-18

**Reliable SSH journal startup and better diagnostics** (retired: downloads and tag
removed)

Built-in SSH journal jails can again discover trusted executable paths when no explicit
profile is supplied, while status and startup failures provide more useful causes.

### Fixes {fix}

- `journald` **Trusted SSH executable discovery restored.** Built-in SSH jails use a
  bounded catalog of standard root-owned executable paths when `journal_executables` is
  omitted. Explicit profiles remain exact overrides; custom journal rules still require
  one.
- `diagnostics` **Actionable startup and health causes.** Status, jail, storage and
  firewall diagnostics retain more context, including source failures, journal child
  results and saved backend or namespace conflicts.

## 0.4.0 — 2026-09-16

**One executable. Durable native state.** (retired: downloads and tag removed)

Daemon and administration now share one executable. Native SQLite persistence keeps
source progress and protection state durable, configuration accepts readable durations,
and the service runs under a dedicated account.

**Upgrade note** There is no automatic converter for 0.3.0 binary state. Preserve the
old installation for rollback and plan the protection transition. This is separate from
supported fail2ban schema-4 migration. The installer never starts or restarts services;
custom state paths require explicit handling. [Read the current upgrade
guide](docs/guides/upgrading.md)

### Features {feat}

- `commands` **Daemon, administration and migration in one executable.** Use `fail2zig
  <command>` instead of `fail2zig-client`. The same binary includes offline `rule-test`
  and the supported inspect/snapshot/plan/validate/cutover/status/rollback workflow. No
  separate client asset ships.
- `persistence` **Native runtime state moves to embedded SQLite.** Durable receipts,
  source checkpoints, retries, protection ownership, effect intent and confirmed history
  share one store. Pinned SQLite C is statically embedded; no database server, SQLite
  CLI or shared SQLite library is required.
- `configuration` **Readable configuration durations.** Use quoted values such as
  `"24h"` and `"1h30m"` for bantime, findtime, escalation cap and jitter. Integer
  seconds remain valid. Only bantime accepts `"permanent"`; CLI duration and timeout
  arguments remain numeric.

### Service identity {sec}

- `installation` **A dedicated non-login service account.** The unit runs as `fail2zig`,
  with a configurable service/monitor group. Group access is read-only; root or the
  daemon UID administers protection. Guarded offline ownership transitions cover
  verified default native SQLite paths and WAL/SHM siblings.
- `privileges` **Explicit capability and HTTP boundaries.** The daemon retains
  NET_ADMIN, NET_RAW and DAC_READ_SEARCH. NET_RAW supports the iptables ipset extension
  and permits raw IP sockets. HTTP shares these privileges and defaults to loopback;
  disabling metrics removes HTTP/WebSocket while IPC remains available.

### Qualification and limits {fix}

- `release` **Five static architecture builds retained.** Selected live Debian 13 x86_64
  checks preceded the version-only update from the unpublished 0.3.1 candidate. Rebuilt
  0.4.0 artifacts passed native/emulated checks. ARM64, ARM and both MIPS byte orders
  have cross-build, ELF and QEMU smoke evidence; non-x86 hardware enforcement and Ubuntu
  remain untested.
- `known limits` **Keep default loopback ignores.** A matching loopback SSH failure with
  ignores removed can lead to storage intervention. Firewall effects stay in the
  daemon’s current network namespace; custom namespace selectors and service overrides
  that move it between namespaces are unsupported.

## 0.3.0 — 2026-09-09

**More reliable enforcement and recovery** (retired: downloads and tag removed)

Observe-only operation becomes explicit, repeat-offender escalation works on a default
install, and journald polling no longer blocks the event loop. Includes MIPS release
binaries.

**Upgrade note** Older state files load unchanged; the first save writes v4.
Hand-managed configurations may need permissions corrected to `0640`.

Validated on a Debian 13 host with the shipping static binary. Thanks to @mwriter for
the first external bug report (#45).

### Security {sec}

- `config` **Unsafe configuration permissions are rejected.** A world-writable or
  non-root-group-writable `config.toml` is now **refused at load** with its mode and the
  fix (`chmod 0640`); a non-root owner warns. The installer already writes
  0640; hand-managed configs may need the chmod.
  ([d45a91d](https://github.com/ul0gic/fail2zig/commit/d45a91d))

### Features {feat}

- `firewall` **Explicit observe-only operation when no firewall is available.**
  `on_no_backend = "fail-closed" | "log-only"` (default `fail-closed`, ADR-007). With
  `log-only`, a host with no usable backend runs `DEGRADED` observe-only instead of
  exiting; the cause (missing `CAP_NET_ADMIN`, no nf_tables, transient) is in `status`,
  `/api/status`, `/metrics` and the event stream. A config whose jails are all log-only
  needs no backend and runs unprivileged. Never silent, never the default.
  ([d45a91d](https://github.com/ul0gic/fail2zig/commit/d45a91d))
- `recidive` **Repeat offenders escalate without a separate log file.** `recidive` is
  fed in-process from confirmed enforced bans in the other jails via a new `internal`
  source (ADR-013). No log file, no `logpath`; the shipped default config escalates
  repeat offenders for the first time.
  ([d45a91d](https://github.com/ul0gic/fail2zig/commit/d45a91d))
- `config` **Configuration errors point to the exact location.** Errors carry
  `file:line:col`, key and section (`config: /etc/fail2zig/config.toml:37:1: UnknownKey
  (key 'logpaht' in [jails.sshd])`); duplicate keys in a section are rejected;
  `--validate-config` prints one resolution line per jail. `backend` is accepted as a
  deprecated fail2ban alias of `source` (`systemd` → journald) with one warning per use;
  the importer emits `source` (#45).
  ([d45a91d](https://github.com/ul0gic/fail2zig/commit/d45a91d))
- `release` **MIPS binaries join the release targets.** `mips-linux-musleabi` and
  `mipsel-linux-musleabi` static binaries (soft-float MIPS32r2), built and smoke-tested
  under qemu in CI (ADR-012). No real-hardware report yet; `install.sh` detects both
  byte orders. ([d45a91d](https://github.com/ul0gic/fail2zig/commit/d45a91d))

### Performance {perf}

- `journald` **Journald polling stays off the blocking path.** journald polling no
  longer blocks the event loop: `journalctl` runs as a non-blocking child on the loop,
  no threads added (ADR-011). IPC p99 under journald load **4 ms** (was 21 ms).
  ([d45a91d](https://github.com/ul0gic/fail2zig/commit/d45a91d))
- `ipc` **Status requests return faster.** Status round-trip p99 **under 1 ms** (was 3–6
  ms): client and response buffers are pooled at startup instead of mapped per
  connection. ([d45a91d](https://github.com/ul0gic/fail2zig/commit/d45a91d))

### Fixes {fix}

- `state` **Observe-only entries stay unenforced after a restart.** A log-only would-ban
  was persisted as a real ban and **reinstalled in the firewall** by reconcile after a
  restart; expiry then called the backend to unban it. State v4 records
  enforcement; reconcile and expiry act only on enforced entries. v1–v3 files load; the
  first save writes v4. ([d45a91d](https://github.com/ul0gic/fail2zig/commit/d45a91d))
- `journald` **Journald polling retains entries and closes descriptors.** One file
  descriptor leaked per poll in the loop-driven path, and entries logged
  between service start and the first poll were dropped as history. Both found
  on the real-box gate, both under regression tests.
  ([d45a91d](https://github.com/ul0gic/fail2zig/commit/d45a91d))
- `persist` **Volatile state paths produce a startup warning.** `state_file` under
  `/run` or tmpfs now warns at startup that state will not survive a restart; every save
  logs path and bytes (found on the demo box after 94 days of silently wiped
  state). State was also saved twice on SIGTERM.
  ([d45a91d](https://github.com/ul0gic/fail2zig/commit/d45a91d))
- `firewall` **Firewall startup failures explain their cause.** Detection names its
  cause (`KernelUnsupported` / `PermissionDenied` / `Transient`) and the nftables probe
  is a read-only `GETGEN`, so a missing `CAP_NET_ADMIN` is reported at detect time
  instead of as a generic init failure; non-root no longer reads `NotAvailable`. Known
  startup failures exit 1 with the cause and no error-return-trace.
  ([d45a91d](https://github.com/ul0gic/fail2zig/commit/d45a91d))
- `client` **Client output handles long values and closed pipes.** Every table column
  sizes from its longest value; `Protection: DEGRADED (<cause>)` rendered; a closed
  stdout pipe (`| head`) is a quiet exit.
  ([d45a91d](https://github.com/ul0gic/fail2zig/commit/d45a91d))

## 0.2.2 — 2026-06-06

**Log rotation fixes and clearer jail health** (retired: downloads and tag removed)

Fixes a protection failure when file jails share a directory. Each jail now reports the
log source it actually reads and the health of that source.

**Upgrade note** Drop-in binary replacement. State v2 migrates to v3 on the first
checkpoint. The log-rotation fix affects file sources; journald sources were not
affected.

### Security {sec}

- `watcher` **File jails keep watching after log rotation.** Multiple file jails
  watching the same directory could **silently stop banning after the first log
  rotation** — a real protection failure. inotify dedups the parent-directory
  watch, but the watch table mapped one directory to one jail, so after a rotate the
  other jails stopped consuming events. Affects v0.2.1 and earlier; journald sources
  were never affected. Disclosed via a release-notes security callout; an e2e harness on
  a real host now locks it in.
  ([ced6e0e](https://github.com/ul0gic/fail2zig/commit/ced6e0e))

### Features {feat}

- `status` **Jail status reports the actual source and its health.** Honest per-jail
  capability and health surface. `status`, `/api/status`, `/metrics`, and the
  WebSocket stream now report each jail's *resolved* log source and read-health,
  populated `Total bans` / `Jails` rollups, and a `DEGRADED` state. The SOURCE label
  comes from the live source that owns the jail, so it can't disagree with runtime
  behavior — a journald-only `sshd` jail reports `journald (sshd)`, not the `auth.log`
  it never reads, and a file jail with an absent log shows its configured path so a typo
  stays visible. Observability only; banning logic unchanged.
  ([56cdd51](https://github.com/ul0gic/fail2zig/commit/56cdd51))

### Performance {perf}

- `startup` **Cold startup drops to about 20 milliseconds.** Cold start down to **~20
  ms** (was ~98 ms) via lazy state-tracker initialization — the ceiling-derived
  entry table is allocated on first use rather than at boot.
  ([ced6e0e](https://github.com/ul0gic/fail2zig/commit/ced6e0e))

### Fixes {fix}

- `health` **Detached log sources affect protection status.** File-source read-health
  now drives `DEGRADED` honestly — a structural was-attached→detached signal,
  so quiet, rotating, and not-yet-created logs never false-flag as unhealthy.
  ([ced6e0e](https://github.com/ul0gic/fail2zig/commit/ced6e0e))
- `state` **Lifetime ban counts survive restarts.** `Total bans` is now a persisted
  per-jail lifetime counter. It had been a per-process count that reset on
  restart and could read *less* than `Active` once restored bans came back. It now
  persists (state v2→v3, back-compat seeded), counts new bans only, and stays `≥ Active`
  across restarts; `/metrics` and the human surface read the same value.
  ([56cdd51](https://github.com/ul0gic/fail2zig/commit/56cdd51))
- `firewall` **Backend errors identify the failure.** Backend-unavailable errors now
  carry cause-distinct messages (no kernel nf_tables / missing `CAP_NET_ADMIN` /
  transient), a batch-error fix in `drainAck`, and a clean fail-closed exit with no
  error-return-trace.
  ([ced6e0e](https://github.com/ul0gic/fail2zig/commit/ced6e0e))
- `memory` **Unused memory-budget scaffolding is removed.** Removed the dead
  `BudgetAllocator` / `MemoryPool` byte-budget scaffolding — the state-tracker
  entry cap with eviction is the sole memory-ceiling mechanism, and the docs now say
  exactly that. ([ced6e0e](https://github.com/ul0gic/fail2zig/commit/ced6e0e))

## 0.2.1 — 2026-05-31

**Consistent versions, more precise documentation** (retired: downloads and tag removed)

The daemon and client report consistent versions. Documentation now describes the
state-tracker entry cap and direct nftables integration accurately.

### Fixes {fix}

- `version` **Both binaries use one version source.** Version reporting is consistent
  across every surface. The string had been hardcoded in four places that
  drifted — the shipped v0.2.0 `fail2zig-client` reported `0.1.1`. `build.zig` now holds
  a single `fail2zig_version` injected into both binaries via a generated
  `build_options` module; a regression test pins them to the same source.
  ([fe8a332](https://github.com/ul0gic/fail2zig/commit/fe8a332))
- `cli` **The client displays the daemon version.** `fail2zig-client version` now shows
  the daemon version. The daemon emitted `version` while the client parsed
  `daemon_version`, so the daemon line was silently dropped; the field name is now
  contract-pinned by a test.
  ([fe8a332](https://github.com/ul0gic/fail2zig/commit/fe8a332))
- `docs` **Memory and nftables documentation matches the implementation.**
  Memory-ceiling documentation reconciled with reality: the ceiling bounds the
  state tracker via a ceiling-derived entry cap with eviction, the parser hot path is
  zero-alloc — not a per-component byte budget. Also documented that the **nftables
  userspace package is not required** ; fail2zig programs nf_tables directly via
  netlink, verified on a box with `nft` absent.
  ([fe8a332](https://github.com/ul0gic/fail2zig/commit/fe8a332))

## 0.2.0 — 2026-05-31

**Configured filters and actions take effect** (retired: downloads and tag removed)

Fixes false bans by applying each jail’s configured filter and honoring observe-only
actions. Adds journald sources, ARMv7 binaries, and build-provenance attestations.

**Upgrade note** Unknown filters now fail closed. Review each jail’s configured filter
and action when upgrading.

### Security {sec}

- `filter` **Each jail uses its configured filter.** Critical severity: the runtime
  now applies each jail's **configured filter**. It had been matching every jail with a
  permissive default (`<*><IP>` — "any line containing an IP"), so benign IP-bearing
  lines could ban: sshd's `Server listening on 0.0.0.0` on restart banned
  `0.0.0.0`/`::`, and a successful login counted as an attempt. Unknown filters now
  **fail closed** ; a guard never bans unspecified/loopback addresses.
  ([2de416e](https://github.com/ul0gic/fail2zig/commit/2de416e))
- `release` **Release binaries include build-provenance attestations.** SLSA
  build-provenance attestation on every released binary (verifiable with `gh attestation
  verify`), plus supply-chain hardening of CI: every Action SHA-pinned, the one
  third-party release action replaced with native `gh release create`, per-job
  least-privilege permissions.
  ([2de416e](https://github.com/ul0gic/fail2zig/commit/2de416e))
- `ipc` **Group members can use the local client.** Socket and `/run/fail2zig` are
  chowned to `root:fail2zig` (dir 0750, socket 0660) so `fail2zig`-group members use the
  client without root, matching the SO_PEERCRED model; degrades safely when the group is
  absent. ([2de416e](https://github.com/ul0gic/fail2zig/commit/2de416e))

### Features {feat}

- `source` **SSH jails can read the systemd journal.** journald log source for sshd
  jails. A jail can set `source = journald` (or leave the default `auto`) to
  read auth events from the systemd journal instead of a text logpath — the
  modern-distro path where `/var/log/auth.log` doesn't exist. `auto` resolves by file
  *existence*, so the default sshd jail protects out-of-box on a journald-only host.
  ([2de416e](https://github.com/ul0gic/fail2zig/commit/2de416e))
- `status` **Status distinguishes enforcement from observation.** Enforcement posture in
  `status`: `Protection: active | log-only | mixed`, and per-jail `action`
  + `enforcing` in `jails` — computed from the same resolver the ban path uses, so it
  can't disagree with actual behavior.
  ([2de416e](https://github.com/ul0gic/fail2zig/commit/2de416e))
- `release` **ARMv7 binaries join the release targets.** armv7 (`arm-linux-musleabihf`)
  release binaries now cross-compile and build in the CI + release matrices.
  ([2de416e](https://github.com/ul0gic/fail2zig/commit/2de416e))

### Fixes {fix}

- `action` **Observe-only jails leave the firewall unchanged.** `banaction` is now
  honored at runtime. A `log-only` jail records a would-ban + metrics but no
  longer mutates the firewall or emits `ip_banned`; previously `banaction` was parsed
  and then ignored, so `log-only` jails created real bans.
  ([2de416e](https://github.com/ul0gic/fail2zig/commit/2de416e))
- `install` **Configuration validation works on a fresh install.** Fresh-install
  onboarding: `--validate-config` no longer hard-fails on a missing
  runtime socket dir (created at startup), which broke the documented quickstart on
  every fresh box. Verified on a clean Debian 13 install.
  ([2de416e](https://github.com/ul0gic/fail2zig/commit/2de416e))
- `build` **32-bit ARM builds handle counters and time values correctly.** 32-bit ARM
  cross-compile fixed (#16): metrics u64 counters use a conditional `Counter`
  (lock-free on 64-bit, mutex-guarded on 32-bit), and width-dependent `timeval` casts
  corrected. `mips-linux-musl` remains blocked on a Zig libc limitation.
  ([2de416e](https://github.com/ul0gic/fail2zig/commit/2de416e))

## 0.1.1 — 2026-05-21

**Per-jail settings are applied correctly** (retired: downloads and tag removed)

Retry thresholds and ban durations now follow each jail’s settings. Fractional
ban-escalation values are accepted by the TOML parser.

**Upgrade note** Drop-in binary replacement. State v1 migrates to v2 on the first
checkpoint, with no data loss.

### Fixes {fix}

- `state` **Each jail uses its own thresholds and ban durations.** Per-jail `maxretry` ·
  `findtime` · `bantime` · `bantime_increment` are now actually applied. In v0.1.0 they
  were parsed and accepted but silently ignored — every jail received `[defaults]`.
  Per-jail `StateTracker` instances now route matches through the right thresholds.
  State file format bumped to v2; v1 files migrate on first checkpoint.
  ([7f4b486](https://github.com/ul0gic/fail2zig/commit/7f4b486))
- `config` **Ban escalation accepts fractional values.** TOML parser now accepts
  fractional values for `bantime_increment_multiplier` and `bantime_increment_factor`.
  Both fields are `f64` in the schema, but the parser was reading them as integers —
  `factor = 1.5` for a softer escalation curve now works.
  ([2c5ca20](https://github.com/ul0gic/fail2zig/commit/2c5ca20))

## 0.1.0 — 2026-04-24

**The first public release** (retired: downloads and tag removed)

A static musl binary with compiled log parsers, firewall integration, a local client,
and built-in metrics. Released under AGPL-3.0-or-later.

| Measure | Value | Note |
| --- | --- | --- |
| Parse throughput | 5.96M l/s | 271× target |
| Ban latency p99 | 932 ns | p50 365 ns |
| Binary (musl x86_64) | 877 KB | stripped |
| Resident memory | 22 MB | 64 MB ceiling |

### Features {feat}

- `engine` Single static musl binary · zero runtime dependencies · 877 KB stripped
  ([5a85cc2](https://github.com/ul0gic/fail2zig/commit/5a85cc2))
- `core` epoll / timerfd / signalfd event loop · inotify log watcher with rotation +
  copytruncate handling ([98cd331](https://github.com/ul0gic/fail2zig/commit/98cd331))
- `parser` Comptime-specialized parsers · no regex engine in the process ·
  zero-allocation hot path verified with `FailingAllocator`
  ([ec31dee](https://github.com/ul0gic/fail2zig/commit/ec31dee))
- `firewall` Pure netlink for nftables (no libnftnl, no shell-out) · argv for iptables +
  ipset ([ec31dee](https://github.com/ul0gic/fail2zig/commit/ec31dee))
- `state` Fixed-arena state tracker with three eviction policies · atomic CRC-checked
  persistence · per-IP 128-slot ring buffer
  ([a9e77dc](https://github.com/ul0gic/fail2zig/commit/a9e77dc))
- `config` Native TOML parser + full `--import-config /etc/fail2ban` pipeline ·
  translates filter.d regexes · maps action.d backends · emits validated TOML
  ([3af15fd](https://github.com/ul0gic/fail2zig/commit/3af15fd))
- `filters` 15 built-in comptime filters: sshd, nginx-*, apache-*, postfix / dovecot /
  courier, named, vsftpd, proftpd, mysqld, recidive
  ([3af15fd](https://github.com/ul0gic/fail2zig/commit/3af15fd))
- `cli` `fail2zig-client` — status / ban / unban / list / jails / reload · table, JSON,
  plain output · bash / zsh / fish completions
  ([2130f37](https://github.com/ul0gic/fail2zig/commit/2130f37))
- `metrics` Built-in HTTP/1.1 server · `/metrics` (Prometheus), `/api/bans` (JSON),
  `/events` (WebSocket, RFC 6455)
  ([2130f37](https://github.com/ul0gic/fail2zig/commit/2130f37))
- `demo` Live internet-exposed honeypot at
  [fail2zig.com/demo](https://fail2zig.com/demo) · real sshd + nginx attack surface ·
  three-pane dashboard ([1803321](https://github.com/ul0gic/fail2zig/commit/1803321))
- `release` Static musl binaries for x86_64 + aarch64 · SHA256SUMS · hardened systemd
  unit · `scripts/install.sh` one-shot installer
  ([1340cae](https://github.com/ul0gic/fail2zig/commit/1340cae))

### Security {sec}

- `parser` High severity: IPv4-mapped IPv6 canonicalization closes ban-evasion by
  peer-format flipping ([8bfc74f](https://github.com/ul0gic/fail2zig/commit/8bfc74f))
- `ipc` Medium severity: `umask(0o117)` around `bind()` closes the socket-permissions
  race window ([8bfc74f](https://github.com/ul0gic/fail2zig/commit/8bfc74f))
- `http` security headers on every response · 5s per-client read
  deadline · 100/sec accept rate cap
  ([8bfc74f](https://github.com/ul0gic/fail2zig/commit/8bfc74f))
- `fuzz` Fuzz corpora for parser · IP parser · IPC protocol · TOML config — all with
  `FailingAllocator` to surface unbounded allocation as `OutOfMemory`
  ([8bfc74f](https://github.com/ul0gic/fail2zig/commit/8bfc74f))
- `systemd` Hardened unit: `CAP_NET_ADMIN + CAP_DAC_READ_SEARCH` only ·
  `ProtectSystem=strict` · `NoNewPrivileges` · seccomp filter · `systemd-analyze
  security` 2.4 ([7df630f](https://github.com/ul0gic/fail2zig/commit/7df630f))
- `license` AGPL-3.0-or-later · trademark asserted on "fail2zig" name + logo ·
  vulnerabilities reported via GitHub Private Security Advisories
  ([ef16d7c](https://github.com/ul0gic/fail2zig/commit/ef16d7c))

### Performance {perf}

- `bench` Parse throughput **5.96M lines/sec** (271× the 22K target) · ban latency p50
  365 ns / p99 932 ns (1000× under the 1ms target)
  ([8bfc74f](https://github.com/ul0gic/fail2zig/commit/8bfc74f))
- `memory` Hard memory ceiling held across 50K unique IPs: 21,845 entries resident,
  15,606 evictions — ceiling never exceeded
  ([8bfc74f](https://github.com/ul0gic/fail2zig/commit/8bfc74f))
- `binary` Static musl binary **877 KB** (x86_64) / **832 KB** (aarch64) — well under
  the 5 MB ceiling ([1340cae](https://github.com/ul0gic/fail2zig/commit/1340cae))

### Fixes {fix}

- `ws` Critical severity: use-after-free in `ws.dispatchFrame` on close / binary
  frames ([b101619](https://github.com/ul0gic/fail2zig/commit/b101619))
- `filter` High severity: sshd filter matched clean disconnects, causing operator
  self-ban during honeypot bring-up
  ([b101619](https://github.com/ul0gic/fail2zig/commit/b101619))
- `state` High severity: restored bans on restart now re-installed into the firewall;
  previously the state tracker held them but the kernel didn't enforce
  ([dc916a9](https://github.com/ul0gic/fail2zig/commit/dc916a9))
- `state` High severity: `bantime_increment` now wired from `[defaults]` to the state
  tracker (was silently ignored)
  ([3d866c7](https://github.com/ul0gic/fail2zig/commit/3d866c7))
- `ws` Broadcast wiring + event schema aligned to the documented `type / ts / payload`
  envelope; dashboard counters now tick in real time
  ([4d75186](https://github.com/ul0gic/fail2zig/commit/4d75186))
- `ipc` daemon and client socket-path defaults unified on
  `/run/fail2zig/fail2zig.sock`
  ([2130f37](https://github.com/ul0gic/fail2zig/commit/2130f37))
- `build` `@bitCast` size mismatch (i128 → u64) resolved via `@truncate`
  ([2130f37](https://github.com/ul0gic/fail2zig/commit/2130f37))
