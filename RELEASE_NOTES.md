# fail2zig v0.4.9

Version 0.4.9 is a hardening release. It shows the stored matched line for each
ban in `history` and `list` (#123), documents running with a custom state path
under the shipped service unit (#124), and lets configurations with more than ten
jails start under that unit. It also carries corrections across storage
maintenance, reload, jail removal, the admin socket and monitoring, found in a
full review of the daemon, with no change to how bans are detected, enforced or
stored.

## Changes

- Show what triggered a ban. `history --details` and `list --details` show the
  retained matched line for each event, wrapped onto continuation rows in the
  terminal and complete in JSON (#123). `history_max_matches` (default 10, global
  and per jail) sets how many lines are kept per address; 0 keeps none.
- Run with a custom state path. The installation guide gives the procedure for a
  `state_file` outside `/var/lib/fail2zig` under the shipped unit's sandbox,
  keeping the service hardening (#124).
- Start with many jails. The daemon raises its open-file soft limit to the hard
  limit the service grants, up to `native_fd_ceiling`, before it checks its
  startup plan. Under the shipped unit, 0.4.8 refused more than ten jails with
  `NativeFdAdmission`; the `native_fd_ceiling` default is now 8192, enough
  descriptors for 64 jails.
- Remove and disable large jails safely. Disabling or removing a jail releases
  its bans in bounded steps that resume after a restart, so a jail holding tens
  of thousands of bans no longer stops startup or reports done early.
- Take the SSH client address only from the connection's own field. An address
  inside a user name or other client-supplied text no longer selects who is
  banned.
- Keep ban details for administrators. `/api/bans` on the HTTP listener now
  returns 403, and ban lists, history and firewall inventory over the socket
  require uid 0 or the daemon's uid; `fail2zig` group members keep aggregate
  status and metrics.
- Show missing log sources in `status` (`Missing:` row, JSON
  `missing_sources`).
- Free DNS cache space when results expire, including across restarts, for
  custom rules that resolve host names.

## Upgrade and compatibility

The first start upgrades a state last written by v0.4.8 (schema 26) to schema
28 after writing `<state_file>.pre27-backup`; a v0.4.7 state takes the v0.4.8
step first. The schema 28 step adds columns with defaults and new tables only,
so its cost does not grow with the state. v0.4.7 remains the minimum supported
upgrade source. v0.4.8 and older binaries refuse schema 28 with
`UnsupportedSchema`; rollback restores the backup with the v0.4.8 binary.

Monitoring that read `/api/bans`, or group members who listed bans through the
socket, must use `fail2zig list` as root. Configurations that set
`native_fd_ceiling` keep their value.

## Known limitations

- Above about twenty jails the default `native_memory_ceiling_mb` (512) refuses
  startup with `NativeMemoryAdmission`; raise it for larger configurations.
- A file write refused near the database's size cap can be reported as
  `RestoreRequired` instead of `StorageFull`.

## Verification scope

The full local suite passed. On the Debian 13 lab host, a v0.4.8 state with
sixteen jails and 5,000 bans upgraded under the shipped unit with no override,
started, enforced a new ban, showed its matched line, removed it and restarted
with every ban in the kernel.

# fail2zig v0.4.8

Version 0.4.8 is the capacity, log-lifecycle and parity release, built on the
report of a production install whose PortSentry jail stalled at 2,048 bans
(#117, #118, #107). All jails now share one pool of 65,536 tracked addresses and
up to 65,536 live bans; a cold restart with 65,536 installed bans reaches
readiness in about six minutes on the lab host, a healthy stop takes one second
because installed rules stay in the kernel, and idle cost at that size is 12 % of
one core. It adds the configured ban list and ban origins asked for in #103, a
guard against banning your own host or SSH session, `repair-source` without a
stop, jail add and remove on `reload`, expiring ignore entries, per-jail
metrics, an audit line per change, JSON logs and `support-bundle`.

## Changes

- Share one tracking pool across all jails. 0.4.7 split a 4,096-entry pool
  evenly between jails and a banned address held its entry for its whole
  bantime, so a jail with `maxretry = 1` and `bantime = 1w` filled its share at
  2,048 bans, could no longer commit, and paused with `PendingRecordMismatch`
  when its log was rotated. The pool is now 65,536 tracked addresses and 65,536
  live bans daemon-wide, a live ban holds no tracking entry, a jail that does
  reach a limit shows `waiting (RetryCapacity)` in `jails` and resumes as room
  frees, and a rotation under `on_truncation = "restart"` no longer pauses the
  jail (#117).
- Tell a missing log apart from a truncated one. A log that is absent at start
  or deleted while the daemon runs shows `missing (FileNotFound)` in `jails`
  (JSON `source_missing`), with one warning in the daemon log; the source stays
  healthy, protection is not degraded, and reading resumes when the file
  appears. A deleted log that was read to its end is released after five quiet
  minutes with nothing lost. Truncation and replacement stay continuity-loss
  events under `on_truncation` (#118, #107).
- Add `banip`, in `[defaults]` and per jail: addresses and CIDRs the jail bans
  while they are listed, applied at start and on `reload`, lifted when removed.
  Every ban now carries one origin, `detection`, `manual` or `config`, shown by
  `list` (with `--origin` to filter), `history` and `firewall show`. `ban` on a
  detection ban extends it and marks it `manual`; `ban` and `unban` on a config
  ban are refused with `banned by config: edit banip` (#103).
- Give `banip` and `ignoreip` entries an optional duration
  (`"198.51.100.0/24 1d"`). The period starts when the entry is first applied
  and runs once; a reload or restart does not restart it; changing the duration
  or re-adding the entry starts a fresh one; an expired configured entry stays
  in the file, does nothing and is listed as `expired`. Runtime entries expire
  with `ignore add --for <duration>`, and `ignoretime` (`[defaults]` and per
  jail, unset or `0` permanent) sets the default life of an entry without a
  duration of its own (#103).
- Add `ignoreself` (default `true`): the host's own IPv4 and IPv6 addresses,
  loopback included, join every jail's effective ignore list with source
  `self`, read at start and at every reload. `ban` refuses, before it contacts
  the daemon, a loopback address, an address of this host or your SSH client
  address, or a `--scope net` network containing one, and names the address;
  `--force` overrides the guard.
- Count failures from zero after a manual `unban`, as fail2ban does. The
  address is banned again at `maxretry`; its escalation memory is kept.
- Run `repair-source` through the daemon's socket while it is running, with the
  same token, refusals and durable outcome as the offline form, so
  acknowledging a loss under `on_truncation = "refuse"` no longer withdraws any
  jail's rules. The offline form stays for a daemon that cannot start.
- Add and remove jails on `reload`. An added enabled jail starts in the same
  reload; a removed jail's bans are lifted and its elements removed last, after
  every other change has committed, one daemon log line names it and the count,
  and its history is kept. One invalid jail rejects the whole reload with a
  message naming it and leaves every running jail unchanged.
- Make room in a full tracking pool by retiring the oldest idle tracked address
  in the same commit; live bans are never evicted. Escalation history resets to
  the base `bantime` when the last ban ended more than `bantime_increment_decay`
  ago (default 30 days, measured from the ban's end, `0` disables).
- Commit admitted records in groups with one fsync, acknowledged only after the
  fsync returns, and install pending bans in batches on nftables, ipset and
  iptables. Ingest through one file source went from 5 to 79 records per second
  on the lab host with bans enforced inside the burst, and `kill -9` mid-burst
  lost or re-read no acknowledged record.
- Confirm nftables installs by the kernel's acknowledgement of each batch and
  detect drift from nf_tables change events, with a full audit of the owned set
  every 60 seconds instead of a readback after every mutation. At 65,536
  installed bans idle cost fell from 21 % to 12 % of one core; with 20,000 bans
  the daemon spends 3.5 % of one core, 2.1 s of it per audit. A foreign element
  in the owned set degrades protection and keeps auditing until the set is
  clean, then recovers.
- Leave installed rules in place at a healthy stop; every element carries its
  kernel timeout, so a stop at 65,536 bans takes about one second instead of
  being killed by the unit's timeout, and a restart reinstalls live bans in
  batches (readiness in 373 s at 65,536 bans on the lab host, hours before).
  `fail2zig firewall withdraw` removes every realized rule and holds
  enforcement off until the next start; `status` then reports
  `DEGRADED (FirewallWithdrawn)`.
- Raise the state-file ceiling from 256 MiB to 1 GiB and raise the SQLite page
  cache to 32 MiB; `status` shows the file's size and page use against the
  ceiling and the tracking pool against its limits.
- Expose per-jail metrics (`fail2zig_jail_bans_active`,
  `fail2zig_jail_bans_total`, `fail2zig_jail_failures_counted_total`,
  `fail2zig_jail_ignored_detections_total`, `fail2zig_jail_source_state`,
  `fail2zig_jail_pool_evictions_total`) and daemon-wide
  `fail2zig_state_file_bytes` and `fail2zig_state_file_pages`. Write one audit
  line per `ban`, `unban`, `ignore add`, `ignore remove`, `reload`, `jail
  pause`, `history reset` and online `repair-source`, with the target, the
  peer UID and the outcome. Add `log_format = "json"` (restart-only) for one
  JSON object per daemon log line.
- Add `fail2zig support-bundle`: one redacted JSON file for a bug report with
  versions, status, jails, stats, loss events, the effective configuration and
  its SHA-256, state-file page and per-table sizes, kernel readback counts,
  memory, host basics and the last warnings and errors from the daemon log;
  addresses are hashed unless `--include-addresses` is given.
- Give every command a help page (`fail2zig help <command>` or
  `<command> --help`, the offline tools included); `help <typo>` and
  `fail2zig <typo>` exit 2 with a suggestion; the daemon's `--help` and the
  client's `help` list the same commands. `ban --duration` accepts the
  configuration's duration syntax as well as seconds. `jails` help documents
  the source-health words.
- Print admin refusals that are not outcome objects on standard error; an
  `ignore add --unban` lifts the ban from `list` at once and reports a disabled
  or paused jail; `support-bundle` runs as root and reports journalctl's own
  reason when the journal cannot be read.
- Add `docs/security/threat-model.md`: assets, trust boundaries, each threat
  with its severity, control and the invariant or decision record behind it.

## Upgrade and compatibility

The first start upgrades a state last written by v0.4.7 (schema 25) to schema
26, which adds ban origins (every existing ban gets `detection`), ignore-entry
deadlines and the table of timed configuration entries, after writing
`<state_file>.pre26-backup`; the backup needs free space of twice the database
size plus 32 MiB and the daemon refuses to start if that file already exists.
The upgrade is one transaction and its schema steps do not scan populated
tables, so its cost does not grow with the state; it was proven on a 65,536-ban
state. v0.4.7 is the only supported upgrade source: states last written by
v0.4.6 or earlier are not an upgrade path and go through v0.4.7 first. v0.4.7
and older binaries refuse schema 26 with `UnsupportedSchema`; rollback restores
the backup with the v0.4.7 binary. The first start also rekeys saved detection
generations once, since the per-jail subject share no longer exists, and logs
that it did.

The default `native_memory_ceiling_mb` is now 512 (the plan for 65,536 live bans
is about 337 MiB with two enforcing jails); a configuration that sets 256
explicitly must raise it or the daemon refuses with `NativeMemoryAdmission`. A
healthy stop now leaves installed rules in the kernel; run `firewall withdraw`
before stopping when the table must be empty. Ban deadlines, source
checkpoints, SQLite WAL/FULL durability and firewall ownership are unchanged;
nftables, iptables and ipset remain supported. Existing plain columns and JSON
keys keep their meaning; `list`, `history` and `firewall show` add `origin`,
`ignore list` adds `expires`, `jails` adds `source_missing`, and `status` adds
the state-file and tracking-pool fields.

## Known limitations

- `status` does not yet list a missing log file; `jails` and the
  `fail2zig_jail_source_state` metric do.
- The state file never shrinks; freed pages are reused inside it, and a file
  past 1 GiB is refused at start.
- The per-ban footprint did not shrink in this release (about 6 to 7 KiB of
  state per live ban); 65,536 live bans plus a day of history fit under the
  ceiling with headroom.
- The full-pool eviction path was not exercised end to end at the gate; the
  65,536-address fill ran past its time budget. The mechanism is proven on the
  component rig only.
- Large curated lists are not a job for bans (each ban is tracked, owned and
  audited); a native list loader is under design in discussion #120.
- Drift detection by events is nftables-only; ipset and iptables keep their
  readback cadence.

## Verification scope

One campaign on `f2z-target` (Debian 13, kernel 6.12, nftables, PortSentry
2.0.7; 8 vCPU and 16 GiB for the large-state runs) covered: the schema 26
upgrade of a 2,040-ban and a 65,536-ban v0.4.7 state; a 65,536-ban cold restart,
idle and stop; a 60-second PortSentry burst against the pre-change binary with
`kill -9` mid-burst; readback at 20,000 elements; the retry behaviors (re-ban
after unban, decay); `banip`, origins and timed entries; `ignoreself` and the
lockout guard over SSH; online `repair-source`; jail add and remove on reload
with kernel readback; `nft flush set` recovery; a rejected reload; the metrics,
audit lines and JSON log format; and the missing, truncated and replaced log
cases. The firewall and daemon suites ran on the development host. Cross-builds
for the other targets do not imply live-kernel qualification there.

The five static Linux targets remain x86_64, aarch64, ARMv7 hard float, MIPS32r2
big endian and MIPS32r2 little endian. Verify downloads against `SHA256SUMS`.

# fail2zig v0.4.7

Version 0.4.7 is a stabilization release built on the reports from a production
install at 2,000 bans: idle CPU at that size falls from about 56 % of one vCPU to
under 3 %, a stop that took 49 seconds takes one, file sources that lose data on
a reboot can resume under an operator-chosen policy, `ignoreip` edits apply with
a reload, and per-jail exclusions can be managed at runtime. It addresses #98,
#99 and #103, and qualifies PortSentry stealth and UDP detection from #75.

## Changes

- Reduce the daemon's steady-state cost with many installed bans. The jail view
  is published only when it changes, effect owners are confirmed by key lookup
  instead of a scan of every live effect, and the journal source waits one
  second after an empty poll instead of spawning `journalctl` seven times a
  second. Measured on a one-vCPU Debian 13 host with 2,000 nftables bans: mean
  idle CPU 2.61 %, maximum 6.0 % in a five-minute window.
- Withdraw realized rules in batches at a healthy stop. With 2,000 bans the stop
  takes about one second in 32 turns instead of 49 seconds in 2,000.
- Add the `on_truncation` jail key for file sources: `refuse` (the default,
  today's behavior) pauses the source until `fail2zig repair-source` acknowledges
  the loss, while the daemon keeps running and other jails enforce; `restart`
  resumes at the new start of the file and records a durable continuity-loss
  event. `fail2zig status` lists paused sources and retained loss events. The
  same policy and the same command also cover a log deleted and recreated by
  its writer (PortSentry recreates its history file at every start): the
  source resumes at the start of the new file and records a `replaced` loss
  event; under `refuse` the printed `repair-source` command acknowledges it.
  A log recreated while the daemon runs is read without loss, and the old,
  unlinked file retires instead of counting against the source limit.
- Apply literal `ignoreip` edits through `fail2zig reload` without a restart
  refusal, and start on the existing state after a jail is added or enabled.
  The share of the subject budget each jail receives changes with the jail
  count and was part of every jail's saved identity, so adding a jail was
  refused with `RetryGenerationMismatch` until the state was recreated. Saved
  detection generations are rekeyed once at the first start so neither the
  ignore list nor that share forms part of their identity.
- Add `fail2zig ignore add`, `ignore remove` and `ignore list`. Runtime entries
  are stored in the state database, survive restart and reload, and merge with
  the configured `ignoreip`. An existing ban stays until its deadline unless
  `--unban` is given; the output names the ban and the command that lifts it.
  Each jail holds at most 128 entries, configuration and runtime combined.
- Qualify PortSentry 2.0.7 `--stealth -m pcap` detection for TCP SYN, FIN, NULL
  and XMAS scans and for UDP, in addition to `--connect`, each through ban,
  blocking while banned and expiry.
- Clean up committed receipts continuously. The cleanup walk no longer stops at
  the first receipt still held by a live ban: held receipts are set aside and
  deleted once their ban and retry window end, and everything behind them is
  cleaned in order. An install with long or permanent bans previously retained
  every receipt behind the oldest live ban until the 256 MiB state cap paused
  ingestion (#104). With 2,000 bans expiring, receipts fell to the held set
  within seconds on the lab host.
- Never dispatch a ban whose lease has already ended. A kernel element that
  timed out moments before the daemon processed the same deadline was re-sent
  with a deadline in the past, refused by nftables, and treated as backend
  uncertainty, which paused ingestion under short ban times with re-bans. Such
  an owner now goes to the expiry path instead.
- Read the nftables set back as one coherent netlink observation and retry an
  interrupted dump instead of trusting a partial one. `stats` reports the retries.
- Document the 256 MiB state-file cap and the pause-and-recover behavior when a
  commit finds the file full, and the `history_retention` and
  `history_max_matches` keys.
- Fix an applied `ignoreip` reload leaving every `ban`, `unban` and `ignore`
  command refused with a stale revision until restart, and list the `ignore`
  commands in `--help`.

## Upgrade and compatibility

The first start upgrades a state last written by v0.4.6 (schema 24) to schema 25
in place after writing `<state_file>.pre25-backup`; the upgrade needs free space
of twice the database size plus 32 MiB and resumes if interrupted. v0.4.6 is the
only supported upgrade source: states last written by older releases are not an
upgrade path, and v0.4.6 and older binaries refuse schema 25 state. Rollback
restores the backup with the v0.4.6 binary; the installation guide has the steps.

Ban deadlines, source checkpoints, SQLite WAL/FULL durability and firewall
ownership are unchanged. nftables, iptables and ipset remain supported. Existing
plain columns and JSON keys keep their meaning; `status` adds `paused_sources` and
a `sources` array, and the `ignore` commands add their own fields. Entries in a
custom-rule jail (`rule_files`) stay in its `ignore_file`; the runtime commands
refuse such a jail and name the file.

## Known limitations

- The state file is capped at 256 MiB. When a commit finds it full, ingestion
  pauses and retries while rules already in the kernel stay enforced; the file
  does not shrink, and cleanup frees pages only inside it. A receipt whose ban is
  permanent is kept for as long as that decision exists.
- A stopped daemon leaves its empty reserved nftables table. A second fail2zig
  installation on the same host refuses to start with `ForeignState` until that
  table is deleted; an in-place upgrade is unaffected.
- At 2,000 bans one status sample in 300 can report protection knowledge about
  five seconds old during idle. Stale status is not confirmation of current
  kernel protection.
- `list` can show a ban for a few seconds after `ignore add --unban` lifted it,
  until the next readback.
- Admin refusals are still printed as text on standard output in non-JSON modes.

## Verification scope

One campaign on a one-vCPU Debian 13 x86_64 host with the nftables backend
covered: the ignore commands end to end, including a 128-entry bound and a
v0.4.6-state upgrade; a 2,000-ban session for idle cost, stale knowledge, bans
under a running dump and the batched stop; the kernel-gated effect-runtime suite
on nftables, ipset and iptables; a 400-ban restart with a 600-second hold; a
sustained-load run at three records per second; a reboot with PortSentry history
truncation; and PortSentry connect, stealth and UDP detection. Component, fuzz and
release-local suites ran on the development host. Cross-builds for the other
targets do not imply live-kernel qualification there.

The five static Linux targets remain x86_64, aarch64, ARMv7 hard float, MIPS32r2
big endian and MIPS32r2 little endian. Verify downloads against `SHA256SUMS`.
