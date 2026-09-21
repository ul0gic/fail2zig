# Command migration: fail2ban-client to fail2zig

This page maps the fail2ban-client invocations operators run in scripts and runbooks to
the stable native `fail2zig` commands, their exit classes and their JSON schema versions.
Anything not listed as supported is not supported; there are no compatibility aliases,
no Python, and no private fail2ban socket protocol.

fail2ban served operators for two decades and its command surface is the reference
point here. Where fail2zig differs it is by design, and the difference is stated
plainly rather than papered over.

## One executable

| Purpose | Invocation |
|---|---|
| Service entry (systemd `Type=notify`) | `fail2zig --config /etc/fail2zig/config.toml` |
| Foreground run | `fail2zig --foreground --config <path>` |
| Administration | `fail2zig [--socket <path>] [--output table\|json\|plain] [--no-color] [--timeout <ms>] <command> [args]` |
| Offline rule evaluation | `fail2zig rule-test …` |
| Migration preparation, cutover and rollback | `fail2zig migrate …` |

There is no `fail2zig-client`. Read-only monitoring works for members of the `fail2zig`
group through the 0660 socket; mutations require uid 0 or the daemon uid, verified with
`SO_PEERCRED`. The daemon sends `READY=1` only after configuration, storage, every source and
enforcing protection are admitted, `RELOADING=1` then `READY=1` around a live reload, and
`STOPPING=1` on exit. `ExecReload` is `SIGHUP`; `SIGUSR1` reopens `log_target` after rotation.
No socket unit ships and `LISTEN_FDS` is not read.

The shipped service runs as the non-login `fail2zig` account. Its group can be selected by
`FAIL2ZIG_GROUP` during installation. `CAP_NET_ADMIN` supplies firewall access and
`CAP_DAC_READ_SEARCH` supplies protected log/journal reads. `CAP_NET_RAW` supports the
ipset backend’s iptables extension and grants raw IP socket authority. HTTP remains in the same process;
`metrics_enabled = false` disables HTTP/WebSocket while socket monitoring stays available.

## Exit classes

Every command returns one of the frozen classes. Scripts branch on these, never on text.

| Code | Class | Meaning |
|---|---|---|
| 0 | success | Completed; every claimed effect was observed. |
| 1 | rejected | Valid request refused, or the requested object is absent. |
| 2 | usage | Argument, parsing or local validation failure. |
| 3 | unavailable | Daemon or transport unreachable (no socket, refused, timeout). |
| 4 | partial | A durable effect was applied but kernel confirmation is incomplete. |
| 5 | uncertain | A durable effect may have been applied and could not be established. |

fail2ban-client returned 0 or 255 (with `-x`, 1 for some failures) and printed the outcome
as text. The native classes are the contract; the JSON `outcome` field carries the detail.

## Command mapping

`table` output is for people; `json` for scripts; `plain` is tab-separated.

| fail2ban-client | fail2zig | Exit | JSON |
|---|---|---|---|
| `status` | `fail2zig status [--details]` | 0 / 3 | object: `version`, `protection`, `active_bans`, `total_bans`, `storage`, `backend`, `generation`, worker and clock flags |
| `status <jail>` | `fail2zig jails [--details]` (all jails) or `fail2zig list --jail <jail> [--details]` (bans) | 0 / 3 | `jails`: array of `name`, `enabled`, `paused`, `healthy`, `active_bans`, `maxretry`, `findtime`, `bantime`, `action`, `enforcing`, `source`, `revision` |
| `get <jail> banip` / `banned` | `fail2zig list [--jail <jail>] [--details]` | 0 / 3 | array of active bans |
| `set <jail> banip <ip>` | `fail2zig ban <ip> --jail <jail> [--duration <s>] [--scope host\|net <cidr>]` | 0 / 1 / 4 / 5 | `schema_version` 1, `kind` `ban`, `outcome` `applied\|rejected\|…`, `generation`, `mutation_revision`, `enforced`, `reasons[]` |
| `set <jail> unbanip <ip>` | `fail2zig unban <ip> --jail <jail> [--scope host\|net <cidr>]` | 0 / 1 / 4 / 5 | `kind` `unban`, otherwise as `ban` |
| `unban --all` | not supported; loop `fail2zig list --output json` and `unban` per address and jail | | |
| `set <jail> banip <ip>` without a jail | not supported; exactly one `--jail` is required | 2 | |
| `reload` / `reload <jail>` | `fail2zig reload` (whole configuration generation) | 0 / 1 / 3 | `schema_version` 1, `outcome` `noop\|applied\|rejected\|restart_required`, `generation`, `reasons[]` |
| `set <jail> maxretry\|bantime\|findtime …` | not supported at runtime by design; edit the file, then `fail2zig reload` | | |
| `start <jail>` / `stop <jail>` | `fail2zig jail enable <jail>` / `fail2zig jail disable <jail>` | 0 / 1 | `kind` `group_enable\|group_disable`, `outcome`, `mutation_revision` |
| (no equivalent) | `fail2zig jail pause <jail>` / `fail2zig jail resume <jail>` | 0 / 1 | `kind` `group_pause\|group_resume` |
| (no equivalent) | `fail2zig firewall show [--limit 1..256] [--cursor <token>] [--details]` | 0 / 3 | retained fail2zig-owned observation with bounded `items[]`, optional `structure`, per-item `placement` and `next_cursor` |
| `get <jail> ...` history queries | `fail2zig history [--jail <jail>] [--limit 1..256] [--cursor <token>]` | 0 / 3 | `schema_version` 1, `generation`, `items[]`, `next_cursor` |
| `set <jail> unbanip` to forget an address | `fail2zig history reset <ip> (--jail <jail> \| --all)` | 0 / 1 | `kind` `history_reset` |
| `version` | `fail2zig version` (daemon) / `fail2zig --version` (local) | 0 / 3 | `client_version`, `daemon.daemon_version` |
| `get dbfile`, `get loglevel`, `get logtarget` | `fail2zig config` | 0 / 3 | `schema_version` 1, `generation`, `redacted`, `global{…}`, `jails[]`; paths and address lists are redacted for non-administrators |
| `set loglevel`, `set logtarget` | edit `global.log_level` (live via reload) or `global.log_target` (restart) | | |
| `fail2ban-regex <log> <filter>` | `fail2zig rule-test --file <log> --service <name>` or `--rule-file <rule.json>` | 0 / 1 / 2 | `schema_version` 1, `input{kind,path,lines_read}`, `rule{kind,name}`, `counts{matched,missed,ignored,rejected}`, `samples[]` |
| `ping` | `fail2zig version` or `fail2zig status`; exit 3 means unreachable | 0 / 3 | |
| `--async`, `--timeout` | `--timeout <ms>` (default 5000) | | |
| `-s <socket>` | `--socket <path>` | | |
| `restart`, `stop` (daemon) | `systemctl restart\|stop fail2zig` | | |
| `flushlogs` | `systemctl kill -s USR1 fail2zig` after rotating `global.log_target` | | |
| `add <jail> <backend>`, `set <jail> addaction …`, `set <jail> action …` | not supported; jails are declared in the configuration file | | |
| `get <jail> failregex`, `set <jail> addfailregex` | not supported; builtin services are compiled in, custom rules use the bounded native JSON grammar in a `rule_files` entry | | |
| `set <jail> addignoreip` | not supported at runtime; edit `ignoreip` and restart (literal lists are restart-only), or use an `ignore_file` on a custom jail and reload | | |
| `set dbpurgeage`, `set dbmaxmatches` | not supported; retention is fixed by the state schema | | |

### Live reload versus restart

`fail2zig reload` (or `SIGHUP`) builds the whole proposed generation before publishing it.
Live keys: per-jail `maxretry`, `bantime`, `bantime_kind`, `bantime_increment`, the global
`log_level`, and the contents of a custom jail's `ignore_file`. Everything else is
restart-only and reported as `outcome: "restart_required"` with the offending keys in
`reasons`: `findtime`, literal `ignoreip` entries, source and plan keys (`logpath`, `source`,
`filter`, `timestamp`, timezone keys, `journal_executables`, `rule_files`), and policy edits
on a disabled jail. An invalid proposal is `rejected` and the running generation is untouched.

Native `bantime`, `findtime`, `bantime_increment_max_bantime` and `bantime_increment_jitter`
accept integer seconds or quoted durations such as `"1h30m"`. This does not change the reload
boundary above or the numeric CLI `--duration`, `--timeout` and migration window arguments.

### Monitoring endpoints

With `metrics_enabled = true` the HTTP listener serves `/metrics` (Prometheus), `/api/status`,
`/api/bans` and `/api/health`. `/api/health` returns the readiness report
(`{"schema_version":1,"ready":…,"components":{config,storage,sources,clock,enforcement,admin},"cause":…}`)
as HTTP 200 when `ready` is true and HTTP 503 (same body) while any component withholds
readiness, so probes can key on the status line. The versioned `health` query kind carries the
same report over the socket; there is no separate readiness spelling, use `status` for the
storage and protection state.

## Migration workflow

This workflow accepts supported **fail2ban schema-4 SQLite** input. It does not convert
fail2zig v0.3.0 binary state. For an existing native database's service-account transition,
follow [upgrading fail2zig state](migration-continuity.md#upgrading-fail2zig-state).

The offline preparation commands never touch the running fail2ban service, its database or
the firewall:

```
fail2zig migrate inspect  --source-dir /etc/fail2ban [--output json|table]
fail2zig migrate snapshot --source-db /var/lib/fail2ban/fail2ban.sqlite3 --staging-dir <dir>
fail2zig migrate plan     --source-dir /etc/fail2ban --source-db <db> --staging-dir <dir> \
                          --out plan.json [--continuity lossless|reset-replay] [--replay-window <s>] \
                          [--runtime-socket <path>]
fail2zig migrate validate --plan plan.json [--source-dir <dir>] [--snapshot <file>]
```

`--staging-dir` must be a private (0700), non-volatile directory; `reset-replay` continuity
needs `--replay-window`, otherwise the plan records a `replay-window-missing` blocker.
`--runtime-socket` records the source service's control socket for a later rollback
(default `/var/run/fail2ban/fail2ban.sock`).

Run preparation and native destination operations as the same UID that will own the native
daemon store. A root-created destination database is not reopenable by the `fail2zig` service
until a safe offline ownership transition. With the account installed, prepare a private,
persistent staging directory owned by it, and invoke commands with the required capabilities:

The source file and its ancestors must also grant the service UID ordinary read/search
permission: the source admission check uses the real UID, so capabilities alone do not satisfy
it. If the source already has a restricted reader group, grant that group only to the offline
command with `-p 'SupplementaryGroups=<existing-source-reader-group>'`. Do not add that membership
to the shipped daemon or make the source writable/world-readable to bypass the check.

```bash
sudo install -d -o fail2zig -g fail2zig -m 0700 /var/lib/fail2zig-migration
sudo systemd-run --wait --pipe --uid=fail2zig --gid=fail2zig \
  -p 'AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH' \
  /usr/local/bin/fail2zig migrate snapshot \
  --source-db /var/lib/fail2ban/fail2ban.sqlite3 \
  --staging-dir /var/lib/fail2zig-migration
```

Use this invocation prefix for `plan`, `validate`, native `cutover` and `status` as well,
with absolute paths. Substitute the configured service group if it differs. Staging must
belong to the invoking UID, and the native destination parent/database must belong to the
daemon UID; configuration and executable files remain administrator-owned. The capability
grant does not make an inaccessible source path writable or bypass systemd mount restrictions.
Keep the destination daemon stopped while creating/staging native state. The commands below
show the migration arguments; apply the account/capability prefix above for destination access.

The cutover is journaled and resumable:

```
systemctl stop fail2ban
fail2zig migrate cutover --plan plan.json --state-file /var/lib/fail2zig/state.bin \
                         --staging-dir <dir> --backend nftables|ipset|iptables [--socket <path>]
fail2zig migrate status  --plan plan.json --state-file <db> --staging-dir <dir> --run-id <hex>
```

Staging happens offline with the daemon stopped; activation and kernel verification run
inside the daemon over the socket. When the socket is unreachable the command exits 3 and
prints the exact `--run-id` command to resume; a rerun with `--run-id` classifies the journal
and the store instead of replaying. Exit mapping: before any mutation every failure is 1;
after a mutation, incomplete protection is 4 (`partial`) and an unestablished outcome is 5
(`uncertain`); `pending` is 3.

The disclosed protection gap is the interval between stopping fail2ban and the daemon's
activation. Start the destination service explicitly after offline staging, then use the
printed resume command against its socket to complete activation. The installer does not
perform this handoff.

### Rollback

Source restoration must write beside the original fail2ban database and restore its original
UID, GID and mode. The ordinary service capabilities are insufficient. Stop **both** source
and destination writers, preserve their current coherent databases, and run the offline restore
as the native service UID with a temporary capability grant. For a root-owned source:

```bash
# RUN_ID is the recorded migration run ID. Use the original backend and paths.
sudo systemctl stop fail2ban fail2zig
sudo systemd-run --wait --pipe --uid=fail2zig --gid=fail2zig \
  -p 'AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE CAP_CHOWN CAP_FOWNER' \
  -p 'CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE CAP_CHOWN CAP_FOWNER' \
  /usr/local/bin/fail2zig migrate rollback \
  --plan /var/lib/fail2zig-migration/plan.json \
  --state-file /var/lib/fail2zig/state.bin \
  --staging-dir /var/lib/fail2zig-migration --backend nftables --run-id "$RUN_ID"
```

Substitute the configured group and, if needed, the transient source-reader group described
above. These additional capabilities belong only to this operator-launched offline command;
do not add them to `fail2zig.service`. The original source parent ownership is retained, and
the restored database receives the source's original ownership and mode. Read-only mounts or
other filesystem restrictions still require operator repair.

After the restore reports its next step, start fail2ban and verify source protection, then
start the destination daemon so the second `--source-verified` operation can release its
owners through IPC. That second operation uses the ordinary migration invocation prefix;
the extra restore capabilities are unnecessary. Keep the source serving until rollback
completion is confirmed. The general arguments are:

```
fail2zig migrate rollback --plan plan.json --state-file <db> --staging-dir <dir> \
                          --backend nftables|ipset|iptables --run-id <hex> [--socket <path>]
fail2zig migrate rollback ... --run-id <hex> --source-verified
```

Only an activated run needs rollback; a staged run is discarded by not activating it, and
a run whose cutover step is still open must first be resumed with `migrate cutover --run-id`.
The rollback is journaled under the same run in two phases:

1. **Restore the source.** The recovery point `recovery-point-<run16>.sqlite3` in the staging
   directory is validated against the plan's snapshot, and the live source database is
   fingerprinted through the SQLite backup API (WAL-aware). A recovery-point or source
   fingerprint mismatch finishes the step as `rollback_failed` with nothing written (exit 4).
   Environment failures (unreadable recovery point or source, no space, a failed rename
   after which the original is put back) are `operational_failure`, exit 1, and the run stays
   resumable. Otherwise the post-cutover deltas are carried back: native bans into
   `bans`/`bips`, released or expired staged owners removed from `bips`, and scopes with
   protocol or port restrictions reported as `unsupported`. The derived database is written
   beside the source, fsync'd and given the original's owner and mode; the original moves to
   `<source>.pre-rollback-<run16>` together with its `-wal`/`-shm` siblings (nothing is
   deleted); the derived file is renamed into place and the directory is synced; a durable
   marker `restored-<run16>` in the staging directory records the completed swap. The command
   then exits 3 and prints the next command.
2. **Release the destination.** Requires `--source-verified`, the source control socket
   recorded in the plan, and a running `fail2ban-server` process (a stale socket is refused).
   The daemon accepts the release only while the rollback step is open; native owners stay.
   `applied` sets the run state to `rolled_back` and exits 0. A partial (4), uncertain (5) or
   refused (1) release leaves the step open for a rerun; an unreachable daemon or a rejected
   request exits 3.

A rerun with `--run-id` classifies by the marker and the files: marker present, release only;
source missing with the derived file present, the swap is completed; source missing with only
the kept copy, it is moved back and the restore repeats; source unchanged, the restore repeats;
source changed with no marker, `rollback_failed`. Not lab-exercised: bans that expire during
the outage window, and a rename failure after the original has been moved aside.

`F2Z_MIGRATE_FAULT=<name>` is a qualification hook that terminates the command right after
the named step's intent is journaled; besides the cutover step names it accepts
`rollback_derived` (after the derived database is durable) and `rollback_swap` (after the
original is moved aside). It exists for rehearsals of the resume paths only and has no
operational use.

## Differences by design

- No runtime `set` of thresholds, actions or regexes: configuration is one reviewed file
  and one published generation.
- Manual bans and unbans name exactly one jail; `--scope net` needs nftables or ipset.
- Manual bans on a log-only jail are `rejected` (exit 1) rather than silently recorded.
- Bans are confirmed against the kernel; a command that could not confirm returns 4 or 5
  instead of 0.
- Monitoring is read-only and group-scoped; there is no shared administrative socket.
- Field names are the ones above; the fail2ban text layouts are not reproduced.
