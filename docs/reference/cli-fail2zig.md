---
title: 'fail2zig — daemon and offline commands'
description: 'Run, validate, test rules, repair sources, collect support bundles and prepare migrations with the one fail2zig executable.'
sidebar_position: 3
category: Reference
audience: operator
last_verified: 2026-10-22
---

One executable contains the daemon, administration, rule testing and migration tools.
Use `fail2zig <command>`; the separate `fail2zig-client` executable was retired in 0.4.0.
For status, bans, exclusions, history and reload, see the [administration reference](cli-fail2zig-client.md).

## Run the daemon

```text
fail2zig [daemon] [OPTIONS]
```

The shipped systemd service runs as the non-login `fail2zig` user. It retains
`CAP_NET_ADMIN`, `CAP_NET_RAW` and `CAP_DAC_READ_SEARCH` for firewall and log access.
HTTP runs in that same privileged process. An all-log-only deployment can run
without firewall capability when its file, journal and state permissions allow it.

| Option              | Behavior                                                                                                                                         |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `--config <path>`   | Read configuration; default `/etc/fail2zig/config.toml`. `--config=<path>` is also accepted.                                                     |
| `--foreground`      | Run in foreground, the only supported mode.                                                                                                      |
| `--validate-config` | Validate configuration and print the configured jail summary without starting the daemon. This does not prove live source or firewall readiness. |
| `--test-config`     | Alias for `--validate-config`.                                                                                                                   |
| `--version`, `-V`   | Print the local executable version.                                                                                                              |
| `--help`, `-h`      | Print usage; it lists the same commands as `fail2zig help`.                                                                                      |

```bash
fail2zig --version
sudo fail2zig --validate-config --config /etc/fail2zig/config.toml
```

`--version` reports the executable on disk, for example `fail2zig 0.4.9`. Use
`fail2zig version` to query the running daemon; replacing a file on disk does not
upgrade a process already running.

At start the daemon raises its soft open-file limit to `native_fd_ceiling`
(default 8192), never past the hard limit the service grants. A start refused
because the service cannot write a configured `state_file` or `socket_path`
directory names the directory and the unit override that grants it; see the
[custom state directory procedure](../operations/installation.md#custom-state-directory-under-systemd).

## Configuration inspection and projection

```bash
sudo fail2zig migrate inspect --source-dir /etc/fail2ban
sudo fail2zig --import-config /etc/fail2ban --import-output /tmp/fail2zig-review.toml
sudo fail2zig --validate-config --config /tmp/fail2zig-review.toml
```

`--import-config [<source-dir>]` defaults to `/etc/fail2ban`.
`--import-output <path>` defaults to `/etc/fail2zig/config.toml` and replaces an
existing file there without a backup; use a separate review path to keep your
working configuration. Both accept the `--flag=<value>` form. The command exits 2
on failure and 1 when the result has no enabled jail. This projects supported
configuration, not database state. Unsupported enabled protection needs an explicit
disposition before activation. A familiar filter name does not establish matching equivalence.

For state transfer, use the separate [migration workflow](../guides/migration-from-fail2ban.md).

## Offline rule testing

```bash
fail2zig rule-test --file /var/log/auth.log --service sshd --output table
fail2zig rule-test --record "Failed password for root from 192.0.2.10 port 22 ssh2" --service sshd
fail2zig rule-test --file /path/to/sample.log --rule-file /path/to/rule.json
```

`rule-test` runs the daemon's own decoder, time admission and detectors against
one input and one rule. It opens no state, no firewall and no socket, and installs
no bans. Each sample is reported as matched, missed, ignored or rejected, with the
reason, the identity and the event time. Test representative failures and
successful logins, not just one matching line. fail2ban regexes and shell actions
are not executed.

Choose exactly one input and exactly one rule:

| Option                      | Meaning                                                                       |
| --------------------------- | ----------------------------------------------------------------------------- |
| `--file <path>`             | Read records from a log file.                                                 |
| `--record "<line>"`         | Test one line given on the command line.                                      |
| `--journal [<match>...]`    | Read records from the journal through `/usr/bin/journalctl`.                  |
| `--service <name>`          | Use a built-in filter.                                                        |
| `--rule-file <path>`        | Use a [custom rule file](custom-rules.md).                                    |

| Option                                   | Meaning                                                                              |
| ---------------------------------------- | ------------------------------------------------------------------------------------ |
| `--config <path>` with `--jail <name>`   | Take the timestamp, time zone and ignore settings from a jail in a configuration.    |
| `--timestamp <contract>`                 | `iso8601`, `syslog`, `epoch_seconds`, `common_log` or `undated`.                     |
| `--time-zone <id>`, `--tz-offset <minutes>` | Time zone for timestamps that carry none.                                         |
| `--year <yyyy>`                          | Year for syslog timestamps, 1 to 9999.                                               |
| `--encoding <name>`                      | `utf8`, `ascii`, `latin1`, `utf16le`, `utf16be`, `utf32le` or `utf32be`.             |
| `--identity raw\|dns --dns-server <ip:port>` | Resolve host-name subjects through the named resolver.                          |
| `--ignore <cidr>`                        | Treat an address or network as ignored; repeat up to 64 times.                       |
| `--max-lines <n>`                        | Stop after this many lines. Default 1,000,000.                                       |
| `--limit <n>`                            | Samples to print, 0 to 10,000. Default 20.                                           |
| `--print-lines`                          | Include the raw lines in the samples.                                                |
| `--now <epoch-seconds>`, `--window <seconds>` | Fix the clock and the admission window, for repeatable results.                 |
| `--output json\|table`                   | Default `json`.                                                                      |

With `--service`, the timestamp contract defaults to `syslog` for every filter
except `portsentry` and the `apache-*` and `nginx-*` filters. A line with no
syslog prefix, such as the `--record` example above, needs `--timestamp undated`
or it is rejected as `malformed_body`.

Exit 0 means the input was processed, even with zero matches; 1 means the rule,
configuration or input was refused; 2 is a usage error. See
[filters](filters.md) and [custom rules](custom-rules.md).

## Migration commands

```text
fail2zig migrate inspect  --source-dir <dir>
fail2zig migrate snapshot --source-db <file> --staging-dir <dir>
fail2zig migrate plan     --source-dir <dir> [--source-db <file> --staging-dir <dir>] --out <plan.json>
                          [--continuity lossless|reset-replay] [--replay-window <seconds>]
                          [--runtime-socket <path>]
fail2zig migrate validate --plan <plan.json> [--source-dir <dir>] [--snapshot <file>]
fail2zig migrate cutover  --plan <plan.json> --state-file <db> --staging-dir <dir>
                          --backend nftables|ipset|iptables [--socket <path>] [--run-id <hex>]
fail2zig migrate status   --plan <plan.json> --state-file <db> --staging-dir <dir>
                          --backend nftables|ipset|iptables --run-id <hex>
fail2zig migrate rollback --plan <plan.json> --state-file <db> --staging-dir <dir>
                          --backend nftables|ipset|iptables --run-id <hex>
                          [--source-verified] [--socket <path>]
```

`inspect`, `snapshot`, `plan` and `validate` are read-only preparation. `cutover`
stages the destination with the daemon stopped and activates it through the
daemon. `status` reports a run. `rollback` reverses an activated run in two
phases. Every subcommand takes `--output json|table`, default `json`.
`--continuity` defaults to `reset-replay`, which needs `--replay-window`.
`--run-id` is the 64-digit hexadecimal id that `cutover` prints. Without
`--socket`, the configured `socket_path` is used.

The input is supported fail2ban schema-4 SQLite; fail2zig 0.3.0 binary state is
not converted. Follow the [migration guide](../guides/migration-from-fail2ban.md)
for ownership, continuity, activation and rollback requirements.

## Signals and service readiness

| Signal              | Behavior                                                                                                                |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `SIGTERM`, `SIGINT` | Stop cleanly. Installed rules stay in the kernel with their timeouts; run `firewall withdraw` first for an empty table. |
| `SIGHUP`            | Validate and apply a supported live configuration generation; report invalid or restart-required changes.               |
| `SIGUSR1`           | Reopen `log_target` after rotation.                                                                                     |

The unit uses `Type=notify`. `READY=1` follows admission of configuration, storage,
every source that can resume and enforcing protection; `RELOADING=1` and
`STOPPING=1` report transitions. A source that cannot resume is paused and does
not hold back readiness. No socket-activation unit ships. See [reload boundaries](cli-fail2zig-client.md#reload).

## Exit classes

| Code | Meaning                                                                    |
| ---- | -------------------------------------------------------------------------- |
| 0    | Success.                                                                   |
| 1    | Valid request rejected, or a required object absent.                       |
| 2    | Usage, parsing or local validation failure.                                |
| 3    | Daemon or transport unavailable; migration can also be pending activation. |
| 4    | Partial durable effect; protection confirmation is incomplete.             |
| 5    | Uncertain durable effect; the outcome could not be established.            |

Scripts must inspect the exit class and structured outcome. A command that could
not confirm an effect must not be treated as a successful ban.

## Files

| Path                          | Purpose                                                                                                         |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `/etc/fail2zig/config.toml`   | Administrator-owned configuration.                                                                              |
| `/run/fail2zig/fail2zig.sock` | Local monitoring and administration socket; `socket_path` changes it.                                           |
| `/var/lib/fail2zig/state.bin` | Native SQLite database despite the historical extension; `state_file` changes it. Preserve WAL/SHM siblings in coherent offline backups. |

`pid_file` is deprecated and not written. Use `systemctl show -p MainPID fail2zig`.
The installed manuals are `man fail2zig` and `man 5 fail2zig.toml`.

## Source repair

```text
fail2zig repair-source --jail <name> --source <absolute path> --token <token>
                       --acknowledge-truncation [--config <path>]
```

A file source that lost continuity under `on_truncation = "refuse"` pauses while
the daemon keeps running; `status` prints the `repair-source` command to run.
When the daemon is running the repair goes through its socket, at the
`socket_path` in the configuration, and every jail stays protected. When the
daemon is stopped the command runs against the state file named by the
configuration; it refuses a locked or absent state and never creates one. It
records the loss; it cannot recover log entries that were never read. Do not
delete native state to bypass a refusal.

| Exit | Meaning                                                                          |
| ---- | -------------------------------------------------------------------------------- |
| 0    | Repaired, or the same token replayed its committed outcome.                      |
| 1    | Refused.                                                                         |
| 2    | Usage error.                                                                     |
| 3    | The daemon answered but could not serve the repair.                              |
| 5    | The connection failed after the request was sent; the outcome is unknown. Repeat the same command. |

See the [log file lifecycle](../guides/log-lifecycle.md#repair-source).

## Effect evidence repair

```text
fail2zig repair-effect-evidence [--config <path>] [--check | --apply]
```

Stop the daemon and run as the state-file owner. Check mode is the default. It
reports how many current effect scopes were examined and how many have the
recognized malformed absence evidence. It does not change effect evidence, create
state or contact the firewall. The state must already use the current schema;
this command does not perform an upgrade.

Apply accepts only a current absence intent whose dispatch and observation times
are equal and earlier than its creation, whose observation receipts agree, and
whose validated owners aggregate to absence. Other invalid effect state is
refused. `InvalidEffect` alone does not establish eligibility.

Before repairing anything, apply writes and verifies a complete SQLite backup,
including committed WAL contents, beside the state file. The name is
`<state_file>.effect-evidence-<random>.backup`, permissions are `0600`, and the
command prints its path and SHA-256. Existing backups are never overwritten.
The existing conservative backup policy requires twice the allocated database
size plus 32 MiB of free space. A healthy state needs no backup and apply does
nothing to it.

Repair runs in bounded transactions. It removes only the invalid observation
receipts and returns their current intents to pending, clearing their invalid
evidence. Owner facts, bans, source checkpoints, receipts and confirmed history
are preserved. Start the daemon afterward and check `status` and `jails` for
confirmed protection; the daemon must obtain genuine kernel evidence.

Keep the backup until recovery has been checked. It preserves the pre-repair
state, including the malformed evidence, so restoring it restores that refusal
too. An interrupted copy leaves a disposable `.effect-evidence-backup.partial`;
a subsequent apply replaces it. An interrupted repair can be repeated: committed
batches remain pending and the remaining eligible intents are repaired. Each
attempt that changes state preserves its own pre-repair backup.

A running writer, unsupported schema, changed state-file identity, insufficient
backup space or unrecognized invalid effect state causes refusal (exit 1).
Preserve the state and any backup for diagnosis. Invalid command arguments exit
2; a completed check or apply exits 0. This is a targeted evidence repair, not a
general database validator or salvage command.

## Support bundle

```text
fail2zig support-bundle [--out <path>|-] [--config <path>] [--socket <path>]
                        [--log-lines <n>] [--timeout <ms>] [--include-addresses]
```

`support-bundle` writes one redacted JSON file for a bug report and also works
while the daemon is stopped. `--log-lines` takes 0 to 2,000, default 200;
`--timeout` defaults to 5000 ms. It exits 0 when every section was collected, 4
when the bundle was written with sections that record an error, 1 when nothing was
written (an existing output file is never overwritten) and 2 on a usage error. See
the [support-bundle guide](../operations/support-bundle.md).
