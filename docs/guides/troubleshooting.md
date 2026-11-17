---
title: 'Troubleshooting'
description: 'Find the cause of a daemon that will not start, a jail that is paused, degraded protection, a refused command or a ban that did not happen, and the command that resolves it.'
sidebar_position: 7
category: Getting Started
audience: operator
last_verified: 2026-11-17
---

Start with the symptom. Every refusal fail2zig makes is deliberate and named: the
daemon would rather stop than run on state it cannot trust. The name tells you
what it protects and what to restore.

## Where to look first

```bash
sudo systemctl status fail2zig
sudo journalctl -u fail2zig -n 50 --no-pager
sudo fail2zig status
sudo fail2zig jails
```

- The journal holds the refusal line when the daemon will not start.
- `status` shows protection, intake, the state file and any paused source.
- `jails` shows each jail's source health.

When you report a problem, attach a [support bundle](../operations/support-bundle.md).

## The daemon will not start

The daemon logs one line that names the cause, then exits. Under the shipped
unit, systemd retries every 5 seconds (`Restart=on-failure`), so the same line
repeats in the journal until the cause is fixed.

| Exit code | Meaning |
| --- | --- |
| 1 | Startup was refused: state, firewall, log target or admission. |
| 2 | The configuration could not be loaded or failed validation. |

### Configuration

Check a configuration without starting the daemon:

```bash
sudo fail2zig --validate-config --config /etc/fail2zig/config.toml
```

It prints `config: OK (N jail(s) configured)` or the same error the daemon would log.

| Log line | Cause | Fix |
| --- | --- | --- |
| `config: <path>: world-writable (mode NNNN); refusing to start` | Anyone on the host can edit the file. | `chmod 0640 <path>`, as the line says. |
| `config: <path>: writable by a non-root group (mode NNNN); refusing to start` | A group other than root can edit the file. | `chmod 0640 <path>`. |
| `config: <path>:<line>:<col>: <Error> (key 'k' in [section])` | A key, section or value the parser does not accept. Unknown keys are errors, never ignored. | Correct the line. See the [configuration reference](../reference/config.md). |
| `config: validation failed: <Error>; <detail>` | The file parses but a setting is not allowed. | See the validation table in the [configuration reference](../reference/config.md). |
| `config: validation failed: NativeIngestionRequired` | `native_ingestion = false`. | Remove the key or set it to `true`. |
| `config: validation failed: CompatibilityNotAdmitted` | `compatibility_pending = true` in an enabled jail, or in `[global]` with any jail enabled. The migration tools set it on an import that is not yet admitted. | Resolve it through the [migration workflow](migration-from-fail2ban.md). Do not set it to false by hand. |
| `log target '<target>' unusable: <Error>; refusing to start` | The `log_target` file cannot be opened. | Make the directory exist and writable by the service. Under systemd see [daemon log file and rotation](../operations/installation.md#daemon-log-file-and-rotation). |

A configuration owned by a user other than root logs
`config: <path> is owned by uid N, not root` as a warning. The daemon still starts.

### Firewall

| Log line | Cause | Fix |
| --- | --- | --- |
| `firewall: no usable backend (<cause>); refusing to run unprotected` | A jail enforces, but no firewall backend can be used: missing tools, missing capability or no kernel support. The cause is in the brackets. | Fix the named cause. To run detection without enforcement on purpose, set `on_no_backend = "log-only"`; the daemon then runs DEGRADED. |
| `firewall: saved backend 'X' conflicts with requested backend 'Y' (InstallationMismatch)` | `firewall` was changed while the state file still belongs to the earlier backend. | Restore `firewall = "X"` or `"auto"`. Do not delete the state file to switch backends. |
| `firewall: saved namespace selector ... conflicts with requested selector ... (InstallationMismatch)` | `firewall_namespace` was changed against existing state. | Restore the previous `firewall_namespace`. |
| `NativeNamespaceAlreadyRunning` | Another enforcing fail2zig daemon runs in the same network namespace. | Stop the other daemon, or see [a second installation](../operations/installation.md#a-second-installation-in-the-same-network-namespace). |

### State file

These lines begin `native: startup failed: <Name>; refusing to start`,
`native: startup recovery failed: <Name>; refusing to start` or
`native: state authority admission failed: <Name>`. In every case **keep the state
file**. Deleting it discards every ban, every read position and the history.

| Name | Cause | Fix |
| --- | --- | --- |
| `RetryGenerationMismatch` | A jail's source, filter profile or policy differs from what the state was saved with. The daemon also logs `source/profile or policy differs from saved state`. | Restore the previous source configuration and SSH executable layout, then restart. |
| `SourceGenerationMismatch` | A saved source belongs to a different jail or source definition than the configured one. | Restore the source configuration the state was written with. |
| `UnsupportedSchema` | The state was written by a newer release than this executable. | Run the release that wrote it, or [roll back](upgrading.md#roll-back) with the backup the upgrade kept. |
| `NativeStateMigrationRequired` | The state file is the v0.3.0 binary format. | There is no converter. See [which releases can upgrade](upgrading.md#which-releases-can-upgrade). |
| `CorruptDatabase` | The file is not empty and is not an SQLite database. | Check `state_file` points at the right file. Restore from a backup. |
| `ForeignDatabase` | The file is an SQLite database that fail2zig did not create. | Check `state_file` points at the right file. |
| `schema N migration refused: backup <file> already exists` | An earlier upgrade left its backup in place. | Keep it if it is the only copy of earlier state; otherwise move it aside and restart. See [upgrading](upgrading.md). |
| `NativeAuthorityAlreadyRunning` | Another process holds the state file: a second daemon, a migration or a repair. | Stop the other process. |
| `UnsafePermissions` | The state file or its directory is not owned by the service user, or is accessible to group or others. | Restore the service user as owner, with no group or other access to the file and no group or other write on the directory. |
| `the service cannot write the state directory '...'` | The systemd unit does not grant write access to a custom directory. | Add the override from [custom state directory under systemd](../operations/installation.md#custom-state-directory-under-systemd). |
| `InvalidRetryPolicy` | A stored policy record is malformed. | Do not edit the state. Collect a support bundle and report it. |
| `RestoreRequired` | A record commit was rolled back and the pipeline could not resume. | Restart once. If it repeats, collect a support bundle and report it. |

A `state_file` on tmpfs or under `/run` logs
`state will not survive restart; use /var/lib/fail2zig` as a warning. The daemon
starts, and every reboot then begins from empty state.

### Sockets

| Log line | Cause | Fix |
| --- | --- | --- |
| `ipc: '<path>' is served by another process` | A daemon is already serving `socket_path`. | Stop it, or give this installation its own `socket_path`. |
| `ipc: refusing to serve '<path>': <reason>` | The socket directory is not owned by root or the service user, or is open to others. | Restore the directory's owner and mode. The shipped unit creates `/run/fail2zig` with mode `0710`. |
| `config: cannot prepare socket directory: <Error>` | The directory above `socket_path` cannot be created. | Create it, or grant it in the unit as for a custom state directory. |

### Limits and jail definitions

| Name | Cause | Fix |
| --- | --- | --- |
| `NativeMemoryAdmission` | The configured jails need more memory than `native_memory_ceiling_mb` allows (default 512). | Raise `native_memory_ceiling_mb`, or enable fewer jails. |
| `NativeFdAdmission` | The configured sources need more file descriptors than `native_fd_ceiling` or the process limit allows. | Raise `native_fd_ceiling` and the unit's `LimitNOFILE`, or watch fewer files. |
| `NativeJailLimit` | No jail is enabled, or more jails are enabled than the daemon supports. | Enable at least one jail; reduce the count. |
| `NativeInternalEventsRequired` | A filter that reads fail2zig's own events is not on `source = "internal"`, more than one such jail exists, or it was given a `logpath`, `journal_executables` or `rule_files`. | Give that jail `source = "internal"` and none of those keys. |
| `HostnameResolutionRequired` | A custom rule produces host names and no resolver is configured. | Set `dns_server`, or change the rule to capture addresses. |
| `ConsumerSourceMismatch` | The rule files of one jail name different sources. | Put rules for different sources in different jails. |

## Protection shows DEGRADED

`fail2zig status` prints `Protection: DEGRADED` with a `Cause:` row. The daemon is
running, and what it reports as enforced is only what it has confirmed in the
kernel.

| Cause | Meaning | What to do |
| --- | --- | --- |
| a backend name such as `IptablesUnavailable` | No usable firewall backend and `on_no_backend = "log-only"`. | Fix the backend. Bans are logged, not applied. |
| `FirewallWithdrawn` | An administrator ran `fail2zig firewall withdraw`. | Restart the daemon to enforce again. `reload` does not lift it. |
| `ReadbackPending` | The daemon has not yet read the kernel state since start. | Wait; it clears after the first successful readback. |
| `ReadbackStale` | The last attempt to read the kernel state failed or found foreign changes. | Check `fail2zig firewall show` and the journal. The daemon logs `readback recovered` when it clears. |
| `EffectRemovalOverdue` | An expired or lifted ban has not been confirmed removed from the kernel. | Check the journal for the firewall error. |
| `SourcePaused` | A log source is paused. | See the next section. |
| `ClockUncertain` | The system clock moved in a way the daemon cannot order. | Check time synchronisation on the host. |
| `WorkerStalled` | The storage worker has not made progress. | Check disk health and the journal; collect a support bundle. |

## A jail's source is paused, waiting or missing

`fail2zig jails` shows the health of each source.

| Health | Meaning | What to do |
| --- | --- | --- |
| `ok` | Reading normally. | Nothing. |
| `missing (FileNotFound)` | The log file does not exist yet. | Nothing if the service has not logged yet; otherwise correct `logpath`. |
| `waiting (StorageCapacity)` | The state file is at its page capacity; intake resumes by itself as old records are cleaned up. | Watch the `State file:` row in `status`. |
| `waiting (...)` | A bounded internal queue is full. | It resumes by itself. Persistent waiting belongs in a support bundle. |
| `paused (truncated)`, `paused (replaced)`, `paused (rotated_unread_removed)` | The file changed in a way that may have lost unread lines, and `on_truncation` is `refuse`. | Run the `repair-source` command that `status` prints. |
| `broken (...)` | The source reader failed; the cause, exit status and its error output are shown. | Fix the named cause. For a journal source, check that `journalctl` runs for the service user. |

For a paused file, `status` prints a `Paused:` block and the exact command:

```bash
sudo fail2zig repair-source --jail sshd --source /var/log/auth.log \
  --token <token from status> --acknowledge-truncation
```

It applies through the running daemon; no stop or restart is needed. A log that
is emptied on purpose (PortSentry's history file, for example) should use
`on_truncation = "restart"`. See [log file lifecycle](log-lifecycle.md).

## A jail matches nothing

Test the jail's filter against real lines, offline:

```bash
fail2zig rule-test --file /var/log/auth.log --service sshd --output table
```

`rule-test` opens no state, no firewall and no socket. Each sample is a match, a
miss, an ignore or a reject with a reason.

| Reason | Meaning | Fix |
| --- | --- | --- |
| `no_match` | The line is well formed and no pattern matches it. | Expected for ordinary lines. If a failure line misses, the filter does not cover that message. |
| `malformed_body` | The line has no prefix in the expected timestamp format. | Set the jail's `timestamp` to the log's real format (`--timestamp` in `rule-test`). |
| `ignored` | The address is on an ignore list. | Check `ignoreip`, `ignoreself` and `fail2zig ignore list`. |
| `origin_transport`, `origin_executable`, `origin_uid` | A journal record did not come from the trusted sender: wrong transport, an executable not in `journal_executables`, or the wrong user. | List the real daemon path in `journal_executables`. |
| `line_too_long`, `invalid_encoding` | The line exceeds 64 KiB or is not valid in the chosen `encoding`. | Set the right `encoding`. |

Test failed logins and successful logins both, not one matching line.

## A ban is not in the kernel

`fail2zig status` shows `Knowledge:` and `Pending:` rows.

- `Knowledge: fresh` means the last kernel readback succeeded. `stale` or `none`
  means the daemon cannot currently confirm the kernel state.
- `Pending: N bans` are decided but not yet confirmed in the kernel.
- A jail whose protection reads `log-only` has `enforce = false`: it records
  what it would ban and installs nothing.
- `fail2zig firewall show` lists what the daemon read back from the kernel.

A ban the daemon has not confirmed is never reported as active.

## An address was not banned, or a ban was refused

- **Ignored addresses.** `ignoreip`, `ignoreself` (the host's own addresses) and
  runtime entries from `fail2zig ignore add` are never banned by detection.
- **`refusing to ban <address>: ...; use --force to override`.** The client
  refuses a manual ban that covers loopback, one of the host's own addresses, or
  the address of your own SSH session. `--force` overrides it.
- **Not enough failures.** A ban needs `maxretry` matches inside `findtime`.

## A command cannot reach the daemon

| Message | Cause | Fix |
| --- | --- | --- |
| `Cannot connect to fail2zig daemon at <path>. Is the service running?` | No daemon is serving that socket. Exit code 3. | Start the service, or pass `--socket` or `--config` for a non-default installation. |
| `Permission denied. fail2zig requires group 'fail2zig' membership.` | Your user cannot open the socket. | Use `sudo`, or add the user to the `fail2zig` group for read-only commands. |
| `mutation requires root or daemon uid` (code 403) | A command that changes state was run by a user who may only read. | Run it with `sudo`. |

Root and the service user may run every command. A member of the `fail2zig`
group may only read, and sees status and jail health but not ban lists, history
or firewall items. See the [administration reference](../reference/cli-fail2zig-client.md).

## `reload` answers `restart_required`

Some settings apply only at start. `reload` applies `log_level`, the ban policy
keys, the ignore lists, `banip` and added or removed jails. Anything else,
including `log_format`, `log_target`, `firewall` and paths, needs
`sudo systemctl restart fail2zig`. The full list is in the
[configuration reference](../reference/config.md).

## `history` answers 409

`cursor expired or observation changed; restart pagination without a cursor`
means the cursor no longer points at a stored record: the configuration changed,
or `history_retention` removed the record. Run the command again without
`--cursor`.
