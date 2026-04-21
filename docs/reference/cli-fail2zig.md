---
title: "fail2zig daemon — CLI reference"
description: Complete command-line reference for the fail2zig daemon binary, including all flags, exit codes, and usage examples.
sidebar_position: 3
category: Reference
audience: operator
last_verified: 2026-04-21
---

The `fail2zig` binary is the intrusion prevention daemon. It runs as root, watches
log files, applies IP bans via the system firewall, and serves a control socket
for `fail2zig-client`.

## Synopsis

```text
fail2zig [OPTIONS]
```

## Options

### `--config <path>`

Config file to load. Default: `/etc/fail2zig/config.toml`.

The file must be valid TOML conforming to the fail2zig schema. Unknown keys are
rejected with a line and column diagnostic.

### `--foreground`

Run in foreground (log to stderr / journald). This is the only supported mode in
v0.1.0; the flag is accepted but has no additional effect. Run the daemon under
systemd or a process supervisor.

### `--validate-config`

Load and validate the configuration file, print the result, and exit. Does not
start log watchers, contact the firewall, or write any files.

```bash
sudo fail2zig --validate-config --config /etc/fail2zig/config.toml
# config: OK (6 jail(s) configured)
```

On error:

```bash
sudo fail2zig --validate-config --config /etc/fail2zig/config.toml
# config: line 7, col 1: unknown key 'bnatime' in section [defaults]
```

### `--test-config`

Alias for `--validate-config`. Retained for compatibility with early release
documentation.

### `--import-config [<source-dir>]`

Import a fail2ban configuration tree and write a native `fail2zig.toml`. The
optional `<source-dir>` argument is the fail2ban config root; it defaults to
`/etc/fail2ban`.

The importer reads `jail.conf` + `jail.local` + `jail.d/*.conf` in fail2ban's
precedence order, resolves each enabled jail's filter against the 15 built-in
filters (or against `filter.d/<name>.conf` for custom filters), and writes a
migration report to stderr.

```bash
sudo fail2zig --import-config /etc/fail2ban \
              --import-output /etc/fail2zig/config.toml
```

Example output:

```text
migration: imported=3 skipped=0 filters(translated=0 builtin=3 skipped=0) output='/etc/fail2zig/config.toml'
```

See [../guides/migration-from-fail2ban.md](../guides/migration-from-fail2ban.md)
for a full walkthrough.

### `--import-output <path>`

Destination path for the generated TOML file when running `--import-config`.
Default: `/etc/fail2zig/config.toml`. The write is atomic (write to temp file,
rename); the parent directory is created if it does not exist.

### `--version` / `-V`

Print the version string and exit.

```bash
fail2zig --version
# fail2zig v0.1.0
```

### `--help` / `-h`

Print usage information and exit.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success. Clean daemon exit (SIGTERM / SIGINT), or non-daemon operation completed successfully. |
| `1` | Configuration load or validation failure; or `--import-config` completed with zero jails imported. |
| `2` | Hard parse error during `--import-config` (file not found, permission denied, unrecoverable format error). |

## Signals

| Signal | Behavior |
|--------|----------|
| `SIGTERM` | Save ban state to `state_file`, flush logs, shut down cleanly. |
| `SIGINT` | Same as SIGTERM. |
| `SIGHUP` | Stub in v0.1.0. Logs "reload not yet implemented." A restart is required to pick up config changes. |

## Files

| Path | Purpose |
|------|---------|
| `/etc/fail2zig/config.toml` | Default configuration file. |
| `/run/fail2zig/fail2zig.pid` | PID file (location configurable). |
| `/run/fail2zig/fail2zig.sock` | IPC socket for `fail2zig-client` (location configurable). |
| `/var/lib/fail2zig/state.bin` | Binary ban-state file, persisted on shutdown (location configurable). |

## See also

- [fail2zig-client CLI reference](cli-fail2zig-client.md)
- [Configuration reference](config.md)
- Man page: `man fail2zig` (after installation)
