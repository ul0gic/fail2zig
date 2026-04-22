---
title: 'fail2zig-client — CLI reference'
description: Complete command-line reference for fail2zig-client, the unprivileged control tool for the fail2zig daemon.
sidebar_position: 4
category: Reference
audience: operator
last_verified: 2026-04-21
---

`fail2zig-client` queries and controls the running `fail2zig` daemon over its
Unix domain socket. It is a separate binary that does not require root — it
requires either uid=0 or membership in the `fail2zig` group.

## Synopsis

```text
fail2zig-client [GLOBAL FLAGS] <COMMAND> [COMMAND ARGS]
```

## Global flags

Global flags may appear before or after the command name.

### `--socket <path>`

Unix socket path. Default: `/run/fail2zig/fail2zig.sock`.

Override when the daemon is configured with a non-default `global.socket_path`,
or when testing against a non-production instance.

### `--output <format>`

Output format. One of: `table` (default), `json`, `plain`.

`table` renders box-drawing borders with ANSI color on a terminal. `plain` emits
tab-separated values with no borders or color, suitable for scripting. `json`
emits compact JSON.

### `--no-color`

Disable ANSI color output unconditionally.

### `--timeout <ms>`

Command timeout in milliseconds. Default: `5000`. If the daemon does not respond
within this window, the client exits with code 3 and prints a diagnostic.

### `--version` / `-V`

Print the client version and exit. Does not contact the daemon.

```bash
fail2zig-client --version
# fail2zig-client 0.1.0
```

### `--help` / `-h`

Print usage information and exit.

## Commands

### `status`

Show a summary of daemon health.

```bash
sudo fail2zig-client status
```

```text
+------------------------------------------+
| fail2zig 0.1.0 — running                |
+------------------------------------------+
| Uptime:      0d 0h 40m 54s               |
| Memory:      0.0 MB                      |
| Parse rate:  0 lines/sec                 |
| Active bans: 0                           |
| Total bans:  -                           |
| Backend:     nftables                    |
| Jails:       -                           |
+------------------------------------------+
```

As JSON:

```bash
sudo fail2zig-client status --output json
```

```json
{
  "version": "0.1.0",
  "uptime_seconds": 2468,
  "memory_bytes_used": 0,
  "parse_rate": 0,
  "active_bans": 0,
  "jail_count": 6,
  "backend": "nftables"
}
```

---

### `ban <ip> [--jail <name>] [--duration <seconds>]`

Manually ban an IP address.

```bash
sudo fail2zig-client ban 45.227.253.98 --jail sshd
```

`--jail` names the jail the ban is attributed to. If omitted, the ban is
attributed to an internal "manual" category. `--duration` sets the ban duration
in seconds; if omitted, the jail's configured `bantime` is used.

> **v0.1.0 note:** `--duration` is accepted but the daemon currently uses the
> jail's configured `bantime`. Per-command duration override will be honored
> in v0.2.0.

---

### `unban <ip> [--jail <name>]`

Remove a ban.

```bash
sudo fail2zig-client unban 45.227.253.98 --jail sshd
```

If `--jail` is specified, only the ban in that jail is removed. If omitted,
the ban is removed from all jails.

---

### `list [--jail <name>]`

List active bans.

```bash
sudo fail2zig-client list
```

```text
IP                 JAIL    BANNED AT             TIME LEFT
------------------------------------------------------------
45.227.253.98      sshd    2026-04-21 12:03:10   57m 43s
```

Filter to a specific jail:

```bash
sudo fail2zig-client list --jail sshd --output plain
```

---

### `jails`

List configured jails and their current state.

```bash
sudo fail2zig-client jails
```

```text
JAIL                STATE     ACTIVE    MAX RETRY FIND TIME   BAN TIME
-----------------------------------------------------------------------
sshd                enabled   0         3         10m         5m
nginx-http-auth     enabled   0         3         10m         5m
nginx-botsearch     enabled   0         3         10m         5m
postfix             enabled   0         3         10m         5m
apache-auth         enabled   0         3         10m         5m
dovecot             enabled   0         3         10m         5m
Total: 6 jails
```

---

### `reload`

Signal the daemon to reload its configuration.

> **v0.1.0 note:** The `reload` command is implemented at the IPC level but the
> daemon-side handler is a stub. The daemon logs the request and acknowledges
> it, but does not reload the config. A service restart is required to pick up
> configuration changes.

```bash
sudo fail2zig-client reload
```

---

### `version`

Print the daemon version (requires a live daemon connection, unlike `--version`).

```bash
sudo fail2zig-client version
```

---

### `completions <bash|zsh|fish>`

Print a shell completion script to stdout.

```bash
# Bash (system-wide)
sudo fail2zig-client completions bash > /etc/bash_completion.d/fail2zig-client

# Zsh (per-user)
fail2zig-client completions zsh > ~/.zsh/completions/_fail2zig-client

# Fish
fail2zig-client completions fish > ~/.config/fish/completions/fail2zig-client.fish
```

---

### `help [<command>]`

Print general help or help for a specific command.

## Exit codes

| Code | Meaning                                                                                               |
| ---- | ----------------------------------------------------------------------------------------------------- |
| `0`  | Success.                                                                                              |
| `1`  | Daemon returned an error response (e.g., unknown jail name, IP not found).                            |
| `2`  | Bad arguments or invalid input (unknown command, missing required argument, unrecognized IP address). |
| `3`  | Connection failed: daemon is not running, permission denied, or command timed out.                    |

## Prometheus and HTTP alternatives

The daemon also exposes a read-only HTTP server on `127.0.0.1:9100` by default:

| Endpoint          | Description                                                                                    |
| ----------------- | ---------------------------------------------------------------------------------------------- |
| `GET /metrics`    | Prometheus text exposition with per-jail `{jail="..."}` labels.                                |
| `GET /api/status` | JSON — same payload as `status --output json`.                                                 |
| `GET /events`     | WebSocket upgrade; broadcasts `ip_banned`, `ip_unbanned`, `attack_detected`, `metrics` events. |

```bash
curl -s http://127.0.0.1:9100/api/status
# {"version":"0.1.0","uptime_seconds":2468,...}

curl -s http://127.0.0.1:9100/metrics | grep fail2zig_active_bans
# fail2zig_active_bans 0
# fail2zig_active_bans{jail="sshd"} 0
```

## See also

- [fail2zig daemon CLI reference](cli-fail2zig.md)
- [Configuration reference](config.md)
- Man page: `man fail2zig-client` (after installation)
