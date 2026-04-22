---
title: Configuration reference
description: Complete reference for fail2zig.toml — every key in [global], [defaults], and [jails.<name>], with types, defaults, constraints, and validation rules.
sidebar_position: 1
category: Reference
audience: operator
last_verified: 2026-04-21
---

## File format

fail2zig uses a strict TOML subset. The parser enforces:

- **Unknown keys are rejected** — a typo in a key name is an error, not a
  silent no-op. The error message includes line number and column.
- **Unknown sections are rejected** — only `[global]`, `[defaults]`, and
  `[jails.<name>]` are valid top-level tables.
- **No dotted keys on the left-hand side** — `a.b = 1` is not supported; use
  the section header form `[a]\nb = 1`.
- **String arrays must be same-type** — mixed arrays (strings and integers in
  the same `[...]`) are rejected.

Comments use `#` and may appear on their own line or as a trailing comment after
any value.

Validate a config file without starting the daemon:

```bash
sudo fail2zig --validate-config --config /etc/fail2zig/config.toml
# config: OK (6 jail(s) configured)
```

---

## `[global]`

Settings that apply to the daemon process as a whole.

### `log_level`

**Type:** string  
**Default:** `"info"`  
**Valid values:** `"debug"`, `"info"`, `"warn"`, `"err"`

Controls the verbosity of the daemon's operational logs (written to stderr /
journald). `"debug"` includes per-line parse events and every state-tracker
decision — useful for troubleshooting but verbose on busy servers.
`"err"` shows only hard failures. `"info"` is the production default.

### `pid_file`

**Type:** string (absolute path)  
**Default:** `"/run/fail2zig/fail2zig.pid"`

Path where the daemon writes its PID on startup. The parent directory is
created automatically (mode 0710) if it does not exist. Used by init systems
and monitoring tools. In v0.1.0, daemon mode is always foreground; the PID
file is written but the process does not daemonize.

### `socket_path`

**Type:** string (absolute path)  
**Default:** `"/run/fail2zig/fail2zig.sock"`

Unix domain socket for `fail2zig-client` communication. The parent directory
is created at startup if missing (mode 0710, group `fail2zig` if that group
exists). The socket itself is created at mode 0660. Authentication uses
`SO_PEERCRED` — the daemon accepts commands from root (uid=0) or members of
the `fail2zig` group.

The `fail2zig-client --socket` flag must match this value if you change it.

### `state_file`

**Type:** string (absolute path)  
**Default:** `"/var/lib/fail2zig/state.bin"`

Binary file where ban state is persisted on clean shutdown (SIGTERM or SIGINT).
On startup, if the file exists and its CRC32 checksum validates, the state tracker
is seeded from it and active bans are reconciled with the firewall backend.
On checksum mismatch or unrecognized format, the file is discarded and the daemon
starts with empty state — a warning is logged.

Writes are atomic: the daemon writes to `state.bin.tmp`, fsyncs, sets permissions
to 0600, then renames to `state.bin`. A crash during write leaves the old state
file intact.

### `memory_ceiling_mb`

**Type:** integer  
**Default:** `64`  
**Minimum:** `16`

Hard memory ceiling for the entire daemon, enforced at the allocator level.
The daemon cannot exceed this limit regardless of attack volume. When the state
tracker reaches capacity, the eviction policy governs what happens (see
`[defaults]` → eviction, planned for v0.2.0).

Allocations are partitioned into per-component budgets (state tracker: 32 MB,
parser: 4 MB, log buffers: 8 MB, events: 1 MB, with the remainder available as
headroom). Reducing `memory_ceiling_mb` below the sum of component budgets causes
the daemon to refuse to start with a clear error.

When to change: increase on servers with many jails or high-volume log streams;
decrease on embedded systems or containers with tight memory constraints.

### `metrics_bind`

**Type:** string (IP address)  
**Default:** `"127.0.0.1"`

IP address the HTTP metrics server binds to. The default binds to the loopback
interface only — the metrics endpoint is not reachable from outside the host.
Set to `"0.0.0.0"` to expose metrics to Prometheus scrapers on other hosts, but
only do this if the port is firewalled from public access. The endpoint is
read-only but leaks operational telemetry (ban rates, jail names, memory usage).

### `metrics_port`

**Type:** integer  
**Default:** `9100`  
**Range:** 1–65535

TCP port for the HTTP server. The server exposes:

- `GET /metrics` — Prometheus text exposition (per-jail labels)
- `GET /api/status` — JSON status identical to the IPC `status` response
- `GET /events` — WebSocket upgrade for real-time ban/unban event streaming

Port 9100 is the Prometheus node_exporter convention. If you run both
`node_exporter` and `fail2zig` on the same host, change one of them.

---

## `[defaults]`

Default values applied to every jail unless the jail explicitly overrides them.
The keys here mirror fail2ban's `[DEFAULT]` section.

### `bantime`

**Type:** integer (seconds)  
**Default:** `600`  
**Minimum:** `1`

How long an IP is banned on first offense. Subsequent offenses may result in
longer bans if `bantime_increment_enabled` is true.

### `findtime`

**Type:** integer (seconds)  
**Default:** `600`  
**Minimum:** `1`

The sliding window in which `maxretry` failures must occur before a ban fires.
A `findtime` of 600 with `maxretry` of 5 means: if 5 failures from the same IP
arrive within any 600-second window, that IP is banned.

### `maxretry`

**Type:** integer  
**Default:** `5`  
**Minimum:** `1`

Number of failures within `findtime` required to trigger a ban. Per-IP attempt
history is tracked in a 128-slot ring buffer; entries older than `findtime` are
ignored when evaluating the threshold.

### `banaction`

**Type:** string  
**Default:** `"nftables"`  
**Valid values:** `"nftables"`, `"iptables"`, `"ipset"`, `"log-only"`

The firewall backend used to apply bans. The daemon auto-detects the best
available backend at startup, but this key overrides the selection:

| Value        | Mechanism                                             | When to use                                                   |
| ------------ | ----------------------------------------------------- | ------------------------------------------------------------- |
| `"nftables"` | Direct netlink to the nftables subsystem              | Modern kernels (≥ 3.13). Preferred.                           |
| `"iptables"` | Subprocess call to `iptables` / `ip6tables`           | Legacy kernels or environments where nftables is unavailable. |
| `"ipset"`    | ipset + iptables match rule                           | High-volume ban lists (tens of thousands of IPs).             |
| `"log-only"` | No firewall action; ban decisions appear in logs only | Dry-run mode; side-by-side verification with fail2ban.        |

### `ignoreip`

**Type:** string array  
**Default:** `[]`

IPs and CIDR ranges that are never banned, regardless of how many failures they
generate. Entries may be exact IPs (`"10.0.0.1"`), IPv4 CIDR (`"10.0.0.0/8"`),
or IPv6 CIDR (`"::1/128"`). IPv4-mapped IPv6 addresses (`::ffff:10.0.0.1`) are
canonicalized to their IPv4 form and matched against IPv4 CIDR entries.

```toml
ignoreip = ["127.0.0.1/8", "::1", "10.0.0.0/8", "192.168.0.0/16"]
```

### Bantime increment settings

These five keys control the recidive escalation policy — bans that grow longer
each time the same IP is banned. They live on `[defaults]` rather than individual
jails because v0.1.0 uses a single global state tracker. Per-jail overrides are
parsed but currently inactive (see note below).

#### `bantime_increment_enabled`

**Type:** boolean  
**Default:** `false`

Enables escalating bantimes. When false, every ban uses `bantime` regardless of
how many times the IP has been banned before.

#### `bantime_increment_multiplier`

**Type:** integer (interpreted as float)  
**Default:** `1`

Base multiplier applied to `bantime` at each ban count. For the linear formula:
`bantime × multiplier × (1 + factor × n)`. For the exponential formula:
`bantime × multiplier × factor^n`.

#### `bantime_increment_factor`

**Type:** integer (interpreted as float)  
**Default:** `1`

The growth rate. In the linear formula, this is an additive coefficient. In
the exponential formula, this is the base of the exponent.

#### `bantime_increment_formula`

**Type:** string  
**Default:** `"linear"`  
**Valid values:** `"linear"`, `"exponential"`

Which formula computes ban duration for offense number `n` (zero-indexed):

| Formula       | Expression                                | n=0  | n=1   | n=2 (example: bantime=600, multiplier=1, factor=2) |
| ------------- | ----------------------------------------- | ---- | ----- | -------------------------------------------------- |
| `linear`      | `bantime × multiplier × (1 + factor × n)` | 600s | 1800s | 3000s                                              |
| `exponential` | `bantime × multiplier × factor^n`         | 600s | 1200s | 2400s                                              |

The exponential formula is recommended for SSH jails — a persistent attacker
hitting the same IP accumulates bans that double each time, reaching the max
bantime within a handful of offenses.

#### `bantime_increment_max_bantime`

**Type:** integer (seconds)  
**Default:** `604800` (7 days)

Hard cap on escalated bantimes. No matter how many times an IP has been banned,
its ban duration never exceeds this value.

**Example — worked escalation (exponential, multiplier=1, factor=2, max=86400):**

| Offense            | n   | Duration                   |
| ------------------ | --- | -------------------------- |
| 1st ban            | 0   | 600s (10 minutes)          |
| 2nd ban            | 1   | 1200s (20 minutes)         |
| 3rd ban            | 2   | 2400s (40 minutes)         |
| 4th ban            | 3   | 4800s (80 minutes)         |
| 5th ban            | 4   | 9600s (~2.7 hours)         |
| 6th ban            | 5   | 19200s (~5.3 hours)        |
| 7th ban            | 6   | 38400s (~10.7 hours)       |
| 8th ban            | 7   | 76800s (~21 hours)         |
| 9th ban and beyond | ≥8  | 86400s (24 hours — capped) |

> **v0.1.0 caveat:** Per-jail `bantime_increment_*` keys in `[jails.<name>]`
> sections are parsed and stored but the state tracker is global in this release
> — only the `[defaults]` values take effect. Per-jail escalation is planned for
> Phase 2. If you set different escalation parameters per jail, they will be
> ignored until then.

---

## `[jails.<name>]`

Each jail watches one or more log files and applies bans when a filter matches
a configured number of times within a time window. The jail name (`<name>`) must
be a non-empty string containing ASCII alphanumeric characters, hyphens, and
underscores.

```toml
[jails.sshd]       # jail named "sshd"
[jails.nginx-http-auth]   # hyphen is valid
```

### `enabled`

**Type:** boolean  
**Default:** `true`

When false, the jail is parsed and validated but no log watcher or parser is
instantiated. Useful for disabling a jail without removing its configuration.

### `filter`

**Type:** string  
**Default:** `""`

Name of the filter to apply to this jail's log lines. Must be one of the 15
built-in filter names (see [filters.md](filters.md)) or a name that resolves
to a valid pattern set. If empty and `enabled = true`, a warning is logged at
startup. Unknown filter names cause the daemon to log a warning and the jail
to operate without matching (no bans will fire).

Filter names accept both hyphenated and underscore forms interchangeably:
`"nginx-http-auth"` and `"nginx_http_auth"` are identical.

### `logpath`

**Type:** string array  
**Default:** `[]`

One or more absolute paths to log files for this jail. The daemon watches each
path with inotify for new content and handles log rotation (file rename, new
file creation, copytruncate truncation) automatically.

```toml
logpath = ["/var/log/auth.log", "/var/log/secure"]
```

Missing paths at startup are logged as warnings but are not fatal — a log file
that appears after the daemon starts (e.g., after a service restarts) is picked
up automatically.

### `maxretry`

**Type:** optional integer  
**Default:** inherits `[defaults].maxretry`  
**Minimum:** 1

Overrides the global `maxretry` for this jail only.

### `findtime`

**Type:** optional integer (seconds)  
**Default:** inherits `[defaults].findtime`  
**Minimum:** 1

Overrides the global `findtime` for this jail only.

### `bantime`

**Type:** optional integer (seconds)  
**Default:** inherits `[defaults].bantime`  
**Minimum:** 1

Overrides the global `bantime` for this jail only.

### `banaction`

**Type:** optional string  
**Default:** inherits `[defaults].banaction`  
**Valid values:** `"nftables"`, `"iptables"`, `"ipset"`, `"log-only"`

Overrides the firewall backend for this jail only. Useful when one jail needs
a different banning mechanism (e.g., `"log-only"` for a low-confidence filter).

### `ignoreip`

**Type:** optional string array  
**Default:** inherits `[defaults].ignoreip`

Per-jail ignore list. When set, this entirely replaces (does not merge with)
the global `ignoreip` for this jail. If you want to extend the global list,
you must repeat the global entries here.

### Per-jail `bantime_increment_*`

All five `bantime_increment_*` keys are accepted in jail sections and are parsed
without error. In v0.1.0, they are stored but not used — only the values from
`[defaults]` take effect. This is documented here so operators aren't confused
by the lack of per-jail escalation behavior.

---

## A complete worked example

A production-shape `fail2zig.toml` protecting SSH, nginx basic auth,
and postfix — with commentary on each block — lives on its own page:
[Example jail configuration](../guides/example-jail-config).

Use that as a starting template and adapt the four or five values
that matter for your environment (`ignoreip`, `memory_ceiling_mb`,
per-jail `maxretry` / `bantime`).

If you are migrating from an existing fail2ban install, the
field-by-field mapping between `jail.conf` and `fail2zig.toml`
lives on the [migration guide](../guides/migration-from-fail2ban).

---

## Validation

Run this before starting or restarting the daemon:

```bash
sudo fail2zig --validate-config --config /etc/fail2zig/config.toml
```

**Success output:**

```text
config: OK (3 jail(s) configured)
```

**Error output (example — unknown key):**

```text
config: line 7, col 1: unknown key 'bnatime' in section [defaults]
```

Validation checks performed:

- `memory_ceiling_mb` ≥ 16
- `bantime` > 0 in `[defaults]` and any per-jail override
- `findtime` > 0 in `[defaults]` and any per-jail override
- `maxretry` > 0 in `[defaults]` and any per-jail override
- Socket path parent directory exists (a warning, not a hard failure — the daemon creates it at startup)
- No duplicate jail names
- All string values are valid TOML strings

Missing log file paths are logged as warnings but do not cause validation to fail — a missing log file may appear after the daemon starts (e.g., nginx creates its error log on first request).
