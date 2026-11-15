---
title: Example jail configuration
description: A configuration for Debian SSH journal input, confirmed-ban recidive and an optional file jail.
sidebar_position: 1
category: Getting Started
audience: operator
last_verified: 2026-10-22
---

Start with the [shipped example](../../deploy/fail2zig.toml.example).
To add scan detection, follow the [PortSentry v2.0.7 setup guide](portsentry.md).
This version makes the source and duration choices explicit. Adjust paths and
policy for your host, then validate before starting the service.

## Configuration

```toml
[global]
log_level = "info"
socket_path = "/run/fail2zig/fail2zig.sock"
state_file = "/var/lib/fail2zig/state.bin"
memory_ceiling_mb = 64
metrics_enabled = true
metrics_bind = "127.0.0.1"
metrics_port = 9100
firewall = "auto"
on_no_backend = "fail-closed"

[defaults]
bantime = "10m"
findtime = "10m"
maxretry = 5
enforce = true
ignoreip = ["127.0.0.1/8", "::1"]

[jails.sshd]
enabled = true
filter = "sshd"
source = "journald"
journal_executables = ["/usr/sbin/sshd", "/usr/lib/openssh/sshd-session"]
maxretry = 3
bantime = "1h"
bantime_increment_enabled = true
bantime_increment_multiplier = 1
bantime_increment_factor = 2
bantime_increment_formula = "exponential"
bantime_increment_max_bantime = "1w"
bantime_increment_jitter = "0s"

[jails.recidive]
enabled = true
filter = "recidive"
source = "internal"
maxretry = 2
findtime = "1d"
bantime = "1w"

[jails.nginx-http-auth]
enabled = false
filter = "nginx-http-auth"
source = "file"
timestamp = "undated"
logpath = ["/var/log/nginx/error.log"]
```

## Why these settings

SSH journal origins include both Debian 13 listener/session executable paths.
Check paths on your own installation; do not substitute a journal tag for origin
validation. Recidive consumes confirmed bans from other jails, so it needs no log file.

The optional nginx jail stays disabled until you verify its source and matcher.
`undated` explicitly uses the undated input contract; choose a supported dated
contract when your format supplies usable event timestamps. Test representative
records with `fail2zig rule-test` before enabling enforcement.

The SSH example doubles durations with multiplier 1 and factor 2, up to one week,
with jitter disabled. The shipped example file sets multiplier 2 with the
exponential formula and no factor; because the factor defaults to 1, that gives a
constant two-hour repeat ban, not a doubling one. Use the keys shown here when you
want doubling. Other jails inherit the defaults, including the 30-day
`bantime_increment_decay`. Quoted durations are configuration syntax; on the
command line only `ban --duration` and `ignore add --for` accept it.

Keep loopback ignores, including when replacing `ignoreip` in an individual jail.
`ignoreself` (default `true`) adds the host's own addresses as well. Add
management addresses only when your trust policy requires it; do not blindly
ignore broad networks. A `banip` list bans addresses while they are listed; an
address may not appear in both lists of one jail.

## Validate and inspect

```bash
sudo fail2zig --validate-config --config /etc/fail2zig/config.toml
sudo fail2zig status
sudo fail2zig jails
```

Validation does not start the service. Status/jails require a running daemon and
show the actual storage, source and protection state. The SQLite parent and
store must belong to the service UID, and systemd must permit writes there.
See [upgrading](upgrading.md) before reusing an older state path.

`firewall` chooses the global backend; `enforce` selects jail policy. To observe
only, set `enforce = false` and check all jail overrides. To disable HTTP
while retaining socket monitoring, set `metrics_enabled = false`.

See the [configuration reference](../reference/config.md) for other settings and
[administration](../reference/cli-fail2zig-client.md#reload) for reload/restart boundaries.
