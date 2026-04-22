---
title: Example jail configuration
description: A readable end-to-end fail2zig.toml that protects SSH, nginx basic auth, and postfix — with commentary on each block, recidive escalation tuning, and a hardened ignoreip policy.
sidebar_position: 4
category: Getting Started
audience: operator
last_verified: 2026-04-21
---

# Example jail configuration

This page is a complete, production-shape `fail2zig.toml`. It is the
config a mid-size Linux server running SSH, nginx with basic auth,
and postfix would realistically deploy. Every block is annotated
with why it looks the way it does — the goal is that you can adapt
this file to your own environment by reading it once and changing
four or five values.

If you want the field-by-field reference, that lives at
[Configuration reference](../reference/config). If you are migrating
from fail2ban, start with [Migrating from fail2ban](migration-from-fail2ban)
— it covers auto-import.

## What this config does

- Watches `sshd`, `nginx`, and `postfix` logs.
- Uses direct netlink to nftables for ban enforcement.
- Caps memory at 64 MB regardless of attack volume.
- Escalates repeat offenders exponentially, up to a two-week ceiling.
- Ignores loopback, the internal subnet, and the Ansible control host.
- Exposes Prometheus metrics on localhost only.

## The file

```toml
# /etc/fail2zig/config.toml
# ---------------------------------------------------------------
# Example production config: SSH + nginx basic auth + postfix.
# ---------------------------------------------------------------

[global]
# Operational logging. "info" is production; bump to "debug" when
# investigating specific match / ban decisions.
log_level         = "info"

# Where the daemon writes its process artifacts. Defaults are fine
# for any distribution using systemd conventions; only change if you
# are running under runit / s6 / OpenRC with different FHS layouts.
pid_file          = "/run/fail2zig/fail2zig.pid"
socket_path       = "/run/fail2zig/fail2zig.sock"
state_file        = "/var/lib/fail2zig/state.bin"

# Hard memory ceiling — enforced at the allocator level, not a target.
# 64 MB is generous for a single-host deployment. Drop to 32 on a
# memory-constrained VPS; raise only if you run >50 jails or pull from
# multi-GB log streams with long findtime windows.
memory_ceiling_mb = 64

# Prometheus metrics. Bind localhost only — the endpoint is read-only
# but leaks operational telemetry (jail names, ban rates, memory use)
# that is needlessly useful to a reconnaissance attacker.
metrics_bind      = "127.0.0.1"
metrics_port      = 9100

# ---------------------------------------------------------------
# Defaults that apply to every jail unless it overrides them.
# ---------------------------------------------------------------

[defaults]
# 10-minute first-offense ban, 10-minute sliding window, 5 failures
# required to trigger. Matches fail2ban's long-standing defaults so
# operators coming from there do not get surprised.
bantime   = 600
findtime  = 600
maxretry  = 5

# nftables is the preferred backend on any modern kernel (>= 3.13).
# The daemon falls back to iptables / ipset / log-only automatically
# if nftables is not available — setting this explicitly is a
# documentation choice, not a requirement.
banaction = "nftables"

# Never ban these sources, regardless of log content.
#  - Loopback: never reachable externally.
#  - Internal 10.0.0.0/8: your network; do not accidentally fence
#    yourself out during an incident.
#  - Ansible control host: the operator's own tooling is not an
#    attacker even when its retry policy looks like one.
ignoreip = [
    "127.0.0.1/8",
    "::1",
    "10.0.0.0/8",
    "192.168.1.50/32",
]

# Recidive escalation. A persistent attacker on the same IP hits
# longer and longer bans without any per-jail tuning required.
#   offense 1:  10 minutes
#   offense 2:  20 minutes
#   offense 3:  40 minutes
#   offense 4:  80 minutes
#   offense 5:  ~2.7 hours
#   offense 6+: eventually capped at 14 days
# Exponential is the right shape for this — linear lets a patient
# attacker probe forever without accumulating meaningful cost.
bantime_increment_enabled     = true
bantime_increment_formula     = "exponential"
bantime_increment_multiplier  = 1
bantime_increment_factor      = 2
bantime_increment_max_bantime = 1209600   # 14 days in seconds

# ---------------------------------------------------------------
# SSH is the highest-value surface on most servers. Tighten the
# threshold and extend the first-offense ban accordingly.
# ---------------------------------------------------------------

[jails.sshd]
enabled  = true
filter   = "sshd"
logpath  = [
    "/var/log/auth.log",  # Debian / Ubuntu convention
    "/var/log/secure",    # RHEL / Fedora / CentOS convention
]

# 3 failures instead of the default 5. Real users rarely miss their
# password three times in ten minutes; credential-stuffing botnets do
# so in under a second.
maxretry = 3

# 1-hour first-offense ban. Recidive escalation still applies on top
# of this, so a returning IP hits 2h / 4h / 8h / ... next.
bantime  = 3600

# ---------------------------------------------------------------
# nginx HTTP basic auth. Defaults are fine here — the surface is
# lower-value than SSH and legitimate users do sometimes fat-finger
# a password a few times.
# ---------------------------------------------------------------

[jails.nginx-http-auth]
enabled = true
filter  = "nginx-http-auth"
logpath = ["/var/log/nginx/error.log"]
# Inherits maxretry = 5, findtime = 600, bantime = 600 from [defaults].

# ---------------------------------------------------------------
# Postfix SASL. Tuned slightly longer than the default — mail
# auth failures are almost always automated, and a 30-minute ban
# costs real attackers meaningfully more than the stock 10-minute.
# ---------------------------------------------------------------

[jails.postfix]
enabled  = true
filter   = "postfix"
logpath  = [
    "/var/log/mail.log",   # Debian / Ubuntu
    "/var/log/maillog",    # RHEL / Fedora / CentOS
]
maxretry = 5
bantime  = 1800
```

## Before you start the daemon

Validate the file without touching the firewall or starting the
event loop:

```bash
sudo fail2zig --validate-config --config /etc/fail2zig/config.toml
```

Expected output:

```text
config: OK (3 jail(s) configured)
```

If validation reports a specific line and column, fix that and
re-run. Do not start the daemon with a config that has not
validated cleanly.

## Adapting this to your environment

The values you are most likely to change:

| Key | Why you might change it |
|---|---|
| `ignoreip` | Add your office egress, monitoring probes, load balancer health-check source IPs. |
| `memory_ceiling_mb` | Decrease on small VPSes or containers; increase only with many jails + long `findtime`. |
| `[jails.sshd].maxretry` | Drop to 2 for a paranoid SSH-only bastion; keep at 3 for mixed-use servers. |
| `[jails.nginx-http-auth].filter` | If you use `nginx-limit-req` or `nginx-botsearch` instead, swap it in. |
| `bantime_increment_factor` | Lower to 1.5 for a gentler curve, raise to 3 for aggressive escalation. |
| `bantime_increment_max_bantime` | Shorten to 86400 (1 day) if you accept the risk of mislabelled real users getting back in faster. |

If you add a new jail, the three keys that matter are `filter`,
`logpath`, and (usually) `maxretry`. Everything else is inherited
from `[defaults]` unless you opt out explicitly.

## Related reading

- [Configuration reference](../reference/config) — every key, every
  type, every validation rule.
- [Filters reference](../reference/filters) — the 15 built-in
  filters and which log paths each one expects.
- [Migrating from fail2ban](migration-from-fail2ban) — if you
  already have a working fail2ban tree, auto-import first and then
  come back to this page to tighten values.
