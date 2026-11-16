---
title: 'PortSentry scan detection'
description: 'Configure the qualified PortSentry v2.0.7 history-file recipe, in connect or stealth mode.'
sidebar_position: 5
category: Getting Started
audience: operator
last_verified: 2026-10-22
---

PortSentry detects connections to selected unused ports. fail2zig reads its
history file and owns the resulting ban policy, durable state and firewall enforcement.
Run the sensor with response actions disabled so there is one ban owner. The
integration arrived in 0.4.3; stealth and UDP detection were qualified in 0.4.7.

## Qualified scope

The qualified target is upstream **PortSentry v2.0.7**, commit
`7526767f67b42ba7b7900ebb0f72ace7c4de93d9`, on Debian 13. Two sensor modes are
qualified, each through IPv4 and IPv6 nftables bans, blocking while banned,
expiry and restored connectivity:

- `--connect`: TCP-connect detection.
- `--stealth -m pcap -i <interface>`: TCP SYN, FIN, NULL and XMAS scans, and UDP.
  Stealth mode runs PortSentry as root with pcap on the interface that owns the
  protected address.

This is a specific deployment recipe, not qualification of every PortSentry
version or mode. Legacy PortSentry 1.2, including the Debian 13 standard
repository package, is not compatible with this filter. Other 2.x versions and
stdout, syslog or journal envelopes are unqualified. A same-named legacy Fail2ban
filter cannot be migrated as this integration.

## Configure the sensor

Use the [upstream v2.0.7 release](https://github.com/portsentry/portsentry/releases/tag/v2.0.7)
and its installation instructions. In the sensor configuration, retain one
`TCP_PORTS` list containing ports you have verified are unused on the protected
host, and one `UDP_PORTS` list of verified unused ports when UDP detection is
wanted:

```text
TCP_PORTS="1,11,15"
UDP_PORTS="1,7,9"
HISTORY_FILE="/var/log/portsentry.log"
RESOLVE_HOST="0"
SCAN_TRIGGER="0"
BLOCK_TCP="0"
BLOCK_UDP="0"
```

The ports are examples; choose unused ports for your host. To observe TCP only,
remove or comment every `UDP_PORTS` directive. Do not set `UDP_PORTS=""`:
PortSentry rejects an empty port list. `BLOCK_UDP="0"` disables the sensor's UDP
response but does not stop UDP observations while UDP ports are configured;
accepted observations cause fail2zig bans.

Run the configured sensor in one of the qualified modes:

```bash
sudo portsentry --connect
sudo portsentry --stealth -m pcap -i eth0
```

Ensure the history file exists and is readable by the fail2zig service identity.
Configuration validation alone does not prove source readiness.

## Configure the jail

Add the following to your reviewed fail2zig configuration. Retain default loopback
ignores and review trusted management/scanner addresses in your ignore policy.

```toml
[jails.portsentry]
enabled = true
filter = "portsentry"
source = "file"
timestamp = "iso8601"
logpath = ["/var/log/portsentry.log"]
maxretry = 1
enforce = true
on_truncation = "restart"
```

This excerpt inherits your configured ban duration and firewall policy. Review
them in the [configuration reference](../reference/config.md). With `maxretry = 1`,
one accepted event can trigger a ban. Automatic bans cover the source across host
ports and protocols; they are not restricted to the sensor port.

PortSentry 2.0.7 empties its history file at every process start, not only at
reboot. Without `on_truncation`, the default `refuse` pauses the source after each
PortSentry restart until `fail2zig repair-source` acknowledges it; the daemon keeps
running and other jails enforce. With `restart`, the jail resumes at the start of
the new file and records a continuity-loss event. Records PortSentry appended
after the committed offset and that the emptying removed were never read; neither
value recovers them. This is the operator's choice for this jail. See the
[log file lifecycle](log-lifecycle.md).

The filter validates the whole history record, takes the typed bracketed source
address and preserves the original event time. Ignored, pre-threshold and
sensor-blocked records do not count as accepted detections.

## Validate and activate

Inspect actual history-file samples without starting the daemon:

```bash
sudo fail2zig rule-test --file /var/log/portsentry.log \
  --service portsentry --output table
sudo fail2zig --validate-config --config /etc/fail2zig/config.toml
```

Review the matches before activating the jail. For an existing daemon, request
`sudo fail2zig reload` and inspect the outcome; adding the jail is a live change,
while `on_truncation` on an existing jail requires a restart. A rejected or
restart-required result does not mean the new configuration is active; follow the
[reload guidance](../reference/config.md#validation-and-reload).
For a new installation, start the reviewed service explicitly.

```bash
sudo fail2zig status --details
sudo fail2zig jails --details
sudo fail2zig list --jail portsentry --details
sudo fail2zig history --jail portsentry --details
sudo fail2zig firewall show --details
```

`list --details` and `history --details` show the PortSentry history record
behind each ban.

Confirm source readiness and ban ownership. Test from a controlled, separate
IPv4/IPv6 source you are authorized to use, with an independent management path.
Check a connection or scan against a selected sensor port, the resulting ban, its
expiry and restored connectivity. A matching sample or retained firewall
observation alone does not prove packet enforcement.

## State file growth

A scan sensor with `maxretry = 1` bans every host that touches a sensor port, so
on a public address this jail's ban count follows internet scan traffic. Every ban is
stored with its decision, owner and up to `history_max_matches` matched lines.
New bans wait once the state file's used pages reach a capacity of 262,144 pages
(1 GiB); bans already installed stay enforced and intake resumes when room returns.
Watch `Used pages:` in `fail2zig status` or the `fail2zig_state_file_used_pages`
metric. To store less per ban, lower the jail's share of matched lines:

```toml
[jails.portsentry]
history_max_matches = 1
```

`0` keeps no matched lines for the jail. The change applies on `reload`. See
[matched lines in history](../reference/config.md#matched-lines-in-history).

## Release sources

This recipe follows the [README](../../README.md#filters-and-integrations),
[shipped example](../../deploy/fail2zig.toml.example)
and [configuration manual](../man/fail2zig.toml.5).
