---
title: 'Frequently asked questions'
description: 'Short answers to the questions operators ask most: capacity, large address lists, permanent bans, restarts and reboots, firewall backends, permissions and what the daemon does while idle.'
sidebar_position: 8
category: Getting Started
audience: operator
last_verified: 2026-11-17
---

Each answer links to the page that holds the detail.

## Capacity

### How many bans can fail2zig hold?

65,536 live bans across the whole daemon. Every ban is tracked individually: a
durable record, the jail that owns it, and confirmation that the kernel holds it.
The default memory budget, `native_memory_ceiling_mb = 512`, covers that ceiling;
the plan for 65,536 bans is about 337 MiB. See the
[configuration reference](../reference/config.md#global).

### Can I load a blocklist of hundreds of thousands or millions of addresses?

Not today. Bans are for addresses fail2zig decided on or you entered, and the
ceiling above applies. `banip` in a jail holds addresses and networks you
maintain by hand, up to 1,024 entries per list, and a network counts as one
entry. A separate loader for large curated lists is being designed in the open;
follow [discussion 120](https://github.com/ul0gic/fail2zig/discussions/120).

### What happens when the state file is full?

Intake pauses and resumes by itself. `status` shows
`Intake: waiting (StorageCapacity)` and the `State file:` row shows used and owed
pages against the fixed capacity of 262,144 pages (1 GiB). See [troubleshooting](troubleshooting.md#a-jails-source-is-paused-waiting-or-missing).

## Bans

### How do I ban an address permanently?

Set `bantime = "permanent"` for a jail, or list the address in `banip`. A manual
ban takes `--duration`. Only `bantime` accepts `"permanent"`. See the
[configuration reference](../reference/config.md#defaults).

### Do bans survive a restart of the daemon?

Yes. A normal stop leaves the firewall rules in place, and the daemon logs
`stop left N realized rules in place; the next start reconciles them`. At start it
compares the kernel with its saved state and corrects any difference. Deadlines
are kept: a ban with ten minutes left still has ten minutes left.

### Do bans survive a reboot?

Yes, as long as `state_file` is on persistent storage. The kernel's rules are gone
after a reboot; the daemon installs them again from its state when it starts. A
state file on tmpfs or under `/run` loses everything at reboot, and the daemon
warns about it at start.

### Why did `fail2zig ban` refuse my address?

The client refuses a manual ban that covers loopback, one of the host's own
addresses, or the address of your own SSH session, so you cannot lock yourself
out by accident. `--force` overrides it.

### How do I make sure an address is never banned?

Add it to `ignoreip`, or at runtime with `fail2zig ignore add`. `ignoreself`
covers the host's own addresses. See
[runtime exclusions](../reference/cli-fail2zig-client.md#runtime-exclusions).

### How do I lift every ban at once?

`sudo fail2zig firewall withdraw` removes every rule the daemon installed and
holds enforcement off until the next start. Ban records and deadlines are kept.
See [withdraw enforcement](../reference/cli-fail2zig-client.md#withdraw-enforcement).

## Firewall

### Which firewall backends are supported?

nftables, ipset and iptables. `firewall = "auto"` probes for a usable one and
keeps the one recorded in existing state; naming one forces it and never falls
back to another. The nftables backend talks to the kernel directly and needs no
`nft` binary. The ipset backend needs both the `ipset` and `iptables` tools.

### Can I switch backends?

Not by editing `firewall` on existing state: the daemon refuses with
`InstallationMismatch`, because the saved bans belong to the earlier backend. Do
not delete the state file to force it. See
[troubleshooting](troubleshooting.md#firewall).

### Does fail2zig touch my own firewall rules?

No. Everything it creates is in objects of its own, named `f2z_` followed by 24
hexadecimal characters: one nftables table, or one chain with a jump at the top
of `INPUT`. It changes no rule it did not create.

### What does the daemon do while nothing is happening?

It keeps checking that the kernel still holds what it reports. If another tool
removes or changes its rules, the next check finds the difference and `status`
shows protection as DEGRADED. What `status` says is enforced is what the daemon
confirmed in the kernel.

### Can I run detection without banning anything?

Yes. `enforce = false` on a jail records what it would ban and installs nothing.
`on_no_backend = "log-only"` does the same for the whole daemon when no firewall
backend is usable.

## Operation

### Who may run the commands?

Root and the service user may run every command. A member of the `fail2zig`
group may run `status`, `jails`, `stats`, `version`, a redacted `config` and
`ignore list` with addresses redacted. Ban lists, history and firewall items are
shown only to root and the service user. See the
[administration reference](../reference/cli-fail2zig-client.md).

### Which settings apply on `reload` and which need a restart?

`reload` applies `log_level`, the ban policy keys, the ignore lists, `banip` and
added or removed jails. Everything else needs a restart, and `reload` answers
`restart_required` to say so. The full list is in the
[configuration reference](../reference/config.md#validation-and-reload).

### How do I test a filter before I trust it?

`fail2zig rule-test` runs the real decoder and detectors over a log file, one
line or the journal, and opens no state, firewall or socket. See
[offline rule testing](../reference/cli-fail2zig.md#offline-rule-testing).

### Is there a web interface?

No. With `metrics_enabled = true` the daemon serves Prometheus metrics and JSON
status and health pages for monitoring. See the
[monitoring API](../reference/api.md).

### How long is history kept?

`history_retention` seconds, one day by default. `fail2zig history` pages through
what is retained.

### Can I move from fail2ban without losing my bans?

The migration workflow can transfer protection owners with their original
deadlines and the confirmed history, in journaled steps you can roll back. Read
[migrating from fail2ban](migration-from-fail2ban.md) first: not every setting
has an equivalent, and the tools report what does not transfer.

### Which systems are supported?

Releases are static executables for five Linux targets. Live qualification is on
Debian 13 x86_64 only. See [installation](../operations/installation.md) for what
that does and does not establish, including the
[SELinux and AppArmor](../operations/installation.md#selinux-and-apparmor) position.

### Something is wrong. Where do I start?

[Troubleshooting](troubleshooting.md), then a
[support bundle](../operations/support-bundle.md) if you need to report it.
