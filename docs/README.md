# fail2zig documentation

Every page describes the release this tree is tagged at. Start with the row that
matches what you are doing.

## Get it running

| You want to | Read |
| --- | --- |
| Install fail2zig or build it from source | [Installation and upgrades](operations/installation.md) |
| Write a first configuration | [Example jail configuration](guides/example-jail-config.md) |
| Move from fail2ban | [Migrating from fail2ban](guides/migration-from-fail2ban.md), [command equivalents](operations/command-migration.md) and the [continuity contract](operations/migration-continuity.md) |
| Upgrade an existing installation | [Upgrading fail2zig](guides/upgrading.md) |
| Check a downloaded release | [Verifying a release build](guides/verifying-zero-dependencies.md) |

## Operate it

| You want to | Read |
| --- | --- |
| Look up a command, its output or its exit code | [Administration](reference/cli-fail2zig-client.md) and [daemon and offline commands](reference/cli-fail2zig.md) |
| Look up a configuration key | [Configuration reference](reference/config.md) |
| Scrape metrics, check health or script the commands | [Monitoring API](reference/api.md) |
| See what a built-in filter matches | [Filters](reference/filters.md) |
| Detect failures in a log no built-in filter covers | [Custom rule files](reference/custom-rules.md) |
| Handle log rotation, truncation or a missing log | [Log file lifecycle](guides/log-lifecycle.md) |
| Detect port scans | [PortSentry scan detection](guides/portsentry.md) |
| Report a problem | [Support bundle](operations/support-bundle.md) |

The installed manuals, `man fail2zig` and `man 5 fail2zig.toml`, are the exact
reference for every command and key. Their sources are
[fail2zig.1](man/fail2zig.1) and [fail2zig.toml.5](man/fail2zig.toml.5).

## Understand it

| You want to know | Read |
| --- | --- |
| How the daemon is built and what its limits are | [Runtime architecture](architecture.md) |
| What is trusted and what each threat's control is | [Threat model](security/threat-model.md) and [trusted computing base](architecture/trusted-computing-base.md) |
| How logs become durable records | [Log watching and continuity](architecture/log-watching.md) |
| How rules are matched | [Parser engine](architecture/parser-engine.md) |
| How bans reach the kernel | [Firewall enforcement](architecture/netlink-interop.md) |
| How memory is bounded | [Memory model](architecture/memory-model.md) |
| What the executable depends on at runtime | [Runtime dependencies](architecture/zero-dependencies.md) |

## Release history

[CHANGELOG.md](../CHANGELOG.md) lists every release. [RELEASE_NOTES.md](../RELEASE_NOTES.md)
has the full notes for supported releases.
