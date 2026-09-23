<div align="center">

# fail2zig

**A Linux intrusion prevention daemon written in Zig.**

[![CI](https://img.shields.io/github/actions/workflow/status/ul0gic/fail2zig/ci.yml?branch=main&label=CI&logo=github)](https://github.com/ul0gic/fail2zig/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue.svg)](LICENSE)
[![Zig](https://img.shields.io/badge/zig-0.14.1-F7A41D?logo=zig&logoColor=white)](https://ziglang.org/download/)
[![Platform](https://img.shields.io/badge/platform-Debian%2013%20x86__64-lightgrey)](#platform-and-support)
[![Version](https://img.shields.io/github/v/release/ul0gic/fail2zig?label=version&color=orange)](https://github.com/ul0gic/fail2zig/releases/latest)

</div>

fail2zig watches file and journal logs, detects abusive activity with bounded native
parsers, and enforces bans through nftables, ipset or iptables. One executable
contains the daemon, administrative commands, rule testing and fail2ban migration
tools. It uses statically embedded SQLite for durable source progress, detection
state and protection ownership. It needs no Python or shared SQLite library at
runtime; journal and legacy firewall backends still use their documented host tools.

## Quick start

```bash
# Inspect the installer before running it as root.
curl -fsSL https://github.com/ul0gic/fail2zig/raw/main/scripts/install.sh | less

# Install the latest release. The installer verifies downloaded assets and does not start the service.
curl -fsSL https://github.com/ul0gic/fail2zig/raw/main/scripts/install.sh | sudo bash

# Review /etc/fail2zig/config.toml, then validate and start protection.
sudo fail2zig --validate-config --config /etc/fail2zig/config.toml
sudo systemctl enable --now fail2zig
sudo fail2zig status
```

The installer creates a dedicated `fail2zig` service account, preserves existing
configuration and installs the unit, man pages and example config. For a dry run,
manual installation, source build or upgrade, see
[installation and upgrades](docs/operations/installation.md). The latest release
is recommended; **v0.4.0 is the minimum supported version**. Pre-v0.4.0
installation and rollback are unsupported.

## Why fail2zig

- **Bounded detection.** Built-in filters compile into specialized parsers with
  explicit input and memory limits. Protection-critical receipts, retry state and
  firewall ownership are retained rather than evicted to satisfy a ceiling.
- **Durable protection.** SQLite transactions preserve source progress and
  detection state; firewall effects are reconciled with observed kernel state
  across restarts. Storage failures pause affected ingestion and report degraded
  health while existing protection remains in place.
- **Scoped enforcement.** nftables uses netlink directly. ipset and iptables use
  fixed-argument host tools. An unavailable backend fails closed unless an operator
  explicitly chooses `on_no_backend = "log-only"`.
- **Operator visibility.** `status`, `jails`, `list`, `history` and the read-only
  `firewall show` command expose protection and its last sampled firewall
  observation. Optional loopback HTTP serves metrics, health and events.
- **Controlled migration.** The fail2ban importer reports unsupported settings;
  the supported migration workflow plans and validates an offline state projection
  before journaled cutover. Exact fail2ban compatibility is not promised.

The [runtime architecture](docs/architecture.md) describes state, privilege and
backend boundaries. The [parser engine](https://fail2zig.com/docs/architecture/parser-engine/)
and [memory model](https://fail2zig.com/docs/architecture/memory-model/) explain
the bounded paths.

## Configuration

The installer places an example at `/etc/fail2zig/config.toml`. Edit it for the
services and log sources on the host, then run `fail2zig --validate-config` before
starting or restarting the daemon. Unknown or duplicate keys are rejected. The
shipped unit runs as the `fail2zig` user; the configuration and state paths must
remain accessible under that service identity.

```toml
[global]
firewall = "auto"

[defaults]
bantime = "10m"
findtime = "10m"
maxretry = 5

[jails.sshd]
enabled = true
filter = "sshd"
source = "journald"
```

`firewall = "auto"` selects a usable backend on first installation and retains
the recorded backend thereafter. Changing the backend or its network namespace
selector does not migrate existing ownership. Do not delete the state database to
switch backends. The full [example configuration](deploy/fail2zig.toml.example),
[config reference](docs/man/fail2zig.toml.5) and
[online guide](https://fail2zig.com/docs/reference/config/) cover jail settings,
source validation, durations, reload limits and firewall selection.

## Commands and operations

```bash
sudo fail2zig status                       # protection, storage and source health
sudo fail2zig jails --details              # per-jail state and diagnostic detail
sudo fail2zig list                         # active bans
sudo fail2zig firewall show --details      # last sampled owned firewall state
sudo fail2zig rule-test --file /var/log/auth.log --service sshd --output table
```

`firewall show` is a bounded, read-only snapshot from the daemon's last complete
readback; it does not refresh the kernel on demand or prove end-to-end packet
reachability. Check its observation age and latest attempt when diagnosing
protection. A degraded or intervention state needs investigation of the reported
cause; deleting state or blindly repeating an uncertain mutation is not a recovery
step. See the [CLI manual](docs/man/fail2zig.1),
[command migration guide](docs/operations/command-migration.md) and
[persistence recovery guidance](docs/operations/migration-continuity.md).

For fail2ban migration, start with a configuration projection and review its
compatibility report:

```bash
sudo fail2zig --import-config /etc/fail2ban \
  --import-output /etc/fail2zig/config.toml
```

The [migration guide](https://fail2zig.com/docs/guides/migration-from-fail2ban/)
covers the inspect, snapshot, plan, validate, cutover and rollback workflow.
Unsupported enabled protection, custom executable actions and unsafe continuity
block activation before mutation. The fail2ban converter does not convert released
v0.3.0 fail2zig binary state.

## Filters and integrations

The 16 built-in filters cover SSH, nginx, Apache, mail, DNS, FTP, MySQL,
PortSentry and repeat offenders (`recidive`). See the
[filter reference](https://fail2zig.com/docs/reference/filters/) for exact names
and matching behavior. Native custom rules are bounded; arbitrary runtime regexes
and shell-script ban actions are not supported.

PortSentry support targets **v2.0.7 history files**, with qualified IPv4 and IPv6
TCP-connect operation on Debian 13. PortSentry acts as the sensor; leave its own
response actions disabled so fail2zig owns enforcement. PortSentry 1.2, UDP and
stealth-mode deployments are outside that qualification. Follow the
[PortSentry setup guide](https://fail2zig.com/docs/guides/portsentry/) before
enabling a jail.

## Platform and support

The current release ships static musl executables for x86_64, AArch64, ARMv7 and
both MIPS32r2 byte orders. Debian 13 x86_64 has selected live qualification.
Other targets have cross-build and emulated checks; these do not qualify live
kernel enforcement. Isolated Ubuntu 24.04 SSH log-source checks do not establish
full Ubuntu platform support. See [installation and upgrades](docs/operations/installation.md)
for the release targets and validation limits.

The service is Linux-only. It runs under a dedicated non-login UID with declared
capabilities, not as a root daemon. Journald ingestion requires `journalctl`;
iptables and ipset backends require those tools. The nftables backend uses kernel
netlink without an `nft` executable. The [security policy](SECURITY.md) and
[architecture](docs/architecture.md) describe the privilege and dependency
boundaries.

## Documentation and contributing

- [Installation and upgrades](docs/operations/installation.md)
- [Configuration reference](docs/man/fail2zig.toml.5) and [CLI manual](docs/man/fail2zig.1)
- [Runtime architecture](docs/architecture.md) and [operations guides](docs/operations/)
- [Online documentation](https://fail2zig.com/docs/) and [test layout](tests/README.md)
- [Contributing](CONTRIBUTING.md), [issues](https://github.com/ul0gic/fail2zig/issues) and [discussions](https://github.com/ul0gic/fail2zig/discussions)

Contributions to filters, tests, documentation and core code are welcome. Include
representative positive and negative log lines for filter proposals. Use a private
[security advisory](https://github.com/ul0gic/fail2zig/security/advisories/new)
for vulnerabilities.

## License

fail2zig is available under [AGPL-3.0-or-later](LICENSE). Individuals and
enterprises may use, contribute to and fork it under those terms.

## Trademark

"fail2zig", the fail2zig wordmark, and the fail2zig logo are trademarks of
the project maintainer. Trademark rights are asserted immediately (™) and
registration is planned.

You may fork and modify the code under the AGPL-3.0-or-later. You may **not**:

- use the "fail2zig" name, wordmark, or logo for a derived, modified, or
  repackaged distribution;
- imply your fork is the official project, endorsed by the maintainer, or
  affiliated with fail2zig;
- use the name or branding for a commercial hosted service offering.

If you ship a fork, give it a different name. Contact the maintainer for any
trademark licensing question.
