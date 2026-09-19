# Security Policy

fail2zig parses attacker-controlled input and manages kernel firewall state.
If you have found a vulnerability, please report it privately.

## Privileges and trust boundaries

The shipped [systemd unit](deploy/fail2zig.service) runs as the dedicated
`fail2zig` user and group, not root. It retains `CAP_NET_ADMIN` for firewall
management, `CAP_NET_RAW` for the iptables ipset extension, and
`CAP_DAC_READ_SEARCH` for protected log and journal access. These are significant
privileges: the service account is not an unprivileged sandbox. HTTP monitoring
runs in the same process and shares those capabilities.

The unit also restricts filesystem access, syscalls and address families.
The [installer](scripts/install.sh) requires root to install files, create the
service account and prepare state ownership. It does not start or restart the
service. Configuration and executable files remain administrator-owned;
the native state directory and database belong to the daemon account.

Manual invocation runs with the caller's identity and privileges. It does not
acquire the systemd unit's capabilities or hardening automatically. All-log-only
configurations can run without firewall capability when their source and state
permissions allow it.

Local administrative commands use the Unix socket. Peer credentials authorize
mutations for root or the daemon UID; other users with socket access have
read-only monitoring access. Attacker-controlled logs are data, not configuration
or executable actions. See the [runtime architecture](docs/architecture.md) for
source validation, durable state and enforcement boundaries.

## Reporting a vulnerability

**Use GitHub's private security advisory form:**

<https://github.com/ul0gic/fail2zig/security/advisories/new>

This creates a private report visible only to the fail2zig maintainers. Do
not open a public issue for a security vulnerability. Public issues are
indexed immediately and give attackers a fix window before we have one.

If GitHub is unavailable, or you need an out-of-band channel, contact the
maintainer via the address listed on the GitHub profile.

## What to include

- A description of the vulnerability and the component affected (parser,
  firewall backend, IPC, state persistence, metrics endpoint, config
  importer).
- A minimal reproduction: config, input, commands, observed behavior,
  expected behavior.
- The fail2zig version (`fail2zig --version`) and the kernel version
  (`uname -r`).
- Any working exploit or proof-of-concept, if you have one. We will not
  ask you for one you do not already have.

## What we commit to

- **Acknowledgement within 48 hours** of a valid report.
- **An initial assessment, best-effort within 14 days**, covering severity,
  affected versions, whether a fix path is clear.
- **A fix before public disclosure** for high-severity issues, or a
  coordinated 90-day disclosure timeline agreed with the reporter.
- **Credit** in the advisory and the release notes, unless you request
  otherwise.
- **No legal action** against anyone reporting in good faith and staying
  within the scope below.

We do not run a bug bounty program.

## Scope

In scope:

- The unified `fail2zig` executable, including the daemon and administrative CLI.
- The filter definitions shipped in the repository.
- Embedded dependencies as used by fail2zig, including the vendored SQLite code.
- The installer, service unit, release packaging and published release artifacts.
- The fail2zig.com marketing and documentation site.

Out of scope:

- Vulnerabilities in the Linux kernel itself (report to the kernel
  security team).
- Vulnerabilities in the services being protected (`sshd`, `nginx`,
  `postfix`, etc.).
- Social engineering of maintainers or project contributors.
- Host-wide exhaustion caused independently of fail2zig. Resource exhaustion
  triggered through fail2zig's own input handling, state growth or administrative
  interfaces is in scope. Internal budgets are not a promise to bound all host
  memory or resources.

## Non-vulnerability bugs

Operational bugs and feature requests without security impact belong in the
public issue tracker:

<https://github.com/ul0gic/fail2zig/issues>

Use the private advisory channel for crashes, regressions or resource exhaustion
that could affect security, including bypassed detection, unauthorized operations
or loss of installed protection. If you are unsure whether a report is security
sensitive, send it privately first.

## Audit and disclosure log

Published advisories, audit reports, and disclosure timelines live at:

<https://github.com/ul0gic/fail2zig/security/advisories>

The threat model this policy is derived from: <https://fail2zig.com/threat-model>
