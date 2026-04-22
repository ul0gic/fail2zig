# Security Policy

fail2zig runs as root, parses attacker-controlled input, and writes kernel
firewall state. The security of the tool matters more than the features of
the tool. If you have found a vulnerability, we want to hear from you.

## Reporting a vulnerability

**Use GitHub's private security advisory form:**

<https://github.com/ul0gic/fail2zig/security/advisories/new>

This creates a private report visible only to the fail2zig maintainers. Do
not open a public issue for a security vulnerability — public issues are
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
- **An initial assessment, best-effort within 14 days** — severity,
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

- The fail2zig daemon and the `fail2zig-client` CLI.
- The filter definitions shipped in the repository.
- The release binaries published on the releases page.
- The Astro-built marketing and documentation site served from
  `fail2zig.com`.

Out of scope:

- Vulnerabilities in the Linux kernel itself (report to the kernel
  security team).
- Vulnerabilities in the services being protected (`sshd`, `nginx`,
  `postfix`, etc.).
- Social engineering of maintainers or project contributors.
- Denial-of-service attacks that require exhausting the host's resources
  beyond what fail2zig itself consumes — the memory ceiling is a
  hard bound on fail2zig, not on the host.

## Non-vulnerability bugs

Operational bugs, crashes, regressions, and feature requests belong in
the public issue tracker:

<https://github.com/ul0gic/fail2zig/issues>

Use that channel freely — public issues are how the project gets better.
The private advisory channel is for vulnerabilities only.

## Audit and disclosure log

Published advisories, audit reports, and disclosure timelines live at:

<https://github.com/ul0gic/fail2zig/security/advisories>

The threat model this policy is derived from: <https://fail2zig.com/threat-model>
