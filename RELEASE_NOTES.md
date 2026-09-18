# fail2zig v0.4.1

This patch fixes SSH journal startup failing with `InvalidJournalExecutables` when
`journal_executables` is omitted, including the minimal configuration reported in
[issue #57](https://github.com/ul0gic/fail2zig/issues/57):

```toml
[jails.sshd]
enabled = true
filter = "sshd"
```

## Changes

- Built-in SSH jails using journald now discover executable defaults from a bounded
  catalog of standard SSH paths. Discovery verifies trusted ownership, permissions
  and path components, resolves supported symlinks and deduplicates deterministically.
  File sources and custom journal rules do not acquire these defaults.
- Journal records still require the local machine ID, root UID, syslog transport and
  an exact allowed executable. Missing or ambiguous origin fields remain rejected.
- Explicit executable profiles retain their existing spelling, order and journal
  selection behavior. An explicitly empty journal profile remains invalid.
- The configuration manual clarifies that `pid_file` is deprecated and ignored.
  Use `systemctl show fail2zig.service --property=MainPID --value` for the service PID.
- Firewall startup diagnostics distinguish a saved backend or namespace selector conflict
  from an unavailable backend and explain how to restore the matching configuration.
  The manual explains that `auto` reuses the backend recorded in an existing state database.
- Status and jail output expose storage, source, recovery and firewall failure details.
  Journal diagnostics retain captured child exit/signal information without printing raw stderr.
- Configuration errors identify the setting and constraint. State-open errors retain the
  failing stage and available POSIX or SQLite cause. Firewall diagnostics identify the
  backend, operation and whether mutation may have been attempted.
- Memory-percentage formatting handles the full unsigned 64-bit input range without
  overflowing. Normal display formatting is unchanged.

## Upgrade notes

Existing explicit SSH profiles can remain unchanged. Back up the executable,
configuration and coherent state before upgrading; the installer preserves configuration
and does not start or restart services.

Changing the effective executable profile or source identity can require operator
intervention. Adding or removing SSH helpers, changing symlink targets, or removing an
explicit override may change that identity. The daemon refuses incompatible saved state;
it does not silently reset history, retries or bans. This release does not promise seamless
SSH layout changes. See the [configuration manual](docs/man/fail2zig.toml.5).

## Verification scope

Focused configuration, detection, reload and startup checks covered the repair. Connected
log-only checks exercised genuine SSH journal input, forged-origin rejection and original
retry/decision expiry preservation across restart on Debian 13 with an observed
`sshd-session` origin and Ubuntu 24.04 LTS with an observed `/usr/sbin/sshd` origin.
A populated v0.4.0 explicit-profile database also reopened with unchanged retry state and
expiry. Genuine `sshd-auth` emission was not observed; synthetic tagged input tested its
selection and rejection separately.

Diagnostic checks covered configuration/reload refusal, storage pause/recovery, journal
child failure/recovery and firewall readback failures. Isolated nftables and iptables
tests exercised kernel readback, IPv4/IPv6 packets, expiry and retained ownership.
The formatter regression reproduced the old overflow and passed after repair.
The startup report in [issue #61](https://github.com/ul0gic/fail2zig/issues/61) remains
open pending the reporter's environment and reproduction details; this release does
not claim to resolve that report.

These checks do not establish new Ubuntu firewall support, socket-activation lifecycle
coverage or real-hardware support for additional architectures. The existing IPv4-loopback
maintenance limitation remains: an unenforceable loopback detection can cause a later
cleanup turn to put storage into intervention.

## Assets

The five static Linux executable targets remain x86_64, aarch64, ARMv7 hard float,
MIPS32r2 big endian and MIPS32r2 little endian. Shared assets include the installer,
service, example configuration, manuals and license notices. Verify downloads against
`SHA256SUMS`; cross-build or emulated command checks do not establish kernel enforcement
on those targets.
