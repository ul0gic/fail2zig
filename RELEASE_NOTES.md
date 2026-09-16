# fail2zig v0.4.0

Version 0.4.0 consolidates daemon and administration commands into one static executable per
architecture, moves durable runtime state to embedded SQLite, adds quoted duration strings and
runs the systemd service under a dedicated non-login account.

Selected live qualification passed on Debian 13 x86_64 before the version-only change
from the unpublished 0.3.1 candidate to 0.4.0. The rebuilt artifacts passed cross-build and native/emulated command checks. ARM64, ARMv7 hard float and both MIPS32r2 soft-float byte orders retain release
artifacts, with cross-build, static inspection and QEMU smoke as their validation tier. Emulation
does not establish real-hardware or kernel-enforcement support. Contemporary Ubuntu is untested.

## Changes from v0.3.0

- Use `fail2zig <command>` in place of `fail2zig-client <command>`. The installer removes the
  retired client after installing its replacement. Rule testing and the supported fail2ban
  inspect/snapshot/plan/validate/cutover/status/rollback workflow share this executable.
- Statically embedded upstream SQLite 3.53.4 stores source receipts, retry state, protection
  ownership, enforcement intent and confirmed history. No shared SQLite library or database
  service is required. This native database is different from v0.3.0's binary state file.
- `bantime`, `findtime`, `bantime_increment_max_bantime` and `bantime_increment_jitter`
  accept quoted durations such as `"24h"` and `"1h30m"`, retaining integer seconds and existing
  limits. Units: `s`, `m`, `mm`, `min`, `h`, `d`, `w`, `mo`, `y`. Months and years are fixed
  2,629,800 and 31,557,600 seconds. `"permanent"` is exclusive to bantime.
- The service uses `User=fail2zig` and `Group=fail2zig`, with `CAP_NET_ADMIN`, `CAP_NET_RAW` and
  `CAP_DAC_READ_SEARCH` retained. The installer supports a custom service/monitor group.
  Root or the daemon UID can administer protection; group membership grants monitoring only.
  `CAP_NET_RAW` is required by the iptables ipset extension and permits raw IP sockets.
  HTTP remains in the same privileged process and defaults to loopback.
- `[global] firewall` selects the daemon-wide backend; an explicit backend never silently
  falls back to another. `defaults.banaction` and jail overrides select enforcement or log-only
  policy. `metrics_enabled = false` disables HTTP and WebSocket while IPC remains available.

The backend compatibility alias and positioned configuration diagnostics from issue #45 shipped
in v0.3.0 and are preserved. File/journal sources, nftables/iptables/ipset and five architecture
artifacts also predate this release; the native persistence and command consolidation above are
the relevant changes.

## Upgrade notes

- Stop every daemon/state writer and back up the current executable, configuration and coherent
  state before installing. The installer preserves operator configuration and never enables,
  starts or restarts the service.
- The installer transitions only the default current-native SQLite directory, database and
  existing WAL/SHM siblings to the service account. It refuses active writers, unsafe paths,
  legacy binary state and automatic custom-path upgrades. It does not recursively chown trees.
- There is no automatic converter for v0.3.0 binary state. Preserve that state for rollback;
  selecting a fresh native database explicitly loses its saved counters, bans/history and source
  positions. This is distinct from supported fail2ban schema-4 SQLite migration. See the
  [state upgrade boundary](docs/operations/migration-continuity.md#upgrading-fail2zig-state).
- Run native destination migration under the service UID with the required capabilities and
  a caller-owned private staging directory, with the destination daemon stopped. See
  [command migration](docs/operations/command-migration.md#migration-workflow).
- Journal input requires journald and `journalctl`. Debian 13 SSH jails must admit both
  `/usr/sbin/sshd` and `/usr/lib/openssh/sshd-session` through `journal_executables`.
  iptables and ipset require their host tools; nftables uses direct netlink.

## Known limitations

- A matching SSH failure originating from IPv4 loopback is classified as unenforceable, but a
  later cleanup turn can put native storage into intervention. This local-only case is tracked
  for repair after 0.4.0; it does not reproduce on the previously qualified remote SSH path.
- Firewall effects are limited to the daemon's current network namespace. Custom namespace
  selectors and service overrides that move it between namespaces are unsupported.
- Persistence warnings on another host require its directory, ownership and filesystem evidence
  to diagnose. This release does not establish the cause of previously reported save failures.

## Release assets

Five executables plus nine shared files make 14 assets; `SHA256SUMS` lists the 13 content files:

```text
fail2zig-v0.4.0-x86_64-linux-musl
fail2zig-v0.4.0-aarch64-linux-musl
fail2zig-v0.4.0-arm-linux-musleabihf
fail2zig-v0.4.0-mips-linux-musleabi
fail2zig-v0.4.0-mipsel-linux-musleabi
fail2zig.service
fail2zig.toml.example
install.sh
fail2zig.1
fail2zig.toml.5
LICENSE
SQLITE-NOTICE.md
COPYING.date-profile
SHA256SUMS
```

The installer verifies the selected executable and every downloaded file it installs against
`SHA256SUMS` before privileged filesystem changes. It installs the service, example configuration,
man pages and dependency/derived-data notices with the executable.
