# Installation and upgrades

The [latest release](https://github.com/ul0gic/fail2zig/releases/latest) is the
recommended installation. v0.4.7 is the minimum supported upgrade source; states last
written by older releases upgrade through v0.4.7 first (see Upgrades below). The shipped
installer does not start or restart the service. Review configuration and state before enabling protection.

## Installer

```bash
curl -fsSL https://github.com/ul0gic/fail2zig/raw/main/scripts/install.sh | less
curl -fsSL https://github.com/ul0gic/fail2zig/raw/main/scripts/install.sh | sudo bash -s -- --dry-run
curl -fsSL https://github.com/ul0gic/fail2zig/raw/main/scripts/install.sh | sudo bash
```

The [installer](../../scripts/install.sh) detects the target architecture, resolves
the latest release unless `FAIL2ZIG_VERSION` is set, downloads the executable,
support files and `SHA256SUMS`, and verifies every file it installs. It creates a
non-login `fail2zig` service account, preserves existing configuration, installs
the unit and man pages, and refuses active state writers or a legacy binary state
file. It does not recursively change state ownership. To use a locally built
binary, run `sudo scripts/install.sh --local-bin zig-out/bin` from the checkout.

The v0.4.8 release provides one combined daemon/admin executable per target:

| Target | Qualification |
|---|---|
| `x86_64-linux-musl` | Selected live Debian 13 qualification; isolated Ubuntu 24.04 SSH log-source checks do not establish full platform support |
| `aarch64-linux-musl` | Cross-build, static inspection and QEMU smoke |
| `arm-linux-musleabihf` | Cross-build, static inspection and QEMU smoke |
| `mips-linux-musleabi` | Cross-build, static inspection and QEMU smoke |
| `mipsel-linux-musleabi` | Cross-build, static inspection and QEMU smoke |

Emulated checks do not qualify real hardware or kernel enforcement. Journal input
requires `journalctl`; iptables and ipset backends require their host tools.

## Manual installation

If the installer is unsuitable, download only the needed executable and support
files from the same release, then verify each against `SHA256SUMS` before use. For
v0.4.8 on x86_64:

```bash
set -euo pipefail
VERSION=v0.4.8
ARCH=x86_64-linux-musl
BASE="https://github.com/ul0gic/fail2zig/releases/download/${VERSION}"
for file in \
  "fail2zig-${VERSION}-${ARCH}" fail2zig.service fail2zig.toml.example \
  install.sh fail2zig.1 fail2zig.toml.5 LICENSE SQLITE-NOTICE.md \
  COPYING.date-profile SHA256SUMS; do
  curl -fsSLO "${BASE}/${file}"
done
for file in "fail2zig-${VERSION}-${ARCH}" fail2zig.service fail2zig.toml.example \
  install.sh fail2zig.1 fail2zig.toml.5 LICENSE SQLITE-NOTICE.md COPYING.date-profile; do
  awk -v name="$file" '$2 == name { print; found++ } END { if (found != 1) exit 1 }' \
    SHA256SUMS | sha256sum --check --strict || exit 1
done
sudo install -m 0755 "fail2zig-${VERSION}-${ARCH}" /usr/local/bin/fail2zig
```

For a **fresh installation**, create the service account and install the verified
unit and example configuration:

```bash
getent group fail2zig >/dev/null || sudo groupadd --system fail2zig
sudo useradd --system --gid fail2zig --home-dir /nonexistent --no-create-home \
  --shell /usr/sbin/nologin fail2zig
sudo install -m 0644 fail2zig.service /etc/systemd/system/
sudo install -d -o root -g fail2zig -m 0750 /etc/fail2zig
sudo install -o root -g fail2zig -m 0640 fail2zig.toml.example /etc/fail2zig/config.toml
sudo install -d -o fail2zig -g fail2zig -m 0750 /var/lib/fail2zig
sudo systemctl daemon-reload
```

Review the config, then explicitly start the service:

```bash
sudo fail2zig --validate-config --config /etc/fail2zig/config.toml
sudo systemctl enable --now fail2zig
sudo fail2zig status
```

The shipped unit runs as the `fail2zig` UID with only its declared service
capabilities. `CAP_NET_ADMIN` permits firewall operations;
`CAP_DAC_READ_SEARCH` permits protected log reads; `CAP_NET_RAW` is needed by the
ipset backend's iptables extension and also grants raw socket authority. Keep the
optional HTTP listener bound to loopback. See [SECURITY.md](../../SECURITY.md)
and the [runtime architecture](../architecture.md) for the full boundary.

## Custom state directory under systemd

Changing `[global] state_file` changes the database path the daemon opens. It does
not change the service's filesystem access. The shipped unit uses
`ProtectSystem=strict`, with explicit `ReadWritePaths` entries for
`/var/lib/fail2zig` and `/run/fail2zig`. A custom persistent parent outside its
writable exceptions can therefore fail with `ReadOnlyFileSystem` even when an
administrator can write there from a shell. `PrivateTmp` still provides writable
private temporary directories. Its inherited
`StateDirectory=fail2zig` also makes systemd create `/var/lib/fail2zig` before the
daemon starts. That directory appearing does not mean the daemon ignored the
configured path.

This example relocates native SQLite state to `/srv/fail2zig-state/state.bin`,
keeping the shipped socket path. It assumes the installed service runs as
`fail2zig:fail2zig`; inspect `sudo systemctl cat fail2zig.service` and
`sudo systemctl show fail2zig.service -p User -p Group -p ExecStart` first, and
adapt the exact owner/group if your installation differs. The automatic
installer deliberately refuses custom `state_file` paths: use the manual
installation/upgrade procedure after relocation, with all state writers stopped.

1. Stop the service and every other daemon, migration or repair process that can
   write this state. Keep them stopped until the configuration and unit agree.
   Preserve the executable and configuration for rollback. A normal stop leaves
   installed firewall rules in place; do not delete state or withdraw protection
   merely to relocate the database.

   ```bash
   sudo systemctl stop fail2zig.service
   sudo systemctl is-active fail2zig.service   # must report inactive
   ```

2. Select a dedicated real directory outside locations hidden by the unit
   (`ProtectHome=yes` and `PrivateTmp=yes` still apply). Its ancestors must permit
   traversal by the service and must not be writable by untrusted users. For this
   example, inspect `/srv` and verify it is a real root-owned directory without
   group/world write permission. The following commands must create a new,
   previously unused parent, not reuse a symlink or shared directory:

   ```bash
   sudo bash -eu -o pipefail <<'ROOT'
   test ! -e /srv/fail2zig-state
   test ! -L /srv/fail2zig-state
   install -d -o fail2zig -g fail2zig -m 0750 /srv/fail2zig-state
   ROOT
   ```

   The parent must exist before service startup. `ReadWritePaths` grants namespace
   access; it does not create the directory, change ownership or override a
   read-only underlying mount. The daemon requires its own UID to own the parent
   and database, a parent without group/world write permission, and private
   database files. A root shell's successful write is not a service access check.

3. For an existing installation, first verify the old native database and every
   existing `-wal`/`-shm` sibling: regular files, one link each, no symlinks, and
   only the expected root or service UID as owner. Reject unexpected objects
   before copying or changing ownership. With every writer still stopped, copy
   the entire set to a private backup and to the new parent. The block below is
   for the default old path; substitute the actual old path if it differs. For a
   fresh installation omit this block and let the daemon create the database.

   ```bash
   sudo bash -eu -o pipefail <<'ROOT'
   umask 077
   test -f /var/lib/fail2zig/state.bin
   backup=$(mktemp -d /var/backups/fail2zig-state.XXXXXXXX)
   for suffix in '' -wal -shm; do
       old="/var/lib/fail2zig/state.bin${suffix}"
       if test -e "$old"; then
           cp -p -- "$old" "$backup/"
           cp -p -- "$old" /srv/fail2zig-state/
           chown fail2zig:fail2zig "/srv/fail2zig-state/state.bin${suffix}"
           chmod 0600 "/srv/fail2zig-state/state.bin${suffix}"
       fi
   done
   printf 'Stopped-state backup: %s\n' "$backup"
   ROOT
   ```

   Never copy only the database while a writer is active, drop sidecars to make
   a copy start, or recursively chown/chmod a shared tree. Keep the old set and
   backup untouched until continuity is checked; do not run daemons against both
   copies. Preserve any older upgrade backups with their matching binary.

4. Set `state_file = "/srv/fail2zig-state/state.bin"` in `[global]` of the config
   used by `ExecStart`. Run `sudo systemctl edit fail2zig.service` and add this
   drop-in:

   ```ini
   [Service]
   ReadWritePaths=
   ReadWritePaths=/srv/fail2zig-state /run/fail2zig
   StateDirectory=
   ```

   The empty assignments clear the inherited lists. The new list contains
   only those two explicit `ReadWritePaths` entries;
   `RuntimeDirectory=fail2zig` remains in effect. Clearing `StateDirectory` stops
   systemd creating the unused default parent; it does not remove an existing
   directory or its rollback state. Keep `ProtectSystem=strict` and the remaining
   hardening. If you configured another writable output such as `log_target`,
   account for that exact destination separately rather than granting `/srv`,
   `/var` or `/` wholesale.

5. Reload the unit, inspect the effective settings, validate the config and start:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl cat fail2zig.service
   sudo systemctl show fail2zig.service -p User -p Group -p ReadWritePaths -p StateDirectory
   sudo fail2zig --validate-config --config /etc/fail2zig/config.toml
   sudo systemctl start fail2zig.service
   sudo fail2zig status
   sudo fail2zig list
   sudo fail2zig history
   ```

   Confirm the expected saved bans, deadlines, history and source continuity, then
   check them again after a controlled restart. Configuration validation alone
   does not exercise the service's mount namespace or its ability to create
   SQLite sidecars. If startup still fails, inspect the effective unit, the
   configured parent and mount, and the service journal before changing access.
   Default installations need no drop-in.

## A second installation in the same network namespace

The daemon owns one nftables table named after its installation. A clean stop leaves that
table and its rules in place so the next start reconciles them; after `fail2zig firewall
withdraw` the table stays with empty sets. A second installation started in the same
namespace with a different state directory finds a table carrying the reserved name that
its own state does not own and refuses with `ForeignState`, which is the ownership check
working. Before starting a second installation, or after moving a state directory, remove
the previous installation's table once its daemon is stopped and withdrawn:

```bash
sudo nft list tables | grep ' f2z_'
sudo nft delete table inet f2z_<hash>
```

An in-place upgrade on the same state directory is unaffected.

## Upgrading existing state

Stop the daemon and all other state writers before installation. Preserve the
executable, configuration and a coherent backup of the native database with its
WAL/SHM siblings. An older binary cannot read newer checkpoint and marker data.
Rollback requires the matching backup and binary, not an executable swap.

v0.4.7 is the minimum supported upgrade source. The first start of this release
upgrades a state last written by v0.4.7 (schema 25) to schema 26 in place. Schema 26
adds ban origins, ignore-entry deadlines and timed configuration entries. States last
written by v0.4.6 or earlier are not a supported upgrade path; upgrade them through
v0.4.7 first, or start from a fresh state.

- Before its first change it writes a coherent copy of the database to a backup. It
  needs free space of twice the database size plus 32 MiB, and refuses to start if
  that backup file already exists. Move an old backup aside only when it is not the
  sole copy of earlier state.
- The backup is `<state_file>.pre26-backup`.
- The upgrade commits in one transaction, so an interrupted upgrade leaves the
  state at schema 25. Every existing ban gets origin `detection`. The log reports
  completion and the backup path.

v0.4.7 and older binaries refuse a schema 26 database with their schema-version
message, so an older binary cannot be started on upgraded state without
restoring the backup.

To roll back, stop the daemon, restore the backup the upgrade wrote over the state
file, remove the upgraded database's `-wal`/`-shm` files and reinstall the binary
that last wrote that state: v0.4.7 for `.pre26-backup`. If you copied the backup
into place instead of moving it, move the backup file aside before the next
upgrade, because an existing backup file refuses the start.

A file source that cannot resume does not stop the daemon. This covers a file
truncated in place below its saved position, a rotated-out file removed while it
still held unread bytes, and a log replaced by a different file whose previous file is
gone. The daemon pauses that source, restores bans for every
jail, enforces every other enabled jail, sends `READY=1` and keeps running, so
`systemctl is-active fail2zig` reports `active` and protection reports degraded
with cause `SourcePaused`. `fail2zig status` and the startup journal line name the
source and print the exact `fail2zig repair-source` command. Configuration,
storage, firewall and schema refusals still stop the start. A rotated-out file that
was read to its end before it was removed does not pause anything.

The jail's `on_truncation` key chooses what happens next (see `fail2zig.toml(5)`):

- `"refuse"`, the default, keeps the source paused. Stop the daemon, run the printed
  `repair-source` command (see `fail2zig(1)`) and start the daemon. The stop
  withdraws firewall rules until the next start reinstalls them.
- `"restart"` resumes the source without pausing and records a durable
  continuity-loss event, shown by `fail2zig status`. A replaced log resumes at offset
  0 of the new file. While the log is absent the source reports `missing` and waits,
  then resumes when the file appears.

Under either setting, records written after the saved position and removed before
they were read, or left in a replaced file that is gone, were never read and cannot be
recovered.

If storage is unhealthy when the daemon stops, it leaves installed firewall rules
in place and logs how many remain; the next start reconciles them. A healthy stop
withdraws its rules while keeping owners and deadlines.

The installer changes ownership only for the default native SQLite state path
and refuses custom paths, active writers and legacy binary state. Follow the
[state upgrade boundary](migration-continuity.md#upgrading-fail2zig-state) before
replacing an installation; never delete state to bypass a refusal. Released
v0.3.0 binary state has no automatic converter, and releases before v0.4.7 are not
an upgrade source: upgrade them through v0.4.7 first, or start from a fresh state.

## Build from source

Zig 0.14.1 is required. A ReleaseSafe build puts the combined executable in
`zig-out/bin/fail2zig`:

```bash
zig build -Doptimize=ReleaseSafe
```

Release maintainers use `make release-all` to build the five targets before the
[release workflow](../../.github/workflows/release.yml) verifies and publishes
them. A cross-build alone does not qualify live kernel enforcement.
