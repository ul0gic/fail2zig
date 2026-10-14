# Installation and upgrades

The [latest release](https://github.com/ul0gic/fail2zig/releases/latest) is the
recommended installation. v0.4.0 is the minimum supported release; pre-v0.4.0
installation and rollback are unsupported. The shipped installer does not start or
restart the service. Review configuration and state before enabling protection.

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

The v0.4.7 release provides one combined daemon/admin executable per target:

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
v0.4.7 on x86_64:

```bash
set -euo pipefail
VERSION=v0.4.7
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

## Upgrading existing state

Stop the daemon and all other state writers before installation. Preserve the
executable, configuration and a coherent backup of the native database with its
WAL/SHM siblings. An older binary cannot read newer checkpoint and marker data.
Rollback requires the matching backup and binary, not an executable swap.

The first start of this release upgrades a state last written by v0.4.6 (schema 24)
to schema 25 in place. Schema 25 adds the storage for runtime ignore entries and
continuity-loss events. States last written by releases before v0.4.6 are not a
supported upgrade path; start from a fresh state.

- Before its first change it writes a coherent copy of the database to a backup. It
  needs free space of twice the database size plus 32 MiB, and refuses to start if
  that backup file already exists. Move an old backup aside only when it is not the
  sole copy of earlier state.
- The backup is `<state_file>.pre25-backup`.
- The upgrade commits in small resumable steps. An interrupted upgrade resumes on
  the next start. While it runs, the daemon extends its systemd start deadline only
  as steps commit. The log reports completion, the backup path and how many
  unsettled outcomes of already-replaced ban decisions were closed as `superseded`.
- The first start also rekeys, once, saved detection generations that hashed the
  ignore list. No ban, deadline, checkpoint or retry subject changes, and the log
  reports how many jails and rows were rekeyed.

v0.4.6 and older binaries refuse a schema 25 database with their schema-version
message, so an older binary cannot be started on upgraded state without
restoring the backup.

To roll back, stop the daemon, restore the backup the upgrade wrote over the state
file, remove the upgraded database's `-wal`/`-shm` files and reinstall the binary
that last wrote that state: v0.4.6 for `.pre25-backup`. If you copied the backup
into place instead of moving it, move the backup file aside before the next
upgrade, because an existing backup file refuses the start.

A file source that cannot resume does not stop the daemon. This covers a file
truncated in place below its saved position and a rotated-out file removed while it
still held unread bytes. The daemon pauses that source, restores bans for every
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
  continuity-loss event, shown by `fail2zig status`.

Under either setting, records written after the saved position and removed before
they were read were never read and cannot be recovered.

If storage is unhealthy when the daemon stops, it leaves installed firewall rules
in place and logs how many remain; the next start reconciles them. A healthy stop
withdraws its rules while keeping owners and deadlines.

The installer changes ownership only for the default native SQLite state path
and refuses custom paths, active writers and legacy binary state. Follow the
[state upgrade boundary](migration-continuity.md#upgrading-fail2zig-state) before
replacing an installation; never delete state to bypass a refusal. Released
v0.3.0 binary state has no automatic converter, and pre-v0.4.0 releases are
unsupported for installation or rollback.

## Build from source

Zig 0.14.1 is required. A ReleaseSafe build puts the combined executable in
`zig-out/bin/fail2zig`:

```bash
zig build -Doptimize=ReleaseSafe
```

Release maintainers use `make release-all` to build the five targets before the
[release workflow](../../.github/workflows/release.yml) verifies and publishes
them. A cross-build alone does not qualify live kernel enforcement.
