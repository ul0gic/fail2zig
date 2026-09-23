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

The v0.4.4 release provides one combined daemon/admin executable per target:

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
v0.4.4 on x86_64:

```bash
set -euo pipefail
VERSION=v0.4.4
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
WAL/SHM siblings. For upgrades within v0.4.x from before v0.4.3, an older binary
cannot read newer checkpoint and marker data. Rollback within the supported line
requires the matching backup and binary, not an executable swap.

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
