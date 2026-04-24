# fail2zig v0.1.0 — Phase 1 Drop-in Replacement

First tagged release of **fail2zig**: a modern, drop-in, binary-compatible
alternative to fail2ban.

One static musl binary. Zero runtime dependencies. Kernel-native ban
timeouts via pure netlink. Comptime-generated parser — no runtime regex
engine. `io_uring`/`epoll` event loop. Prometheus `/metrics`. WebSocket
event stream. Single IPC-controlled unprivileged CLI.

## Measured

| Metric | fail2zig 0.1.0 | Target |
|---|---|---|
| Parse throughput | 5,960,000 lines/sec | >22,000 |
| Ban latency (p50) | 365 ns | <1 ms |
| Ban latency (p99) | 932 ns | <1 ms |
| Resident memory (under load) | 22 MB | <64 MB |
| Stripped binary size (x86_64-linux-musl) | 877 KB | <5 MB |
| Stripped binary size (aarch64-linux-musl) | 832 KB | <5 MB |
| Tests passing | 595 | — |

## What ships in 0.1.0

### Core engine
- Zero-allocation hot path (log line → parse → state update)
- Comptime-specialized parsers (no runtime regex)
- Pre-allocated memory pools with hard ceilings — no unbounded growth under attack
- `inotify`-based log watcher with rename / copytruncate / delete-create rotation handling
- Atomic state persistence (CRC-checked) — survives SIGTERM + restart

### Firewall backends
- **nftables** (preferred) — pure netlink, no libnftnl, no shelling out to `nft`
- **ipset** — argv-based, atomic set swaps
- **iptables** (fallback) — match-set rules with explicit classification
- Auto-detection with explicit override

### Filters (Phase 1 parity)
- sshd (9 OpenSSH patterns, 7.x / 8.x / 9.x)
- nginx (http-auth, limit-req, botsearch)
- apache (auth, badbots, overflows)
- postfix, dovecot, courier
- named, vsftpd, proftpd, mysqld
- **recidive** (meta-filter: escalates repeat offenders from fail2zig's own log)

### Drop-in migration
- Native TOML config (clean, documented)
- `fail2zig --import-config /etc/fail2ban` — imports `jail.conf`, `jail.local`, `jail.d/*.conf`, and translates filter.d + action.d
- Operators familiar with fail2ban can switch without rewriting config

### Operator surfaces
- `/metrics` — Prometheus text exposition, per-jail labels
- `/api/bans` — JSON snapshot of active bans (live, bounded)
- `/events` — WebSocket stream of `attack_detected`, `ip_banned`, `ip_unbanned`, `metrics_update`
- `fail2zig-client` — unprivileged CLI for `status`, `ban`, `unban`, `list`, `jails`, `reload`
- Shell completions for bash / zsh / fish

### Security posture
- AGPL-3.0-or-later licensed. Trademark asserted on "fail2zig" name + logo.
- Reports via GitHub Private Security Advisories (see `SECURITY.md`)
- STRIDE threat model documented at [fail2zig.com/threat-model](https://fail2zig.com/threat-model)
- Every `.zig` file carries SPDX + copyright header, CI-enforced
- CAP_NET_ADMIN + CAP_DAC_READ_SEARCH only — no full root
- Hardened systemd unit shipped in `fail2zig.service`
- `ReleaseSafe` builds retain bounds checking on attacker-controlled paths

## See it running on real traffic

[**demo.fail2zig.com**](https://demo.fail2zig.com/metrics) is a live honeypot:
a real internet-exposed sshd + nginx running under fail2zig, with the
three-pane dashboard at [**fail2zig.com/see-it-live**](https://fail2zig.com/see-it-live)
streaming organic attack traffic, ban decisions, and the live nftables set
over WebSocket. No simulation.

## Installing

### Verify the download

```
sha256sum --check --ignore-missing SHA256SUMS
```

### Linux (x86_64)

```
curl -fsSL -o fail2zig \
  https://github.com/ul0gic/fail2zig/releases/download/v0.1.0/fail2zig-v0.1.0-x86_64-linux-musl
chmod +x fail2zig
sudo mv fail2zig /usr/local/bin/
```

### Linux (aarch64)

```
curl -fsSL -o fail2zig \
  https://github.com/ul0gic/fail2zig/releases/download/v0.1.0/fail2zig-v0.1.0-aarch64-linux-musl
chmod +x fail2zig
sudo mv fail2zig /usr/local/bin/
```

### systemd service

`fail2zig.service`, `fail2zig.socket`, and `fail2zig.toml.example` are
included in this release — drop them into `/etc/systemd/system/` and
`/etc/fail2zig/` respectively and `systemctl enable --now fail2zig`.

## Verified static linking

Every binary in this release has been checked post-build — if `file`
reports `dynamically linked`, the release job fails closed. You can verify
yourself: `file fail2zig-v0.1.0-x86_64-linux-musl` → `ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, ...`.

## Thanks

20 years of fail2ban made it obvious what a log-driven IPS should do. This
release is a re-implementation of that idea on a modern stack — the shape
of the problem was solved long ago.

## What's next

- Debian/Ubuntu `.deb` packaging + APT repository
- `armv7-linux-musleabihf` and `mips-linux-musl` targets (SYS-009)
- Signed audit log (hash-chained, tamper-evident)
- Modern filter library (Docker, Traefik, Vaultwarden, Authelia, LLM endpoints)
- eBPF/XDP firewall backend
- Embedded web dashboard (`@embedFile`)

---

**Issues:** https://github.com/ul0gic/fail2zig/issues
**Security reports:** https://github.com/ul0gic/fail2zig/security/advisories/new
