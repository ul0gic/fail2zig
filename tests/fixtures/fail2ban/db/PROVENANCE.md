# fail2ban SQLite fixture provenance

No database file is stored in this directory. Every schema-4 fixture used by
`zig build test-native-migration-snapshot` is generated at test time by
`engine/migration/fail2ban_fixture.zig` through the embedded SQLite, inside a
per-test temporary directory that is removed afterwards.

## Reference

| Item | Value |
|---|---|
| Upstream | fail2ban 1.1.1 (supported source set: 1.1.0 and 1.1.1) |
| Reference checkout | `/tmp/fail2ban-parity-reference-1.1.1` (read-only, not vendored) |
| Schema source | `fail2ban/server/database.py:114-160` (`Fail2BanDb.__version__ = 4`, `_CREATE_SCRIPTS`) |
| Runtime journal mode | `database.py:208` sets `PRAGMA journal_mode = MEMORY` per connection |

## Derivation and license

The `CREATE TABLE`/`CREATE INDEX` statements in `fail2ban_fixture.zig` restate the
upstream DDL (GPL-2.0-or-later) so the generated fixtures match the exact on-disk
layout a fail2ban 1.1.x installation produces. The statements are a structural
interface description used only by tests; they are not shipped in the product
binary, and the snapshot reader validates against column names/types rather than
executing them. `engine/migration/fail2ban_db.zig` cites the same path and lines.

## Content review

Seeded rows use only documentation address ranges: 192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24 (concurrent-writer test) and 2001:db8::/32. Jail names are the
upstream defaults `sshd` and `nginx-http-auth`. Log paths are conventional Debian
locations, the MD5 value is the well-known digest of the empty string, and the
`data` JSON contains counters only. No real hosts, hostnames, users, tokens or
secrets appear in any fixture or test.
