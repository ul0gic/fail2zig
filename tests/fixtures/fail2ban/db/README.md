# fail2ban database fixtures

No database file is stored in this directory. Every fixture used by
`zig build test-native-migration-snapshot` is generated at test time by
`engine/migration/fail2ban_fixture.zig` through the embedded SQLite, inside a
per-test temporary directory that is removed afterwards.

Seeded rows use only documentation address ranges: 192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24 (concurrent-writer test) and 2001:db8::/32.
Jail names are `sshd` and `nginx-http-auth`. Log paths are conventional Debian
locations, the MD5 value is the digest of the empty string, and the `data` JSON
contains counters only. No real hosts, hostnames, users, tokens or secrets
appear in any fixture or test.
