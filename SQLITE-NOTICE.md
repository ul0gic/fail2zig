# Embedded SQLite notice

fail2zig statically embeds the unmodified upstream SQLite 3.53.4 amalgamation.
It was downloaded on 2026-09-11 from the
[official SQLite archive](https://sqlite.org/2026/sqlite-amalgamation-3530400.zip).
The archive SHA3-256 published by SQLite is:

`628a44cfe82c66aed1ccbbe85a562d2e33ebe64b3288981ed76285612227934e`

Retained upstream files and SHA-256 identities:

- `sqlite3.c`: `b1dd5d74ec7f29055a6684fa06fb3c2f6821c87dd38f9a458dfd2e8a1db28189`
- `sqlite3.h`: `919e7f2e8ed1d8f56ac17b412b8971c76aa5d1a879752cc6058f75e7d5910e1d`

SQLite is dedicated to the public domain. Its upstream notice is available at
[sqlite.org/copyright.html](https://sqlite.org/copyright.html). The embedded
SQLite files are not project-authored Zig and are not relicensed as fail2zig
AGPL code.

The amalgamation is compiled directly into the executable with
`SQLITE_OMIT_LOAD_EXTENSION=1`; fail2zig does not require an installed SQLite
library or database service.
