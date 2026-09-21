# Embedded SQLite

Unmodified upstream SQLite **3.53.4** amalgamation, downloaded 2026-09-11 from
[the official release archive](https://sqlite.org/2026/sqlite-amalgamation-3530400.zip).
The archive SHA3-256 matches the hash published on the
[SQLite download page](https://sqlite.org/download.html):

`628a44cfe82c66aed1ccbbe85a562d2e33ebe64b3288981ed76285612227934e`

Retained files and SHA-256:

- sqlite3.c: `b1dd5d74ec7f29055a6684fa06fb3c2f6821c87dd38f9a458dfd2e8a1db28189`
- sqlite3.h: `919e7f2e8ed1d8f56ac17b412b8971c76aa5d1a879752cc6058f75e7d5910e1d`

SQLite is dedicated to the public domain; retain its upstream notices in these files.
See [SQLite copyright](https://sqlite.org/copyright.html). These upstream files are not
project-authored Zig or relicensed as project-authored AGPL code.

`build.zig` compiles the C amalgamation directly with Zig's C compiler and links it
statically. No source generator, configure script, Tcl, Python, installed SQLite library
or SQLite service is required. The command-line shell and extension header are omitted.

The only SQLite feature override is `SQLITE_OMIT_LOAD_EXTENSION=1`, which removes dynamic
extension loading. Default thread safety, mutexes and integrity features remain enabled.
Connection setup requires WAL, FULL synchronous commits, foreign keys and untrusted schema.
Upstream [compile options](https://sqlite.org/compile.html) document the build settings.

When updating, verify the archive against the upstream published hash, update these hashes
and the embedded-version test, and rerun transaction/restart/upgrade tests on supported
targets. Do not patch the amalgamation or adopt extra feature-removal flags silently.

The active daemon uses this statically embedded SQLite library for durable runtime state.
Legacy state migration and continuity requirements are documented separately from the
upstream amalgamation and its pinned provenance.
