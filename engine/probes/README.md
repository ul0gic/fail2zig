# Manual probes

These small Zig programs are diagnostic tools for source, journal and storage
behavior. They are not part of the product binary or maintained CI test suites.
Build one with `zig build build-probe-source -Doptimize=ReleaseSafe`; run it with
`zig build probe-source -Doptimize=ReleaseSafe -- <arguments>`. The other names
are `file-alias`, `file-mode`, `ignore-store` and `journal-policy`. Each probe
uses the internal-only engine module supplied by `build.zig`.
