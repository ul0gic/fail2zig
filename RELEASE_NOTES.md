# fail2zig v0.2.2

Stabilization release: honest file-source health, rotation-safe log watching, clearer firewall diagnostics, and faster startup. No config changes — re-run the installer (it preserves `config.toml`) and restart the service.

## Security

- **File jails sharing a directory silently stopped banning after the first log rotation (affects v0.2.1 and earlier).** When two or more file-source jails watched logs in the same directory, a routine `logrotate` (rename + recreate) detached one jail's log watch and it never reattached — that jail stopped consuming new lines and **stopped issuing bans until the daemon was restarted**, with no error and (in v0.2.1) a `healthy` status. journald sources were unaffected, and single-jail-per-directory configs were unaffected. **If you run v0.2.1 or earlier with multiple file jails under one directory (e.g. several under `/var/log`), upgrade to v0.2.2.** Root cause: inotify deduplicates the directory watch, but the watch table was keyed 1:1, so a shared directory watch resolved to only one jail; parent-directory events now fan out to every jail watching that directory.

## Fixed

- **Honest file-source read-health** — a file jail whose log breaks after it was reading (deleted, permissions revoked, mount lost) now surfaces as `DEGRADED`, while a quiet-but-healthy jail, a normal rotation, and a not-yet-appeared log never false-flag. Completes the per-jail health surface for file sources. (#38)
- **Clearer firewall diagnostics** — startup now distinguishes "no nf_tables in the kernel" from "missing `CAP_NET_ADMIN`" from a transient error, with an actionable message naming the cause. A netlink batch the kernel rejects at batch-begin is no longer mis-reported as a timeout, and known-fatal startup conditions fail closed cleanly. (#39)
- **Faster startup** — the state tracker no longer reserves its full entry budget up front; cold start drops to ~20 ms (was ~98 ms), well under the 100 ms target. (#15)

## Internal

- Removed unused byte-budget allocator scaffolding; the memory ceiling is enforced solely by the state-tracker entry cap with eviction. (#40)
- Added an end-to-end file-source `DEGRADED` test harness, validated on a real Debian target running the shipped musl binary.
