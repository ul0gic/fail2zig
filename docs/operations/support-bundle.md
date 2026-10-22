# Support bundle

`fail2zig support-bundle` writes one redacted JSON file that you attach to a GitHub
issue. It answers the questions a maintainer would otherwise ask one by one: versions,
daemon status and jails, continuity loss events, configuration hashes, state file size
per table, kernel readback counts, memory and the recent warnings and errors.

## Produce a bundle

Run it as root. The state file is opened read-only by its owner or by root, and the
`log` section reads the unit's journal, which the daemon's own account cannot; any other
account records an error in those sections instead of their contents.

```bash
sudo fail2zig support-bundle --out - > fail2zig-support.json
```

With `--out -` the bundle goes to stdout and your shell writes the file, so the output
directory does not need to be writable by the `fail2zig` account. Without `--out`, the
bundle is written to `./fail2zig-support-<UTC time>.json` with mode 0600, an existing
file is never overwritten, and the path is printed.

The command prints nothing else when every section was collected and exits 0. When a
section could not be read it still writes the bundle, names each incomplete section on
stderr and exits 4:

```text
support-bundle: incomplete section host.nft: FileNotFound
```

A bundle also works while the daemon is stopped: the daemon sections then record
`Cannot connect` errors, and the configuration, state, log and host sections are still
collected.

The `log` section reads the `log_target` file, or the `fail2zig.service` journal when
`log_target = "stderr"`. Reading the journal needs journal access (on Debian, membership
in `systemd-journal` or `adm`); without it the section records the `journalctl` failure.
`--log-lines <n>` sets how many warning and error lines to keep (default 200, at most
2000, 0 to skip).

The `memory` section holds the configured `native_memory_ceiling_mb` and
`native_fd_ceiling`, the daemon's planned memory admission
(`memory_admission_bytes`, the same figure as in `fail2zig status`), and the daemon
process's `VmRSS_kib`, `VmHWM_kib`, `VmSize_kib` and `Threads`.

## What is redacted

- Every IPv4 and IPv6 address becomes `v4-<hash>` or `v6-<hash>`. The hash uses a key
  drawn for this bundle only, so the same address keeps the same label everywhere in
  the bundle (counts and repeats stay readable) and labels cannot be matched across two
  bundles. Loopback and unspecified addresses such as `127.0.0.1` are kept.
- Every path except a configured `logpath` (or a file it expands to) becomes `<path>`.
- The bundle contains no ban list.

`--include-addresses` keeps addresses as they are. Use it only when a maintainer asks
for a specific address and you accept publishing it.

## Before you attach it

Open the file and read it; it is plain JSON. Then attach it to the issue, or paste it
inside a collapsed block:

````markdown
<details><summary>support bundle</summary>

```json
...
```
</details>
````

Every option is listed in `fail2zig help support-bundle` and in fail2zig(1).
