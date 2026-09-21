# fail2zig v0.4.2

Version 0.4.2 adds read-only firewall observability to the unified CLI and
improves protection-health reporting for operators.

## Changes

- `fail2zig firewall show` reports the daemon's latest retained observation of
  fail2zig-owned kernel protection. It distinguishes unavailable, absent,
  owned-but-empty, current and retained stale observations without refreshing
  or modifying firewall state.
- `--details` expands the table views for `status`, `jails`, `list` and
  `firewall show`. Firewall details include verified owned tables, chains,
  sets, attachment rules and sampled entry placement when exact structural
  proof is available.
- Firewall observation JSON adds nullable structural and placement fields.
  Existing fields retain their meaning. The `--details` flag affects table
  presentation only.
- Native nftables observation communicates directly with the kernel and does
  not require the `nft` executable.
- Routine worker activity now retains the last verified protection view.
  Effect-changing transactions and actual storage, clock, worker, expiry or
  firewall-readback faults continue to expose uncertainty or degraded health.
  Jail source health is reported independently from storage and enforcement
  health.
- Matching client and daemon versions now render as one clearly labelled line.
  Mismatched versions continue to identify the client and daemon separately.
- Cleanup now treats only candidate detections as retry subjects. Ignored or
  unenforceable evidence remains stored without incorrectly pinning retry
  cleanup.
- The startup test harness now cleans up every child process and watchdog on
  error paths. Maintained `--import-config` exit-class coverage was tightened
  without adding a runtime dependency.

## Upgrade notes

No configuration or persistence-schema migration is introduced by this
release. Back up the executable, configuration and coherent state before
upgrading; the installer preserves configuration and does not start or restart
the service.

`firewall show` reads a bounded cached observation. It performs no query-time
kernel refresh or repair, and exit status 0 means that the query was answered,
not that packet reachability or installed protection was proved. At most 256
entries are retained. Pages default to 64 entries, and cursors expire after
60 seconds or when the observation or daemon changes.

## Verification scope

Focused ReleaseSafe checks covered CLI formatting and entry behavior, firewall
query projection, resource bounds, health publication, startup harness cleanup,
maintenance cleanup and import routing. Isolated nftables and iptables runs
exercised real owned-state observation, IPv4 and IPv6 entries, retained stale
state, hidden `nft` userspace tooling and read-only command behavior.

The new observation path was not qualified against a live ipset executable,
a remote target, live journal permissions or end-to-end packet reachability.
Cross-build and emulated command checks do not establish kernel enforcement or
real-hardware support on additional architectures.

## Assets

The five static Linux executable targets remain x86_64, aarch64, ARMv7 hard
float, MIPS32r2 big endian and MIPS32r2 little endian. Shared assets include
the installer, service, example configuration, manuals and license notices.
Verify downloads against `SHA256SUMS`.
