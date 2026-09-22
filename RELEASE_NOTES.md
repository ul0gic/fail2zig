# fail2zig v0.4.4

Version 0.4.4 fixes four native recovery, enforcement and retention defects. It
adds no features, integrations or configuration options.

## Fixes

- Recover populated state without a stale maintenance fence or a page-at-a-time
  startup delay that could prevent the daemon becoming ready (#84).
- Treat expected firewall element expiry between readback passes as transient
  enforcement uncertainty, while continuing to reject structural and foreign
  firewall changes (#83).
- Advance reconciliation after full readback and reclaim spent effect records
  after live leases, confirmed history and unsettled work are clear (#85).
- Reclaim eligible retry-decision detail history before accumulated old rows
  block new decisions. Current owner and retained confirmation provenance remain
  protected (#86).

## Upgrade

The persistence schema remains 23; two additive lookup indexes are created for
existing databases. The stored record format and configuration are unchanged.
Take a coherent state backup with its matching binary before upgrading. Older
binaries cannot read checkpoint and marker data introduced in v0.4.3, so a
binary-only rollback to an earlier release is not supported.

## Verification scope

ReleaseSafe component and native daemon tests cover populated-state recovery,
transient firewall readback, effect reconciliation/retention, exact-capacity
retry-detail reclamation, transaction rollback and reopened state. Isolated
Debian 13 lab checks covered nftables and ipset expiry waves and live SSH
enforcement for the firewall fixes. The published executable and package are
subject to the existing release workflow's hash-bound verification.

The five static Linux targets remain x86_64, aarch64, ARMv7 hard float, MIPS32r2
big endian and MIPS32r2 little endian. Cross-builds and emulation do not claim
live kernel qualification on those other architectures. Verify downloaded
assets against `SHA256SUMS`.
