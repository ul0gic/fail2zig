# Zero Runtime Dependencies

> A security tool should not be the source of risk it's protecting against.
> That thesis is not a tagline for fail2zig — it's a hard constraint that
> shapes every architectural decision.

## What we mean by it

fail2zig is a single static binary. At runtime it depends on:

- **The Linux kernel** — specifically its netfilter, inotify, and epoll ABIs.
- **Nothing else.**

No Python interpreter. No Perl. No Ruby. No Node. No Java. No C library
beyond the one statically linked into the binary (musl, in the release builds).
No `iptables`, `nft`, `ipset`, `systemctl`, `curl`, `wget`, or any other CLI
tool. No shell. No config-file preprocessor. No SELinux helpers. No D-Bus.
No AppArmor profiles we need to exec against. No plugins. No hot-loaded
modules. No eval, no dynamic code, no JIT.

This is a deliberately aggressive posture. The rest of this document explains
why it's the only posture that makes sense for a root-privileged security
daemon parsing attacker-controlled input, and how we uphold it in practice.

## The anti-pattern

The tool we're replacing, fail2ban, reacts to log matches by forking a shell
and running `iptables`, `ipset`, `nft`, or a custom operator script. The
command template is expanded from an `.conf` file that embeds `<ip>` and
`<host>` placeholders filled in from the matched log line.

That means fail2ban's effective trust-computing-base for the ban action is:

- fail2ban itself (Python process running as root)
- The Python interpreter
- The entire Python standard library
- The shell (`/bin/sh`, usually bash)
- Every CLI the action template invokes (`iptables`, `ip6tables`, `ipset`,
  `nftables`, ...) and each of their transitive library dependencies
- The `PATH` environment variable, and whatever binaries resolve against it
- The `.conf` action templates — essentially small programs — shipped by
  the distribution maintainer

Compromising any link in that chain compromises the whole system. Swap
`/usr/sbin/nft` with a hostile binary and fail2ban obediently executes it as
root every time a ban fires. Trick a `.conf` template into including
attacker-influenced bytes in a shell command and you have remote code
execution on a server you were installing defensive software onto.

This is not theoretical. fail2ban has had multiple CVEs along exactly these
lines: [CVE-2013-2178](https://www.cve.org/CVERecord?id=CVE-2013-2178) (shell
injection via crafted log content), [CVE-2021-32749](https://www.cve.org/CVERecord?id=CVE-2021-32749)
(mail action template passing attacker-controlled data to the sendmail CLI).
The common thread is the same: **the ban action path is a shell program, and
a shell program that processes attacker-derived inputs is an attack surface**.

fail2zig rejects this model entirely. We never exec. We never shell. The
ban action is a handful of pure Zig functions that speak netlink directly
to the kernel.

## Why "pure netlink" is the answer, not "exec nft safely"

An obvious counter-proposal is: fork `nft` but pass arguments as a discrete
`argv` array (avoiding shell interpretation) and use `execve` directly. This
is what a hardened shell-out would look like.

We rejected this path for fail2zig because it still introduces dependencies
that erode the product's trust posture:

1. **`nft` becomes part of fail2zig's TCB.** Every ban now depends on the
   correctness of the `nft` binary, its version, its parser's handling of
   inputs we pass, and the integrity of `/usr/sbin/nft` on disk. If the
   binary is replaced — by a compromised package mirror, a rootkit, a
   malicious admin — fail2zig silently runs hostile code with CAP_NET_ADMIN
   on every firewall operation.

2. **PATH attacks remain.** Even with a hardcoded absolute path, upgrades,
   installer bugs, and filesystem layout changes across distributions make
   the target location fragile. The first hotfix release that ships `nft`
   in a different location breaks fail2zig or, worse, introduces a
   redirect exploit.

3. **Version skew over time.** fail2zig's install script pinning the exact
   `nft` version is unrealistic. Over years, the distribution's `nft`
   upgrades, changing error message formats (which we might parse for
   diagnostics), changing attribute emission defaults, introducing
   deprecations. Each change is an upstream-driven regression we have to
   chase.

4. **The "zero runtime dependencies" claim on the README would be a lie.**
   Product honesty matters. Operators who choose fail2zig are choosing a
   specific story — "the binary IS the trusted computing base." A
   dependency on `/usr/sbin/nft` at runtime breaks that story.

5. **The performance path matters too.** Shell-out adds a process spawn
   to every ban (typically 1-5 ms). Our p99 ban-latency target is <1 ms.
   Subprocess overhead would make that target unreachable, which in turn
   would force us to either lower the bar or solve the same performance
   problem later anyway.

The pure-netlink path is more code — but it's code that lives inside the
fail2zig binary, compiled with the same memory safety guarantees as the
rest of the daemon, covered by the same test suite, shipped in the same
signed release.

## What we depend on, precisely

Zero-runtime-deps is a claim about what lives outside the binary. It does
not mean fail2zig implements its own TCP stack from scratch. The boundary
is: **fail2zig depends only on stable kernel ABIs that are part of Linux's
core promise of backward compatibility.**

| ABI | Used for | Why acceptable |
|---|---|---|
| netlink (`AF_NETLINK`) | Talking to nftables / the netfilter subsystem | Stable since Linux 2.2 (1999). Backward-compatible by kernel policy. Wire format documented in `linux/netlink.h` and `linux/netfilter/nf_tables.h`. |
| inotify | Watching log files for new content | Stable since Linux 2.6.13 (2005). |
| epoll | Event loop, signalfd, timerfd, eventfd | Stable since Linux 2.6 (2004). |
| signalfd, timerfd, eventfd | Signal + timer integration with the event loop | Stable since Linux 2.6.22 / 2.6.25. |
| `procfs` / `sysfs` read-only access | Reading `/proc/$(pid)/...` for capability checks, `/proc/self/status` | Stable interfaces. We read, never write kernel tunables. |
| AF_UNIX | IPC socket between daemon and client | POSIX. Stable everywhere. |

These are **kernel ABIs**, not userspace libraries or tools. They are the
lowest-level primitives available to any Linux program. Depending on them
is equivalent to depending on the kernel itself, which is unavoidable for
anything that runs.

We deliberately do not use:

- libmnl, libnfnetlink, libnftnl — third-party C libraries for netlink
  helpers. We build the TLV frames ourselves.
- libnl-3, libnftables — ditto.
- libcap, libcap-ng — C libraries for capability manipulation. We read
  `/proc/self/status` and use the `prctl` syscall directly.
- libsystemd — the systemd client library. We read environment variables
  systemd sets (`LISTEN_FDS`, `NOTIFY_SOCKET`) and use the small subset
  of the sd_notify protocol we need, implemented in-tree.

Every one of those libraries is an opportunity for supply-chain compromise.
Every one adds transitive C dependencies (glibc, pcre, json-c, ...). None
of them give us capabilities we couldn't build in a few hundred lines of
auditable Zig. The trade between "library ergonomics" and "the binary IS
the TCB" is decided in favor of the TCB every time.

## Case study: the nftables scaffold installer

This section is included because it's the most architecturally non-trivial
consequence of the zero-deps principle. If you're going to do pure netlink,
you need to speak netlink fluently for every operation your product needs —
not just the easy ones.

When fail2zig starts, it must install a ruleset in the kernel:

```
table inet fail2zig {
    set banned_ipv4 { type ipv4_addr; flags timeout; }
    set banned_ipv6 { type ipv6_addr; flags timeout; }
    chain input {
        type filter hook input priority filter; policy accept;
        ip  saddr @banned_ipv4 drop
        ip6 saddr @banned_ipv6 drop
    }
}
```

The shell-out approach would be a single `nft -f - <<'EOF' ... EOF` call —
about 8 lines of code. The pure-netlink path is more involved:

1. **Six distinct netlink messages** in a single atomic batch bracketed by
   `NFNL_MSG_BATCH_BEGIN` / `NFNL_MSG_BATCH_END`: one `NEWTABLE`, two
   `NEWSET`, one `NEWCHAIN`, two `NEWRULE`.
2. **Each message** is a `nlmsghdr` header, a netfilter `nfgenmsg` header,
   and a tree of TLV attributes — the leaves being strings, u32s in big
   endian, and recursively-nested sub-attributes.
3. **The `NEWRULE` payload** is the most complex: the rule body is a nested
   list of three expressions (`payload` load, `lookup`, `immediate`
   verdict), each of which has its own nested attribute tree.
4. **Every message gets an ACK.** We correlate responses by sequence number
   and surface specific errnos (ENOENT, EINVAL, EEXIST, EPERM) up the stack
   as typed Zig errors. Silently swallowing netlink errors is how
   [SYS-003](../../.project/issues/closed/SYS-003-nftables-scaffold-never-installed.md)
   remained invisible for 5 development phases.
5. **Fail closed.** If any step of scaffold install fails, the backend
   returns `NotAvailable`, backend auto-detection falls through to
   iptables / ipset / log-only, and if nothing works the daemon exits
   rather than pretending to be banning things.

All of this lives in `engine/firewall/nftables.zig`. It's extensively
unit-tested at the byte layout level and integration-tested against a real
kernel when the tests run as root. When a regression happens — an attribute
ID is wrong, a TLV is malformed — the failure is a typed Zig error with a
specific errno, surfaced in the daemon logs and the CI output. Not a
silent drop.

## How to verify

Zero-deps is an empirical claim — here's how to check it:

```bash
# The install artifact:
$ ldd /usr/local/bin/fail2zig
        statically linked

# No subprocess spawns during normal operation:
$ sudo strace -f -e trace=execve -p $(pgrep fail2zig)
# Watch for a while — exec of any other binary is a zero-deps violation.
# You won't see any. If you do, file an issue.

# What the daemon is actually doing:
$ sudo strace -p $(pgrep fail2zig)
# Syscalls you'll see: epoll_wait, read, inotify_read, accept4, recvmsg,
# sendmsg, timerfd_settime. No openat of /usr/sbin/*, no fork, no execve.

# What talks to nftables at runtime:
$ sudo lsof -p $(pgrep fail2zig) | grep -i netlink
fail2zig ... NETLINK connection to "netfilter"
```

## Implications for packaging and audits

For distributors:

- fail2zig has no package dependencies. On any Linux kernel ≥ 4.1, it runs.
- The release binary is `strip`ped and musl-linked. It runs on every
  distribution without worrying about glibc versions, library paths, or
  `LD_LIBRARY_PATH`.
- The install script creates a config dir and a systemd unit. It does not
  install or require any other package.

For auditors:

- The TCB is the fail2zig binary itself, plus the Linux kernel. No other
  userspace code is trusted by the daemon.
- Reproducing a release: same fail2zig source + same Zig version + same
  target triple = byte-identical binary (verified via `sha256sum` against
  the release manifest).
- Sandboxing: fail2zig runs under systemd with `CapabilityBoundingSet=`
  restricted to `CAP_NET_ADMIN CAP_DAC_READ_SEARCH` and `ProtectSystem=strict`
  (see `deploy/fail2zig.service`). Because the daemon never execs, those
  hardening flags can't be bypassed by an intermediary.

For operators:

- `fail2zig --check-config` validates a config without touching the
  firewall or starting event loops — no subprocess, no kernel state
  mutation.
- A crash diagnostic dump (planned for v0.2.0 via `/run/fail2zig/crash.bin`)
  is a pure memory snapshot readable only by the fail2zig binary itself.
  No third-party analysis tool needed.

## What this cost us

Honesty:

- The `NewRule` payload took six hours of Zig + kernel-header reading +
  debugging against a live kernel to get right. A shell-out would have
  been 8 lines of code.
- We've already paid four production-impacting bugs in the netlink path
  that a shell-out would have avoided (SYS-003, SYS-004, and two issues
  closed during Phase 3). Every one of those bugs surfaced a class of
  failure we now have regression tests for.
- Future backends (iptables, ipset) have the same rule: pure libkernel
  ABI, no shell-out, no libc helpers. That's more work than "just exec
  iptables-restore."

The cost of the zero-deps posture is real. The cost of the alternative
— a security tool that becomes the attack surface it was meant to close —
is higher.

## Related reading

- [security.md](../../.claude/rules/security.md) — project-wide security
  rules that flow from this posture
- [SYS-003](../../.project/issues/closed/SYS-003-nftables-scaffold-never-installed.md)
  — the bug that demonstrated why silent netlink errors are fatal, and
  shaped the ACK-drain discipline
- `engine/firewall/nftables.zig` — the reference implementation of the
  scaffold installer + ban/unban path
- `engine/firewall/netlink.zig` — the narrow netlink wrapper, audited
  against `linux/netlink.h`
