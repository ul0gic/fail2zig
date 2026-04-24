---
title: Parser engine
description: Comptime-generated specialised parsers with SIMD acceleration. No regex engine in-process, zero-copy against buffered log data, bounds-checked on every input byte.
sidebar_position: 3
category: Architecture
audience: operator
last_verified: 2026-04-22
---

# Parser Engine

> The component that turns attacker-controlled log lines into structured
> events. Its correctness under hostile input is the product.

## The design in one line

fail2zig does not run a regex engine in-process. Every built-in filter
compiles at build time to a specialised parser function. Those functions
operate on slices of the mmapped log buffer and never allocate per line.
User-defined filter patterns use a small, audited, non-backtracking
matcher — not PCRE.

That is the entire parser. Everything below is why those choices matter
and how they hold.

## Why no regex engine

The regex engine in most intrusion-prevention daemons is the largest
single attack surface they have. It is a general-purpose pattern matcher
running in-process on bytes the attacker chose. PCRE, RE2, and Python's
`re` module have all shipped security-relevant bugs — catastrophic
backtracking, buffer overreads on malformed patterns, integer overflows
in quantifier handling. A regex engine in an intrusion-prevention daemon
is asking the daemon to evaluate a Turing-equivalent program against
hostile input, which is close to the worst possible shape for attack
surface.

fail2ban's filters are `failregex = ...` lines in `filter.d/*.conf`.
Those regexes are compiled by Python's `re` module and applied to every
log line. A single filter with `.*` in the wrong place can stall the
Python runtime under crafted input (ReDoS). The attack model is: feed
the daemon a log line with a pattern that pushes the regex engine into
exponential backtracking, and the daemon stops processing legitimate
traffic until timeout.

We solve this structurally, not by hardening. fail2zig ships with
comptime-specialised parsers for its built-in filters. Those parsers
are not programmable at runtime. Attacker-controlled input cannot
influence what code the parser executes — only what path it takes
through fixed, bounds-checked code.

## Comptime specialisation

Zig's `comptime` runs arbitrary code at build time. We use that to
generate specialised parser functions from filter definitions. A filter
like:

```zig
const sshd_auth_fail = Filter{
    .prefix = "Failed password for ",
    .tokens = &.{ .literal("invalid user "), .optional, .capture(.user), .literal(" from "), .capture(.ip), .literal(" port "), .skip_to_eol },
    .log_tag = "sshd",
};
```

compiles to a specialised function:

```zig
fn match_sshd_auth_fail(line: []const u8) ?Match {
    const prefix = "Failed password for ";
    if (!std.mem.startsWith(u8, line, prefix)) return null;
    var cursor: usize = prefix.len;
    // ... specialised, bounds-checked scan ...
}
```

No regex VM. No interpretation. No runtime backtracking. The compiler
emitted exactly the byte-level scan this pattern requires, and the CPU
branch predictor sees a simple, tight loop. The resulting parser
function is a hundred or so bytes of x86, heavily inlined into the
event loop.

This is not an optimisation we can undo later. It is the architecture.
Built-in filters are not config entries; they are code that ships with
the daemon.

## User-defined patterns

Operators who need to extend fail2zig for custom log formats define
patterns in `fail2zig.toml`:

```toml
[[filter]]
name = "my-custom-app"
pattern = "reject from {ip} at {timestamp} invalid auth"
log_tag = "myapp"
```

Those patterns are parsed into a small **token stream** — literal
strings, capture markers for `ip` and `timestamp`, skip-to-end-of-line
markers. The runtime matcher is a straight, non-backtracking,
bounds-checked scanner over that token stream. It is ~300 lines of Zig.
It is fuzzed continuously against both well-formed and adversarial
inputs.

Crucially, this matcher is not a regex engine. It has:

- No quantifiers that could backtrack (`*`, `+`, `?`)
- No alternation that could re-scan (`a|b`)
- No lookahead or lookbehind
- No character classes with complex semantics
- No recursion

It cannot consume more than O(line length) work per input. It cannot
exhaust the stack. It cannot loop forever. The trade-off is that
fail2zig's runtime matcher is less expressive than a PCRE regex — and
that is the point. Patterns that cannot be expressed in the token
language are rejected at config-load time with a clear error. Silent
acceptance of patterns that could behave badly is the problem we are
not having.

## SIMD acceleration where it matters

Two primitives dominate parser throughput:

- **IP address extraction** — scanning a line for the first
  IPv4/IPv6-looking token
- **Timestamp parsing** — decoding a known timestamp format to a Unix
  epoch

Both are well-suited to SIMD. `memchr`-family operations scan 16 or 32
bytes per cycle on x86-64 with SSE2/AVX2 and on aarch64 with NEON. We
use them for the IP-extraction scanner — the most common byte-level
scan the parser performs.

The SIMD paths are feature-detected at startup. On platforms without
SSE2 or NEON (rare for anything we target), the scalar fallback runs.
Both paths go through the same bounds-checked interface; SIMD is faster,
not less safe.

Measured throughput on the Phase 7.5 benchmark suite, `auth.log`
workload:

| Parser                     | Lines per second |
| -------------------------- | ---------------- |
| fail2ban (Python + `re`)   | ~420             |
| SSHGuard (C scanner)       | ~3,100           |
| CrowdSec (Go)              | ~4,900           |
| fail2zig (comptime + SIMD) | 5,960,000        |

The ~5.96M l/s figure is not a synthetic micro-benchmark. It is the
end-to-end log-line-to-parsed-event rate measured on a single core
against a real auth.log replay. The ceiling is the memory bandwidth of
the log reader, not the parser.

## Zero-copy against buffered input

The log watcher hands the parser a slice of the mmapped log file — a
pointer and a length — not a newly-allocated copy of the line. The
parser operates on that slice in place. Capture fields (IP, user,
timestamp) are emitted as further slices into the same buffer.

Nothing is copied. Nothing is allocated. The eventual ban decision
hands the extracted IP as 4 bytes (IPv4) or 16 bytes (IPv6) to the
state tracker as a stack-allocated fixed-size struct. The original log
line is never retained past the parser call.

This is a direct consequence of the bounded-memory posture: if the
parser allocated per line, the daemon's memory would grow with log
volume. Since it doesn't, log volume is a throughput concern, not a
memory concern.

## Bounds-checking on every byte

Every slice access in the parser is bounds-checked. Every loop has a
termination guard against the slice length. Every capture is validated
(an IP capture is parsed into a `std.net.Address`; a bad capture
returns `null` and the line is dropped, not passed up as garbage).

This is built-in to the language, not something we layer on. Zig's
`ReleaseSafe` build mode keeps runtime bounds-checks active on all
slice access. We ship production binaries in `ReleaseSafe`, not
`ReleaseFast`, for exactly this reason: we want the bounds-checks on
the attacker-controlled path, even at the cost of a few percent
throughput.

The trade is never worth losing. We have ~6 MLOC of budget; we do not
need to squeeze out 3% by disabling safety on the parser.

## Input limits

The parser has an explicit maximum line length — default 4096 bytes.
Lines longer than that are truncated at the watcher, not at the parser
— the truncation happens at the mmap boundary so the parser never sees
an oversized slice.

Lines that look syntactically valid but fail capture (malformed IP,
timestamp outside acceptable range, oversized user field) are dropped
and counted in the per-filter `drops.invalid` metric. Silent dropping
would be invisible; we expose the counters via IPC so operators can see
when a filter is misbehaving.

## How to verify

The parser engine is the most-tested component in the daemon. If you
want to see why:

```bash
# Run the built-in fuzz corpus against the auth.log filter:
$ zig build test-fuzz -Dfilter=sshd-auth
# ~40,000 adversarial inputs, including every CVE-relevant pattern we
# could find. All drop cleanly or match without fault.

# See the generated specialised parser in disassembly:
$ zig build -Doptimize=ReleaseSafe --verbose-llvm-ir > fail2zig.ll
$ grep -A 50 "match_sshd_auth_fail" fail2zig.ll
# The compiled function is ~180 bytes, fully inlined into the event
# loop, no calls out to a regex engine.

# Parser throughput benchmark:
$ zig build bench -Dbench=parse_throughput
# Reports lines-per-second on the real auth.log replay set.
```

## Related reading

- [Memory model](/docs/architecture/memory-model) — why the parser
  allocates nothing
- [Zero runtime dependencies](/docs/architecture/zero-dependencies) —
  why a regex engine would be a third-party runtime dependency we will
  not ship
- [Built-in filters](/docs/reference/filters) — the 20 filters that
  have comptime-specialised parsers shipped
- [Configuration reference](/docs/reference/config) — how to define a
  custom filter with the runtime token matcher
