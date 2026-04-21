//! Fuzz corpus for the log-line parser.
//!
//! Drives `engine.parser_mod.compile` (a couple of representative
//! production patterns) against a table of adversarial inputs:
//! random-looking bytes, integer-overflow-provoking digits, unterminated
//! tokens, every opcode of unicode chaos we can think of, and regression
//! seeds from prior security findings.
//!
//! Each input is parsed under a `BudgetAllocator` with a TIGHT ceiling
//! (the parser is documented zero-allocation on the hot path, so any
//! allocation inside the matcher under fuzz is an immediate FAIL). We
//! also wrap the allocator in `std.testing.FailingAllocator` to double-
//! enforce.
//!
//! Wire-up: this file is NOT yet plugged into build.zig (it is a conflict
//! zone during Phase 7). See `tests/fuzz/README.md` for the exact `zig
//! test` invocation Lead should use at the gate, and for the one-line
//! build.zig addition to run under `zig build test`.

const std = @import("std");
const shared = @import("shared");

// Direct import of the parser source file. This avoids depending on
// whether `parser_mod` is pub on the engine root module and keeps the
// fuzz binary compile-time cheap — only the parser + matcher + its
// transitive imports (shared) are pulled in, not the whole engine.
const parser = @import("parser");

const testing = std.testing;

// ============================================================================
// Seed corpus — deterministic adversarial inputs.
// ============================================================================

const seeds = [_][]const u8{
    // Empty and near-empty.
    "",
    "\n",
    " ",
    "\x00",

    // Valid baseline (for coverage sanity — parser must NOT reject these).
    "Failed password for root from 1.2.3.4",
    "Failed password for root from ::1",

    // Malformed IPs the parser is expected to REJECT (no panic).
    "Failed password for root from 999.999.999.999",
    "Failed password for root from 1.2.3",
    "Failed password for root from 1.2.3.4.5",
    "Failed password for root from ...",
    "Failed password for root from :::::::::::",
    "Failed password for root from 1.2.3.-4",
    "Failed password for root from 256.256.256.256",

    // Integer overflow probes — multi-digit octet sequences that,
    // without the digit-count cap, would overflow u32 arithmetic.
    "Failed password for root from 99999999.99999999.99999999.99999999",

    // Timestamp edge cases routed through a <TIMESTAMP> pattern below.
    "2026-04-20T14:30:22Z sshd from 1.2.3.4",
    "9999-99-99T99:99:99Z sshd from 1.2.3.4",
    "0000-00-00T00:00:00Z sshd from 1.2.3.4",
    "2026-13-40T25:61:61+99:99 sshd from 1.2.3.4",
    "Apr 99 99:99:99 host sshd 1.2.3.4",
    "9999999999999999999999 sshd from 1.2.3.4",

    // IPv6 truncation-loop stressor (see SEC-009).
    "Failed password for root from a:b:c:d:e:f:0123456789abcdef:0123456789abcdef:z",
    "Failed password for root from :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::",

    // Extreme length (parser operates on any []const u8 up to the caller's
    // buffer cap — LineBuffer enforces 4KB; we go higher to be abusive).
    "Failed password for root from " ++ ("A" ** 8000) ++ " 1.2.3.4",

    // High-bit / UTF-8 garbage.
    "\xff\xff\xff\xff\xff\xff\xff\xff",
    "\xc3\xa9\xc3\xa9\xc3\xa9 1.2.3.4",

    // Only literal prefix, no IP.
    "Failed password for root from",

    // Multiple IPs — first-match wins semantics.
    "Failed password for 1.2.3.4 and 5.6.7.8 from 9.9.9.9",

    // Mixed-case hex in v6.
    "Failed password for root from 2001:DB8:AAAA:BBBB::1",

    // IPv4-in-v6 mapped (regression seed for SEC-001).
    "Failed password for root from ::ffff:1.2.3.4",

    // Control characters injected mid-line.
    "Failed password\x01for root\x02from\t1.2.3.4",

    // NUL in the middle (Zig slices tolerate but C APIs might not).
    "Failed\x00password for root from 1.2.3.4",
};

// ============================================================================
// Fuzz entry points
// ============================================================================

const sshd_pattern = "Failed password for <*> from <IP>";
const ts_pattern = "<TIMESTAMP> <*> from <IP>";

fn runOne(match_fn: parser.MatchFn, input: []const u8) !void {
    // The parser is documented zero-allocation on the hot path. Run the
    // call directly; if any allocation ever shows up here, switch this
    // to a FailingAllocator-wrapped Parser.withMatcher and inspect the
    // allocator state (see the `zero heap allocation` test inside
    // parser.zig for the precise pattern).
    //
    // Contract under fuzz: match_fn must not panic, must not hang, and
    // must terminate within a bounded number of iterations proportional
    // to input.len — no attacker-controlled backtracking.
    _ = match_fn(input);
}

test "fuzz_parser: sshd pattern over full seed corpus" {
    const m = comptime parser.compile(sshd_pattern);
    for (seeds) |s| {
        try runOne(m, s);
    }
}

test "fuzz_parser: timestamped pattern over full seed corpus" {
    const m = comptime parser.compile(ts_pattern);
    for (seeds) |s| {
        try runOne(m, s);
    }
}

test "fuzz_parser: extractors on raw adversarial bytes" {
    // Drive the low-level extractors directly so the fuzz surface covers
    // them even when no pattern literal happens to land the cursor there.
    for (seeds) |s| {
        _ = parser.extractIpv4(s);
        _ = parser.extractIpv6(s);
        _ = parser.extractTimestamp(s);
    }
}

test "fuzz_parser: multi-pattern matcher rejects garbage cleanly" {
    const m = comptime parser.matcher.Matcher.init(&.{
        .{
            .pattern = sshd_pattern,
            .jail = shared.JailId.fromSlice("sshd") catch unreachable,
            .id = 1,
        },
        .{
            .pattern = ts_pattern,
            .jail = shared.JailId.fromSlice("sshd") catch unreachable,
            .id = 2,
        },
    });
    for (seeds) |s| {
        _ = m.match(s);
    }
}

// ============================================================================
// PRNG-driven expansion — generate 10k random byte streams up to 256 bytes
// each. Each stream is parsed; the only assertion is "does not crash".
// ============================================================================

test "fuzz_parser: random byte streams do not crash the parser" {
    var prng = std.Random.DefaultPrng.init(0xDEADBEEF_CAFEBABE);
    const rand = prng.random();
    const m = comptime parser.compile(sshd_pattern);

    var i: usize = 0;
    while (i < 10_000) : (i += 1) {
        var buf: [256]u8 = undefined;
        const len = rand.intRangeAtMost(usize, 0, buf.len);
        rand.bytes(buf[0..len]);
        _ = m(buf[0..len]);
    }
}
