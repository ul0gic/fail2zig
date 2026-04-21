// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Ban-latency benchmark.
//!
//! Measures the time from a log line being written to a "ban decision"
//! emerging — the core hot-path latency the PRD targets (<1ms).
//!
//! We measure in-process, not via a daemon subprocess, because:
//!
//!   * An IPC round-trip adds its own scheduling/socket overhead that
//!     isn't part of the ban-decision latency.
//!   * The parser → state-tracker flow IS the ban-decision path. Any
//!     production daemon running this code sees the same number ±
//!     inotify/syscall overhead, which we measure separately.
//!
//! The benchmark:
//!
//!   1. Configures a `Matcher` holding the built-in sshd pattern set.
//!   2. Configures a `StateTracker` with maxretry=3.
//!   3. Pre-populates the tracker with 2 attempts for one IP.
//!   4. Times the sequence: `match(line)` → `recordAttempt(result.ip)` →
//!      receive the `BanDecision`.
//!   5. Averages over N iterations; reports p50 and p99.
//!
//! Output is one JSON line for machine-readable comparison.

const std = @import("std");
const builtin = @import("builtin");

const shared = @import("shared");
const engine = @import("engine");

const state = engine.state_mod;
const parser = @import("../../engine/core/parser.zig");

const testing = std.testing;

const iterations: u32 = 10_000;
const target_ns: u64 = 1_000_000; // 1ms

test "benchmark: ban decision latency under target" {
    if (!benchmarkEnabled()) return error.SkipZigTest;
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const a = testing.allocator;

    // Matcher built from the sshd pattern's first entry. Direct
    // `parser.compile` gives us the same MatchFn the production Matcher
    // wraps.
    const match_fn = comptime parser.compile("Failed password for <*> from <IP>");

    // Pre-constructed log line.
    const line = "Failed password for root from 203.0.113.42 port 22 ssh2";
    const jail = try shared.JailId.fromSlice("sshd");

    // Samples in a flat array so we can sort for percentiles.
    var samples = try a.alloc(u64, iterations);
    defer a.free(samples);

    var total_decisions: u64 = 0;
    var timer = try std.time.Timer.start();
    var i: u32 = 0;
    while (i < iterations) : (i += 1) {
        // Per-iteration tracker so we can measure the full "cold ban"
        // latency each time — from first match to ban decision. A shared
        // tracker would only emit a ban once.
        var tracker = try state.StateTracker.init(a, .{
            .findtime = 600,
            .maxretry = 3,
            .bantime = 600,
        });
        defer tracker.deinit();

        // Pre-seed 2 attempts so the 3rd attempt triggers the ban.
        const ip = try shared.IpAddress.parse("203.0.113.42");
        _ = try tracker.recordAttempt(ip, jail, 1_700_000_000);
        _ = try tracker.recordAttempt(ip, jail, 1_700_000_001);

        const t0 = timer.read();
        const result = match_fn(line) orelse unreachable;
        const decision = try tracker.recordAttempt(result.ip, jail, 1_700_000_002);
        const t1 = timer.read();

        if (decision != null) total_decisions += 1;
        samples[i] = t1 - t0;
    }

    std.sort.pdq(u64, samples, {}, std.sort.asc(u64));
    const p50 = samples[samples.len / 2];
    const p99 = samples[(samples.len * 99) / 100];
    const mean_sum: u64 = blk: {
        var s: u64 = 0;
        for (samples) |x| s += x;
        break :blk s;
    };
    const mean = mean_sum / samples.len;

    try testing.expectEqual(@as(u64, iterations), total_decisions);

    const stdout = std.io.getStdOut().writer();
    stdout.print(
        \\{{"bench":"ban_latency","iterations":{d},"p50_ns":{d},"p99_ns":{d},"mean_ns":{d},"target_ns":{d}}}
        \\
    ,
        .{ iterations, p50, p99, mean, target_ns },
    ) catch {};

    if (p99 > target_ns) {
        std.log.err("ban-latency regression: p99={d}ns > target {d}ns", .{ p99, target_ns });
        return error.TestBelowTarget;
    }
}

fn benchmarkEnabled() bool {
    const val = std.process.getEnvVarOwned(std.heap.page_allocator, "FAIL2ZIG_RUN_BENCH") catch return false;
    defer std.heap.page_allocator.free(val);
    return std.mem.eql(u8, val, "1") or std.mem.eql(u8, val, "true");
}
