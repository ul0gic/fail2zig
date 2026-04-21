//! Memory-ceiling benchmark.
//!
//! Simulates a 10,000-unique-IPs/min attack for 5 minutes against the
//! in-process `StateTracker` and asserts the tracker's memory footprint
//! stays under the configured ceiling. Exercises the eviction policy
//! — without eviction, 50K unique IPs would blow past the 64MB default
//! budget.
//!
//! We compress the wall-clock of a 5-minute simulation into a few
//! seconds of synthetic time by advancing the `timestamp` parameter of
//! `recordAttempt`, not `std.time.timestamp()`. The ring buffer trims
//! against that logical time, so ban decisions fire exactly as they
//! would in production.
//!
//! Opt-in via FAIL2ZIG_RUN_BENCH=1 — this test does real work and
//! shouldn't run on every developer `zig build test`.

const std = @import("std");
const builtin = @import("builtin");

const shared = @import("shared");
const engine = @import("engine");

const state = engine.state_mod;

const testing = std.testing;

const ips_per_minute: u32 = 10_000;
const minutes: u32 = 5;
const total_attempts: u64 = @as(u64, ips_per_minute) * minutes;

/// Capacity derived from a conservative 32MB budget for the tracker
/// (half of the default 64MB ceiling). approx_bytes_per_entry is ~1536
/// so this comes to ~21,800 slots — well below our 50K unique IPs.
const tracker_budget_bytes: usize = 32 * 1024 * 1024;

test "benchmark: memory stays under ceiling with eviction under sustained attack" {
    if (!benchmarkEnabled()) return error.SkipZigTest;
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const a = testing.allocator;

    const capacity = state.capacityFromBudget(tracker_budget_bytes);
    var tracker = try state.StateTracker.init(a, .{
        .max_entries = capacity,
        .findtime = 600,
        .maxretry = 5,
        .bantime = 3600,
        .eviction_policy = .drop_oldest_unbanned,
    });
    defer tracker.deinit();

    const jail = try shared.JailId.fromSlice("sshd");
    var rng = std.Random.DefaultPrng.init(0xBEEF1234);
    const rnd = rng.random();

    var timer = try std.time.Timer.start();
    const t0 = timer.read();

    // Walk logical time forward by 1s per 10_000/60 ≈ 167 attempts —
    // i.e. ~167 new IPs per second, 10K per minute. We feed the tracker
    // the next logical second after each batch of 167 attempts.
    var logical_ts: shared.Timestamp = 1_700_000_000;
    var batch_count: u32 = 0;
    var observed_decisions: u64 = 0;
    var i: u64 = 0;
    while (i < total_attempts) : (i += 1) {
        // Random 10.0.0.0/16 IPv4 — 65K-IP pool means ~75% of the
        // 50K total attempts collide, reinforcing the same IP's ring
        // and exercising both the ban path AND the eviction path.
        const octet_c = rnd.uintLessThan(u32, 256);
        const octet_d = rnd.uintLessThan(u32, 256);
        const ip: shared.IpAddress = .{ .ipv4 = (@as(u32, 10) << 24) | (octet_c << 8) | octet_d };
        if (try tracker.recordAttempt(ip, jail, logical_ts)) |_| {
            observed_decisions += 1;
        }

        batch_count += 1;
        if (batch_count >= 167) {
            logical_ts += 1;
            batch_count = 0;
        }
    }

    const elapsed_ns = timer.read() - t0;
    const stats = tracker.stats();

    // Invariants:
    //   - Tracker never exceeds its configured capacity.
    //   - Eviction counter is non-zero (we exceeded capacity → evictions).
    //   - At least one ban fired.
    try testing.expect(stats.entry_count <= capacity);
    try testing.expect(stats.evictions > 0);
    try testing.expect(observed_decisions > 0);

    const stdout = std.io.getStdOut().writer();
    stdout.print(
        \\{{"bench":"memory_ceiling","attempts":{d},"capacity":{d},"entry_count":{d},"evictions":{d},"decisions":{d},"elapsed_ns":{d}}}
        \\
    ,
        .{
            total_attempts,
            capacity,
            stats.entry_count,
            stats.evictions,
            observed_decisions,
            elapsed_ns,
        },
    ) catch {};
}

fn benchmarkEnabled() bool {
    const val = std.process.getEnvVarOwned(std.heap.page_allocator, "FAIL2ZIG_RUN_BENCH") catch return false;
    defer std.heap.page_allocator.free(val);
    return std.mem.eql(u8, val, "1") or std.mem.eql(u8, val, "true");
}
