// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const builtin = @import("builtin");

const engine = @import("engine");
const parser = engine.parser_mod;

const testing = std.testing;

const min_lines_per_sec: u64 = 22_000;

const total_lines: usize = 1_000_000;

test "benchmark: parser throughput >= target" {
    if (!benchmarkEnabled()) return error.SkipZigTest;

    const a = testing.allocator;

    const avg_line_len: usize = 96;
    var corpus = try a.alloc(u8, total_lines * avg_line_len);
    defer a.free(corpus);

    var offsets = try a.alloc(struct { start: usize, end: usize }, total_lines);
    defer a.free(offsets);

    var rng = std.Random.DefaultPrng.init(0xF221);
    const rnd = rng.random();
    var pos: usize = 0;
    for (0..total_lines) |i| {
        const start = pos;
        const ip_a = rnd.uintLessThan(u32, 256);
        const ip_b = rnd.uintLessThan(u32, 256);
        const ip_c = rnd.uintLessThan(u32, 256);
        const ip_d = rnd.uintLessThan(u32, 256);
        const port = 1024 + rnd.uintLessThan(u32, 64000);
        const written = try std.fmt.bufPrint(
            corpus[pos..],
            "Failed password for root from {d}.{d}.{d}.{d} port {d} ssh2",
            .{ ip_a, ip_b, ip_c, ip_d, port },
        );
        pos += written.len;
        offsets[i] = .{ .start = start, .end = pos };
    }

    const match_fn = comptime parser.compile("Failed password for <*> from <IP>");

    var matched: u64 = 0;
    var timer = try std.time.Timer.start();
    const t0 = timer.read();
    for (offsets) |o| {
        if (match_fn(corpus[o.start..o.end])) |_| matched += 1;
    }
    const elapsed_ns = timer.read() - t0;

    const elapsed_s: f64 = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, std.time.ns_per_s);
    const rate: f64 = @as(f64, @floatFromInt(total_lines)) / elapsed_s;

    const stdout = std.io.getStdOut().writer();
    stdout.print(
        \\{{"bench":"parse_throughput","lines":{d},"matched":{d},"elapsed_ns":{d},"lines_per_sec":{d:.0},"target":{d}}}
        \\
    ,
        .{ total_lines, matched, elapsed_ns, rate, min_lines_per_sec },
    ) catch {};

    try testing.expect(matched == total_lines);
    if (@as(u64, @intFromFloat(rate)) < min_lines_per_sec) {
        std.log.err(
            "parse throughput regression: {d:.0} lines/sec < target {d}",
            .{ rate, min_lines_per_sec },
        );
        return error.TestBelowTarget;
    }
}

fn benchmarkEnabled() bool {
    if (builtin.os.tag != .linux) return false;
    const val = std.process.getEnvVarOwned(std.heap.page_allocator, "FAIL2ZIG_RUN_BENCH") catch return false;
    defer std.heap.page_allocator.free(val);
    return std.mem.eql(u8, val, "1") or std.mem.eql(u8, val, "true");
}
