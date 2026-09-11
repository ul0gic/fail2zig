// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const persist = @import("persist");
const shared = @import("shared");
// Use the exact tracker type accepted by the production persistence component.
const Tracker = @typeInfo(@typeInfo(@TypeOf(persist.save)).@"fn".params[0].type.?).pointer.child;
const Config = @typeInfo(@TypeOf(Tracker.init)).@"fn".params[1].type.?;

fn observe(current: anytype, writer: anytype) !void {
    try std.json.stringify(.{
        .pending_retry = if (current.isBanned()) @as(u32, 0) else @as(u32, current.ring_len),
        .pending_last_time = if (current.isBanned()) @as(?i64, null) else current.last_attempt,
        .threshold_reached = current.isBanned(),
        .attempt_count = current.attempt_count,
        .ban_count = current.ban_count,
        .ban_expiry = current.ban_expiry,
    }, .{}, writer);
}

/// Component save/load/seed only: no daemon, clock, action, or backend.
pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const args = try std.process.argsAlloc(allocator);
    if (args.len != 5) return error.ExpectedPathFindtimeMaxretryAndEventCsv;
    const findtime = try std.fmt.parseInt(u64, args[2], 10);
    const maxretry = try std.fmt.parseInt(u32, args[3], 10);
    if (findtime == 0 or findtime > 3600 or maxretry == 0 or maxretry > 1024 or args[4].len > 8192)
        return error.FixtureOutsideProbeBounds;
    const settings: Config = .{ .max_entries = 2, .findtime = findtime, .maxretry = maxretry, .bantime = 60 };
    var before = try Tracker.init(allocator, settings);
    const ip = try shared.IpAddress.parse("192.0.2.10");
    const jail = try shared.JailId.fromSlice("synthetic");
    const writer = std.io.getStdOut().writer();
    {
        defer before.deinit();
        var tokens = std.mem.splitScalar(u8, args[4], ',');
        var count: usize = 0;
        while (tokens.next()) |token| {
            if (count >= 256) return error.FixtureOutsideProbeBounds;
            const timestamp = try std.fmt.parseInt(i64, token, 10);
            const decision = try before.recordAttempt(ip, jail, timestamp);
            count += 1;
            if (decision != null and tokens.next() != null) return error.EventAfterDecision;
        }
        if (count == 0) return error.EmptyFixture;
        try persist.save(&before, args[1]);
        try writer.writeAll("{\"persisted\":");
        try observe(before.get(ip) orelse return error.MissingFixtureState, writer);
    }
    var after = try Tracker.init(allocator, settings);
    defer after.deinit();
    const entries = try persist.load(allocator, args[1]);
    defer allocator.free(entries);
    try persist.seed(&after, entries);
    try writer.writeAll(",\"restored\":");
    try observe(after.get(ip) orelse return error.MissingRestoredState, writer);
    try writer.writeAll("}\n");
}
