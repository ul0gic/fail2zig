// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const state = @import("state");
const shared = @import("shared");

/// Narrow observation probe: real StateTracker only, no daemon or backend.
pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const args = try std.process.argsAlloc(arena.allocator());
    if (args.len != 4) return error.ExpectedFindtimeMaxretryAndEventCsv;
    const findtime = try std.fmt.parseInt(u64, args[1], 10);
    const maxretry = try std.fmt.parseInt(u32, args[2], 10);
    if (findtime == 0 or findtime > 3600 or maxretry == 0 or maxretry > 1024)
        return error.FixtureOutsideProbeBounds;
    if (args[3].len > 8192) return error.FixtureOutsideProbeBounds;
    var tracker = try state.StateTracker.init(arena.allocator(), .{
        .max_entries = 2,
        .findtime = findtime,
        .maxretry = maxretry,
        .bantime = 60,
    });
    defer tracker.deinit();
    const ip = try shared.IpAddress.parse("192.0.2.10");
    const jail = try shared.JailId.fromSlice("synthetic");
    var tokens = std.mem.splitScalar(u8, args[3], ',');
    const writer = std.io.getStdOut().writer();
    try writer.writeAll("{\"trace\":[");
    var count: usize = 0;
    while (tokens.next()) |token| {
        if (count >= 256) return error.FixtureOutsideProbeBounds;
        const timestamp = try std.fmt.parseInt(i64, token, 10);
        const decision = try tracker.recordAttempt(ip, jail, timestamp);
        const current = tracker.get(ip) orelse return error.MissingFixtureState;
        if (count != 0) try writer.writeByte(',');
        try std.json.stringify(.{
            .pending_retry = if (current.isBanned()) @as(u32, 0) else @as(u32, current.ring_len),
            .pending_last_time = if (current.isBanned()) @as(?i64, null) else current.last_attempt,
            .threshold_reached = decision != null,
        }, .{}, writer);
        count += 1;
        // Fixtures stop at first decision: action/reban semantics are out of scope.
        if (decision != null and tokens.next() != null) return error.EventAfterDecision;
    }
    if (count == 0) return error.EmptyFixture;
    try writer.writeAll("]}\n");
}
