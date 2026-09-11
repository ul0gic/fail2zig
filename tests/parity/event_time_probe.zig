// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const event = @import("event_time");
const duration = @import("duration");
const parser = @import("parser");
/// Observation of actual candidate APIs; no daemon, matcher, scheduler or action execution.
pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const args = try std.process.argsAlloc(arena.allocator());
    const writer = std.io.getStdOut().writer();
    if (args.len == 3 and std.mem.eql(u8, args[1], "duration")) {
        try std.json.stringify(.{ .seconds = try duration.expression(args[2]) }, .{}, writer);
    } else if (args.len == 6 and std.mem.eql(u8, args[1], "normalize")) {
        var context: event.Context = .{};
        const mode = std.meta.stringToEnum(event.Mode, args[2]) orelse return error.InvalidMode;
        const now = try event.EventTime.init(try std.fmt.parseFloat(f64, args[3]));
        const window = try std.fmt.parseFloat(f64, args[4]);
        const input: event.Input = if (std.mem.eql(u8, args[5], "missing")) .missing else if (std.mem.eql(u8, args[5], "invalid")) .invalid else .{ .parsed = try event.EventTime.init(try std.fmt.parseFloat(f64, args[5])) };
        const result = try context.normalize(input, now, window, mode, true);
        try std.json.stringify(.{
            .disposition = @tagName(result.disposition),
            .parsed_time = if (result.effective) |t| t.seconds else @as(?f64, null),
            .stored_time = if (result.stored) |t| t.seconds else @as(?f64, null),
            .diagnostic = result.diagnostic,
        }, .{}, writer);
    } else if (args.len == 6 and std.mem.eql(u8, args[1], "timestamp")) {
        const result = parser.extractTimestampExact(args[5], .{
            .year = try std.fmt.parseInt(i64, args[2], 10),
            .now = try std.fmt.parseFloat(f64, args[3]),
            .default_offset_seconds = try std.fmt.parseInt(i32, args[4], 10),
        });
        try std.json.stringify(.{ .seconds = if (result) |r| r.seconds else @as(?f64, null) }, .{}, writer);
    } else return error.InvalidArguments;
    try writer.writeByte('\n');
}
