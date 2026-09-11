// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Staged pre-matching line tuples. Matching/removal/correlation belongs to P3.
const std = @import("std");
pub const times = @import("event_time.zig");
pub const Tuple = struct { prefix: []const u8 = "", time: []const u8 = "", suffix: []const u8 = "" };
pub const Snapshot = struct {
    last_time_text: []const u8 = "",
    lines: []const Tuple = &.{},
    processed: ?Tuple = null,
};
pub const Limits = struct { max_lines: usize = 1, max_bytes: usize = 1024 * 1024 };
pub const Input = struct {
    line: []const u8,
    parts: ?Tuple = null,
    event_input: times.Input,
    previous_date: ?times.EventTime,
    now: times.EventTime,
    normalized: times.Result,
};
pub const Staged = struct { snapshot: Snapshot, prospective: Tuple, no_date: bool, appended: bool };

fn tupleBytes(tuple: Tuple) !usize {
    return std.math.add(usize, try std.math.add(usize, tuple.prefix.len, tuple.time.len), tuple.suffix.len);
}

pub fn validate(saved: Snapshot, limits: Limits) !void {
    if (limits.max_lines == 0 or limits.max_lines > 1000 or limits.max_bytes == 0 or limits.max_bytes > 8 * 1024 * 1024) return error.InvalidLineLimits;
    if (saved.lines.len > limits.max_lines) return error.InvalidLineContext;
    var count = saved.last_time_text.len;
    if (saved.processed) |tuple| count = try std.math.add(usize, count, try tupleBytes(tuple));
    for (saved.lines) |tuple| count = try std.math.add(usize, count, try tupleBytes(tuple));
    if (count > limits.max_bytes) return error.LineContextTooLarge;
}

/// Slices borrow the line and saved context; only the new tuple array is allocated.
/// Serialize/copy the staged snapshot before releasing either backing allocation.
pub fn stage(allocator: std.mem.Allocator, saved: Snapshot, input: Input, limits: Limits) !Staged {
    try validate(saved, limits);
    _ = try times.EventTime.init(input.now.seconds);
    if (input.event_input == .parsed) _ = try times.EventTime.init(input.event_input.parsed.seconds);
    var next = saved;
    var tuple = input.parts orelse Tuple{ .suffix = input.line };
    const no_date = input.event_input == .missing or input.event_input == .invalid;
    if (input.event_input == .parsed) {
        if (input.parts == null) return error.MissingParsedTuple;
        next.last_time_text = tuple.time;
    } else if (input.previous_date) |last| {
        _ = try times.EventTime.init(last.seconds);
        if (last.seconds != 0 and last.seconds > input.now.seconds - 60) tuple = .{ .time = saved.last_time_text, .suffix = input.line };
    }
    const appended = input.normalized.disposition != .obsolete;
    var allocated: ?[]Tuple = null;
    errdefer if (allocated) |lines| allocator.free(lines);
    if (appended) {
        const retained = @min(saved.lines.len, limits.max_lines - 1);
        const lines = try allocator.alloc(Tuple, retained + 1);
        allocated = lines;
        @memcpy(lines[0..retained], saved.lines[saved.lines.len - retained ..]);
        lines[retained] = tuple;
        next.lines = lines;
        next.processed = tuple;
    }
    try validate(next, limits);
    return .{ .snapshot = next, .prospective = tuple, .no_date = no_date, .appended = appended };
}

/// Python DateResult start/end count Unicode codepoints, not UTF-8 bytes.
pub fn splitCodepoints(line: []const u8, start: usize, end: usize) !Tuple {
    if (start > end) return error.InvalidDateSpan;
    var view = try std.unicode.Utf8View.init(line);
    var iterator = view.iterator();
    var point: usize = 0;
    var start_byte: ?usize = if (start == 0) 0 else null;
    var end_byte: ?usize = if (end == 0) 0 else null;
    while (iterator.nextCodepointSlice()) |_| {
        point += 1;
        if (point == start) start_byte = iterator.i;
        if (point == end) end_byte = iterator.i;
    }
    const first = start_byte orelse return error.InvalidDateSpan;
    const last = end_byte orelse return error.InvalidDateSpan;
    return .{ .prefix = line[0..first], .time = line[first..last], .suffix = line[last..] };
}

/// A nonparticipating optional regex group reports (-1,-1). The reference uses
/// Python slicing, preserving all but the final codepoint as the prefix.
pub fn splitPythonSpan(line: []const u8, start: i64, end: i64) !Tuple {
    if (start == -1 and end == -1) {
        const count = try std.unicode.utf8CountCodepoints(line);
        const boundary = count -| 1;
        return splitCodepoints(line, boundary, boundary);
    }
    if (start < 0 or end < 0) return error.InvalidDateSpan;
    return splitCodepoints(line, std.math.cast(usize, start) orelse return error.InvalidDateSpan, std.math.cast(usize, end) orelse return error.InvalidDateSpan);
}

test "recent text reuse and obsolete update are staged before matching" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var saved = Snapshot{};
    const parsed = try stage(arena.allocator(), saved, .{ .line = "[old] event", .parts = .{ .prefix = "[", .time = "old", .suffix = "] event" }, .event_input = .{ .parsed = try times.EventTime.init(1) }, .previous_date = null, .now = try times.EventTime.init(1000), .normalized = .{ .disposition = .obsolete } }, .{});
    try std.testing.expectEqualStrings("old", parsed.snapshot.last_time_text);
    try std.testing.expectEqual(@as(usize, 0), parsed.snapshot.lines.len);
    saved = parsed.snapshot;
    const missing = try stage(arena.allocator(), saved, .{ .line = "follow", .event_input = .missing, .previous_date = try times.EventTime.init(999), .now = try times.EventTime.init(1000), .normalized = .{ .disposition = .accepted } }, .{});
    try std.testing.expectEqualStrings("old", missing.prospective.time);
    try std.testing.expectEqualStrings("follow", missing.prospective.suffix);
    try std.testing.expect(missing.no_date);
    try std.testing.expectEqual(@as(usize, 0), saved.lines.len);
}

test "date spans count Unicode codepoints and enforce buffer budget" {
    const tuple = try splitCodepoints("é[123] Ω", 2, 5);
    try std.testing.expectEqualStrings("é[", tuple.prefix);
    try std.testing.expectEqualStrings("123", tuple.time);
    try std.testing.expectEqualStrings("] Ω", tuple.suffix);
    try std.testing.expectError(error.InvalidDateSpan, splitCodepoints("x", 0, 2));
    try std.testing.expectError(error.LineContextTooLarge, validate(.{ .last_time_text = "long" }, .{ .max_bytes = 3 }));
    const optional = try splitPythonSpan("aΩ", -1, -1);
    try std.testing.expectEqualStrings("a", optional.prefix);
    try std.testing.expectEqualStrings("Ω", optional.suffix);
}

test "staged oversize context releases general allocator memory" {
    try std.testing.expectError(error.LineContextTooLarge, stage(std.testing.allocator, .{}, .{ .line = "oversize", .event_input = .missing, .previous_date = null, .now = try times.EventTime.init(1000), .normalized = .{ .disposition = .undated } }, .{ .max_bytes = 3 }));
    try std.testing.expectError(error.OutOfMemory, stage(std.testing.failing_allocator, .{}, .{ .line = "x", .event_input = .missing, .previous_date = null, .now = try times.EventTime.init(1000), .normalized = .{ .disposition = .undated } }, .{}));
}
