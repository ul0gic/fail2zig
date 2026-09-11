// SPDX-License-Identifier: AGPL-3.0-or-later
const std = @import("std");
const lines = @import("line_context");
const times = lines.times;
const Row = struct { line: []const u8, kind: enum { parsed, missing, invalid, optional_empty }, value: ?f64 = null, start: i64 = 0, end: i64 = 0, now: f64, mode: times.Mode };
const Case = struct { max_lines: usize, rows: []const Row };
pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const args = try std.process.argsAlloc(a);
    if (args.len != 2) return error.InvalidArguments;
    const fixture = try std.json.parseFromSliceLeaky(Case, a, args[1], .{});
    var context = lines.Snapshot{};
    var dates = times.Context{};
    const out = std.io.getStdOut().writer();
    try out.writeByte('[');
    for (fixture.rows, 0..) |row, index| {
        const now = try times.EventTime.init(row.now);
        const prior = dates.last_date;
        const input: times.Input = switch (row.kind) {
            .parsed => .{ .parsed = try times.EventTime.init(row.value.?) },
            .missing => .missing,
            .invalid => .invalid,
            .optional_empty => .optional_empty,
        };
        const normalized = try dates.normalize(input, now, 600, row.mode, true);
        const staged = try lines.stage(a, context, .{ .line = row.line, .parts = if (row.kind == .missing) null else try lines.splitPythonSpan(row.line, row.start, row.end), .event_input = input, .previous_date = prior, .now = now, .normalized = normalized }, .{ .max_lines = fixture.max_lines });
        context = staged.snapshot;
        if (index != 0) try out.writeByte(',');
        try std.json.stringify(.{ .last_date = if (dates.last_date) |date| date.seconds else @as(?f64, null), .last_time_text = context.last_time_text, .buffer = context.lines, .processed = context.processed, .appended = staged.appended, .no_date = if (staged.appended) staged.no_date else @as(?bool, null), .date = if (staged.appended and normalized.effective != null) normalized.effective.?.seconds else @as(?f64, null) }, .{}, out);
    }
    try out.writeByte(']');
}
