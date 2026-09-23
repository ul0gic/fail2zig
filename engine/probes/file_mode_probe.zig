// SPDX-License-Identifier: AGPL-3.0-or-later
const std = @import("std");
const files = @import("engine_probe").core.durable_file_source;
const records = @import("engine_probe").core.source_record;
const Event = struct { line: []const u8, live: bool };
const Capture = struct {
    allocator: std.mem.Allocator,
    source: *files.FileSource,
    events: std.ArrayList(Event),
    append_during_ack: ?[]const u8 = null,
    fn ack(record: records.Record, context: ?*anyopaque) !void {
        const self: *Capture = @ptrCast(@alignCast(context.?));
        if (record.kind == .data) try self.events.append(.{ .line = try self.allocator.dupe(u8, record.message), .live = self.source.in_operation });
        if (record.kind == .data) if (self.append_during_ack) |path| {
            self.append_during_ack = null;
            var writer = try std.fs.cwd().openFile(path, .{ .mode = .write_only });
            defer writer.close();
            try writer.seekFromEnd(0);
            try writer.writeAll("during acknowledgement\n");
        };
    }
};
pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const args = try std.process.argsAlloc(a);
    if (args.len != 4 and args.len != 5) return error.InvalidArguments;
    const tail = std.mem.eql(u8, args[2], "1");
    const restored = !std.mem.eql(u8, args[3], "none");
    var source = try files.FileSource.init(a, args[1], "original-mode", if (tail or restored) .tail else .head, null);
    defer source.deinit();
    var capture = Capture{ .allocator = a, .source = &source, .events = std.ArrayList(Event).init(a), .append_during_ack = if (args.len == 5) args[1] else null };
    if (restored) {
        _ = try source.poll(Capture.ack, &capture);
        var checkpoint = source.committed.?;
        checkpoint.offset = try std.fmt.parseInt(u64, args[3], 10);
        source.deinit();
        source = try files.FileSource.init(a, args[1], "original-mode", .head, checkpoint);
    }
    const out = std.io.getStdOut().writer();
    try out.writeByte('[');
    for (0..2) |step| {
        if (step != 0) {
            var writer = try std.fs.cwd().openFile(args[1], .{ .mode = .write_only });
            defer writer.close();
            try writer.seekFromEnd(0);
            try writer.writeAll("later\n");
            try out.writeByte(',');
        }
        capture.events.clearRetainingCapacity();
        const before = source.in_operation;
        while (try source.poll(Capture.ack, &capture)) {}
        try std.json.stringify(.{ .stage = if (step == 0) "first" else "append", .before = before, .after = source.in_operation, .position = source.committed.?.offset, .events = capture.events.items }, .{}, out);
    }
    try out.writeByte(']');
}
