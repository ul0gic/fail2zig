// SPDX-License-Identifier: AGPL-3.0-or-later
const std = @import("std");
const files = @import("core/durable_file_source.zig");
const Capture = struct {
    allocator: std.mem.Allocator,
    messages: std.ArrayList([]const u8),
    fn ack(record: @import("core/source_record.zig").Record, context: ?*anyopaque) !void {
        const self: *Capture = @ptrCast(@alignCast(context.?));
        if (record.kind == .data) try self.messages.append(try self.allocator.dupe(u8, record.message));
    }
};
pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const args = try std.process.argsAlloc(allocator);
    if (args.len < 2) return error.InvalidArguments;
    var set = try files.FileSet.init(allocator, "original-aliases");
    defer set.deinit();
    for (args[1..]) |pattern| try set.add(pattern, .head);
    var capture = Capture{ .allocator = allocator, .messages = std.ArrayList([]const u8).init(allocator) };
    while (try set.poll(Capture.ack, &capture) != 0) {}
    const positions = try allocator.alloc(u64, set.sources.items.len);
    for (set.sources.items, 0..) |source, index| positions[index] = source.committed.?.offset;
    try std.json.stringify(.{ .configured_sources = set.sources.items.len, .records = capture.messages.items, .positions = positions }, .{}, std.io.getStdOut().writer());
}
