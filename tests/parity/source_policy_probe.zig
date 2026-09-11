// SPDX-License-Identifier: AGPL-3.0-or-later
const std = @import("std");
const policy = @import("source_policy");
fn boolean(value: []const u8) bool {
    return std.mem.eql(u8, value, "1");
}
const Factory = struct {
    outcomes: []const u8,
    attempted: [3]policy.Backend = undefined,
    count: usize = 0,
    fn initialize(backend: policy.Backend, context: ?*anyopaque) !void {
        const self: *Factory = @ptrCast(@alignCast(context.?));
        self.attempted[self.count] = backend;
        self.count += 1;
        switch (self.outcomes[@intFromEnum(backend)]) {
            'm' => return error.DependencyUnavailable,
            'e' => return error.InitializationFailed,
            else => {},
        }
    }
};
pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const args = try std.process.argsAlloc(arena.allocator());
    const out = std.io.getStdOut().writer();
    if (args.len == 10 and std.mem.eql(u8, args[1], "prepare")) {
        const result = policy.prepare(.{ .raw_backend = args[2], .logpath_present = boolean(args[3]), .matched_files = try std.fmt.parseInt(usize, args[4], 10), .journalmatch_present = boolean(args[5]), .skip_if_nologs = boolean(args[6]), .systemd_if_nologs = boolean(args[7]), .global_systemd_if_nologs = boolean(args[8]), .allow_no_files = boolean(args[9]) });
        try std.json.stringify(.{ .disposition = @tagName(result.disposition), .backend = result.backend }, .{}, out);
    } else if (args.len == 4 and std.mem.eql(u8, args[1], "select")) {
        if (args[3].len != 3) return error.InvalidArguments;
        var factory = Factory{ .outcomes = args[3] };
        const result = policy.select(args[2], &factory, Factory.initialize) catch |err| {
            try std.json.stringify(.{ .failure = @errorName(err), .attempts = factory.attempted[0..factory.count] }, .{}, out);
            return;
        };
        try std.json.stringify(.{ .backend = @tagName(result.backend), .attempts = factory.attempted[0..factory.count] }, .{}, out);
    } else return error.InvalidArguments;
}
