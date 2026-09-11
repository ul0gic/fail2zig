// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const config = @import("fail2ban_config");
pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const args = try std.process.argsAlloc(a);
    if (args.len == 3 and std.mem.eql(u8, args[1], "selectors")) {
        const Pair = struct { name: []const u8, value: []const u8 };
        const Selected = struct { name: []const u8, parameters: []const Pair };
        var selected = std.ArrayListUnmanaged(Selected){};
        for (try config.splitSelectors(a, args[2])) |raw| {
            const parsed = try config.parseSelector(a, raw);
            var pairs = std.ArrayListUnmanaged(Pair){};
            var iterator = parsed.parameters.iterator();
            while (iterator.next()) |entry| try pairs.append(a, .{ .name = entry.key_ptr.*, .value = entry.value_ptr.* });
            try selected.append(a, .{ .name = parsed.name, .parameters = pairs.items });
        }
        try std.json.stringify(selected.items, .{}, std.io.getStdOut().writer());
        return;
    }
    if (args.len == 7 and std.mem.eql(u8, args[1], "asset")) {
        const asset = try config.loadParameterizedAsset(a, args[2], args[3], args[4]);
        const combined = config.combineAsset(a, &asset, args[6]) catch |err| {
            try std.json.stringify(.{ .value = @as(?[]const u8, null), .failure = @errorName(err) }, .{}, std.io.getStdOut().writer());
            return;
        };
        try std.json.stringify(.{ .value = combined.get(args[5]), .failure = @as(?[]const u8, null) }, .{}, std.io.getStdOut().writer());
        return;
    }
    if (args.len != 5) return error.ExpectedDirectoryStemSectionOption;
    var ini = try config.loadConfig(a, args[1], args[2]);
    const value = config.resolve(a, &ini, args[3], args[4]) catch |err| {
        try std.json.stringify(.{ .value = @as(?[]const u8, null), .failure = @errorName(err) }, .{}, std.io.getStdOut().writer());
        return;
    };
    try std.json.stringify(.{ .value = value, .failure = @as(?[]const u8, null) }, .{}, std.io.getStdOut().writer());
}
