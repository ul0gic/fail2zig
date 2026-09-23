// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const guard_options = @import("guard_options");

const testing = std.testing;

const forbidden = "@import(\"..";
const max_file_bytes: usize = 4 * 1024 * 1024;

fn scan(allocator: std.mem.Allocator, dir: std.fs.Dir, offenders: *std.ArrayList([]const u8)) !void {
    var walker = try dir.walk(allocator);
    defer walker.deinit();
    while (try walker.next()) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.basename, ".zig")) continue;
        const contents = try entry.dir.readFileAlloc(allocator, entry.basename, max_file_bytes);
        defer allocator.free(contents);
        if (std.mem.indexOf(u8, contents, forbidden) == null) continue;
        try offenders.append(try allocator.dupe(u8, entry.path));
    }
}

test "module graph: tests/ never imports engine sources by relative path" {
    const a = testing.allocator;
    var dir = try std.fs.openDirAbsolute(guard_options.tests_dir, .{ .iterate = true });
    defer dir.close();

    var offenders = std.ArrayList([]const u8).init(a);
    defer {
        for (offenders.items) |p| a.free(p);
        offenders.deinit();
    }
    try scan(a, dir, &offenders);

    for (offenders.items) |p| {
        std.debug.print("relative parent import in tests/{s}: use @import(\"engine\") or a named module\n", .{p});
    }
    try testing.expectEqual(@as(usize, 0), offenders.items.len);
}
