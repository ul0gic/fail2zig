// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");

// Hosted images need not install zoneinfo with permissions accepted by the
// daemon. Preserve the host's bytes while controlling this test's trust boundary.
pub fn copyInstalled(tmp: *std.testing.TmpDir, names: []const []const u8) ![]u8 {
    try tmp.dir.chmod(0o700);
    var installed = try std.fs.openDirAbsolute("/usr/share/zoneinfo", .{});
    defer installed.close();
    for (names) |name| {
        if (std.fs.path.dirname(name)) |parent| {
            try tmp.dir.makePath(parent);
            var directory = try tmp.dir.openDir(parent, .{ .iterate = true });
            defer directory.close();
            try directory.chmod(0o700);
        }
        const bytes = try installed.readFileAlloc(std.testing.allocator, name, 1024 * 1024);
        defer std.testing.allocator.free(bytes);
        var file = try tmp.dir.createFile(name, .{ .mode = 0o600 });
        defer file.close();
        try file.chmod(0o600);
        try file.writeAll(bytes);
    }
    return tmp.dir.realpathAlloc(std.testing.allocator, ".");
}
