// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const config = @import("fail2ban_config");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const args = try std.process.argsAlloc(allocator);
    if (args.len != 2) return error.ExpectedFixtureDirectory;
    var ini = try config.loadJailConfig(allocator, args[1]);
    const value = if (ini.section("probe")) |section| section.get("maxretry") else null;
    const writer = std.io.getStdOut().writer();
    try std.json.stringify(.{ .value = value, .warnings = ini.warnings.items.len }, .{}, writer);
    try writer.writeByte('\n');
}
