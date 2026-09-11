// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const engine = @import("engine");

/// Observe the production import/render/native-resolve pipeline. No daemon runs.
pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const args = try std.process.argsAlloc(allocator);
    if (args.len != 3) return error.ExpectedFixtureDirectoryAndPrivateOutput;
    const report = try engine.migration_mod.importConfig(allocator, args[1], args[2]);
    const config = try engine.config_mod.Config.loadFile(allocator, args[2]);
    const resolved = engine.config_mod.resolveJail(&config, "probe") orelse return error.MissingImportedJail;
    const value = try std.fmt.allocPrint(allocator, "{d}", .{resolved.maxretry});
    const writer = std.io.getStdOut().writer();
    try std.json.stringify(.{ .value = value, .warnings = report.warnings.len }, .{}, writer);
    try writer.writeByte('\n');
}
