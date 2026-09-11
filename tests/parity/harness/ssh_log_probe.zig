// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const engine = @import("engine");

/// One ordinary sanitized authentication record, using the native SSH matcher.
/// This observes matching only: no ticket, daemon, action, source or firewall.
pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const args = try std.process.argsAlloc(allocator);
    if (args.len != 2 or args[1].len > 1024) return error.ExpectedBoundedLogRecord;
    const body = engine.parser_mod.stripSyslogPrefix(args[1]);
    var identity: ?[]const u8 = null;
    for (engine.filter_sshd_mod.patterns) |pattern| {
        if (pattern.match(body)) |matched| {
            identity = try std.fmt.allocPrint(allocator, "{}", .{matched.ip});
            break;
        }
    }
    const writer = std.io.getStdOut().writer();
    try std.json.stringify(.{ .identity = identity, .result = if (identity != null) "matched" else "ignored" }, .{}, writer);
    try writer.writeByte('\n');
}
