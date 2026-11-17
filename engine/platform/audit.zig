// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const logger = @import("logger.zig");

pub const AuditEvent = struct {
    command: []const u8,
    target: []const u8,
    jail: ?[]const u8,
    peer_uid: u32,
    outcome: []const u8,

    pub fn format(self: AuditEvent, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        try writer.writeAll("audit: command=");
        try writeValue(writer, self.command);
        try writer.writeAll(" target=");
        try writeValue(writer, self.target);
        try writer.writeAll(" jail=");
        try writeValue(writer, self.jail orelse "-");
        try writer.print(" uid={d} outcome=", .{self.peer_uid});
        try writeValue(writer, self.outcome);
    }

    pub fn logFields(self: AuditEvent) [5]logger.Field {
        return .{
            logger.Field.str("command", self.command),
            logger.Field.str("target", self.target),
            logger.Field.str("jail", self.jail orelse "-"),
            logger.Field.uint("uid", self.peer_uid),
            logger.Field.str("outcome", self.outcome),
        };
    }
};

pub fn write(event: AuditEvent) void {
    std.log.scoped(.audit).info("{}", .{event});
}

fn needsQuote(value: []const u8) bool {
    if (value.len == 0) return true;
    for (value) |c| {
        if (c <= ' ' or c == '"' or c == '\\' or c == 0x7f) return true;
    }
    return false;
}

fn writeValue(writer: anytype, value: []const u8) !void {
    if (!needsQuote(value)) return writer.writeAll(value);
    try writer.writeByte('"');
    for (value) |c| switch (c) {
        '"' => try writer.writeAll("\\\""),
        '\\' => try writer.writeAll("\\\\"),
        ' ' => try writer.writeByte(' '),
        0x00...0x1f, 0x7f => try writer.print("\\x{x:0>2}", .{c}),
        else => try writer.writeByte(c),
    };
    try writer.writeByte('"');
}
