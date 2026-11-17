// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Renders an error code and message as JSON, a plain line or a coloured table line, and the unknown-jail error.
// Holds: formatUnknownJail escapes the jail name with renderDiagnostic; formatError prints the message it is given unescaped.

const std = @import("std");
const OutputFormat = @import("shared.zig").OutputFormat;
const Color = @import("shared.zig").Color;
const diagnostic_max_bytes = @import("shared.zig").diagnostic_max_bytes;
const renderDiagnostic = @import("shared.zig").renderDiagnostic;

pub fn formatError(
    writer: anytype,
    code: u16,
    message: []const u8,
    fmt: OutputFormat,
    color: Color,
) !void {
    switch (fmt) {
        .json => try writer.print("{{\"error\":{{\"code\":{d},\"message\":\"{s}\"}}}}\n", .{ code, message }),
        .plain => try writer.print("error\t{d}\t{s}\n", .{ code, message }),
        .table => {
            try color.on(writer, Color.red);
            try writer.writeAll("error: ");
            try color.off(writer);
            try writer.print("{s} (code {d})\n", .{ message, code });
        },
    }
}

pub fn formatUnknownJail(
    writer: anytype,
    jail: []const u8,
    fmt: OutputFormat,
    color: Color,
) !void {
    var name_buffer: [diagnostic_max_bytes]u8 = undefined;
    var message_buffer: [diagnostic_max_bytes + 32]u8 = undefined;
    const message = try std.fmt.bufPrint(&message_buffer, "jail '{s}' is not configured", .{renderDiagnostic(&name_buffer, jail)});
    if (fmt != .json) return formatError(writer, 404, message, fmt, color);
    try writer.writeAll("{\"error\":{\"code\":404,\"message\":");
    try std.json.encodeJsonString(message, .{}, writer);
    try writer.writeAll("}}\n");
}
