// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Renders the active ban list as JSON, plain lines, a column table or stacked records fitted to the terminal width.
// Holds: Ban IP, jail and matched-line text pass through renderDiagnostic or the escaping matched-line writer before reaching the terminal.

const std = @import("std");
const OutputFormat = @import("shared.zig").OutputFormat;
const Color = @import("shared.zig").Color;
const terminalColumns = @import("shared.zig").terminalColumns;
const diagnostic_max_bytes = @import("shared.zig").diagnostic_max_bytes;
const renderDiagnostic = @import("shared.zig").renderDiagnostic;
const repeatChar = @import("shared.zig").repeatChar;
const matchedText = @import("shared.zig").matchedText;
const writeMatchedLine = @import("shared.zig").writeMatchedLine;
const padRightPrint = @import("shared.zig").padRightPrint;
const formatRemaining = @import("shared.zig").formatRemaining;
const formatOptU32Local = @import("shared.zig").formatOptU32Local;
const colWidth = @import("shared.zig").colWidth;
const writeCell = @import("shared.zig").writeCell;

pub const BanEntry = struct {
    ip: ?[]const u8 = null,
    jail: ?[]const u8 = null,
    attempt_count: ?u32 = null,
    last_attempt: ?i64 = null,
    ban_count: ?u32 = null,
    ban_expiry: ?i64 = null,
    permanent: ?bool = null,
    enforced: ?bool = null,
    confirmed: ?bool = null,
    origin: ?[]const u8 = null,
    matches: ?[]const []const u8 = null,
    expired: ?bool = null,
};

pub fn formatList(
    allocator: std.mem.Allocator,
    writer: anytype,
    payload_json: []const u8,
    fmt: OutputFormat,
    color: Color,
) !void {
    try formatListWithDetails(allocator, writer, payload_json, fmt, color, false);
}

pub fn formatListDetailed(allocator: std.mem.Allocator, writer: anytype, payload_json: []const u8, fmt: OutputFormat, color: Color) !void {
    try formatListWithDetails(allocator, writer, payload_json, fmt, color, true);
}

fn formatListWithDetails(allocator: std.mem.Allocator, writer: anytype, payload_json: []const u8, fmt: OutputFormat, color: Color, details: bool) !void {
    try formatListForWidthDetailed(allocator, writer, payload_json, fmt, color, terminalColumns(), details);
}

fn formatListForWidthDetailed(allocator: std.mem.Allocator, writer: anytype, payload_json: []const u8, fmt: OutputFormat, color: Color, columns: usize, details: bool) !void {
    switch (fmt) {
        .json => {
            try writer.writeAll(payload_json);
            if (payload_json.len == 0 or payload_json[payload_json.len - 1] != '\n') {
                try writer.writeAll("\n");
            }
        },
        .plain, .table => {
            const parsed = std.json.parseFromSlice(
                []BanEntry,
                allocator,
                payload_json,
                .{ .ignore_unknown_fields = true, .allocate = .alloc_always },
            ) catch |e| {
                try writer.print("error: could not parse list payload ({s})\n", .{@errorName(e)});
                return;
            };
            defer parsed.deinit();

            const now = std.time.timestamp();
            if (fmt == .plain) {
                try writeListPlain(writer, parsed.value, now, details);
            } else {
                try writeListTable(writer, parsed.value, color, now, columns, details);
            }
        },
    }
}

fn remainingFromExpiry(ban_expiry: ?i64, now: i64) ?i64 {
    const exp = ban_expiry orelse return null;
    return std.math.sub(i64, exp, now) catch if (exp < now) std.math.minInt(i64) else std.math.maxInt(i64);
}

fn writeListPlain(writer: anytype, entries: []const BanEntry, now: i64, details: bool) !void {
    for (entries) |e| {
        var ip_buffer: [diagnostic_max_bytes]u8 = undefined;
        var jail_buffer: [diagnostic_max_bytes]u8 = undefined;
        try writer.print("{s}\t{s}\t{d}\t{d}", .{
            if (e.ip) |ip| renderDiagnostic(&ip_buffer, ip) else "-",
            if (e.jail) |jail| renderDiagnostic(&jail_buffer, jail) else "-",
            remainingFromExpiry(e.ban_expiry, now) orelse 0,
            e.ban_count orelse 0,
        });
        if (details) {
            var matched: [diagnostic_max_bytes]u8 = undefined;
            try writer.print("\t{s}", .{matchedText(&matched, e.matches)});
        }
        try writer.writeAll("\n");
    }
}

fn writeListTable(writer: anytype, entries: []const BanEntry, color: Color, now: i64, columns: usize, details: bool) !void {
    if (entries.len == 0) {
        try writer.writeAll("No active bans.\n");
        return;
    }

    const ip_col = colWidth("IP ADDRESS", longestBanText(entries, "ip"));
    const jail_col = colWidth("JAIL", longestBanText(entries, "jail"));
    const origin_col = colWidth("ORIGIN", longestBanText(entries, "origin"));
    var time_w: usize = 0;
    var count_w: usize = 0;
    var confirmation_w: usize = 0;
    for (entries) |e| {
        time_w = @max(time_w, banExpiryText(e, now).len);
        count_w = @max(count_w, formatOptU32Local(e.ban_count).len);
        confirmation_w = @max(confirmation_w, confirmationText(e).len);
    }
    const time_col = colWidth("TIME LEFT", time_w);
    const count_col = colWidth("BAN COUNT", count_w);
    const confirmation_col = colWidth("CONFIRMATION", confirmation_w);
    const full_width = ip_col + jail_col + origin_col + time_col + confirmation_col + if (details) count_col else 0;
    if (full_width <= columns) return writeListColumns(writer, entries, color, now, ip_col, jail_col, origin_col, time_col, confirmation_col, count_col, details, columns, details);
    // Why: 76 is the sum of the fixed widths passed below (25 + 16 + 10 + 12 + 13).
    if (columns >= 76) return writeListColumns(writer, entries, color, now, 25, 16, 10, 12, 13, 0, false, columns, details);
    try writeListStacked(writer, entries, color, now, columns, details);
}

fn writeListColumns(writer: anytype, entries: []const BanEntry, color: Color, now: i64, ip_col: usize, jail_col: usize, origin_col: usize, time_col: usize, confirmation_col: usize, count_col: usize, include_count: bool, columns: usize, details: bool) !void {
    try color.on(writer, Color.bold);
    try padRightPrint(writer, "IP ADDRESS", ip_col);
    try padRightPrint(writer, "JAIL", jail_col);
    try padRightPrint(writer, "ORIGIN", origin_col);
    try padRightPrint(writer, "TIME LEFT", time_col);
    try padRightPrint(writer, "CONFIRMATION", confirmation_col);
    if (include_count) try padRightPrint(writer, "BAN COUNT", count_col);
    try color.off(writer);
    try writer.writeAll("\n");

    const total_w = ip_col + jail_col + origin_col + time_col + confirmation_col + if (include_count) count_col else 0;
    try repeatChar(writer, '-', total_w);
    try writer.writeAll("\n");

    for (entries) |e| {
        var ip_buffer: [diagnostic_max_bytes]u8 = undefined;
        var jail_buffer: [diagnostic_max_bytes]u8 = undefined;
        try color.on(writer, Color.cyan);
        try writeCell(writer, if (e.ip) |ip| renderDiagnostic(&ip_buffer, ip) else "-", ip_col);
        try color.off(writer);
        try writeCell(writer, if (e.jail) |jail| renderDiagnostic(&jail_buffer, jail) else "-", jail_col);
        var origin_buffer: [diagnostic_max_bytes]u8 = undefined;
        try writeCell(writer, if (e.origin) |origin| renderDiagnostic(&origin_buffer, origin) else "-", origin_col);
        try writeCell(writer, banExpiryText(e, now), time_col);
        const confirmation = confirmationText(e);
        if (std.mem.eql(u8, confirmation, "confirmed")) try color.on(writer, Color.green);
        if (std.mem.eql(u8, confirmation, "pending")) try color.on(writer, Color.yellow);
        try writeCell(writer, confirmation, confirmation_col);
        try color.off(writer);
        if (include_count) try writeCell(writer, formatOptU32Local(e.ban_count), count_col);
        try writer.writeAll("\n");
        if (details) try writeMatchedLine(writer, e.matches, columns);
    }

    try writer.print("Total: {d} active bans\n", .{entries.len});
}

fn writeListStacked(writer: anytype, entries: []const BanEntry, color: Color, now: i64, columns: usize, details: bool) !void {
    const value_width = @max(@as(usize, 4), columns -| "CONFIRMATION: ".len);
    for (entries, 0..) |e, index| {
        var ip_buffer: [diagnostic_max_bytes]u8 = undefined;
        var jail_buffer: [diagnostic_max_bytes]u8 = undefined;
        if (index > 0) try writer.writeAll("\n");
        try writer.writeAll("IP ADDRESS: ");
        try color.on(writer, Color.cyan);
        try writeCell(writer, if (e.ip) |ip| renderDiagnostic(&ip_buffer, ip) else "-", value_width);
        try color.off(writer);
        try writer.writeAll("\nJAIL:       ");
        try writeCell(writer, if (e.jail) |jail| renderDiagnostic(&jail_buffer, jail) else "-", value_width);
        var origin_buffer: [diagnostic_max_bytes]u8 = undefined;
        try writer.writeAll("\nORIGIN:     ");
        try writeCell(writer, if (e.origin) |origin| renderDiagnostic(&origin_buffer, origin) else "-", value_width);
        try writer.writeAll("\nTIME LEFT:  ");
        try writeCell(writer, banExpiryText(e, now), value_width);
        try writer.writeAll("\nCONFIRMATION: ");
        try writeCell(writer, confirmationText(e), value_width);
        try writer.writeAll("\n");
        if (details) try writeMatchedLine(writer, e.matches, columns);
    }
    try writer.print("Total: {d} active bans\n", .{entries.len});
}

fn banExpiryText(entry: BanEntry, now: i64) []const u8 {
    if (entry.expired == true) return "expired";
    if (entry.permanent == true) return "permanent";
    if (entry.ban_expiry != null) return formatRemaining(remainingFromExpiry(entry.ban_expiry, now));
    return "unknown";
}

fn confirmationText(entry: BanEntry) []const u8 {
    const confirmed = entry.confirmed orelse entry.enforced orelse return "unknown";
    if (entry.confirmed) |value| if (entry.enforced) |enforced| if (value != enforced) return "unknown";
    return if (confirmed) "confirmed" else "pending";
}

fn longestBanText(entries: []const BanEntry, comptime field: []const u8) usize {
    var widest: usize = 0;
    for (entries) |entry| {
        var buffer: [diagnostic_max_bytes]u8 = undefined;
        widest = @max(widest, if (@field(entry, field)) |value| renderDiagnostic(&buffer, value).len else 1);
    }
    return widest;
}
