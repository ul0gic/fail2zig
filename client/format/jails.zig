// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Renders the configured jails with their state, protection and source health as JSON, plain lines, a table or stacked records.
// Holds: Jail names, sources and health causes pass through renderDiagnostic; state, mode and protection cells are fixed words.

const std = @import("std");
const OutputFormat = @import("shared.zig").OutputFormat;
const Color = @import("shared.zig").Color;
const terminalColumns = @import("shared.zig").terminalColumns;
const writeStatusNarrowRow = @import("shared.zig").writeStatusNarrowRow;
const diagnostic_max_bytes = @import("shared.zig").diagnostic_max_bytes;
const renderDiagnostic = @import("shared.zig").renderDiagnostic;
const repeatChar = @import("shared.zig").repeatChar;
const padRightPrint = @import("shared.zig").padRightPrint;
const formatOptU32Local = @import("shared.zig").formatOptU32Local;
const colWidth = @import("shared.zig").colWidth;
const writeCell = @import("shared.zig").writeCell;
const formatDurationSecs = @import("shared.zig").formatDurationSecs;

pub const JailEntry = struct {
    name: ?[]const u8 = null,
    enabled: ?bool = null,
    paused: ?bool = null,
    active_bans: ?u32 = null,
    maxretry: ?u32 = null,
    findtime: ?u32 = null,
    bantime: ?u32 = null,
    action: ?[]const u8 = null,
    enforce_configured: ?bool = null,
    enforcing: ?bool = null,
    log_source: ?[]const u8 = null,
    source_healthy: ?bool = null,
    lines_seen: ?u64 = null,
    cause: ?[]const u8 = null,
    source_exit_code: ?u8 = null,
    source_signal: ?u32 = null,
    source_stderr_present: ?bool = null,
    source_paused: ?bool = null,
    source_missing: ?bool = null,
};

pub fn formatJails(
    allocator: std.mem.Allocator,
    writer: anytype,
    payload_json: []const u8,
    fmt: OutputFormat,
    color: Color,
) !void {
    try formatJailsWithDetails(allocator, writer, payload_json, fmt, color, false);
}

pub fn formatJailsDetailed(allocator: std.mem.Allocator, writer: anytype, payload_json: []const u8, fmt: OutputFormat, color: Color) !void {
    try formatJailsWithDetails(allocator, writer, payload_json, fmt, color, true);
}

fn formatJailsWithDetails(allocator: std.mem.Allocator, writer: anytype, payload_json: []const u8, fmt: OutputFormat, color: Color, details: bool) !void {
    try formatJailsForWidthDetailed(allocator, writer, payload_json, fmt, color, terminalColumns(), details);
}

fn formatJailsForWidthDetailed(allocator: std.mem.Allocator, writer: anytype, payload_json: []const u8, fmt: OutputFormat, color: Color, columns: usize, details: bool) !void {
    switch (fmt) {
        .json => {
            try writer.writeAll(payload_json);
            if (payload_json.len == 0 or payload_json[payload_json.len - 1] != '\n') {
                try writer.writeAll("\n");
            }
        },
        .plain, .table => {
            const parsed = std.json.parseFromSlice(
                []JailEntry,
                allocator,
                payload_json,
                .{ .ignore_unknown_fields = true, .allocate = .alloc_always },
            ) catch |e| {
                try writer.print("error: could not parse jails payload ({s})\n", .{@errorName(e)});
                return;
            };
            defer parsed.deinit();

            if (fmt == .plain) {
                try writeJailsPlain(writer, parsed.value);
            } else {
                try writeJailsTable(writer, parsed.value, color, columns, details);
            }
        },
    }
}

fn writeJailsPlain(writer: anytype, jails: []const JailEntry) !void {
    for (jails) |j| {
        var name_buffer: [diagnostic_max_bytes]u8 = undefined;
        var action_buffer: [diagnostic_max_bytes]u8 = undefined;
        var source_buffer: [diagnostic_max_bytes]u8 = undefined;
        try writer.print("{s}\t{s}\t{s}\t{d}\t{d}\t{d}\t{s}\t{s}\t{s}\t{s}\t{d}\n", .{
            if (j.name) |name| renderDiagnostic(&name_buffer, name) else "-",
            if (j.enabled orelse false) "enabled" else "disabled",
            formatOptU32Local(j.active_bans),
            j.maxretry orelse 0,
            j.findtime orelse 0,
            j.bantime orelse 0,
            if (j.action) |action| renderDiagnostic(&action_buffer, action) else "-",
            if (j.enforcing) |e| (if (e) "true" else "false") else "-",
            if (j.log_source) |source| renderDiagnostic(&source_buffer, source) else "-",
            sourceHealthStr(j.source_healthy),
            j.lines_seen orelse 0,
        });
    }
}

fn sourceHealthStr(opt: ?bool) []const u8 {
    const h = opt orelse return "unknown";
    return if (h) "healthy" else "unhealthy";
}

fn writeJailsTable(writer: anytype, jails: []const JailEntry, color: Color, columns: usize, details: bool) !void {
    if (jails.len == 0) {
        try writer.writeAll("No jails configured.\n");
        return;
    }
    if (!details) return writeJailsSummary(writer, jails, color, columns);

    var w: JailsWidths = .{};
    for (jails) |j| w.widen(j);
    const name_col = colWidth("JAIL", longestJailNameLen(jails));
    const state_col = colWidth("STATE", w.state);
    const active_col = colWidth("ACTIVE", w.active);
    const max_col = colWidth("MAX RETRY", w.max);
    const find_col = colWidth("FIND TIME", w.find);
    const ban_col = colWidth("BAN TIME", w.ban);
    const action_col = colWidth("ACTION", longestJailText(jails, "action"));
    const mode_col = colWidth("MODE", w.mode);
    const protection_col = colWidth("PROTECTION", w.protection);
    const source_col = colWidth("SOURCE", longestJailText(jails, "log_source"));
    const health_col = @max("HEALTH".len, @min(w.health, diagnostic_max_bytes)) + 1;
    const full_width = name_col + state_col + active_col + max_col + find_col + ban_col + action_col + mode_col + protection_col + source_col + health_col;
    // Why: Too narrow for every column, the detail view stacks rows so max retry, find time and ban time are still shown.
    if (full_width > columns) return writeJailsStacked(writer, jails, color, columns, true);

    try color.on(writer, Color.bold);
    try padRightPrint(writer, "JAIL", name_col);
    try padRightPrint(writer, "STATE", state_col);
    try padRightPrint(writer, "ACTIVE", active_col);
    try padRightPrint(writer, "MAX RETRY", max_col);
    try padRightPrint(writer, "FIND TIME", find_col);
    try padRightPrint(writer, "BAN TIME", ban_col);
    try padRightPrint(writer, "ACTION", action_col);
    try padRightPrint(writer, "MODE", mode_col);
    try padRightPrint(writer, "PROTECTION", protection_col);
    try padRightPrint(writer, "SOURCE", source_col);
    try padRightPrint(writer, "HEALTH", health_col);
    try color.off(writer);
    try writer.writeAll("\n");

    try repeatChar(writer, '-', name_col + state_col + active_col + max_col + find_col + ban_col + action_col + mode_col + protection_col + source_col + health_col);
    try writer.writeAll("\n");

    for (jails) |j| {
        var name_buffer: [diagnostic_max_bytes]u8 = undefined;
        var action_buffer: [diagnostic_max_bytes]u8 = undefined;
        var source_buffer: [diagnostic_max_bytes]u8 = undefined;
        try writeCell(writer, if (j.name) |name| renderDiagnostic(&name_buffer, name) else "-", name_col);
        try color.on(writer, if (j.enabled orelse false) Color.green else Color.yellow);
        try writeCell(writer, stateStr(j), state_col);
        try color.off(writer);
        try writeCell(writer, formatOptU32Local(j.active_bans), active_col);
        try writeCell(writer, formatOptU32Local(j.maxretry), max_col);
        try writeCell(writer, formatDurationSecs(j.findtime), find_col);
        try writeCell(writer, formatDurationSecs(j.bantime), ban_col);
        try writeCell(writer, if (j.action) |action| renderDiagnostic(&action_buffer, action) else "-", action_col);
        try writeCell(writer, modeStr(j), mode_col);
        if (std.mem.eql(u8, protectionStr(j), "active") or std.mem.eql(u8, protectionStr(j), "log-only")) try color.on(writer, Color.green) else try color.on(writer, Color.yellow);
        try writeCell(writer, protectionStr(j), protection_col);
        try color.off(writer);
        try writeCell(writer, if (j.log_source) |source| renderDiagnostic(&source_buffer, source) else "-", source_col);
        if (j.source_healthy) |h| try color.on(writer, if (h and j.source_missing != true) Color.green else Color.yellow);
        var health_buffer: [diagnostic_max_bytes]u8 = undefined;
        try writeCell(writer, formatJailHealth(&health_buffer, j), health_col);
        try color.off(writer);
        try writer.writeAll("\n");
    }

    try writer.print("Total: {d} jails\n", .{jails.len});
}

fn writeJailsSummary(writer: anytype, jails: []const JailEntry, color: Color, columns: usize) !void {
    const name_col = colWidth("JAIL", longestJailNameLen(jails));
    const state_col = colWidth("STATE", 8);
    const source_col = colWidth("SOURCE", longestJailText(jails, "log_source"));
    const health_col = @max("SOURCE HEALTH".len, longestJailHealth(jails)) + 1;
    const mode_col = colWidth("MODE", "log-only".len);
    const protection_col = colWidth("PROTECTION", 11);
    const bans_col = colWidth("BANS", 10);
    const full_width = name_col + state_col + source_col + health_col + mode_col + protection_col + bans_col;
    if (full_width > columns) return writeJailsStacked(writer, jails, color, columns, false);
    try color.on(writer, Color.bold);
    try padRightPrint(writer, "JAIL", name_col);
    try padRightPrint(writer, "STATE", state_col);
    try padRightPrint(writer, "SOURCE", source_col);
    try padRightPrint(writer, "SOURCE HEALTH", health_col);
    try padRightPrint(writer, "MODE", mode_col);
    try padRightPrint(writer, "PROTECTION", protection_col);
    try padRightPrint(writer, "BANS", bans_col);
    try color.off(writer);
    try writer.writeAll("\n");
    try repeatChar(writer, '-', full_width);
    try writer.writeAll("\n");
    for (jails) |j| {
        var name: [diagnostic_max_bytes]u8 = undefined;
        var source: [diagnostic_max_bytes]u8 = undefined;
        var health: [diagnostic_max_bytes]u8 = undefined;
        try writeCell(writer, if (j.name) |value| renderDiagnostic(&name, value) else "-", name_col);
        try color.on(writer, if (j.paused == true or !(j.enabled orelse false)) Color.yellow else Color.green);
        try writeCell(writer, stateStr(j), state_col);
        try color.off(writer);
        try writeCell(writer, if (j.log_source) |value| renderDiagnostic(&source, value) else "-", source_col);
        if (j.source_healthy) |value| try color.on(writer, if (value and j.source_missing != true) Color.green else Color.yellow);
        try writeCell(writer, formatJailHealth(&health, j), health_col);
        try color.off(writer);
        try writeCell(writer, modeStr(j), mode_col);
        try writeCell(writer, protectionStr(j), protection_col);
        try writeCell(writer, formatOptU32Local(j.active_bans), bans_col);
        try writer.writeAll("\n");
    }
    try writer.print("Total: {d} jails\n", .{jails.len});
}

fn longestJailHealth(jails: []const JailEntry) usize {
    var widest: usize = 0;
    for (jails) |jail| {
        var health: [diagnostic_max_bytes]u8 = undefined;
        widest = @max(widest, formatJailHealth(&health, jail).len);
    }
    return widest;
}

fn writeJailsStacked(writer: anytype, jails: []const JailEntry, color: Color, columns: usize, details: bool) !void {
    const value_width = @max(@as(usize, 4), columns -| "HEALTH: ".len);
    for (jails, 0..) |j, index| {
        var name_buffer: [diagnostic_max_bytes]u8 = undefined;
        var action_buffer: [diagnostic_max_bytes]u8 = undefined;
        var health_buffer: [diagnostic_max_bytes]u8 = undefined;
        var source_buffer: [diagnostic_max_bytes]u8 = undefined;
        if (index > 0) try writer.writeAll("\n");
        try writer.writeAll("JAIL:   ");
        try writeCell(writer, if (j.name) |name| renderDiagnostic(&name_buffer, name) else "-", value_width);
        try writer.writeAll("\nSTATE:  ");
        try color.on(writer, if (j.paused == true or !(j.enabled orelse false)) Color.yellow else Color.green);
        try writeCell(writer, stateStr(j), value_width);
        try color.off(writer);
        try writer.writeAll("\nACTIVE: ");
        try writeCell(writer, formatOptU32Local(j.active_bans), value_width);
        try writer.writeAll("\nSOURCE: ");
        try writeCell(writer, if (j.log_source) |source| renderDiagnostic(&source_buffer, source) else "-", value_width);
        try writer.writeAll("\nMODE:   ");
        try writeCell(writer, modeStr(j), @max(@as(usize, 4), columns -| "MODE:   ".len));
        try writer.writeAll("\nPROTECTION: ");
        try writeCell(writer, protectionStr(j), @max(@as(usize, 4), columns -| "PROTECTION: ".len));
        try writer.writeAll("\nACTION: ");
        try writeCell(writer, if (j.action) |action| renderDiagnostic(&action_buffer, action) else "-", value_width);
        try writer.writeAll("\nHEALTH: ");
        try writeCell(writer, formatJailHealth(&health_buffer, j), value_width);
        try writer.writeAll("\n");
        if (details) {
            try writeStatusNarrowRow(writer, "MAX RETRY: ", formatOptU32Local(j.maxretry), columns);
            try writeStatusNarrowRow(writer, "FIND TIME: ", formatDurationSecs(j.findtime), columns);
            try writeStatusNarrowRow(writer, "BAN TIME: ", formatDurationSecs(j.bantime), columns);
        }
    }
    try writer.print("Total: {d} jails\n", .{jails.len});
}

const JailsWidths = struct {
    state: usize = 0,
    active: usize = 0,
    max: usize = 0,
    find: usize = 0,
    ban: usize = 0,
    mode: usize = 0,
    protection: usize = 0,
    health: usize = 0,

    fn widen(self: *JailsWidths, j: JailEntry) void {
        self.state = @max(self.state, stateStr(j).len);
        self.active = @max(self.active, formatOptU32Local(j.active_bans).len);
        self.max = @max(self.max, formatOptU32Local(j.maxretry).len);
        self.find = @max(self.find, formatDurationSecs(j.findtime).len);
        self.ban = @max(self.ban, formatDurationSecs(j.bantime).len);
        self.mode = @max(self.mode, modeStr(j).len);
        self.protection = @max(self.protection, protectionStr(j).len);
        var health_buffer: [diagnostic_max_bytes]u8 = undefined;
        self.health = @max(self.health, formatJailHealth(&health_buffer, j).len);
    }
};

fn stateStr(j: JailEntry) []const u8 {
    if (j.paused == true) return "paused";
    const enabled = j.enabled orelse return "unknown";
    return if (enabled) "enabled" else "disabled";
}

fn modeStr(j: JailEntry) []const u8 {
    const configured = j.enforce_configured orelse return "unknown";
    return if (configured) "enforce" else "log-only";
}

fn protectionStr(j: JailEntry) []const u8 {
    const configured = j.enforce_configured orelse return "unknown";
    if (!configured) return "log-only";
    const active = j.enforcing orelse return "unknown";
    return if (active) "active" else "unconfirmed";
}

fn formatJailHealth(buffer: []u8, jail: JailEntry) []const u8 {
    const healthy = jail.source_healthy orelse return "unknown";
    if (healthy) return if (jail.source_missing == true) "missing (FileNotFound)" else "ok";
    var cause_buffer: [40]u8 = undefined;
    const cause = if (jail.cause) |value|
        if (std.mem.eql(u8, value, "none")) "unknown" else renderDiagnostic(&cause_buffer, value)
    else
        "unknown";
    var stream = std.io.fixedBufferStream(buffer[0..@min(buffer.len, diagnostic_max_bytes)]);
    const writer = stream.writer();
    if (jail.source_paused == true) {
        writer.print("paused ({s})", .{cause}) catch return "paused (unknown)";
        return stream.getWritten();
    }
    if (std.mem.eql(u8, cause, "RetryCapacity") or std.mem.eql(u8, cause, "ReserveBackpressure") or std.mem.eql(u8, cause, "RetryEligibilityPending") or std.mem.eql(u8, cause, "StorageCapacity")) {
        writer.print("waiting ({s})", .{cause}) catch return "waiting (unknown)";
        return stream.getWritten();
    }
    writer.print("broken ({s}", .{cause}) catch return "broken (unknown)";
    if (jail.source_exit_code) |code| writer.print("; exit={d}", .{code}) catch return "broken (unknown)";
    if (jail.source_signal) |signal| writer.print("; signal={d}", .{signal}) catch return "broken (unknown)";
    if (jail.source_stderr_present == true) writer.writeAll("; stderr") catch return "broken (unknown)";
    writer.writeByte(')') catch return "broken (unknown)";
    return stream.getWritten();
}

fn longestJailNameLen(jails: []const JailEntry) usize {
    var widest: usize = 0;
    for (jails) |jail| {
        var buffer: [diagnostic_max_bytes]u8 = undefined;
        widest = @max(widest, if (jail.name) |name| renderDiagnostic(&buffer, name).len else 1);
    }
    return widest;
}

fn longestJailText(jails: []const JailEntry, comptime field: []const u8) usize {
    var widest: usize = 0;
    for (jails) |jail| {
        var buffer: [diagnostic_max_bytes]u8 = undefined;
        widest = @max(widest, if (@field(jail, field)) |value| renderDiagnostic(&buffer, value).len else 1);
    }
    return widest;
}
