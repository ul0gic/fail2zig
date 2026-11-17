// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Renders the daemon's effective configuration as JSON, plain key lines or a global summary and jail table.
// Holds: Configuration strings, jail names and lists print as the daemon sent them; no field in this file passes through renderDiagnostic.

const std = @import("std");
const OutputFormat = @import("shared.zig").OutputFormat;
const Color = @import("shared.zig").Color;
const repeatChar = @import("shared.zig").repeatChar;
const padRightPrint = @import("shared.zig").padRightPrint;
const formatOptU32Local = @import("shared.zig").formatOptU32Local;
const longestLen = @import("shared.zig").longestLen;
const colWidth = @import("shared.zig").colWidth;
const writeCell = @import("shared.zig").writeCell;
const formatDurationSecs = @import("shared.zig").formatDurationSecs;
const formatQuery = @import("shared.zig").formatQuery;
const plainOpt = @import("shared.zig").plainOpt;
const plainBool = @import("shared.zig").plainBool;
const plainInt = @import("shared.zig").plainInt;
const plainList = @import("shared.zig").plainList;
const boolStr = @import("shared.zig").boolStr;

pub const ConfigJail = struct {
    name: ?[]const u8 = null,
    enabled: ?bool = null,
    filter: ?[]const u8 = null,
    source: ?[]const u8 = null,
    logpath: ?[]const []const u8 = null,
    maxretry: ?u32 = null,
    findtime: ?u64 = null,
    bantime: ?u64 = null,
    bantime_permanent: ?bool = null,
    banaction: ?[]const u8 = null,
    ignoreip: ?[]const []const u8 = null,
};

pub const ConfigGlobal = struct {
    log_level: ?[]const u8 = null,
    firewall: ?[]const u8 = null,
    metrics_enabled: ?bool = null,
    metrics_bind: ?[]const u8 = null,
    metrics_port: ?u16 = null,
    socket_path: ?[]const u8 = null,
    state_file: ?[]const u8 = null,
    dns_server: ?[]const u8 = null,
    timezone_root: ?[]const u8 = null,
};

pub const ConfigPayload = struct {
    generation: ?[]const u8 = null,
    redacted: ?bool = null,
    jails: ?[]const ConfigJail = null,
    global: ?ConfigGlobal = null,
};

pub fn formatConfig(allocator: std.mem.Allocator, writer: anytype, payload_json: []const u8, fmt: OutputFormat, color: Color) !void {
    return formatQuery(ConfigPayload, "config", writeConfigPlain, writeConfigTable, allocator, writer, payload_json, fmt, color);
}

fn writeConfigPlain(writer: anytype, c: ConfigPayload) !void {
    try plainOpt(writer, "generation", c.generation);
    try plainBool(writer, "redacted", c.redacted);
    if (c.global) |g| {
        try plainOpt(writer, "global.log_level", g.log_level);
        try plainOpt(writer, "global.firewall", g.firewall);
        try plainBool(writer, "global.metrics_enabled", g.metrics_enabled);
        try plainOpt(writer, "global.metrics_bind", g.metrics_bind);
        try plainInt(writer, "global.metrics_port", g.metrics_port);
        try plainOpt(writer, "global.socket_path", g.socket_path);
        try plainOpt(writer, "global.state_file", g.state_file);
        try plainOpt(writer, "global.dns_server", g.dns_server);
        try plainOpt(writer, "global.timezone_root", g.timezone_root);
    }
    for (c.jails orelse &.{}) |j| {
        const name = j.name orelse "-";
        var key: [96]u8 = undefined;
        try plainBool(writer, try jailKey(&key, name, "enabled"), j.enabled);
        try plainOpt(writer, try jailKey(&key, name, "filter"), j.filter);
        try plainOpt(writer, try jailKey(&key, name, "source"), j.source);
        try plainList(writer, try jailKey(&key, name, "logpath"), j.logpath);
        try plainInt(writer, try jailKey(&key, name, "maxretry"), j.maxretry);
        try plainInt(writer, try jailKey(&key, name, "findtime"), j.findtime);
        try plainInt(writer, try jailKey(&key, name, "bantime"), j.bantime);
        try plainBool(writer, try jailKey(&key, name, "bantime_permanent"), j.bantime_permanent);
        try plainOpt(writer, try jailKey(&key, name, "banaction"), j.banaction);
        try plainList(writer, try jailKey(&key, name, "ignoreip"), j.ignoreip);
    }
}

fn jailKey(buffer: *[96]u8, name: []const u8, field_name: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, "jail.{s}.{s}", .{ name, field_name }) catch error.NameTooLong;
}

fn writeConfigTable(writer: anytype, c: ConfigPayload, color: Color) !void {
    try color.on(writer, Color.bold);
    try writer.writeAll("GLOBAL");
    try color.off(writer);
    try writer.writeAll("\n");
    if (c.redacted orelse false) {
        try color.on(writer, Color.yellow);
        try writer.writeAll("(paths and addresses redacted for monitor access)\n");
        try color.off(writer);
    }
    try writer.print("  generation       {s}\n", .{c.generation orelse "-"});
    if (c.global) |g| {
        try writer.print("  log_level        {s}\n", .{g.log_level orelse "-"});
        try writer.print("  firewall         {s}\n", .{g.firewall orelse "-"});
        try writer.print("  metrics          {s}", .{boolStr(g.metrics_enabled)});
        if (g.metrics_enabled orelse false) try writer.print(" ({s}:{d})", .{ g.metrics_bind orelse "-", g.metrics_port orelse 0 });
        try writer.writeAll("\n");
        try writer.print("  socket_path      {s}\n", .{g.socket_path orelse "-"});
        try writer.print("  state_file       {s}\n", .{g.state_file orelse "-"});
        try writer.print("  dns_server       {s}\n", .{g.dns_server orelse "-"});
        try writer.print("  timezone_root    {s}\n", .{g.timezone_root orelse "-"});
    }
    const jails = c.jails orelse &.{};
    try writer.writeAll("\n");
    try color.on(writer, Color.bold);
    try writer.writeAll("JAILS");
    try color.off(writer);
    try writer.writeAll("\n");
    if (jails.len == 0) {
        try writer.writeAll("No jails configured.\n");
        return;
    }
    const name_col = colWidth("JAIL", longestLen(ConfigJail, jails, "name"));
    const filter_col = colWidth("FILTER", longestLen(ConfigJail, jails, "filter"));
    const source_col = colWidth("SOURCE", longestLen(ConfigJail, jails, "source"));
    const action_col = colWidth("ACTION", longestLen(ConfigJail, jails, "banaction"));
    try color.on(writer, Color.bold);
    try padRightPrint(writer, "JAIL", name_col);
    try padRightPrint(writer, "STATE", 9);
    try padRightPrint(writer, "FILTER", filter_col);
    try padRightPrint(writer, "SOURCE", source_col);
    try padRightPrint(writer, "MAX RETRY", 10);
    try padRightPrint(writer, "FIND TIME", 10);
    try padRightPrint(writer, "BAN TIME", 10);
    try padRightPrint(writer, "ACTION", action_col);
    try color.off(writer);
    try writer.writeAll("\n");
    try repeatChar(writer, '-', name_col + 9 + filter_col + source_col + 30 + action_col);
    try writer.writeAll("\n");
    for (jails) |j| {
        try writeCell(writer, j.name orelse "-", name_col);
        try color.on(writer, if (j.enabled orelse false) Color.green else Color.yellow);
        try padRightPrint(writer, if (j.enabled orelse false) "enabled" else "disabled", 9);
        try color.off(writer);
        try writeCell(writer, j.filter orelse "-", filter_col);
        try writeCell(writer, j.source orelse "-", source_col);
        try padRightPrint(writer, formatOptU32Local(j.maxretry), 10);
        try padRightPrint(writer, formatDurationU64(j.findtime), 10);
        try padRightPrint(writer, if (j.bantime_permanent orelse false) "permanent" else formatDurationU64(j.bantime), 10);
        try writeCell(writer, j.banaction orelse "-", action_col);
        try writer.writeAll("\n");
    }
    try writer.print("Total: {d} jails\n", .{jails.len});
}

fn formatDurationU64(opt: ?u64) []const u8 {
    const v = opt orelse return "-";
    return formatDurationSecs(std.math.cast(u32, v) orelse return ">49d");
}
