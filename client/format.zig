// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Output formatters for fail2zig-client responses.
//!
//! Three modes, selected by `OutputFormat`:
//!   - table:  Human-readable. Box-drawing characters for the status view,
//!             fixed-width columns for lists. ANSI color when stdout is a TTY
//!             and the user hasn't passed --no-color.
//!   - json:   Pretty-printed JSON. One root object per response. Scriptable.
//!   - plain:  Tab-separated values, one record per line, no headers. Easy
//!             to pipe into awk/cut/wc.
//!
//! The daemon returns a JSON payload inside `Response.ok.payload`. This
//! module defines tolerant schemas for each response shape: every field is
//! optional with a sensible default, so changes to the daemon's JSON (adding
//! new fields, renaming obscure ones) don't break the client — they just
//! show `-` in the table or are omitted from plain output.

const std = @import("std");
const shared = @import("shared");
const args = @import("args.zig");

pub const OutputFormat = args.OutputFormat;

// ============================================================================
// ANSI color helpers
// ============================================================================

pub const Color = struct {
    enabled: bool,

    const reset = "\x1b[0m";
    const bold = "\x1b[1m";
    const dim = "\x1b[2m";
    const red = "\x1b[31m";
    const green = "\x1b[32m";
    const yellow = "\x1b[33m";
    const cyan = "\x1b[36m";
    const gray = "\x1b[90m";

    pub fn wrap(self: Color, writer: anytype, code: []const u8, text: []const u8) !void {
        if (self.enabled) try writer.writeAll(code);
        try writer.writeAll(text);
        if (self.enabled) try writer.writeAll(reset);
    }

    pub fn on(self: Color, writer: anytype, code: []const u8) !void {
        if (self.enabled) try writer.writeAll(code);
    }

    pub fn off(self: Color, writer: anytype) !void {
        if (self.enabled) try writer.writeAll(reset);
    }
};

/// Decide whether color should be emitted. `--no-color` wins. Otherwise color
/// only if stdout is a TTY.
pub fn shouldColor(allow_color: bool) bool {
    if (!allow_color) return false;
    const fd = std.io.getStdOut().handle;
    return std.posix.isatty(fd);
}

// ============================================================================
// Response schemas
// ============================================================================

/// Daemon status response. Fields optional — client tolerates missing data.
pub const StatusPayload = struct {
    version: ?[]const u8 = null,
    uptime_seconds: ?u64 = null,
    memory_bytes_used: ?u64 = null,
    memory_bytes_limit: ?u64 = null,
    active_bans: ?u32 = null,
    total_bans_24h: ?u64 = null,
    parse_rate: ?f64 = null, // lines/sec
    backend: ?[]const u8 = null,
    jails_active: ?u32 = null,
};

/// Matches the JSON emitted by `engine/net/commands.zig::writeListEntry`.
/// `ban_expiry` is an absolute unix timestamp in seconds; the "time left"
/// column is computed locally from `ban_expiry - now`.
pub const BanEntry = struct {
    ip: ?[]const u8 = null,
    jail: ?[]const u8 = null,
    attempt_count: ?u32 = null,
    last_attempt: ?i64 = null,
    ban_count: ?u32 = null,
    ban_expiry: ?i64 = null,
};

/// Matches the JSON emitted by `engine/net/commands.zig::handleListJails`.
/// Shows the effective `maxretry / findtime / bantime` the daemon resolved
/// for each jail from its config + inherited defaults.
pub const JailEntry = struct {
    name: ?[]const u8 = null,
    enabled: ?bool = null,
    active_bans: ?u32 = null,
    maxretry: ?u32 = null,
    findtime: ?u32 = null,
    bantime: ?u32 = null,
};

pub const VersionPayload = struct {
    daemon_version: ?[]const u8 = null,
    git_commit: ?[]const u8 = null,
    build_date: ?[]const u8 = null,
};

pub const BanActionPayload = struct {
    ip: ?[]const u8 = null,
    jail: ?[]const u8 = null,
    duration_seconds: ?u64 = null,
    result: ?[]const u8 = null, // e.g. "banned", "already_banned"
};

pub const UnbanActionPayload = struct {
    ip: ?[]const u8 = null,
    jail: ?[]const u8 = null,
    result: ?[]const u8 = null, // e.g. "unbanned", "not_found"
};

pub const ReloadPayload = struct {
    result: ?[]const u8 = null, // e.g. "reloaded"
    jails_loaded: ?u32 = null,
    warnings: ?[]const []const u8 = null,
};

// ============================================================================
// Status
// ============================================================================

pub fn formatStatus(
    allocator: std.mem.Allocator,
    writer: anytype,
    payload_json: []const u8,
    fmt: OutputFormat,
    color: Color,
) !void {
    switch (fmt) {
        .json => {
            try writer.writeAll(payload_json);
            if (payload_json.len == 0 or payload_json[payload_json.len - 1] != '\n') {
                try writer.writeAll("\n");
            }
        },
        .plain, .table => {
            const parsed = std.json.parseFromSlice(
                StatusPayload,
                allocator,
                payload_json,
                .{ .ignore_unknown_fields = true, .allocate = .alloc_always },
            ) catch |e| {
                try writer.print("error: could not parse status payload ({s})\n", .{@errorName(e)});
                return;
            };
            defer parsed.deinit();

            if (fmt == .plain) {
                try writeStatusPlain(writer, parsed.value);
            } else {
                try writeStatusTable(writer, parsed.value, color);
            }
        },
    }
}

fn writeStatusPlain(writer: anytype, s: StatusPayload) !void {
    if (s.version) |v| try writer.print("version\t{s}\n", .{v});
    if (s.uptime_seconds) |u| try writer.print("uptime_seconds\t{d}\n", .{u});
    if (s.memory_bytes_used) |m| try writer.print("memory_bytes_used\t{d}\n", .{m});
    if (s.memory_bytes_limit) |m| try writer.print("memory_bytes_limit\t{d}\n", .{m});
    if (s.active_bans) |a| try writer.print("active_bans\t{d}\n", .{a});
    if (s.total_bans_24h) |a| try writer.print("total_bans_24h\t{d}\n", .{a});
    if (s.parse_rate) |p| try writer.print("parse_rate\t{d:.2}\n", .{p});
    if (s.backend) |b| try writer.print("backend\t{s}\n", .{b});
    if (s.jails_active) |j| try writer.print("jails_active\t{d}\n", .{j});
}

fn writeStatusTable(writer: anytype, s: StatusPayload, color: Color) !void {
    const width: usize = 44;
    try drawTopLine(writer, width);
    // Header
    try writer.writeAll("| ");
    try color.on(writer, Color.bold);
    try writer.print("fail2zig", .{});
    if (s.version) |v| try writer.print(" {s}", .{v});
    try color.off(writer);
    try color.on(writer, Color.green);
    try writer.writeAll(" — running");
    try color.off(writer);
    try padTo(writer, 11 + versionLen(s.version) + 10, width - 2);
    try writer.writeAll(" |\n");
    try drawMidLine(writer, width);

    try rowLabel(writer, "Uptime:", formatUptime(s.uptime_seconds), width);
    try rowLabel(writer, "Memory:", formatMemory(s.memory_bytes_used, s.memory_bytes_limit), width);
    try rowLabel(writer, "Parse rate:", formatRate(s.parse_rate), width);
    try rowLabel(writer, "Active bans:", formatOptU32(s.active_bans), width);
    try rowLabel(writer, "Total bans:", formatOptU64Suffix(s.total_bans_24h, " (24h)"), width);
    try rowLabel(writer, "Backend:", s.backend orelse "-", width);
    try rowLabel(writer, "Jails:", formatOptU32(s.jails_active), width);

    try drawBotLine(writer, width);
}

fn versionLen(v: ?[]const u8) usize {
    if (v) |s| return s.len + 1; // leading space
    return 0;
}

fn rowLabel(writer: anytype, label: []const u8, value: []const u8, width: usize) !void {
    try writer.writeAll("| ");
    try writer.writeAll(label);
    // Target: label in 13-char column, then value.
    const label_col = 13;
    if (label.len < label_col) {
        try writeSpaces(writer, label_col - label.len);
    }
    try writer.writeAll(value);
    const used = 1 + 1 + @max(label.len, label_col) + value.len;
    if (used < width - 1) {
        try writeSpaces(writer, width - 1 - used);
    }
    try writer.writeAll("|\n");
}

fn drawTopLine(writer: anytype, width: usize) !void {
    try writer.writeAll("+");
    try repeatChar(writer, '-', width - 2);
    try writer.writeAll("+\n");
}

fn drawMidLine(writer: anytype, width: usize) !void {
    try writer.writeAll("+");
    try repeatChar(writer, '-', width - 2);
    try writer.writeAll("+\n");
}

fn drawBotLine(writer: anytype, width: usize) !void {
    try writer.writeAll("+");
    try repeatChar(writer, '-', width - 2);
    try writer.writeAll("+\n");
}

fn repeatChar(writer: anytype, ch: u8, n: usize) !void {
    var i: usize = 0;
    while (i < n) : (i += 1) try writer.writeByte(ch);
}

fn writeSpaces(writer: anytype, n: usize) !void {
    try repeatChar(writer, ' ', n);
}

fn padTo(writer: anytype, used: usize, target: usize) !void {
    if (used < target) try writeSpaces(writer, target - used);
}

// ============================================================================
// Human-readable formatters for status fields (use small stack buffers)
// ============================================================================

threadlocal var scratch: [64]u8 = undefined;

fn formatUptime(opt: ?u64) []const u8 {
    const secs = opt orelse return "-";
    const days = secs / 86_400;
    const hours = (secs % 86_400) / 3600;
    const mins = (secs % 3600) / 60;
    const s = secs % 60;
    const r = std.fmt.bufPrint(&scratch, "{d}d {d}h {d}m {d}s", .{ days, hours, mins, s }) catch return "-";
    return r;
}

fn formatMemory(used_opt: ?u64, limit_opt: ?u64) []const u8 {
    const used = used_opt orelse return "-";
    if (limit_opt) |limit| {
        if (limit == 0) return "-";
        const pct = (used * 100) / limit;
        const r = std.fmt.bufPrint(&scratch, "{d:.1} / {d:.1} MB ({d}%)", .{
            mb(used), mb(limit), pct,
        }) catch return "-";
        return r;
    }
    const r = std.fmt.bufPrint(&scratch, "{d:.1} MB", .{mb(used)}) catch return "-";
    return r;
}

fn mb(bytes: u64) f64 {
    return @as(f64, @floatFromInt(bytes)) / (1024.0 * 1024.0);
}

fn formatRate(opt: ?f64) []const u8 {
    const r = opt orelse return "-";
    const out = std.fmt.bufPrint(&scratch, "{d:.0} lines/sec", .{r}) catch return "-";
    return out;
}

fn formatOptU32(opt: ?u32) []const u8 {
    const v = opt orelse return "-";
    const out = std.fmt.bufPrint(&scratch, "{d}", .{v}) catch return "-";
    return out;
}

fn formatOptU64Suffix(opt: ?u64, suffix: []const u8) []const u8 {
    const v = opt orelse return "-";
    const out = std.fmt.bufPrint(&scratch, "{d}{s}", .{ v, suffix }) catch return "-";
    return out;
}

// ============================================================================
// List (active bans)
// ============================================================================

pub fn formatList(
    allocator: std.mem.Allocator,
    writer: anytype,
    payload_json: []const u8,
    fmt: OutputFormat,
    color: Color,
) !void {
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
                try writeListPlain(writer, parsed.value, now);
            } else {
                try writeListTable(writer, parsed.value, color, now);
            }
        },
    }
}

fn remainingFromExpiry(ban_expiry: ?i64, now: i64) ?i64 {
    const exp = ban_expiry orelse return null;
    return exp - now;
}

fn writeListPlain(writer: anytype, entries: []const BanEntry, now: i64) !void {
    for (entries) |e| {
        try writer.print("{s}\t{s}\t{d}\t{d}\n", .{
            e.ip orelse "-",
            e.jail orelse "-",
            remainingFromExpiry(e.ban_expiry, now) orelse 0,
            e.ban_count orelse 0,
        });
    }
}

fn writeListTable(writer: anytype, entries: []const BanEntry, color: Color, now: i64) !void {
    if (entries.len == 0) {
        try writer.writeAll("No active bans.\n");
        return;
    }

    const ip_col: usize = 18;
    // Jail names can be hyphenated (e.g. `nginx-http-auth`, 15 chars).
    // Width chosen to fit the longest built-in filter name with a
    // single trailing space so it doesn't bleed into TIME LEFT.
    const jail_col: usize = 18;
    const time_col: usize = 12;
    const count_col: usize = 10;

    try color.on(writer, Color.bold);
    try padRightPrint(writer, "IP ADDRESS", ip_col);
    try padRightPrint(writer, "JAIL", jail_col);
    try padRightPrint(writer, "TIME LEFT", time_col);
    try padRightPrint(writer, "BAN COUNT", count_col);
    try color.off(writer);
    try writer.writeAll("\n");

    const total_w = ip_col + jail_col + time_col + count_col;
    try repeatChar(writer, '-', total_w);
    try writer.writeAll("\n");

    for (entries) |e| {
        try color.on(writer, Color.cyan);
        try padRightPrint(writer, e.ip orelse "-", ip_col);
        try color.off(writer);
        try padRightPrint(writer, e.jail orelse "-", jail_col);
        try padRightPrint(writer, formatRemaining(remainingFromExpiry(e.ban_expiry, now)), time_col);
        try padRightPrint(writer, formatOptU32Local(e.ban_count), count_col);
        try writer.writeAll("\n");
    }

    try writer.print("Total: {d} active bans\n", .{entries.len});
}

fn padRightPrint(writer: anytype, s: []const u8, width: usize) !void {
    try writer.writeAll(s);
    if (s.len < width) try writeSpaces(writer, width - s.len);
}

fn formatRemaining(opt: ?i64) []const u8 {
    const secs = opt orelse return "-";
    if (secs < 0) return "expired";
    const mins = @divTrunc(secs, 60);
    const s = @mod(secs, 60);
    const out = std.fmt.bufPrint(&scratch, "{d}m {d:0>2}s", .{ mins, s }) catch return "-";
    return out;
}

fn formatOptU32Local(opt: ?u32) []const u8 {
    const v = opt orelse return "-";
    const out = std.fmt.bufPrint(&scratch, "{d}", .{v}) catch return "-";
    return out;
}

// ============================================================================
// Jails
// ============================================================================

pub fn formatJails(
    allocator: std.mem.Allocator,
    writer: anytype,
    payload_json: []const u8,
    fmt: OutputFormat,
    color: Color,
) !void {
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
                try writeJailsTable(writer, parsed.value, color);
            }
        },
    }
}

fn writeJailsPlain(writer: anytype, jails: []const JailEntry) !void {
    for (jails) |j| {
        try writer.print("{s}\t{s}\t{d}\t{d}\t{d}\t{d}\n", .{
            j.name orelse "-",
            if (j.enabled orelse false) "enabled" else "disabled",
            j.active_bans orelse 0,
            j.maxretry orelse 0,
            j.findtime orelse 0,
            j.bantime orelse 0,
        });
    }
}

fn writeJailsTable(writer: anytype, jails: []const JailEntry, color: Color) !void {
    if (jails.len == 0) {
        try writer.writeAll("No jails configured.\n");
        return;
    }

    const name_col: usize = 20;
    const state_col: usize = 10;
    const active_col: usize = 10;
    const max_col: usize = 10;
    const find_col: usize = 12;
    const ban_col: usize = 12;

    try color.on(writer, Color.bold);
    try padRightPrint(writer, "JAIL", name_col);
    try padRightPrint(writer, "STATE", state_col);
    try padRightPrint(writer, "ACTIVE", active_col);
    try padRightPrint(writer, "MAX RETRY", max_col);
    try padRightPrint(writer, "FIND TIME", find_col);
    try padRightPrint(writer, "BAN TIME", ban_col);
    try color.off(writer);
    try writer.writeAll("\n");

    try repeatChar(writer, '-', name_col + state_col + active_col + max_col + find_col + ban_col);
    try writer.writeAll("\n");

    for (jails) |j| {
        try padRightPrint(writer, j.name orelse "-", name_col);
        const state_str: []const u8 = if (j.enabled orelse false) "enabled" else "disabled";
        if (j.enabled orelse false) {
            try color.on(writer, Color.green);
        } else {
            try color.on(writer, Color.yellow);
        }
        try padRightPrint(writer, state_str, state_col);
        try color.off(writer);
        try padRightPrint(writer, formatOptU32Local(j.active_bans), active_col);
        try padRightPrint(writer, formatOptU32Local(j.maxretry), max_col);
        try padRightPrint(writer, formatDurationSecs(j.findtime), find_col);
        try padRightPrint(writer, formatDurationSecs(j.bantime), ban_col);
        try writer.writeAll("\n");
    }

    try writer.print("Total: {d} jails\n", .{jails.len});
}

fn formatDurationSecs(opt: ?u32) []const u8 {
    const secs = opt orelse return "-";
    if (secs >= 86400) {
        const out = std.fmt.bufPrint(&scratch, "{d}d", .{secs / 86400}) catch return "-";
        return out;
    }
    if (secs >= 3600) {
        const out = std.fmt.bufPrint(&scratch, "{d}h", .{secs / 3600}) catch return "-";
        return out;
    }
    if (secs >= 60) {
        const out = std.fmt.bufPrint(&scratch, "{d}m", .{secs / 60}) catch return "-";
        return out;
    }
    const out = std.fmt.bufPrint(&scratch, "{d}s", .{secs}) catch return "-";
    return out;
}

// ============================================================================
// Version
// ============================================================================

pub fn formatVersion(
    allocator: std.mem.Allocator,
    writer: anytype,
    client_version: []const u8,
    payload_json: []const u8,
    fmt: OutputFormat,
    color: Color,
) !void {
    _ = color;
    switch (fmt) {
        .json => {
            // Wrap daemon payload + client version in a single JSON object.
            try writer.print(
                \\{{"client_version":"{s}","daemon":
            , .{client_version});
            if (payload_json.len == 0) {
                try writer.writeAll("null");
            } else {
                try writer.writeAll(payload_json);
            }
            try writer.writeAll("}\n");
        },
        .plain => {
            try writer.print("client\t{s}\n", .{client_version});
            if (payload_json.len > 0) {
                const parsed = std.json.parseFromSlice(
                    VersionPayload,
                    allocator,
                    payload_json,
                    .{ .ignore_unknown_fields = true, .allocate = .alloc_always },
                ) catch return;
                defer parsed.deinit();
                if (parsed.value.daemon_version) |v| try writer.print("daemon\t{s}\n", .{v});
                if (parsed.value.git_commit) |c| try writer.print("git\t{s}\n", .{c});
                if (parsed.value.build_date) |d| try writer.print("built\t{s}\n", .{d});
            }
        },
        .table => {
            try writer.print("fail2zig-client {s}\n", .{client_version});
            if (payload_json.len > 0) {
                const parsed = std.json.parseFromSlice(
                    VersionPayload,
                    allocator,
                    payload_json,
                    .{ .ignore_unknown_fields = true, .allocate = .alloc_always },
                ) catch return;
                defer parsed.deinit();
                if (parsed.value.daemon_version) |v| try writer.print("fail2zig       {s}\n", .{v});
                if (parsed.value.git_commit) |c| try writer.print("  commit:      {s}\n", .{c});
                if (parsed.value.build_date) |d| try writer.print("  built:       {s}\n", .{d});
            } else {
                try writer.writeAll("fail2zig       (daemon unreachable)\n");
            }
        },
    }
}

// ============================================================================
// Ban / Unban / Reload — simple action responses
// ============================================================================

pub fn formatBan(
    allocator: std.mem.Allocator,
    writer: anytype,
    payload_json: []const u8,
    fmt: OutputFormat,
    color: Color,
) !void {
    try formatSimpleAction(
        BanActionPayload,
        allocator,
        writer,
        payload_json,
        fmt,
        color,
        "Banned",
    );
}

pub fn formatUnban(
    allocator: std.mem.Allocator,
    writer: anytype,
    payload_json: []const u8,
    fmt: OutputFormat,
    color: Color,
) !void {
    try formatSimpleAction(
        UnbanActionPayload,
        allocator,
        writer,
        payload_json,
        fmt,
        color,
        "Unbanned",
    );
}

fn formatSimpleAction(
    comptime T: type,
    allocator: std.mem.Allocator,
    writer: anytype,
    payload_json: []const u8,
    fmt: OutputFormat,
    color: Color,
    verb: []const u8,
) !void {
    switch (fmt) {
        .json => {
            try writer.writeAll(payload_json);
            if (payload_json.len == 0 or payload_json[payload_json.len - 1] != '\n') {
                try writer.writeAll("\n");
            }
        },
        .plain => {
            const parsed = std.json.parseFromSlice(
                T,
                allocator,
                payload_json,
                .{ .ignore_unknown_fields = true, .allocate = .alloc_always },
            ) catch return;
            defer parsed.deinit();
            if (parsed.value.ip) |ip| try writer.print("ip\t{s}\n", .{ip});
            if (parsed.value.jail) |j| try writer.print("jail\t{s}\n", .{j});
            if (parsed.value.result) |r| try writer.print("result\t{s}\n", .{r});
        },
        .table => {
            const parsed = std.json.parseFromSlice(
                T,
                allocator,
                payload_json,
                .{ .ignore_unknown_fields = true, .allocate = .alloc_always },
            ) catch {
                try writer.print("{s} request accepted.\n", .{verb});
                return;
            };
            defer parsed.deinit();
            try color.on(writer, Color.green);
            try writer.writeAll(verb);
            try color.off(writer);
            if (parsed.value.ip) |ip| try writer.print(" {s}", .{ip});
            if (parsed.value.jail) |j| try writer.print(" (jail: {s})", .{j});
            if (parsed.value.result) |r| {
                if (!std.mem.eql(u8, r, "banned") and !std.mem.eql(u8, r, "unbanned")) {
                    try writer.print(" [{s}]", .{r});
                }
            }
            try writer.writeAll("\n");
        },
    }
}

pub fn formatReload(
    allocator: std.mem.Allocator,
    writer: anytype,
    payload_json: []const u8,
    fmt: OutputFormat,
    color: Color,
) !void {
    switch (fmt) {
        .json => {
            try writer.writeAll(payload_json);
            if (payload_json.len == 0 or payload_json[payload_json.len - 1] != '\n') {
                try writer.writeAll("\n");
            }
        },
        .plain => {
            const parsed = std.json.parseFromSlice(
                ReloadPayload,
                allocator,
                payload_json,
                .{ .ignore_unknown_fields = true, .allocate = .alloc_always },
            ) catch return;
            defer parsed.deinit();
            if (parsed.value.result) |r| try writer.print("result\t{s}\n", .{r});
            if (parsed.value.jails_loaded) |j| try writer.print("jails_loaded\t{d}\n", .{j});
        },
        .table => {
            const parsed = std.json.parseFromSlice(
                ReloadPayload,
                allocator,
                payload_json,
                .{ .ignore_unknown_fields = true, .allocate = .alloc_always },
            ) catch {
                try writer.writeAll("Reload requested.\n");
                return;
            };
            defer parsed.deinit();
            try color.on(writer, Color.green);
            try writer.writeAll("Reloaded");
            try color.off(writer);
            if (parsed.value.jails_loaded) |j| {
                try writer.print(" ({d} jails loaded)", .{j});
            }
            try writer.writeAll(".\n");
            if (parsed.value.warnings) |ws| {
                for (ws) |w| {
                    try color.on(writer, Color.yellow);
                    try writer.writeAll("warning: ");
                    try color.off(writer);
                    try writer.print("{s}\n", .{w});
                }
            }
        },
    }
}

// ============================================================================
// Error formatter — used for Response.err across all modes
// ============================================================================

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

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

fn runStatus(alloc: std.mem.Allocator, payload: []const u8, fmt: OutputFormat) ![]u8 {
    var list = std.ArrayList(u8).init(alloc);
    errdefer list.deinit();
    try formatStatus(alloc, list.writer(), payload, fmt, .{ .enabled = false });
    return list.toOwnedSlice();
}

test "format: status table shows box lines and version" {
    const payload =
        \\{"version":"0.1.0","uptime_seconds":86461,"memory_bytes_used":8388608,
        \\"memory_bytes_limit":67108864,"active_bans":142,"parse_rate":12847.0,
        \\"backend":"nftables","jails_active":8,"total_bans_24h":3891}
    ;
    const out = try runStatus(testing.allocator, payload, .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "+---") != null);
    try testing.expect(std.mem.indexOf(u8, out, "fail2zig 0.1.0") != null);
    try testing.expect(std.mem.indexOf(u8, out, "1d 0h 1m 1s") != null);
    try testing.expect(std.mem.indexOf(u8, out, "nftables") != null);
    try testing.expect(std.mem.indexOf(u8, out, "142") != null);
    try testing.expect(std.mem.indexOf(u8, out, "3891 (24h)") != null);
}

test "format: status json passes through" {
    const payload = "{\"version\":\"0.1.0\"}";
    const out = try runStatus(testing.allocator, payload, .json);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.startsWith(u8, out, "{"));
    try testing.expect(std.mem.indexOf(u8, out, "0.1.0") != null);
}

test "format: status plain is tab-separated" {
    const payload = "{\"version\":\"0.1.0\",\"active_bans\":3}";
    const out = try runStatus(testing.allocator, payload, .plain);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "version\t0.1.0") != null);
    try testing.expect(std.mem.indexOf(u8, out, "active_bans\t3") != null);
}

test "format: status tolerates missing fields" {
    const payload = "{}";
    const out = try runStatus(testing.allocator, payload, .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "+---") != null);
    try testing.expect(std.mem.indexOf(u8, out, "-") != null);
}

test "format: status plain missing fields produces nothing" {
    const payload = "{}";
    const out = try runStatus(testing.allocator, payload, .plain);
    defer testing.allocator.free(out);
    try testing.expectEqual(@as(usize, 0), out.len);
}

test "format: status bad json surfaces error" {
    const out = try runStatus(testing.allocator, "not json", .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "error") != null);
}

fn runList(alloc: std.mem.Allocator, payload: []const u8, fmt: OutputFormat) ![]u8 {
    var list = std.ArrayList(u8).init(alloc);
    errdefer list.deinit();
    try formatList(alloc, list.writer(), payload, fmt, .{ .enabled = false });
    return list.toOwnedSlice();
}

test "format: list table with entries (daemon-shape JSON, SYS-002)" {
    // Matches engine/net/commands.zig::writeListEntry output exactly.
    // ban_expiry is an absolute unix timestamp; table must compute "time left"
    // from it using std.time.timestamp(). We can't pin the result without
    // mocking the clock, but we can assert on the IPs, column headers and
    // total count -- same shape real daemons produce.
    const payload =
        \\[
        \\  {"ip":"45.227.253.98","jail":"sshd","attempt_count":5,"last_attempt":0,"ban_count":3,"ban_expiry":9999999999},
        \\  {"ip":"103.144.82.210","jail":"sshd","attempt_count":4,"last_attempt":0,"ban_count":1,"ban_expiry":9999999999}
        \\]
    ;
    const out = try runList(testing.allocator, payload, .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "IP ADDRESS") != null);
    try testing.expect(std.mem.indexOf(u8, out, "JAIL") != null);
    try testing.expect(std.mem.indexOf(u8, out, "TIME LEFT") != null);
    try testing.expect(std.mem.indexOf(u8, out, "BAN COUNT") != null);
    try testing.expect(std.mem.indexOf(u8, out, "45.227.253.98") != null);
    try testing.expect(std.mem.indexOf(u8, out, "103.144.82.210") != null);
    try testing.expect(std.mem.indexOf(u8, out, "sshd") != null);
    try testing.expect(std.mem.indexOf(u8, out, "Total: 2 active bans") != null);
    // Country column has been removed (GeoIP is a Phase 2 feature).
    try testing.expect(std.mem.indexOf(u8, out, "COUNTRY") == null);
}

test "format: list table empty (SYS-002)" {
    const payload = "[]";
    const out = try runList(testing.allocator, payload, .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "No active bans") != null);
}

test "format: list plain tab-separated (SYS-002)" {
    const payload = "[{\"ip\":\"1.2.3.4\",\"jail\":\"sshd\",\"attempt_count\":3,\"last_attempt\":0,\"ban_count\":2,\"ban_expiry\":9999999999}]";
    const out = try runList(testing.allocator, payload, .plain);
    defer testing.allocator.free(out);
    // Four tab-separated columns: ip, jail, remaining_seconds, ban_count.
    // remaining is clock-dependent so we assert only on the stable prefix.
    try testing.expect(std.mem.startsWith(u8, out, "1.2.3.4\tsshd\t"));
    try testing.expect(std.mem.endsWith(u8, out, "\t2\n"));
}

test "format: list expired entry shows 'expired' (SYS-002)" {
    // ban_expiry in the past (year 2001) must render as "expired" rather than
    // a negative number or garbage.
    const payload = "[{\"ip\":\"5.5.5.5\",\"jail\":\"sshd\",\"attempt_count\":3,\"last_attempt\":0,\"ban_count\":1,\"ban_expiry\":1000000000}]";
    const out = try runList(testing.allocator, payload, .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "expired") != null);
}

test "format: list json passes through (SYS-002)" {
    const payload = "[]";
    const out = try runList(testing.allocator, payload, .json);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.startsWith(u8, out, "["));
}

test "format: list rejects object-shape payload (SYS-002 regression)" {
    // The old wrapper shape would have succeeded before SYS-002 was filed;
    // the new parser must reject it so a future regression can't silently
    // drift the wire format again.
    const payload = "{\"entries\":[]}";
    const out = try runList(testing.allocator, payload, .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "error: could not parse list payload") != null);
}

fn runJails(alloc: std.mem.Allocator, payload: []const u8, fmt: OutputFormat) ![]u8 {
    var list = std.ArrayList(u8).init(alloc);
    errdefer list.deinit();
    try formatJails(alloc, list.writer(), payload, fmt, .{ .enabled = false });
    return list.toOwnedSlice();
}

test "format: jails table (daemon-shape JSON, SYS-002)" {
    // Matches engine/net/commands.zig::handleListJails output exactly.
    const payload =
        \\[
        \\  {"name":"sshd","enabled":true,"active_bans":5,"maxretry":3,"findtime":600,"bantime":3600},
        \\  {"name":"nginx","enabled":false,"active_bans":0,"maxretry":5,"findtime":600,"bantime":600}
        \\]
    ;
    const out = try runJails(testing.allocator, payload, .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "JAIL") != null);
    try testing.expect(std.mem.indexOf(u8, out, "MAX RETRY") != null);
    try testing.expect(std.mem.indexOf(u8, out, "FIND TIME") != null);
    try testing.expect(std.mem.indexOf(u8, out, "BAN TIME") != null);
    try testing.expect(std.mem.indexOf(u8, out, "sshd") != null);
    try testing.expect(std.mem.indexOf(u8, out, "nginx") != null);
    try testing.expect(std.mem.indexOf(u8, out, "enabled") != null);
    try testing.expect(std.mem.indexOf(u8, out, "disabled") != null);
    try testing.expect(std.mem.indexOf(u8, out, "Total: 2 jails") != null);
    // TOTAL and BACKEND columns removed (not per-jail data in v0.1.0).
    try testing.expect(std.mem.indexOf(u8, out, "TOTAL") == null);
    try testing.expect(std.mem.indexOf(u8, out, "BACKEND") == null);
}

test "format: jails plain (SYS-002)" {
    const payload = "[{\"name\":\"sshd\",\"enabled\":true,\"active_bans\":1,\"maxretry\":3,\"findtime\":600,\"bantime\":300}]";
    const out = try runJails(testing.allocator, payload, .plain);
    defer testing.allocator.free(out);
    // Six tab-separated columns: name, state, active, maxretry, findtime, bantime.
    try testing.expect(std.mem.indexOf(u8, out, "sshd\tenabled\t1\t3\t600\t300") != null);
}

test "format: jails empty table (SYS-002)" {
    const out = try runJails(testing.allocator, "[]", .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "No jails") != null);
}

test "format: jails human duration formatting (SYS-002)" {
    // findtime=600 -> "10m", bantime=86400 -> "1d".
    const payload = "[{\"name\":\"sshd\",\"enabled\":true,\"active_bans\":0,\"maxretry\":3,\"findtime\":600,\"bantime\":86400}]";
    const out = try runJails(testing.allocator, payload, .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "10m") != null);
    try testing.expect(std.mem.indexOf(u8, out, "1d") != null);
}

test "format: jails rejects object-shape payload (SYS-002 regression)" {
    const payload = "{\"jails\":[]}";
    const out = try runJails(testing.allocator, payload, .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "error: could not parse jails payload") != null);
}

fn runVersion(alloc: std.mem.Allocator, payload: []const u8, fmt: OutputFormat) ![]u8 {
    var list = std.ArrayList(u8).init(alloc);
    errdefer list.deinit();
    try formatVersion(alloc, list.writer(), "0.1.0", payload, fmt, .{ .enabled = false });
    return list.toOwnedSlice();
}

test "format: version table shows client and daemon" {
    const payload = "{\"daemon_version\":\"0.1.0\",\"git_commit\":\"abc123\"}";
    const out = try runVersion(testing.allocator, payload, .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "fail2zig-client 0.1.0") != null);
    try testing.expect(std.mem.indexOf(u8, out, "fail2zig       0.1.0") != null);
    try testing.expect(std.mem.indexOf(u8, out, "abc123") != null);
}

test "format: version table with no daemon payload" {
    const out = try runVersion(testing.allocator, "", .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "fail2zig-client 0.1.0") != null);
    try testing.expect(std.mem.indexOf(u8, out, "daemon unreachable") != null);
}

test "format: version plain" {
    const payload = "{\"daemon_version\":\"0.1.0\"}";
    const out = try runVersion(testing.allocator, payload, .plain);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "client\t0.1.0") != null);
    try testing.expect(std.mem.indexOf(u8, out, "daemon\t0.1.0") != null);
}

test "format: version json wraps daemon payload" {
    const payload = "{\"daemon_version\":\"0.1.0\"}";
    const out = try runVersion(testing.allocator, payload, .json);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "\"client_version\":\"0.1.0\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"daemon\":{\"daemon_version\"") != null);
}

test "format: ban action table" {
    const payload = "{\"ip\":\"1.2.3.4\",\"jail\":\"sshd\",\"result\":\"banned\"}";
    var list = std.ArrayList(u8).init(testing.allocator);
    defer list.deinit();
    try formatBan(testing.allocator, list.writer(), payload, .table, .{ .enabled = false });
    try testing.expect(std.mem.indexOf(u8, list.items, "Banned 1.2.3.4") != null);
    try testing.expect(std.mem.indexOf(u8, list.items, "jail: sshd") != null);
}

test "format: unban plain" {
    const payload = "{\"ip\":\"1.2.3.4\",\"result\":\"unbanned\"}";
    var list = std.ArrayList(u8).init(testing.allocator);
    defer list.deinit();
    try formatUnban(testing.allocator, list.writer(), payload, .plain, .{ .enabled = false });
    try testing.expect(std.mem.indexOf(u8, list.items, "ip\t1.2.3.4") != null);
    try testing.expect(std.mem.indexOf(u8, list.items, "result\tunbanned") != null);
}

test "format: reload table with jails count" {
    const payload = "{\"result\":\"reloaded\",\"jails_loaded\":4}";
    var list = std.ArrayList(u8).init(testing.allocator);
    defer list.deinit();
    try formatReload(testing.allocator, list.writer(), payload, .table, .{ .enabled = false });
    try testing.expect(std.mem.indexOf(u8, list.items, "Reloaded") != null);
    try testing.expect(std.mem.indexOf(u8, list.items, "4 jails loaded") != null);
}

test "format: error all modes" {
    var list = std.ArrayList(u8).init(testing.allocator);
    defer list.deinit();

    try formatError(list.writer(), 42, "jail not found", .table, .{ .enabled = false });
    try testing.expect(std.mem.indexOf(u8, list.items, "error: jail not found") != null);

    list.clearRetainingCapacity();
    try formatError(list.writer(), 42, "jail not found", .json, .{ .enabled = false });
    try testing.expect(std.mem.indexOf(u8, list.items, "\"code\":42") != null);

    list.clearRetainingCapacity();
    try formatError(list.writer(), 42, "jail not found", .plain, .{ .enabled = false });
    try testing.expect(std.mem.indexOf(u8, list.items, "error\t42\tjail not found") != null);
}

test "format: color escapes emitted only when enabled" {
    var list = std.ArrayList(u8).init(testing.allocator);
    defer list.deinit();
    const payload = "[{\"ip\":\"1.2.3.4\",\"jail\":\"sshd\",\"attempt_count\":3,\"last_attempt\":0,\"ban_count\":1,\"ban_expiry\":9999999999}]";

    try formatList(testing.allocator, list.writer(), payload, .table, .{ .enabled = true });
    try testing.expect(std.mem.indexOf(u8, list.items, "\x1b[") != null);

    list.clearRetainingCapacity();
    try formatList(testing.allocator, list.writer(), payload, .table, .{ .enabled = false });
    try testing.expect(std.mem.indexOf(u8, list.items, "\x1b[") == null);
}
