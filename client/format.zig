// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const shared = @import("shared");
const args = @import("args.zig");

pub const OutputFormat = args.OutputFormat;

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

pub fn shouldColor(allow_color: bool) bool {
    if (!allow_color) return false;
    const fd = std.io.getStdOut().handle;
    return std.posix.isatty(fd);
}

fn terminalColumns() usize {
    const fd = std.io.getStdOut().handle;
    if (!std.posix.isatty(fd)) return 80;
    var winsize: std.posix.winsize = .{ .row = 0, .col = 0, .xpixel = 0, .ypixel = 0 };
    const result = std.posix.system.ioctl(fd, std.posix.T.IOCGWINSZ, @intFromPtr(&winsize));
    if (std.posix.errno(result) != .SUCCESS or winsize.col == 0) return 80;
    return winsize.col;
}

pub const StatusPayload = struct {
    version: ?[]const u8 = null,
    uptime_seconds: ?u64 = null,
    memory_bytes_used: ?u64 = null,
    memory_bytes_limit: ?u64 = null,
    active_bans: ?u32 = null,
    total_bans: ?u64 = null,
    parse_rate: ?f64 = null,
    protection: ?[]const u8 = null,
    protection_cause: ?[]const u8 = null,
    backend: ?[]const u8 = null,
    jails_active: ?u32 = null,
    generation: ?[]const u8 = null,
    storage: ?[]const u8 = null,
    cause: ?[]const u8 = null,
    sqlite_code: ?i32 = null,
    next_retry_ms: ?u64 = null,
    unhealthy_sources: ?u32 = null,
    effect_backend: ?[]const u8 = null,
    effect_stage: ?[]const u8 = null,
    effect_cause: ?[]const u8 = null,
    effect_mutation: ?[]const u8 = null,
    effects_uncertain: ?bool = null,
    overdue_effects: ?u64 = null,
    worker_busy: ?bool = null,
    worker_stalled: ?bool = null,
    worker_busy_age_ms: ?u64 = null,
    worker_heartbeat_age_ms: ?u64 = null,
    clock_uncertain: ?bool = null,
    expiry_overdue: ?bool = null,
    expiry_uncertain: ?bool = null,
    next_committed_expiry_us: ?i64 = null,
};

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
};

pub const JailEntry = struct {
    name: ?[]const u8 = null,
    enabled: ?bool = null,
    paused: ?bool = null,
    active_bans: ?u32 = null,
    maxretry: ?u32 = null,
    findtime: ?u32 = null,
    bantime: ?u32 = null,
    action: ?[]const u8 = null,
    enforcing: ?bool = null,
    log_source: ?[]const u8 = null,
    source_healthy: ?bool = null,
    lines_seen: ?u64 = null,
    cause: ?[]const u8 = null,
    source_exit_code: ?u8 = null,
    source_signal: ?u32 = null,
    source_stderr_present: ?bool = null,
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
    result: ?[]const u8 = null,
};

pub const UnbanActionPayload = struct {
    ip: ?[]const u8 = null,
    jail: ?[]const u8 = null,
    result: ?[]const u8 = null,
};

pub const ReloadPayload = struct {
    result: ?[]const u8 = null,
    jails_loaded: ?u32 = null,
    warnings: ?[]const []const u8 = null,
};

pub fn formatStatus(
    allocator: std.mem.Allocator,
    writer: anytype,
    payload_json: []const u8,
    fmt: OutputFormat,
    color: Color,
) !void {
    try formatStatusWithDetails(allocator, writer, payload_json, fmt, color, false);
}

pub fn formatStatusDetailed(allocator: std.mem.Allocator, writer: anytype, payload_json: []const u8, fmt: OutputFormat, color: Color) !void {
    try formatStatusWithDetails(allocator, writer, payload_json, fmt, color, true);
}

fn formatStatusWithDetails(allocator: std.mem.Allocator, writer: anytype, payload_json: []const u8, fmt: OutputFormat, color: Color, details: bool) !void {
    try formatStatusForWidthDetailed(allocator, writer, payload_json, fmt, color, terminalColumns(), details);
}

fn formatStatusForWidth(
    allocator: std.mem.Allocator,
    writer: anytype,
    payload_json: []const u8,
    fmt: OutputFormat,
    color: Color,
    columns: usize,
) !void {
    return formatStatusForWidthDetailed(allocator, writer, payload_json, fmt, color, columns, true);
}

fn formatStatusForWidthDetailed(
    allocator: std.mem.Allocator,
    writer: anytype,
    payload_json: []const u8,
    fmt: OutputFormat,
    color: Color,
    columns: usize,
    details: bool,
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
                try writeStatusTable(writer, parsed.value, color, columns, details);
            }
        },
    }
}

fn writeStatusPlain(writer: anytype, s: StatusPayload) !void {
    var diagnostic_buffer: [diagnostic_max_bytes]u8 = undefined;
    if (s.version) |v| try writer.print("version\t{s}\n", .{renderDiagnostic(&diagnostic_buffer, v)});
    if (s.uptime_seconds) |u| try writer.print("uptime_seconds\t{d}\n", .{u});
    if (s.memory_bytes_used) |m| try writer.print("memory_bytes_used\t{d}\n", .{m});
    if (s.memory_bytes_limit) |m| try writer.print("memory_bytes_limit\t{d}\n", .{m});
    if (s.active_bans) |a| try writer.print("active_bans\t{d}\n", .{a});
    if (s.total_bans) |a| try writer.print("total_bans\t{d}\n", .{a});
    if (s.parse_rate) |p| try writer.print("parse_rate\t{d:.2}\n", .{p});
    if (s.protection) |p| try writer.print("protection\t{s}\n", .{renderDiagnostic(&diagnostic_buffer, p)});
    if (s.protection_cause) |c| try writer.print("protection_cause\t{s}\n", .{renderDiagnostic(&diagnostic_buffer, c)});
    if (s.backend) |b| try writer.print("backend\t{s}\n", .{renderDiagnostic(&diagnostic_buffer, b)});
    if (s.jails_active) |j| try writer.print("jails_active\t{d}\n", .{j});
    if (s.generation) |g| try writer.print("generation\t{s}\n", .{renderDiagnostic(&diagnostic_buffer, g)});
    if (s.storage) |storage| try writer.print("storage\t{s}\n", .{renderDiagnostic(&diagnostic_buffer, storage)});
    if (s.cause) |cause| try writer.print("cause\t{s}\n", .{renderDiagnostic(&diagnostic_buffer, cause)});
    if (s.sqlite_code) |code| try writer.print("sqlite_code\t{d}\n", .{code});
    if (s.next_retry_ms) |deadline| try writer.print("next_retry_ms\t{d}\n", .{deadline});
    if (s.unhealthy_sources) |count| try writer.print("unhealthy_sources\t{d}\n", .{count});
    if (s.effect_backend) |backend| try writer.print("effect_backend\t{s}\n", .{renderDiagnostic(&diagnostic_buffer, backend)});
    if (s.effect_stage) |stage| try writer.print("effect_stage\t{s}\n", .{renderDiagnostic(&diagnostic_buffer, stage)});
    if (s.effect_cause) |cause| try writer.print("effect_cause\t{s}\n", .{renderDiagnostic(&diagnostic_buffer, cause)});
    if (s.effect_mutation) |mutation| try writer.print("effect_mutation\t{s}\n", .{renderDiagnostic(&diagnostic_buffer, mutation)});
    if (s.effects_uncertain) |uncertain| try writer.print("effects_uncertain\t{s}\n", .{boolValue(uncertain)});
    if (s.overdue_effects) |count| try writer.print("overdue_effects\t{d}\n", .{count});
    if (s.worker_busy) |busy| try writer.print("worker_busy\t{s}\n", .{boolValue(busy)});
    if (s.worker_stalled) |stalled| try writer.print("worker_stalled\t{s}\n", .{boolValue(stalled)});
    if (s.worker_busy_age_ms) |age| try writer.print("worker_busy_age_ms\t{d}\n", .{age});
    if (s.worker_heartbeat_age_ms) |age| try writer.print("worker_heartbeat_age_ms\t{d}\n", .{age});
    if (s.clock_uncertain) |uncertain| try writer.print("clock_uncertain\t{s}\n", .{boolValue(uncertain)});
    if (s.expiry_overdue) |overdue| try writer.print("expiry_overdue\t{s}\n", .{boolValue(overdue)});
    if (s.expiry_uncertain) |uncertain| try writer.print("expiry_uncertain\t{s}\n", .{boolValue(uncertain)});
    if (s.next_committed_expiry_us) |deadline| try writer.print("next_committed_expiry_us\t{d}\n", .{deadline});
}

fn writeStatusTable(writer: anytype, s: StatusPayload, color: Color, columns: usize, details: bool) !void {
    if (!details) return writeStatusSummary(writer, s, color, columns);
    const width = statusWidth(s);
    if (width > columns) return writeStatusNarrow(writer, s, color, columns);
    try drawTopLine(writer, width);
    try writer.writeAll("| ");
    try color.on(writer, Color.bold);
    try writer.print("fail2zig", .{});
    var heading_buffer: [diagnostic_max_bytes]u8 = undefined;
    if (s.version) |v| try writer.print(" {s}", .{renderDiagnostic(&heading_buffer, v)});
    try color.off(writer);
    try writer.writeAll(" — status");
    try padTo(writer, statusHeadingLen(s.version), width - 2);
    try writer.writeAll(" |\n");
    try drawMidLine(writer, width);

    try rowLabel(writer, "Uptime:", formatUptime(s.uptime_seconds), width);
    try rowLabel(writer, "Memory:", formatMemory(s.memory_bytes_used, s.memory_bytes_limit), width);
    try rowLabel(writer, "Parse rate:", formatRate(s.parse_rate), width);
    try rowLabel(writer, "Active bans:", formatOptU32(s.active_bans), width);
    try rowLabel(writer, "Total bans:", formatOptU64(s.total_bans), width);
    var protection_buffer: [diagnostic_max_bytes + 16]u8 = undefined;
    try rowLabel(writer, "Protection:", formatProtection(&protection_buffer, s), width);
    var backend_buffer: [diagnostic_max_bytes]u8 = undefined;
    try rowLabel(writer, "Backend:", if (s.backend) |backend| renderDiagnostic(&backend_buffer, backend) else "-", width);
    try rowLabel(writer, "Jails:", formatOptU32(s.jails_active), width);
    var diagnostic_buffer: [diagnostic_max_bytes]u8 = undefined;
    if (s.generation) |g| try rowLabel(writer, "Generation:", renderDiagnostic(&diagnostic_buffer, g), width);

    if (s.storage) |storage| try rowLabel(writer, "Storage:", renderDiagnostic(&diagnostic_buffer, storage), width);
    if (statusCause(s)) |cause| try rowLabel(writer, "Cause:", renderDiagnostic(&diagnostic_buffer, cause), width);
    if (s.sqlite_code) |code| {
        var code_buffer: [32]u8 = undefined;
        try rowLabel(writer, "SQLite code:", std.fmt.bufPrint(&code_buffer, "{d}", .{code}) catch "-", width);
    }
    if (s.next_retry_ms) |deadline| {
        var retry_buffer: [64]u8 = undefined;
        try rowLabel(writer, "Retry at:", std.fmt.bufPrint(&retry_buffer, "{d} ms monotonic", .{deadline}) catch "-", width);
    }
    if (s.unhealthy_sources) |count| if (count > 0) {
        var source_buffer: [96]u8 = undefined;
        try rowLabel(writer, "Sources:", std.fmt.bufPrint(&source_buffer, "{d} unhealthy; inspect fail2zig jails", .{count}) catch "unhealthy; inspect fail2zig jails", width);
    };
    var summary_buffer: [160]u8 = undefined;
    if (formatEffects(&summary_buffer, s)) |value| try rowLabel(writer, "Effects:", value, width);
    if (s.effect_backend) |backend| try rowLabel(writer, "Effect:", renderDiagnostic(&diagnostic_buffer, backend), width);
    if (s.effect_stage) |stage| try rowLabel(writer, "  Stage:", renderDiagnostic(&diagnostic_buffer, stage), width);
    if (s.effect_cause) |cause| try rowLabel(writer, "  Cause:", renderDiagnostic(&diagnostic_buffer, cause), width);
    if (s.effect_mutation) |mutation| try rowLabel(writer, "  Attempt:", renderDiagnostic(&diagnostic_buffer, mutation), width);
    if (formatWorker(&summary_buffer, s)) |value| try rowLabel(writer, "Worker:", value, width);
    if (s.clock_uncertain == true) try rowLabel(writer, "Clock:", "uncertain", width);
    if (formatExpiry(&summary_buffer, s)) |value| try rowLabel(writer, "Expiry:", value, width);

    try drawBotLine(writer, width);
}

fn writeStatusSummary(writer: anytype, s: StatusPayload, color: Color, columns: usize) !void {
    var protection: [diagnostic_max_bytes + 16]u8 = undefined;
    var diagnostic: [diagnostic_max_bytes]u8 = undefined;
    var backend: [diagnostic_max_bytes]u8 = undefined;
    try color.on(writer, Color.bold);
    try writer.writeAll("fail2zig");
    if (s.version) |value| {
        try writer.writeByte(' ');
        try writeClipped(writer, renderDiagnostic(&diagnostic, value), @max(@as(usize, 4), columns -| "fail2zig  status".len));
    }
    try writer.writeAll(" status\n");
    try color.off(writer);
    try writeStatusNarrowRow(writer, "Protection: ", formatProtection(&protection, s), columns);
    try writeStatusNarrowRow(writer, "Backend: ", if (s.backend) |value| renderDiagnostic(&backend, value) else "unknown", columns);
    if (s.storage) |value| try writeStatusNarrowRow(writer, "Storage: ", renderDiagnostic(&diagnostic, value), columns);
    try writeStatusNarrowRow(writer, "Jails: ", formatOptU32(s.jails_active), columns);
    try writeStatusNarrowRow(writer, "Active bans: ", formatOptU32(s.active_bans), columns);
    try writeStatusNarrowRow(writer, "Uptime: ", formatUptime(s.uptime_seconds), columns);
    if (statusCause(s)) |value| try writeStatusNarrowRow(writer, "Cause: ", renderDiagnostic(&diagnostic, value), columns);
    if (s.sqlite_code) |value| {
        var code: [32]u8 = undefined;
        try writeStatusNarrowRow(writer, "SQLite code: ", std.fmt.bufPrint(&code, "{d}", .{value}) catch "unknown", columns);
    }
    if (s.next_retry_ms) |value| {
        var retry: [64]u8 = undefined;
        try writeStatusNarrowRow(writer, "Retry at: ", std.fmt.bufPrint(&retry, "{d} ms monotonic", .{value}) catch "unknown", columns);
    }
    if (s.unhealthy_sources) |count| if (count > 0) {
        var source: [96]u8 = undefined;
        try writeStatusNarrowRow(writer, "Sources: ", std.fmt.bufPrint(&source, "{d} unhealthy; inspect fail2zig jails", .{count}) catch "unhealthy", columns);
    };
    var summary: [160]u8 = undefined;
    const effects_problem = formatEffects(&summary, s);
    if (effects_problem) |value| try writeStatusNarrowRow(writer, "Effects: ", value, columns);
    if (effects_problem != null or s.effect_cause != null or s.effect_mutation != null) {
        if (s.effect_backend) |value| try writeStatusNarrowRow(writer, "Effect: ", renderDiagnostic(&diagnostic, value), columns);
        if (s.effect_stage) |value| try writeStatusNarrowRow(writer, "Effect stage: ", renderDiagnostic(&diagnostic, value), columns);
        if (s.effect_cause) |value| try writeStatusNarrowRow(writer, "Effect cause: ", renderDiagnostic(&diagnostic, value), columns);
        if (s.effect_mutation) |value| try writeStatusNarrowRow(writer, "Effect attempt: ", renderDiagnostic(&diagnostic, value), columns);
    }
    if (s.worker_stalled == true) if (formatWorker(&summary, s)) |value| try writeStatusNarrowRow(writer, "Worker: ", value, columns);
    if (s.clock_uncertain == true) try writeStatusNarrowRow(writer, "Clock: ", "uncertain", columns);
    if (formatExpiry(&summary, s)) |value| try writeStatusNarrowRow(writer, "Expiry: ", value, columns);
}

fn writeStatusNarrow(writer: anytype, s: StatusPayload, color: Color, columns: usize) !void {
    var version_buffer: [diagnostic_max_bytes]u8 = undefined;
    try color.on(writer, Color.bold);
    try writer.writeAll("fail2zig");
    if (s.version) |version| {
        try writer.writeByte(' ');
        try writeCell(writer, renderDiagnostic(&version_buffer, version), @max(@as(usize, 4), columns -| "fail2zig  status".len));
    }
    try writer.writeAll(" status\n");
    try color.off(writer);

    var protection_buffer: [diagnostic_max_bytes + 16]u8 = undefined;
    var diagnostic_buffer: [diagnostic_max_bytes]u8 = undefined;
    var backend_buffer: [diagnostic_max_bytes]u8 = undefined;
    try writeStatusNarrowRow(writer, "Protection: ", formatProtection(&protection_buffer, s), columns);
    try writeStatusNarrowRow(writer, "Backend: ", if (s.backend) |backend| renderDiagnostic(&backend_buffer, backend) else "-", columns);
    try writeStatusNarrowRow(writer, "Active bans: ", formatOptU32(s.active_bans), columns);
    try writeStatusNarrowRow(writer, "Total bans: ", formatOptU64(s.total_bans), columns);
    try writeStatusNarrowRow(writer, "Jails: ", formatOptU32(s.jails_active), columns);
    if (s.generation) |generation| try writeStatusNarrowRow(writer, "Generation: ", renderDiagnostic(&diagnostic_buffer, generation), columns);
    try writeStatusNarrowRow(writer, "Uptime: ", formatUptime(s.uptime_seconds), columns);
    try writeStatusNarrowRow(writer, "Memory: ", formatMemory(s.memory_bytes_used, s.memory_bytes_limit), columns);
    try writeStatusNarrowRow(writer, "Parse rate: ", formatRate(s.parse_rate), columns);
    if (s.storage) |storage| try writeStatusNarrowRow(writer, "Storage: ", renderDiagnostic(&diagnostic_buffer, storage), columns);
    if (statusCause(s)) |cause| try writeStatusNarrowRow(writer, "Cause: ", renderDiagnostic(&diagnostic_buffer, cause), columns);
    if (s.sqlite_code) |code| {
        var code_buffer: [32]u8 = undefined;
        try writeStatusNarrowRow(writer, "SQLite code: ", std.fmt.bufPrint(&code_buffer, "{d}", .{code}) catch "-", columns);
    }
    if (s.next_retry_ms) |deadline| {
        var retry_buffer: [64]u8 = undefined;
        try writeStatusNarrowRow(writer, "Retry at: ", std.fmt.bufPrint(&retry_buffer, "{d} ms monotonic", .{deadline}) catch "-", columns);
    }
    if (s.unhealthy_sources) |count| if (count > 0) {
        var source_buffer: [96]u8 = undefined;
        try writeStatusNarrowRow(writer, "Sources: ", std.fmt.bufPrint(&source_buffer, "{d} unhealthy", .{count}) catch "unhealthy", columns);
    };
    var summary_buffer: [160]u8 = undefined;
    if (formatEffects(&summary_buffer, s)) |value| try writeStatusNarrowRow(writer, "Effects: ", value, columns);
    if (s.effect_backend) |backend| try writeStatusNarrowRow(writer, "Effect: ", renderDiagnostic(&diagnostic_buffer, backend), columns);
    if (s.effect_stage) |stage| try writeStatusNarrowRow(writer, "Stage: ", renderDiagnostic(&diagnostic_buffer, stage), columns);
    if (s.effect_cause) |cause| try writeStatusNarrowRow(writer, "Effect cause: ", renderDiagnostic(&diagnostic_buffer, cause), columns);
    if (s.effect_mutation) |mutation| try writeStatusNarrowRow(writer, "Attempt: ", renderDiagnostic(&diagnostic_buffer, mutation), columns);
    if (formatWorker(&summary_buffer, s)) |value| try writeStatusNarrowRow(writer, "Worker: ", value, columns);
    if (s.clock_uncertain == true) try writeStatusNarrowRow(writer, "Clock: ", "uncertain", columns);
    if (formatExpiry(&summary_buffer, s)) |value| try writeStatusNarrowRow(writer, "Expiry: ", value, columns);
}

fn writeStatusNarrowRow(writer: anytype, label: []const u8, value: []const u8, columns: usize) !void {
    try writer.writeAll(label);
    try writeCell(writer, value, @max(@as(usize, 4), columns -| label.len));
    try writer.writeAll("\n");
}

fn statusWidth(s: StatusPayload) usize {
    var used: usize = statusHeadingLen(s.version);
    used = @max(used, rowUsed(formatUptime(s.uptime_seconds)));
    used = @max(used, rowUsed(formatMemory(s.memory_bytes_used, s.memory_bytes_limit)));
    used = @max(used, rowUsed(formatRate(s.parse_rate)));
    used = @max(used, rowUsed(formatOptU32(s.active_bans)));
    used = @max(used, rowUsed(formatOptU64(s.total_bans)));
    var protection_buffer: [diagnostic_max_bytes + 16]u8 = undefined;
    used = @max(used, rowUsed(formatProtection(&protection_buffer, s)));
    var backend_buffer: [diagnostic_max_bytes]u8 = undefined;
    used = @max(used, rowUsed(if (s.backend) |backend| renderDiagnostic(&backend_buffer, backend) else "-"));
    used = @max(used, rowUsed(formatOptU32(s.jails_active)));
    var diagnostic_buffer: [diagnostic_max_bytes]u8 = undefined;
    if (s.generation) |g| used = @max(used, rowUsed(renderDiagnostic(&diagnostic_buffer, g)));
    if (s.storage) |storage| used = @max(used, rowUsed(renderDiagnostic(&diagnostic_buffer, storage)));
    if (statusCause(s)) |cause| used = @max(used, rowUsed(renderDiagnostic(&diagnostic_buffer, cause)));
    if (s.sqlite_code) |code| {
        var code_buffer: [32]u8 = undefined;
        used = @max(used, rowUsed(std.fmt.bufPrint(&code_buffer, "{d}", .{code}) catch "-"));
    }
    if (s.next_retry_ms) |deadline| {
        var retry_buffer: [64]u8 = undefined;
        used = @max(used, rowUsed(std.fmt.bufPrint(&retry_buffer, "{d} ms monotonic", .{deadline}) catch "-"));
    }
    if (s.unhealthy_sources) |count| if (count > 0) {
        var source_buffer: [96]u8 = undefined;
        used = @max(used, rowUsed(std.fmt.bufPrint(&source_buffer, "{d} unhealthy; inspect fail2zig jails", .{count}) catch "unhealthy; inspect fail2zig jails"));
    };
    var summary_buffer: [160]u8 = undefined;
    if (formatEffects(&summary_buffer, s)) |value| used = @max(used, rowUsed(value));
    if (s.effect_backend) |backend| used = @max(used, rowUsed(renderDiagnostic(&diagnostic_buffer, backend)));
    if (s.effect_stage) |stage| used = @max(used, rowUsed(renderDiagnostic(&diagnostic_buffer, stage)));
    if (s.effect_cause) |cause| used = @max(used, rowUsed(renderDiagnostic(&diagnostic_buffer, cause)));
    if (s.effect_mutation) |mutation| used = @max(used, rowUsed(renderDiagnostic(&diagnostic_buffer, mutation)));
    if (formatWorker(&summary_buffer, s)) |value| used = @max(used, rowUsed(value));
    if (s.clock_uncertain == true) used = @max(used, rowUsed("uncertain"));
    if (formatExpiry(&summary_buffer, s)) |value| used = @max(used, rowUsed(value));
    return @max(44, used + 2);
}

fn rowUsed(value: []const u8) usize {
    return 2 + label_col + value.len;
}

const label_col: usize = 13;

fn formatProtection(buffer: []u8, s: StatusPayload) []const u8 {
    const p = s.protection orelse return "-";
    if (!std.mem.eql(u8, p, "degraded")) return renderDiagnostic(buffer, p);
    const value = s.protection_cause orelse return "DEGRADED";
    if (std.mem.eql(u8, value, "none")) return "DEGRADED";
    var cause_buffer: [diagnostic_max_bytes]u8 = undefined;
    const cause = renderDiagnostic(&cause_buffer, value);
    return std.fmt.bufPrint(buffer, "DEGRADED ({s})", .{cause}) catch "DEGRADED";
}

fn statusCause(s: StatusPayload) ?[]const u8 {
    if (s.cause) |cause| {
        if (!std.mem.eql(u8, cause, "none")) return cause;
    }
    if (s.protection) |protection| {
        if (std.mem.eql(u8, protection, "degraded")) return "unknown";
    }
    return null;
}

fn boolValue(value: bool) []const u8 {
    return if (value) "true" else "false";
}

fn formatEffects(buffer: []u8, s: StatusPayload) ?[]const u8 {
    const uncertain = s.effects_uncertain == true;
    const overdue = s.overdue_effects orelse 0;
    if (!uncertain and overdue == 0) return null;
    if (uncertain and overdue > 0) return std.fmt.bufPrint(buffer, "uncertain; {d} overdue", .{overdue}) catch "uncertain";
    if (uncertain) return "uncertain";
    return std.fmt.bufPrint(buffer, "{d} overdue", .{overdue}) catch "overdue";
}

fn formatWorker(buffer: []u8, s: StatusPayload) ?[]const u8 {
    const busy = s.worker_busy == true;
    const stalled = s.worker_stalled == true;
    if (!busy and !stalled) return null;
    const busy_age = s.worker_busy_age_ms;
    const heartbeat_age = s.worker_heartbeat_age_ms;
    if (stalled and busy and busy_age != null and heartbeat_age != null) return std.fmt.bufPrint(buffer, "stalled; busy {d} ms; heartbeat {d} ms ago", .{ busy_age.?, heartbeat_age.? }) catch "stalled; busy";
    if (stalled and heartbeat_age != null) return std.fmt.bufPrint(buffer, "stalled; heartbeat {d} ms ago", .{heartbeat_age.?}) catch "stalled";
    if (stalled) return "stalled";
    if (busy_age) |age| return std.fmt.bufPrint(buffer, "busy for {d} ms", .{age}) catch "busy";
    return "busy";
}

fn formatExpiry(buffer: []u8, s: StatusPayload) ?[]const u8 {
    const overdue = s.expiry_overdue == true;
    const uncertain = s.expiry_uncertain == true;
    if (!overdue and !uncertain) return null;
    const deadline = s.next_committed_expiry_us;
    if (overdue and uncertain and deadline != null) return std.fmt.bufPrint(buffer, "overdue; view uncertain; next committed {d} us", .{deadline.?}) catch "overdue; view uncertain";
    if (overdue and deadline != null) return std.fmt.bufPrint(buffer, "overdue; next committed {d} us", .{deadline.?}) catch "overdue";
    if (uncertain and deadline != null) return std.fmt.bufPrint(buffer, "view uncertain; next committed {d} us", .{deadline.?}) catch "view uncertain";
    if (overdue and uncertain) return "overdue; view uncertain";
    return if (overdue) "overdue" else "view uncertain";
}

const diagnostic_max_bytes: usize = 96;

const DiagnosticUnit = struct {
    input_len: usize,
    output_len: usize,
    kind: enum { raw, slash, newline, carriage_return, tab, hex },
};

fn diagnosticUnit(input: []const u8) DiagnosticUnit {
    const byte = input[0];
    if (byte == '\\') return .{ .input_len = 1, .output_len = 2, .kind = .slash };
    if (byte == '\n') return .{ .input_len = 1, .output_len = 2, .kind = .newline };
    if (byte == '\r') return .{ .input_len = 1, .output_len = 2, .kind = .carriage_return };
    if (byte == '\t') return .{ .input_len = 1, .output_len = 2, .kind = .tab };
    if (byte < 0x20 or byte == 0x7f) return .{ .input_len = 1, .output_len = 4, .kind = .hex };
    if (byte < 0x7f) return .{ .input_len = 1, .output_len = 1, .kind = .raw };
    const sequence_len: usize = std.unicode.utf8ByteSequenceLength(byte) catch return .{ .input_len = 1, .output_len = 4, .kind = .hex };
    if (sequence_len > input.len) return .{ .input_len = 1, .output_len = 4, .kind = .hex };
    const codepoint = std.unicode.utf8Decode(input[0..sequence_len]) catch return .{ .input_len = 1, .output_len = 4, .kind = .hex };
    if (isUnsafeUnicodeControl(codepoint)) return .{ .input_len = sequence_len, .output_len = sequence_len * 4, .kind = .hex };
    return .{ .input_len = sequence_len, .output_len = sequence_len, .kind = .raw };
}

fn isUnsafeUnicodeControl(codepoint: u21) bool {
    return (codepoint >= 0x80 and codepoint <= 0x9f) or
        codepoint == 0x061c or
        (codepoint >= 0x200e and codepoint <= 0x200f) or
        (codepoint >= 0x202a and codepoint <= 0x202e) or
        (codepoint >= 0x2066 and codepoint <= 0x2069);
}

fn renderDiagnostic(buffer: []u8, input: []const u8) []const u8 {
    const capacity = @min(buffer.len, diagnostic_max_bytes);
    if (capacity == 0) return buffer[0..0];
    var input_index: usize = 0;
    var escaped_len: usize = 0;
    while (input_index < input.len and escaped_len <= capacity) {
        const unit = diagnosticUnit(input[input_index..]);
        escaped_len +|= unit.output_len;
        input_index += unit.input_len;
    }
    const truncated = input_index < input.len or escaped_len > capacity;
    const suffix_len = if (truncated) @min(capacity, 3) else 0;
    const limit = capacity - suffix_len;
    input_index = 0;
    var output_index: usize = 0;
    while (input_index < input.len) {
        const unit = diagnosticUnit(input[input_index..]);
        if (unit.output_len > limit - output_index) break;
        switch (unit.kind) {
            .raw => @memcpy(buffer[output_index..][0..unit.output_len], input[input_index..][0..unit.input_len]),
            .slash => @memcpy(buffer[output_index..][0..2], "\\\\"),
            .newline => @memcpy(buffer[output_index..][0..2], "\\n"),
            .carriage_return => @memcpy(buffer[output_index..][0..2], "\\r"),
            .tab => @memcpy(buffer[output_index..][0..2], "\\t"),
            .hex => {
                const hex = "0123456789ABCDEF";
                for (input[input_index..][0..unit.input_len], 0..) |hex_byte, index| {
                    const offset = output_index + index * 4;
                    buffer[offset] = '\\';
                    buffer[offset + 1] = 'x';
                    buffer[offset + 2] = hex[hex_byte >> 4];
                    buffer[offset + 3] = hex[hex_byte & 0x0f];
                }
            },
        }
        output_index += unit.output_len;
        input_index += unit.input_len;
    }
    if (truncated) {
        @memset(buffer[output_index..][0..suffix_len], '.');
        output_index += suffix_len;
    }
    return buffer[0..output_index];
}

fn statusHeadingLen(version: ?[]const u8) usize {
    var version_buffer: [diagnostic_max_bytes]u8 = undefined;
    const version_len = if (version) |value| 1 + renderDiagnostic(&version_buffer, value).len else 0;
    return "fail2zig".len + version_len + " — status".len;
}

fn rowLabel(writer: anytype, label: []const u8, value: []const u8, width: usize) !void {
    try writer.writeAll("| ");
    try writer.writeAll(label);
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
        const pct = (@as(u128, used) * 100) / limit;
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

fn formatOptU64(opt: ?u64) []const u8 {
    const v = opt orelse return "-";
    const out = std.fmt.bufPrint(&scratch, "{d}", .{v}) catch return "-";
    return out;
}

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

fn formatListForWidth(
    allocator: std.mem.Allocator,
    writer: anytype,
    payload_json: []const u8,
    fmt: OutputFormat,
    color: Color,
    columns: usize,
) !void {
    return formatListForWidthDetailed(allocator, writer, payload_json, fmt, color, columns, true);
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
                try writeListPlain(writer, parsed.value, now);
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

fn writeListPlain(writer: anytype, entries: []const BanEntry, now: i64) !void {
    for (entries) |e| {
        var ip_buffer: [diagnostic_max_bytes]u8 = undefined;
        var jail_buffer: [diagnostic_max_bytes]u8 = undefined;
        try writer.print("{s}\t{s}\t{d}\t{d}\n", .{
            if (e.ip) |ip| renderDiagnostic(&ip_buffer, ip) else "-",
            if (e.jail) |jail| renderDiagnostic(&jail_buffer, jail) else "-",
            remainingFromExpiry(e.ban_expiry, now) orelse 0,
            e.ban_count orelse 0,
        });
    }
}

fn writeListTable(writer: anytype, entries: []const BanEntry, color: Color, now: i64, columns: usize, details: bool) !void {
    if (entries.len == 0) {
        try writer.writeAll("No active bans.\n");
        return;
    }

    const ip_col = colWidth("IP ADDRESS", longestBanText(entries, "ip"));
    const jail_col = colWidth("JAIL", longestBanText(entries, "jail"));
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
    const full_width = ip_col + jail_col + time_col + confirmation_col + if (details) count_col else 0;
    if (full_width <= columns) return writeListColumns(writer, entries, color, now, ip_col, jail_col, time_col, confirmation_col, count_col, details);
    if (columns >= 71) return writeListColumns(writer, entries, color, now, 25, 21, 12, 13, 0, false);
    try writeListStacked(writer, entries, color, now, columns);
}

fn writeListColumns(writer: anytype, entries: []const BanEntry, color: Color, now: i64, ip_col: usize, jail_col: usize, time_col: usize, confirmation_col: usize, count_col: usize, include_count: bool) !void {
    try color.on(writer, Color.bold);
    try padRightPrint(writer, "IP ADDRESS", ip_col);
    try padRightPrint(writer, "JAIL", jail_col);
    try padRightPrint(writer, "TIME LEFT", time_col);
    try padRightPrint(writer, "CONFIRMATION", confirmation_col);
    if (include_count) try padRightPrint(writer, "BAN COUNT", count_col);
    try color.off(writer);
    try writer.writeAll("\n");

    const total_w = ip_col + jail_col + time_col + confirmation_col + if (include_count) count_col else 0;
    try repeatChar(writer, '-', total_w);
    try writer.writeAll("\n");

    for (entries) |e| {
        var ip_buffer: [diagnostic_max_bytes]u8 = undefined;
        var jail_buffer: [diagnostic_max_bytes]u8 = undefined;
        try color.on(writer, Color.cyan);
        try writeCell(writer, if (e.ip) |ip| renderDiagnostic(&ip_buffer, ip) else "-", ip_col);
        try color.off(writer);
        try writeCell(writer, if (e.jail) |jail| renderDiagnostic(&jail_buffer, jail) else "-", jail_col);
        try writeCell(writer, banExpiryText(e, now), time_col);
        const confirmation = confirmationText(e);
        if (std.mem.eql(u8, confirmation, "confirmed")) try color.on(writer, Color.green);
        if (std.mem.eql(u8, confirmation, "pending")) try color.on(writer, Color.yellow);
        try writeCell(writer, confirmation, confirmation_col);
        try color.off(writer);
        if (include_count) try writeCell(writer, formatOptU32Local(e.ban_count), count_col);
        try writer.writeAll("\n");
    }

    try writer.print("Total: {d} active bans\n", .{entries.len});
}

fn writeListStacked(writer: anytype, entries: []const BanEntry, color: Color, now: i64, columns: usize) !void {
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
        try writer.writeAll("\nTIME LEFT:  ");
        try writeCell(writer, banExpiryText(e, now), value_width);
        try writer.writeAll("\nCONFIRMATION: ");
        try writeCell(writer, confirmationText(e), value_width);
        try writer.writeAll("\n");
    }
    try writer.print("Total: {d} active bans\n", .{entries.len});
}

fn banExpiryText(entry: BanEntry, now: i64) []const u8 {
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

fn padRightPrint(writer: anytype, s: []const u8, width: usize) !void {
    try writer.writeAll(s);
    if (s.len < width) try writeSpaces(writer, width - s.len);
}

fn formatRemaining(opt: ?i64) []const u8 {
    const secs = opt orelse return "-";
    if (secs < 0) return "expired";
    const mins = @divTrunc(secs, 60);
    const s: u64 = @intCast(@mod(secs, 60));
    const out = std.fmt.bufPrint(&scratch, "{d}m {d:0>2}s", .{ mins, s }) catch return "-";
    return out;
}

fn formatOptU32Local(opt: ?u32) []const u8 {
    const v = opt orelse return "-";
    const out = std.fmt.bufPrint(&scratch, "{d}", .{v}) catch return "-";
    return out;
}

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

fn formatJailsForWidth(
    allocator: std.mem.Allocator,
    writer: anytype,
    payload_json: []const u8,
    fmt: OutputFormat,
    color: Color,
    columns: usize,
) !void {
    return formatJailsForWidthDetailed(allocator, writer, payload_json, fmt, color, columns, true);
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
        try writer.print("{s}\t{s}\t{d}\t{d}\t{d}\t{d}\t{s}\t{s}\t{s}\t{s}\t{d}\n", .{
            if (j.name) |name| renderDiagnostic(&name_buffer, name) else "-",
            if (j.enabled orelse false) "enabled" else "disabled",
            j.active_bans orelse 0,
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

const compact_jail_health_width = 19;

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
    const enforce_col = colWidth("ENFORCING", w.enforce);
    const source_col = colWidth("SOURCE", longestJailText(jails, "log_source"));
    const health_col = @max("HEALTH".len, @min(w.health, diagnostic_max_bytes)) + 1;
    const full_width = name_col + state_col + active_col + max_col + find_col + ban_col + action_col + enforce_col + source_col + health_col;
    if (full_width > columns) {
        // Preserve ordinary source causes instead of clipping them in the compact column.
        if (columns >= 74 and w.health < compact_jail_health_width) return writeJailsCompact(writer, jails, color);
        return writeJailsStacked(writer, jails, color, columns);
    }

    try color.on(writer, Color.bold);
    try padRightPrint(writer, "JAIL", name_col);
    try padRightPrint(writer, "STATE", state_col);
    try padRightPrint(writer, "ACTIVE", active_col);
    try padRightPrint(writer, "MAX RETRY", max_col);
    try padRightPrint(writer, "FIND TIME", find_col);
    try padRightPrint(writer, "BAN TIME", ban_col);
    try padRightPrint(writer, "ACTION", action_col);
    try padRightPrint(writer, "ENFORCING", enforce_col);
    try padRightPrint(writer, "SOURCE", source_col);
    try padRightPrint(writer, "HEALTH", health_col);
    try color.off(writer);
    try writer.writeAll("\n");

    try repeatChar(writer, '-', name_col + state_col + active_col + max_col + find_col + ban_col + action_col + enforce_col + source_col + health_col);
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
        if (j.enforcing) |e| try color.on(writer, if (e) Color.green else Color.yellow);
        try writeCell(writer, enforcingStr(j), enforce_col);
        try color.off(writer);
        try writeCell(writer, if (j.log_source) |source| renderDiagnostic(&source_buffer, source) else "-", source_col);
        if (j.source_healthy) |h| try color.on(writer, if (h) Color.green else Color.yellow);
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
    const enforcing_col = colWidth("ENFORCING", 7);
    const bans_col = colWidth("BANS", 10);
    const full_width = name_col + state_col + source_col + health_col + enforcing_col + bans_col;
    if (full_width > columns) return writeJailsStacked(writer, jails, color, columns);
    try color.on(writer, Color.bold);
    try padRightPrint(writer, "JAIL", name_col);
    try padRightPrint(writer, "STATE", state_col);
    try padRightPrint(writer, "SOURCE", source_col);
    try padRightPrint(writer, "SOURCE HEALTH", health_col);
    try padRightPrint(writer, "ENFORCING", enforcing_col);
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
        if (j.source_healthy) |value| try color.on(writer, if (value) Color.green else Color.yellow);
        try writeCell(writer, formatJailHealth(&health, j), health_col);
        try color.off(writer);
        try writeCell(writer, enforcingStr(j), enforcing_col);
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

fn writeJailsCompact(writer: anytype, jails: []const JailEntry, color: Color) !void {
    const name_col = 21;
    const state_col = 9;
    const active_col = 8;
    const action_col = 17;
    const health_col = compact_jail_health_width;
    try color.on(writer, Color.bold);
    try padRightPrint(writer, "JAIL", name_col);
    try padRightPrint(writer, "STATE", state_col);
    try padRightPrint(writer, "ACTIVE", active_col);
    try padRightPrint(writer, "ACTION", action_col);
    try padRightPrint(writer, "HEALTH", health_col);
    try color.off(writer);
    try writer.writeAll("\n");
    try repeatChar(writer, '-', name_col + state_col + active_col + action_col + health_col);
    try writer.writeAll("\n");
    for (jails) |j| {
        var name_buffer: [diagnostic_max_bytes]u8 = undefined;
        var action_buffer: [diagnostic_max_bytes]u8 = undefined;
        var health_buffer: [diagnostic_max_bytes]u8 = undefined;
        try writeCell(writer, if (j.name) |name| renderDiagnostic(&name_buffer, name) else "-", name_col);
        try color.on(writer, if (j.paused == true or !(j.enabled orelse false)) Color.yellow else Color.green);
        try writeCell(writer, stateStr(j), state_col);
        try color.off(writer);
        try writeCell(writer, formatOptU32Local(j.active_bans), active_col);
        try writeCell(writer, if (j.action) |action| renderDiagnostic(&action_buffer, action) else "-", action_col);
        if (j.source_healthy) |healthy| try color.on(writer, if (healthy) Color.green else Color.yellow);
        try writeCell(writer, formatJailHealth(&health_buffer, j), health_col);
        try color.off(writer);
        try writer.writeAll("\n");
    }
    try writer.print("Total: {d} jails\n", .{jails.len});
}

fn writeJailsStacked(writer: anytype, jails: []const JailEntry, color: Color, columns: usize) !void {
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
        try writer.writeAll("\nENFORCING: ");
        try writeCell(writer, enforcingStr(j), @max(@as(usize, 4), columns -| "ENFORCING: ".len));
        try writer.writeAll("\nACTION: ");
        try writeCell(writer, if (j.action) |action| renderDiagnostic(&action_buffer, action) else "-", value_width);
        try writer.writeAll("\nHEALTH: ");
        try writeCell(writer, formatJailHealth(&health_buffer, j), value_width);
        try writer.writeAll("\n");
    }
    try writer.print("Total: {d} jails\n", .{jails.len});
}

const JailsWidths = struct {
    state: usize = 0,
    active: usize = 0,
    max: usize = 0,
    find: usize = 0,
    ban: usize = 0,
    enforce: usize = 0,
    health: usize = 0,

    fn widen(self: *JailsWidths, j: JailEntry) void {
        self.state = @max(self.state, stateStr(j).len);
        self.active = @max(self.active, formatOptU32Local(j.active_bans).len);
        self.max = @max(self.max, formatOptU32Local(j.maxretry).len);
        self.find = @max(self.find, formatDurationSecs(j.findtime).len);
        self.ban = @max(self.ban, formatDurationSecs(j.bantime).len);
        self.enforce = @max(self.enforce, enforcingStr(j).len);
        var health_buffer: [diagnostic_max_bytes]u8 = undefined;
        self.health = @max(self.health, formatJailHealth(&health_buffer, j).len);
    }
};

fn stateStr(j: JailEntry) []const u8 {
    if (j.paused == true) return "paused";
    const enabled = j.enabled orelse return "unknown";
    return if (enabled) "enabled" else "disabled";
}

fn enforcingStr(j: JailEntry) []const u8 {
    const e = j.enforcing orelse return "-";
    return if (e) "true" else "false";
}

fn formatJailHealth(buffer: []u8, jail: JailEntry) []const u8 {
    const healthy = jail.source_healthy orelse return "unknown";
    if (healthy) return "ok";
    var cause_buffer: [40]u8 = undefined;
    const cause = if (jail.cause) |value|
        if (std.mem.eql(u8, value, "none")) "unknown" else renderDiagnostic(&cause_buffer, value)
    else
        "unknown";
    var stream = std.io.fixedBufferStream(buffer[0..@min(buffer.len, diagnostic_max_bytes)]);
    const writer = stream.writer();
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

const col_max: usize = 48;

fn longestLen(comptime T: type, entries: []const T, comptime field: []const u8) usize {
    var widest: usize = 0;
    for (entries) |e| widest = @max(widest, (@field(e, field) orelse "-").len);
    return widest;
}

fn colWidth(header: []const u8, longest: usize) usize {
    return @max(header.len, @min(longest, col_max)) + 1;
}

fn writeCell(writer: anytype, s: []const u8, width: usize) !void {
    const value_max = width - 1;
    if (s.len <= value_max) return padRightPrint(writer, s, width);
    var cut = value_max - 3;
    while (cut > 0 and (s[cut] & 0xC0) == 0x80) cut -= 1;
    try writer.writeAll(s[0..cut]);
    try writer.writeAll("...");
    try writeSpaces(writer, width - (cut + 3));
}

fn writeClipped(writer: anytype, s: []const u8, width: usize) !void {
    if (s.len <= width) return writer.writeAll(s);
    if (width <= 3) return writer.writeAll(s[0..width]);
    var cut = width - 3;
    while (cut > 0 and (s[cut] & 0xC0) == 0x80) cut -= 1;
    try writer.writeAll(s[0..cut]);
    try writer.writeAll("...");
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
            const parsed = try std.json.parseFromSlice(
                VersionPayload,
                allocator,
                if (payload_json.len == 0) "{}" else payload_json,
                .{ .ignore_unknown_fields = true, .allocate = .alloc_always },
            );
            defer parsed.deinit();
            var diagnostic: [diagnostic_max_bytes]u8 = undefined;
            if (parsed.value.daemon_version) |v| {
                if (std.mem.eql(u8, client_version, v)) {
                    try writer.print("fail2zig {s} (client and daemon)\n", .{renderDiagnostic(&diagnostic, client_version)});
                } else {
                    try writer.print("Client: fail2zig {s}\n", .{renderDiagnostic(&diagnostic, client_version)});
                    try writer.print("Daemon: fail2zig {s}\n", .{renderDiagnostic(&diagnostic, v)});
                }
            } else {
                try writer.print("Client: fail2zig {s}\nDaemon: version unavailable\n", .{renderDiagnostic(&diagnostic, client_version)});
            }
            if (parsed.value.git_commit) |c| try writer.print("  commit: {s}\n", .{renderDiagnostic(&diagnostic, c)});
            if (parsed.value.build_date) |d| try writer.print("  built:  {s}\n", .{renderDiagnostic(&diagnostic, d)});
        },
    }
}

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

pub const ScopeView = struct {
    family: ?[]const u8 = null,
    address: ?[]const u8 = null,
    prefix: ?u8 = null,
    subject_kind: ?[]const u8 = null,
    protocols: ?[]const []const u8 = null,
    port_ranges: ?[]const PortRangeView = null,
    legacy_exact: ?bool = null,
    protocol: ?[]const u8 = null,
    port: ?u16 = null,
    direction: ?[]const u8 = null,
    target: ?[]const u8 = null,
};

pub const PortRangeView = struct {
    first: ?u16 = null,
    last: ?u16 = null,
};

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

pub const ScopeEntry = struct {
    jail: ?[]const u8 = null,
    scope: ?ScopeView = null,
    lease: ?[]const u8 = null,
    deadline_us: ?i64 = null,
    decision_id_hex: ?[]const u8 = null,
    confirmed: ?bool = null,
};

pub const ScopesPayload = struct {
    generation: ?[]const u8 = null,
    items: ?[]const ScopeEntry = null,
    next_cursor: ?[]const u8 = null,
};

pub const HistoryEntry = struct {
    sequence: ?u64 = null,
    event_id_hex: ?[]const u8 = null,
    jail: ?[]const u8 = null,
    decision_id_hex: ?[]const u8 = null,
    confirmed_us: ?i64 = null,
    scope: ?ScopeView = null,
    native_retry: ?bool = null,
};

pub const HistoryPayload = struct {
    generation: ?[]const u8 = null,
    items: ?[]const HistoryEntry = null,
    next_cursor: ?[]const u8 = null,
};

pub const FirewallInstallation = struct {
    id_hex: ?[]const u8 = null,
    backend: ?[]const u8 = null,
    namespace: ?[]const u8 = null,
};

pub const FirewallObservation = struct {
    id: ?[]const u8 = null,
    state: ?[]const u8 = null,
    observed_wall_us: ?i64 = null,
    age_ms: ?u64 = null,
    observation_complete: ?bool = null,
    observed_total: ?u64 = null,
    sample_count: ?u64 = null,
    sample_truncated: ?bool = null,
    inventory: ?[]const u8 = null,
    origin: ?[]const u8 = null,
    comparison: ?[]const u8 = null,
    comparison_reason: ?[]const u8 = null,
};

pub const FirewallAttempt = struct {
    outcome: ?[]const u8 = null,
    cause: ?[]const u8 = null,
    stage: ?[]const u8 = null,
    age_ms: ?u64 = null,
};

pub const FirewallItem = struct {
    scope: ?ScopeView = null,
    effect_id_hex: ?[]const u8 = null,
    remaining_ms_at_observation: ?u64 = null,
    deadline_us: ?i64 = null,
    placement: ?FirewallPlacement = null,
};

pub const FirewallPlacement = struct {
    kind: ?[]const u8 = null,
    family: ?[]const u8 = null,
    table: ?[]const u8 = null,
    chain: ?[]const u8 = null,
    set: ?[]const u8 = null,
    verdict: ?[]const u8 = null,
};

pub const FirewallStructure = struct {
    proof: ?[]const u8 = null,
    tables: ?[]const FirewallTable = null,
    chains: ?[]const FirewallChain = null,
    sets: ?[]const FirewallSet = null,
    rules: ?[]const FirewallRule = null,
};
pub const FirewallTable = struct { family: ?[]const u8 = null, name: ?[]const u8 = null };
pub const FirewallChain = struct { family: ?[]const u8 = null, table: ?[]const u8 = null, name: ?[]const u8 = null, type: ?[]const u8 = null, hook: ?[]const u8 = null, priority: ?i32 = null, policy: ?[]const u8 = null };
pub const FirewallSet = struct { family: ?[]const u8 = null, table: ?[]const u8 = null, name: ?[]const u8 = null, key_type: ?[]const u8 = null };
pub const FirewallRule = struct { family: ?[]const u8 = null, table: ?[]const u8 = null, chain: ?[]const u8 = null, match: ?[]const u8 = null, verdict: ?[]const u8 = null, position: ?u8 = null };

pub const FirewallPayload = struct {
    schema_version: ?u32 = null,
    generation: ?[]const u8 = null,
    kind: ?[]const u8 = null,
    available: ?bool = null,
    unavailable_reason: ?[]const u8 = null,
    installation: ?FirewallInstallation = null,
    observation: ?FirewallObservation = null,
    last_attempt: ?FirewallAttempt = null,
    structure: ?FirewallStructure = null,
    items: ?[]const FirewallItem = null,
    next_cursor: ?[]const u8 = null,
};

pub fn formatConfig(allocator: std.mem.Allocator, writer: anytype, payload_json: []const u8, fmt: OutputFormat, color: Color) !void {
    return formatQuery(ConfigPayload, "config", writeConfigPlain, writeConfigTable, allocator, writer, payload_json, fmt, color);
}

pub fn formatScopes(allocator: std.mem.Allocator, writer: anytype, payload_json: []const u8, fmt: OutputFormat, color: Color) !void {
    return formatQuery(ScopesPayload, "scopes", writeScopesPlain, writeScopesTable, allocator, writer, payload_json, fmt, color);
}

pub fn formatHistory(allocator: std.mem.Allocator, writer: anytype, payload_json: []const u8, fmt: OutputFormat, color: Color) !void {
    return formatQuery(HistoryPayload, "history", writeHistoryPlain, writeHistoryTable, allocator, writer, payload_json, fmt, color);
}

pub fn formatFirewall(allocator: std.mem.Allocator, writer: anytype, payload_json: []const u8, fmt: OutputFormat, color: Color) !void {
    return formatFirewallWithDetails(allocator, writer, payload_json, fmt, color, false);
}

pub fn formatFirewallDetailed(allocator: std.mem.Allocator, writer: anytype, payload_json: []const u8, fmt: OutputFormat, color: Color) !void {
    return formatFirewallWithDetails(allocator, writer, payload_json, fmt, color, true);
}

fn formatFirewallWithDetails(allocator: std.mem.Allocator, writer: anytype, payload_json: []const u8, fmt: OutputFormat, color: Color, details: bool) !void {
    return formatFirewallForWidthDetailed(allocator, writer, payload_json, fmt, color, terminalColumns(), details);
}

fn formatQuery(
    comptime Payload: type,
    comptime label: []const u8,
    comptime plain: anytype,
    comptime table: anytype,
    allocator: std.mem.Allocator,
    writer: anytype,
    payload_json: []const u8,
    fmt: OutputFormat,
    color: Color,
) !void {
    switch (fmt) {
        .json => {
            try writer.writeAll(payload_json);
            if (payload_json.len == 0 or payload_json[payload_json.len - 1] != '\n') try writer.writeAll("\n");
        },
        .plain, .table => {
            const parsed = std.json.parseFromSlice(Payload, allocator, payload_json, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch |e| {
                try writer.print("error: could not parse " ++ label ++ " payload ({s})\n", .{@errorName(e)});
                return;
            };
            defer parsed.deinit();
            if (fmt == .plain) try plain(writer, parsed.value) else try table(writer, parsed.value, color);
        },
    }
}

fn plainOpt(writer: anytype, key: []const u8, value: ?[]const u8) !void {
    try writer.print("{s}\t{s}\n", .{ key, value orelse "-" });
}

fn plainBool(writer: anytype, key: []const u8, value: ?bool) !void {
    try writer.print("{s}\t{s}\n", .{ key, boolStr(value) });
}

fn plainInt(writer: anytype, key: []const u8, value: anytype) !void {
    if (value) |v| try writer.print("{s}\t{d}\n", .{ key, v }) else try writer.print("{s}\t-\n", .{key});
}

fn plainList(writer: anytype, key: []const u8, values: ?[]const []const u8) !void {
    try writer.print("{s}\t", .{key});
    if (values) |list| {
        for (list, 0..) |v, i| {
            if (i != 0) try writer.writeAll(",");
            try writer.writeAll(v);
        }
    } else try writer.writeAll("-");
    try writer.writeAll("\n");
}

fn boolStr(value: ?bool) []const u8 {
    const v = value orelse return "-";
    return if (v) "true" else "false";
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

fn scopeAddress(buffer: *[64]u8, scope: ?ScopeView) []const u8 {
    const s = scope orelse return "-";
    const address = s.address orelse return "-";
    const prefix = s.prefix orelse return address;
    const host_prefix: u8 = if (std.mem.eql(u8, s.family orelse "", "v6")) 128 else 32;
    if (prefix == host_prefix) return address;
    return std.fmt.bufPrint(buffer, "{s}/{d}", .{ address, prefix }) catch address;
}

const scope_match_max_bytes: usize = 384;

fn scopeMatch(buffer: []u8, scope: ?ScopeView) []const u8 {
    const s = scope orelse return "-";
    if (s.protocols) |protocols| {
        if (protocols.len == 0) return "unknown";
        var stream = std.io.fixedBufferStream(buffer);
        const writer = stream.writer();
        const all = protocols.len == 1 and std.mem.eql(u8, protocols[0], "all");
        if (all) {
            writer.writeAll("any") catch return "unknown";
        } else {
            for (protocols, 0..) |protocol, index| {
                if (index != 0) writer.writeByte(',') catch return "unknown";
                var diagnostic: [diagnostic_max_bytes]u8 = undefined;
                writer.writeAll(renderDiagnostic(&diagnostic, protocol)) catch return "unknown";
            }
        }
        if (s.port_ranges) |ranges| if (ranges.len != 0) {
            writer.writeByte('/') catch return "unknown";
            for (ranges, 0..) |range, index| {
                if (index != 0) writer.writeByte(',') catch return "unknown";
                const first = range.first orelse {
                    writer.writeByte('?') catch return "unknown";
                    continue;
                };
                const last = range.last orelse {
                    writer.writeByte('?') catch return "unknown";
                    continue;
                };
                if (first == last) {
                    writer.print("{d}", .{first}) catch return "unknown";
                } else {
                    writer.print("{d}-{d}", .{ first, last }) catch return "unknown";
                }
            }
        };
        return stream.getWritten();
    }
    if (s.protocol == null and s.port == null) return "any";
    if (s.port) |port| {
        var diagnostic: [diagnostic_max_bytes]u8 = undefined;
        const protocol = if (s.protocol) |value| renderDiagnostic(&diagnostic, value) else "any";
        return std.fmt.bufPrint(buffer, "{s}/{d}", .{ protocol, port }) catch "unknown";
    }
    return renderDiagnostic(buffer, s.protocol.?);
}

fn writeScopesPlain(writer: anytype, p: ScopesPayload) !void {
    try plainOpt(writer, "generation", p.generation);
    for (p.items orelse &.{}, 0..) |it, i| {
        var key: [64]u8 = undefined;
        var addr: [64]u8 = undefined;
        var match: [scope_match_max_bytes]u8 = undefined;
        try plainOpt(writer, try itemKey(&key, i, "jail"), it.jail);
        try plainOpt(writer, try itemKey(&key, i, "scope"), scopeAddress(&addr, it.scope));
        try plainOpt(writer, try itemKey(&key, i, "match"), scopeMatch(&match, it.scope));
        try plainOpt(writer, try itemKey(&key, i, "lease"), it.lease);
        try plainInt(writer, try itemKey(&key, i, "deadline_us"), it.deadline_us);
        try plainBool(writer, try itemKey(&key, i, "confirmed"), it.confirmed);
        try plainOpt(writer, try itemKey(&key, i, "decision_id"), it.decision_id_hex);
    }
    try plainOpt(writer, "next_cursor", p.next_cursor);
}

fn itemKey(buffer: *[64]u8, index: usize, field_name: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, "items.{d}.{s}", .{ index, field_name }) catch error.NameTooLong;
}

fn writeScopesTable(writer: anytype, p: ScopesPayload, color: Color) !void {
    const items = p.items orelse &.{};
    if (items.len == 0) {
        try writer.writeAll("No active scopes.\n");
    } else {
        const now = std.time.timestamp();
        var widest_addr: usize = 0;
        var widest_match: usize = 0;
        for (items) |it| {
            var addr: [64]u8 = undefined;
            var match: [scope_match_max_bytes]u8 = undefined;
            widest_addr = @max(widest_addr, scopeAddress(&addr, it.scope).len);
            widest_match = @max(widest_match, scopeMatch(&match, it.scope).len);
        }
        const jail_col = colWidth("JAIL", longestLen(ScopeEntry, items, "jail"));
        const addr_col = colWidth("SCOPE", widest_addr);
        const match_col = colWidth("MATCH", widest_match);
        try color.on(writer, Color.bold);
        try padRightPrint(writer, "JAIL", jail_col);
        try padRightPrint(writer, "SCOPE", addr_col);
        try padRightPrint(writer, "MATCH", match_col);
        try padRightPrint(writer, "LEASE", 11);
        try padRightPrint(writer, "REMAINING", 12);
        try padRightPrint(writer, "CONFIRMED", 11);
        try padRightPrint(writer, "DECISION", 13);
        try color.off(writer);
        try writer.writeAll("\n");
        try repeatChar(writer, '-', jail_col + addr_col + match_col + 47);
        try writer.writeAll("\n");
        for (items) |it| {
            var addr: [64]u8 = undefined;
            var match: [scope_match_max_bytes]u8 = undefined;
            try writeCell(writer, it.jail orelse "-", jail_col);
            try writeCell(writer, scopeAddress(&addr, it.scope), addr_col);
            try writeCell(writer, scopeMatch(&match, it.scope), match_col);
            try padRightPrint(writer, it.lease orelse "-", 11);
            const remaining: []const u8 = if (std.mem.eql(u8, it.lease orelse "", "permanent")) "never" else formatRemaining(remainingFromDeadlineUs(it.deadline_us, now));
            try padRightPrint(writer, remaining, 12);
            try color.on(writer, if (it.confirmed orelse false) Color.green else Color.yellow);
            try padRightPrint(writer, if (it.confirmed orelse false) "yes" else "no", 11);
            try color.off(writer);
            try padRightPrint(writer, shortHex(it.decision_id_hex), 13);
            try writer.writeAll("\n");
        }
        try writer.print("Total: {d} scopes\n", .{items.len});
    }
    try writePageFooter(writer, p.generation, p.next_cursor);
}

fn remainingFromDeadlineUs(deadline_us: ?i64, now: i64) ?i64 {
    const deadline = deadline_us orelse return null;
    return @divTrunc(deadline, std.time.us_per_s) - now;
}

fn shortHex(opt: ?[]const u8) []const u8 {
    const hex = opt orelse return "-";
    return hex[0..@min(hex.len, 12)];
}

fn writePageFooter(writer: anytype, generation: ?[]const u8, next_cursor: ?[]const u8) !void {
    try writer.print("generation: {s}\n", .{generation orelse "-"});
    if (next_cursor) |cursor| try writer.print("more available: rerun with --cursor {s}\n", .{cursor});
}

fn writeHistoryPlain(writer: anytype, p: HistoryPayload) !void {
    try plainOpt(writer, "generation", p.generation);
    for (p.items orelse &.{}, 0..) |it, i| {
        var key: [64]u8 = undefined;
        var addr: [64]u8 = undefined;
        try plainInt(writer, try itemKey(&key, i, "sequence"), it.sequence);
        try plainOpt(writer, try itemKey(&key, i, "jail"), it.jail);
        try plainOpt(writer, try itemKey(&key, i, "scope"), scopeAddress(&addr, it.scope));
        try plainInt(writer, try itemKey(&key, i, "confirmed_us"), it.confirmed_us);
        try plainBool(writer, try itemKey(&key, i, "native_retry"), it.native_retry);
        try plainOpt(writer, try itemKey(&key, i, "decision_id"), it.decision_id_hex);
        try plainOpt(writer, try itemKey(&key, i, "event_id"), it.event_id_hex);
    }
    try plainOpt(writer, "next_cursor", p.next_cursor);
}

fn writeHistoryTable(writer: anytype, p: HistoryPayload, color: Color) !void {
    const items = p.items orelse &.{};
    if (items.len == 0) {
        try writer.writeAll("No confirmed history.\n");
    } else {
        var widest_addr: usize = 0;
        var widest_match: usize = 0;
        var widest_seq: usize = 0;
        for (items) |it| {
            var addr: [64]u8 = undefined;
            var match: [scope_match_max_bytes]u8 = undefined;
            widest_addr = @max(widest_addr, scopeAddress(&addr, it.scope).len);
            widest_match = @max(widest_match, scopeMatch(&match, it.scope).len);
            widest_seq = @max(widest_seq, formatOptU64Local(it.sequence).len);
        }
        const seq_col = colWidth("SEQ", widest_seq);
        const jail_col = colWidth("JAIL", longestLen(HistoryEntry, items, "jail"));
        const addr_col = colWidth("SCOPE", widest_addr);
        const match_col = colWidth("MATCH", widest_match);
        try color.on(writer, Color.bold);
        try padRightPrint(writer, "SEQ", seq_col);
        try padRightPrint(writer, "JAIL", jail_col);
        try padRightPrint(writer, "SCOPE", addr_col);
        try padRightPrint(writer, "MATCH", match_col);
        try padRightPrint(writer, "CONFIRMED (UTC)", 21);
        try padRightPrint(writer, "RETRY", 7);
        try padRightPrint(writer, "DECISION", 13);
        try color.off(writer);
        try writer.writeAll("\n");
        try repeatChar(writer, '-', seq_col + jail_col + addr_col + match_col + 41);
        try writer.writeAll("\n");
        for (items) |it| {
            var addr: [64]u8 = undefined;
            var match: [scope_match_max_bytes]u8 = undefined;
            var when: [32]u8 = undefined;
            try padRightPrint(writer, formatOptU64Local(it.sequence), seq_col);
            try writeCell(writer, it.jail orelse "-", jail_col);
            try writeCell(writer, scopeAddress(&addr, it.scope), addr_col);
            try writeCell(writer, scopeMatch(&match, it.scope), match_col);
            try padRightPrint(writer, formatUtc(&when, it.confirmed_us), 21);
            try padRightPrint(writer, boolStr(it.native_retry), 7);
            try padRightPrint(writer, shortHex(it.decision_id_hex), 13);
            try writer.writeAll("\n");
        }
        try writer.print("Total: {d} events\n", .{items.len});
    }
    try writePageFooter(writer, p.generation, p.next_cursor);
}

fn formatFirewallForWidth(
    allocator: std.mem.Allocator,
    writer: anytype,
    payload_json: []const u8,
    fmt: OutputFormat,
    color: Color,
    columns: usize,
) !void {
    return formatFirewallForWidthDetailed(allocator, writer, payload_json, fmt, color, columns, true);
}

fn formatFirewallForWidthDetailed(
    allocator: std.mem.Allocator,
    writer: anytype,
    payload_json: []const u8,
    fmt: OutputFormat,
    color: Color,
    columns: usize,
    details: bool,
) !void {
    if (fmt == .json) {
        try writer.writeAll(payload_json);
        if (payload_json.len == 0 or payload_json[payload_json.len - 1] != '\n') try writer.writeAll("\n");
        return;
    }
    const parsed = try std.json.parseFromSlice(
        FirewallPayload,
        allocator,
        payload_json,
        .{ .ignore_unknown_fields = true, .allocate = .alloc_always },
    );
    defer parsed.deinit();
    if (parsed.value.available == true and parsed.value.observation == null) return error.InvalidFirewallPayload;
    if (fmt == .plain) return writeFirewallPlain(writer, parsed.value);
    return writeFirewallTable(writer, parsed.value, color, columns, details);
}

fn firewallPlainText(writer: anytype, key: []const u8, value: ?[]const u8) !void {
    var buffer: [diagnostic_max_bytes]u8 = undefined;
    try writer.print("{s}\t{s}\n", .{ key, if (value) |text| renderDiagnostic(&buffer, text) else "-" });
}

fn writeFirewallPlain(writer: anytype, payload: FirewallPayload) !void {
    try plainInt(writer, "schema_version", payload.schema_version);
    try firewallPlainText(writer, "generation", payload.generation);
    try firewallPlainText(writer, "kind", payload.kind);
    try plainBool(writer, "available", payload.available);
    try firewallPlainText(writer, "unavailable_reason", payload.unavailable_reason);
    if (payload.installation) |installation| {
        try firewallPlainText(writer, "installation.id", installation.id_hex);
        try firewallPlainText(writer, "installation.backend", installation.backend);
        try firewallPlainText(writer, "installation.namespace", installation.namespace);
    }
    if (payload.observation) |observation| {
        try firewallPlainText(writer, "observation.id", observation.id);
        try firewallPlainText(writer, "observation.state", observation.state);
        try plainInt(writer, "observation.observed_wall_us", observation.observed_wall_us);
        try plainInt(writer, "observation.age_ms", observation.age_ms);
        try plainBool(writer, "observation.complete", observation.observation_complete);
        try plainInt(writer, "observation.observed_total", observation.observed_total);
        try plainInt(writer, "observation.sample_count", observation.sample_count);
        try plainBool(writer, "observation.sample_truncated", observation.sample_truncated);
        try firewallPlainText(writer, "observation.inventory", observation.inventory);
        try firewallPlainText(writer, "observation.origin", observation.origin);
        try firewallPlainText(writer, "observation.comparison", observation.comparison);
        try firewallPlainText(writer, "observation.comparison_reason", observation.comparison_reason);
    }
    if (payload.last_attempt) |attempt| {
        try firewallPlainText(writer, "last_attempt.outcome", attempt.outcome);
        try firewallPlainText(writer, "last_attempt.cause", attempt.cause);
        try firewallPlainText(writer, "last_attempt.stage", attempt.stage);
        try plainInt(writer, "last_attempt.age_ms", attempt.age_ms);
    }
    for (payload.items orelse &.{}, 0..) |item, index| {
        var key: [64]u8 = undefined;
        var address: [64]u8 = undefined;
        var match: [scope_match_max_bytes]u8 = undefined;
        try firewallPlainText(writer, try itemKey(&key, index, "scope"), scopeAddress(&address, item.scope));
        try firewallPlainText(writer, try itemKey(&key, index, "match"), scopeMatch(&match, item.scope));
        try firewallPlainText(writer, try itemKey(&key, index, "effect_id"), item.effect_id_hex);
        try plainInt(writer, try itemKey(&key, index, "remaining_ms_at_observation"), item.remaining_ms_at_observation);
        try plainInt(writer, try itemKey(&key, index, "deadline_us"), item.deadline_us);
    }
    try firewallPlainText(writer, "next_cursor", payload.next_cursor);
}

fn writeFirewallTable(writer: anytype, payload: FirewallPayload, color: Color, columns: usize, details: bool) !void {
    try color.on(writer, Color.bold);
    try writer.writeAll("OWNED FIREWALL");
    if (payload.installation) |installation| if (installation.backend) |backend| {
        var backend_buffer: [diagnostic_max_bytes]u8 = undefined;
        const text = renderDiagnostic(&backend_buffer, backend);
        if ("OWNED FIREWALL  ".len + text.len <= columns) try writer.print("  {s}", .{text});
    };
    try writer.writeAll("\n");
    try color.off(writer);

    var state_buffer: [192]u8 = undefined;
    const state = firewallState(&state_buffer, payload);
    if (payload.available == true and firewallIsStale(payload)) try color.on(writer, Color.yellow);
    try writeFirewallSummaryRow(writer, "State:        ", state, columns);
    try color.off(writer);

    var diagnostic: [diagnostic_max_bytes]u8 = undefined;
    if (payload.installation) |installation| {
        try writeFirewallSummaryRow(writer, "Backend:      ", if (installation.backend) |value| renderDiagnostic(&diagnostic, value) else "unknown", columns);
        if (details) try writeFirewallSummaryRow(writer, "Installation: ", if (installation.id_hex) |value| renderDiagnostic(&diagnostic, value) else "unknown", columns);
        try writeFirewallSummaryRow(writer, "Namespace:    ", if (installation.namespace) |value| renderDiagnostic(&diagnostic, value) else "unknown", columns);
    }
    if (payload.observation) |observation| {
        if (details) try writeFirewallSummaryRow(writer, "Observation:  ", if (observation.id) |value| renderDiagnostic(&diagnostic, value) else "unknown", columns);
        var age_buffer: [64]u8 = undefined;
        try writeFirewallSummaryRow(writer, "Age:          ", formatMilliseconds(&age_buffer, observation.age_ms), columns);
        var coverage_buffer: [160]u8 = undefined;
        try writeFirewallSummaryRow(writer, "Coverage:     ", firewallCoverage(&coverage_buffer, observation), columns);
        try writeFirewallSummaryRow(writer, "Inventory:    ", if (observation.inventory) |value| renderDiagnostic(&diagnostic, value) else "unknown", columns);
        try writeFirewallSummaryRow(writer, "Origin:       ", if (observation.origin) |value| renderDiagnostic(&diagnostic, value) else "unknown", columns);
        var comparison_buffer: [192]u8 = undefined;
        try writeFirewallSummaryRow(writer, "Comparison:   ", firewallComparison(&comparison_buffer, observation), columns);
    }
    var attempt_buffer: [192]u8 = undefined;
    try writeFirewallSummaryRow(writer, "Last attempt: ", firewallAttempt(&attempt_buffer, payload.last_attempt), columns);
    if (details) try writeFirewallSummaryRow(writer, "Generation:   ", if (payload.generation) |value| renderDiagnostic(&diagnostic, value) else "unknown", columns);

    if (details) try writeFirewallStructure(writer, payload.structure, color, columns);

    const items = payload.items orelse &.{};
    try writer.writeAll("\n");
    if (items.len == 0) {
        if (payload.available != true) {
            try writer.writeAll("No sample is available.\n");
        } else if (payload.observation) |observation| {
            if (std.mem.eql(u8, observation.state orelse "", "absent"))
                try writer.writeAll("The owned installation was absent at observation time.\n")
            else
                try writer.writeAll("No sampled protection entries.\n");
        } else {
            try writer.writeAll("No sampled protection entries.\n");
        }
    } else {
        try writeFirewallItems(writer, items, color, columns, details);
    }
    if (payload.next_cursor) |cursor| {
        var cursor_buffer: [diagnostic_max_bytes]u8 = undefined;
        try writer.print("more available: rerun firewall show with --cursor {s}\n", .{renderDiagnostic(&cursor_buffer, cursor)});
    }
}

fn writeFirewallStructure(writer: anytype, structure_opt: ?FirewallStructure, color: Color, columns: usize) !void {
    const structure = structure_opt orelse {
        try writeFirewallSummaryRow(writer, "Structure: ", "unavailable (daemon did not provide a verified owned snapshot)", columns);
        return;
    };
    var proof: [diagnostic_max_bytes]u8 = undefined;
    const proof_text = if (structure.proof) |value| renderDiagnostic(&proof, value) else "unknown";
    if (!std.mem.eql(u8, proof_text, "exact_v1")) {
        var message: [diagnostic_max_bytes]u8 = undefined;
        try writeFirewallSummaryRow(writer, "Structure: ", std.fmt.bufPrint(&message, "unavailable (proof {s})", .{proof_text}) catch "unavailable", columns);
        return;
    }
    try color.on(writer, Color.bold);
    try writer.writeAll("VERIFIED OWNED STRUCTURE\n");
    try color.off(writer);
    try writeFirewallStructureTables(writer, structure.tables orelse &.{}, color, columns);
    try writeFirewallStructureChains(writer, structure.chains orelse &.{}, color, columns);
    try writeFirewallStructureSets(writer, structure.sets orelse &.{}, color, columns);
    try writeFirewallStructureRules(writer, structure.rules orelse &.{}, color, columns);
}

fn writeFirewallStructureTables(writer: anytype, items: []const FirewallTable, color: Color, columns: usize) !void {
    if (items.len == 0) return;
    var widths = [_]usize{ "TABLE".len + 1, "FAMILY".len + 1 };
    for (items) |row| {
        widths[0] = @max(widths[0], structureWidth(row.name));
        widths[1] = @max(widths[1], structureWidth(row.family));
    }
    if (sumWidths(&widths) > columns) {
        for (items) |row| try writeStructureFields(writer, &.{ .{ .label = "TABLE", .value = row.name }, .{ .label = "FAMILY", .value = row.family } }, columns);
        return;
    }
    try writer.writeByte('\n');
    try writeStructureHeader(writer, &.{ "TABLE", "FAMILY" }, &widths, color);
    for (items) |row| try writeStructureRow(writer, &.{ row.name, row.family }, &widths);
}

fn writeFirewallStructureChains(writer: anytype, items: []const FirewallChain, color: Color, columns: usize) !void {
    if (items.len == 0) return;
    var widths = [_]usize{ 6, 5, 5, 9, 7 };
    for (items) |row| {
        var priority: [16]u8 = undefined;
        const value = if (row.priority) |number| try std.fmt.bufPrint(&priority, "{d}", .{number}) else "-";
        for ([_]?[]const u8{ row.name, row.type, row.hook, value, row.policy }, &widths) |field, *width| width.* = @max(width.*, structureWidth(field));
    }
    for (items, 0..) |row, index| {
        var priority: [16]u8 = undefined;
        const value = if (row.priority) |number| try std.fmt.bufPrint(&priority, "{d}", .{number}) else "-";
        if (sumWidths(&widths) > columns) {
            try writeStructureFields(writer, &.{ .{ .label = "CHAIN", .value = row.name }, .{ .label = "FAMILY", .value = row.family }, .{ .label = "TABLE", .value = row.table }, .{ .label = "TYPE", .value = row.type }, .{ .label = "HOOK", .value = row.hook }, .{ .label = "PRIORITY", .value = value }, .{ .label = "POLICY", .value = row.policy } }, columns);
        } else {
            if (index == 0 or !sameStructureContext(items[index - 1], row)) {
                try writeStructureContext(writer, row.family, row.table, columns);
                try writeStructureHeader(writer, &.{ "CHAIN", "TYPE", "HOOK", "PRIORITY", "POLICY" }, &widths, color);
            }
            try writeStructureRow(writer, &.{ row.name, row.type, row.hook, value, row.policy }, &widths);
        }
    }
}

fn writeFirewallStructureSets(writer: anytype, items: []const FirewallSet, color: Color, columns: usize) !void {
    if (items.len == 0) return;
    var widths = [_]usize{ 4, 9 };
    for (items) |row| {
        widths[0] = @max(widths[0], structureWidth(row.name));
        widths[1] = @max(widths[1], structureWidth(row.key_type));
    }
    for (items, 0..) |row, index| {
        if (sumWidths(&widths) > columns) {
            try writeStructureFields(writer, &.{ .{ .label = "SET", .value = row.name }, .{ .label = "FAMILY", .value = row.family }, .{ .label = "TABLE", .value = row.table }, .{ .label = "KEY TYPE", .value = row.key_type } }, columns);
        } else {
            if (index == 0 or !sameStructureContext(items[index - 1], row)) {
                try writeStructureContext(writer, row.family, row.table, columns);
                try writeStructureHeader(writer, &.{ "SET", "KEY TYPE" }, &widths, color);
            }
            try writeStructureRow(writer, &.{ row.name, row.key_type }, &widths);
        }
    }
}

fn writeFirewallStructureRules(writer: anytype, items: []const FirewallRule, color: Color, columns: usize) !void {
    if (items.len == 0) return;
    var widths = [_]usize{ 6, 6, 8, 9 };
    for (items) |row| {
        var position: [4]u8 = undefined;
        const value = if (row.position) |number| try std.fmt.bufPrint(&position, "{d}", .{number}) else "-";
        for ([_]?[]const u8{ row.chain, row.match, row.verdict, value }, &widths) |field, *width| width.* = @max(width.*, structureWidth(field));
    }
    for (items, 0..) |row, index| {
        var position: [4]u8 = undefined;
        const value = if (row.position) |number| try std.fmt.bufPrint(&position, "{d}", .{number}) else "-";
        if (sumWidths(&widths) > columns) {
            try writeStructureFields(writer, &.{ .{ .label = "CHAIN", .value = row.chain }, .{ .label = "FAMILY", .value = row.family }, .{ .label = "TABLE", .value = row.table }, .{ .label = "MATCH", .value = row.match }, .{ .label = "VERDICT", .value = row.verdict }, .{ .label = "POSITION", .value = value } }, columns);
        } else {
            if (index == 0 or !sameStructureContext(items[index - 1], row)) {
                try writeStructureContext(writer, row.family, row.table, columns);
                try writeStructureHeader(writer, &.{ "CHAIN", "MATCH", "VERDICT", "POSITION" }, &widths, color);
            }
            try writeStructureRow(writer, &.{ row.chain, row.match, row.verdict, value }, &widths);
        }
    }
}

fn structureWidth(value: ?[]const u8) usize {
    var buffer: [diagnostic_max_bytes]u8 = undefined;
    return (if (value) |text| renderDiagnostic(&buffer, text).len else @as(usize, 1)) + 1;
}

fn sameOptionalText(left: ?[]const u8, right: ?[]const u8) bool {
    if (left) |text| return if (right) |other| std.mem.eql(u8, text, other) else false;
    return right == null;
}

fn sameStructureContext(left: anytype, right: @TypeOf(left)) bool {
    return sameOptionalText(left.family, right.family) and sameOptionalText(left.table, right.table);
}

fn sumWidths(widths: []const usize) usize {
    var total: usize = 0;
    for (widths) |width| total += width;
    return total;
}

fn writeStructureHeader(writer: anytype, headers: []const []const u8, widths: []const usize, color: Color) !void {
    try color.on(writer, Color.bold);
    for (headers, widths) |header, width| try padRightPrint(writer, header, width);
    try color.off(writer);
    try writer.writeAll("\n");
    try repeatChar(writer, '-', sumWidths(widths));
    try writer.writeAll("\n");
}

const StructureField = struct { label: []const u8, value: ?[]const u8 };

fn writeStructureFields(writer: anytype, fields: []const StructureField, columns: usize) !void {
    for (fields) |field| {
        var escaped: [diagnostic_max_bytes]u8 = undefined;
        var label: [64]u8 = undefined;
        const text = std.fmt.bufPrint(&label, "{s}: ", .{field.label}) catch "Field: ";
        try writeFirewallSummaryRow(writer, text, if (field.value) |value| renderDiagnostic(&escaped, value) else "-", columns);
    }
    try writer.writeAll("\n");
}

fn writeStructureContext(writer: anytype, family: ?[]const u8, table: ?[]const u8, columns: usize) !void {
    try writer.writeByte('\n');
    var family_buffer: [diagnostic_max_bytes]u8 = undefined;
    var table_buffer: [diagnostic_max_bytes]u8 = undefined;
    try writeFirewallSummaryRow(writer, "Family: ", if (family) |value| renderDiagnostic(&family_buffer, value) else "-", columns);
    try writeFirewallSummaryRow(writer, "Table: ", if (table) |value| renderDiagnostic(&table_buffer, value) else "-", columns);
}

fn writeStructureRow(writer: anytype, values: []const ?[]const u8, widths: []const usize) !void {
    for (values, widths) |value, width| {
        var escaped: [diagnostic_max_bytes]u8 = undefined;
        try writeCell(writer, if (value) |text| renderDiagnostic(&escaped, text) else "-", width);
    }
    try writer.writeAll("\n");
}

fn writeFirewallSummaryRow(writer: anytype, label: []const u8, value: []const u8, columns: usize) !void {
    try writer.writeAll(label);
    try writeCell(writer, value, @max(@as(usize, 4), columns -| label.len));
    try writer.writeAll("\n");
}

fn firewallState(buffer: []u8, payload: FirewallPayload) []const u8 {
    if (payload.available != true) {
        const reason = payload.unavailable_reason orelse "unknown";
        var diagnostic: [diagnostic_max_bytes]u8 = undefined;
        return std.fmt.bufPrint(buffer, "unavailable ({s})", .{renderDiagnostic(&diagnostic, reason)}) catch "unavailable";
    }
    const observation = payload.observation orelse return "unavailable (missing observation)";
    const state = observation.state orelse "unknown";
    if (std.mem.eql(u8, state, "absent")) return "absent";
    if (observation.inventory) |inventory| if (std.mem.eql(u8, inventory, "unexpected_entries"))
        return "owned (unexpected entries)";
    if (firewallAttemptForeign(payload.last_attempt)) return "owned (stale; foreign state on last attempt)";
    if (firewallIsStale(payload)) return "owned (stale; last attempt failed)";
    if (std.mem.eql(u8, state, "owned")) return "owned (clean observation)";
    return renderDiagnostic(buffer, state);
}

fn firewallIsStale(payload: FirewallPayload) bool {
    const attempt = payload.last_attempt orelse return false;
    return std.mem.eql(u8, attempt.outcome orelse "", "failed");
}

fn firewallAttemptForeign(attempt: ?FirewallAttempt) bool {
    const value = attempt orelse return false;
    return std.mem.eql(u8, value.cause orelse "", "ForeignState");
}

fn formatMilliseconds(buffer: []u8, value: ?u64) []const u8 {
    const milliseconds = value orelse return "unknown";
    return std.fmt.bufPrint(buffer, "{d} ms", .{milliseconds}) catch "unknown";
}

fn formatRemainingMilliseconds(buffer: []u8, value: ?u64) []const u8 {
    const milliseconds = value orelse return "unknown";
    const seconds = milliseconds / std.time.ms_per_s;
    if (seconds < 60) return std.fmt.bufPrint(buffer, "{d}s", .{seconds}) catch "unknown";
    return std.fmt.bufPrint(buffer, "{d}m {d:0>2}s", .{ seconds / 60, seconds % 60 }) catch "unknown";
}

fn firewallCoverage(buffer: []u8, observation: FirewallObservation) []const u8 {
    const complete = if (observation.observation_complete == true) "complete readback" else "unknown completeness";
    var stream = std.io.fixedBufferStream(buffer);
    const writer = stream.writer();
    writer.writeAll(complete) catch return complete;
    if (observation.observed_total) |observed|
        writer.print("; {d} observed", .{observed}) catch return complete
    else
        writer.writeAll("; unknown observed") catch return complete;
    if (observation.sample_count) |retained|
        writer.print("; {d} retained", .{retained}) catch return complete
    else
        writer.writeAll("; unknown retained") catch return complete;
    if (observation.sample_truncated == true) writer.writeAll("; sample truncated") catch return complete;
    return stream.getWritten();
}

fn firewallComparison(buffer: []u8, observation: FirewallObservation) []const u8 {
    var comparison_buffer: [diagnostic_max_bytes]u8 = undefined;
    var reason_buffer: [diagnostic_max_bytes]u8 = undefined;
    const comparison_text = observation.comparison orelse return "unknown";
    if (observation.comparison_reason) |reason| {
        const comparison = renderDiagnostic(&comparison_buffer, comparison_text);
        return std.fmt.bufPrint(buffer, "{s} ({s})", .{ comparison, renderDiagnostic(&reason_buffer, reason) }) catch "unknown";
    }
    return renderDiagnostic(buffer, comparison_text);
}

fn firewallAttempt(buffer: []u8, attempt_opt: ?FirewallAttempt) []const u8 {
    const attempt = attempt_opt orelse return "unknown";
    var outcome_buffer: [diagnostic_max_bytes]u8 = undefined;
    var cause_buffer: [diagnostic_max_bytes]u8 = undefined;
    var stage_buffer: [diagnostic_max_bytes]u8 = undefined;
    const outcome = if (attempt.outcome) |value| renderDiagnostic(&outcome_buffer, value) else "unknown";
    var stream = std.io.fixedBufferStream(buffer);
    const writer = stream.writer();
    writer.writeAll(outcome) catch return "unknown";
    if (attempt.cause) |cause| writer.print("; cause={s}", .{renderDiagnostic(&cause_buffer, cause)}) catch return "unknown";
    if (attempt.stage) |stage| writer.print("; stage={s}", .{renderDiagnostic(&stage_buffer, stage)}) catch return "unknown";
    if (attempt.age_ms) |age| writer.print("; {d} ms ago", .{age}) catch return "unknown";
    return stream.getWritten();
}

fn writeFirewallItems(writer: anytype, items: []const FirewallItem, color: Color, columns: usize, details: bool) !void {
    var widest_scope: usize = 0;
    var widest_match: usize = 0;
    for (items) |item| {
        var address: [64]u8 = undefined;
        var safe_address: [diagnostic_max_bytes]u8 = undefined;
        var match: [scope_match_max_bytes]u8 = undefined;
        widest_scope = @max(widest_scope, firewallScopeText(&address, &safe_address, item.scope).len);
        widest_match = @max(widest_match, scopeMatch(&match, item.scope).len);
    }
    const scope_col = colWidth("SCOPE", widest_scope);
    const match_col = colWidth("MATCH", widest_match);
    const full_width = scope_col + match_col + (if (details) @as(usize, 13) else 0) + 18 + 21;
    if (full_width > columns) return writeFirewallItemsStacked(writer, items, color, columns, details);

    try color.on(writer, Color.bold);
    try padRightPrint(writer, "SCOPE", scope_col);
    try padRightPrint(writer, "MATCH", match_col);
    if (details) try padRightPrint(writer, "EFFECT", 13);
    try padRightPrint(writer, "REMAINING@OBS", 18);
    try padRightPrint(writer, "DEADLINE (UTC)", 21);
    try color.off(writer);
    try writer.writeAll("\n");
    try repeatChar(writer, '-', full_width);
    try writer.writeAll("\n");
    for (items) |item| {
        var address: [64]u8 = undefined;
        var safe_address: [diagnostic_max_bytes]u8 = undefined;
        var match: [scope_match_max_bytes]u8 = undefined;
        var effect: [diagnostic_max_bytes]u8 = undefined;
        var remaining: [64]u8 = undefined;
        var deadline: [32]u8 = undefined;
        try writeCell(writer, firewallScopeText(&address, &safe_address, item.scope), scope_col);
        try writeCell(writer, scopeMatch(&match, item.scope), match_col);
        if (details) try writeCell(writer, firewallEffectText(&effect, item.effect_id_hex), 13);
        try writeCell(writer, formatRemainingMilliseconds(&remaining, item.remaining_ms_at_observation), 18);
        try writeCell(writer, if (item.deadline_us == null) "unknown" else formatUtc(&deadline, item.deadline_us), 21);
        try writer.writeAll("\n");
        if (details) try writeFirewallPlacement(writer, item.placement, columns);
    }
    try writer.print("Total: {d} sampled entries\n", .{items.len});
}

fn writeFirewallItemsStacked(writer: anytype, items: []const FirewallItem, color: Color, columns: usize, details: bool) !void {
    for (items, 0..) |item, index| {
        if (index != 0) try writer.writeAll("\n");
        var address: [64]u8 = undefined;
        var safe_address: [diagnostic_max_bytes]u8 = undefined;
        var match: [scope_match_max_bytes]u8 = undefined;
        var effect: [diagnostic_max_bytes]u8 = undefined;
        var remaining: [64]u8 = undefined;
        var deadline: [32]u8 = undefined;
        try color.on(writer, Color.bold);
        try writer.print("ENTRY {d}\n", .{index + 1});
        try color.off(writer);
        try writeFirewallSummaryRow(writer, "Scope:        ", firewallScopeText(&address, &safe_address, item.scope), columns);
        try writeFirewallSummaryRow(writer, "Match:        ", scopeMatch(&match, item.scope), columns);
        if (details) try writeFirewallSummaryRow(writer, "Effect:       ", firewallEffectText(&effect, item.effect_id_hex), columns);
        if (details) try writeFirewallPlacement(writer, item.placement, columns);
        try writeFirewallSummaryRow(writer, "Remaining:    ", formatRemainingMilliseconds(&remaining, item.remaining_ms_at_observation), columns);
        try writeFirewallSummaryRow(writer, "Deadline:     ", if (item.deadline_us == null) "unknown" else formatUtc(&deadline, item.deadline_us), columns);
    }
    try writer.print("Total: {d} sampled entries\n", .{items.len});
}

fn writeFirewallPlacement(writer: anytype, placement_opt: ?FirewallPlacement, columns: usize) !void {
    const placement = placement_opt orelse return;
    var family: [diagnostic_max_bytes]u8 = undefined;
    var table: [diagnostic_max_bytes]u8 = undefined;
    var chain: [diagnostic_max_bytes]u8 = undefined;
    var set: [diagnostic_max_bytes]u8 = undefined;
    var kind: [diagnostic_max_bytes]u8 = undefined;
    try writeFirewallSummaryRow(writer, "Placement kind: ", if (placement.kind) |value| renderDiagnostic(&kind, value) else "unknown", columns);
    try writeFirewallSummaryRow(writer, "Placement family: ", if (placement.family) |value| renderDiagnostic(&family, value) else "-", columns);
    try writeFirewallSummaryRow(writer, "Placement table: ", if (placement.table) |value| renderDiagnostic(&table, value) else "-", columns);
    try writeFirewallSummaryRow(writer, "Placement chain: ", if (placement.chain) |value| renderDiagnostic(&chain, value) else "-", columns);
    try writeFirewallSummaryRow(writer, "Placement set: ", if (placement.set) |value| renderDiagnostic(&set, value) else "-", columns);
}

fn firewallScopeText(raw_buffer: *[64]u8, safe_buffer: *[diagnostic_max_bytes]u8, scope: ?ScopeView) []const u8 {
    return renderDiagnostic(safe_buffer, scopeAddress(raw_buffer, scope));
}

fn firewallEffectText(buffer: *[diagnostic_max_bytes]u8, effect_id_hex: ?[]const u8) []const u8 {
    const value = effect_id_hex orelse return "-";
    return renderDiagnostic(buffer, value);
}

fn formatOptU64Local(opt: ?u64) []const u8 {
    const v = opt orelse return "-";
    return std.fmt.bufPrint(&scratch, "{d}", .{v}) catch "-";
}

fn formatUtc(buffer: *[32]u8, confirmed_us: ?i64) []const u8 {
    const us = confirmed_us orelse return "-";
    if (us < 0) return "out-of-range";
    const secs: u64 = @intCast(@divTrunc(us, std.time.us_per_s));
    const max_supported_utc_seconds: u64 = 253_402_300_799;
    if (secs > max_supported_utc_seconds) return "out-of-range";
    const day = std.time.epoch.EpochSeconds{ .secs = secs };
    const ymd = day.getEpochDay().calculateYearDay().calculateMonthDay();
    const hms = day.getDaySeconds();
    return std.fmt.bufPrint(buffer, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}", .{
        day.getEpochDay().calculateYearDay().year,
        ymd.month.numeric(),
        ymd.day_index + 1,
        hms.getHoursIntoDay(),
        hms.getMinutesIntoHour(),
        hms.getSecondsIntoMinute(),
    }) catch "-";
}

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

const testing = std.testing;

fn runStatus(alloc: std.mem.Allocator, payload: []const u8, fmt: OutputFormat) ![]u8 {
    var list = std.ArrayList(u8).init(alloc);
    errdefer list.deinit();
    try formatStatusForWidth(alloc, list.writer(), payload, fmt, .{ .enabled = false }, 160);
    return list.toOwnedSlice();
}

test "format: status table shows box lines and version" {
    const payload =
        \\{"version":"0.1.0","uptime_seconds":86461,"memory_bytes_used":8388608,
        \\"memory_bytes_limit":67108864,"active_bans":142,"parse_rate":12847.0,
        \\"backend":"nftables","jails_active":8,"total_bans":3891}
    ;
    const out = try runStatus(testing.allocator, payload, .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "+---") != null);
    try testing.expect(std.mem.indexOf(u8, out, "fail2zig 0.1.0") != null);
    try testing.expect(std.mem.indexOf(u8, out, "1d 0h 1m 1s") != null);
    try testing.expect(std.mem.indexOf(u8, out, "nftables") != null);
    try testing.expect(std.mem.indexOf(u8, out, "142") != null);
    try testing.expect(std.mem.indexOf(u8, out, "3891") != null);
    try testing.expect(std.mem.indexOf(u8, out, "(24h)") == null);
    try testing.expect(std.mem.indexOf(u8, out, "8") != null);
}

test "format: BUG-059 status memory percentage handles the full u64 range" {
    const cases = .{
        .{ "18446744073709551615", "1", "17592186044416.0 / 0.0 MB (1844674407370955161500%)" },
        .{ "18446744073709551615", "18446744073709551615", "17592186044416.0 / 17592186044416.0 MB (100%)" },
        .{ "1", "18446744073709551615", "0.0 / 17592186044416.0 MB (0%)" },
        .{ "8388608", "67108864", "8.0 / 64.0 MB (12%)" },
        .{ "3", "2", "0.0 / 0.0 MB (150%)" },
        .{ "0", "1", "0.0 / 0.0 MB (0%)" },
        .{ "18446744073709551615", "0", "-" },
    };
    inline for (cases) |case| {
        const payload = "{\"memory_bytes_used\":" ++ case[0] ++ ",\"memory_bytes_limit\":" ++ case[1] ++ "}";
        const out = try runStatus(testing.allocator, payload, .table);
        defer testing.allocator.free(out);
        const start = (std.mem.indexOf(u8, out, "Memory:") orelse return error.MissingMemoryRow) + "Memory:".len;
        const end = std.mem.indexOfScalarPos(u8, out, start, '\n') orelse return error.MissingMemoryRow;
        try testing.expectEqualStrings(case[2], std.mem.trim(u8, out[start..end], " |\r"));
    }

    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var output: [128]u8 = undefined;
    var stream = std.io.fixedBufferStream(&output);
    try formatStatus(failing.allocator(), stream.writer(), "{\"memory_bytes_used\":18446744073709551615,\"memory_bytes_limit\":1}", .table, .{ .enabled = false });
    try testing.expect(std.mem.indexOf(u8, stream.getWritten(), "could not parse status payload (OutOfMemory)") != null);
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

test "format: status table renders Protection row when present" {
    const payload = "{\"version\":\"0.2.0\",\"protection\":\"log-only\",\"backend\":\"nftables\"}";
    const out = try runStatus(testing.allocator, payload, .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "Protection:") != null);
    try testing.expect(std.mem.indexOf(u8, out, "log-only") != null);
}

test "format: CP-02 status heading is neutral and narrow output is bounded" {
    const payload = "{\"version\":\"v\\t1\",\"protection\":\"degraded\",\"backend\":\"backend-with-a-very-long-name-that-must-not-overflow-a-narrow-terminal\",\"active_bans\":3}";
    const table = try runStatus(testing.allocator, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "— status") != null);
    try testing.expect(std.mem.indexOf(u8, table, "running") == null);
    try testing.expect(std.mem.indexOf(u8, table, "v\\t1") != null);

    var narrow = std.ArrayList(u8).init(testing.allocator);
    defer narrow.deinit();
    try formatStatusForWidth(testing.allocator, narrow.writer(), payload, .table, .{ .enabled = false }, 40);
    try testing.expect(std.mem.indexOf(u8, narrow.items, "Protection:") != null);
    var lines = std.mem.splitScalar(u8, narrow.items, '\n');
    while (lines.next()) |line| if (line.len != 0) try testing.expect(line.len <= 40);
}

test "format: status plain renders protection when present" {
    const payload = "{\"protection\":\"mixed\"}";
    const out = try runStatus(testing.allocator, payload, .plain);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "protection\tmixed") != null);
}

test "format: status table tolerates missing protection (older daemon)" {
    const payload = "{\"backend\":\"nftables\"}";
    const out = try runStatus(testing.allocator, payload, .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "Protection:") != null);
}

test "format: status degraded with protection_cause renders the cause" {
    const payload = "{\"protection\":\"degraded\",\"protection_cause\":\"NftablesUnavailable\",\"backend\":\"none\"}";
    const table = try runStatus(testing.allocator, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "Protection:  DEGRADED (NftablesUnavailable)") != null);
    try testing.expect(std.mem.indexOf(u8, table, "Backend:     none") != null);

    const plain = try runStatus(testing.allocator, payload, .plain);
    defer testing.allocator.free(plain);
    try testing.expect(std.mem.indexOf(u8, plain, "protection\tdegraded\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "protection_cause\tNftablesUnavailable\n") != null);

    const json = try runStatus(testing.allocator, payload, .json);
    defer testing.allocator.free(json);
    try testing.expect(std.mem.indexOf(u8, json, "\"protection_cause\":\"NftablesUnavailable\"") != null);
}

test "format: status degraded without protection_cause renders plain DEGRADED (older daemon)" {
    const payload = "{\"protection\":\"degraded\",\"backend\":\"nftables\"}";
    const table = try runStatus(testing.allocator, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "Protection:  DEGRADED ") != null);
    try testing.expect(std.mem.indexOf(u8, table, "DEGRADED (") == null);
    try testing.expect(std.mem.indexOf(u8, table, "Cause:       unknown") != null);

    const plain = try runStatus(testing.allocator, payload, .plain);
    defer testing.allocator.free(plain);
    try testing.expect(std.mem.indexOf(u8, plain, "protection_cause") == null);
}

test "format: status all-log-only renders Protection log-only and Backend none" {
    const payload = "{\"protection\":\"log-only\",\"backend\":\"none\",\"jails_active\":2}";
    const table = try runStatus(testing.allocator, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "Protection:  log-only ") != null);
    try testing.expect(std.mem.indexOf(u8, table, "Backend:     none ") != null);
    try testing.expect(std.mem.indexOf(u8, table, "DEGRADED") == null);
}

test "format: BUG-054 status renders simultaneous scoped degradation details" {
    const payload =
        \\{"protection":"degraded","storage":"paused","cause":"StorageFull","sqlite_code":13,
        \\"next_retry_ms":18446744073709551615,"unhealthy_sources":2,"effects_uncertain":true,
        \\"overdue_effects":3,"effect_backend":"nftables","effect_stage":"dispatch",
        \\"effect_cause":"PermissionDenied","effect_mutation":"not_started",
        \\"worker_busy":true,"worker_stalled":true,"worker_busy_age_ms":6001,
        \\"worker_heartbeat_age_ms":7002,"clock_uncertain":true,"expiry_overdue":true,
        \\"expiry_uncertain":true,"next_committed_expiry_us":-42}
    ;
    const table = try runStatus(testing.allocator, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "Protection:  DEGRADED ") != null);
    try testing.expect(std.mem.indexOf(u8, table, "Protection:  DEGRADED (") == null);
    try testing.expect(std.mem.indexOf(u8, table, "Storage:     paused") != null);
    try testing.expect(std.mem.indexOf(u8, table, "Cause:       StorageFull") != null);
    try testing.expect(std.mem.indexOf(u8, table, "SQLite code: 13") != null);
    try testing.expect(std.mem.indexOf(u8, table, "Retry at:    18446744073709551615 ms monotonic") != null);
    try testing.expect(std.mem.indexOf(u8, table, "Sources:     2 unhealthy; inspect fail2zig jails") != null);
    try testing.expect(std.mem.indexOf(u8, table, "Effects:     uncertain; 3 overdue") != null);
    try testing.expect(std.mem.indexOf(u8, table, "Effect:      nftables") != null);
    try testing.expect(std.mem.indexOf(u8, table, "  Stage:     dispatch") != null);
    try testing.expect(std.mem.indexOf(u8, table, "  Cause:     PermissionDenied") != null);
    try testing.expect(std.mem.indexOf(u8, table, "  Attempt:   not_started") != null);
    try testing.expect(std.mem.indexOf(u8, table, "Worker:      stalled; busy 6001 ms; heartbeat 7002 ms ago") != null);
    try testing.expect(std.mem.indexOf(u8, table, "Clock:       uncertain") != null);
    try testing.expect(std.mem.indexOf(u8, table, "Expiry:      overdue; view uncertain; next committed -42 us") != null);

    const plain = try runStatus(testing.allocator, payload, .plain);
    defer testing.allocator.free(plain);
    try testing.expect(std.mem.indexOf(u8, plain, "storage\tpaused\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "cause\tStorageFull\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "sqlite_code\t13\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "next_retry_ms\t18446744073709551615\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "unhealthy_sources\t2\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "effect_backend\tnftables\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "effect_stage\tdispatch\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "effect_cause\tPermissionDenied\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "effect_mutation\tnot_started\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "effects_uncertain\ttrue\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "worker_stalled\ttrue\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "clock_uncertain\ttrue\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "next_committed_expiry_us\t-42\n") != null);
}

test "format: BUG-054 healthy log-only status does not invent fault context" {
    const payload =
        \\{"protection":"log-only","backend":"none","storage":"healthy","cause":"none",
        \\"unhealthy_sources":0,"effects_uncertain":false,"overdue_effects":0,
        \\"worker_busy":false,"worker_stalled":false,"worker_busy_age_ms":0,
        \\"worker_heartbeat_age_ms":7,"clock_uncertain":false,"expiry_overdue":false,
        \\"expiry_uncertain":false}
    ;
    const table = try runStatus(testing.allocator, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "Protection:  log-only") != null);
    try testing.expect(std.mem.indexOf(u8, table, "Storage:     healthy") != null);
    try testing.expect(std.mem.indexOf(u8, table, "Cause:") == null);
    try testing.expect(std.mem.indexOf(u8, table, "Sources:") == null);
    try testing.expect(std.mem.indexOf(u8, table, "Effects:") == null);
    try testing.expect(std.mem.indexOf(u8, table, "Effect:") == null);
    try testing.expect(std.mem.indexOf(u8, table, "Worker:") == null);
    try testing.expect(std.mem.indexOf(u8, table, "Clock:") == null);
    try testing.expect(std.mem.indexOf(u8, table, "Expiry:") == null);

    const plain = try runStatus(testing.allocator, payload, .plain);
    defer testing.allocator.free(plain);
    try testing.expect(std.mem.indexOf(u8, plain, "cause\tnone\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "effects_uncertain\tfalse\n") != null);
}

test "format: BUG-054 diagnostic strings are escaped and capped without splitting UTF-8" {
    const payload =
        \\{"protection":"degraded","protection_cause":"bad\nline\tcol\u001b\\tail",
        \\"storage":"paused\\rstate","cause":"éééééééééééééééééééééééééééééééééééééééééééééééééééééééééééé"}
    ;
    const table = try runStatus(testing.allocator, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.unicode.utf8ValidateSlice(table));
    try testing.expect(std.mem.indexOf(u8, table, "bad\\nline\\tcol\\x1B\\\\tail") != null);
    try testing.expect(std.mem.indexOf(u8, table, "paused\\\\rstate") != null);
    try testing.expect(std.mem.indexOf(u8, table, "...") != null);
    try testing.expect(std.mem.indexOf(u8, table, "\x1b") == null);

    const plain = try runStatus(testing.allocator, payload, .plain);
    defer testing.allocator.free(plain);
    try testing.expect(std.unicode.utf8ValidateSlice(plain));
    try testing.expect(std.mem.indexOf(u8, plain, "protection_cause\tbad\\nline\\tcol\\x1B\\\\tail\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "\nline") == null);
}

test "format: BUG-054 diagnostic renderer handles zero and tiny capacities" {
    var empty: [0]u8 = .{};
    try testing.expectEqual(@as(usize, 0), renderDiagnostic(&empty, "hostile\nvalue").len);
    var tiny: [2]u8 = undefined;
    try testing.expectEqualStrings("..", renderDiagnostic(&tiny, "hostile\nvalue"));
}

test "format: diagnostic renderer escapes C1 and bidi controls atomically" {
    const hostile = "oké\u{009b}\u{061c}\u{200e}\u{202e}\u{2066}雪";
    var buffer: [diagnostic_max_bytes]u8 = undefined;
    try testing.expectEqualStrings(
        "oké\\xC2\\x9B\\xD8\\x9C\\xE2\\x80\\x8E\\xE2\\x80\\xAE\\xE2\\x81\\xA6雪",
        renderDiagnostic(&buffer, hostile),
    );

    var tight: [11]u8 = undefined;
    try testing.expectEqualStrings("...", renderDiagnostic(&tight, "\u{202e}"));
    try testing.expect(isUnsafeUnicodeControl(0x80));
    try testing.expect(isUnsafeUnicodeControl(0x9f));
    try testing.expect(isUnsafeUnicodeControl(0x202a));
    try testing.expect(isUnsafeUnicodeControl(0x2069));
    try testing.expect(!isUnsafeUnicodeControl(0x200d));
    try testing.expect(!isUnsafeUnicodeControl(0x206a));
}

test "format: status escapes Unicode controls in effect diagnostics" {
    const payload =
        \\{"protection":"degraded","cause":"safe\u009bspoof\u202e",
        \\"effect_backend":"nft\u2066","effect_stage":"verify","effect_cause":"Denied\u061c",
        \\"effect_mutation":"outcome_uncertain"}
    ;
    const table = try runStatus(testing.allocator, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "safe\\xC2\\x9Bspoof\\xE2\\x80\\xAE") != null);
    try testing.expect(std.mem.indexOf(u8, table, "Effect:      nft\\xE2\\x81\\xA6") != null);
    try testing.expect(std.mem.indexOf(u8, table, "  Cause:     Denied\\xD8\\x9C") != null);
    try testing.expect(std.mem.indexOf(u8, table, "  Attempt:   outcome_uncertain") != null);
    try testing.expect(std.mem.indexOf(u8, table, "\u{009b}") == null);
    try testing.expect(std.mem.indexOf(u8, table, "\u{202e}") == null);

    const plain = try runStatus(testing.allocator, payload, .plain);
    defer testing.allocator.free(plain);
    try testing.expect(std.mem.indexOf(u8, plain, "effect_backend\tnft\\xE2\\x81\\xA6\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "effect_mutation\toutcome_uncertain\n") != null);
}

test "format: BUG-054 status JSON remains byte-for-byte passthrough" {
    const payload = "{\"protection\":\"degraded\",\"cause\":\"x\\n y\",\"future\":{\"field\":1}}\n";
    const json = try runStatus(testing.allocator, payload, .json);
    defer testing.allocator.free(json);
    try testing.expectEqualStrings(payload, json);
}

test "format: status reports parser allocation failure without retaining diagnostics" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var output: [128]u8 = undefined;
    var stream = std.io.fixedBufferStream(&output);
    try formatStatus(failing.allocator(), stream.writer(), "{\"cause\":\"StorageFull\"}", .plain, .{ .enabled = false });
    try testing.expect(std.mem.indexOf(u8, stream.getWritten(), "could not parse status payload (OutOfMemory)") != null);
}

fn runList(alloc: std.mem.Allocator, payload: []const u8, fmt: OutputFormat) ![]u8 {
    var list = std.ArrayList(u8).init(alloc);
    errdefer list.deinit();
    try formatListForWidth(alloc, list.writer(), payload, fmt, .{ .enabled = false }, 160);
    return list.toOwnedSlice();
}

test "format: list table with entries (daemon-shape JSON, SYS-002)" {
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
    try testing.expect(std.mem.startsWith(u8, out, "1.2.3.4\tsshd\t"));
    try testing.expect(std.mem.endsWith(u8, out, "\t2\n"));
}

test "format: BUG-040 list preserves network CIDR and ordinary host presentation" {
    const payload = "[{\"ip\":\"192.0.2.0/24\",\"jail\":\"sshd\",\"ban_count\":1},{\"ip\":\"198.51.100.7\",\"jail\":\"sshd\",\"ban_count\":2}]";

    const json = try runList(testing.allocator, payload, .json);
    defer testing.allocator.free(json);
    try testing.expect(std.mem.indexOf(u8, json, "\"ip\":\"192.0.2.0/24\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"ip\":\"198.51.100.7\"") != null);

    const plain = try runList(testing.allocator, payload, .plain);
    defer testing.allocator.free(plain);
    try testing.expect(std.mem.indexOf(u8, plain, "192.0.2.0/24\tsshd\t") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "198.51.100.7\tsshd\t") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "198.51.100.7/32") == null);

    const table = try runList(testing.allocator, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "192.0.2.0/24") != null);
    try testing.expect(std.mem.indexOf(u8, table, "198.51.100.7") != null);
    try testing.expect(std.mem.indexOf(u8, table, "198.51.100.7/32") == null);
}

test "format: list expired entry shows 'expired' (SYS-002)" {
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

test "format: CP-02 list distinguishes permanent confirmed pending and unknown" {
    const payload = "[{\"ip\":\"192.0.2.1\",\"jail\":\"sshd\",\"ban_count\":1,\"permanent\":true,\"confirmed\":true},{\"ip\":\"192.0.2.2\",\"jail\":\"sshd\",\"ban_count\":2,\"ban_expiry\":9999999999,\"enforced\":false},{\"ip\":\"192.0.2.3\",\"jail\":\"sshd\",\"ban_count\":3}]";
    const table = try runList(testing.allocator, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "permanent") != null);
    try testing.expect(std.mem.indexOf(u8, table, "confirmed") != null);
    try testing.expect(std.mem.indexOf(u8, table, "pending") != null);
    try testing.expect(std.mem.indexOf(u8, table, "unknown") != null);

    const plain = try runList(testing.allocator, payload, .plain);
    defer testing.allocator.free(plain);
    try testing.expectEqual(@as(usize, 9), std.mem.count(u8, plain, "\t"));
    try testing.expect(std.mem.indexOf(u8, plain, "permanent") == null);

    const json = try runList(testing.allocator, payload, .json);
    defer testing.allocator.free(json);
    try testing.expectEqualStrings(payload ++ "\n", json);
}

test "format: CP-02 list narrow fallback keeps core meaning" {
    const payload = "[{\"ip\":\"192.0.2.1\",\"jail\":\"ssh\\tadmin\",\"permanent\":true,\"confirmed\":false}]";
    var out = std.ArrayList(u8).init(testing.allocator);
    defer out.deinit();
    try formatListForWidth(testing.allocator, out.writer(), payload, .table, .{ .enabled = false }, 40);
    try testing.expect(std.mem.indexOf(u8, out.items, "IP ADDRESS:") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "ssh\\tadmin") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "permanent") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "pending") != null);
    var lines = std.mem.splitScalar(u8, out.items, '\n');
    while (lines.next()) |line| if (line.len != 0) try testing.expect(line.len <= 40);
}

test "format: CP-02 ban expiry saturates hostile timestamps" {
    const min = std.math.minInt(i64);
    const max = std.math.maxInt(i64);
    try testing.expectEqual(max, remainingFromExpiry(max, min).?);
    try testing.expectEqual(min, remainingFromExpiry(min, max).?);
}

test "format: list rejects object-shape payload (SYS-002 regression)" {
    const payload = "{\"entries\":[]}";
    const out = try runList(testing.allocator, payload, .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "error: could not parse list payload") != null);
}

fn runJails(alloc: std.mem.Allocator, payload: []const u8, fmt: OutputFormat) ![]u8 {
    var list = std.ArrayList(u8).init(alloc);
    errdefer list.deinit();
    try formatJailsForWidth(alloc, list.writer(), payload, fmt, .{ .enabled = false }, 160);
    return list.toOwnedSlice();
}

test "format: jails table (daemon-shape JSON, SYS-002)" {
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
    try testing.expect(std.mem.indexOf(u8, out, "TOTAL") == null);
    try testing.expect(std.mem.indexOf(u8, out, "BACKEND") == null);
}

test "format: jails plain (SYS-002)" {
    const payload = "[{\"name\":\"sshd\",\"enabled\":true,\"active_bans\":1,\"maxretry\":3,\"findtime\":600,\"bantime\":300}]";
    const out = try runJails(testing.allocator, payload, .plain);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "sshd\tenabled\t1\t3\t600\t300\t-\t-\t-\tunknown\t0\n") != null);
}

test "format: jails empty table (SYS-002)" {
    const out = try runJails(testing.allocator, "[]", .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "No jails") != null);
}

test "format: jails human duration formatting (SYS-002)" {
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

test "format: jails table renders action and enforcing (SYS-017)" {
    const payload =
        \\[
        \\  {"name":"sshd","enabled":true,"active_bans":0,"maxretry":3,"findtime":600,"bantime":3600,"action":"nftables","enforcing":true},
        \\  {"name":"sshd-test","enabled":true,"active_bans":0,"maxretry":3,"findtime":600,"bantime":600,"action":"log-only","enforcing":false}
        \\]
    ;
    const out = try runJails(testing.allocator, payload, .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "ACTION") != null);
    try testing.expect(std.mem.indexOf(u8, out, "ENFORCING") != null);
    try testing.expect(std.mem.indexOf(u8, out, "nftables") != null);
    try testing.expect(std.mem.indexOf(u8, out, "log-only") != null);
    try testing.expect(std.mem.indexOf(u8, out, "true") != null);
    try testing.expect(std.mem.indexOf(u8, out, "false") != null);
}

test "format: jails plain renders action and enforcing (SYS-017)" {
    const payload = "[{\"name\":\"sshd-test\",\"enabled\":true,\"active_bans\":0,\"maxretry\":3,\"findtime\":600,\"bantime\":600,\"action\":\"log-only\",\"enforcing\":false}]";
    const out = try runJails(testing.allocator, payload, .plain);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "sshd-test\tenabled\t0\t3\t600\t600\tlog-only\tfalse\t-\tunknown\t0\n") != null);
}

test "format: CP-02 jails show paused without changing plain columns" {
    const payload = "[{\"name\":\"sshd\",\"enabled\":true,\"paused\":true,\"active_bans\":1,\"action\":\"nftables\",\"source_healthy\":true}]";
    const table = try runJails(testing.allocator, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "paused") != null);

    const plain = try runJails(testing.allocator, payload, .plain);
    defer testing.allocator.free(plain);
    try testing.expectEqual(@as(usize, 10), std.mem.count(u8, plain, "\t"));
    try testing.expect(std.mem.indexOf(u8, plain, "\tenabled\t") != null);
}

test "format: CP-02 jails keep an absent enabled field unknown in tables" {
    const payload = "[{\"name\":\"sshd\"}]";
    const table = try runJails(testing.allocator, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "sshd unknown") != null);

    const plain = try runJails(testing.allocator, payload, .plain);
    defer testing.allocator.free(plain);
    try testing.expect(std.mem.indexOf(u8, plain, "sshd\tdisabled\t") != null);
}

test "format: CP-02 jails narrow fallback escapes untrusted text" {
    const payload = "[{\"name\":\"ssh\\nadmin\",\"enabled\":true,\"paused\":true,\"active_bans\":1,\"action\":\"nf\\tables\",\"source_healthy\":false,\"cause\":\"bad\"}]";
    var out = std.ArrayList(u8).init(testing.allocator);
    defer out.deinit();
    try formatJailsForWidth(testing.allocator, out.writer(), payload, .table, .{ .enabled = false }, 40);
    try testing.expect(std.mem.indexOf(u8, out.items, "ssh\\nadmin") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "nf\\tables") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "paused") != null);
    var lines = std.mem.splitScalar(u8, out.items, '\n');
    while (lines.next()) |line| if (line.len != 0) try testing.expect(line.len <= 40);
}

test "format: status renders protection degraded (SYS-017)" {
    const payload = "{\"protection\":\"degraded\",\"total_bans\":7,\"jails_active\":2}";
    const table = try runStatus(testing.allocator, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "Protection:  DEGRADED ") != null);
    try testing.expect(std.mem.indexOf(u8, table, "Total bans:") != null);
    try testing.expect(std.mem.indexOf(u8, table, "7") != null);

    const plain = try runStatus(testing.allocator, payload, .plain);
    defer testing.allocator.free(plain);
    try testing.expect(std.mem.indexOf(u8, plain, "protection\tdegraded") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "total_bans\t7") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "jails_active\t2") != null);
}

test "format: jails table renders source + health, tints broken (SYS-017)" {
    const payload =
        \\[
        \\  {"name":"sshd","enabled":true,"active_bans":0,"maxretry":3,"findtime":600,"bantime":3600,"action":"nftables","enforcing":true,"log_source":"journald (sshd)","source_healthy":false,"lines_seen":0},
        \\  {"name":"nginx","enabled":true,"active_bans":0,"maxretry":3,"findtime":600,"bantime":600,"action":"nftables","enforcing":true,"log_source":"/var/log/nginx/error.log","lines_seen":12}
        \\]
    ;
    const out = try runJails(testing.allocator, payload, .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "SOURCE") != null);
    try testing.expect(std.mem.indexOf(u8, out, "HEALTH") != null);
    try testing.expect(std.mem.indexOf(u8, out, "journald (sshd)") != null);
    try testing.expect(std.mem.indexOf(u8, out, "broken") != null);
    try testing.expect(std.mem.indexOf(u8, out, "/var/log/nginx/error.log") != null);
    try testing.expect(std.mem.indexOf(u8, out, "unknown") != null);
}

test "format: BUG-054 jail cause is bounded in HEALTH while plain stays eleven escaped columns" {
    const payload =
        \\[{"name":"ssh\tadmin\nrow\u2066","enabled":true,"active_bans":1,"maxretry":3,
        \\"findtime":600,"bantime":3600,"action":"log-only","enforcing":false,
        \\"log_source":"journal","source_healthy":false,"lines_seen":9,
        \\"cause":"JournalChildFailed\nnext","source_exit_code":7,"source_signal":9,
        \\"source_stderr_present":true}]
    ;
    const table = try runJails(testing.allocator, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "ssh\\tadmin\\nrow\\xE2\\x81\\xA6") != null);
    try testing.expect(std.mem.indexOf(u8, table, "broken (JournalChildFailed\\nnext; exit=7; signal=9; stderr)") != null);
    try testing.expect(std.mem.indexOf(u8, table, "\nrow") == null);

    const plain = try runJails(testing.allocator, payload, .plain);
    defer testing.allocator.free(plain);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, plain, "\n"));
    try testing.expectEqual(@as(usize, 10), std.mem.count(u8, plain, "\t"));
    try testing.expect(std.mem.startsWith(u8, plain, "ssh\\tadmin\\nrow\\xE2\\x81\\xA6\tenabled\t"));
    try testing.expect(std.mem.indexOf(u8, plain, "JournalChildFailed") == null);
}

test "format: BUG-054 unhealthy jail without a cause reports unknown" {
    const payload = "[{\"name\":\"sshd\",\"source_healthy\":false,\"cause\":\"none\"}]";
    const table = try runJails(testing.allocator, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "broken (unknown)") != null);
}

test "format: jails table tolerates missing source fields (older daemon, SYS-017)" {
    const payload = "[{\"name\":\"sshd\",\"enabled\":true,\"active_bans\":0,\"maxretry\":3,\"findtime\":600,\"bantime\":3600,\"action\":\"nftables\",\"enforcing\":true}]";
    const out = try runJails(testing.allocator, payload, .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "SOURCE") != null);
    try testing.expect(std.mem.indexOf(u8, out, "unknown") != null);
    try testing.expect(std.mem.indexOf(u8, out, "sshd") != null);
}

fn lineLens(out: []const u8) [3]usize {
    var it = std.mem.splitScalar(u8, out, '\n');
    return .{ it.next().?.len, it.next().?.len, it.next().?.len };
}

test "format: jails table sizes SOURCE from the longest path, keeps HEALTH separator (BUG-008)" {
    const payload =
        \\[
        \\  {"name":"sshd","enabled":true,"log_source":"journald (sshd)","source_healthy":true},
        \\  {"name":"recidive","enabled":true,"log_source":"/var/log/fail2zig/fail2zig.log"}
        \\]
    ;
    const out = try runJails(testing.allocator, payload, .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "/var/log/fail2zig/fail2zig.log unknown") != null);
    try testing.expect(std.mem.indexOf(u8, out, "journald (sshd)                ok") != null);
    try testing.expect(std.mem.indexOf(u8, out, "fail2zig.logunknown") == null);
    const lens = lineLens(out);
    try testing.expectEqual(lens[0], lens[1]);
    try testing.expectEqual(lens[0], lens[2]);
}

test "format: jails table ellipsis-truncates SOURCE beyond the column cap (BUG-008)" {
    const payload = "[{\"name\":\"web\",\"enabled\":true,\"log_source\":\"/srv/very/deeply/nested/path/to/some/application/logs/access.log\",\"source_healthy\":false}]";
    const out = try runJails(testing.allocator, payload, .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "access.log") == null);
    try testing.expect(std.mem.indexOf(u8, out, "/srv/very/deeply/nested/path/to/some/applicat... broken") != null);
    const lens = lineLens(out);
    try testing.expectEqual(lens[0], lens[1]);
    try testing.expectEqual(lens[0], lens[2]);
}

test "format: jails table SOURCE truncation never splits a UTF-8 sequence (BUG-008)" {
    const payload = "[{\"name\":\"web\",\"enabled\":true,\"log_source\":\"/var/log/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaééééé.log\"}]";
    const out = try runJails(testing.allocator, payload, .table);
    defer testing.allocator.free(out);
    try testing.expect(std.unicode.utf8ValidateSlice(out));
    try testing.expect(std.mem.indexOf(u8, out, "aaa...  unknown") != null);
    const lens = lineLens(out);
    try testing.expectEqual(lens[0], lens[1]);
    try testing.expectEqual(lens[0], lens[2]);
}

test "format: jails table sizes JAIL from a 40-char jail name (BUG-010)" {
    const payload = "[{\"name\":\"nginx-http-auth-strict-mode-for-tenant-a\",\"enabled\":true},{\"name\":\"sshd\",\"enabled\":false}]";
    const out = try runJails(testing.allocator, payload, .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "nginx-http-auth-strict-mode-for-tenant-a enabled") != null);
    try testing.expect(std.mem.indexOf(u8, out, "tenant-aenabled") == null);
    const lens = lineLens(out);
    try testing.expectEqual(lens[0], lens[1]);
    try testing.expectEqual(lens[0], lens[2]);
}

test "format: list table sizes IP ADDRESS and JAIL from the longest values (BUG-010)" {
    const payload = "[{\"ip\":\"2001:0db8:85a3:0000:0000:8a2e:0370:7334\",\"jail\":\"nginx-http-auth-strict-mode-for-tenant-a\",\"ban_count\":1,\"ban_expiry\":1},{\"ip\":\"1.2.3.4\",\"jail\":\"sshd\",\"ban_count\":2,\"ban_expiry\":1}]";
    const out = try runList(testing.allocator, payload, .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "2001:0db8:85a3:0000:0000:8a2e:0370:7334 nginx-http-auth-strict-mode-for-tenant-a ") != null);
    try testing.expect(std.mem.indexOf(u8, out, "7334nginx") == null);
    try testing.expect(std.mem.indexOf(u8, out, "tenant-a") != null);
    const lens = lineLens(out);
    try testing.expectEqual(lens[0], lens[1]);
    try testing.expectEqual(lens[0], lens[2]);
}

test "format: list table TIME LEFT sized for a decades-long ban (BUG-011)" {
    const payload = "[{\"ip\":\"1.2.3.4\",\"jail\":\"sshd\",\"ban_count\":4294967295,\"ban_expiry\":9999999999},{\"ip\":\"5.6.7.8\",\"jail\":\"sshd\",\"ban_count\":1,\"ban_expiry\":1}]";
    const out = try runList(testing.allocator, payload, .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "expired") != null);
    const lens = lineLens(out);
    try testing.expectEqual(lens[0], lens[1]);
    try testing.expectEqual(lens[0], lens[2]);
    var it = std.mem.splitScalar(u8, out, '\n');
    const header = it.next().?;
    _ = it.next();
    const first_row = it.next().?;
    const time_start = std.mem.indexOf(u8, header, "TIME LEFT").?;
    const confirmation_start = std.mem.indexOf(u8, header, "CONFIRMATION").?;
    const count_start = std.mem.indexOf(u8, header, "BAN COUNT").?;
    try testing.expect(time_start < confirmation_start);
    try testing.expect(confirmation_start < count_start);
    const time_value = std.mem.trim(u8, first_row[time_start..confirmation_start], " ");
    const confirmation_value = std.mem.trim(u8, first_row[confirmation_start..count_start], " ");
    const count_value = std.mem.trim(u8, first_row[count_start..], " ");
    try testing.expect(time_value.len > 1);
    try testing.expect(std.mem.endsWith(u8, time_value, "s"));
    try testing.expectEqualStrings("unknown", confirmation_value);
    try testing.expectEqualStrings("4294967295", count_value);
    try testing.expectEqual(lens[0], it.next().?.len);
}

test "format: jails table every column keeps its separator at extreme values (BUG-011)" {
    const payload = "[{\"name\":\"sshd\",\"enabled\":false,\"active_bans\":4294967295,\"maxretry\":4294967295,\"findtime\":4294967295,\"bantime\":4294967295,\"action\":\"a-very-long-action-name-here\",\"enforcing\":false,\"log_source\":\"x\",\"source_healthy\":true}]";
    const out = try runJails(testing.allocator, payload, .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "sshd disabled 4294967295 4294967295 49710d    49710d   a-very-long-action-name-here false     x      ok") != null);
    const lens = lineLens(out);
    try testing.expectEqual(lens[0], lens[1]);
    try testing.expectEqual(lens[0], lens[2]);
}

test "format: status box widens for a long value (BUG-011)" {
    const payload = "{\"backend\":\"nftables-with-an-unusually-long-descriptive-backend-name\",\"active_bans\":3}";
    const out = try runStatus(testing.allocator, payload, .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "nftables-with-an-unusually-long-descriptive-backend-name |") != null);
    var it = std.mem.splitScalar(u8, out, '\n');
    const top = it.next().?;
    _ = it.next();
    _ = it.next();
    while (it.next()) |line| {
        if (line.len == 0) break;
        try testing.expectEqual(top.len, line.len);
    }
}

fn runVersion(alloc: std.mem.Allocator, payload: []const u8, fmt: OutputFormat) ![]u8 {
    var list = std.ArrayList(u8).init(alloc);
    errdefer list.deinit();
    try formatVersion(alloc, list.writer(), "0.1.0", payload, fmt, .{ .enabled = false });
    return list.toOwnedSlice();
}

test "format: version table combines matching client and daemon versions" {
    const payload = "{\"daemon_version\":\"0.1.0\",\"git_commit\":\"abc123\"}";
    const out = try runVersion(testing.allocator, payload, .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.startsWith(u8, out, "fail2zig 0.1.0 (client and daemon)\n"));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, out, "0.1.0"));
    try testing.expect(std.mem.indexOf(u8, out, "abc123") != null);
}

test "format: version table distinguishes mismatched client and daemon" {
    const out = try runVersion(testing.allocator, "{\"daemon_version\":\"0.2.0\"}", .table);
    defer testing.allocator.free(out);
    try testing.expectEqualStrings("Client: fail2zig 0.1.0\nDaemon: fail2zig 0.2.0\n", out);
}

test "format: version table reports missing metadata without inventing a connection failure" {
    for ([_][]const u8{ "", "{}", "{\"daemon_version\":null}" }) |payload| {
        const out = try runVersion(testing.allocator, payload, .table);
        defer testing.allocator.free(out);
        try testing.expectEqualStrings("Client: fail2zig 0.1.0\nDaemon: version unavailable\n", out);
    }
}

test "format: version table rejects malformed payload and escapes terminal data" {
    try testing.expectError(error.UnexpectedEndOfInput, runVersion(testing.allocator, "{", .table));
    const out = try runVersion(testing.allocator, "{\"daemon_version\":\"0.2.0\\u001b[2J\",\"git_commit\":\"a\\nb\"}", .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOfScalar(u8, out, 0x1b) == null);
    try testing.expect(std.mem.indexOf(u8, out, "a\nb") == null);
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

const config_payload =
    \\{"schema_version":1,"generation":"ab12","redacted":false,"jails":[
    \\{"name":"sshd","enabled":true,"filter":"sshd","source":"journal","logpath":["/var/log/auth.log"],
    \\"maxretry":5,"findtime":600,"bantime":3600,"bantime_permanent":false,"banaction":"nftables","ignoreip":["127.0.0.1/8","192.0.2.0/24"]},
    \\{"name":"nginx","enabled":false,"filter":"nginx-http-auth","source":"file","logpath":[],
    \\"maxretry":3,"findtime":60,"bantime":0,"bantime_permanent":true,"banaction":"nftables","ignoreip":[]}],
    \\"global":{"log_level":"info","firewall":"nftables","metrics_enabled":true,"metrics_bind":"127.0.0.1","metrics_port":9101,
    \\"socket_path":"/run/fail2zig/fail2zig.sock","state_file":"/var/lib/fail2zig/state.sqlite","dns_server":null,"timezone_root":null}}
;

const scopes_payload =
    \\{"schema_version":1,"generation":"ab12","items":[
    \\{"jail":"sshd","scope":{"family":"v4","address":"192.0.2.1","prefix":32},"lease":"finite","deadline_us":4102444800000000,"decision_id_hex":"0101010101010101abcd","confirmed":true},
    \\{"jail":"nginx","scope":{"family":"v6","address":"2001:db8::","prefix":64,"protocol":"tcp","port":22},"lease":"permanent","deadline_us":null,"decision_id_hex":null,"confirmed":false}],
    \\"next_cursor":"czoxOjA"}
;

const history_payload =
    \\{"schema_version":1,"generation":"ab12","items":[
    \\{"sequence":7,"event_id_hex":"ee","jail":"sshd","decision_id_hex":"1111111111111111ffff","confirmed_us":1700000000000000,"scope":{"family":"v4","address":"192.0.2.9","prefix":32},"native_retry":true}],
    \\"next_cursor":null}
;

const firewall_payload =
    \\{"schema_version":1,"generation":"ab12","kind":"firewall","available":true,"unavailable_reason":null,
    \\"installation":{"id_hex":"00112233445566778899aabbccddeeff","backend":"nftables","namespace":"daemon-current"},
    \\"observation":{"id":"00112233445566778899aabbccddeeff:7","state":"owned","observed_wall_us":1700000000000000,"age_ms":25,
    \\"observation_complete":true,"observed_total":2,"sample_count":2,"sample_truncated":false,"inventory":"known_entries",
    \\"origin":"normal_readback","comparison":"unavailable","comparison_reason":"intent_revision_not_aligned"},
    \\"last_attempt":{"outcome":"success","cause":null,"stage":null,"age_ms":25},"items":[
    \\{"scope":{"family":"v4","address":"192.0.2.9","prefix":32,"subject_kind":"host","protocols":["tcp","udp"],
    \\"port_ranges":[{"first":53,"last":53},{"first":8000,"last":8010}],"legacy_exact":false,"direction":"input","target":"drop"},
    \\"effect_id_hex":"1111111111111111ffff","remaining_ms_at_observation":3000,"deadline_us":1700000003000000},
    \\{"scope":{"family":"v6","address":"2001:db8::","prefix":64,"subject_kind":"network","protocols":["all"],
    \\"port_ranges":[],"legacy_exact":true,"direction":"input","target":"drop"},"effect_id_hex":null,
    \\"remaining_ms_at_observation":null,"deadline_us":null}],"next_cursor":"fw-token"}
;

fn runFormatter(comptime formatter: anytype, payload: []const u8, fmt: OutputFormat) ![]u8 {
    var list = std.ArrayList(u8).init(testing.allocator);
    errdefer list.deinit();
    try formatter(testing.allocator, list.writer(), payload, fmt, .{ .enabled = false });
    return list.toOwnedSlice();
}

test "format: status renders the generation field in plain and table" {
    const payload = "{\"version\":\"0.4.0\",\"generation\":\"abcdef0123\",\"active_bans\":1}";
    const plain = try runStatus(testing.allocator, payload, .plain);
    defer testing.allocator.free(plain);
    try testing.expect(std.mem.indexOf(u8, plain, "generation\tabcdef0123") != null);
    const table = try runStatus(testing.allocator, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "Generation:  abcdef0123") != null);
}

test "format: config json passes through unchanged" {
    const out = try runFormatter(formatConfig, config_payload, .json);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.startsWith(u8, out, config_payload));
    try testing.expect(out[out.len - 1] == '\n');
}

test "format: config plain is key-tab-value with dotted jail keys" {
    const out = try runFormatter(formatConfig, config_payload, .plain);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "generation\tab12\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "redacted\tfalse\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "global.socket_path\t/run/fail2zig/fail2zig.sock\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "global.dns_server\t-\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "jail.sshd.ignoreip\t127.0.0.1/8,192.0.2.0/24\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "jail.nginx.bantime_permanent\ttrue\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "jail.nginx.logpath\t\n") != null);
}

test "format: config table shows global block and jail rows" {
    const out = try runFormatter(formatConfig, config_payload, .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "GLOBAL\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "metrics          true (127.0.0.1:9101)") != null);
    try testing.expect(std.mem.indexOf(u8, out, "JAILS\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "JAIL") != null);
    try testing.expect(std.mem.indexOf(u8, out, "enabled") != null);
    try testing.expect(std.mem.indexOf(u8, out, "permanent") != null);
    try testing.expect(std.mem.indexOf(u8, out, "10m") != null);
    try testing.expect(std.mem.indexOf(u8, out, "Total: 2 jails") != null);
    try testing.expect(std.mem.indexOf(u8, out, "redacted") == null);
}

test "format: redacted config table warns and keeps placeholders" {
    const payload = "{\"generation\":\"g\",\"redacted\":true,\"jails\":[{\"name\":\"sshd\",\"enabled\":true,\"logpath\":[\"<redacted>\"],\"ignoreip\":[\"<redacted>\"]}],\"global\":{\"socket_path\":\"<redacted>\"}}";
    const table = try runFormatter(formatConfig, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "redacted for monitor access") != null);
    try testing.expect(std.mem.indexOf(u8, table, "socket_path      <redacted>") != null);
    const plain = try runFormatter(formatConfig, payload, .plain);
    defer testing.allocator.free(plain);
    try testing.expect(std.mem.indexOf(u8, plain, "jail.sshd.ignoreip\t<redacted>\n") != null);
}

test "format: scopes json passes through" {
    const out = try runFormatter(formatScopes, scopes_payload, .json);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.startsWith(u8, out, scopes_payload));
}

test "format: scopes plain lists indexed items and the next cursor" {
    const out = try runFormatter(formatScopes, scopes_payload, .plain);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "items.0.jail\tsshd\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "items.0.scope\t192.0.2.1\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "items.0.match\tany\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "items.0.deadline_us\t4102444800000000\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "items.1.scope\t2001:db8::/64\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "items.1.match\ttcp/22\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "items.1.deadline_us\t-\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "items.1.decision_id\t-\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "next_cursor\tczoxOjA\n") != null);
}

test "format: scopes table shows remaining time, confirmation and cursor hint" {
    const out = try runFormatter(formatScopes, scopes_payload, .table);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "JAIL") != null);
    try testing.expect(std.mem.indexOf(u8, out, "2001:db8::/64") != null);
    try testing.expect(std.mem.indexOf(u8, out, "tcp/22") != null);
    try testing.expect(std.mem.indexOf(u8, out, "never") != null);
    try testing.expect(std.mem.indexOf(u8, out, "m ") != null);
    try testing.expect(std.mem.indexOf(u8, out, "010101010101") != null);
    try testing.expect(std.mem.indexOf(u8, out, "Total: 2 scopes") != null);
    try testing.expect(std.mem.indexOf(u8, out, "--cursor czoxOjA") != null);
    try testing.expect(std.mem.indexOf(u8, out, "generation: ab12") != null);
}

test "format: scopes and history empty pages" {
    const empty = "{\"generation\":\"g\",\"items\":[],\"next_cursor\":null}";
    const scopes = try runFormatter(formatScopes, empty, .table);
    defer testing.allocator.free(scopes);
    try testing.expect(std.mem.indexOf(u8, scopes, "No active scopes.") != null);
    try testing.expect(std.mem.indexOf(u8, scopes, "--cursor") == null);
    const history = try runFormatter(formatHistory, empty, .table);
    defer testing.allocator.free(history);
    try testing.expect(std.mem.indexOf(u8, history, "No confirmed history.") != null);
    const plain = try runFormatter(formatHistory, empty, .plain);
    defer testing.allocator.free(plain);
    try testing.expectEqualStrings("generation\tg\nnext_cursor\t-\n", plain);
}

test "format: history empty page with a cursor still tells the operator to keep paging" {
    const payload = "{\"generation\":\"g\",\"items\":[],\"next_cursor\":\"aDoy\"}";
    const table = try runFormatter(formatHistory, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "No confirmed history.") != null);
    try testing.expect(std.mem.indexOf(u8, table, "--cursor aDoy") != null);
    const plain = try runFormatter(formatHistory, payload, .plain);
    defer testing.allocator.free(plain);
    try testing.expectEqualStrings("generation\tg\nnext_cursor\taDoy\n", plain);
}

test "format: history json passes through" {
    const out = try runFormatter(formatHistory, history_payload, .json);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.startsWith(u8, out, history_payload));
}

test "format: history plain and table" {
    const plain = try runFormatter(formatHistory, history_payload, .plain);
    defer testing.allocator.free(plain);
    try testing.expect(std.mem.indexOf(u8, plain, "items.0.sequence\t7\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "items.0.confirmed_us\t1700000000000000\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "items.0.native_retry\ttrue\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "next_cursor\t-\n") != null);
    const table = try runFormatter(formatHistory, history_payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "SEQ") != null);
    try testing.expect(std.mem.indexOf(u8, table, "2023-11-14 22:13:20") != null);
    try testing.expect(std.mem.indexOf(u8, table, "192.0.2.9") != null);
    try testing.expect(std.mem.indexOf(u8, table, "111111111111") != null);
    try testing.expect(std.mem.indexOf(u8, table, "Total: 1 events") != null);
    try testing.expect(std.mem.indexOf(u8, table, "--cursor") == null);
}

test "format: canonical scope sets stay exact in scope and history tables" {
    const scope_payload =
        \\{"generation":"g","items":[{"jail":"dns","scope":{"family":"v4","address":"192.0.2.0","prefix":24,
        \\"subject_kind":"network","protocols":["tcp","udp"],"port_ranges":[{"first":53,"last":53},{"first":8000,"last":8010}],
        \\"legacy_exact":false},"lease":"finite","confirmed":true}],"next_cursor":null}
    ;
    const scopes = try runFormatter(formatScopes, scope_payload, .table);
    defer testing.allocator.free(scopes);
    try testing.expect(std.mem.indexOf(u8, scopes, "tcp,udp/53,8000-8010") != null);

    const history =
        \\{"generation":"g","items":[{"sequence":1,"jail":"dns","confirmed_us":1700000000000000,
        \\"scope":{"family":"v4","address":"192.0.2.0","prefix":24,"subject_kind":"network","protocols":["tcp","udp"],
        \\"port_ranges":[{"first":53,"last":53},{"first":8000,"last":8010}],"legacy_exact":false},"native_retry":false}],"next_cursor":null}
    ;
    const table = try runFormatter(formatHistory, history, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "MATCH") != null);
    try testing.expect(std.mem.indexOf(u8, table, "tcp,udp/53,8000-8010") != null);
    const plain = try runFormatter(formatHistory, history, .plain);
    defer testing.allocator.free(plain);
    try testing.expect(std.mem.indexOf(u8, plain, "items.0.scope\t192.0.2.0/24\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "items.0.match") == null);
}

test "format: firewall table and plain distinguish observation from intent" {
    const table = try runFormatter(formatFirewall, firewall_payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "owned (clean observation)") != null);
    try testing.expect(std.mem.indexOf(u8, table, "complete readback; 2 observed; 2 retained") != null);
    try testing.expect(std.mem.indexOf(u8, table, "tcp,udp/53,8000-8010") != null);
    try testing.expect(std.mem.indexOf(u8, table, "unknown") != null);
    try testing.expect(std.mem.indexOf(u8, table, "--cursor fw-token") != null);
    try testing.expect(std.mem.indexOf(u8, table, "confirmed") == null);
    try testing.expect(std.mem.indexOf(u8, table, "permanent") == null);

    const plain = try runFormatter(formatFirewall, firewall_payload, .plain);
    defer testing.allocator.free(plain);
    try testing.expect(std.mem.indexOf(u8, plain, "observation.id\t00112233445566778899aabbccddeeff:7\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "items.0.match\ttcp,udp/53,8000-8010\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "items.1.remaining_ms_at_observation\t-\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "next_cursor\tfw-token\n") != null);
}

test "format: firewall states keep unavailable absent stale and foreign distinct" {
    const unavailable = try runFormatter(formatFirewall, "{\"schema_version\":1,\"kind\":\"firewall\",\"available\":false,\"unavailable_reason\":\"no_manager\",\"installation\":null,\"observation\":null,\"last_attempt\":{\"outcome\":\"none\",\"cause\":null,\"stage\":null,\"age_ms\":null},\"items\":[],\"next_cursor\":null}", .table);
    defer testing.allocator.free(unavailable);
    try testing.expect(std.mem.indexOf(u8, unavailable, "unavailable (no_manager)") != null);
    try testing.expect(std.mem.indexOf(u8, unavailable, "No sample is available") != null);

    const absent = try runFormatter(formatFirewall, "{\"schema_version\":1,\"kind\":\"firewall\",\"available\":true,\"installation\":{\"backend\":\"iptables\"},\"observation\":{\"id\":\"n:1\",\"state\":\"absent\",\"observation_complete\":true,\"observed_total\":0,\"sample_count\":0,\"sample_truncated\":false},\"last_attempt\":{\"outcome\":\"success\"},\"items\":[],\"next_cursor\":null}", .table);
    defer testing.allocator.free(absent);
    try testing.expect(std.mem.indexOf(u8, absent, "State:        absent") != null);
    try testing.expect(std.mem.indexOf(u8, absent, "owned installation was absent") != null);

    const foreign = try runFormatter(formatFirewall, "{\"schema_version\":1,\"kind\":\"firewall\",\"available\":true,\"installation\":{\"backend\":\"nftables\"},\"observation\":{\"id\":\"n:2\",\"state\":\"owned\",\"observation_complete\":true,\"observed_total\":1,\"sample_count\":1,\"sample_truncated\":false},\"last_attempt\":{\"outcome\":\"failed\",\"cause\":\"ForeignState\",\"stage\":\"readback\",\"age_ms\":4},\"items\":[],\"next_cursor\":null}", .table);
    defer testing.allocator.free(foreign);
    try testing.expect(std.mem.indexOf(u8, foreign, "stale; foreign state on last attempt") != null);
    try testing.expect(std.mem.indexOf(u8, foreign, "cause=ForeignState") != null);
}

test "format: firewall narrow output bounds and escapes diagnostic text" {
    const payload =
        "{\"schema_version\":1,\"kind\":\"firewall\",\"available\":true,\"installation\":{\"backend\":\"nf\\ntables-with-a-long-name\",\"namespace\":\"daemon-current\"},\"observation\":{\"id\":\"nonce:1\",\"state\":\"owned\",\"observation_complete\":true,\"observed_total\":0,\"sample_count\":0,\"sample_truncated\":false},\"last_attempt\":{\"outcome\":\"success\"},\"items\":[],\"next_cursor\":null}";
    var out = std.ArrayList(u8).init(testing.allocator);
    defer out.deinit();
    try formatFirewallForWidth(testing.allocator, out.writer(), payload, .table, .{ .enabled = false }, 40);
    try testing.expect(std.mem.indexOf(u8, out.items, "nf\\ntables") != null);
    var lines = std.mem.splitScalar(u8, out.items, '\n');
    while (lines.next()) |line| if (line.len != 0) try testing.expect(line.len <= 40);
}

test "format: firewall item fields escape controls in wide and stacked tables" {
    const payload =
        "{\"schema_version\":1,\"kind\":\"firewall\",\"available\":true,\"installation\":{\"backend\":\"nftables\"},\"observation\":{\"id\":\"nonce:3\",\"state\":\"owned\",\"observation_complete\":true,\"observed_total\":2,\"sample_count\":2,\"sample_truncated\":false},\"last_attempt\":{\"outcome\":\"success\"},\"items\":[{\"scope\":{\"family\":\"v4\",\"address\":\"192.0.2.1\\u001b\\nrow\",\"prefix\":32,\"protocols\":[\"tcp\",\"udp\"],\"port_ranges\":[{\"first\":53,\"last\":53},{\"first\":8000,\"last\":8010}]},\"effect_id_hex\":\"abc\\tdef\\u001b\",\"remaining_ms_at_observation\":1,\"deadline_us\":9223372036854775807},{\"scope\":{\"family\":\"v4\",\"address\":\"198.51.100.2\",\"prefix\":32,\"protocol\":\"u\\u001b\\np\\t\",\"port\":53},\"effect_id_hex\":null,\"remaining_ms_at_observation\":null,\"deadline_us\":null}],\"next_cursor\":null}";
    inline for (.{ @as(usize, 200), @as(usize, 40) }) |columns| {
        var out = std.ArrayList(u8).init(testing.allocator);
        defer out.deinit();
        try formatFirewallForWidth(testing.allocator, out.writer(), payload, .table, .{ .enabled = false }, columns);
        try testing.expect(std.mem.indexOfScalar(u8, out.items, 0x1b) == null);
        try testing.expect(std.mem.indexOfScalar(u8, out.items, '\t') == null);
        try testing.expect(std.mem.indexOf(u8, out.items, "192.0.2.1\\x1B\\nrow") != null);
        try testing.expect(std.mem.indexOf(u8, out.items, "abc\\tdef\\x1B") != null);
        try testing.expect(std.mem.indexOf(u8, out.items, "tcp,udp/53,8000-8010") != null);
        try testing.expect(std.mem.indexOf(u8, out.items, "u\\x1B\\np\\t/53") != null);
        try testing.expect(std.mem.indexOf(u8, out.items, "out-of-range") != null);
        if (columns == 40) {
            var lines = std.mem.splitScalar(u8, out.items, '\n');
            while (lines.next()) |line| if (line.len != 0) try testing.expect(line.len <= columns);
        }
    }
}

test "format: firewall coverage preserves missing counts as unknown" {
    const payload =
        "{\"schema_version\":1,\"kind\":\"firewall\",\"available\":true,\"installation\":{\"backend\":\"nftables\"},\"observation\":{\"id\":\"nonce:4\",\"state\":\"owned\",\"observation_complete\":true},\"last_attempt\":{\"outcome\":\"success\"},\"items\":[],\"next_cursor\":null}";
    const table = try runFormatter(formatFirewall, payload, .table);
    defer testing.allocator.free(table);
    try testing.expect(std.mem.indexOf(u8, table, "unknown observed; unknown retained") != null);
    try testing.expect(std.mem.indexOf(u8, table, "0 observed; 0 retained") == null);
}

test "format: UTC rendering bounds hostile microsecond timestamps" {
    var buffer: [32]u8 = undefined;
    try testing.expectEqualStrings("out-of-range", formatUtc(&buffer, std.math.maxInt(i64)));
    try testing.expectEqualStrings("out-of-range", formatUtc(&buffer, -1));
    try testing.expectEqualStrings("9999-12-31 23:59:59", formatUtc(&buffer, 253_402_300_799_000_000));
}

test "format: firewall json remains raw passthrough" {
    const out = try runFormatter(formatFirewall, firewall_payload, .json);
    defer testing.allocator.free(out);
    try testing.expectEqualStrings(firewall_payload ++ "\n", out);
}

test "format: presentation details retains machine formats and exposes table identifiers" {
    const status = "{\"generation\":\"g\\nunsafe\",\"protection\":\"active\",\"backend\":\"nftables\",\"jails_active\":1,\"active_bans\":2}";
    const plain = try runFormatter(formatStatusDetailed, status, .plain);
    defer testing.allocator.free(plain);
    try testing.expect(std.mem.indexOf(u8, plain, "generation\tg\\nunsafe") != null);
    const json = try runFormatter(formatStatusDetailed, status, .json);
    defer testing.allocator.free(json);
    try testing.expectEqualStrings(status ++ "\n", json);
    const summary_status = try runFormatter(formatStatus, status, .table);
    defer testing.allocator.free(summary_status);
    try testing.expect(std.mem.indexOf(u8, summary_status, "fail2zig status") != null);
    try testing.expect(std.mem.indexOf(u8, summary_status, "Generation:") == null);

    var status_table = std.ArrayList(u8).init(testing.allocator);
    defer status_table.deinit();
    try formatStatusForWidthDetailed(testing.allocator, status_table.writer(), status, .table, .{ .enabled = false }, 34, true);
    try testing.expect(std.mem.indexOf(u8, status_table.items, "Generation: g\\nunsafe") != null);

    const firewall = "{\"schema_version\":1,\"kind\":\"firewall\",\"available\":true,\"generation\":\"g-1\",\"installation\":{\"id_hex\":\"install-1\",\"backend\":\"nftables\"},\"observation\":{\"id\":\"obs-1\",\"state\":\"owned\",\"observation_complete\":true,\"observed_total\":1,\"sample_count\":1,\"sample_truncated\":false},\"last_attempt\":{\"outcome\":\"success\"},\"structure\":{\"proof\":\"exact_v1\",\"tables\":[{\"family\":\"inet\",\"name\":\"f2z\\nowned\"}],\"chains\":[{\"family\":\"inet\",\"table\":\"f2z\\u001bowned\",\"name\":\"input\",\"type\":\"filter\",\"hook\":\"input\",\"priority\":-1,\"policy\":\"accept\"}],\"sets\":[],\"rules\":[]},\"items\":[{\"scope\":{\"family\":\"v4\",\"address\":\"192.0.2.1\",\"prefix\":32},\"effect_id_hex\":\"effect-1\",\"remaining_ms_at_observation\":118000,\"placement\":{\"kind\":\"set_\\u001belement\",\"family\":\"inet\",\"table\":\"f2z\",\"chain\":\"input\",\"set\":\"banned_v4\",\"verdict\":\"drop\"}}],\"next_cursor\":null}";
    var summary = std.ArrayList(u8).init(testing.allocator);
    defer summary.deinit();
    try formatFirewallForWidthDetailed(testing.allocator, summary.writer(), firewall, .table, .{ .enabled = false }, 160, false);
    try testing.expect(std.mem.indexOf(u8, summary.items, "effect-1") == null);
    try testing.expect(std.mem.indexOf(u8, summary.items, "install-1") == null);
    var detailed = std.ArrayList(u8).init(testing.allocator);
    defer detailed.deinit();
    try formatFirewallForWidthDetailed(testing.allocator, detailed.writer(), firewall, .table, .{ .enabled = false }, 160, true);
    try testing.expect(std.mem.indexOf(u8, detailed.items, "effect-1") != null);
    try testing.expect(std.mem.indexOf(u8, detailed.items, "install-1") != null);
    try testing.expect(std.mem.indexOf(u8, detailed.items, "TABLE") != null);
    try testing.expect(std.mem.indexOf(u8, detailed.items, "FAMILY") != null);
    try testing.expect(std.mem.indexOf(u8, detailed.items, "f2z\\nowned") != null);
    try testing.expect(std.mem.indexOf(u8, detailed.items, "set_\\x1Belement") != null);
    try testing.expect(std.mem.indexOfScalar(u8, detailed.items, 0x1b) == null);
    try testing.expect(std.mem.indexOf(u8, detailed.items, "1m 58s") != null);
}

test "format: compact jail summary stacks safely on narrow terminals" {
    const payload = "[{\"name\":\"ssh\\nud\",\"enabled\":true,\"active_bans\":3,\"enforcing\":true,\"log_source\":\"journal\\u001bctl\",\"source_healthy\":false,\"cause\":\"PermissionDenied\"}]";
    var wide = std.ArrayList(u8).init(testing.allocator);
    defer wide.deinit();
    try formatJailsForWidthDetailed(testing.allocator, wide.writer(), payload, .table, .{ .enabled = false }, 160, false);
    try testing.expect(std.mem.indexOf(u8, wide.items, "SOURCE HEALTH") != null);
    try testing.expect(std.mem.indexOf(u8, wide.items, "\\x1B") != null);
    var narrow = std.ArrayList(u8).init(testing.allocator);
    defer narrow.deinit();
    try formatJailsForWidthDetailed(testing.allocator, narrow.writer(), payload, .table, .{ .enabled = false }, 36, false);
    try testing.expect(std.mem.indexOf(u8, narrow.items, "JAIL:") != null);
    try testing.expect(std.mem.indexOf(u8, narrow.items, "SOURCE:") != null);
    try testing.expect(std.mem.indexOf(u8, narrow.items, "ENFORCING:") != null);
    try testing.expect(std.mem.indexOf(u8, narrow.items, "HEALTH:") != null);
    var lines = std.mem.splitScalar(u8, narrow.items, '\n');
    while (lines.next()) |line| if (line.len != 0) try testing.expect(line.len <= 36);
}

test "format: BUG-068 default summaries retain health and failure context" {
    const jails = "[{\"name\":\"sshd\",\"enabled\":true,\"active_bans\":1,\"enforcing\":false,\"log_source\":\"journal\",\"source_healthy\":false,\"cause\":\"JournalCursorLost\",\"source_exit_code\":125,\"source_signal\":15,\"source_stderr_present\":true}]";
    var jail_output = std.ArrayList(u8).init(testing.allocator);
    defer jail_output.deinit();
    try formatJailsForWidthDetailed(testing.allocator, jail_output.writer(), jails, .table, .{ .enabled = false }, 120, false);
    try testing.expect(std.mem.indexOf(u8, jail_output.items, "broken (JournalCursorLost; exit=125; signal=15; stderr)") != null);
    try testing.expect(std.mem.indexOf(u8, jail_output.items, "false") != null);

    const status = "{\"protection\":\"degraded\",\"sqlite_code\":5,\"next_retry_ms\":1234,\"effect_mutation\":\"retry-17\"}";
    const output = try runFormatter(formatStatus, status, .table);
    defer testing.allocator.free(output);
    try testing.expect(std.mem.indexOf(u8, output, "SQLite code: 5") != null);
    try testing.expect(std.mem.indexOf(u8, output, "Retry at: 1234 ms monotonic") != null);
    try testing.expect(std.mem.indexOf(u8, output, "Effect attempt: retry-17") != null);
}

test "format: verified structural identities fit or stack without clipping" {
    const name = "f2z_0123456789abcdef01234567";
    const set = name ++ "_4";
    const rules = [_]FirewallRule{
        .{ .family = "v4", .table = "filter", .chain = "INPUT", .match = "all", .verdict = name, .position = 1 },
        .{ .family = "v4", .table = "filter", .chain = name, .match = "source in " ++ set, .verdict = "drop" },
    };
    for ([_]usize{ 80, 120 }) |columns| {
        var out = std.ArrayList(u8).init(testing.allocator);
        defer out.deinit();
        try writeFirewallStructureRules(out.writer(), &rules, .{ .enabled = false }, columns);
        try testing.expect(std.mem.indexOf(u8, out.items, "source in " ++ set) != null);
        try testing.expect(std.mem.indexOf(u8, out.items, name) != null);
        try testing.expect(std.mem.indexOf(u8, out.items, "...") == null);
        var lines = std.mem.splitScalar(u8, out.items, '\n');
        while (lines.next()) |line| try testing.expect(line.len <= columns);
    }
    var nft_out = std.ArrayList(u8).init(testing.allocator);
    defer nft_out.deinit();
    try writeFirewallStructureRules(nft_out.writer(), &.{.{ .family = "inet", .table = name, .chain = "input", .match = "ip saddr @banned_ipv4", .verdict = "drop" }}, .{ .enabled = false }, 80);
    try testing.expect(std.mem.indexOf(u8, nft_out.items, "MATCH") != null);
    try testing.expect(std.mem.indexOf(u8, nft_out.items, "MATCH:") == null);
}

test "format: ban countdown uses unsigned seconds after expiry validation" {
    try testing.expectEqualStrings("1m 58s", formatRemaining(118));
    try testing.expectEqualStrings("1m 00s", formatRemaining(60));
    try testing.expectEqualStrings("0m 00s", formatRemaining(0));
    try testing.expectEqualStrings("expired", formatRemaining(-1));
    try testing.expectEqualStrings("-", formatRemaining(null));
}

test "format: firewall rejects available response without an observation" {
    var out = std.ArrayList(u8).init(testing.allocator);
    defer out.deinit();
    try testing.expectError(error.InvalidFirewallPayload, formatFirewallForWidth(
        testing.allocator,
        out.writer(),
        "{\"schema_version\":1,\"kind\":\"firewall\",\"available\":true,\"observation\":null}",
        .table,
        .{ .enabled = false },
        80,
    ));
}

test "format: query renderers report unparseable payloads without failing" {
    inline for (.{ formatConfig, formatScopes, formatHistory }) |formatter| {
        const out = try runFormatter(formatter, "nope", .table);
        defer testing.allocator.free(out);
        try testing.expect(std.mem.startsWith(u8, out, "error: could not parse"));
    }
}

test "format: BUG-064 compact jail fallback preserves full source causes at default widths" {
    const payload =
        \\[{"name":"sshd","enabled":true,"source_healthy":false,"cause":"RestoreRequired"},
        \\ {"name":"other","enabled":true,"source_healthy":false,"cause":"InvalidEncoding"}]
    ;
    for ([_]usize{ 74, 80 }) |width| {
        var out = std.ArrayList(u8).init(testing.allocator);
        defer out.deinit();
        try formatJailsForWidth(testing.allocator, out.writer(), payload, .table, .{ .enabled = false }, width);
        try testing.expect(std.mem.indexOf(u8, out.items, "broken (RestoreRequired)") != null);
        try testing.expect(std.mem.indexOf(u8, out.items, "broken (InvalidEncoding)") != null);
        var lines = std.mem.splitScalar(u8, out.items, '\n');
        while (lines.next()) |line| try testing.expect(line.len <= width);
    }
}
