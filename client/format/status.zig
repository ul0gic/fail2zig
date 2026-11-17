// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Renders the daemon status response as JSON, plain lines, or a boxed, summary or narrow table fitted to the terminal width.
// Holds: JSON output keeps the daemon's status bytes, adding loss_events before the closing brace; other forms escape daemon text.

const std = @import("std");
const OutputFormat = @import("shared.zig").OutputFormat;
const Color = @import("shared.zig").Color;
const terminalColumns = @import("shared.zig").terminalColumns;
const writeStatusNarrowRow = @import("shared.zig").writeStatusNarrowRow;
const rowUsed = @import("shared.zig").rowUsed;
const label_col = @import("shared.zig").label_col;
const boolValue = @import("shared.zig").boolValue;
const diagnostic_max_bytes = @import("shared.zig").diagnostic_max_bytes;
const renderDiagnostic = @import("shared.zig").renderDiagnostic;
const rowLabel = @import("shared.zig").rowLabel;
const repeatChar = @import("shared.zig").repeatChar;
const writeSpaces = @import("shared.zig").writeSpaces;
const formatUptime = @import("shared.zig").formatUptime;
const formatMemory = @import("shared.zig").formatMemory;
const formatRate = @import("shared.zig").formatRate;
const formatOptU32 = @import("shared.zig").formatOptU32;
const formatHistoryCount = @import("shared.zig").formatHistoryCount;
const writeCell = @import("shared.zig").writeCell;
const writeClipped = @import("shared.zig").writeClipped;
const StatusPayload = @import("status_sources.zig").StatusPayload;
const LossReport = @import("status_sources.zig").LossReport;
const writeSourcePlain = @import("status_sources.zig").writeSourcePlain;
const writeLossPlain = @import("status_sources.zig").writeLossPlain;
const writeSourcesNarrow = @import("status_sources.zig").writeSourcesNarrow;
const writeSourcesBoxed = @import("status_sources.zig").writeSourcesBoxed;
const sourcesWidth = @import("status_sources.zig").sourcesWidth;
const writeLossTable = @import("status_sources.zig").writeLossTable;

pub fn formatStatus(
    allocator: std.mem.Allocator,
    writer: anytype,
    payload_json: []const u8,
    fmt: OutputFormat,
    color: Color,
) !void {
    try formatStatusWithDetails(allocator, writer, payload_json, fmt, color, false, null);
}

pub fn formatStatusWithLoss(allocator: std.mem.Allocator, writer: anytype, payload_json: []const u8, fmt: OutputFormat, color: Color, loss: LossReport) !void {
    try formatStatusWithDetails(allocator, writer, payload_json, fmt, color, true, loss);
}

fn formatStatusWithDetails(allocator: std.mem.Allocator, writer: anytype, payload_json: []const u8, fmt: OutputFormat, color: Color, details: bool, loss: ?LossReport) !void {
    try formatStatusReport(allocator, writer, payload_json, fmt, color, terminalColumns(), details, loss);
}

fn formatStatusReport(
    allocator: std.mem.Allocator,
    writer: anytype,
    payload_json: []const u8,
    fmt: OutputFormat,
    color: Color,
    columns: usize,
    details: bool,
    loss: ?LossReport,
) !void {
    switch (fmt) {
        .json => {
            if (loss) |report| return writeStatusJsonWithLoss(writer, payload_json, report);
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
                if (loss) |report| try writeLossPlain(writer, report);
            } else {
                try writeStatusTable(writer, parsed.value, color, columns, details);
                if (loss) |report| try writeLossTable(writer, report, color, columns);
            }
        },
    }
}

// Does:  Adds loss_events to the daemon's status object by writing it before the closing brace; the daemon's bytes are not re-encoded.
fn writeStatusJsonWithLoss(writer: anytype, payload_json: []const u8, report: LossReport) !void {
    const object = std.mem.trim(u8, payload_json, " \t\r\n");
    if (object.len < 2 or object[0] != '{' or object[object.len - 1] != '}') return error.InvalidStatusPayload;
    const members = std.mem.trim(u8, object[1 .. object.len - 1], " \t\r\n");
    try writer.writeAll(object[0 .. object.len - 1]);
    if (members.len != 0) try writer.writeByte(',');
    switch (report) {
        .events => |events| {
            try writer.writeAll("\"loss_events\":");
            try std.json.stringify(events, .{}, writer);
        },
        .unavailable => |message| {
            try writer.writeAll("\"loss_events\":null,\"loss_events_unavailable\":");
            try std.json.encodeJsonString(message, .{}, writer);
        },
    }
    try writer.writeAll("}\n");
}

fn writeStatusPlain(writer: anytype, s: StatusPayload) !void {
    var diagnostic_buffer: [diagnostic_max_bytes]u8 = undefined;
    if (s.version) |v| try writer.print("version\t{s}\n", .{renderDiagnostic(&diagnostic_buffer, v)});
    if (s.uptime_seconds) |u| try writer.print("uptime_seconds\t{d}\n", .{u});
    if (s.memory_bytes_used) |m| try writer.print("memory_bytes_used\t{d}\n", .{m});
    if (s.memory_bytes_limit) |m| try writer.print("memory_bytes_limit\t{d}\n", .{m});
    if (s.active_bans) |a| try writer.print("active_bans\t{d}\n", .{a});
    if (s.total_bans) |a| try writer.print("total_bans\t{d}\n", .{a});
    if (s.knowledge) |k| try writer.print("knowledge\t{s}\n", .{renderDiagnostic(&diagnostic_buffer, k)});
    if (s.confirmed_at_us) |at| try writer.print("confirmed_at_us\t{d}\n", .{at});
    if (s.knowledge_age_ms) |age| try writer.print("knowledge_age_ms\t{d}\n", .{age});
    if (s.pending_bans) |count| try writer.print("pending_bans\t{d}\n", .{count});
    if (s.oldest_pending_ms) |age| try writer.print("oldest_pending_ms\t{d}\n", .{age});
    if (s.overdue_removals) |count| try writer.print("overdue_removals\t{d}\n", .{count});
    if (s.oldest_overdue_ms) |age| try writer.print("oldest_overdue_ms\t{d}\n", .{age});
    if (s.overdue_bookkeeping) |count| try writer.print("overdue_bookkeeping\t{d}\n", .{count});
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
    if (s.paused_sources) |count| try writer.print("paused_sources\t{d}\n", .{count});
    if (s.missing_sources) |count| try writer.print("missing_sources\t{d}\n", .{count});
    if (s.pool_sample_available) |available| try writer.print("pool_sample_available\t{s}\n", .{boolValue(available)});
    if (s.pool_sample_pending) |pending| try writer.print("pool_sample_pending\t{s}\n", .{boolValue(pending)});
    if (s.pool_sample_as_of_us) |as_of| try writer.print("pool_sample_as_of_us\t{d}\n", .{as_of});
    if (s.memory_admission_bytes) |m| try writer.print("memory_admission_bytes\t{d}\n", .{m});
    var footprint_buffer: [96]u8 = undefined;
    if (formatStateFile(&footprint_buffer, s)) |value| try writer.print("state_file\t{s}\n", .{value});
    if (s.state_file_used_pages) |pages| try writer.print("state_file_used_pages\t{d}\n", .{pages});
    if (s.state_file_capacity_pages) |pages| try writer.print("state_file_capacity_pages\t{d}\n", .{pages});
    if (s.state_file_owed_pages) |pages| try writer.print("state_file_owed_pages\t{d}\n", .{pages});
    if (s.intake) |value| try writer.print("intake\t{s}\n", .{renderDiagnostic(&footprint_buffer, value)});
    if (s.intake_cause) |value| try writer.print("intake_cause\t{s}\n", .{renderDiagnostic(&footprint_buffer, value)});
    if (s.waiting_sources) |count| try writer.print("waiting_sources\t{d}\n", .{count});
    if (formatTrackingPool(&footprint_buffer, s)) |value| try writer.print("tracking_pool\t{s}\n", .{value});
    for (s.sources orelse &.{}) |source| try writeSourcePlain(writer, source);
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
    if (s.memory_admission_bytes != null) try rowLabel(writer, "Memory plan:", formatMemory(s.memory_admission_bytes, null), width);
    try rowLabel(writer, "Parse rate:", formatRate(s.parse_rate), width);
    try rowLabel(writer, "Active bans:", formatOptU32(s.active_bans), width);
    try rowLabel(writer, "History:", formatHistoryCount(s.total_bans), width);
    var knowledge_buffer: [diagnostic_max_bytes + 32]u8 = undefined;
    try rowLabel(writer, "Knowledge:", formatKnowledge(&knowledge_buffer, s), width);
    var pending_buffer: [96]u8 = undefined;
    try rowLabel(writer, "Pending:", formatPending(&pending_buffer, s), width);
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
    try writeSourcesBoxed(writer, s, color, width);
    var summary_buffer: [160]u8 = undefined;
    if (formatEffects(&summary_buffer, s)) |value| try rowLabel(writer, "Effects:", value, width);
    if (s.effect_backend) |backend| try rowLabel(writer, "Effect:", renderDiagnostic(&diagnostic_buffer, backend), width);
    if (s.effect_stage) |stage| try rowLabel(writer, "  Stage:", renderDiagnostic(&diagnostic_buffer, stage), width);
    if (s.effect_cause) |cause| try rowLabel(writer, "  Cause:", renderDiagnostic(&diagnostic_buffer, cause), width);
    if (s.effect_mutation) |mutation| try rowLabel(writer, "  Attempt:", renderDiagnostic(&diagnostic_buffer, mutation), width);
    if (formatWorker(&summary_buffer, s)) |value| try rowLabel(writer, "Worker:", value, width);
    if (s.clock_uncertain == true) try rowLabel(writer, "Clock:", "uncertain", width);
    if (formatExpiry(&summary_buffer, s)) |value| try rowLabel(writer, "Expiry:", value, width);
    if (formatStateFile(&summary_buffer, s)) |value| try rowLabel(writer, "State file:", value, width);
    if (formatUsedPages(&summary_buffer, s)) |value| try rowLabel(writer, "Used pages:", value, width);
    if (formatCapacity(&summary_buffer, s)) |value| try rowLabel(writer, "Capacity:", value, width);
    if (formatIntake(&summary_buffer, s)) |value| try rowLabel(writer, "Intake:", value, width);
    if (formatTrackingPool(&summary_buffer, s)) |value| try rowLabel(writer, tracking_pool_label, value, width);

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
    try writeStatusNarrowRow(writer, "History: ", formatHistoryCount(s.total_bans), columns);
    var knowledge_buffer: [diagnostic_max_bytes + 32]u8 = undefined;
    try writeStatusNarrowRow(writer, "Knowledge: ", formatKnowledge(&knowledge_buffer, s), columns);
    var pending_buffer: [96]u8 = undefined;
    try writeStatusNarrowRow(writer, "Pending: ", formatPending(&pending_buffer, s), columns);
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
    try writeSourcesNarrow(writer, s, color, columns);
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
    if (formatStateFile(&summary, s)) |value| try writeStatusNarrowRow(writer, "State file: ", value, columns);
    if (formatUsedPages(&summary, s)) |value| try writeStatusNarrowRow(writer, "Used pages: ", value, columns);
    if (formatCapacity(&summary, s)) |value| try writeStatusNarrowRow(writer, "Capacity: ", value, columns);
    if (formatIntake(&summary, s)) |value| try writeStatusNarrowRow(writer, "Intake: ", value, columns);
    if (formatTrackingPool(&summary, s)) |value| try writeStatusNarrowRow(writer, tracking_pool_label, value, columns);
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
    try writeStatusNarrowRow(writer, "History: ", formatHistoryCount(s.total_bans), columns);
    var knowledge_buffer: [diagnostic_max_bytes + 32]u8 = undefined;
    try writeStatusNarrowRow(writer, "Knowledge: ", formatKnowledge(&knowledge_buffer, s), columns);
    var pending_buffer: [96]u8 = undefined;
    try writeStatusNarrowRow(writer, "Pending: ", formatPending(&pending_buffer, s), columns);
    try writeStatusNarrowRow(writer, "Jails: ", formatOptU32(s.jails_active), columns);
    if (s.generation) |generation| try writeStatusNarrowRow(writer, "Generation: ", renderDiagnostic(&diagnostic_buffer, generation), columns);
    try writeStatusNarrowRow(writer, "Uptime: ", formatUptime(s.uptime_seconds), columns);
    try writeStatusNarrowRow(writer, "Memory: ", formatMemory(s.memory_bytes_used, s.memory_bytes_limit), columns);
    if (s.memory_admission_bytes != null) try writeStatusNarrowRow(writer, "Memory plan: ", formatMemory(s.memory_admission_bytes, null), columns);
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
    try writeSourcesNarrow(writer, s, color, columns);
    var summary_buffer: [160]u8 = undefined;
    if (formatEffects(&summary_buffer, s)) |value| try writeStatusNarrowRow(writer, "Effects: ", value, columns);
    if (s.effect_backend) |backend| try writeStatusNarrowRow(writer, "Effect: ", renderDiagnostic(&diagnostic_buffer, backend), columns);
    if (s.effect_stage) |stage| try writeStatusNarrowRow(writer, "Stage: ", renderDiagnostic(&diagnostic_buffer, stage), columns);
    if (s.effect_cause) |cause| try writeStatusNarrowRow(writer, "Effect cause: ", renderDiagnostic(&diagnostic_buffer, cause), columns);
    if (s.effect_mutation) |mutation| try writeStatusNarrowRow(writer, "Attempt: ", renderDiagnostic(&diagnostic_buffer, mutation), columns);
    if (formatWorker(&summary_buffer, s)) |value| try writeStatusNarrowRow(writer, "Worker: ", value, columns);
    if (s.clock_uncertain == true) try writeStatusNarrowRow(writer, "Clock: ", "uncertain", columns);
    if (formatExpiry(&summary_buffer, s)) |value| try writeStatusNarrowRow(writer, "Expiry: ", value, columns);
    if (formatStateFile(&summary_buffer, s)) |value| try writeStatusNarrowRow(writer, "State file: ", value, columns);
    if (formatUsedPages(&summary_buffer, s)) |value| try writeStatusNarrowRow(writer, "Used pages: ", value, columns);
    if (formatCapacity(&summary_buffer, s)) |value| try writeStatusNarrowRow(writer, "Capacity: ", value, columns);
    if (formatIntake(&summary_buffer, s)) |value| try writeStatusNarrowRow(writer, "Intake: ", value, columns);
    if (formatTrackingPool(&summary_buffer, s)) |value| try writeStatusNarrowRow(writer, tracking_pool_label, value, columns);
}

fn statusWidth(s: StatusPayload) usize {
    var used: usize = statusHeadingLen(s.version);
    used = @max(used, rowUsed(formatUptime(s.uptime_seconds)));
    used = @max(used, rowUsed(formatMemory(s.memory_bytes_used, s.memory_bytes_limit)));
    used = @max(used, rowUsed(formatMemory(s.memory_admission_bytes, null)));
    used = @max(used, rowUsed(formatRate(s.parse_rate)));
    used = @max(used, rowUsed(formatOptU32(s.active_bans)));
    used = @max(used, rowUsed(formatHistoryCount(s.total_bans)));
    var protection_buffer: [diagnostic_max_bytes + 16]u8 = undefined;
    used = @max(used, rowUsed(formatProtection(&protection_buffer, s)));
    var backend_buffer: [diagnostic_max_bytes]u8 = undefined;
    used = @max(used, rowUsed(if (s.backend) |backend| renderDiagnostic(&backend_buffer, backend) else "-"));
    used = @max(used, rowUsed(formatOptU32(s.jails_active)));
    var knowledge_buffer: [diagnostic_max_bytes + 32]u8 = undefined;
    used = @max(used, rowUsed(formatKnowledge(&knowledge_buffer, s)));
    var pending_buffer: [96]u8 = undefined;
    used = @max(used, rowUsed(formatPending(&pending_buffer, s)));
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
    if (formatStateFile(&summary_buffer, s)) |value| used = @max(used, rowUsed(value));
    if (formatUsedPages(&summary_buffer, s)) |value| used = @max(used, rowUsed(value));
    if (formatCapacity(&summary_buffer, s)) |value| used = @max(used, rowUsed(value));
    if (formatIntake(&summary_buffer, s)) |value| used = @max(used, rowUsed(value));
    if (formatTrackingPool(&summary_buffer, s)) |value| used = @max(used, rowUsed(value) + tracking_pool_label.len - label_col);
    used = @max(used, sourcesWidth(s));
    return @max(44, used + 2);
}

const tracking_pool_label = "Tracking pool: ";

fn formatStateFile(buffer: []u8, s: StatusPayload) ?[]const u8 {
    const bytes = s.state_file_bytes orelse return null;
    const pages = s.state_file_pages orelse return null;
    const max_pages = s.state_file_max_pages orelse return null;
    return std.fmt.bufPrint(buffer, "{d} ({d} pages of {d})", .{ bytes, pages, max_pages }) catch null;
}

fn formatUsedPages(buffer: []u8, s: StatusPayload) ?[]const u8 {
    const used = s.state_file_used_pages orelse return null;
    const pages = s.state_file_pages orelse return null;
    return std.fmt.bufPrint(buffer, "{d} of {d} allocated", .{ used, pages }) catch null;
}

fn formatCapacity(buffer: []u8, s: StatusPayload) ?[]const u8 {
    const used = s.state_file_used_pages orelse return null;
    const capacity = s.state_file_capacity_pages orelse return null;
    if (s.state_file_owed_pages) |owed| return std.fmt.bufPrint(buffer, "{d} used + {d} owed of {d} pages", .{ used, owed, capacity }) catch null;
    return std.fmt.bufPrint(buffer, "{d} used + unknown owed of {d} pages", .{ used, capacity }) catch null;
}

fn formatIntake(buffer: []u8, s: StatusPayload) ?[]const u8 {
    const intake = s.intake orelse return null;
    var cause_buffer: [40]u8 = undefined;
    const state = renderDiagnostic(&cause_buffer, intake);
    if (s.intake_cause) |cause| {
        var detail_buffer: [40]u8 = undefined;
        return std.fmt.bufPrint(buffer, "{s} ({s}), {d} sources waiting", .{ state, renderDiagnostic(&detail_buffer, cause), s.waiting_sources orelse 0 }) catch null;
    }
    return std.fmt.bufPrint(buffer, "{s}", .{state}) catch null;
}

fn formatTrackingPool(buffer: []u8, s: StatusPayload) ?[]const u8 {
    if (s.pool_sample_available == false) return std.fmt.bufPrint(buffer, "unknown (sample pending)", .{}) catch null;
    const tracked = s.pool_tracked orelse return null;
    const banned = s.pool_banned orelse return null;
    const tracking_limit = s.pool_tracking_limit orelse return null;
    const ban_limit = s.pool_ban_limit orelse return null;
    return std.fmt.bufPrint(
        buffer,
        "{d} of {d} tracked, {d} of {d} banned{s}",
        .{ tracked, tracking_limit, banned, ban_limit, if (s.pool_sample_pending == true) " (sample pending)" else "" },
    ) catch null;
}

fn formatProtection(buffer: []u8, s: StatusPayload) []const u8 {
    const p = s.protection orelse return "-";
    if (!std.mem.eql(u8, p, "degraded")) return renderDiagnostic(buffer, p);
    const value = s.protection_cause orelse return "DEGRADED";
    if (std.mem.eql(u8, value, "none")) return "DEGRADED";
    var cause_buffer: [diagnostic_max_bytes]u8 = undefined;
    const cause = renderDiagnostic(&cause_buffer, value);
    return std.fmt.bufPrint(buffer, "DEGRADED ({s})", .{cause}) catch "DEGRADED";
}

fn formatKnowledge(buffer: []u8, s: StatusPayload) []const u8 {
    const knowledge = s.knowledge orelse return "unknown";
    var knowledge_buffer: [diagnostic_max_bytes]u8 = undefined;
    const rendered = renderDiagnostic(&knowledge_buffer, knowledge);
    const age = s.knowledge_age_ms orelse return std.fmt.bufPrint(buffer, "{s}", .{rendered}) catch "-";
    return std.fmt.bufPrint(buffer, "{s} (readback {d} ms ago)", .{ rendered, age }) catch "-";
}
fn formatPending(buffer: []u8, s: StatusPayload) []const u8 {
    const pending = s.pending_bans orelse return "unknown";
    const overdue = s.overdue_removals orelse return "unknown";
    if (pending == 0 and overdue == 0) return "none";
    if (pending != 0 and overdue != 0) return std.fmt.bufPrint(
        buffer,
        "{d} bans (oldest {d} ms); {d} overdue (oldest {d} ms)",
        .{ pending, s.oldest_pending_ms orelse 0, overdue, s.oldest_overdue_ms orelse 0 },
    ) catch "-";
    if (pending != 0) return std.fmt.bufPrint(buffer, "{d} bans (oldest {d} ms)", .{ pending, s.oldest_pending_ms orelse 0 }) catch "-";
    return std.fmt.bufPrint(buffer, "{d} overdue (oldest {d} ms)", .{ overdue, s.oldest_overdue_ms orelse 0 }) catch "-";
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
    if (stalled and busy and busy_age != null and heartbeat_age != null) return std.fmt.bufPrint(
        buffer,
        "stalled; busy {d} ms; heartbeat {d} ms ago",
        .{ busy_age.?, heartbeat_age.? },
    ) catch "stalled; busy";
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

fn statusHeadingLen(version: ?[]const u8) usize {
    var version_buffer: [diagnostic_max_bytes]u8 = undefined;
    const version_len = if (version) |value| 1 + renderDiagnostic(&version_buffer, value).len else 0;
    return "fail2zig".len + version_len + " — status".len;
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

fn padTo(writer: anytype, used: usize, target: usize) !void {
    if (used < target) try writeSpaces(writer, target - used);
}
