// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Renders the daemon stats response as JSON, plain lines or a table.
// Holds: Daemon text fields in plain and table output pass through renderDiagnostic; JSON output is the daemon's payload unchanged.

const std = @import("std");
const OutputFormat = @import("shared.zig").OutputFormat;
const Color = @import("shared.zig").Color;
const terminalColumns = @import("shared.zig").terminalColumns;
const boolValue = @import("shared.zig").boolValue;
const diagnostic_max_bytes = @import("shared.zig").diagnostic_max_bytes;
const renderDiagnostic = @import("shared.zig").renderDiagnostic;
const formatUptime = @import("shared.zig").formatUptime;
const formatOptU32 = @import("shared.zig").formatOptU32;
const formatOptU64 = @import("shared.zig").formatOptU64;
const formatAge = @import("shared.zig").formatAge;
const writeCell = @import("shared.zig").writeCell;

pub const StatsPayload = struct {
    schema_version: ?u32 = null,
    kind: ?[]const u8 = null,
    generation: ?[]const u8 = null,
    available: ?bool = null,
    reason: ?[]const u8 = null,
    backend: ?[]const u8 = null,
    uptime_seconds: ?u64 = null,
    snapshot_age_ms: ?u64 = null,
    knowledge: ?[]const u8 = null,
    knowledge_age_ms: ?u64 = null,
    view_ready: ?bool = null,
    view_entries: ?u64 = null,
    last_observed_installed: ?u64 = null,
    pending_live_dispatches: ?u64 = null,
    overdue_blocking_removals: ?u64 = null,
    overdue_bookkeeping: ?u64 = null,
    accepted_readbacks: ?u64 = null,
    dump_interruptions: ?u64 = null,
    view_rebuilds: ?u64 = null,
    view_restarts: ?u64 = null,
    incremental_updates: ?u64 = null,
    expiry_batches: ?u64 = null,
    expiries_prepared: ?u64 = null,
    retirement_batches: ?u64 = null,
    retry_subjects_retired: ?u64 = null,
    retry_subjects_examined: ?u64 = null,
    retirement_pinned_state: ?u64 = null,
    retirement_pinned_effect: ?u64 = null,
    retirement_refused: ?u64 = null,
};

pub fn formatStats(allocator: std.mem.Allocator, writer: anytype, payload_json: []const u8, fmt: OutputFormat, color: Color) !void {
    try formatStatsWithDetails(allocator, writer, payload_json, fmt, color, terminalColumns(), false);
}

pub fn formatStatsDetailed(allocator: std.mem.Allocator, writer: anytype, payload_json: []const u8, fmt: OutputFormat, color: Color) !void {
    try formatStatsWithDetails(allocator, writer, payload_json, fmt, color, terminalColumns(), true);
}

fn formatStatsWithDetails(allocator: std.mem.Allocator, writer: anytype, payload_json: []const u8, fmt: OutputFormat, color: Color, columns: usize, details: bool) !void {
    if (fmt == .json) {
        try writer.writeAll(payload_json);
        if (payload_json.len == 0 or payload_json[payload_json.len - 1] != '\n') try writer.writeByte('\n');
        return;
    }
    const parsed = std.json.parseFromSlice(StatsPayload, allocator, payload_json, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch |e| {
        try writer.print("error: could not parse stats payload ({s})\n", .{@errorName(e)});
        return;
    };
    defer parsed.deinit();
    if (fmt == .plain) return writeStatsPlain(writer, parsed.value);
    return writeStatsTable(writer, parsed.value, color, columns, details);
}

fn writeStatsPlain(writer: anytype, s: StatsPayload) !void {
    var diagnostic: [diagnostic_max_bytes]u8 = undefined;
    try writer.print("schema_version\t{s}\n", .{formatOptU32(s.schema_version)});
    try writer.print("kind\t{s}\n", .{if (s.kind) |v| renderDiagnostic(&diagnostic, v) else "-"});
    try writer.print("generation\t{s}\n", .{if (s.generation) |v| renderDiagnostic(&diagnostic, v) else "-"});
    try writeStatsPlainBool(writer, "available", s.available);
    try writer.print("reason\t{s}\n", .{if (s.reason) |v| renderDiagnostic(&diagnostic, v) else "-"});
    try writer.print("backend\t{s}\n", .{if (s.backend) |v| renderDiagnostic(&diagnostic, v) else "-"});
    try writeStatsPlainNumber(writer, "uptime_seconds", s.uptime_seconds);
    try writeStatsPlainNumber(writer, "snapshot_age_ms", s.snapshot_age_ms);
    try writer.print("knowledge\t{s}\n", .{if (s.knowledge) |v| renderDiagnostic(&diagnostic, v) else "-"});
    try writeStatsPlainNumber(writer, "knowledge_age_ms", s.knowledge_age_ms);
    try writeStatsPlainBool(writer, "view_ready", s.view_ready);
    try writeStatsPlainNumber(writer, "view_entries", s.view_entries);
    try writeStatsPlainNumber(writer, "last_observed_installed", s.last_observed_installed);
    try writeStatsPlainNumber(writer, "pending_live_dispatches", s.pending_live_dispatches);
    try writeStatsPlainNumber(writer, "overdue_blocking_removals", s.overdue_blocking_removals);
    try writeStatsPlainNumber(writer, "overdue_bookkeeping", s.overdue_bookkeeping);
    try writeStatsPlainNumber(writer, "accepted_readbacks", s.accepted_readbacks);
    try writeStatsPlainNumber(writer, "dump_interruptions", s.dump_interruptions);
    try writeStatsPlainNumber(writer, "view_rebuilds", s.view_rebuilds);
    try writeStatsPlainNumber(writer, "view_restarts", s.view_restarts);
    try writeStatsPlainNumber(writer, "incremental_updates", s.incremental_updates);
    try writeStatsPlainNumber(writer, "expiry_batches", s.expiry_batches);
    try writeStatsPlainNumber(writer, "expiries_prepared", s.expiries_prepared);
    try writeStatsPlainNumber(writer, "retirement_batches", s.retirement_batches);
    try writeStatsPlainNumber(writer, "retry_subjects_retired", s.retry_subjects_retired);
    try writeStatsPlainNumber(writer, "retry_subjects_examined", s.retry_subjects_examined);
    try writeStatsPlainNumber(writer, "retirement_pinned_state", s.retirement_pinned_state);
    try writeStatsPlainNumber(writer, "retirement_pinned_effect", s.retirement_pinned_effect);
    try writeStatsPlainNumber(writer, "retirement_refused", s.retirement_refused);
}

fn writeStatsPlainNumber(writer: anytype, name: []const u8, value: ?u64) !void {
    try writer.print("{s}\t{s}\n", .{ name, formatOptU64(value) });
}

fn writeStatsPlainBool(writer: anytype, name: []const u8, value: ?bool) !void {
    try writer.print("{s}\t{s}\n", .{ name, if (value) |v| boolValue(v) else "-" });
}

fn writeStatsTable(writer: anytype, s: StatsPayload, color: Color, columns: usize, details: bool) !void {
    try color.on(writer, Color.bold);
    try writer.writeAll("Enforcement stats\n");
    try color.off(writer);
    if (s.available != true) {
        var diagnostic: [diagnostic_max_bytes]u8 = undefined;
        try writeStatsRow(writer, "Available:", "no", columns);
        try writeStatsRow(writer, "Reason:", if (s.reason) |v| renderDiagnostic(&diagnostic, v) else "unknown", columns);
        if (s.backend) |backend| try writeStatsRow(writer, "Backend:", renderDiagnostic(&diagnostic, backend), columns);
        return;
    }
    var diagnostic: [diagnostic_max_bytes]u8 = undefined;
    try writeStatsRow(writer, "Backend:", if (s.backend) |v| renderDiagnostic(&diagnostic, v) else "unknown", columns);
    try writeStatsRow(writer, "Uptime:", if (s.uptime_seconds) |v| formatUptime(v) else "unknown", columns);
    try writeStatsRow(writer, "Snapshot age:", if (s.snapshot_age_ms) |v| formatAge(v) else "unknown", columns);
    var knowledge: [96]u8 = undefined;
    const knowledge_text = if (s.knowledge) |value| blk: {
        if (s.knowledge_age_ms) |age| break :blk std.fmt.bufPrint(&knowledge, "{s} (readback {s} ago)", .{ renderDiagnostic(&diagnostic, value), formatAge(age) }) catch "unknown";
        break :blk renderDiagnostic(&diagnostic, value);
    } else "unknown";
    try writeStatsRow(writer, "Knowledge:", knowledge_text, columns);
    try writer.writeAll("\nCurrent view\n");
    try writeStatsRow(writer, "Ready:", if (s.view_ready) |v| boolValue(v) else "unknown", columns);
    try writeStatsRow(writer, "Entries:", formatOptU64(s.view_entries), columns);
    try writeStatsRow(writer, "Last observed installed:", formatOptU64(s.last_observed_installed), columns);
    try writeStatsRow(writer, "Pending live dispatches:", formatOptU64(s.pending_live_dispatches), columns);
    try writeStatsRow(writer, "Overdue blocking removals:", formatOptU64(s.overdue_blocking_removals), columns);
    try writer.writeAll("\nActivity since daemon start\n");
    try writeStatsRow(writer, "Accepted readbacks:", formatOptU64(s.accepted_readbacks), columns);
    try writeStatsRow(writer, "Dump interruptions:", formatOptU64(s.dump_interruptions), columns);
    var completed_buffer: [32]u8 = undefined;
    var restarted_buffer: [32]u8 = undefined;
    var counts: [96]u8 = undefined;
    const completed = if (s.view_rebuilds) |value| std.fmt.bufPrint(&completed_buffer, "{d}", .{value}) catch "-" else "-";
    const restarted = if (s.view_restarts) |value| std.fmt.bufPrint(&restarted_buffer, "{d}", .{value}) catch "-" else "-";
    try writeStatsRow(writer, "View rebuilds:", std.fmt.bufPrint(&counts, "{s} completed, {s} restarted", .{ completed, restarted }) catch "-", columns);
    try writeStatsRow(writer, "Incremental updates:", formatOptU64(s.incremental_updates), columns);
    try writeStatsRow(writer, "Expiry batches:", formatOptU64(s.expiry_batches), columns);
    try writeStatsRow(writer, "Expiries prepared:", formatOptU64(s.expiries_prepared), columns);
    try writeStatsRow(writer, "Retirement batches:", formatOptU64(s.retirement_batches), columns);
    try writeStatsRow(writer, "Retry subjects retired:", formatOptU64(s.retry_subjects_retired), columns);
    if (details) {
        try writeStatsRow(writer, "Overdue bookkeeping:", formatOptU64(s.overdue_bookkeeping), columns);
        try writeStatsRow(writer, "Retry subjects examined:", formatOptU64(s.retry_subjects_examined), columns);
        try writeStatsRow(writer, "Retirement pinned state:", formatOptU64(s.retirement_pinned_state), columns);
        try writeStatsRow(writer, "Retirement pinned effect:", formatOptU64(s.retirement_pinned_effect), columns);
        try writeStatsRow(writer, "Retirement refused:", formatOptU64(s.retirement_refused), columns);
    }
}

fn writeStatsRow(writer: anytype, label: []const u8, value: []const u8, columns: usize) !void {
    try writer.writeAll(label);
    try writer.writeByte(' ');
    try writeCell(writer, value, @max(@as(usize, 4), columns -| label.len -| 1));
    try writer.writeByte('\n');
}
