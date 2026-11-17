// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Declares the status payload types and renders the per-source health, repair and loss-event parts of the status output.
// Holds: Loss-event cells and source locations are built with renderDiagnostic or written with writeEscaped before they reach the terminal.

const std = @import("std");
const Color = @import("shared.zig").Color;
const writeStatusNarrowRow = @import("shared.zig").writeStatusNarrowRow;
const rowUsed = @import("shared.zig").rowUsed;
const label_col = @import("shared.zig").label_col;
const diagnostic_max_bytes = @import("shared.zig").diagnostic_max_bytes;
const escapedLen = @import("shared.zig").escapedLen;
const writeEscaped = @import("shared.zig").writeEscaped;
const renderDiagnostic = @import("shared.zig").renderDiagnostic;
const rowLabel = @import("shared.zig").rowLabel;
const rowLabelStyled = @import("shared.zig").rowLabelStyled;
const padRightPrint = @import("shared.zig").padRightPrint;
const col_max = @import("shared.zig").col_max;
const writeCell = @import("shared.zig").writeCell;
const formatUtc = @import("shared.zig").formatUtc;

pub const StatusPayload = struct {
    version: ?[]const u8 = null,
    uptime_seconds: ?u64 = null,
    memory_bytes_used: ?u64 = null,
    memory_bytes_limit: ?u64 = null,
    memory_admission_bytes: ?u64 = null,
    active_bans: ?u32 = null,
    total_bans: ?u64 = null,
    knowledge: ?[]const u8 = null,
    confirmed_at_us: ?i64 = null,
    knowledge_age_ms: ?u64 = null,
    pending_bans: ?u64 = null,
    oldest_pending_ms: ?u64 = null,
    overdue_removals: ?u64 = null,
    oldest_overdue_ms: ?u64 = null,
    overdue_bookkeeping: ?u64 = null,
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
    paused_sources: ?u32 = null,
    missing_sources: ?u32 = null,
    state_file_bytes: ?u64 = null,
    state_file_pages: ?u64 = null,
    state_file_max_pages: ?u64 = null,
    state_file_used_pages: ?u64 = null,
    state_file_capacity_pages: ?u64 = null,
    state_file_owed_pages: ?u64 = null,
    intake: ?[]const u8 = null,
    intake_cause: ?[]const u8 = null,
    waiting_sources: ?u32 = null,
    pool_sample_available: ?bool = null,
    pool_sample_pending: ?bool = null,
    pool_sample_as_of_us: ?i64 = null,
    pool_tracked: ?u32 = null,
    pool_banned: ?u32 = null,
    pool_tracking_limit: ?u32 = null,
    pool_ban_limit: ?u32 = null,
    sources: ?[]const SourceEntry = null,
};

pub const LossEvent = struct {
    sequence: ?u64 = null,
    jail: ?[]const u8 = null,
    path: ?[]const u8 = null,
    wall_us: ?i64 = null,
    reason: ?[]const u8 = null,
    inode: ?u64 = null,
    committed_offset: ?u64 = null,
    observed_size: ?u64 = null,
};

pub const SourceEntry = struct {
    jail: ?[]const u8 = null,
    kind: ?[]const u8 = null,
    path: ?[]const u8 = null,
    on_truncation: ?[]const u8 = null,
    state: ?[]const u8 = null,
    cause: ?[]const u8 = null,
    inode: ?u64 = null,
    committed_offset: ?u64 = null,
    observed_size: ?u64 = null,
    repair: ?[]const u8 = null,
    loss_events: ?u32 = null,
    last_loss: ?LossEvent = null,
};

pub const LossReport = union(enum) {
    events: []const LossEvent,
    unavailable: []const u8,
};

pub fn writeSourcePlain(writer: anytype, source: SourceEntry) !void {
    try writer.writeAll("source\t");
    try writeEscaped(writer, source.jail orelse "-");
    try writer.writeByte('\t');
    try writeEscaped(writer, source.kind orelse "-");
    try writer.writeByte('\t');
    try writeEscaped(writer, source.path orelse "-");
    try writer.writeByte('\t');
    try writeEscaped(writer, source.state orelse "-");
    try writer.writeByte('\t');
    try writeEscaped(writer, source.cause orelse "-");
    try writer.writeByte('\t');
    try writeEscaped(writer, source.on_truncation orelse "-");
    try writer.print("\t{d}\t", .{source.loss_events orelse 0});
    if (source.last_loss) |last| {
        try writeOptInt(writer, last.wall_us, "-");
        try writer.writeByte('\t');
        try writeOptInt(writer, last.committed_offset, "-");
    } else {
        try writer.writeAll("-\t-");
    }
    try writer.writeByte('\n');
    if (source.repair) |repair| {
        try writer.writeAll("source_repair\t");
        try writeEscaped(writer, source.jail orelse "-");
        try writer.writeByte('\t');
        try writeEscaped(writer, source.path orelse "-");
        try writer.writeByte('\t');
        try writeEscaped(writer, repair);
        try writer.writeByte('\n');
    }
}

fn writeOptInt(writer: anytype, value: anytype, absent: []const u8) !void {
    if (value) |number| try writer.print("{d}", .{number}) else try writer.writeAll(absent);
}

pub fn writeLossPlain(writer: anytype, report: LossReport) !void {
    switch (report) {
        .unavailable => |message| {
            try writer.writeAll("loss_events_unavailable\t");
            try writeEscaped(writer, message);
            try writer.writeByte('\n');
        },
        .events => |events| for (events) |event| {
            try writer.writeAll("loss_event\t");
            try writeOptInt(writer, event.sequence, "-");
            try writer.writeByte('\t');
            try writeEscaped(writer, event.jail orelse "-");
            try writer.writeByte('\t');
            try writeEscaped(writer, event.path orelse "-");
            try writer.writeByte('\t');
            try writeOptInt(writer, event.wall_us, "-");
            try writer.writeByte('\t');
            try writeEscaped(writer, event.reason orelse "-");
            try writer.writeByte('\t');
            try writeOptInt(writer, event.inode, "-");
            try writer.writeByte('\t');
            try writeOptInt(writer, event.committed_offset, "-");
            try writer.writeByte('\t');
            try writeOptInt(writer, event.observed_size, "unknown");
            try writer.writeByte('\n');
        },
    }
}

const repair_steps = "run:";
const repair_none = "no offline repair applies to this cause; see the daemon log.";
const repair_restart = "It applies through the running daemon; no stop or restart is needed.";

fn isPaused(source: SourceEntry) bool {
    const state = source.state orelse return false;
    return std.mem.eql(u8, state, "paused");
}

fn stuckLabel(source: SourceEntry) ?[]const u8 {
    const state = source.state orelse return null;
    if (std.mem.eql(u8, state, "waiting")) return "Waiting:";
    if (std.mem.eql(u8, state, "broken")) return "Broken:";
    return null;
}

fn isMissing(source: SourceEntry) bool {
    const state = source.state orelse return false;
    return std.mem.eql(u8, state, "missing");
}

fn hasLossEvents(source: SourceEntry) bool {
    return (source.loss_events orelse 0) > 0;
}

fn sourceLocation(buffer: []u8, source: SourceEntry) []const u8 {
    var jail_buffer: [diagnostic_max_bytes]u8 = undefined;
    var place_buffer: [diagnostic_max_bytes]u8 = undefined;
    const jail = renderDiagnostic(&jail_buffer, source.jail orelse "-");
    const place = renderDiagnostic(&place_buffer, source.path orelse source.kind orelse "-");
    return std.fmt.bufPrint(buffer, "{s} {s}", .{ jail, place }) catch jail;
}

fn pausedValue(buffer: []u8, source: SourceEntry) []const u8 {
    var location_buffer: [2 * diagnostic_max_bytes + 1]u8 = undefined;
    var cause_buffer: [diagnostic_max_bytes]u8 = undefined;
    const location = sourceLocation(&location_buffer, source);
    const cause = renderDiagnostic(&cause_buffer, source.cause orelse "unknown");
    return std.fmt.bufPrint(buffer, "{s} ({s})", .{ location, cause }) catch "paused source";
}

fn missingValue(buffer: []u8, source: SourceEntry) []const u8 {
    return sourceLocation(buffer, source);
}

fn utcWithZone(buffer: *[40]u8, wall_us: ?i64) []const u8 {
    var time_buffer: [32]u8 = undefined;
    const time = formatUtc(&time_buffer, wall_us);
    if (time.len != 19) return std.fmt.bufPrint(buffer, "{s}", .{time}) catch "-";
    return std.fmt.bufPrint(buffer, "{s} UTC", .{time}) catch "-";
}

fn lossValue(buffer: []u8, source: SourceEntry) []const u8 {
    var location_buffer: [2 * diagnostic_max_bytes + 1]u8 = undefined;
    const location = sourceLocation(&location_buffer, source);
    const count = source.loss_events orelse 0;
    const last = source.last_loss orelse return std.fmt.bufPrint(buffer, "{s}: {d}", .{ location, count }) catch "loss events";
    var time_buffer: [40]u8 = undefined;
    var reason_buffer: [diagnostic_max_bytes]u8 = undefined;
    return std.fmt.bufPrint(buffer, "{s}: {d}; latest {s}, {s} at offset {d}", .{
        location,
        count,
        utcWithZone(&time_buffer, last.wall_us),
        renderDiagnostic(&reason_buffer, last.reason orelse "-"),
        last.committed_offset orelse 0,
    }) catch "loss events";
}

fn writeWrapped(writer: anytype, text: []const u8, first_indent: []const u8, rest_indent: []const u8, columns: usize) !void {
    var rest = text;
    var indent = first_indent;
    while (true) {
        try writer.writeAll(indent);
        const room = @max(@as(usize, 8), columns -| indent.len);
        if (rest.len <= room) {
            try writer.writeAll(rest);
            try writer.writeByte('\n');
            return;
        }
        var cut = room;
        while (cut > 0 and rest[cut] != ' ') cut -= 1;
        if (cut == 0) cut = room;
        try writer.writeAll(rest[0..cut]);
        try writer.writeByte('\n');
        rest = std.mem.trimLeft(u8, rest[cut..], " ");
        indent = rest_indent;
    }
}

pub fn writeSourcesNarrow(writer: anytype, s: StatusPayload, color: Color, columns: usize) !void {
    for (s.sources orelse &.{}) |source| {
        if (!isMissing(source)) continue;
        var value_buffer: [512]u8 = undefined;
        try writer.writeAll("Missing: ");
        try color.on(writer, Color.yellow);
        try writeCell(writer, missingValue(&value_buffer, source), @max(@as(usize, 4), columns -| "Missing: ".len));
        try color.off(writer);
        try writer.writeByte('\n');
    }
    for (s.sources orelse &.{}) |source| {
        if (!isPaused(source)) continue;
        var value_buffer: [512]u8 = undefined;
        try writer.writeAll("Paused: ");
        try color.on(writer, Color.yellow);
        try writeCell(writer, pausedValue(&value_buffer, source), @max(@as(usize, 4), columns -| "Paused: ".len));
        try color.off(writer);
        try writer.writeByte('\n');
        if (source.repair) |repair| {
            try writer.print("  Repair: {s}\n    ", .{repair_steps});
            try writeEscaped(writer, repair);
            try writer.writeByte('\n');
            try writeWrapped(writer, repair_restart, "  ", "    ", columns);
        } else {
            try writer.print("  Repair: {s}\n", .{repair_none});
        }
    }
    for (s.sources orelse &.{}) |source| {
        const label = stuckLabel(source) orelse continue;
        var value_buffer: [512]u8 = undefined;
        try writer.print("{s} ", .{label});
        try color.on(writer, Color.yellow);
        try writeCell(writer, pausedValue(&value_buffer, source), @max(@as(usize, 4), columns -| (label.len + 1)));
        try color.off(writer);
        try writer.writeByte('\n');
    }
    for (s.sources orelse &.{}) |source| {
        if (!hasLossEvents(source)) continue;
        var value_buffer: [512]u8 = undefined;
        try writeStatusNarrowRow(writer, "Loss events: ", lossValue(&value_buffer, source), columns);
    }
}

pub fn writeSourcesBoxed(writer: anytype, s: StatusPayload, color: Color, width: usize) !void {
    for (s.sources orelse &.{}) |source| {
        if (!isMissing(source)) continue;
        var value_buffer: [512]u8 = undefined;
        try rowLabelStyled(writer, color, Color.yellow, "Missing:", missingValue(&value_buffer, source), width, false);
    }
    for (s.sources orelse &.{}) |source| {
        if (!isPaused(source)) continue;
        var value_buffer: [512]u8 = undefined;
        try rowLabelStyled(writer, color, Color.yellow, "Paused:", pausedValue(&value_buffer, source), width, false);
        if (source.repair) |repair| {
            try rowLabel(writer, "  Repair:", repair_steps, width);
            try rowLabelStyled(writer, .{ .enabled = false }, "", "", repair, width, true);
            try rowLabel(writer, "", repair_restart, width);
        } else {
            try rowLabel(writer, "  Repair:", repair_none, width);
        }
    }
    for (s.sources orelse &.{}) |source| {
        const label = stuckLabel(source) orelse continue;
        var value_buffer: [512]u8 = undefined;
        try rowLabelStyled(writer, color, Color.yellow, label, pausedValue(&value_buffer, source), width, false);
    }
    for (s.sources orelse &.{}) |source| {
        if (!hasLossEvents(source)) continue;
        var value_buffer: [512]u8 = undefined;
        try rowLabel(writer, "Loss events:", lossValue(&value_buffer, source), width);
    }
}

pub fn sourcesWidth(s: StatusPayload) usize {
    var used: usize = 0;
    for (s.sources orelse &.{}) |source| {
        var value_buffer: [512]u8 = undefined;
        if (isMissing(source)) used = @max(used, rowUsed(missingValue(&value_buffer, source)));
        if (stuckLabel(source) != null) used = @max(used, rowUsed(pausedValue(&value_buffer, source)));
        if (isPaused(source)) {
            used = @max(used, rowUsed(pausedValue(&value_buffer, source)));
            if (source.repair) |repair| {
                used = @max(used, rowUsed(repair_restart));
                used = @max(used, 2 + label_col + escapedLen(repair));
            } else {
                used = @max(used, rowUsed(repair_none));
            }
        }
        if (hasLossEvents(source)) used = @max(used, rowUsed(lossValue(&value_buffer, source)));
    }
    return used;
}

const loss_gap: usize = 2;

fn lossColumn(header: []const u8, longest: usize) usize {
    return @max(header.len, @min(longest, col_max)) + loss_gap;
}

fn numberCell(buffer: *[24]u8, value: ?u64, absent: []const u8) []const u8 {
    const number = value orelse return absent;
    return std.fmt.bufPrint(buffer, "{d}", .{number}) catch "-";
}

const LossRow = struct {
    jail_buffer: [diagnostic_max_bytes]u8 = undefined,
    path_buffer: [diagnostic_max_bytes]u8 = undefined,
    time_buffer: [40]u8 = undefined,
    reason_buffer: [diagnostic_max_bytes]u8 = undefined,
    inode_buffer: [24]u8 = undefined,
    offset_buffer: [24]u8 = undefined,
    size_buffer: [24]u8 = undefined,
    jail: []const u8 = "",
    path: []const u8 = "",
    time: []const u8 = "",
    reason: []const u8 = "",
    inode: []const u8 = "",
    offset: []const u8 = "",
    size: []const u8 = "",

    fn fill(self: *LossRow, event: LossEvent) void {
        self.jail = renderDiagnostic(&self.jail_buffer, event.jail orelse "-");
        self.path = renderDiagnostic(&self.path_buffer, event.path orelse "-");
        self.time = utcWithZone(&self.time_buffer, event.wall_us);
        self.reason = renderDiagnostic(&self.reason_buffer, event.reason orelse "-");
        self.inode = numberCell(&self.inode_buffer, event.inode, "-");
        self.offset = numberCell(&self.offset_buffer, event.committed_offset, "-");
        self.size = numberCell(&self.size_buffer, event.observed_size, "unknown");
    }
};

const LossWidths = struct {
    jail: usize = 0,
    path: usize = 0,
    time: usize = 0,
    reason: usize = 0,
    inode: usize = 0,
    offset: usize = 0,
    size: usize = 0,

    fn widen(self: *LossWidths, row: LossRow) void {
        self.jail = @max(self.jail, row.jail.len);
        self.path = @max(self.path, row.path.len);
        self.time = @max(self.time, row.time.len);
        self.reason = @max(self.reason, row.reason.len);
        self.inode = @max(self.inode, row.inode.len);
        self.offset = @max(self.offset, row.offset.len);
        self.size = @max(self.size, row.size.len);
    }
};

pub fn writeLossTable(writer: anytype, report: LossReport, color: Color, columns: usize) !void {
    try writer.writeByte('\n');
    switch (report) {
        .unavailable => |message| {
            try writer.writeAll("Continuity loss events: unavailable (");
            try writeEscaped(writer, message);
            try writer.writeAll(")\n");
        },
        .events => |events| {
            if (events.len == 0) return writer.writeAll("Continuity loss events: none\n");
            try writer.writeAll("Continuity loss events (newest first)\n");
            var widest: LossWidths = .{};
            for (events) |event| {
                var row: LossRow = .{};
                row.fill(event);
                widest.widen(row);
            }
            const jail_col = lossColumn("JAIL", widest.jail);
            const path_col = lossColumn("PATH", widest.path);
            const time_col = lossColumn("TIME", widest.time);
            const reason_col = lossColumn("REASON", widest.reason);
            const inode_col = lossColumn("INODE", widest.inode);
            const offset_col = lossColumn("OFFSET", widest.offset);
            const size_width = @max("SIZE".len, widest.size);
            if (jail_col + path_col + time_col + reason_col + inode_col + offset_col + size_width > columns) {
                try writeLossStacked(writer, events, columns);
            } else {
                try color.on(writer, Color.bold);
                try padRightPrint(writer, "JAIL", jail_col);
                try padRightPrint(writer, "PATH", path_col);
                try padRightPrint(writer, "TIME", time_col);
                try padRightPrint(writer, "REASON", reason_col);
                try padRightPrint(writer, "INODE", inode_col);
                try padRightPrint(writer, "OFFSET", offset_col);
                try writer.writeAll("SIZE");
                try color.off(writer);
                try writer.writeByte('\n');
                for (events) |event| {
                    var row: LossRow = .{};
                    row.fill(event);
                    try writeCell(writer, row.jail, jail_col);
                    try writeCell(writer, row.path, path_col);
                    try writeCell(writer, row.time, time_col);
                    try writeCell(writer, row.reason, reason_col);
                    try writeCell(writer, row.inode, inode_col);
                    try writeCell(writer, row.offset, offset_col);
                    try writer.print("{s}\n", .{row.size});
                }
            }
            try writer.print("Total: {d} events\n", .{events.len});
        },
    }
}

fn writeLossStacked(writer: anytype, events: []const LossEvent, columns: usize) !void {
    for (events, 0..) |event, index| {
        var row: LossRow = .{};
        row.fill(event);
        if (index > 0) try writer.writeByte('\n');
        try writeStatusNarrowRow(writer, "JAIL:   ", row.jail, columns);
        try writeStatusNarrowRow(writer, "PATH:   ", row.path, columns);
        try writeStatusNarrowRow(writer, "TIME:   ", row.time, columns);
        try writeStatusNarrowRow(writer, "REASON: ", row.reason, columns);
        try writeStatusNarrowRow(writer, "INODE:  ", row.inode, columns);
        try writeStatusNarrowRow(writer, "OFFSET: ", row.offset, columns);
        try writeStatusNarrowRow(writer, "SIZE:   ", row.size, columns);
    }
}
