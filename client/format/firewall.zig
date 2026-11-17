// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Renders the owned firewall view: state, readback coverage, last attempt, owned items and table, chain, set and rule structure.
// Holds: Each daemon-supplied string in plain and table output passes through renderDiagnostic; JSON output is the daemon's bytes as sent.

const std = @import("std");
const OutputFormat = @import("shared.zig").OutputFormat;
const Color = @import("shared.zig").Color;
const terminalColumns = @import("shared.zig").terminalColumns;
const diagnostic_max_bytes = @import("shared.zig").diagnostic_max_bytes;
const renderDiagnostic = @import("shared.zig").renderDiagnostic;
const repeatChar = @import("shared.zig").repeatChar;
const padRightPrint = @import("shared.zig").padRightPrint;
const colWidth = @import("shared.zig").colWidth;
const writeCell = @import("shared.zig").writeCell;
const ScopeView = @import("shared.zig").ScopeView;
const plainBool = @import("shared.zig").plainBool;
const plainInt = @import("shared.zig").plainInt;
const scopeAddress = @import("shared.zig").scopeAddress;
const scope_match_max_bytes = @import("shared.zig").scope_match_max_bytes;
const scopeMatch = @import("shared.zig").scopeMatch;
const itemKey = @import("shared.zig").itemKey;
const formatUtc = @import("shared.zig").formatUtc;

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
    origin: ?[]const u8 = null,
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

pub fn formatFirewall(allocator: std.mem.Allocator, writer: anytype, payload_json: []const u8, fmt: OutputFormat, color: Color) !void {
    return formatFirewallWithDetails(allocator, writer, payload_json, fmt, color, false);
}

pub fn formatFirewallDetailed(allocator: std.mem.Allocator, writer: anytype, payload_json: []const u8, fmt: OutputFormat, color: Color) !void {
    return formatFirewallWithDetails(allocator, writer, payload_json, fmt, color, true);
}

fn formatFirewallWithDetails(allocator: std.mem.Allocator, writer: anytype, payload_json: []const u8, fmt: OutputFormat, color: Color, details: bool) !void {
    return formatFirewallForWidthDetailed(allocator, writer, payload_json, fmt, color, terminalColumns(), details);
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
        try firewallPlainText(writer, try itemKey(&key, index, "origin"), item.origin);
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
    var widest_origin: usize = 0;
    for (items) |item| {
        var address: [64]u8 = undefined;
        var safe_address: [diagnostic_max_bytes]u8 = undefined;
        var match: [scope_match_max_bytes]u8 = undefined;
        var origin: [diagnostic_max_bytes]u8 = undefined;
        widest_scope = @max(widest_scope, firewallScopeText(&address, &safe_address, item.scope).len);
        widest_match = @max(widest_match, scopeMatch(&match, item.scope).len);
        widest_origin = @max(widest_origin, (if (item.origin) |value| renderDiagnostic(&origin, value) else "-").len);
    }
    const scope_col = colWidth("SCOPE", widest_scope);
    const match_col = colWidth("MATCH", widest_match);
    const origin_col = colWidth("ORIGIN", widest_origin);
    const full_width = scope_col + match_col + origin_col + (if (details) @as(usize, 13) else 0) + 18 + 21;
    if (full_width > columns) return writeFirewallItemsStacked(writer, items, color, columns, details);

    try color.on(writer, Color.bold);
    try padRightPrint(writer, "SCOPE", scope_col);
    try padRightPrint(writer, "MATCH", match_col);
    try padRightPrint(writer, "ORIGIN", origin_col);
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
        var origin: [diagnostic_max_bytes]u8 = undefined;
        try writeCell(writer, if (item.origin) |value| renderDiagnostic(&origin, value) else "-", origin_col);
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
        var origin: [diagnostic_max_bytes]u8 = undefined;
        try writeFirewallSummaryRow(writer, "Origin:       ", if (item.origin) |value| renderDiagnostic(&origin, value) else "-", columns);
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
