// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Renders the confirmed ban history page as JSON, plain item lines or a table, with its generation and next-page cursor.
// Holds: Matched lines and scope matches are escaped; jail, origin, address, ids, generation and cursor print as the daemon sent them.

const std = @import("std");
const OutputFormat = @import("shared.zig").OutputFormat;
const Color = @import("shared.zig").Color;
const terminalColumns = @import("shared.zig").terminalColumns;
const diagnostic_max_bytes = @import("shared.zig").diagnostic_max_bytes;
const repeatChar = @import("shared.zig").repeatChar;
const matchedText = @import("shared.zig").matchedText;
const writeMatchedLine = @import("shared.zig").writeMatchedLine;
const padRightPrint = @import("shared.zig").padRightPrint;
const longestLen = @import("shared.zig").longestLen;
const colWidth = @import("shared.zig").colWidth;
const writeCell = @import("shared.zig").writeCell;
const ScopeView = @import("shared.zig").ScopeView;
const formatQuery = @import("shared.zig").formatQuery;
const plainOpt = @import("shared.zig").plainOpt;
const plainBool = @import("shared.zig").plainBool;
const plainInt = @import("shared.zig").plainInt;
const boolStr = @import("shared.zig").boolStr;
const scopeAddress = @import("shared.zig").scopeAddress;
const scope_match_max_bytes = @import("shared.zig").scope_match_max_bytes;
const scopeMatch = @import("shared.zig").scopeMatch;
const itemKey = @import("shared.zig").itemKey;
const formatOptU64Local = @import("shared.zig").formatOptU64Local;
const formatUtc = @import("shared.zig").formatUtc;

pub const HistoryEntry = struct {
    sequence: ?u64 = null,
    event_id_hex: ?[]const u8 = null,
    jail: ?[]const u8 = null,
    decision_id_hex: ?[]const u8 = null,
    confirmed_us: ?i64 = null,
    scope: ?ScopeView = null,
    native_retry: ?bool = null,
    origin: ?[]const u8 = null,
    matches: ?[]const []const u8 = null,
};

pub const HistoryPayload = struct {
    generation: ?[]const u8 = null,
    items: ?[]const HistoryEntry = null,
    next_cursor: ?[]const u8 = null,
};

pub fn formatHistory(allocator: std.mem.Allocator, writer: anytype, payload_json: []const u8, fmt: OutputFormat, color: Color) !void {
    return formatQuery(HistoryPayload, "history", writeHistoryPlain, writeHistoryTable, allocator, writer, payload_json, fmt, color);
}

pub fn formatHistoryDetailed(allocator: std.mem.Allocator, writer: anytype, payload_json: []const u8, fmt: OutputFormat, color: Color) !void {
    return formatQuery(HistoryPayload, "history", writeHistoryPlainDetailed, writeHistoryTableDetailed, allocator, writer, payload_json, fmt, color);
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
    return writeHistoryPlainWithDetails(writer, p, false);
}

fn writeHistoryPlainDetailed(writer: anytype, p: HistoryPayload) !void {
    return writeHistoryPlainWithDetails(writer, p, true);
}

fn writeHistoryPlainWithDetails(writer: anytype, p: HistoryPayload, details: bool) !void {
    try plainOpt(writer, "generation", p.generation);
    for (p.items orelse &.{}, 0..) |it, i| {
        var key: [64]u8 = undefined;
        var addr: [64]u8 = undefined;
        try plainInt(writer, try itemKey(&key, i, "sequence"), it.sequence);
        try plainOpt(writer, try itemKey(&key, i, "jail"), it.jail);
        try plainOpt(writer, try itemKey(&key, i, "origin"), it.origin);
        try plainOpt(writer, try itemKey(&key, i, "scope"), scopeAddress(&addr, it.scope));
        try plainInt(writer, try itemKey(&key, i, "confirmed_us"), it.confirmed_us);
        try plainBool(writer, try itemKey(&key, i, "native_retry"), it.native_retry);
        try plainOpt(writer, try itemKey(&key, i, "decision_id"), it.decision_id_hex);
        try plainOpt(writer, try itemKey(&key, i, "event_id"), it.event_id_hex);
        if (details) {
            var matched: [diagnostic_max_bytes]u8 = undefined;
            try plainOpt(writer, try itemKey(&key, i, "matches"), matchedText(&matched, it.matches));
        }
    }
    try plainOpt(writer, "next_cursor", p.next_cursor);
}

fn writeHistoryTable(writer: anytype, p: HistoryPayload, color: Color) !void {
    return writeHistoryTableWithDetails(writer, p, color, false);
}

fn writeHistoryTableDetailed(writer: anytype, p: HistoryPayload, color: Color) !void {
    return writeHistoryTableWithDetails(writer, p, color, true);
}

fn writeHistoryTableWithDetails(writer: anytype, p: HistoryPayload, color: Color, details: bool) !void {
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
        const origin_col = colWidth("ORIGIN", longestLen(HistoryEntry, items, "origin"));
        const addr_col = colWidth("SCOPE", widest_addr);
        const match_col = colWidth("MATCH", widest_match);
        try color.on(writer, Color.bold);
        try padRightPrint(writer, "SEQ", seq_col);
        try padRightPrint(writer, "JAIL", jail_col);
        try padRightPrint(writer, "ORIGIN", origin_col);
        try padRightPrint(writer, "SCOPE", addr_col);
        try padRightPrint(writer, "MATCH", match_col);
        try padRightPrint(writer, "CONFIRMED (UTC)", 21);
        try padRightPrint(writer, "RETRY", 7);
        try padRightPrint(writer, "DECISION", 13);
        try color.off(writer);
        try writer.writeAll("\n");
        try repeatChar(writer, '-', seq_col + jail_col + origin_col + addr_col + match_col + 41);
        try writer.writeAll("\n");
        for (items) |it| {
            var addr: [64]u8 = undefined;
            var match: [scope_match_max_bytes]u8 = undefined;
            var when: [32]u8 = undefined;
            try padRightPrint(writer, formatOptU64Local(it.sequence), seq_col);
            try writeCell(writer, it.jail orelse "-", jail_col);
            try writeCell(writer, it.origin orelse "-", origin_col);
            try writeCell(writer, scopeAddress(&addr, it.scope), addr_col);
            try writeCell(writer, scopeMatch(&match, it.scope), match_col);
            try padRightPrint(writer, formatUtc(&when, it.confirmed_us), 21);
            try padRightPrint(writer, boolStr(it.native_retry), 7);
            try padRightPrint(writer, shortHex(it.decision_id_hex), 13);
            try writer.writeAll("\n");
            if (details) try writeMatchedLine(writer, it.matches, terminalColumns());
        }
        try writer.print("Total: {d} events\n", .{items.len});
    }
    try writePageFooter(writer, p.generation, p.next_cursor);
}
