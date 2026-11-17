// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Renders ignore add, remove and list outcomes, including the bans each change kept or lifted and the commands that lift them.
// Holds: Jail, address, entry and ban text goes through writeEscaped, and a suggested shell argument is single-quoted unless it is bare.

const std = @import("std");
const OutputFormat = @import("shared.zig").OutputFormat;
const Color = @import("shared.zig").Color;
const terminalColumns = @import("shared.zig").terminalColumns;
const diagnostic_max_bytes = @import("shared.zig").diagnostic_max_bytes;
const escapedLen = @import("shared.zig").escapedLen;
const writeEscaped = @import("shared.zig").writeEscaped;
const renderDiagnostic = @import("shared.zig").renderDiagnostic;
const writeSpaces = @import("shared.zig").writeSpaces;
const formatRemaining = @import("shared.zig").formatRemaining;
const col_max = @import("shared.zig").col_max;
const writeClipped = @import("shared.zig").writeClipped;
const formatUtc = @import("shared.zig").formatUtc;

const IgnoreBan = struct {
    scope: []const u8 = "",
    deadline_us: ?i64 = null,
    permanent: bool = false,
    confirmed: bool = false,
    relation: []const u8 = "",
    lift: []const u8 = "",
    lift_reason: ?[]const u8 = null,
};

const IgnoreOutcome = struct {
    kind: []const u8 = "",
    outcome: []const u8 = "",
    generation: []const u8 = "",
    mutation_revision: u64 = 0,
    enforced: bool = false,
    reasons: []const []const u8 = &.{},
    jail: []const u8 = "",
    address: []const u8 = "",
    entry: []const u8 = "",
    source: ?[]const u8 = null,
    covered_by: []const []const u8 = &.{},
    still_ignored_by: []const []const u8 = &.{},
    unban_requested: bool = false,
    bans_total: u32 = 0,
    jail_enabled: ?bool = null,
    jail_paused: ?bool = null,
    bans: []const IgnoreBan = &.{},
};

const IgnoreListEntry = struct {
    address: []const u8 = "",
    source: []const u8 = "",
    expires_us: ?i64 = null,
    remaining_s: ?u64 = null,
    expired: bool = false,
};

const IgnoreListJail = struct {
    jail: []const u8 = "",
    count: u32 = 0,
    limit: ?u32 = null,
    ignore_file: ?[]const u8 = null,
    entries: []const IgnoreListEntry = &.{},
};

const IgnoreUnconfigured = struct {
    jail: []const u8 = "",
    runtime_entries: u32 = 0,
};

const IgnoreListPayload = struct {
    redacted: bool = false,
    limit: u32 = 128,
    jails: []const IgnoreListJail = &.{},
    unconfigured: []const IgnoreUnconfigured = &.{},
};

const ignore_listed_bans_max: usize = 10;
const ignore_ban_column_gap: usize = 4;
const ignore_list_gap: usize = 2;

fn writeJsonDocument(writer: anytype, payload_json: []const u8) !void {
    try writer.writeAll(payload_json);
    if (payload_json.len == 0 or payload_json[payload_json.len - 1] != '\n') try writer.writeAll("\n");
}

fn printEscaped(writer: anytype, comptime template: []const u8, values: anytype) !void {
    comptime var rest: []const u8 = template;
    inline for (values) |value| {
        const split = comptime std.mem.indexOf(u8, rest, "{}") orelse @compileError("template has fewer placeholders than values");
        try writer.writeAll(rest[0..split]);
        try writeEscaped(writer, value);
        rest = rest[split + 2 ..];
    }
    try writer.writeAll(rest);
}

fn isShellBare(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or std.mem.indexOfScalar(u8, "._:/@%+=,-", byte) != null;
}

fn writeShellArg(writer: anytype, text: []const u8) !void {
    var bare = text.len != 0;
    for (text) |byte| bare = bare and isShellBare(byte);
    if (bare) return writer.writeAll(text);
    try writer.writeByte('\'');
    var start: usize = 0;
    for (text, 0..) |byte, index| {
        // Why: writeEscaped would double a backslash, which single quotes keep literally, so a backslash is written as itself.
        if (byte != '\'' and byte != '\\') continue;
        try writeEscaped(writer, text[start..index]);
        try writer.writeAll(if (byte == '\'') "'\\''" else "\\");
        start = index + 1;
    }
    try writeEscaped(writer, text[start..]);
    try writer.writeByte('\'');
}

fn writeJoined(writer: anytype, values: []const []const u8) !void {
    for (values, 0..) |value, index| {
        if (index != 0) try writer.writeAll(", ");
        try writeEscaped(writer, value);
    }
}

fn networkBase(scope: []const u8) []const u8 {
    return scope[0 .. std.mem.indexOfScalar(u8, scope, '/') orelse scope.len];
}

pub fn formatIgnoreOutcome(allocator: std.mem.Allocator, writer: anytype, payload_json: []const u8, fmt: OutputFormat) !void {
    switch (fmt) {
        .json => try writeJsonDocument(writer, payload_json),
        .plain, .table => {
            const parsed = try std.json.parseFromSlice(IgnoreOutcome, allocator, payload_json, .{ .ignore_unknown_fields = true, .allocate = .alloc_always });
            defer parsed.deinit();
            if (fmt == .plain) try writeIgnoreOutcomePlain(writer, parsed.value) else try writeIgnoreOutcomeTable(writer, parsed.value);
        },
    }
}

fn writeIgnoreOutcomePlain(writer: anytype, o: IgnoreOutcome) !void {
    try writer.print("kind\t{s}\noutcome\t{s}\nenforced\t{}\ngeneration\t{s}\nmutation_revision\t{d}\n", .{ o.kind, o.outcome, o.enforced, o.generation, o.mutation_revision });
    try printEscaped(writer, "jail\t{}\naddress\t{}\nentry\t{}\n", .{ o.jail, o.address, o.entry });
    if (std.mem.eql(u8, o.kind, "ignore_remove")) {
        for (o.still_ignored_by) |covering| try printEscaped(writer, "still_ignored_by\t{}\n", .{covering});
    } else {
        try printEscaped(writer, "source\t{}\n", .{o.source orelse "-"});
        for (o.covered_by) |covering| try printEscaped(writer, "covered_by\t{}\n", .{covering});
        try writer.print("bans_total\t{d}\n", .{o.bans_total});
        for (o.bans) |ban| {
            try printEscaped(writer, "ban\t{}\t", .{ban.scope});
            if (ban.permanent) {
                try writer.writeAll("permanent");
            } else if (ban.deadline_us) |deadline| {
                try writer.print("{d}", .{deadline});
            } else {
                try writer.writeAll("-");
            }
            try printEscaped(writer, "\t{}\t{}\t{}\n", .{ if (ban.confirmed) "confirmed" else "pending", ban.relation, ban.lift });
        }
    }
    for (o.reasons) |reason| try printEscaped(writer, "reason\t{}\n", .{reason});
}

fn writeIgnoreOutcomeTable(writer: anytype, o: IgnoreOutcome) !void {
    if (std.mem.eql(u8, o.kind, "ignore_remove")) return writeIgnoreRemoveTable(writer, o);
    return writeIgnoreAddTable(writer, o);
}

fn isStaleReason(reason: []const u8) bool {
    return std.mem.startsWith(u8, reason, "stale generation") or std.mem.eql(u8, reason, "StaleAdminRevision");
}

fn writeIgnoreReasons(writer: anytype, o: IgnoreOutcome) !void {
    const refused = std.mem.eql(u8, o.outcome, "rejected") or std.mem.eql(u8, o.outcome, "absent");
    var stale = false;
    for (o.reasons) |reason| {
        if (refused) try writer.writeAll("Refused: ");
        try printEscaped(writer, "{}\n", .{reason});
        stale = stale or isStaleReason(reason);
    }
    if (o.reasons.len == 0) {
        if (refused) try writer.writeAll("Refused: no reason reported.\n") else try printEscaped(writer, "Outcome {}: no reason reported.\n", .{o.outcome});
    }
    if (stale) try writer.writeAll("Retry the command.\n");
}

fn writeIgnoreRemoveTable(writer: anytype, o: IgnoreOutcome) !void {
    if (!std.mem.eql(u8, o.entry, "removed")) {
        try writeIgnoreReasons(writer, o);
        if (std.mem.eql(u8, o.entry, "absent") and o.still_ignored_by.len != 0) {
            try printEscaped(writer, "The configuration covers {} in {} through ", .{ o.address, o.jail });
            try writeJoined(writer, o.still_ignored_by);
            try writer.writeAll("; edit ignoreip to change that.\n");
        }
        return;
    }
    try printEscaped(writer, "Removed runtime ignore entry {} from jail {}.\n", .{ o.address, o.jail });
    if (o.still_ignored_by.len == 0) {
        try printEscaped(writer, "New events from {} in {} are detected again.\n", .{ o.address, o.jail });
        return;
    }
    try printEscaped(writer, "{} remains ignored in {}: the configuration ", .{ o.address, o.jail });
    for (o.still_ignored_by) |covering| {
        if (std.mem.eql(u8, covering, o.address)) {
            try printEscaped(writer, "lists {}.\n", .{o.address});
            return;
        }
    }
    try writer.writeAll("covers it through ");
    try writeJoined(writer, o.still_ignored_by);
    try writer.writeAll(".\n");
}

fn writeBanDeadline(writer: anytype, ban: IgnoreBan, comptime timed_tail: []const u8) !void {
    if (ban.permanent) return writer.writeAll(" permanently. The ban stays until it is lifted.\n");
    var buffer: [32]u8 = undefined;
    try writer.print(" until {s} UTC" ++ timed_tail, .{formatUtc(&buffer, ban.deadline_us)});
}

fn writeLiftHint(writer: anytype, o: IgnoreOutcome, comptime pronoun: []const u8) !void {
    try writer.writeAll("To lift " ++ pronoun ++ " now: fail2zig ignore add ");
    try writeShellArg(writer, o.address);
    try writer.writeAll(" --jail ");
    try writeShellArg(writer, o.jail);
    try writer.writeAll(" --unban\n");
}

fn writeWiderBanLift(writer: anytype, o: IgnoreOutcome, ban: IgnoreBan) !void {
    try writer.writeAll("fail2zig unban ");
    try writeShellArg(writer, networkBase(ban.scope));
    try writer.writeAll(" --jail ");
    try writeShellArg(writer, o.jail);
    try writer.writeAll(" --scope net ");
    try writeShellArg(writer, ban.scope);
    try writer.writeAll("\n");
}

fn isInsideEntry(ban: IgnoreBan) bool {
    return std.mem.eql(u8, ban.relation, "inside_entry");
}

fn isKept(ban: IgnoreBan) bool {
    return std.mem.eql(u8, ban.lift, "kept");
}

const LiftResult = enum { kept, confirmed, incomplete, unknown, refused };

fn liftResult(ban: IgnoreBan) LiftResult {
    return std.meta.stringToEnum(LiftResult, ban.lift) orelse .unknown;
}

fn writeIgnoreAddTable(writer: anytype, o: IgnoreOutcome) !void {
    const added = std.mem.eql(u8, o.entry, "added");
    if (!added and !std.mem.eql(u8, o.entry, "present")) return writeIgnoreReasons(writer, o);

    if (!added) {
        try printEscaped(writer, "{} is already a runtime ignore entry in jail {}. Nothing changed.\n", .{ o.address, o.jail });
    } else {
        try printEscaped(writer, "Added runtime ignore entry {} to jail {}.\n", .{ o.address, o.jail });
        if (o.jail_enabled == false) try printEscaped(writer, "Jail {} is disabled; the entry applies when it is enabled.\n", .{o.jail});
        if (o.jail_paused == true) try printEscaped(writer, "Jail {} is paused; the entry applies when it resumes.\n", .{o.jail});
        const also_configured = if (o.source) |source| std.mem.eql(u8, source, "config+runtime") else false;
        if (also_configured) {
            try printEscaped(writer, "The configuration also lists {} for {}; its source is now config+runtime.\n", .{ o.address, o.jail });
        } else {
            try printEscaped(writer, "New events from {} in {} will not lead to a ban.\n", .{ o.address, o.jail });
        }
    }

    if (o.covered_by.len != 0) {
        try printEscaped(writer, "The configuration already covers {} in {} through ", .{ o.address, o.jail });
        try writeJoined(writer, o.covered_by);
        try writer.writeAll(".\n");
    }

    if (o.unban_requested) try writeIgnoreLifts(writer, o) else try writeIgnoreKeptBans(writer, o);

    if (std.mem.endsWith(u8, o.address, "/0")) {
        const family = if (std.mem.indexOfScalar(u8, o.address, ':') != null) "IPv6" else "IPv4";
        try writer.print("This entry covers every {s} address: jail ", .{family});
        try writeEscaped(writer, o.jail);
        try writer.print(" will not ban any {s} address from new events.\n", .{family});
    }
}

fn writeIgnoreKeptBans(writer: anytype, o: IgnoreOutcome) !void {
    var inside_kept: usize = 0;
    var inside_total: usize = 0;
    for (o.bans) |ban| {
        if (!isInsideEntry(ban)) continue;
        inside_total += 1;
        if (isKept(ban)) inside_kept += 1;
    }
    const hidden_inside = @as(usize, o.bans_total) -| o.bans.len;

    if (inside_kept == 1) {
        for (o.bans) |ban| {
            if (!isInsideEntry(ban) or !isKept(ban)) continue;
            try printEscaped(writer, "{} ", .{ban.scope});
            try writer.writeAll(if (ban.confirmed) "is banned" else "has a pending ban");
            try printEscaped(writer, " in {}", .{o.jail});
            try writeBanDeadline(writer, ban, ". The ban stays until then.\n");
        }
        try writeLiftHint(writer, o, "it");
    } else if (inside_kept > 1) {
        const listed = @min(inside_kept, ignore_listed_bans_max);
        const total = inside_total + hidden_inside;
        try writer.print("{d} bans in ", .{total});
        try printEscaped(writer, "{} fall inside {}. They stay until their deadlines:\n", .{ o.jail, o.address });
        var scope_width: usize = 0;
        var seen: usize = 0;
        for (o.bans) |ban| {
            if (!isInsideEntry(ban) or !isKept(ban)) continue;
            if (seen == listed) break;
            seen += 1;
            scope_width = @max(scope_width, escapedLen(ban.scope));
        }
        seen = 0;
        for (o.bans) |ban| {
            if (!isInsideEntry(ban) or !isKept(ban)) continue;
            if (seen == listed) break;
            seen += 1;
            try writer.writeAll("  ");
            try writeEscaped(writer, ban.scope);
            try writeSpaces(writer, scope_width + ignore_ban_column_gap - escapedLen(ban.scope));
            if (ban.permanent) {
                try writer.writeAll(if (ban.confirmed) "permanent\n" else "pending, permanent\n");
            } else {
                var buffer: [32]u8 = undefined;
                try writer.print("{s}until {s} UTC\n", .{ if (ban.confirmed) "" else "pending, ", formatUtc(&buffer, ban.deadline_us) });
            }
        }
        if (total > listed) {
            try writer.print("  and {d} more; see fail2zig list --jail ", .{total - listed});
            try writeShellArg(writer, o.jail);
            try writer.writeAll("\n");
        }
        try writeLiftHint(writer, o, "them");
    }

    for (o.bans) |ban| {
        if (isInsideEntry(ban) or !isKept(ban)) continue;
        try printEscaped(writer, "{} is inside the ", .{o.address});
        try writer.writeAll(if (ban.confirmed) "network ban " else "pending network ban ");
        try printEscaped(writer, "{} in {}", .{ ban.scope, o.jail });
        try writeBanDeadline(writer, ban, ". The ban stays until then.\n");
        try writer.writeAll("--unban does not lift a ban wider than the entry. To lift it: ");
        try writeWiderBanLift(writer, o, ban);
    }
}

fn writeIgnoreLifts(writer: anytype, o: IgnoreOutcome) !void {
    if (o.bans_total == 0) {
        try printEscaped(writer, "No ban in {} falls inside {}; nothing to lift.\n", .{ o.jail, o.address });
        return;
    }
    var attempted: usize = 0;
    var confirmed: usize = 0;
    var incomplete: usize = 0;
    var unknown: usize = 0;
    var refused: usize = 0;
    for (o.bans) |ban| {
        const result = liftResult(ban);
        if (result == .kept) continue;
        attempted += 1;
        const show = attempted <= ignore_listed_bans_max;
        switch (result) {
            .kept => {},
            .confirmed => {
                confirmed += 1;
                if (show) try printEscaped(writer, "Lifted the ban on {} in {}; removal confirmed in the kernel.\n", .{ ban.scope, o.jail });
            },
            .incomplete => {
                incomplete += 1;
                if (show) {
                    try printEscaped(writer, "Lifted the ban on {} in {}; kernel removal is not confirmed yet. Check fail2zig list --jail ", .{ ban.scope, o.jail });
                    try writeShellArg(writer, o.jail);
                    try writer.writeAll(".\n");
                }
            },
            .unknown => {
                unknown += 1;
                if (show) {
                    try printEscaped(writer, "The ban on {} in {} may or may not have been lifted; the outcome could not be established. Check fail2zig list --jail ", .{ ban.scope, o.jail });
                    try writeShellArg(writer, o.jail);
                    try writer.writeAll(" and fail2zig status.\n");
                }
            },
            .refused => {
                refused += 1;
                if (show and !isInsideEntry(ban)) {
                    try printEscaped(writer, "Not lifted: {} is a network ban wider than the entry. To lift it: ", .{ban.scope});
                    try writeWiderBanLift(writer, o, ban);
                } else if (show) {
                    try printEscaped(writer, "Not lifted: {} in {}", .{ ban.scope, o.jail });
                    if (ban.lift_reason) |reason| try printEscaped(writer, ": {}", .{reason});
                    try writer.writeAll("\n");
                }
            },
        }
    }
    if (attempted <= ignore_listed_bans_max) return;
    try writer.print("Lifted {d} bans in ", .{attempted});
    try printEscaped(writer, "{}:", .{o.jail});
    var separator: []const u8 = " ";
    const parts = [_]struct { count: usize, label: []const u8 }{
        .{ .count = confirmed, .label = "confirmed" },
        .{ .count = incomplete, .label = "not confirmed yet" },
        .{ .count = unknown, .label = "unknown" },
        .{ .count = refused, .label = "not lifted" },
    };
    for (parts) |part| {
        if (part.count == 0) continue;
        try writer.print("{s}{d} {s}", .{ separator, part.count, part.label });
        separator = ", ";
    }
    try writer.writeAll(".\n");
}

pub fn formatIgnoreList(allocator: std.mem.Allocator, writer: anytype, payload_json: []const u8, fmt: OutputFormat, color: Color, jail_filter: ?[]const u8) !void {
    return formatIgnoreListForWidth(allocator, writer, payload_json, fmt, color, jail_filter, terminalColumns());
}

fn formatIgnoreListForWidth(allocator: std.mem.Allocator, writer: anytype, payload_json: []const u8, fmt: OutputFormat, color: Color, jail_filter: ?[]const u8, columns: usize) !void {
    switch (fmt) {
        .json => try writeJsonDocument(writer, payload_json),
        .plain, .table => {
            const parsed = try std.json.parseFromSlice(IgnoreListPayload, allocator, payload_json, .{ .ignore_unknown_fields = true, .allocate = .alloc_always });
            defer parsed.deinit();
            if (fmt == .plain) try writeIgnoreListPlain(writer, parsed.value) else try writeIgnoreListTable(writer, parsed.value, color, jail_filter, columns);
        },
    }
}

fn writeIgnoreListPlain(writer: anytype, p: IgnoreListPayload) !void {
    for (p.jails) |jail| {
        for (jail.entries) |entry| try printEscaped(writer, "{}\t{}\t{}\n", .{ jail.jail, entry.address, entry.source });
    }
}

fn writeIgnoreCell(writer: anytype, text: []const u8, width: usize, gap: usize) !void {
    var buffer: [diagnostic_max_bytes]u8 = undefined;
    const shown = renderDiagnostic(&buffer, text);
    const clipped = @min(shown.len, width);
    try writeClipped(writer, shown, width);
    try writeSpaces(writer, width - clipped + gap);
}

fn ignoreExpiresText(buffer: *[32]u8, entry: IgnoreListEntry) []const u8 {
    if (entry.expired) return "expired";
    if (entry.expires_us == null) return "-";
    const remaining = entry.remaining_s orelse return "-";
    const seconds = std.math.cast(i64, remaining) orelse std.math.maxInt(i64);
    return std.fmt.bufPrint(buffer, "in {s}", .{formatRemaining(seconds)}) catch "-";
}

fn writeIgnoreListTable(writer: anytype, p: IgnoreListPayload, color: Color, jail_filter: ?[]const u8, columns: usize) !void {
    var rows: usize = 0;
    var jail_width: usize = "JAIL".len;
    var address_width: usize = "ADDRESS".len;
    var source_width: usize = "SOURCE".len;
    var expires_width: usize = "EXPIRES".len;
    for (p.jails) |jail| {
        for (jail.entries) |entry| {
            rows += 1;
            jail_width = @max(jail_width, @min(escapedLen(jail.jail), col_max));
            address_width = @max(address_width, @min(escapedLen(entry.address), col_max));
            source_width = @max(source_width, @min(escapedLen(entry.source), col_max));
            var expires_buffer: [32]u8 = undefined;
            expires_width = @max(expires_width, ignoreExpiresText(&expires_buffer, entry).len);
        }
    }

    if (rows == 0) {
        if (jail_filter) |name| try printEscaped(writer, "No ignore entries for jail {}.\n", .{name}) else try writer.writeAll("No ignore entries.\n");
    } else if (jail_width + address_width + source_width + expires_width + 3 * ignore_list_gap <= columns) {
        try color.on(writer, Color.bold);
        try writeIgnoreCell(writer, "JAIL", jail_width, ignore_list_gap);
        try writeIgnoreCell(writer, "ADDRESS", address_width, ignore_list_gap);
        try writeIgnoreCell(writer, "SOURCE", source_width, ignore_list_gap);
        try writer.writeAll("EXPIRES");
        try color.off(writer);
        try writer.writeAll("\n");
        for (p.jails) |jail| {
            for (jail.entries) |entry| {
                try writeIgnoreCell(writer, jail.jail, jail_width, ignore_list_gap);
                try writeIgnoreCell(writer, entry.address, address_width, ignore_list_gap);
                try writeIgnoreCell(writer, entry.source, source_width, ignore_list_gap);
                var expires_buffer: [32]u8 = undefined;
                try writer.writeAll(ignoreExpiresText(&expires_buffer, entry));
                try writer.writeAll("\n");
            }
        }
    } else {
        const value_width = @max(@as(usize, 4), columns -| "ADDRESS: ".len);
        var first = true;
        for (p.jails) |jail| {
            for (jail.entries) |entry| {
                if (!first) try writer.writeAll("\n");
                first = false;
                var buffer: [diagnostic_max_bytes]u8 = undefined;
                try writer.writeAll("JAIL:    ");
                try writeClipped(writer, renderDiagnostic(&buffer, jail.jail), value_width);
                try writer.writeAll("\nADDRESS: ");
                try writeClipped(writer, renderDiagnostic(&buffer, entry.address), value_width);
                try writer.writeAll("\nSOURCE:  ");
                try writeClipped(writer, renderDiagnostic(&buffer, entry.source), value_width);
                var expires_buffer: [32]u8 = undefined;
                try writer.writeAll("\nEXPIRES: ");
                try writeClipped(writer, ignoreExpiresText(&expires_buffer, entry), value_width);
                try writer.writeAll("\n");
            }
        }
    }
    if (rows != 0) try writer.print("Total: {d} {s}\n", .{ rows, if (rows == 1) "entry" else "entries" });

    for (p.jails) |jail| {
        const file = jail.ignore_file orelse continue;
        try printEscaped(writer, "Jail {} also reads exclusions from its ignore_file {}; they are not listed here.\n", .{ jail.jail, file });
    }
    if (p.unconfigured.len != 0) {
        try writer.writeAll("Runtime entries are stored for jails that are not configured: ");
        for (p.unconfigured, 0..) |stored, index| {
            if (index != 0) try writer.writeAll(", ");
            try printEscaped(writer, "{}", .{stored.jail});
            try writer.print(" ({d})", .{stored.runtime_entries});
        }
        try writer.writeAll(". Remove them with fail2zig ignore remove <address> --jail ");
        if (p.unconfigured.len == 1) try writeShellArg(writer, p.unconfigured[0].jail) else try writer.writeAll("<jail>");
        try writer.writeAll(".\n");
    }
    for (p.jails) |jail| {
        const limit = jail.limit orelse p.limit;
        if (jail.count <= limit) continue;
        try printEscaped(writer, "Jail {} has ", .{jail.jail});
        try writer.print("{d} ignore entries, above the limit of {d}, after a configuration change. Adds are refused until it is at or below {d}.\n", .{ jail.count, limit, limit });
    }
    if (p.redacted) try writer.writeAll("Addresses are redacted unless the caller is an administrator.\n");
}
