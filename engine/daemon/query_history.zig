// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Reads the history and continuity pages from the read-only store.
// Holds: A history read starts after its cursor or the retained floor, and a cursor below that floor is refused as InvalidatedCursor.

const std = @import("std");
const effect = @import("../effect/effect.zig");
const history = @import("../effect/effect_history.zig");
const durable = @import("../store/store.zig");
const files = @import("../source/durable_file_source.zig");
const query_v1 = @import("../net/query_v1.zig");
const query_mod = @import("query.zig");
const CaptureMemory = query_mod.CaptureMemory;

pub fn Methods(comptime Coordinator: type) type {
    return struct {
        const beginConfigRead = Coordinator.beginConfigRead;
        const redacted_text = Coordinator.redacted_text;
        pub fn continuityRender(ctx: ?*anyopaque, arena: std.mem.Allocator, cursor: ?u64, limit: u16, redact: bool, out: *query_v1.JsonStream) anyerror!void {
            const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
            const reader = if (self.history_reader) |*value| value else return error.HistoryUnavailable;
            const events = try arena.alloc(files.LossEvent, limit);
            const count = try reader.continuityEvents(null, cursor, events, arena);
            try out.objectField("items");
            try out.beginArray();
            for (events[0..count]) |event| {
                try out.beginObject();
                try out.objectField("sequence");
                try out.write(event.sequence);
                try out.objectField("jail");
                try out.write(event.jail);
                try out.objectField("path");
                try out.write(if (redact) redacted_text else event.path);
                try out.objectField("wall_us");
                try out.write(event.wall_us);
                try out.objectField("reason");
                try out.write(@tagName(event.reason));
                try out.objectField("inode");
                try out.write(event.inode);
                try out.objectField("committed_offset");
                try out.write(event.committed_offset);
                try out.objectField("observed_size");
                try out.write(event.observed_size);
                try out.endObject();
            }
            try out.endArray();
            try out.objectField("next_cursor");
            if (count == limit and count != 0) {
                var buffer: [20]u8 = undefined;
                try out.write(try std.fmt.bufPrint(&buffer, "{d}", .{events[count - 1].sequence}));
            } else try out.write(null);
        }
        pub const HistoryQuery = struct { coordinator: *Coordinator, generation: [32]u8, details: bool, memory: ?*CaptureMemory };
        pub fn historyRead(ctx: ?*anyopaque, jail: ?[]const u8, after_sequence: ?u64, limit: u16, out: *std.ArrayList(query_v1.HistoryEvent)) anyerror!query_v1.HistoryRead {
            const query: *HistoryQuery = @ptrCast(@alignCast(ctx.?));
            const self = query.coordinator;
            if (!query.details) return historyReadPlain(self, jail, after_sequence, limit, out);
            const memory = query.memory orelse return error.HistoryUnavailable;
            const reader = if (self.history_reader) |*value| value else return error.HistoryUnavailable;
            try beginConfigRead(reader, query.generation);
            errdefer reader.rollback();
            const installation = try reader.readInstallation();
            const start = try historyStart(try reader.confirmedHistoryStartTx(), after_sequence);
            var after = start;
            var more = false;
            if (installation) |installed| {
                var events: [history.max_page]history.Event = undefined;
                var selected: [history.max_page]history.Event = undefined;
                var count: usize = 0;
                var appended: usize = 0;
                var pages: usize = 0;
                while (appended + count < limit and pages < history_scan_pages) : (pages += 1) {
                    const page = try reader.confirmedEffectPageTx(installed, after, null, &events);
                    more = page.more;
                    if (page.count == 0) break;
                    for (events[0..page.count]) |event| {
                        if (appended + count == limit) break;
                        after = event.sequence;
                        if (jail) |wanted| if (!std.mem.eql(u8, wanted, event.jail.slice())) continue;
                        selected[count] = event;
                        count += 1;
                        if (count == selected.len) {
                            try appendHistoryMatches(memory, reader, installed, selected[0..count], out);
                            appended += count;
                            count = 0;
                        }
                    }
                    more = after < page.token.head_sequence;
                    if (!more) break;
                }
                if (count != 0) try appendHistoryMatches(memory, reader, installed, selected[0..count], out);
            }
            try reader.commitTransaction();
            if (!self.unchanged(query.generation)) return error.InvalidatedCursor;
            return .{ .more = more, .started_after = start, .resume_after = after };
        }
        // Does:  Picks where a history read starts: after the cursor, or after the retained floor when there is no cursor.
        // Holds: A cursor below the retained floor is InvalidatedCursor, never a read that would report a gap.
        fn historyStart(floor_after: u64, requested: ?u64) error{InvalidatedCursor}!u64 {
            const after = requested orelse return floor_after;
            if (after < floor_after) return error.InvalidatedCursor;
            return after;
        }
        fn appendHistoryMatches(memory: *CaptureMemory, reader: *durable.Store, installation: effect.Installation, events: []const history.Event, out: *std.ArrayList(query_v1.HistoryEvent)) !void {
            var lines: [history.max_page]?[]u8 = undefined;
            try reader.retainedMatchesForEventsTx(memory.fixed.allocator(), installation, events, lines[0..events.len]);
            for (events, lines[0..events.len]) |event, line| {
                try out.append(.{
                    .sequence = event.sequence,
                    .event_id = event.event_id,
                    .jail = try memory.text(event.jail.slice()),
                    .decision_id = event.decision_id,
                    .confirmed_us = event.confirmed_us,
                    .scope = try query_v1.projectScope(event.scope.canonical),
                    .native_retry = event.native_retry,
                    .origin = event.origin,
                    .match = line,
                });
            }
        }
        // Why: A jail filter can skip every event, so one page scans at most 16 store pages and returns where to resume.
        const history_scan_pages = 16;
        fn historyReadPlain(ctx: ?*anyopaque, jail: ?[]const u8, after_sequence: ?u64, limit: u16, out: *std.ArrayList(query_v1.HistoryEvent)) anyerror!query_v1.HistoryRead {
            const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
            const reader = if (self.history_reader) |*value| value else return error.HistoryUnavailable;
            const installation = try reader.readInstallation() orelse {
                const none = after_sequence orelse 0;
                return .{ .more = false, .started_after = none, .resume_after = none };
            };
            var events: [history.max_page]history.Event = undefined;
            const start = try historyStart(try reader.confirmedHistoryStart(), after_sequence);
            var after = start;
            var appended: usize = 0;
            var pages: usize = 0;
            while (appended < limit and pages < history_scan_pages) : (pages += 1) {
                const page = reader.confirmedEffectPage(installation, after, null, &events) catch |failure| {
                    // Why: Each page is its own read, so retention can prune past this position between two of them.
                    if (failure == error.HistoryGap and after < try reader.confirmedHistoryStart()) return error.InvalidatedCursor;
                    return failure;
                };
                if (page.count == 0) return .{ .more = false, .started_after = start, .resume_after = after };
                for (events[0..page.count]) |event| {
                    if (appended == limit) return .{ .more = true, .started_after = start, .resume_after = after };
                    after = event.sequence;
                    if (jail) |wanted| if (!std.mem.eql(u8, wanted, event.jail.slice())) continue;
                    try out.append(.{
                        .sequence = event.sequence,
                        .event_id = event.event_id,
                        .jail = try out.allocator.dupe(u8, event.jail.slice()),
                        .decision_id = event.decision_id,
                        .confirmed_us = event.confirmed_us,
                        .scope = try query_v1.projectScope(event.scope.canonical),
                        .native_retry = event.native_retry,
                        .origin = event.origin,
                    });
                    appended += 1;
                }
                if (!page.more) return .{ .more = false, .started_after = start, .resume_after = after };
            }
            return .{ .more = true, .started_after = start, .resume_after = after };
        }
    };
}
