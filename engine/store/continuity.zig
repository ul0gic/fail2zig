// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const files = @import("../core/durable_file_source.zig");
const store = @import("store.zig");
const Error = store.Error;
const Stmt = store.Stmt;

pub const retained_events_per_source: i64 = 256;
const max_jail_bytes = 64;
const max_text_bytes = 4096;

fn validJail(jail: []const u8) bool {
    return jail.len >= 1 and jail.len <= max_jail_bytes and std.mem.indexOfScalar(u8, jail, 0) == null;
}

fn validText(text: []const u8) bool {
    return text.len >= 1 and text.len <= max_text_bytes and std.mem.indexOfScalar(u8, text, 0) == null;
}

fn unsigned(value: i64) Error!u64 {
    return std.math.cast(u64, value) orelse error.DatabaseFailure;
}

fn signedFrom(value: u64) Error!i64 {
    return std.math.cast(i64, value) orelse error.StorageLimit;
}

const event_columns = "sequence,wall_us,reason,inode,committed_offset,observed_size";

fn readEvent(row: *Stmt, jail: []const u8, path: []const u8, source_id: []const u8) Error!files.LossEvent {
    return .{
        .sequence = try unsigned(try row.signed(0)),
        .jail = jail,
        .path = path,
        .source_id = source_id,
        .wall_us = try row.signed(1),
        .reason = std.meta.intToEnum(files.LossReason, try row.signed(2)) catch return error.DatabaseFailure,
        .inode = try unsigned(try row.signed(3)),
        .committed_offset = try unsigned(try row.signed(4)),
        .observed_size = try unsigned(try row.signed(5)),
    };
}

pub fn Methods(comptime Store: type) type {
    return struct {
        pub const CheckpointReset = struct { jail: []const u8, source_id: []const u8, cursor_json: []const u8 };

        pub fn recordContinuityLoss(self: *Store, event: files.LossEvent, reset: ?CheckpointReset) Error!u64 {
            if (!validJail(event.jail) or !validText(event.path) or !validText(event.source_id)) return error.InvalidRecord;
            if (reset) |value| {
                if (!validJail(value.jail) or value.source_id.len == 0 or value.source_id.len > store.Limits.source_bytes) return error.InvalidRecord;
                if (value.cursor_json.len == 0 or value.cursor_json.len > store.Limits.cursor_bytes) return error.InvalidRecord;
            }
            const inode = try signedFrom(event.inode);
            const committed_offset = try signedFrom(event.committed_offset);
            const observed_size = try signedFrom(event.observed_size);
            try self.beginWrite();
            errdefer self.rollback();
            if (self.schema_version < store.latest_schema) return error.UnsupportedSchema;
            {
                var insert = try self.statement("INSERT INTO continuity_loss_events(jail,path,source,wall_us,reason,inode,committed_offset,observed_size) VALUES(?1,?2,?3,?4,?5,?6,?7,?8);");
                defer insert.deinit();
                try insert.text(1, event.jail);
                try insert.text(2, event.path);
                try insert.text(3, event.source_id);
                try insert.int(4, event.wall_us);
                try insert.int(5, @intFromEnum(event.reason));
                try insert.int(6, inode);
                try insert.int(7, committed_offset);
                try insert.int(8, observed_size);
                try insert.done();
            }
            const sequence = try unsigned(try self.integer("SELECT last_insert_rowid();"));
            {
                var prune = try self.statement("DELETE FROM continuity_loss_events WHERE jail=?1 AND path=?2 AND sequence NOT IN (SELECT sequence FROM continuity_loss_events WHERE jail=?1 AND path=?2 ORDER BY sequence DESC LIMIT ?3);");
                defer prune.deinit();
                try prune.text(1, event.jail);
                try prune.text(2, event.path);
                try prune.int(3, retained_events_per_source);
                try prune.done();
            }
            if (reset) |value| {
                {
                    var pending = try self.statement("SELECT 1 FROM pending_receipts WHERE jail=?1 AND source=?2;");
                    defer pending.deinit();
                    try pending.text(1, value.jail);
                    try pending.text(2, value.source_id);
                    if (try pending.row()) return error.ReceiptRequired;
                }
                var update = try self.statement("UPDATE source_cursors SET cursor=?3 WHERE jail=?1 AND source=?2;");
                defer update.deinit();
                try update.text(1, value.jail);
                try update.text(2, value.source_id);
                try update.blob(3, value.cursor_json);
                try update.done();
                if (self.api.changes(self.db) != 1) return error.StaleCheckpoint;
            }
            try self.commitTransaction();
            return sequence;
        }

        pub fn retireSourceCheckpoint(self: *Store, jail: []const u8, source_id: []const u8) Error!void {
            if (!validJail(jail) or source_id.len == 0 or source_id.len > store.Limits.source_bytes) return error.InvalidRecord;
            try self.beginWrite();
            errdefer self.rollback();
            {
                var pending = try self.statement("SELECT 1 FROM pending_receipts WHERE jail=?1 AND source=?2;");
                defer pending.deinit();
                try pending.text(1, jail);
                try pending.text(2, source_id);
                if (try pending.row()) return error.ReceiptRequired;
            }
            {
                var delete = try self.statement("DELETE FROM source_cursors WHERE jail=?1 AND source=?2;");
                defer delete.deinit();
                try delete.text(1, jail);
                try delete.text(2, source_id);
                try delete.done();
            }
            try self.commitTransaction();
        }

        pub fn continuityEvents(self: *Store, jail: ?[]const u8, before: ?u64, out: []files.LossEvent, arena: std.mem.Allocator) Error!usize {
            if (out.len > retained_events_per_source) return error.InvalidRecord;
            if (jail) |name| if (!validJail(name)) return error.InvalidRecord;
            const bound = if (before) |value| try signedFrom(value) else 0;
            try self.beginRead();
            errdefer self.rollback();
            if (self.schema_version < store.latest_schema) return error.UnsupportedSchema;
            var count: usize = 0;
            {
                var rows = try self.statement("SELECT sequence,wall_us,reason,inode,committed_offset,observed_size,jail,path,source FROM continuity_loss_events WHERE (?1 IS NULL OR jail=?1) AND (?2 IS NULL OR sequence<?2) ORDER BY sequence DESC LIMIT ?3;");
                defer rows.deinit();
                if (jail) |name| try rows.text(1, name) else try self.check(self.api.bind_null(rows.ptr, 1));
                if (before != null) try rows.int(2, bound) else try self.check(self.api.bind_null(rows.ptr, 2));
                try rows.int(3, @intCast(out.len));
                while (try rows.row()) {
                    const event_jail = try arena.dupe(u8, try rows.boundedBytes(6, max_jail_bytes));
                    const event_path = try arena.dupe(u8, try rows.boundedBytes(7, max_text_bytes));
                    const event_source = try arena.dupe(u8, try rows.boundedBytes(8, max_text_bytes));
                    out[count] = try readEvent(&rows, event_jail, event_path, event_source);
                    count += 1;
                }
            }
            try self.commitTransaction();
            return count;
        }

        pub fn continuitySummary(self: *Store, jail: []const u8, path: []const u8, out: *files.LossEvent) Error!u16 {
            if (!validJail(jail) or !validText(path)) return error.InvalidRecord;
            try self.beginRead();
            errdefer self.rollback();
            if (self.schema_version < store.latest_schema) return error.UnsupportedSchema;
            var count: u16 = 0;
            {
                var total = try self.statement("SELECT count(*) FROM continuity_loss_events WHERE jail=?1 AND path=?2;");
                defer total.deinit();
                try total.text(1, jail);
                try total.text(2, path);
                if (!try total.row()) return error.DatabaseFailure;
                count = std.math.cast(u16, try total.signed(0)) orelse return error.DatabaseFailure;
            }
            if (count != 0) {
                var newest = try self.statement("SELECT " ++ event_columns ++ " FROM continuity_loss_events WHERE jail=?1 AND path=?2 ORDER BY sequence DESC LIMIT 1;");
                defer newest.deinit();
                try newest.text(1, jail);
                try newest.text(2, path);
                if (!try newest.row()) return error.DatabaseFailure;
                out.* = try readEvent(&newest, jail, path, "");
            }
            try self.commitTransaction();
            return count;
        }

        pub fn lossForIncarnation(self: *Store, jail: []const u8, source_id: []const u8, inode: u64, out: *files.LossEvent) Error!bool {
            if (!validJail(jail) or !validText(source_id)) return error.InvalidRecord;
            const wanted = try signedFrom(inode);
            try self.beginRead();
            errdefer self.rollback();
            if (self.schema_version < store.latest_schema) return error.UnsupportedSchema;
            var found = false;
            {
                var row = try self.statement("SELECT " ++ event_columns ++ " FROM continuity_loss_events WHERE jail=?1 AND source=?2 AND inode=?3 AND reason=?4 ORDER BY sequence DESC LIMIT 1;");
                defer row.deinit();
                try row.text(1, jail);
                try row.text(2, source_id);
                try row.int(3, wanted);
                try row.int(4, @intFromEnum(files.LossReason.truncated));
                if (try row.row()) {
                    out.* = try readEvent(&row, jail, "", source_id);
                    found = true;
                }
            }
            try self.commitTransaction();
            return found;
        }
    };
}
