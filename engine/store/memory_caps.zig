// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const effects = @import("../core/native_effect.zig");
const detection = @import("../core/native_detection_record.zig");
const store = @import("store.zig");
const Error = store.Error;

pub const memory_row_cap: i64 = 65_536;
pub const max_examined_rows: usize = 32;
const warn_interval_us: i64 = 60 * 1_000_000;

pub const MemoryTable = enum { retired, summaries };
const table_count = @typeInfo(MemoryTable).@"enum".fields.len;

pub const Evictions = struct {
    total: [table_count]u64 = [_]u64{0} ** table_count,
    unreported: [table_count]u64 = [_]u64{0} ** table_count,
    warned_us: [table_count]?i64 = [_]?i64{null} ** table_count,

    pub fn count(self: *const Evictions, table: MemoryTable) u64 {
        return self.total[@intFromEnum(table)];
    }

    fn note(self: *Evictions, table: MemoryTable, evicted: u32, now_us: i64) void {
        const index = @intFromEnum(table);
        self.total[index] +|= evicted;
        self.unreported[index] +|= evicted;
        if (self.warned_us[index]) |last| if (now_us - last < warn_interval_us) return;
        std.log.warn("native: {s} reached its cap of {d} rows: evicted {d} idle addresses in the last 60 s, {d} since start", .{ tableName(table), memory_row_cap, self.unreported[index], self.total[index] });
        self.unreported[index] = 0;
        self.warned_us[index] = now_us;
    }
};

fn tableName(table: MemoryTable) [:0]const u8 {
    return switch (table) {
        .retired => "retry_retired",
        .summaries => "confirmed_policy_summaries",
    };
}

pub fn Methods(comptime Store: type) type {
    return struct {
        pub fn evictMemoryRows(self: *Store, table: MemoryTable, now_us: i64) Error!u32 {
            return switch (table) {
                inline else => |known| self.evictMemoryRowsFrom(known, now_us),
            };
        }

        fn evictMemoryRowsFrom(self: *Store, comptime table: MemoryTable, now_us: i64) Error!u32 {
            const name = comptime tableName(table);
            const rows = try self.integer("SELECT count(*) FROM " ++ name ++ ";");
            if (rows <= memory_row_cap) return 0;
            const over = rows - memory_row_cap;
            const Candidate = struct { rowid: i64, jail: detection.Name, subject: detection.Subject };
            var candidates: [max_examined_rows]Candidate = undefined;
            var count: usize = 0;
            {
                var select = try self.statement(std.fmt.comptimePrint("SELECT rowid,jail,family,subject FROM {s} ORDER BY rowid LIMIT {d};", .{ name, max_examined_rows }));
                defer select.deinit();
                while (try select.row()) {
                    const jail = detection.Name.init(try select.boundedBytes(1, 64)) catch return error.InvalidRetryState;
                    candidates[count] = .{ .rowid = try select.signed(0), .jail = jail, .subject = try self.decodeRetrySubject(&select, 2, 3) };
                    count += 1;
                }
            }
            const installation = try self.readInstallation();
            var evicted: u32 = 0;
            for (candidates[0..count]) |candidate| {
                if (evicted == over) break;
                if (try self.memoryRowHeld(installation, candidate.jail.slice(), candidate.subject)) {
                    var rotate = try self.statement("UPDATE " ++ name ++ " SET rowid=(SELECT max(rowid) FROM " ++ name ++ ")+1 WHERE rowid=?1;");
                    defer rotate.deinit();
                    try rotate.int(1, candidate.rowid);
                    try rotate.done();
                    continue;
                }
                var delete = try self.statement("DELETE FROM " ++ name ++ " WHERE rowid=?1;");
                defer delete.deinit();
                try delete.int(1, candidate.rowid);
                try delete.done();
                evicted += 1;
            }
            if (evicted != 0) self.memory_evictions.note(table, evicted, now_us);
            return evicted;
        }

        fn memoryRowHeld(self: *Store, installation: ?effects.Installation, jail: []const u8, subject: detection.Subject) Error!bool {
            {
                var decision = try self.statement("SELECT EXISTS(SELECT 1 FROM retry_decisions WHERE jail=?1 AND family=?2 AND subject=?3);");
                defer decision.deinit();
                try decision.text(1, jail);
                try Store.bindSubject(&decision, &subject);
                if (!try decision.row()) return error.DatabaseFailure;
                if (try decision.signed(0) == 1) return true;
            }
            const known = installation orelse return false;
            const entry = try self.readEffect(try (try effects.Scope.host(subject)).key(known), known) orelse return false;
            return entry.desired != .absent or entry.status != .absent;
        }
    };
}
