// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const types = @import("shared").types;
const store = @import("store.zig");
const Error = store.Error;
const Stmt = store.Stmt;

pub const ConfigList = enum(u8) {
    ignoreip = 1,
    banip = 2,
};

pub const ConfigDeadline = struct {
    first_applied_us: i64,
    expires_us: i64,
};

const max_jail_bytes = 64;
const stale_batch = 32;

const StaleRow = struct {
    address: [types.IgnoreEntry.max_text_bytes]u8,
    address_len: u8,
    duration_s: i64,
};

fn validRequest(jail: []const u8, entries: []const types.TimedEntry, out_len: usize) bool {
    if (jail.len < 1 or jail.len > max_jail_bytes or std.mem.indexOfScalar(u8, jail, 0) != null) return false;
    if (out_len < entries.len) return false;
    for (entries) |item| {
        if (item.duration_s) |seconds| if (seconds < 1 or seconds > types.TimedEntry.max_duration_s) return false;
    }
    return true;
}

fn bindKey(row: *Stmt, list: ConfigList, jail: []const u8, address: []const u8, duration_s: u64) Error!void {
    try row.int(1, @intFromEnum(list));
    try row.text(2, jail);
    try row.text(3, address);
    try row.int(4, @intCast(duration_s));
}

fn listed(entries: []const types.TimedEntry, address: []const u8, duration_s: i64) bool {
    const parsed = types.IgnoreEntry.parse(address) catch return false;
    var buffer: [types.IgnoreEntry.max_text_bytes]u8 = undefined;
    if (!std.mem.eql(u8, parsed.canonical(&buffer), address)) return false;
    for (entries) |item| {
        const seconds = item.duration_s orelse continue;
        if (seconds != duration_s) continue;
        if (types.IgnoreEntry.order(item.entry, parsed) == .eq) return true;
    }
    return false;
}

pub fn Methods(comptime Store: type) type {
    return struct {
        pub fn applyConfigDeadlines(self: *Store, list: ConfigList, jail: []const u8, entries: []const types.TimedEntry, now_us: i64, out: []?i64) Error!void {
            if (!validRequest(jail, entries, out.len) or now_us <= 0) return error.InvalidRecord;
            const own = self.api.get_autocommit(self.db) != 0;
            if (own) try self.beginWrite();
            errdefer if (own) self.rollback();
            if (self.schema_version < store.latest_schema) return error.UnsupportedSchema;
            for (entries, 0..) |item, index| {
                const seconds = item.duration_s orelse {
                    out[index] = null;
                    continue;
                };
                var buffer: [types.IgnoreEntry.max_text_bytes]u8 = undefined;
                const address = item.entry.canonical(&buffer);
                {
                    var existing = try self.statement("SELECT expires_us FROM config_timed_entries WHERE list=?1 AND jail=?2 AND address=?3 AND duration_s=?4;");
                    defer existing.deinit();
                    try bindKey(&existing, list, jail, address, seconds);
                    if (try existing.row()) {
                        out[index] = try existing.signed(0);
                        continue;
                    }
                }
                const span = std.math.mul(i64, @intCast(seconds), std.time.us_per_s) catch return error.InvalidRecord;
                const expires_us = std.math.add(i64, now_us, span) catch return error.InvalidRecord;
                {
                    var insert = try self.statement("INSERT INTO config_timed_entries(list,jail,address,duration_s,first_applied_us,expires_us) VALUES(?1,?2,?3,?4,?5,?6);");
                    defer insert.deinit();
                    try bindKey(&insert, list, jail, address, seconds);
                    try insert.int(5, now_us);
                    try insert.int(6, expires_us);
                    try insert.done();
                }
                out[index] = expires_us;
            }
            while (true) {
                var stale: [stale_batch]StaleRow = undefined;
                var stale_count: usize = 0;
                {
                    var rows = try self.statement("SELECT address,duration_s FROM config_timed_entries WHERE list=?1 AND jail=?2 ORDER BY address,duration_s;");
                    defer rows.deinit();
                    try rows.int(1, @intFromEnum(list));
                    try rows.text(2, jail);
                    while (stale_count < stale_batch and try rows.row()) {
                        const address = try rows.boundedBytes(0, types.IgnoreEntry.max_text_bytes);
                        const duration_s = try rows.signed(1);
                        if (listed(entries, address, duration_s)) continue;
                        stale[stale_count] = .{ .address = undefined, .address_len = @intCast(address.len), .duration_s = duration_s };
                        @memcpy(stale[stale_count].address[0..address.len], address);
                        stale_count += 1;
                    }
                }
                for (stale[0..stale_count]) |*row| {
                    var delete = try self.statement("DELETE FROM config_timed_entries WHERE list=?1 AND jail=?2 AND address=?3 AND duration_s=?4;");
                    defer delete.deinit();
                    try delete.int(1, @intFromEnum(list));
                    try delete.text(2, jail);
                    try delete.text(3, row.address[0..row.address_len]);
                    try delete.int(4, row.duration_s);
                    try delete.done();
                }
                if (stale_count < stale_batch) break;
            }
            if (own) try self.commitTransaction();
        }

        pub fn configEntryDeadlines(self: *Store, list: ConfigList, jail: []const u8, entries: []const types.TimedEntry, out: []?i64) Error!void {
            if (!validRequest(jail, entries, out.len)) return error.InvalidRecord;
            const own = self.api.get_autocommit(self.db) != 0;
            if (own) try self.beginRead();
            errdefer if (own) self.rollback();
            if (self.schema_version < store.latest_schema) return error.UnsupportedSchema;
            for (entries, 0..) |item, index| {
                const seconds = item.duration_s orelse {
                    out[index] = null;
                    continue;
                };
                var buffer: [types.IgnoreEntry.max_text_bytes]u8 = undefined;
                const address = item.entry.canonical(&buffer);
                var existing = try self.statement("SELECT expires_us FROM config_timed_entries WHERE list=?1 AND jail=?2 AND address=?3 AND duration_s=?4;");
                defer existing.deinit();
                try bindKey(&existing, list, jail, address, seconds);
                out[index] = if (try existing.row()) try existing.signed(0) else null;
            }
            if (own) try self.commitTransaction();
        }
    };
}
