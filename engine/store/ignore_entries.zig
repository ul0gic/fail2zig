// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const types = @import("shared").types;
const store = @import("store.zig");
const Error = store.Error;
const Stmt = store.Stmt;

const max_entries_per_jail = 128;
const max_jail_bytes = 64;
const address_bytes = 16;

fn validJail(jail: []const u8) bool {
    return jail.len >= 1 and jail.len <= max_jail_bytes and std.mem.indexOfScalar(u8, jail, 0) == null;
}

fn canonicalNetwork(entry: types.IgnoreEntry) bool {
    const width: u8 = switch (entry.family) {
        .v4 => 32,
        .v6 => 128,
    };
    if (entry.prefix > width) return false;
    for (entry.address, 0..) |byte, index| {
        const start = index * 8;
        const kept: u4 = if (entry.prefix > start) @intCast(@min(8, entry.prefix - start)) else 0;
        const mask: u8 = if (kept == 0) 0 else @as(u8, 0xff) << @intCast(8 - kept);
        if (byte & ~mask != 0) return false;
    }
    return true;
}

fn bindEntry(row: *Stmt, jail: []const u8, entry: *const types.IgnoreEntry) Error!void {
    try row.text(1, jail);
    try row.int(2, @intFromEnum(entry.family));
    try row.blob(3, &entry.address);
    try row.int(4, entry.prefix);
}

pub fn Methods(comptime Store: type) type {
    return struct {
        pub const IgnoreJailCount = struct { jail: [max_jail_bytes]u8, jail_len: u8, count: u16 };

        pub fn addIgnoreEntry(self: *Store, jail: []const u8, entry: types.IgnoreEntry, now_us: i64) Error!enum { added, present } {
            if (!validJail(jail) or !canonicalNetwork(entry)) return error.InvalidIgnoreEntry;
            try self.beginWrite();
            errdefer self.rollback();
            if (self.schema_version < store.latest_schema) return error.UnsupportedSchema;
            {
                var existing = try self.statement("SELECT 1 FROM ignore_entries WHERE jail=?1 AND family=?2 AND address=?3 AND prefix=?4;");
                defer existing.deinit();
                try bindEntry(&existing, jail, &entry);
                if (try existing.row()) {
                    try self.commitTransaction();
                    return .present;
                }
            }
            {
                var count = try self.statement("SELECT count(*) FROM ignore_entries WHERE jail=?1;");
                defer count.deinit();
                try count.text(1, jail);
                if (!try count.row()) return error.DatabaseFailure;
                if (try count.signed(0) >= max_entries_per_jail) return error.IgnoreCapacity;
            }
            {
                var insert = try self.statement("INSERT INTO ignore_entries(jail,family,address,prefix,added_us) VALUES(?1,?2,?3,?4,?5);");
                defer insert.deinit();
                try bindEntry(&insert, jail, &entry);
                try insert.int(5, now_us);
                try insert.done();
            }
            try self.commitTransaction();
            return .added;
        }

        pub fn removeIgnoreEntry(self: *Store, jail: []const u8, entry: types.IgnoreEntry) Error!bool {
            if (!validJail(jail) or !canonicalNetwork(entry)) return error.InvalidIgnoreEntry;
            try self.beginWrite();
            errdefer self.rollback();
            if (self.schema_version < store.latest_schema) return error.UnsupportedSchema;
            {
                var delete = try self.statement("DELETE FROM ignore_entries WHERE jail=?1 AND family=?2 AND address=?3 AND prefix=?4;");
                defer delete.deinit();
                try bindEntry(&delete, jail, &entry);
                try delete.done();
            }
            const removed = self.api.changes(self.db) == 1;
            try self.commitTransaction();
            return removed;
        }

        pub fn ignoreEntries(self: *Store, jail: []const u8, out: []types.IgnoreEntry) Error!usize {
            if (!validJail(jail)) return error.InvalidIgnoreEntry;
            try self.beginRead();
            errdefer self.rollback();
            if (self.schema_version < store.latest_schema) return error.UnsupportedSchema;
            var count: usize = 0;
            {
                var rows = try self.statement("SELECT family,address,prefix FROM ignore_entries WHERE jail=?1 ORDER BY family,address,prefix;");
                defer rows.deinit();
                try rows.text(1, jail);
                while (try rows.row()) {
                    if (count == out.len) return error.StorageLimit;
                    const family = std.meta.intToEnum(@FieldType(types.IgnoreEntry, "family"), try rows.signed(0)) catch return error.DatabaseFailure;
                    const address = try rows.boundedBytes(1, address_bytes);
                    const prefix = std.math.cast(u8, try rows.signed(2)) orelse return error.DatabaseFailure;
                    if (address.len != address_bytes) return error.DatabaseFailure;
                    const entry = types.IgnoreEntry{ .family = family, .address = address[0..address_bytes].*, .prefix = prefix };
                    if (!canonicalNetwork(entry)) return error.DatabaseFailure;
                    out[count] = entry;
                    count += 1;
                }
            }
            try self.commitTransaction();
            return count;
        }

        pub fn ignoreEntryJails(self: *Store, out: []IgnoreJailCount) Error!usize {
            try self.beginRead();
            errdefer self.rollback();
            if (self.schema_version < store.latest_schema) return error.UnsupportedSchema;
            var count: usize = 0;
            {
                var rows = try self.statement("SELECT jail,count(*) FROM ignore_entries GROUP BY jail ORDER BY jail;");
                defer rows.deinit();
                while (try rows.row()) {
                    if (count == out.len) return error.StorageLimit;
                    const jail = try rows.boundedBytes(0, max_jail_bytes);
                    if (jail.len == 0) return error.DatabaseFailure;
                    var item = IgnoreJailCount{ .jail = [_]u8{0} ** max_jail_bytes, .jail_len = @intCast(jail.len), .count = std.math.cast(u16, try rows.signed(1)) orelse return error.DatabaseFailure };
                    @memcpy(item.jail[0..jail.len], jail);
                    out[count] = item;
                    count += 1;
                }
            }
            try self.commitTransaction();
            return count;
        }
    };
}
