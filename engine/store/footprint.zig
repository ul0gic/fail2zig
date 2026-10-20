// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const store = @import("store.zig");
const Error = store.Error;

pub const max_tables = 256;
const max_table_name_bytes = 64;

pub const TableFootprint = struct { name: []const u8, rows: u64, bytes: u64 };

pub const Footprint = struct {
    page_size: u64,
    page_count: u64,
    freelist_count: u64,
    tables: []const TableFootprint,
};

fn unsigned(value: i64) Error!u64 {
    return std.math.cast(u64, value) orelse error.DatabaseFailure;
}

fn plainIdentifier(name: []const u8) bool {
    if (name.len == 0 or name.len > max_table_name_bytes) return false;
    for (name) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '_') return false;
    return true;
}

pub fn Methods(comptime Store: type) type {
    return struct {
        pub fn footprint(self: *Store, arena: std.mem.Allocator) Error!Footprint {
            try self.beginRead();
            errdefer self.rollback();
            const page_size = try unsigned(try self.integer("PRAGMA page_size;"));
            const page_count = try unsigned(try self.integer("PRAGMA page_count;"));
            const freelist_count = try unsigned(try self.integer("PRAGMA freelist_count;"));
            var tables: std.ArrayListUnmanaged(TableFootprint) = .empty;
            {
                var rows = try self.statement("SELECT s.tbl_name,sum(d.pgsize) FROM dbstat AS d JOIN sqlite_schema AS s ON s.name=d.name WHERE d.aggregate=1 AND s.type IN('table','index') GROUP BY s.tbl_name ORDER BY s.tbl_name;");
                defer rows.deinit();
                while (try rows.row()) {
                    if (tables.items.len == max_tables) return error.StorageLimit;
                    const name = try rows.boundedBytes(0, max_table_name_bytes);
                    if (!plainIdentifier(name)) return error.DatabaseFailure;
                    try tables.append(arena, .{ .name = try arena.dupe(u8, name), .rows = 0, .bytes = try unsigned(try rows.signed(1)) });
                }
            }
            for (tables.items) |*table| {
                const sql = try std.fmt.allocPrintZ(arena, "SELECT count(*) FROM \"{s}\";", .{table.name});
                table.rows = try unsigned(try self.integer(sql));
            }
            try self.commitTransaction();
            return .{ .page_size = page_size, .page_count = page_count, .freelist_count = freelist_count, .tables = tables.items };
        }
    };
}
