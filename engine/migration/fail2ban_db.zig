// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Schema reference: GPL-2.0 upstream `fail2ban-1.1.1/fail2ban/server/database.py:114-160`.
//! The DDL is restated as a structural expectation and is not copied into product output.
const std = @import("std");

pub const Db = opaque {};
pub const Statement = opaque {};
pub const Backup = opaque {};
// SQLite accepts the unaligned SQLITE_TRANSIENT (-1) sentinel as well as callbacks.
const Destructor = ?*align(1) const fn (?*anyopaque) callconv(.c) void;

pub const Api = struct {
    open_v2: *const fn ([*:0]const u8, *?*Db, c_int, ?[*:0]const u8) callconv(.c) c_int,
    close_v2: *const fn (*Db) callconv(.c) c_int,
    exec: *const fn (*Db, [*:0]const u8, ?*anyopaque, ?*anyopaque, ?*?[*:0]u8) callconv(.c) c_int,
    free: *const fn (?*anyopaque) callconv(.c) void,
    prepare_v2: *const fn (*Db, [*:0]const u8, c_int, *?*Statement, ?*?[*:0]const u8) callconv(.c) c_int,
    finalize: *const fn (*Statement) callconv(.c) c_int,
    step: *const fn (*Statement) callconv(.c) c_int,
    reset: *const fn (*Statement) callconv(.c) c_int,
    bind_text: *const fn (*Statement, c_int, [*]const u8, c_int, Destructor) callconv(.c) c_int,
    bind_null: *const fn (*Statement, c_int) callconv(.c) c_int,
    bind_int64: *const fn (*Statement, c_int, i64) callconv(.c) c_int,
    column_type: *const fn (*Statement, c_int) callconv(.c) c_int,
    column_blob: *const fn (*Statement, c_int) callconv(.c) ?*const anyopaque,
    column_bytes: *const fn (*Statement, c_int) callconv(.c) c_int,
    column_int64: *const fn (*Statement, c_int) callconv(.c) i64,
    column_count: *const fn (*Statement) callconv(.c) c_int,
    busy_timeout: *const fn (*Db, c_int) callconv(.c) c_int,
    extended_errcode: *const fn (*Db) callconv(.c) c_int,
    errmsg: *const fn (*Db) callconv(.c) [*:0]const u8,
    db_config: *const fn (*Db, c_int, ...) callconv(.c) c_int,
    backup_init: *const fn (*Db, [*:0]const u8, *Db, [*:0]const u8) callconv(.c) ?*Backup,
    backup_step: *const fn (*Backup, c_int) callconv(.c) c_int,
    backup_finish: *const fn (?*Backup) callconv(.c) c_int,
    backup_remaining: *const fn (*Backup) callconv(.c) c_int,
    backup_pagecount: *const fn (*Backup) callconv(.c) c_int,
};
pub const api: Api = blk: {
    var value: Api = undefined;
    for (std.meta.fields(Api)) |field| {
        @field(value, field.name) = @extern(field.type, .{ .name = "sqlite3_" ++ field.name });
    }
    break :blk value;
};

pub const rc = struct {
    pub const ok: c_int = 0;
    pub const busy: c_int = 5;
    pub const locked: c_int = 6;
    pub const row: c_int = 100;
    pub const done: c_int = 101;
};
pub const open_flags = struct {
    pub const readonly: c_int = 0x1;
    pub const readwrite: c_int = 0x2;
    pub const create: c_int = 0x4;
    pub const uri: c_int = 0x40;
    pub const exrescode: c_int = 0x02000000;
};
const column_type = struct {
    const integer: c_int = 1;
    const text: c_int = 3;
    const blob: c_int = 4;
    const null_value: c_int = 5;
};
const dbconfig_no_ckpt_on_close: c_int = 1006;

pub const Error = error{
    OpenFailed,
    AccessDenied,
    Busy,
    ReadOnly,
    StorageIo,
    StorageFull,
    CorruptDatabase,
    Interrupted,
    DatabaseFailure,
    IntegrityCheckFailed,
    UnsupportedSchema,
    UnsupportedVersion,
    InvalidRow,
    OutOfMemory,
};

pub fn sqliteError(code: c_int) Error {
    return switch (code & 0xff) {
        3, 23 => error.AccessDenied,
        5, 6 => error.Busy,
        7 => error.OutOfMemory,
        8 => error.ReadOnly,
        9 => error.Interrupted,
        10 => error.StorageIo,
        11, 26 => error.CorruptDatabase,
        13 => error.StorageFull,
        14 => error.OpenFailed,
        else => error.DatabaseFailure,
    };
}

pub const expected_version: i64 = 4;
pub const max_jail_bytes = 64;
pub const max_ip_bytes = 64;
pub const max_path_bytes = 4096;
pub const max_md5_bytes = 64;
pub const max_data_bytes = 64 * 1024;

pub const Connection = struct {
    db: *Db,

    pub fn open(path_z: [*:0]const u8, flags: c_int) Error!Connection {
        var handle: ?*Db = null;
        const code = api.open_v2(path_z, &handle, flags | open_flags.exrescode, null);
        const db = handle orelse return error.OutOfMemory;
        if (code != rc.ok) {
            _ = api.close_v2(db);
            return sqliteError(code);
        }
        return .{ .db = db };
    }

    pub fn close(self: *Connection) void {
        _ = api.close_v2(self.db);
        self.* = undefined;
    }

    pub fn busyTimeoutMs(self: Connection, ms: c_int) Error!void {
        const code = api.busy_timeout(self.db, ms);
        if (code != rc.ok) return sqliteError(code);
    }

    pub fn disableCheckpointOnClose(self: Connection) Error!void {
        var previous: c_int = 0;
        const code = api.db_config(self.db, dbconfig_no_ckpt_on_close, @as(c_int, 1), &previous);
        if (code != rc.ok) return sqliteError(code);
    }

    pub fn exec(self: Connection, sql: [*:0]const u8) Error!void {
        var message: ?[*:0]u8 = null;
        const code = api.exec(self.db, sql, null, null, &message);
        if (message) |text| api.free(text);
        if (code != rc.ok) return sqliteError(code);
    }

    pub fn prepare(self: Connection, sql: [*:0]const u8) Error!Stmt {
        var handle: ?*Statement = null;
        const code = api.prepare_v2(self.db, sql, -1, &handle, null);
        if (code != rc.ok) return sqliteError(code);
        return .{ .stmt = handle orelse return error.DatabaseFailure };
    }

    pub fn scalarInt(self: Connection, sql: [*:0]const u8) Error!?i64 {
        var stmt = try self.prepare(sql);
        defer stmt.finalize();
        if (!try stmt.step()) return null;
        if (stmt.columnType(0) != column_type.integer) return error.InvalidRow;
        return stmt.columnInt64(0);
    }

    pub fn integrityCheck(self: Connection) Error!void {
        var stmt = try self.prepare("PRAGMA integrity_check");
        defer stmt.finalize();
        var rows: usize = 0;
        var ok = false;
        while (try stmt.step()) {
            rows += 1;
            if (rows > 1) return error.IntegrityCheckFailed;
            const text = stmt.columnBytes(0) orelse return error.IntegrityCheckFailed;
            ok = std.mem.eql(u8, text, "ok");
        }
        if (rows != 1 or !ok) return error.IntegrityCheckFailed;
    }

    pub fn journalMode(self: Connection, buffer: []u8) Error![]const u8 {
        var stmt = try self.prepare("PRAGMA journal_mode");
        defer stmt.finalize();
        if (!try stmt.step()) return error.DatabaseFailure;
        const text = stmt.columnBytes(0) orelse return error.DatabaseFailure;
        if (text.len > buffer.len) return error.DatabaseFailure;
        @memcpy(buffer[0..text.len], text);
        return buffer[0..text.len];
    }
};

pub const Stmt = struct {
    stmt: *Statement,

    pub fn finalize(self: *Stmt) void {
        _ = api.finalize(self.stmt);
        self.* = undefined;
    }

    pub fn step(self: Stmt) Error!bool {
        const code = api.step(self.stmt);
        return switch (code) {
            rc.row => true,
            rc.done => false,
            else => sqliteError(code),
        };
    }

    pub fn bindText(self: Stmt, index: c_int, text: []const u8) Error!void {
        const len = std.math.cast(c_int, text.len) orelse return error.InvalidRow;
        // SQLite copies the bytes before returning; this sentinel is never called.
        const transient: Destructor = @ptrFromInt(std.math.maxInt(usize));
        const code = api.bind_text(self.stmt, index, text.ptr, len, transient);
        if (code != rc.ok) return sqliteError(code);
    }

    pub fn bindNull(self: Stmt, index: c_int) Error!void {
        const code = api.bind_null(self.stmt, index);
        if (code != rc.ok) return sqliteError(code);
    }

    pub fn bindInt64(self: Stmt, index: c_int, value: i64) Error!void {
        const code = api.bind_int64(self.stmt, index, value);
        if (code != rc.ok) return sqliteError(code);
    }

    pub fn columnType(self: Stmt, index: c_int) c_int {
        return api.column_type(self.stmt, index);
    }

    pub fn columnInt64(self: Stmt, index: c_int) i64 {
        return api.column_int64(self.stmt, index);
    }

    pub fn columnBytes(self: Stmt, index: c_int) ?[]const u8 {
        const kind = self.columnType(index);
        if (kind != column_type.text and kind != column_type.blob) return null;
        const len_c = api.column_bytes(self.stmt, index);
        const len = std.math.cast(usize, len_c) orelse return null;
        if (len == 0) return "";
        const ptr = api.column_blob(self.stmt, index) orelse return "";
        const bytes: [*]const u8 = @ptrCast(ptr);
        return bytes[0..len];
    }
};

const Column = struct { name: []const u8, decl: []const u8 };
const Table = struct { name: [:0]const u8, columns: []const Column, pragma: [*:0]const u8 };
pub const required_tables = [_]Table{
    .{ .name = "fail2banDb", .pragma = "PRAGMA table_info(fail2banDb)", .columns = &.{
        .{ .name = "version", .decl = "INTEGER" },
    } },
    .{ .name = "jails", .pragma = "PRAGMA table_info(jails)", .columns = &.{
        .{ .name = "name", .decl = "TEXT" },
        .{ .name = "enabled", .decl = "INTEGER" },
    } },
    .{ .name = "logs", .pragma = "PRAGMA table_info(logs)", .columns = &.{
        .{ .name = "jail", .decl = "TEXT" },
        .{ .name = "path", .decl = "TEXT" },
        .{ .name = "firstlinemd5", .decl = "TEXT" },
        .{ .name = "lastfilepos", .decl = "INTEGER" },
    } },
    .{ .name = "bans", .pragma = "PRAGMA table_info(bans)", .columns = &.{
        .{ .name = "jail", .decl = "TEXT" },
        .{ .name = "ip", .decl = "TEXT" },
        .{ .name = "timeofban", .decl = "INTEGER" },
        .{ .name = "bantime", .decl = "INTEGER" },
        .{ .name = "bancount", .decl = "INTEGER" },
        .{ .name = "data", .decl = "JSON" },
    } },
    .{ .name = "bips", .pragma = "PRAGMA table_info(bips)", .columns = &.{
        .{ .name = "ip", .decl = "TEXT" },
        .{ .name = "jail", .decl = "TEXT" },
        .{ .name = "timeofban", .decl = "INTEGER" },
        .{ .name = "bantime", .decl = "INTEGER" },
        .{ .name = "bancount", .decl = "INTEGER" },
        .{ .name = "data", .decl = "JSON" },
    } },
};

pub fn validateSchema(conn: Connection) Error!void {
    inline for (required_tables) |table| {
        var kind = try conn.prepare("SELECT type FROM sqlite_master WHERE name = ?1");
        defer kind.finalize();
        try kind.bindText(1, table.name);
        if (!try kind.step()) return error.UnsupportedSchema;
        const type_text = kind.columnBytes(0) orelse return error.UnsupportedSchema;
        if (!std.mem.eql(u8, type_text, "table")) return error.UnsupportedSchema;

        var info = try conn.prepare(table.pragma);
        defer info.finalize();
        var index: usize = 0;
        while (try info.step()) : (index += 1) {
            if (index >= table.columns.len) return error.UnsupportedSchema;
            const name = info.columnBytes(1) orelse return error.UnsupportedSchema;
            const decl = info.columnBytes(2) orelse return error.UnsupportedSchema;
            if (!std.mem.eql(u8, name, table.columns[index].name)) return error.UnsupportedSchema;
            if (!std.ascii.eqlIgnoreCase(decl, table.columns[index].decl)) return error.UnsupportedSchema;
        }
        if (index != table.columns.len) return error.UnsupportedSchema;
    }
}

pub fn readVersion(conn: Connection) Error!i64 {
    const rows = (try conn.scalarInt("SELECT count(*) FROM fail2banDb")) orelse return error.UnsupportedVersion;
    if (rows != 1) return error.UnsupportedVersion;
    const version = (conn.scalarInt("SELECT version FROM fail2banDb") catch |err| switch (err) {
        error.InvalidRow => return error.UnsupportedVersion,
        else => return err,
    }) orelse return error.UnsupportedVersion;
    if (version != expected_version) return error.UnsupportedVersion;
    return version;
}

pub const RowCounts = struct { jails: u64, logs: u64, bans: u64, bips: u64 };

pub fn countRows(conn: Connection) Error!RowCounts {
    return .{
        .jails = try countTable(conn, "SELECT count(*) FROM jails"),
        .logs = try countTable(conn, "SELECT count(*) FROM logs"),
        .bans = try countTable(conn, "SELECT count(*) FROM bans"),
        .bips = try countTable(conn, "SELECT count(*) FROM bips"),
    };
}

fn countTable(conn: Connection, sql: [*:0]const u8) Error!u64 {
    const value = (try conn.scalarInt(sql)) orelse return error.DatabaseFailure;
    return std.math.cast(u64, value) orelse error.DatabaseFailure;
}

pub fn Optional(comptime T: type) type {
    return union(enum) { absent, present: T };
}

pub const Jail = struct {
    name: []u8,
    enabled: Optional(i64),
    pub fn deinit(self: *Jail, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        self.* = undefined;
    }
};
pub const Log = struct {
    jail: []u8,
    path: Optional([]u8),
    firstlinemd5: Optional([]u8),
    lastfilepos: Optional(i64),
    pub fn deinit(self: *Log, allocator: std.mem.Allocator) void {
        allocator.free(self.jail);
        freeOptional(allocator, self.path);
        freeOptional(allocator, self.firstlinemd5);
        self.* = undefined;
    }
};
pub const Ban = struct {
    jail: []u8,
    ip: Optional([]u8),
    timeofban: i64,
    bantime: i64,
    bancount: i64,
    data: Optional([]u8),
    pub fn deinit(self: *Ban, allocator: std.mem.Allocator) void {
        allocator.free(self.jail);
        freeOptional(allocator, self.ip);
        freeOptional(allocator, self.data);
        self.* = undefined;
    }
};
pub const Bip = Ban;

fn freeOptional(allocator: std.mem.Allocator, value: Optional([]u8)) void {
    switch (value) {
        .absent => {},
        .present => |bytes| allocator.free(bytes),
    }
}

pub fn Iterator(comptime Row: type, comptime decode: fn (std.mem.Allocator, Stmt) Error!Row) type {
    return struct {
        const Self = @This();
        stmt: Stmt,
        allocator: std.mem.Allocator,
        pub fn next(self: *Self) Error!?Row {
            if (!try self.stmt.step()) return null;
            return try decode(self.allocator, self.stmt);
        }
        pub fn deinit(self: *Self) void {
            self.stmt.finalize();
            self.* = undefined;
        }
    };
}
pub const JailIterator = Iterator(Jail, decodeJail);
pub const LogIterator = Iterator(Log, decodeLog);
pub const BanIterator = Iterator(Ban, decodeBan);

pub const Reader = struct {
    conn: Connection,
    allocator: std.mem.Allocator,

    pub fn open(allocator: std.mem.Allocator, snapshot_path: []const u8) Error!Reader {
        const path_z = allocator.dupeZ(u8, snapshot_path) catch return error.OutOfMemory;
        defer allocator.free(path_z);
        var conn = try Connection.open(path_z, open_flags.readonly);
        errdefer conn.close();
        try validateSchema(conn);
        _ = try readVersion(conn);
        return .{ .conn = conn, .allocator = allocator };
    }

    pub fn close(self: *Reader) void {
        self.conn.close();
        self.* = undefined;
    }

    pub fn jails(self: Reader) Error!JailIterator {
        return .{ .allocator = self.allocator, .stmt = try self.conn.prepare("SELECT name, enabled FROM jails ORDER BY rowid") };
    }
    pub fn logs(self: Reader) Error!LogIterator {
        return .{ .allocator = self.allocator, .stmt = try self.conn.prepare("SELECT jail, path, firstlinemd5, lastfilepos FROM logs ORDER BY rowid") };
    }
    pub fn bans(self: Reader) Error!BanIterator {
        return .{ .allocator = self.allocator, .stmt = try self.conn.prepare("SELECT jail, ip, timeofban, bantime, bancount, data FROM bans ORDER BY rowid") };
    }
    pub fn bips(self: Reader) Error!BanIterator {
        return .{ .allocator = self.allocator, .stmt = try self.conn.prepare("SELECT jail, ip, timeofban, bantime, bancount, data FROM bips ORDER BY rowid") };
    }
};

fn requiredText(allocator: std.mem.Allocator, stmt: Stmt, index: c_int, max: usize) Error![]u8 {
    if (stmt.columnType(index) != column_type.text) return error.InvalidRow;
    const bytes = stmt.columnBytes(index) orelse return error.InvalidRow;
    if (bytes.len > max) return error.InvalidRow;
    return allocator.dupe(u8, bytes) catch return error.OutOfMemory;
}

fn optionalBytes(allocator: std.mem.Allocator, stmt: Stmt, index: c_int, max: usize) Error!Optional([]u8) {
    const kind = stmt.columnType(index);
    if (kind == column_type.null_value) return .absent;
    if (kind != column_type.text and kind != column_type.blob) return error.InvalidRow;
    const bytes = stmt.columnBytes(index) orelse return error.InvalidRow;
    if (bytes.len > max) return error.InvalidRow;
    return .{ .present = allocator.dupe(u8, bytes) catch return error.OutOfMemory };
}

fn requiredInt(stmt: Stmt, index: c_int) Error!i64 {
    if (stmt.columnType(index) != column_type.integer) return error.InvalidRow;
    return stmt.columnInt64(index);
}

fn optionalInt(stmt: Stmt, index: c_int) Error!Optional(i64) {
    const kind = stmt.columnType(index);
    if (kind == column_type.null_value) return .absent;
    if (kind != column_type.integer) return error.InvalidRow;
    return .{ .present = stmt.columnInt64(index) };
}

fn decodeJail(allocator: std.mem.Allocator, stmt: Stmt) Error!Jail {
    const name = try requiredText(allocator, stmt, 0, max_jail_bytes);
    errdefer allocator.free(name);
    return .{ .name = name, .enabled = try optionalInt(stmt, 1) };
}

fn decodeLog(allocator: std.mem.Allocator, stmt: Stmt) Error!Log {
    const jail = try requiredText(allocator, stmt, 0, max_jail_bytes);
    errdefer allocator.free(jail);
    const path = try optionalBytes(allocator, stmt, 1, max_path_bytes);
    errdefer freeOptional(allocator, path);
    const md5 = try optionalBytes(allocator, stmt, 2, max_md5_bytes);
    errdefer freeOptional(allocator, md5);
    return .{ .jail = jail, .path = path, .firstlinemd5 = md5, .lastfilepos = try optionalInt(stmt, 3) };
}

fn decodeBan(allocator: std.mem.Allocator, stmt: Stmt) Error!Ban {
    const jail = try requiredText(allocator, stmt, 0, max_jail_bytes);
    errdefer allocator.free(jail);
    const ip = try optionalBytes(allocator, stmt, 1, max_ip_bytes);
    errdefer freeOptional(allocator, ip);
    const timeofban = try requiredInt(stmt, 2);
    const bantime = try requiredInt(stmt, 3);
    const bancount = try requiredInt(stmt, 4);
    const data = try optionalBytes(allocator, stmt, 5, max_data_bytes);
    errdefer freeOptional(allocator, data);
    return .{ .jail = jail, .ip = ip, .timeofban = timeofban, .bantime = bantime, .bancount = bancount, .data = data };
}
