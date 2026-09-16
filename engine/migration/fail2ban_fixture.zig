// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! DDL restated from GPL-2.0 upstream `fail2ban-1.1.1/fail2ban/server/database.py:114-160`.
//! Addresses use only the RFC 5737 and RFC 3849 documentation ranges.
const std = @import("std");
const db = @import("fail2ban_db.zig");

pub const Error = db.Error || error{PathTooLong};

pub const JournalProfile = enum {
    wal,
    wal_pending,
    delete,
    memory,
};

pub const Options = struct {
    profile: JournalProfile = .delete,
    version: i64 = db.expected_version,
    omit_table: ?[]const u8 = null,
    now: i64 = 1_700_000_000,
    seed_rows: bool = true,
    omit_sentinel: bool = false,
};

pub const ddl = [_]struct { table: []const u8, sql: [*:0]const u8 }{
    .{ .table = "fail2banDb", .sql = "CREATE TABLE IF NOT EXISTS fail2banDb(version INTEGER);" },
    .{ .table = "jails", .sql = "CREATE TABLE IF NOT EXISTS jails(name TEXT NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 1);" ++
        "CREATE INDEX IF NOT EXISTS jails_name ON jails(name);" },
    .{ .table = "logs", .sql = "CREATE TABLE IF NOT EXISTS logs(jail TEXT NOT NULL, path TEXT, firstlinemd5 TEXT, lastfilepos INTEGER DEFAULT 0, " ++
        "FOREIGN KEY(jail) REFERENCES jails(name) ON DELETE CASCADE, UNIQUE(jail, path),UNIQUE(jail, path, firstlinemd5));" ++
        "CREATE INDEX IF NOT EXISTS logs_path ON logs(path);CREATE INDEX IF NOT EXISTS logs_jail_path ON logs(jail, path);" },
    .{ .table = "bans", .sql = "CREATE TABLE IF NOT EXISTS bans(jail TEXT NOT NULL, ip TEXT, timeofban INTEGER NOT NULL, bantime INTEGER NOT NULL, " ++
        "bancount INTEGER NOT NULL default 1, data JSON, FOREIGN KEY(jail) REFERENCES jails(name) );" ++
        "CREATE INDEX IF NOT EXISTS bans_jail_timeofban_ip ON bans(jail, timeofban);CREATE INDEX IF NOT EXISTS bans_jail_ip ON bans(jail, ip);" ++
        "CREATE INDEX IF NOT EXISTS bans_ip ON bans(ip);" },
    .{ .table = "bips", .sql = "CREATE TABLE IF NOT EXISTS bips(ip TEXT NOT NULL, jail TEXT NOT NULL, timeofban INTEGER NOT NULL, bantime INTEGER NOT NULL, " ++
        "bancount INTEGER NOT NULL default 1, data JSON, PRIMARY KEY(ip, jail), FOREIGN KEY(jail) REFERENCES jails(name) );" ++
        "CREATE INDEX IF NOT EXISTS bips_timeofban ON bips(timeofban);CREATE INDEX IF NOT EXISTS bips_ip ON bips(ip);" },
};

pub const BanRow = struct {
    jail: []const u8,
    ip: ?[]const u8,
    timeofban: i64,
    bantime: i64,
    bancount: i64 = 1,
    data: ?[]const u8,
};

pub fn seededBans(now: i64) [6]BanRow {
    return .{
        .{ .jail = "sshd", .ip = "192.0.2.10", .timeofban = now - 600, .bantime = 3600, .bancount = 1, .data = "{\"matches\": [], \"failures\": 5}" },
        .{ .jail = "sshd", .ip = "192.0.2.11", .timeofban = now - 7200, .bantime = 3600, .bancount = 2, .data = "{\"matches\": [], \"failures\": 8}" },
        .{ .jail = "sshd", .ip = "198.51.100.7", .timeofban = now - 86400, .bantime = -1, .bancount = 3, .data = "{\"matches\": [], \"failures\": 20}" },
        .{ .jail = "sshd", .ip = "198.51.100.8", .timeofban = now - 300, .bantime = -2, .bancount = 1, .data = null },
        .{ .jail = "sshd", .ip = "2001:db8::1", .timeofban = now - 60, .bantime = 600, .bancount = 1, .data = "{\"matches\": [], \"failures\": 5}" },
        .{ .jail = "nginx-http-auth", .ip = "192.0.2.200", .timeofban = now - 30, .bantime = 600, .bancount = 1, .data = "{}" },
    };
}

pub const seeded_jail_count: u64 = 2;
pub const seeded_log_count: u64 = 2;
pub const seeded_ban_count: u64 = 6;

pub fn build(path: []const u8, options: Options) Error!void {
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path_z = std.fmt.bufPrintZ(&path_buffer, "{s}", .{path}) catch return error.PathTooLong;
    var conn = try db.Connection.open(path_z, db.open_flags.readwrite | db.open_flags.create);
    defer conn.close();
    switch (options.profile) {
        .wal => try conn.exec("PRAGMA journal_mode=WAL"),
        .wal_pending => {
            try conn.exec("PRAGMA journal_mode=WAL");
            try conn.exec("PRAGMA wal_autocheckpoint=0");
            try conn.disableCheckpointOnClose();
        },
        .delete => try conn.exec("PRAGMA journal_mode=DELETE"),
        .memory => try conn.exec("PRAGMA journal_mode=MEMORY"),
    }
    try conn.exec("BEGIN");
    for (ddl) |entry| {
        if (options.omit_table) |omitted| {
            if (std.mem.eql(u8, omitted, entry.table)) continue;
        }
        try conn.exec(entry.sql);
    }
    if (options.omit_table == null or !std.mem.eql(u8, options.omit_table.?, "fail2banDb")) {
        var version = try conn.prepare("INSERT INTO fail2banDb(version) VALUES(?1)");
        defer version.finalize();
        try version.bindInt64(1, options.version);
        _ = try version.step();
    }
    if (options.seed_rows and options.omit_table == null) try seed(conn, options.now, options.omit_sentinel);
    try conn.exec("COMMIT");
    if (options.profile == .wal) try conn.exec("PRAGMA wal_checkpoint(TRUNCATE)");
}

fn seed(conn: db.Connection, now: i64, omit_sentinel: bool) Error!void {
    try conn.exec("INSERT INTO jails(name, enabled) VALUES('sshd', 1), ('nginx-http-auth', 0)");
    try conn.exec("INSERT INTO logs(jail, path, firstlinemd5, lastfilepos) VALUES" ++
        "('sshd', '/var/log/auth.log', 'd41d8cd98f00b204e9800998ecf8427e', 12345)," ++
        "('nginx-http-auth', '/var/log/nginx/error.log', NULL, 0)");
    for (seededBans(now)) |row| {
        if (omit_sentinel and row.bantime == -2) continue;
        try insertBan(conn, "bans", row);
        try insertBan(conn, "bips", row);
    }
}

pub fn insertBan(conn: db.Connection, table: []const u8, row: BanRow) Error!void {
    const sql: [*:0]const u8 = if (std.mem.eql(u8, table, "bips"))
        "INSERT OR REPLACE INTO bips(jail, ip, timeofban, bantime, bancount, data) VALUES(?1, ?2, ?3, ?4, ?5, ?6)"
    else
        "INSERT INTO bans(jail, ip, timeofban, bantime, bancount, data) VALUES(?1, ?2, ?3, ?4, ?5, ?6)";
    var stmt = try conn.prepare(sql);
    defer stmt.finalize();
    try stmt.bindText(1, row.jail);
    if (row.ip) |ip| try stmt.bindText(2, ip) else try stmt.bindNull(2);
    try stmt.bindInt64(3, row.timeofban);
    try stmt.bindInt64(4, row.bantime);
    try stmt.bindInt64(5, row.bancount);
    if (row.data) |data| try stmt.bindText(6, data) else try stmt.bindNull(6);
    _ = try stmt.step();
}

pub fn openWriter(path: []const u8) Error!db.Connection {
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path_z = std.fmt.bufPrintZ(&path_buffer, "{s}", .{path}) catch return error.PathTooLong;
    var conn = try db.Connection.open(path_z, db.open_flags.readwrite);
    errdefer conn.close();
    try conn.busyTimeoutMs(1000);
    return conn;
}
