// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Deterministic fail2ban schema-4 fixture databases built with the embedded
//! SQLite. Test-only: nothing here runs in the product and no generated file
//! is checked in (see tests/fixtures/fail2ban/db/PROVENANCE.md).
//!
//! DDL restated from the GPL-2.0 upstream reference
//! `fail2ban-1.1.1/fail2ban/server/database.py:114-160`; addresses are drawn
//! from the RFC 5737 / RFC 3849 documentation ranges only.
const std = @import("std");
const db = @import("fail2ban_db.zig");

pub const Error = db.Error || error{PathTooLong};

pub const JournalProfile = enum {
    /// WAL with every write checkpointed into the main file before close.
    wal,
    /// WAL with autocheckpoint off and checkpoint-on-close suppressed, so the
    /// seeded rows exist only in `<path>-wal` when the builder returns.
    wal_pending,
    delete,
    /// fail2ban 1.1.x's own runtime choice (database.py:208); not persistent,
    /// so the on-disk file is indistinguishable from `delete` once closed.
    memory,
};

pub const Options = struct {
    profile: JournalProfile = .delete,
    /// Written into `fail2banDb.version`; 4 is the only supported value.
    version: i64 = db.expected_version,
    /// When set, that table's CREATE statement is skipped.
    omit_table: ?[]const u8 = null,
    /// Reference instant for the seeded bans; every seeded time is relative to it.
    now: i64 = 1_700_000_000,
    seed_rows: bool = true,
    /// Leaves out the `-2` sentinel row so the seeded set imports without a blocker.
    omit_sentinel: bool = false,
};

/// The reference DDL, one statement group per table, matching `_CREATE_SCRIPTS`.
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

/// Seeded `bans` rows, offset from `Options.now`. `bips` receives the same set
/// keyed by (ip, jail). Benign documentation addresses only.
pub fn seededBans(now: i64) [6]BanRow {
    return .{
        // Active finite ban: banned 10 min ago for 1 h.
        .{ .jail = "sshd", .ip = "192.0.2.10", .timeofban = now - 600, .bantime = 3600, .bancount = 1, .data = "{\"matches\": [], \"failures\": 5}" },
        // Expired finite ban: banned 2 h ago for 1 h.
        .{ .jail = "sshd", .ip = "192.0.2.11", .timeofban = now - 7200, .bantime = 3600, .bancount = 2, .data = "{\"matches\": [], \"failures\": 8}" },
        // Permanent (-1).
        .{ .jail = "sshd", .ip = "198.51.100.7", .timeofban = now - 86400, .bantime = -1, .bancount = 3, .data = "{\"matches\": [], \"failures\": 20}" },
        // Unknown/legacy sentinel (-2).
        .{ .jail = "sshd", .ip = "198.51.100.8", .timeofban = now - 300, .bantime = -2, .bancount = 1, .data = null },
        // IPv6 active.
        .{ .jail = "sshd", .ip = "2001:db8::1", .timeofban = now - 60, .bantime = 600, .bancount = 1, .data = "{\"matches\": [], \"failures\": 5}" },
        // Disabled jail history.
        .{ .jail = "nginx-http-auth", .ip = "192.0.2.200", .timeofban = now - 30, .bantime = 600, .bancount = 1, .data = "{}" },
    };
}

pub const seeded_jail_count: u64 = 2;
pub const seeded_log_count: u64 = 2;
pub const seeded_ban_count: u64 = 6;

/// Creates a fresh database at `path` (which must not exist) and returns.
/// All handles are closed; for `.wal_pending` the WAL keeps its frames.
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

/// Inserts one row into `bans` or `bips` through the given (writable) handle.
/// Tests use this from a second connection to act as a concurrent writer.
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

/// Opens an existing fixture writable (default journal handling) for tests
/// that need raw SQL, e.g. malformed rows or a concurrent writer.
pub fn openWriter(path: []const u8) Error!db.Connection {
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path_z = std.fmt.bufPrintZ(&path_buffer, "{s}", .{path}) catch return error.PathTooLong;
    var conn = try db.Connection.open(path_z, db.open_flags.readwrite);
    errdefer conn.close();
    try conn.busyTimeoutMs(1000);
    return conn;
}
