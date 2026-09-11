// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Optional full-profile SQLite record/cursor transaction foundation.
//! A committed checkpoint is authoritative; external effects are queued, never executed here.
const std = @import("std");
const builtin = @import("builtin");
const Db = opaque {};
const Statement = opaque {};
const Destructor = ?*const fn (?*anyopaque) callconv(.c) void;
const Api = struct {
    open: *const fn ([*:0]const u8, *?*Db, c_int, ?[*:0]const u8) callconv(.c) c_int,
    close: *const fn (*Db) callconv(.c) c_int,
    exec: *const fn (*Db, [*:0]const u8, ?*anyopaque, ?*anyopaque, ?*?[*:0]u8) callconv(.c) c_int,
    prepare: *const fn (*Db, [*:0]const u8, c_int, *?*Statement, ?*?[*:0]const u8) callconv(.c) c_int,
    finalize: *const fn (*Statement) callconv(.c) c_int,
    step: *const fn (*Statement) callconv(.c) c_int,
    bind_blob: *const fn (*Statement, c_int, ?*const anyopaque, c_int, Destructor) callconv(.c) c_int,
    bind_text: *const fn (*Statement, c_int, [*]const u8, c_int, Destructor) callconv(.c) c_int,
    bind_null: *const fn (*Statement, c_int) callconv(.c) c_int,
    column_blob: *const fn (*Statement, c_int) callconv(.c) ?*const anyopaque,
    column_bytes: *const fn (*Statement, c_int) callconv(.c) c_int,
    column_int64: *const fn (*Statement, c_int) callconv(.c) i64,
    changes: *const fn (*Db) callconv(.c) c_int,
    busy_timeout: *const fn (*Db, c_int) callconv(.c) c_int,
};
pub const Error = error{ UnsupportedProfile, LibraryUnavailable, SymbolMissing, OpenFailed, UnsafePermissions, ForeignDatabase, UnsupportedSchema, DatabaseFailure, Busy, InvalidRecord, OccurrenceConflict, StaleCheckpoint, StaleSharedCheckpoint, InjectedFailure, OutOfMemory };
pub const CommitStage = enum { after_record, after_checkpoint, after_shared_checkpoint, before_commit };
pub const SharedState = struct {
    name: []const u8,
    expected_revision: u64,
    /// Null validates a read dependency without rewriting or bumping its revision.
    /// Supply the dependency whenever a decision reads shared state, even if its
    /// bytes are unchanged. Zero revision explicitly depends on absent state.
    payload: ?[]const u8 = null,
};
pub const Record = struct {
    jail: []const u8,
    source: []const u8,
    occurrence: []const u8,
    cursor: []const u8,
    source_path: ?[]const u8 = null,
    raw_hash: [32]u8,
    event_time: ?f64 = null,
    timestamp_us: ?u64 = null,
    expected_revision: u64 = 0,
    disposition: []const u8,
    /// Versioned caller-owned filter/ticket snapshot, atomically paired with cursor.
    checkpoint: []const u8,
    /// Versioned typed intent payload. Null means no external effect requested.
    action_intent: ?[]const u8 = null,
    /// Process-wide state (for example DNS caches) participates in the same
    /// transaction as this jail's record, checkpoint, cursor and action intent.
    shared_state: ?SharedState = null,
};
pub const CommitResult = enum { committed, already_committed };
pub const Store = struct {
    allocator: std.mem.Allocator,
    library: std.DynLib,
    api: Api,
    db: *Db,
    /// Tests inject an ordinary transaction error; no crash or external action is required.
    fail_at: ?CommitStage = null,

    pub fn open(allocator: std.mem.Allocator, path: []const u8) Error!Store {
        if (comptime !builtin.link_libc or (builtin.abi == .musl and builtin.link_mode == .static))
            return error.UnsupportedProfile;
        if (path.len == 0 or std.mem.indexOfScalar(u8, path, 0) != null) return error.OpenFailed;
        var parent = std.fs.cwd().openDir(std.fs.path.dirname(path) orelse ".", .{ .no_follow = true }) catch return error.OpenFailed;
        defer parent.close();
        const parent_stat = std.posix.fstat(parent.fd) catch return error.OpenFailed;
        if (parent_stat.uid != std.os.linux.geteuid() or parent_stat.mode & 0o022 != 0) return error.UnsafePermissions;
        const fd = std.posix.open(path, .{ .ACCMODE = .RDWR, .CREAT = true, .CLOEXEC = true, .NOFOLLOW = true }, 0o600) catch return error.OpenFailed;
        defer std.posix.close(fd);
        const stat = std.posix.fstat(fd) catch return error.OpenFailed;
        if (!std.posix.S.ISREG(stat.mode) or stat.mode & 0o077 != 0 or stat.uid != std.os.linux.geteuid())
            return error.UnsafePermissions;
        var library = std.DynLib.open("libsqlite3.so.0") catch return error.LibraryUnavailable;
        errdefer library.close();
        var api: Api = undefined;
        inline for (std.meta.fields(Api)) |field| {
            const symbol = if (std.mem.eql(u8, field.name, "open")) "sqlite3_open_v2" else if (std.mem.eql(u8, field.name, "close")) "sqlite3_close_v2" else if (std.mem.eql(u8, field.name, "prepare")) "sqlite3_prepare_v2" else "sqlite3_" ++ field.name;
            @field(api, field.name) = library.lookup(field.type, symbol) orelse return error.SymbolMissing;
        }
        const filename = allocator.dupeZ(u8, path) catch return error.OutOfMemory;
        defer allocator.free(filename);
        var db: ?*Db = null;
        const opened = api.open(filename, &db, 2 | 4 | 0x10000 | 0x01000000, null);
        if (opened != 0 or db == null) {
            if (db) |handle| _ = api.close(handle);
            return error.OpenFailed;
        }
        var self = Store{ .allocator = allocator, .library = library, .api = api, .db = db.? };
        errdefer _ = self.api.close(self.db);
        try self.check(api.busy_timeout(self.db, 1000));
        try self.exec("PRAGMA trusted_schema=OFF;");
        const application = try self.integer("PRAGMA application_id;");
        const schema = try self.integer("PRAGMA user_version;");
        if (application == 0) {
            if (schema != 0 or try self.integer("SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%';") != 0) return error.ForeignDatabase;
        } else if (application != 0x46325a31) return error.ForeignDatabase;
        if (schema != 0 and schema != 1 and schema != 2) return error.UnsupportedSchema;
        try self.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;");
        {
            var mode = try self.statement("PRAGMA journal_mode;");
            defer mode.deinit();
            if (!try mode.row() or !std.mem.eql(u8, mode.bytes(0), "wal") or try self.integer("PRAGMA synchronous;") != 2)
                return error.DatabaseFailure;
        }
        self.exec(
            \\BEGIN IMMEDIATE;
            \\CREATE TABLE IF NOT EXISTS records(jail TEXT NOT NULL,source TEXT NOT NULL,occurrence TEXT NOT NULL,raw_hash BLOB NOT NULL CHECK(length(raw_hash)=32),cursor BLOB NOT NULL,event_time BLOB CHECK(event_time IS NULL OR length(event_time)=8),timestamp_us TEXT,disposition TEXT NOT NULL,PRIMARY KEY(jail,source,occurrence));
            \\CREATE TABLE IF NOT EXISTS source_cursors(jail TEXT NOT NULL,source TEXT NOT NULL,cursor BLOB NOT NULL,occurrence TEXT NOT NULL,path TEXT,PRIMARY KEY(jail,source));
            \\CREATE TABLE IF NOT EXISTS checkpoints(jail TEXT PRIMARY KEY NOT NULL,payload BLOB NOT NULL,revision INTEGER NOT NULL CHECK(revision>0));
            \\CREATE TABLE IF NOT EXISTS shared_checkpoints(name TEXT PRIMARY KEY NOT NULL,payload BLOB NOT NULL,revision INTEGER NOT NULL CHECK(revision>0));
            \\CREATE TABLE IF NOT EXISTS action_intents(jail TEXT NOT NULL,source TEXT NOT NULL,occurrence TEXT NOT NULL,payload BLOB NOT NULL,status TEXT NOT NULL DEFAULT 'pending',PRIMARY KEY(jail,source,occurrence),FOREIGN KEY(jail,source,occurrence) REFERENCES records(jail,source,occurrence));
            \\PRAGMA application_id=1177705009;
            \\PRAGMA user_version=2;
            \\COMMIT;
        ) catch |err| {
            self.exec("ROLLBACK;") catch {};
            return err;
        };
        return self;
    }

    pub fn close(self: *Store) void {
        _ = self.api.close(self.db);
        self.library.close();
        self.* = undefined;
    }
    fn check(self: *Store, rc: c_int) Error!void {
        _ = self;
        if (rc == 0) return;
        return if (rc == 5 or rc == 6) error.Busy else error.DatabaseFailure;
    }
    fn exec(self: *Store, sql: [:0]const u8) Error!void {
        try self.check(self.api.exec(self.db, sql, null, null, null));
    }
    fn statement(self: *Store, sql: [:0]const u8) Error!Stmt {
        var ptr: ?*Statement = null;
        try self.check(self.api.prepare(self.db, sql, -1, &ptr, null));
        return .{ .store = self, .ptr = ptr orelse return error.DatabaseFailure };
    }
    fn integer(self: *Store, sql: [:0]const u8) Error!i64 {
        var stmt = try self.statement(sql);
        defer stmt.deinit();
        if (!try stmt.row()) return error.DatabaseFailure;
        return self.api.column_int64(stmt.ptr, 0);
    }
    fn fault(self: *Store, stage: CommitStage) Error!void {
        if (self.fail_at == stage) return error.InjectedFailure;
    }
    pub fn commitRecord(self: *Store, record: Record) Error!CommitResult {
        if (record.jail.len == 0 or record.source.len == 0 or record.occurrence.len == 0 or record.cursor.len == 0 or
            record.jail.len > 4096 or record.source.len > 16384 or record.occurrence.len > 16384 or record.cursor.len > 65536 or
            record.checkpoint.len > 16 * 1024 * 1024 or record.disposition.len > 64) return error.InvalidRecord;
        if (record.source_path) |path| if (path.len > 16384 or std.mem.indexOfScalar(u8, path, 0) != null) return error.InvalidRecord;
        if (record.event_time) |time| if (!std.math.isFinite(time)) return error.InvalidRecord;
        if (record.action_intent) |intent| if (intent.len > 1024 * 1024) return error.InvalidRecord;
        if (record.shared_state) |shared| {
            if (shared.name.len == 0 or shared.name.len > 4096 or std.mem.indexOfScalar(u8, shared.name, 0) != null) return error.InvalidRecord;
            if (shared.payload) |payload| if (payload.len > 4 * 1024 * 1024) return error.InvalidRecord;
        }
        try self.exec("BEGIN IMMEDIATE;");
        errdefer self.exec("ROLLBACK;") catch {};
        {
            var prior = try self.statement("SELECT raw_hash,cursor FROM records WHERE jail=?1 AND source=?2 AND occurrence=?3;");
            defer prior.deinit();
            try prior.text(1, record.jail);
            try prior.text(2, record.source);
            try prior.text(3, record.occurrence);
            if (try prior.row()) {
                if (!std.mem.eql(u8, prior.bytes(0), &record.raw_hash) or !std.mem.eql(u8, prior.bytes(1), record.cursor)) return error.OccurrenceConflict;
                try self.exec("COMMIT;");
                return .already_committed;
            }
        }
        {
            const expected = record.expected_revision;
            var current = try self.statement("SELECT revision FROM checkpoints WHERE jail=?1;");
            defer current.deinit();
            try current.text(1, record.jail);
            var current_revision: u64 = 0;
            if (try current.row()) {
                const stored_revision = self.api.column_int64(current.ptr, 0);
                if (stored_revision <= 0) return error.DatabaseFailure;
                current_revision = @intCast(stored_revision);
            }
            if (current_revision != expected or current_revision >= std.math.maxInt(i64)) return error.StaleCheckpoint;
        }
        if (record.shared_state) |shared| {
            var current = try self.statement("SELECT revision FROM shared_checkpoints WHERE name=?1;");
            defer current.deinit();
            try current.text(1, shared.name);
            var current_revision: u64 = 0;
            if (try current.row()) {
                const stored_revision = self.api.column_int64(current.ptr, 0);
                if (stored_revision <= 0) return error.DatabaseFailure;
                current_revision = @intCast(stored_revision);
            }
            if (current_revision != shared.expected_revision or (shared.payload != null and current_revision >= std.math.maxInt(i64))) return error.StaleSharedCheckpoint;
        }
        {
            var stmt = try self.statement("INSERT INTO records VALUES(?1,?2,?3,?4,?5,?6,?7,?8);");
            defer stmt.deinit();
            try stmt.text(1, record.jail);
            try stmt.text(2, record.source);
            try stmt.text(3, record.occurrence);
            try stmt.blob(4, &record.raw_hash);
            try stmt.blob(5, record.cursor);
            var time_bits: [8]u8 = undefined;
            if (record.event_time) |time| {
                std.mem.writeInt(u64, &time_bits, @bitCast(time), .big);
                try stmt.blob(6, &time_bits);
            } else try self.check(self.api.bind_null(stmt.ptr, 6));
            var timestamp_buffer: [20]u8 = undefined;
            if (record.timestamp_us) |timestamp| {
                const encoded = std.fmt.bufPrint(&timestamp_buffer, "{d}", .{timestamp}) catch return error.InvalidRecord;
                try stmt.text(7, encoded);
            } else try self.check(self.api.bind_null(stmt.ptr, 7));
            try stmt.text(8, record.disposition);
            try stmt.done();
        }
        try self.fault(.after_record);
        {
            var stmt = try self.statement("INSERT INTO checkpoints VALUES(?1,?2,1) ON CONFLICT(jail) DO UPDATE SET payload=excluded.payload,revision=checkpoints.revision+1;");
            defer stmt.deinit();
            try stmt.text(1, record.jail);
            try stmt.blob(2, record.checkpoint);
            try stmt.done();
        }
        try self.fault(.after_checkpoint);
        if (record.shared_state) |shared| if (shared.payload) |payload| {
            var stmt = try self.statement("INSERT INTO shared_checkpoints VALUES(?1,?2,1) ON CONFLICT(name) DO UPDATE SET payload=excluded.payload,revision=shared_checkpoints.revision+1;");
            defer stmt.deinit();
            try stmt.text(1, shared.name);
            try stmt.blob(2, payload);
            try stmt.done();
        };
        try self.fault(.after_shared_checkpoint);
        {
            var stmt = try self.statement("INSERT INTO source_cursors VALUES(?1,?2,?3,?4,?5) ON CONFLICT(jail,source) DO UPDATE SET cursor=excluded.cursor,occurrence=excluded.occurrence,path=excluded.path;");
            defer stmt.deinit();
            try stmt.text(1, record.jail);
            try stmt.text(2, record.source);
            try stmt.blob(3, record.cursor);
            try stmt.text(4, record.occurrence);
            if (record.source_path) |path| try stmt.text(5, path) else try self.check(self.api.bind_null(stmt.ptr, 5));
            try stmt.done();
        }
        if (record.action_intent) |intent| {
            var stmt = try self.statement("INSERT INTO action_intents(jail,source,occurrence,payload) VALUES(?1,?2,?3,?4);");
            defer stmt.deinit();
            try stmt.text(1, record.jail);
            try stmt.text(2, record.source);
            try stmt.text(3, record.occurrence);
            try stmt.blob(4, intent);
            try stmt.done();
        }
        try self.fault(.before_commit);
        try self.exec("COMMIT;");
        return .committed;
    }
    pub fn sourceCursor(self: *Store, allocator: std.mem.Allocator, jail: []const u8, source: []const u8) Error!?[]u8 {
        var stmt = try self.statement("SELECT cursor FROM source_cursors WHERE jail=?1 AND source=?2;");
        defer stmt.deinit();
        try stmt.text(1, jail);
        try stmt.text(2, source);
        if (!try stmt.row()) return null;
        return allocator.dupe(u8, stmt.bytes(0)) catch error.OutOfMemory;
    }
    pub fn revision(self: *Store, jail: []const u8) Error!u64 {
        var stmt = try self.statement("SELECT revision FROM checkpoints WHERE jail=?1;");
        defer stmt.deinit();
        try stmt.text(1, jail);
        if (!try stmt.row()) return 0;
        const value = self.api.column_int64(stmt.ptr, 0);
        if (value <= 0) return error.DatabaseFailure;
        return @intCast(value);
    }
    pub const Snapshot = struct {
        payload: ?[]u8,
        revision: u64,
        pub fn deinit(self: Snapshot, allocator: std.mem.Allocator) void {
            if (self.payload) |payload| allocator.free(payload);
        }
    };
    pub fn snapshot(self: *Store, allocator: std.mem.Allocator, jail: []const u8) Error!Snapshot {
        var stmt = try self.statement("SELECT payload,revision FROM checkpoints WHERE jail=?1;");
        defer stmt.deinit();
        try stmt.text(1, jail);
        if (!try stmt.row()) return .{ .payload = null, .revision = 0 };
        const saved_revision = self.api.column_int64(stmt.ptr, 1);
        if (saved_revision <= 0) return error.DatabaseFailure;
        return .{ .payload = allocator.dupe(u8, stmt.bytes(0)) catch return error.OutOfMemory, .revision = @intCast(saved_revision) };
    }
    pub fn sharedSnapshot(self: *Store, allocator: std.mem.Allocator, name: []const u8) Error!Snapshot {
        var stmt = try self.statement("SELECT payload,revision FROM shared_checkpoints WHERE name=?1;");
        defer stmt.deinit();
        try stmt.text(1, name);
        if (!try stmt.row()) return .{ .payload = null, .revision = 0 };
        const saved_revision = self.api.column_int64(stmt.ptr, 1);
        if (saved_revision <= 0) return error.DatabaseFailure;
        return .{ .payload = allocator.dupe(u8, stmt.bytes(0)) catch return error.OutOfMemory, .revision = @intCast(saved_revision) };
    }
    pub fn checkpoint(self: *Store, allocator: std.mem.Allocator, jail: []const u8) Error!?[]u8 {
        var stmt = try self.statement("SELECT payload FROM checkpoints WHERE jail=?1;");
        defer stmt.deinit();
        try stmt.text(1, jail);
        if (!try stmt.row()) return null;
        return allocator.dupe(u8, stmt.bytes(0)) catch error.OutOfMemory;
    }
    pub fn pendingIntents(self: *Store) Error!i64 {
        return self.integer("SELECT count(*) FROM action_intents WHERE status='pending';");
    }

    /// Callback slices live only until the callback returns. Enumerate before
    /// discovering current paths so renamed incarnations are not forgotten.
    pub fn visitSources(self: *Store, jail: []const u8, callback: *const fn ([]const u8, []const u8, []const u8, ?*anyopaque) anyerror!void, context: ?*anyopaque) !void {
        var stmt = try self.statement("SELECT source,path,cursor FROM source_cursors WHERE jail=?1 ORDER BY source;");
        defer stmt.deinit();
        try stmt.text(1, jail);
        while (try stmt.row()) try callback(stmt.bytes(0), stmt.bytes(1), stmt.bytes(2), context);
    }

    pub fn hasRecord(self: *Store, jail: []const u8, source: []const u8, occurrence: []const u8, raw_hash: [32]u8, cursor: []const u8) Error!bool {
        var stmt = try self.statement("SELECT raw_hash,cursor FROM records WHERE jail=?1 AND source=?2 AND occurrence=?3;");
        defer stmt.deinit();
        try stmt.text(1, jail);
        try stmt.text(2, source);
        try stmt.text(3, occurrence);
        if (!try stmt.row()) return false;
        if (!std.mem.eql(u8, stmt.bytes(0), &raw_hash) or !std.mem.eql(u8, stmt.bytes(1), cursor)) return error.OccurrenceConflict;
        return true;
    }
};
const Stmt = struct {
    store: *Store,
    ptr: *Statement,
    fn deinit(self: *Stmt) void {
        _ = self.store.api.finalize(self.ptr);
    }
    fn text(self: *Stmt, index: c_int, value: []const u8) Error!void {
        if (value.len > std.math.maxInt(c_int)) return error.InvalidRecord;
        try self.store.check(self.store.api.bind_text(self.ptr, index, value.ptr, @intCast(value.len), null));
    }
    fn blob(self: *Stmt, index: c_int, value: []const u8) Error!void {
        if (value.len > std.math.maxInt(c_int)) return error.InvalidRecord;
        try self.store.check(self.store.api.bind_blob(self.ptr, index, value.ptr, @intCast(value.len), null));
    }
    fn row(self: *Stmt) Error!bool {
        return switch (self.store.api.step(self.ptr)) {
            100 => true,
            101 => false,
            5, 6 => error.Busy,
            else => error.DatabaseFailure,
        };
    }
    fn done(self: *Stmt) Error!void {
        if (try self.row()) return error.DatabaseFailure;
    }
    fn bytes(self: *Stmt, column: c_int) []const u8 {
        const length = self.store.api.column_bytes(self.ptr, column);
        if (length <= 0) return "";
        const ptr: [*]const u8 = @ptrCast(self.store.api.column_blob(self.ptr, column) orelse return "");
        return ptr[0..@intCast(length)];
    }
};

test "record store: record checkpoint cursor and intent commit together and replay is idempotent" {
    if (!builtin.link_libc) return error.SkipZigTest;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const path = try std.fs.path.join(std.testing.allocator, &.{ base, "state.sqlite" });
    defer std.testing.allocator.free(path);
    var store = try Store.open(std.testing.allocator, path);
    const record = Record{ .jail = "sshd", .source = "file:1", .occurrence = "incarnation:1:0:20", .cursor = "20", .raw_hash = [_]u8{1} ** 32, .event_time = 1800000000.125, .disposition = "matched", .checkpoint = "ticket=1", .action_intent = "typed-test-intent" };
    for ([_]CommitStage{ .after_record, .after_checkpoint, .before_commit }) |stage| {
        store.fail_at = stage;
        try std.testing.expectError(error.InjectedFailure, store.commitRecord(record));
        try std.testing.expectEqual(@as(?[]u8, null), try store.sourceCursor(std.testing.allocator, "sshd", "file:1"));
        try std.testing.expectEqual(@as(?[]u8, null), try store.checkpoint(std.testing.allocator, "sshd"));
        try std.testing.expectEqual(@as(i64, 0), try store.pendingIntents());
    }
    store.fail_at = null;
    try std.testing.expectEqual(CommitResult.committed, try store.commitRecord(record));
    try std.testing.expectEqual(CommitResult.already_committed, try store.commitRecord(record));
    try std.testing.expectEqual(@as(i64, 1), try store.pendingIntents());
    var conflict = record;
    conflict.raw_hash[0] = 2;
    try std.testing.expectError(error.OccurrenceConflict, store.commitRecord(conflict));
    store.close();
    store = try Store.open(std.testing.allocator, path);
    defer store.close();
    const cursor = (try store.sourceCursor(std.testing.allocator, "sshd", "file:1")).?;
    defer std.testing.allocator.free(cursor);
    try std.testing.expectEqualStrings("20", cursor);
    const saved = (try store.checkpoint(std.testing.allocator, "sshd")).?;
    defer std.testing.allocator.free(saved);
    try std.testing.expectEqualStrings("ticket=1", saved);
}

test "record store: stale writers cannot overwrite a committed jail checkpoint" {
    if (!builtin.link_libc) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const path = try std.fs.path.join(allocator, &.{ base, "state.sqlite" });
    defer allocator.free(path);
    var first = try Store.open(allocator, path);
    defer first.close();
    var second = try Store.open(allocator, path);
    defer second.close();
    var record = Record{ .jail = "fixture", .source = "one", .occurrence = "one", .cursor = "1", .raw_hash = [_]u8{1} ** 32, .disposition = "counted", .checkpoint = "first", .expected_revision = 0, .timestamp_us = std.math.maxInt(u64), .event_time = @bitCast(@as(u64, 0x8000000000000000)) };
    const stale = try second.snapshot(allocator, "fixture");
    defer stale.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), stale.revision);
    _ = try first.commitRecord(record);
    {
        var value = try first.statement("SELECT event_time,timestamp_us FROM records;");
        defer value.deinit();
        try std.testing.expect(try value.row());
        try std.testing.expectEqualSlices(u8, &.{ 0x80, 0, 0, 0, 0, 0, 0, 0 }, value.bytes(0));
        try std.testing.expectEqualStrings("18446744073709551615", value.bytes(1));
    }
    record.occurrence = "two";
    record.checkpoint = "stale";
    try std.testing.expectError(error.StaleCheckpoint, second.commitRecord(record));
    const current = try second.snapshot(allocator, "fixture");
    defer current.deinit(allocator);
    try std.testing.expectEqualStrings("first", current.payload.?);
    try std.testing.expectEqual(@as(u64, 1), current.revision);
    try std.testing.expectEqual(@as(i64, 1), try first.integer("SELECT count(*) FROM records;"));
    record.expected_revision = current.revision;
    record.checkpoint = "second";
    _ = try second.commitRecord(record);
    try std.testing.expectEqual(@as(i64, 2), try first.integer("SELECT count(*) FROM records;"));
}

test "record store: shared read dependencies and writes are atomic across jails and connections" {
    if (!builtin.link_libc) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const path = try std.fs.path.join(allocator, &.{ base, "shared.sqlite" });
    defer allocator.free(path);
    var first = try Store.open(allocator, path);
    defer first.close();
    var second = try Store.open(allocator, path);
    defer second.close();
    var record = Record{ .jail = "one", .source = "file", .occurrence = "1", .cursor = "1", .raw_hash = [_]u8{1} ** 32, .disposition = "ordinary", .checkpoint = "jail-one", .action_intent = "inert-intent", .shared_state = .{ .name = "dns", .expected_revision = 0 } };
    // A dependency on absent state does not create an empty cache checkpoint.
    _ = try first.commitRecord(record);
    {
        const absent = try second.sharedSnapshot(allocator, "dns");
        defer absent.deinit(allocator);
        try std.testing.expectEqual(@as(u64, 0), absent.revision);
        try std.testing.expect(absent.payload == null);
    }
    record.jail = "two";
    record.shared_state.?.payload = "cache-one";
    second.fail_at = .after_shared_checkpoint;
    try std.testing.expectError(error.InjectedFailure, second.commitRecord(record));
    try std.testing.expectEqual(@as(u64, 0), try first.revision("two"));
    try std.testing.expectEqual(@as(?[]u8, null), try first.sourceCursor(allocator, "two", "file"));
    try std.testing.expectEqual(@as(i64, 1), try first.pendingIntents());
    {
        const absent = try first.sharedSnapshot(allocator, "dns");
        defer absent.deinit(allocator);
        try std.testing.expectEqual(@as(u64, 0), absent.revision);
    }
    second.fail_at = null;
    _ = try second.commitRecord(record);
    var stale = record;
    stale.jail = "three";
    stale.shared_state.?.payload = null;
    try std.testing.expectError(error.StaleSharedCheckpoint, first.commitRecord(stale));
    stale.shared_state.?.payload = "stale-cache";
    try std.testing.expectError(error.StaleSharedCheckpoint, first.commitRecord(stale));
    try std.testing.expectEqual(@as(u64, 0), try first.revision("three"));
    stale.shared_state.?.expected_revision = 1;
    stale.shared_state.?.payload = null;
    _ = try first.commitRecord(stale);
    {
        const saved = try second.sharedSnapshot(allocator, "dns");
        defer saved.deinit(allocator);
        try std.testing.expectEqual(@as(u64, 1), saved.revision);
        try std.testing.expectEqualStrings("cache-one", saved.payload.?);
    }
    stale.jail = "four";
    stale.shared_state.?.payload = "cache-two";
    _ = try first.commitRecord(stale);
    // Replaying an old committed record cannot rewind the process-wide cache.
    try std.testing.expectEqual(CommitResult.already_committed, try second.commitRecord(record));
    const saved = try second.sharedSnapshot(allocator, "dns");
    defer saved.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 2), saved.revision);
    try std.testing.expectEqualStrings("cache-two", saved.payload.?);
}

test "record store: schema one upgrade preserves committed state" {
    if (!builtin.link_libc) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const path = try std.fs.path.join(allocator, &.{ base, "upgrade.sqlite" });
    defer allocator.free(path);
    {
        var old = try Store.open(allocator, path);
        defer old.close();
        _ = try old.commitRecord(.{ .jail = "retained", .source = "file", .occurrence = "1", .cursor = "saved-cursor", .raw_hash = [_]u8{1} ** 32, .disposition = "ordinary", .checkpoint = "saved-jail", .action_intent = "saved-intent" });
        try old.exec("DROP TABLE shared_checkpoints; PRAGMA user_version=1;");
    }
    var upgraded = try Store.open(allocator, path);
    defer upgraded.close();
    try std.testing.expectEqual(@as(i64, 2), try upgraded.integer("PRAGMA user_version;"));
    const saved = try upgraded.snapshot(allocator, "retained");
    defer saved.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), saved.revision);
    try std.testing.expectEqualStrings("saved-jail", saved.payload.?);
    const cursor = (try upgraded.sourceCursor(allocator, "retained", "file")).?;
    defer allocator.free(cursor);
    try std.testing.expectEqualStrings("saved-cursor", cursor);
    try std.testing.expectEqual(@as(i64, 1), try upgraded.pendingIntents());
    const shared = try upgraded.sharedSnapshot(allocator, "dns");
    defer shared.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), shared.revision);
}
