// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Embedded SQLite record/cursor transaction foundation.
//! A committed checkpoint is authoritative; external effects are queued, never executed here.
const std = @import("std");
const builtin = @import("builtin");
const native_time = @import("native_time.zig");
const time_policy = @import("source_time_policy.zig");
const native_record = @import("native_time_record.zig");
const detection = @import("native_detection_record.zig");
const retry = @import("native_retry.zig");
pub const latest_schema: i64 = 9;
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
    bind_int64: *const fn (*Statement, c_int, i64) callconv(.c) c_int,
    column_type: *const fn (*Statement, c_int) callconv(.c) c_int,
    column_blob: *const fn (*Statement, c_int) callconv(.c) ?*const anyopaque,
    column_bytes: *const fn (*Statement, c_int) callconv(.c) c_int,
    column_int64: *const fn (*Statement, c_int) callconv(.c) i64,
    changes: *const fn (*Db) callconv(.c) c_int,
    busy_timeout: *const fn (*Db, c_int) callconv(.c) c_int,
    extended_errcode: *const fn (*Db) callconv(.c) c_int,
    get_autocommit: *const fn (*Db) callconv(.c) c_int,
    limit: *const fn (*Db, c_int, c_int) callconv(.c) c_int,
};
const embedded_api: Api = blk: {
    var api: Api = undefined;
    for (std.meta.fields(Api)) |field| {
        const symbol = if (std.mem.eql(u8, field.name, "open")) "sqlite3_open_v2" else if (std.mem.eql(u8, field.name, "close")) "sqlite3_close_v2" else if (std.mem.eql(u8, field.name, "prepare")) "sqlite3_prepare_v2" else "sqlite3_" ++ field.name;
        @field(api, field.name) = @extern(field.type, .{ .name = symbol });
    }
    break :blk api;
};
pub const Error = retry.Error || error{ OpenFailed, UnsafePermissions, ForeignDatabase, UnsupportedSchema, DatabaseFailure, Busy, StorageFull, ReadOnly, StorageIo, CorruptDatabase, StorageLimit, Interrupted, AccessDenied, ReopenRequired, InvalidRecord, OccurrenceConflict, StaleCheckpoint, StaleSharedCheckpoint, InjectedFailure, OutOfMemory, ReceiptStorageRequired, InferenceStorageRequired, DetectionStorageRequired, ReceiptConflict, ReceiptRequired, ReceiptAlreadyCommitted, ReceiptLimit, RetryStorageRequired, RetryAdmissionRequired, RetryGenerationMismatch, RetryMigrationRequired, RetryCapacity, ReceiptClockReversed };

fn sqliteError(rc: c_int) Error {
    // Extended result codes retain their primary result in the low eight bits.
    return switch (rc & 0xff) {
        3, 23 => error.AccessDenied,
        5, 6 => error.Busy,
        7 => error.OutOfMemory,
        8 => error.ReadOnly,
        9 => error.Interrupted,
        10 => error.StorageIo,
        11, 26 => error.CorruptDatabase,
        13 => error.StorageFull,
        14 => error.OpenFailed,
        18 => error.StorageLimit,
        else => error.DatabaseFailure,
    };
}
pub const CommitStage = enum { after_record, after_checkpoint, after_shared_checkpoint, before_commit, before_receipt_commit, after_receipt_commit, after_receipt_delete, before_receipt_schema_commit, before_native_time_schema_commit, before_inference_schema_commit, before_detection_schema_commit, after_detection, before_clock_schema_commit, before_journal_detection_schema_commit, before_retry_schema_commit, after_retry_state, after_retry_decision };
/// Existing write admission limits also govern restored values. The SQLite row
/// ceiling allows the largest checkpoint plus its key and record encoding.
/// These are value/row bounds, not a process-wide memory or disk quota.
pub const Limits = struct {
    /// Staged aggregate ceiling, not a new public daemon configuration setting.
    pub const pending_receipts = 4096;
    pub const checkpoint_bytes = 16 * 1024 * 1024;
    pub const shared_bytes = 4 * 1024 * 1024;
    pub const cursor_bytes = 65536;
    pub const source_bytes = 16384;
    pub const sqlite_row_bytes = checkpoint_bytes + 128 * 1024;
};
pub const ReceiptIdentity = struct {
    jail: []const u8,
    source: []const u8,
    occurrence: []const u8,
    cursor: []const u8,
    raw_hash: [32]u8,
    generation: [32]u8,
};
pub const Receipt = struct { time: native_time.Timestamp, generation: [32]u8 };
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
    receipt: ?Receipt = null,
    native_time_outcome: ?time_policy.Result = null,
    native_detection: ?detection.Outcome = null,
    native_retry: ?retry.Admission = null,
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
    api: Api,
    db: *Db,
    /// Sticky numeric diagnostics for the most recent SQLite failure. Successful
    /// reads/cleanup do not erase its cause. SQL and record contents are not kept.
    last_error_code: ?c_int = null,
    rollback_error_code: ?c_int = null,
    reopen_required: bool = false,
    /// Tests inject an ordinary transaction error; no crash or external action is required.
    fail_at: ?CommitStage = null,
    schema_version: i64 = 2,
    receipt_limit: ?usize = null,
    runtime_limits: bool = false,
    runtime_path: ?[]const u8 = null,
    work_remaining: u32 = 1000,

    /// One daemon-wide SQLite heap ceiling and per-transaction VM allowance.
    /// These exclude Zig/OS/helper allocations and do not promise a disk quota.
    pub fn configureRuntimeLimits(self: *Store) Error!void {
        const hard_limit = @extern(*const fn (i64) callconv(.c) i64, .{ .name = "sqlite3_hard_heap_limit64" });
        const prior = hard_limit(-1);
        _ = hard_limit(if (prior > 0) @min(prior, 64 * 1024 * 1024) else 64 * 1024 * 1024);
        try self.exec("PRAGMA cache_size=-2048; PRAGMA wal_autocheckpoint=0;");
        const page_size = try self.integer("PRAGMA page_size;");
        if (page_size <= 0) return error.DatabaseFailure;
        const pages = @divTrunc(@as(i64, 256 * 1024 * 1024), page_size);
        if (try self.integer("PRAGMA page_count;") > pages) return error.StorageLimit;
        var sql: [80]u8 = undefined;
        const maximum = std.fmt.bufPrintZ(&sql, "PRAGMA max_page_count={d};", .{pages}) catch return error.StorageLimit;
        if (try self.integer(maximum) != pages) return error.StorageLimit;
        self.runtime_limits = true;
        const progress = @extern(*const fn (*Db, c_int, ?*const fn (?*anyopaque) callconv(.c) c_int, ?*anyopaque) callconv(.c) void, .{ .name = "sqlite3_progress_handler" });
        progress(self.db, 1000, workProgress, self);
    }
    fn workProgress(ctx: ?*anyopaque) callconv(.c) c_int {
        const self: *Store = @ptrCast(@alignCast(ctx.?));
        if (self.work_remaining == 0) return 1;
        self.work_remaining -= 1;
        return 0;
    }
    /// Worker-only checkpoint barrier. A busy/failed checkpoint stops subsequent
    /// ingestion; the WAL trigger allows transaction overshoot, not a hard quota.
    pub fn maintainWal(self: *Store, database_path: []const u8) !void {
        const path = try std.fmt.allocPrint(self.allocator, "{s}-wal", .{database_path});
        defer self.allocator.free(path);
        const stat = std.fs.cwd().statFile(path) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        if (stat.size < 16 * 1024 * 1024) return;
        var row = try self.statement("PRAGMA wal_checkpoint(TRUNCATE);");
        defer row.deinit();
        if (!try row.row()) return error.DatabaseFailure;
        if (try row.signed(0) != 0) return error.Busy;
    }

    pub fn open(allocator: std.mem.Allocator, path: []const u8) Error!Store {
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
        const api = embedded_api;
        const filename = allocator.dupeZ(u8, path) catch return error.OutOfMemory;
        defer allocator.free(filename);
        var db: ?*Db = null;
        const opened = api.open(filename, &db, 2 | 4 | 0x10000 | 0x01000000, null);
        if (opened != 0 or db == null) {
            if (db) |handle| _ = api.close(handle);
            return if (opened != 0) sqliteError(opened) else error.OpenFailed;
        }
        var self = Store{ .allocator = allocator, .api = api, .db = db.? };
        errdefer _ = self.api.close(self.db);
        _ = api.limit(self.db, 0, Limits.sqlite_row_bytes); // SQLITE_LIMIT_LENGTH
        if (api.limit(self.db, 0, -1) != Limits.sqlite_row_bytes) return error.StorageLimit;
        try self.check(api.busy_timeout(self.db, 1000));
        try self.exec("PRAGMA trusted_schema=OFF;");
        const application = try self.integer("PRAGMA application_id;");
        const schema = try self.integer("PRAGMA user_version;");
        if (application == 0) {
            if (schema != 0 or try self.integer("SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%';") != 0) return error.ForeignDatabase;
        } else if (application != 0x46325a31) return error.ForeignDatabase;
        if (schema < 0 or schema > latest_schema) return error.UnsupportedSchema;
        self.schema_version = @max(schema, 2);
        try self.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;");
        {
            var mode = try self.statement("PRAGMA journal_mode;");
            defer mode.deinit();
            if (!try mode.row() or !std.mem.eql(u8, try mode.bytes(0), "wal") or try self.integer("PRAGMA synchronous;") != 2)
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
        ) catch |err| {
            self.rollback();
            return err;
        };
        if (schema < 2) self.exec("PRAGMA user_version=2;") catch |err| {
            self.rollback();
            return err;
        };
        self.exec("COMMIT;") catch |err| {
            self.rollback();
            return err;
        };
        return self;
    }

    /// Explicit native admission; ordinary open does not upgrade a schema-2
    /// database to receipt storage. No worker checkpoint conversion is implied.
    /// The caller budgets one pending row per admitted source before activation.
    pub fn enableReceipts(self: *Store, maximum_pending: usize) Error!void {
        if (maximum_pending == 0 or maximum_pending > Limits.pending_receipts) return error.ReceiptLimit;
        try self.exec("BEGIN IMMEDIATE;");
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema == 2) {
            try self.exec(
                \\CREATE TABLE pending_receipts(jail TEXT NOT NULL,source TEXT NOT NULL,generation BLOB NOT NULL CHECK(length(generation)=32),occurrence TEXT NOT NULL,raw_hash BLOB NOT NULL CHECK(length(raw_hash)=32),cursor BLOB NOT NULL,receipt_us INTEGER NOT NULL CHECK(typeof(receipt_us)='integer'),PRIMARY KEY(jail,source));
                \\ALTER TABLE records ADD COLUMN receipt_us INTEGER CHECK(receipt_us IS NULL OR typeof(receipt_us)='integer');
                \\ALTER TABLE records ADD COLUMN receipt_generation BLOB CHECK((receipt_generation IS NULL AND receipt_us IS NULL) OR (receipt_generation IS NOT NULL AND length(receipt_generation)=32 AND receipt_us IS NOT NULL));
                \\PRAGMA user_version=3;
            );
        } else if (schema < 3 or schema > latest_schema) return error.UnsupportedSchema;
        if (try self.integer("SELECT count(*) FROM pending_receipts;") > maximum_pending) return error.ReceiptLimit;
        try self.fault(.before_receipt_schema_commit);
        try self.exec("COMMIT;");
        self.schema_version = @max(schema, 3);
        self.receipt_limit = maximum_pending;
    }

    fn validateReceiptIdentity(identity: ReceiptIdentity) Error!void {
        if (identity.jail.len == 0 or identity.jail.len > 4096 or identity.source.len == 0 or identity.source.len > Limits.source_bytes or
            identity.occurrence.len == 0 or identity.occurrence.len > 16384 or identity.cursor.len == 0 or identity.cursor.len > Limits.cursor_bytes)
            return error.InvalidRecord;
    }

    /// Admit native time rows only after receipt storage. A schema-3 database
    /// remains schema 3 until this native consumer is explicitly activated.
    pub fn enableNativeTime(self: *Store) Error!void {
        if (self.receipt_limit == null) return error.ReceiptStorageRequired;
        try self.exec("BEGIN IMMEDIATE;");
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema == 3) {
            try self.exec(
                \\ALTER TABLE records ADD COLUMN native_time_kind INTEGER CHECK(native_time_kind IS NULL OR (typeof(native_time_kind)='integer' AND native_time_kind BETWEEN 1 AND 11 AND receipt_us IS NOT NULL));
                \\ALTER TABLE records ADD COLUMN original_us INTEGER CHECK(original_us IS NULL OR (typeof(original_us)='integer' AND native_time_kind IS NOT NULL));
                \\ALTER TABLE records ADD COLUMN effective_us INTEGER CHECK(effective_us IS NULL OR (typeof(effective_us)='integer' AND native_time_kind BETWEEN 1 AND 6));
                \\PRAGMA user_version=4;
            );
        } else if (schema < 4 or schema > latest_schema) return error.UnsupportedSchema;
        try self.fault(.before_native_time_schema_commit);
        try self.exec("COMMIT;");
        self.schema_version = @max(schema, 4);
    }

    /// Explicit opt-in preserves inference provenance. Ordinary schema-4 opens
    /// and native-time admission never silently enable this migration.
    pub fn enableYearInference(self: *Store) Error!void {
        if (self.receipt_limit == null) return error.ReceiptStorageRequired;
        try self.exec("BEGIN IMMEDIATE;");
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema == 4) {
            try self.exec("ALTER TABLE records ADD COLUMN inferred_year INTEGER CHECK(inferred_year IS NULL OR (typeof(inferred_year)='integer' AND inferred_year BETWEEN 1 AND 9999 AND original_us IS NOT NULL AND native_time_kind IN (1,3,4,6,11))); PRAGMA user_version=5;");
        } else if (schema < 5 or schema > latest_schema) return error.UnsupportedSchema;
        try self.fault(.before_inference_schema_commit);
        try self.exec("COMMIT;");
        self.schema_version = @max(schema, 5);
    }

    /// Explicit native detection admission. A schema-4 upgrade adds inference
    /// provenance and detection rows in ONE transaction; failure leaves schema 4.
    /// Merely opening a prior store or enabling time never admits detection.
    pub fn enableDetection(self: *Store) Error!void {
        if (self.receipt_limit == null) return error.ReceiptStorageRequired;
        try self.exec("BEGIN IMMEDIATE;");
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 4 or schema > latest_schema) return error.UnsupportedSchema;
        if (schema == 4) try self.exec("ALTER TABLE records ADD COLUMN inferred_year INTEGER CHECK(inferred_year IS NULL OR (typeof(inferred_year)='integer' AND inferred_year BETWEEN 1 AND 9999 AND original_us IS NOT NULL AND native_time_kind IN (1,3,4,6,11)));");
        if (schema < 6) try self.exec(
            \\CREATE TABLE record_detections(
            \\jail TEXT NOT NULL,source TEXT NOT NULL,occurrence TEXT NOT NULL,
            \\version INTEGER NOT NULL CHECK(typeof(version)='integer' AND version=1),
            \\kind INTEGER NOT NULL CHECK(typeof(kind)='integer' AND kind BETWEEN 1 AND 6),
            \\generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=32),
            \\filter TEXT NOT NULL CHECK(typeof(filter)='text' AND length(filter) BETWEEN 1 AND 64),
            \\pattern TEXT CHECK(pattern IS NULL OR (typeof(pattern)='text' AND length(pattern) BETWEEN 1 AND 64)),
            \\pattern_index INTEGER CHECK(pattern_index IS NULL OR (typeof(pattern_index)='integer' AND pattern_index BETWEEN 0 AND 65535)),
            \\family INTEGER CHECK(family IS NULL OR (typeof(family)='integer' AND family IN (4,6))),
            \\subject BLOB CHECK(subject IS NULL OR (typeof(subject)='blob' AND ((family=4 AND length(subject)=4) OR (family=6 AND length(subject)=16)))),
            \\CHECK((kind<=3 AND pattern IS NULL AND pattern_index IS NULL AND family IS NULL AND subject IS NULL) OR (kind>=4 AND pattern IS NOT NULL AND pattern_index IS NOT NULL AND family IS NOT NULL AND subject IS NOT NULL)),
            \\PRIMARY KEY(jail,source,occurrence),FOREIGN KEY(jail,source,occurrence) REFERENCES records(jail,source,occurrence));
            \\PRAGMA user_version=6;
        );
        try self.fault(.before_detection_schema_commit);
        try self.exec("COMMIT;");
        self.schema_version = @max(schema, 6);
    }

    /// Explicit startup migration. The scan of old receipts happens once while
    /// no ingestion is admitted, never in the record-processing loop. The floor
    /// survives later ledger retention and does not replace any event timestamp.
    pub fn enableClockRecovery(self: *Store) Error!void {
        if (self.receipt_limit == null) return error.ReceiptStorageRequired;
        try self.exec("BEGIN IMMEDIATE;");
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 6 or schema > latest_schema) return error.UnsupportedSchema;
        if (schema == 6) {
            // Reject malformed prior types rather than letting MAX coerce them.
            if (try self.integer("SELECT EXISTS(SELECT 1 FROM records WHERE receipt_us IS NOT NULL AND typeof(receipt_us)!='integer') OR EXISTS(SELECT 1 FROM pending_receipts WHERE typeof(receipt_us)!='integer');") != 0) return error.DatabaseFailure;
            try self.exec(
                \\CREATE TABLE receipt_clock(id INTEGER PRIMARY KEY CHECK(id=1),floor_us INTEGER CHECK(floor_us IS NULL OR typeof(floor_us)='integer'));
                \\INSERT INTO receipt_clock SELECT 1,MAX(value) FROM (SELECT MAX(receipt_us) AS value FROM records UNION ALL SELECT MAX(receipt_us) FROM pending_receipts);
                \\PRAGMA user_version=7;
            );
        }
        _ = try self.readReceiptClock();
        try self.fault(.before_clock_schema_commit);
        try self.exec("COMMIT;");
        self.schema_version = @max(schema, 7);
    }

    /// Explicit schema-7 admission for typed journal-origin exclusions. Preserve
    /// all previous detection rows and the durable clock floor atomically.
    pub fn enableJournalDetection(self: *Store) Error!void {
        if (self.receipt_limit == null) return error.ReceiptStorageRequired;
        try self.exec("BEGIN IMMEDIATE;");
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 7 or schema > latest_schema) return error.UnsupportedSchema;
        _ = try self.readReceiptClock();
        if (schema == 7) {
            if (try self.integer("SELECT EXISTS(SELECT 1 FROM record_detections WHERE kind NOT BETWEEN 1 AND 6);") != 0) return error.DatabaseFailure;
            try self.exec(
                \\CREATE TABLE record_detections_v8(
                \\jail TEXT NOT NULL,source TEXT NOT NULL,occurrence TEXT NOT NULL,
                \\version INTEGER NOT NULL CHECK(typeof(version)='integer' AND version=1),
                \\kind INTEGER NOT NULL CHECK(typeof(kind)='integer' AND kind BETWEEN 1 AND 12),
                \\generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=32),
                \\filter TEXT NOT NULL CHECK(typeof(filter)='text' AND length(filter) BETWEEN 1 AND 64),
                \\pattern TEXT CHECK(pattern IS NULL OR (typeof(pattern)='text' AND length(pattern) BETWEEN 1 AND 64)),
                \\pattern_index INTEGER CHECK(pattern_index IS NULL OR (typeof(pattern_index)='integer' AND pattern_index BETWEEN 0 AND 65535)),
                \\family INTEGER CHECK(family IS NULL OR (typeof(family)='integer' AND family IN (4,6))),
                \\subject BLOB CHECK(subject IS NULL OR (typeof(subject)='blob' AND ((family=4 AND length(subject)=4) OR (family=6 AND length(subject)=16)))),
                \\CHECK(((kind<=3 OR kind>=7) AND pattern IS NULL AND pattern_index IS NULL AND family IS NULL AND subject IS NULL) OR (kind BETWEEN 4 AND 6 AND pattern IS NOT NULL AND pattern_index IS NOT NULL AND family IS NOT NULL AND subject IS NOT NULL)),
                \\PRIMARY KEY(jail,source,occurrence),FOREIGN KEY(jail,source,occurrence) REFERENCES records(jail,source,occurrence));
                \\INSERT INTO record_detections_v8 SELECT * FROM record_detections;
                \\DROP TABLE record_detections;
                \\ALTER TABLE record_detections_v8 RENAME TO record_detections;
                \\PRAGMA user_version=8;
            );
        }
        try self.fault(.before_journal_detection_schema_commit);
        try self.exec("COMMIT;");
        self.schema_version = @max(schema, 8);
    }

    /// Explicit admission; opening a schema-8 database does not upgrade it.
    pub fn enableRetry(self: *Store) Error!void {
        if (self.receipt_limit == null) return error.ReceiptStorageRequired;
        try self.exec("BEGIN IMMEDIATE;");
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 8 or schema > latest_schema) return error.UnsupportedSchema;
        if (schema == 8) try self.exec(
            \\CREATE TABLE retry_policies(jail TEXT PRIMARY KEY NOT NULL,generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=32),policy BLOB NOT NULL CHECK(typeof(policy)='blob' AND length(policy)=32));
            \\CREATE TABLE retry_clock(id INTEGER PRIMARY KEY CHECK(id=1),floor_us INTEGER CHECK(floor_us IS NULL OR typeof(floor_us)='integer'));
            \\INSERT INTO retry_clock VALUES(1,NULL);
            \\CREATE TABLE retry_states(jail TEXT NOT NULL,family INTEGER NOT NULL CHECK(typeof(family)='integer' AND family IN (4,6)),subject BLOB NOT NULL CHECK(typeof(subject)='blob' AND length(subject)=CASE family WHEN 4 THEN 4 ELSE 16 END),last_processed_us INTEGER NOT NULL CHECK(typeof(last_processed_us)='integer'),expiry_us INTEGER CHECK(expiry_us IS NULL OR typeof(expiry_us)='integer'),decisions INTEGER NOT NULL CHECK(typeof(decisions)='integer' AND decisions>=0),attempts BLOB NOT NULL CHECK(typeof(attempts)='blob' AND length(attempts)<=5120 AND length(attempts)%40=0),PRIMARY KEY(jail,family,subject),FOREIGN KEY(jail) REFERENCES retry_policies(jail));
            \\CREATE TABLE retry_decisions(jail TEXT NOT NULL,source TEXT NOT NULL,occurrence TEXT NOT NULL,family INTEGER NOT NULL CHECK(typeof(family)='integer' AND family IN (4,6)),subject BLOB NOT NULL CHECK(typeof(subject)='blob' AND length(subject)=CASE family WHEN 4 THEN 4 ELSE 16 END),decided_us INTEGER NOT NULL CHECK(typeof(decided_us)='integer'),expiry_us INTEGER NOT NULL CHECK(typeof(expiry_us)='integer' AND expiry_us>decided_us),ordinal INTEGER NOT NULL CHECK(typeof(ordinal)='integer' AND ordinal>0),enforce INTEGER NOT NULL CHECK(typeof(enforce)='integer' AND enforce IN (0,1)),PRIMARY KEY(jail,source,occurrence),FOREIGN KEY(jail,source,occurrence) REFERENCES records(jail,source,occurrence));
            \\PRAGMA user_version=9;
        );
        try self.fault(.before_retry_schema_commit);
        try self.exec("COMMIT;");
        self.schema_version = 9;
    }

    /// Register the entire jail before source activation. Enabling retry on an
    /// already acknowledged evidence-only jail requires a migration boundary;
    /// silently starting with an empty window would lose protection history.
    pub fn admitRetry(self: *Store, jail: []const u8, generation: [32]u8, policy: retry.Policy) Error!void {
        if (jail.len == 0 or jail.len > 64 or std.mem.indexOfScalar(u8, jail, 0) != null) return error.InvalidRecord;
        const encoded = try policy.encode();
        try self.exec("BEGIN IMMEDIATE;");
        errdefer self.rollback();
        if (try self.integer("PRAGMA user_version;") != 9) return error.RetryStorageRequired;
        if (try self.readRetryPolicy(jail)) |saved| {
            if (!std.mem.eql(u8, &saved.generation, &generation) or !std.mem.eql(u8, &try saved.policy.encode(), &encoded)) return error.RetryGenerationMismatch;
        } else {
            if (try self.revision(jail) != 0) return error.RetryMigrationRequired;
            var pending = try self.statement("SELECT 1 FROM pending_receipts WHERE jail=?1 LIMIT 1;");
            defer pending.deinit();
            try pending.text(1, jail);
            if (try pending.row()) return error.RetryMigrationRequired;
            var insert = try self.statement("INSERT INTO retry_policies VALUES(?1,?2,?3);");
            defer insert.deinit();
            try insert.text(1, jail);
            try insert.blob(2, &generation);
            try insert.blob(3, &encoded);
            try insert.done();
        }
        try self.exec("COMMIT;");
    }

    fn readRetryPolicy(self: *Store, jail: []const u8) Error!?retry.Admission {
        var row = try self.statement("SELECT generation,policy FROM retry_policies WHERE jail=?1;");
        defer row.deinit();
        try row.text(1, jail);
        if (!try row.row()) return null;
        if (self.api.column_type(row.ptr, 0) != 4 or self.api.column_type(row.ptr, 1) != 4) return error.InvalidRetryState;
        const generation = try row.boundedBytes(0, 32);
        if (generation.len != 32) return error.InvalidRetryState;
        var result = retry.Admission{ .generation = undefined, .policy = try retry.Policy.decode(try row.boundedBytes(1, retry.policy_bytes)) };
        @memcpy(&result.generation, generation);
        return result;
    }

    fn bindSubject(row: *Stmt, subject: *const detection.Subject) Error!void {
        subject.validate() catch return error.InvalidRetryState;
        if (subject.unenforceable()) return error.InvalidRetryState;
        switch (subject.*) {
            .v4 => {
                try row.int(2, 4);
                try row.blob(3, &subject.v4);
            },
            .v6 => {
                try row.int(2, 6);
                try row.blob(3, &subject.v6);
            },
        }
    }

    fn readRetryState(self: *Store, jail: []const u8, subject: detection.Subject, policy: retry.Policy) Error!?retry.State {
        var row = try self.statement("SELECT last_processed_us,expiry_us,decisions,attempts FROM retry_states WHERE jail=?1 AND family=?2 AND subject=?3;");
        defer row.deinit();
        try row.text(1, jail);
        try bindSubject(&row, &subject);
        if (!try row.row()) return null;
        const result = try self.decodeRetryState(&row, policy);
        if (result.last_processed_us > ((try self.readRetryClock()) orelse return error.InvalidRetryState)) return error.InvalidRetryState;
        return result;
    }

    fn decodeRetryState(self: *Store, row: *Stmt, policy: retry.Policy) Error!retry.State {
        const decisions = try row.signed(2);
        if (decisions < 0 or self.api.column_type(row.ptr, 3) != 4) return error.InvalidRetryState;
        var result = retry.State{ .last_processed_us = try row.signed(0), .expiry_us = try row.optionalSigned(1), .decisions = @intCast(decisions) };
        try result.decodeAttempts(try row.boundedBytes(3, retry.max_attempts * retry.attempt_bytes), policy);
        return result;
    }

    pub fn retryState(self: *Store, jail: []const u8, subject: detection.Subject) Error!?retry.State {
        try self.exec("BEGIN;");
        errdefer self.rollback();
        if (try self.integer("PRAGMA user_version;") != 9) return error.RetryStorageRequired;
        const admission = (try self.readRetryPolicy(jail)) orelse return error.RetryAdmissionRequired;
        const result = try self.readRetryState(jail, subject, admission.policy);
        try self.exec("COMMIT;");
        return result;
    }

    pub fn validateRuntimeOwners(self: *Store, names: []const []const u8) !void {
        if (names.len == 0 or names.len > 64) return error.InvalidRecord;
        try self.exec("BEGIN;");
        errdefer self.rollback();
        var row = try self.statement("SELECT jail FROM checkpoints UNION SELECT jail FROM pending_receipts UNION SELECT jail FROM source_cursors UNION SELECT jail FROM retry_policies;");
        defer row.deinit();
        var count: usize = 0;
        while (try row.row()) {
            count += 1;
            if (count > names.len or self.api.column_type(row.ptr, 0) != 3) return error.UnconfiguredStateOwner;
            const jail = try row.boundedBytes(0, 64);
            for (names) |name| {
                if (std.mem.eql(u8, jail, name)) break;
            } else return error.UnconfiguredStateOwner;
        }
        if (try self.integer("SELECT EXISTS(SELECT 1 FROM source_cursors c LEFT JOIN checkpoints p ON c.jail=p.jail LEFT JOIN records r ON c.jail=r.jail AND c.source=r.source AND c.occurrence=r.occurrence WHERE p.jail IS NULL OR r.jail IS NULL);") != 0) return error.InvalidRecord;
        try self.exec("COMMIT;");
    }

    pub const ActiveDecision = struct { subject: detection.Subject, expiry_us: i64, ordinal: u64 };
    pub const RetrySummary = struct { subjects: usize = 0, active: usize = 0, decisions: u64 = 0 };
    /// Detached, capacity-admitted status data. No read transaction survives the
    /// call, and expired decisions are excluded without rewriting their deadlines.
    pub fn retrySummary(self: *Store, jail: []const u8, now_us: i64, output: []ActiveDecision) Error!RetrySummary {
        try self.exec("BEGIN;");
        errdefer self.rollback();
        const admission = (try self.readRetryPolicy(jail)) orelse return error.RetryAdmissionRequired;
        if (output.len < admission.policy.max_subjects) return error.RetryCapacity;
        const floor = try self.readRetryClock();
        // The clock may move after source admission but before publication.
        // Use the shared recoverable clock error, including for empty owners.
        if (floor) |value| if (now_us < value) return error.ReceiptClockReversed;
        var row = try self.statement("SELECT last_processed_us,expiry_us,decisions,attempts,family,subject FROM retry_states WHERE jail=?1 ORDER BY family,subject;");
        defer row.deinit();
        try row.text(1, jail);
        var summary = RetrySummary{};
        while (try row.row()) {
            summary.subjects += 1;
            if (summary.subjects > admission.policy.max_subjects) return error.RetryCapacity;
            const state = try self.decodeRetryState(&row, admission.policy);
            if (state.last_processed_us > (floor orelse return error.InvalidRetryState)) return error.InvalidRetryState;
            const subject = try self.decodeRetrySubject(&row, 4, 5);
            summary.decisions = std.math.add(u64, summary.decisions, state.decisions) catch return error.InvalidRetryState;
            if (state.expiry_us) |expiry| if (expiry > now_us) {
                output[summary.active] = .{ .subject = subject, .expiry_us = expiry, .ordinal = state.decisions };
                summary.active += 1;
            };
        }
        try self.exec("COMMIT;");
        return summary;
    }

    /// Bounded startup validation, with no publication or callbacks while the
    /// SQLite snapshot is open. The coordinator serializes this with ingestion.
    pub fn validateRetry(self: *Store, jail: []const u8, generation: [32]u8, policy: retry.Policy) Error!void {
        try self.exec("BEGIN;");
        errdefer self.rollback();
        if (try self.integer("PRAGMA user_version;") != 9) return error.RetryStorageRequired;
        const admission = (try self.readRetryPolicy(jail)) orelse return error.RetryAdmissionRequired;
        if (!std.mem.eql(u8, &admission.generation, &generation) or !std.mem.eql(u8, &try admission.policy.encode(), &try policy.encode())) return error.RetryGenerationMismatch;
        const floor = try self.readRetryClock();
        var row = try self.statement("SELECT last_processed_us,expiry_us,decisions,attempts,family,subject FROM retry_states WHERE jail=?1;");
        defer row.deinit();
        try row.text(1, jail);
        var count: usize = 0;
        while (try row.row()) {
            count += 1;
            if (count > policy.max_subjects) return error.RetryCapacity;
            const state = try self.decodeRetryState(&row, policy);
            if (state.last_processed_us > (floor orelse return error.InvalidRetryState)) return error.InvalidRetryState;
            _ = try self.decodeRetrySubject(&row, 4, 5);
        }
        try self.exec("COMMIT;");
    }

    fn decodeRetrySubject(self: *Store, row: *Stmt, family_col: c_int, subject_col: c_int) Error!detection.Subject {
        if (self.api.column_type(row.ptr, subject_col) != 4) return error.InvalidRetryState;
        const bytes = try row.boundedBytes(subject_col, 16);
        const family = try row.signed(family_col);
        var subject: detection.Subject = undefined;
        if (family == 4 and bytes.len == 4) {
            subject = .{ .v4 = undefined };
            @memcpy(&subject.v4, bytes);
        } else if (family == 6 and bytes.len == 16) {
            subject = .{ .v6 = undefined };
            @memcpy(&subject.v6, bytes);
        } else return error.InvalidRetryState;
        subject.validate() catch return error.InvalidRetryState;
        if (subject.unenforceable()) return error.InvalidRetryState;
        return subject;
    }

    pub fn retryDecision(self: *Store, jail: []const u8, source: []const u8, occurrence: ?[]const u8) Error!?retry.Decision {
        var row = try self.statement(if (occurrence != null)
            "SELECT family,subject,decided_us,expiry_us,ordinal,enforce FROM retry_decisions WHERE jail=?1 AND source=?2 AND occurrence=?3;"
        else
            "SELECT d.family,d.subject,d.decided_us,d.expiry_us,d.ordinal,d.enforce FROM retry_decisions d JOIN source_cursors c USING(jail,source,occurrence) WHERE d.jail=?1 AND d.source=?2;");
        defer row.deinit();
        try row.text(1, jail);
        try row.text(2, source);
        if (occurrence) |value| try row.text(3, value);
        if (!try row.row()) return null;
        const ordinal = try row.signed(4);
        const enforce = try row.signed(5);
        const now = try row.signed(2);
        const expiry = try row.signed(3);
        if (ordinal <= 0 or enforce < 0 or enforce > 1 or expiry <= now) return error.InvalidRetryState;
        return .{ .subject = try self.decodeRetrySubject(&row, 0, 1), .decided_us = now, .expiry_us = expiry, .ordinal = @intCast(ordinal), .enforce = enforce == 1 };
    }

    fn commitRetry(self: *Store, record: Record, admission: retry.Admission) Error!void {
        if (admission.processing_us) |now| {
            if (try self.readRetryClock()) |floor| if (now < floor) return error.ReceiptClockReversed;
            var clock = try self.statement("UPDATE retry_clock SET floor_us=CASE WHEN floor_us IS NULL OR floor_us<?1 THEN ?1 ELSE floor_us END WHERE id=1;");
            defer clock.deinit();
            try clock.int(1, now);
            try clock.done();
            if (self.api.changes(self.db) != 1) return error.InvalidRetryState;
        }
        const detected = record.native_detection orelse return;
        if (detected.kind != .candidate) return;
        const outcome = record.native_time_outcome orelse return error.InvalidRecord;
        if (outcome != .eligible) return error.InvalidRecord;
        const now = admission.processing_us orelse return error.InvalidRecord;
        const subject = detected.subject orelse return error.InvalidRecord;
        const previous = try self.readRetryState(record.jail, subject, admission.policy);
        if (previous == null) {
            var count = try self.statement("SELECT count(*) FROM retry_states WHERE jail=?1;");
            defer count.deinit();
            try count.text(1, record.jail);
            if (!try count.row()) return error.DatabaseFailure;
            if (try count.signed(0) >= admission.policy.max_subjects) return error.RetryCapacity;
        }
        const next = try retry.advance(admission.policy, previous, subject, .{ .at_us = outcome.eligible.timestamp.us, .occurrence = retry.occurrenceKey(record.source, record.occurrence) }, now);
        var bytes: [retry.max_attempts * retry.attempt_bytes]u8 = undefined;
        var row = try self.statement("INSERT INTO retry_states VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(jail,family,subject) DO UPDATE SET last_processed_us=excluded.last_processed_us,expiry_us=excluded.expiry_us,decisions=excluded.decisions,attempts=excluded.attempts;");
        defer row.deinit();
        try row.text(1, record.jail);
        try bindSubject(&row, &subject);
        try row.int(4, next.state.last_processed_us);
        if (next.state.expiry_us) |expiry| try row.int(5, expiry);
        try row.int(6, @intCast(next.state.decisions));
        try row.blob(7, next.state.encodeAttempts(&bytes));
        try row.done();
        try self.fault(.after_retry_state);
        if (next.decision) |decision| {
            var decision_row = try self.statement("INSERT INTO retry_decisions(jail,family,subject,source,occurrence,decided_us,expiry_us,ordinal,enforce) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9);");
            defer decision_row.deinit();
            try decision_row.text(1, record.jail);
            try bindSubject(&decision_row, &subject);
            try decision_row.text(4, record.source);
            try decision_row.text(5, record.occurrence);
            try decision_row.int(6, decision.decided_us);
            try decision_row.int(7, decision.expiry_us);
            try decision_row.int(8, @intCast(decision.ordinal));
            try decision_row.int(9, @intFromBool(decision.enforce));
            try decision_row.done();
            try self.fault(.after_retry_decision);
        }
    }

    /// Null is an empty admitted store, not a missing/corrupt singleton. The
    /// signed floor is the greatest durably accepted receipt across all owners.
    pub fn receiptClock(self: *Store) Error!?native_time.Timestamp {
        try self.exec("BEGIN;");
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 7 or schema > latest_schema) return error.UnsupportedSchema;
        const value = try self.readReceiptClock();
        try self.exec("COMMIT;");
        self.schema_version = schema;
        return value;
    }
    fn readRetryClock(self: *Store) Error!?i64 {
        var row = try self.statement("SELECT id,floor_us FROM retry_clock ORDER BY id;");
        defer row.deinit();
        if (!try row.row() or try row.signed(0) != 1) return error.InvalidRetryState;
        const floor = try row.optionalSigned(1);
        if (try row.row()) return error.InvalidRetryState;
        return floor;
    }
    /// Retry decisions also use processing time. Preserve its committed floor
    /// separately from first-observation receipts, and wait for both on recovery.
    pub fn admissionClock(self: *Store) Error!?native_time.Timestamp {
        try self.exec("BEGIN;");
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 7 or schema > latest_schema) return error.UnsupportedSchema;
        var value = try self.readReceiptClock();
        if (schema >= 9) if (try self.readRetryClock()) |floor| {
            value = .{ .us = if (value) |receipt| @max(receipt.us, floor) else floor };
        };
        try self.exec("COMMIT;");
        return value;
    }
    fn readReceiptClock(self: *Store) Error!?native_time.Timestamp {
        var row = try self.statement("SELECT id,floor_us FROM receipt_clock ORDER BY id;");
        defer row.deinit();
        if (!try row.row() or try row.signed(0) != 1) return error.DatabaseFailure;
        const floor = try row.optionalSigned(1);
        if (try row.row()) return error.DatabaseFailure;
        return if (floor) |value| .{ .us = value } else null;
    }

    /// Detached, validated result paired with its native time in one short read
    /// snapshot. Null occurrence addresses the current committed source cursor.
    pub fn nativeDetection(self: *Store, jail: []const u8, source: []const u8, occurrence: ?[]const u8) Error!?detection.Outcome {
        try self.exec("BEGIN;");
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema > latest_schema) return error.UnsupportedSchema;
        if (schema < 6) return error.DetectionStorageRequired;
        self.schema_version = schema;
        const value = try self.readDetection(jail, source, occurrence);
        try self.exec("COMMIT;");
        return value;
    }
    fn readDetection(self: *Store, jail: []const u8, source: []const u8, occurrence: ?[]const u8) Error!?detection.Outcome {
        var row = try self.statement("SELECT version,kind,generation,filter,pattern,pattern_index,family,subject FROM record_detections WHERE jail=?1 AND source=?2 AND occurrence=COALESCE(?3,(SELECT occurrence FROM source_cursors WHERE jail=?1 AND source=?2));");
        defer row.deinit();
        try row.text(1, jail);
        try row.text(2, source);
        if (occurrence) |value| try row.text(3, value) else try self.check(self.api.bind_null(row.ptr, 3));
        if (!try row.row()) return null;
        if (try row.signed(0) != detection.version or self.api.column_type(row.ptr, 2) != 4 or self.api.column_type(row.ptr, 3) != 3) return error.DatabaseFailure;
        const generation = try row.boundedBytes(2, 32);
        if (generation.len != 32) return error.DatabaseFailure;
        var result = detection.Outcome{
            .kind = std.meta.intToEnum(detection.Kind, try row.signed(1)) catch return error.DatabaseFailure,
            .generation = generation[0..32].*,
            .filter = detection.Name.init(try row.boundedBytes(3, 64)) catch return error.DatabaseFailure,
        };
        if (self.schema_version < 8 and @intFromEnum(result.kind) >= 7) return error.DatabaseFailure;
        if (self.api.column_type(row.ptr, 4) != 5) {
            if (self.api.column_type(row.ptr, 4) != 3) return error.DatabaseFailure;
            result.pattern = detection.Name.init(try row.boundedBytes(4, 64)) catch return error.DatabaseFailure;
        }
        if (try row.optionalSigned(5)) |index| result.pattern_index = std.math.cast(u16, index) orelse return error.DatabaseFailure;
        if (try row.optionalSigned(6)) |family| {
            if (self.api.column_type(row.ptr, 7) != 4) return error.DatabaseFailure;
            const address = try row.boundedBytes(7, 16);
            result.subject = switch (family) {
                4 => if (address.len == 4) .{ .v4 = address[0..4].* } else return error.DatabaseFailure,
                6 => if (address.len == 16) .{ .v6 = address[0..16].* } else return error.DatabaseFailure,
                else => return error.DatabaseFailure,
            };
        } else if (self.api.column_type(row.ptr, 7) != 5) return error.DatabaseFailure;
        const time = (try self.readNativeTime(jail, source, occurrence)) orelse return error.DatabaseFailure;
        result.validate(time) catch return error.DatabaseFailure;
        return result;
    }

    /// Null occurrence reads the latest committed source position, including a
    /// baseline (which has no native time). No long-lived reader escapes here.
    pub fn nativeTime(self: *Store, jail: []const u8, source: []const u8, occurrence: ?[]const u8) Error!?time_policy.Result {
        // Pin schema and row to one read snapshot. Another connection may have
        // upgraded since open; stale schema-4 knowledge must not erase provenance.
        try self.exec("BEGIN;");
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 4 or schema > latest_schema) return error.UnsupportedSchema;
        self.schema_version = schema;
        const outcome = try self.readNativeTime(jail, source, occurrence);
        try self.exec("COMMIT;");
        return outcome;
    }

    fn readNativeTime(self: *Store, jail: []const u8, source: []const u8, occurrence: ?[]const u8) Error!?time_policy.Result {
        var row = try self.statement(if (self.schema_version >= 5)
            "SELECT native_time_kind,original_us,effective_us,receipt_us,disposition,inferred_year FROM records WHERE jail=?1 AND source=?2 AND occurrence=COALESCE(?3,(SELECT occurrence FROM source_cursors WHERE jail=?1 AND source=?2));"
        else
            "SELECT native_time_kind,original_us,effective_us,receipt_us,disposition,NULL FROM records WHERE jail=?1 AND source=?2 AND occurrence=COALESCE(?3,(SELECT occurrence FROM source_cursors WHERE jail=?1 AND source=?2));");
        defer row.deinit();
        try row.text(1, jail);
        try row.text(2, source);
        if (occurrence) |value| try row.text(3, value) else try self.check(self.api.bind_null(row.ptr, 3));
        if (!try row.row()) return null;
        if (self.api.column_type(row.ptr, 0) == 5) {
            if (self.api.column_type(row.ptr, 1) != 5 or self.api.column_type(row.ptr, 2) != 5 or self.api.column_type(row.ptr, 5) != 5) return error.DatabaseFailure;
            return null;
        }
        const kind = std.meta.intToEnum(native_record.Kind, try row.signed(0)) catch return error.DatabaseFailure;
        const inferred_year = if (try row.optionalSigned(5)) |year| std.math.cast(u16, year) orelse return error.DatabaseFailure else null;
        const stored = native_record.Stored{ .kind = kind, .original_us = try row.optionalSigned(1), .effective_us = try row.optionalSigned(2), .inferred_year = inferred_year };
        const outcome = stored.outcome(.{ .us = try row.signed(3) }) catch return error.DatabaseFailure;
        if (!std.mem.eql(u8, outcome.disposition(), try row.boundedBytes(4, 64))) return error.DatabaseFailure;
        return outcome;
    }

    /// Match the entire occurrence binding before returning a saved time. A
    /// different occurrence cannot evict an unresolved record of this source.
    pub fn pendingReceipt(self: *Store, identity: ReceiptIdentity) Error!?native_time.Timestamp {
        try validateReceiptIdentity(identity);
        if (self.schema_version < 3) return error.ReceiptStorageRequired;
        var row = try self.statement("SELECT generation,occurrence,raw_hash,cursor,receipt_us FROM pending_receipts WHERE jail=?1 AND source=?2;");
        defer row.deinit();
        try row.text(1, identity.jail);
        try row.text(2, identity.source);
        if (!try row.row()) return null;
        if (!std.mem.eql(u8, try row.boundedBytes(0, 32), &identity.generation) or
            !std.mem.eql(u8, try row.boundedBytes(1, 16384), identity.occurrence) or
            !std.mem.eql(u8, try row.boundedBytes(2, 32), &identity.raw_hash) or
            !std.mem.eql(u8, try row.boundedBytes(3, Limits.cursor_bytes), identity.cursor)) return error.ReceiptConflict;
        return .{ .us = try row.signed(4) };
    }

    pub fn pendingReceiptCount(self: *Store) Error!usize {
        if (self.schema_version < 3) return error.ReceiptStorageRequired;
        return std.math.cast(usize, try self.integer("SELECT count(*) FROM pending_receipts;")) orelse error.DatabaseFailure;
    }

    /// Read exact native receipt provenance for a committed occurrence. This
    /// also prevents a duplicate retry from silently changing its generation.
    pub fn committedReceipt(self: *Store, identity: ReceiptIdentity) Error!?native_time.Timestamp {
        try validateReceiptIdentity(identity);
        if (self.schema_version < 3) return error.ReceiptStorageRequired;
        var row = try self.statement("SELECT raw_hash,cursor,receipt_generation,receipt_us FROM records WHERE jail=?1 AND source=?2 AND occurrence=?3;");
        defer row.deinit();
        try row.text(1, identity.jail);
        try row.text(2, identity.source);
        try row.text(3, identity.occurrence);
        if (!try row.row()) return null;
        if (!std.mem.eql(u8, try row.boundedBytes(0, 32), &identity.raw_hash) or
            !std.mem.eql(u8, try row.boundedBytes(1, Limits.cursor_bytes), identity.cursor) or
            !std.mem.eql(u8, try row.boundedBytes(2, 32), &identity.generation)) return error.ReceiptConflict;
        return .{ .us = try row.signed(3) };
    }

    pub fn validateReceiptGeneration(self: *Store, jail: []const u8, generation: [32]u8) Error!void {
        if (self.receipt_limit == null) return error.ReceiptStorageRequired;
        var row = try self.statement("SELECT 1 FROM pending_receipts WHERE jail=?1 AND (typeof(generation)!='blob' OR generation!=?2) LIMIT 1;");
        defer row.deinit();
        try row.text(1, jail);
        try row.blob(2, &generation);
        if (try row.row()) return error.ReceiptConflict;
    }

    /// Recovery must account for every pending source, including ones absent
    /// from current discovery. Each bounded row is detached and its statement
    /// finalized before invoking source IO. Callbacks must not mutate this store;
    /// another connection changing the snapshot refuses the entire traversal.
    pub fn visitPendingReceipts(self: *Store, callback: *const fn (ReceiptIdentity, native_time.Timestamp, ?*anyopaque) anyerror!void, context: ?*anyopaque) !void {
        const maximum = self.receipt_limit orelse return error.ReceiptStorageRequired;
        const initial_version = try self.integer("PRAGMA data_version;");
        if (try self.pendingReceiptCount() == 0) {
            if (try self.integer("PRAGMA data_version;") != initial_version) return error.StaleCheckpoint;
            return;
        }
        // One page, well below the approved 1-MiB detached-read allowance. The
        // separate key buffer survives reuse of the row during the next query.
        const buffer = try self.allocator.alloc(u8, 4096 + Limits.source_bytes + 16384 + Limits.cursor_bytes);
        defer self.allocator.free(buffer);
        const key = try self.allocator.alloc(u8, 4096 + Limits.source_bytes);
        defer self.allocator.free(key);
        var jail_len: usize = 0;
        var source_len: usize = 0;
        var count: usize = 0;
        while (true) {
            var identity: ReceiptIdentity = undefined;
            var stamp: native_time.Timestamp = undefined;
            const found = blk: {
                var row = try self.statement(if (count == 0)
                    "SELECT jail,source,occurrence,cursor,raw_hash,generation,receipt_us FROM pending_receipts ORDER BY jail,source LIMIT 1;"
                else
                    "SELECT jail,source,occurrence,cursor,raw_hash,generation,receipt_us FROM pending_receipts WHERE (jail,source)>(?1,?2) ORDER BY jail,source LIMIT 1;");
                defer row.deinit();
                if (count != 0) {
                    try row.text(1, key[0..jail_len]);
                    try row.text(2, key[jail_len..][0..source_len]);
                }
                if (!try row.row()) break :blk false;
                if (count >= maximum) return error.ReceiptLimit;
                inline for (0..6) |column| if (self.api.column_type(row.ptr, column) != (if (column < 3) @as(c_int, 3) else 4)) return error.DatabaseFailure;
                var used: usize = 0;
                var values: [4][]const u8 = undefined;
                inline for (.{ 4096, Limits.source_bytes, 16384, Limits.cursor_bytes }, 0..) |limit, column| {
                    const bytes = try row.boundedBytes(column, limit);
                    @memcpy(buffer[used..][0..bytes.len], bytes);
                    values[column] = buffer[used..][0..bytes.len];
                    used += bytes.len;
                }
                const hash = try row.boundedBytes(4, 32);
                const generation = try row.boundedBytes(5, 32);
                if (hash.len != 32 or generation.len != 32) return error.DatabaseFailure;
                identity = .{ .jail = values[0], .source = values[1], .occurrence = values[2], .cursor = values[3], .raw_hash = hash[0..32].*, .generation = generation[0..32].* };
                try validateReceiptIdentity(identity);
                stamp = .{ .us = try row.signed(6) };
                break :blk true;
            };
            if (try self.integer("PRAGMA data_version;") != initial_version) return error.StaleCheckpoint;
            if (!found) return;
            try callback(identity, stamp, context);
            if (try self.integer("PRAGMA data_version;") != initial_version) return error.StaleCheckpoint;
            jail_len = identity.jail.len;
            source_len = identity.source.len;
            @memcpy(key[0..jail_len], identity.jail);
            @memcpy(key[jail_len..][0..source_len], identity.source);
            count += 1;
        }
    }

    /// Observation commits no cursor, outcome, checkpoint or effect. Retries
    /// read the saved receipt even when an earlier COMMIT's result was uncertain.
    pub fn beginReceipt(self: *Store, identity: ReceiptIdentity, proposed: native_time.Timestamp, expected_revision: u64) Error!native_time.Timestamp {
        try validateReceiptIdentity(identity);
        const maximum = self.receipt_limit orelse return error.ReceiptStorageRequired;
        try self.exec("BEGIN IMMEDIATE;");
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 3 or schema > latest_schema) return error.UnsupportedSchema;
        self.schema_version = schema;
        if (schema >= 7) _ = try self.readReceiptClock();
        if (expected_revision >= std.math.maxInt(i64) or try self.revision(identity.jail) != expected_revision) return error.StaleCheckpoint;
        try self.validateReceiptGeneration(identity.jail, identity.generation);
        if (try self.hasRecord(identity.jail, identity.source, identity.occurrence, identity.raw_hash, identity.cursor)) return error.ReceiptAlreadyCommitted;
        if (try self.pendingReceipt(identity)) |saved| {
            try self.exec("COMMIT;");
            return saved;
        }
        if (try self.pendingReceiptCount() >= maximum) return error.ReceiptLimit;
        {
            var row = try self.statement("INSERT INTO pending_receipts VALUES(?1,?2,?3,?4,?5,?6,?7);");
            defer row.deinit();
            try row.text(1, identity.jail);
            try row.text(2, identity.source);
            try row.blob(3, &identity.generation);
            try row.text(4, identity.occurrence);
            try row.blob(5, &identity.raw_hash);
            try row.blob(6, identity.cursor);
            try row.int(7, proposed.us);
            try row.done();
        }
        if (schema >= 7) {
            var clock = try self.statement("UPDATE receipt_clock SET floor_us=CASE WHEN floor_us IS NULL OR floor_us<?1 THEN ?1 ELSE floor_us END WHERE id=1;");
            defer clock.deinit();
            try clock.int(1, proposed.us);
            try clock.done();
        }
        self.schema_version = schema;
        try self.fault(.before_receipt_commit);
        try self.exec("COMMIT;");
        try self.fault(.after_receipt_commit);
        return proposed;
    }

    pub fn close(self: *Store) void {
        _ = self.api.close(self.db);
        self.* = undefined;
    }
    fn check(self: *Store, rc: c_int) Error!void {
        if (rc == 0) return;
        self.last_error_code = self.failureCode(rc);
        return sqliteError(rc);
    }
    fn failureCode(self: *Store, rc: c_int) c_int {
        const extended = self.api.extended_errcode(self.db);
        return if (extended & 0xff == rc & 0xff) extended else rc;
    }
    fn usable(self: *Store) Error!void {
        if (self.reopen_required) return error.ReopenRequired;
    }
    fn rollback(self: *Store) void {
        self.work_remaining = 1000;
        // FULL/IOERR/NOMEM can already have rolled back the whole transaction.
        if (self.api.get_autocommit(self.db) != 0) return;
        const rc = self.api.exec(self.db, "ROLLBACK;", null, null, null);
        if (rc != 0) self.rollback_error_code = self.failureCode(rc);
        // Never expose this connection's uncommitted state after failed cleanup.
        if (rc != 0 or self.api.get_autocommit(self.db) == 0) self.reopen_required = true;
    }
    fn exec(self: *Store, sql: [:0]const u8) Error!void {
        try self.usable();
        if (self.runtime_limits and self.api.get_autocommit(self.db) != 0) self.work_remaining = 1000;
        try self.check(self.api.exec(self.db, sql, null, null, null));
    }
    fn statement(self: *Store, sql: [:0]const u8) Error!Stmt {
        try self.usable();
        if (self.runtime_limits and self.api.get_autocommit(self.db) != 0) self.work_remaining = 1000;
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
        try self.usable();
        if (record.jail.len == 0 or record.source.len == 0 or record.occurrence.len == 0 or record.cursor.len == 0 or
            record.jail.len > 4096 or record.source.len > Limits.source_bytes or record.occurrence.len > 16384 or record.cursor.len > Limits.cursor_bytes or
            record.checkpoint.len > Limits.checkpoint_bytes or record.disposition.len > 64) return error.InvalidRecord;
        if (record.source_path) |path| if (path.len > Limits.source_bytes or std.mem.indexOfScalar(u8, path, 0) != null) return error.InvalidRecord;
        if (record.event_time) |time| if (!std.math.isFinite(time)) return error.InvalidRecord;
        if (record.action_intent) |intent| if (intent.len > 1024 * 1024) return error.InvalidRecord;
        if (record.shared_state) |shared| {
            if (shared.name.len == 0 or shared.name.len > 4096 or std.mem.indexOfScalar(u8, shared.name, 0) != null) return error.InvalidRecord;
            if (shared.payload) |payload| if (payload.len > Limits.shared_bytes) return error.InvalidRecord;
        }
        try self.exec("BEGIN IMMEDIATE;");
        errdefer self.rollback();
        // Never let an old adapter or a baseline skip unresolved native input.
        // Another connection may have activated native storage since open.
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 2 or schema > latest_schema) return error.UnsupportedSchema;
        self.schema_version = schema;
        if (schema >= 9) {
            const registered = try self.readRetryPolicy(record.jail);
            if ((registered != null) != (record.native_retry != null)) return error.RetryAdmissionRequired;
            if (registered) |saved| {
                const supplied = record.native_retry.?;
                if (!std.mem.eql(u8, &saved.generation, &supplied.generation) or !std.mem.eql(u8, &try saved.policy.encode(), &try supplied.policy.encode())) return error.RetryGenerationMismatch;
                if (record.receipt) |receipt| {
                    if (!std.mem.eql(u8, &receipt.generation, &supplied.generation) or record.native_detection == null or
                        (supplied.processing_us orelse return error.InvalidRecord) < receipt.time.us) return error.InvalidRecord;
                } else if (record.native_detection != null or supplied.processing_us != null) return error.InvalidRecord;
            }
        } else if (record.native_retry != null) return error.RetryStorageRequired;
        const native_values: ?native_record.Stored = if (record.native_time_outcome) |outcome| blk: {
            if (schema < 4 or record.event_time != null) return error.InvalidRecord;
            const receipt = record.receipt orelse return error.ReceiptRequired;
            if (!std.mem.eql(u8, outcome.disposition(), record.disposition)) return error.InvalidRecord;
            const values = native_record.Stored.fromOutcome(outcome, receipt.time) catch return error.InvalidRecord;
            if (values.inferred_year != null and schema < 5) return error.InferenceStorageRequired;
            break :blk values;
        } else null;
        if (record.native_detection) |value| {
            if (schema < 6) return error.DetectionStorageRequired;
            if (schema < 8 and @intFromEnum(value.kind) >= 7) return error.DetectionStorageRequired;
            const outcome = record.native_time_outcome orelse return error.InvalidRecord;
            value.validate(outcome) catch return error.InvalidRecord;
        }
        if (self.schema_version >= 3) {
            if (record.receipt) |receipt| {
                const saved = try self.pendingReceipt(.{ .jail = record.jail, .source = record.source, .occurrence = record.occurrence, .cursor = record.cursor, .raw_hash = record.raw_hash, .generation = receipt.generation });
                if (saved) |value| {
                    if (value.us != receipt.time.us) return error.ReceiptConflict;
                } else {
                    const committed = (try self.committedReceipt(.{ .jail = record.jail, .source = record.source, .occurrence = record.occurrence, .cursor = record.cursor, .raw_hash = record.raw_hash, .generation = receipt.generation })) orelse return error.ReceiptRequired;
                    if (committed.us != receipt.time.us) return error.ReceiptConflict;
                }
            } else {
                var pending = try self.statement("SELECT 1 FROM pending_receipts WHERE jail=?1 AND source=?2;");
                defer pending.deinit();
                try pending.text(1, record.jail);
                try pending.text(2, record.source);
                if (try pending.row()) return error.ReceiptRequired;
            }
        } else if (record.receipt != null) return error.ReceiptStorageRequired;
        {
            var prior = try self.statement("SELECT raw_hash,cursor FROM records WHERE jail=?1 AND source=?2 AND occurrence=?3;");
            defer prior.deinit();
            try prior.text(1, record.jail);
            try prior.text(2, record.source);
            try prior.text(3, record.occurrence);
            if (try prior.row()) {
                if (!std.mem.eql(u8, try prior.boundedBytes(0, 32), &record.raw_hash) or !std.mem.eql(u8, try prior.boundedBytes(1, Limits.cursor_bytes), record.cursor)) return error.OccurrenceConflict;
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
            var stmt = try self.statement(if (record.receipt != null)
                "INSERT INTO records(jail,source,occurrence,raw_hash,cursor,event_time,timestamp_us,disposition,receipt_us,receipt_generation) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10);"
            else
                "INSERT INTO records(jail,source,occurrence,raw_hash,cursor,event_time,timestamp_us,disposition) VALUES(?1,?2,?3,?4,?5,?6,?7,?8);");
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
            if (record.receipt) |receipt| {
                try stmt.int(9, receipt.time.us);
                try stmt.blob(10, &receipt.generation);
            }
            try stmt.done();
        }
        try self.fault(.after_record);
        if (native_values) |values| {
            var row = try self.statement(if (schema >= 5)
                "UPDATE records SET native_time_kind=?4,original_us=?5,effective_us=?6,inferred_year=?7 WHERE jail=?1 AND source=?2 AND occurrence=?3;"
            else
                "UPDATE records SET native_time_kind=?4,original_us=?5,effective_us=?6 WHERE jail=?1 AND source=?2 AND occurrence=?3;");
            defer row.deinit();
            try row.text(1, record.jail);
            try row.text(2, record.source);
            try row.text(3, record.occurrence);
            try row.int(4, @intFromEnum(values.kind));
            if (values.original_us) |value| try row.int(5, value) else try self.check(self.api.bind_null(row.ptr, 5));
            if (values.effective_us) |value| try row.int(6, value) else try self.check(self.api.bind_null(row.ptr, 6));
            if (schema >= 5) {
                if (values.inferred_year) |year| try row.int(7, year) else try self.check(self.api.bind_null(row.ptr, 7));
            }
            try row.done();
        }
        if (record.native_detection) |value| {
            var row = try self.statement("INSERT INTO record_detections(jail,source,occurrence,version,kind,generation,filter,pattern,pattern_index,family,subject) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11);");
            defer row.deinit();
            try row.text(1, record.jail);
            try row.text(2, record.source);
            try row.text(3, record.occurrence);
            try row.int(4, detection.version);
            try row.int(5, @intFromEnum(value.kind));
            try row.blob(6, &value.generation);
            try row.text(7, value.filter.slice());
            if (value.pattern != null) try row.text(8, value.pattern.?.slice());
            if (value.pattern_index) |index| try row.int(9, index);
            var subject_bytes: [16]u8 = undefined;
            if (value.subject) |subject| switch (subject) {
                .v4 => |address| {
                    @memcpy(subject_bytes[0..4], &address);
                    try row.int(10, 4);
                    try row.blob(11, subject_bytes[0..4]);
                },
                .v6 => |address| {
                    @memcpy(&subject_bytes, &address);
                    try row.int(10, 6);
                    try row.blob(11, &subject_bytes);
                },
            };
            try row.done();
            try self.fault(.after_detection);
        }
        if (record.native_retry) |admission| try self.commitRetry(record, admission);
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
        if (record.receipt != null) {
            var pending = try self.statement("DELETE FROM pending_receipts WHERE jail=?1 AND source=?2;");
            defer pending.deinit();
            try pending.text(1, record.jail);
            try pending.text(2, record.source);
            try pending.done();
            if (self.api.changes(self.db) != 1) return error.ReceiptRequired;
            try self.fault(.after_receipt_delete);
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
        return allocator.dupe(u8, try stmt.boundedBytes(0, Limits.cursor_bytes)) catch error.OutOfMemory;
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
        return .{ .payload = allocator.dupe(u8, try stmt.boundedBytes(0, Limits.checkpoint_bytes)) catch return error.OutOfMemory, .revision = @intCast(saved_revision) };
    }
    pub fn sharedSnapshot(self: *Store, allocator: std.mem.Allocator, name: []const u8) Error!Snapshot {
        var stmt = try self.statement("SELECT payload,revision FROM shared_checkpoints WHERE name=?1;");
        defer stmt.deinit();
        try stmt.text(1, name);
        if (!try stmt.row()) return .{ .payload = null, .revision = 0 };
        const saved_revision = self.api.column_int64(stmt.ptr, 1);
        if (saved_revision <= 0) return error.DatabaseFailure;
        return .{ .payload = allocator.dupe(u8, try stmt.boundedBytes(0, Limits.shared_bytes)) catch return error.OutOfMemory, .revision = @intCast(saved_revision) };
    }
    pub fn checkpoint(self: *Store, allocator: std.mem.Allocator, jail: []const u8) Error!?[]u8 {
        var stmt = try self.statement("SELECT payload FROM checkpoints WHERE jail=?1;");
        defer stmt.deinit();
        try stmt.text(1, jail);
        if (!try stmt.row()) return null;
        return allocator.dupe(u8, try stmt.boundedBytes(0, Limits.checkpoint_bytes)) catch error.OutOfMemory;
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
        while (try stmt.row()) try callback(try stmt.boundedBytes(0, Limits.source_bytes), try stmt.boundedBytes(1, Limits.source_bytes), try stmt.boundedBytes(2, Limits.cursor_bytes), context);
    }

    pub fn hasRecord(self: *Store, jail: []const u8, source: []const u8, occurrence: []const u8, raw_hash: [32]u8, cursor: []const u8) Error!bool {
        var stmt = try self.statement("SELECT raw_hash,cursor FROM records WHERE jail=?1 AND source=?2 AND occurrence=?3;");
        defer stmt.deinit();
        try stmt.text(1, jail);
        try stmt.text(2, source);
        try stmt.text(3, occurrence);
        if (!try stmt.row()) return false;
        if (!std.mem.eql(u8, try stmt.boundedBytes(0, 32), &raw_hash) or !std.mem.eql(u8, try stmt.boundedBytes(1, Limits.cursor_bytes), cursor)) return error.OccurrenceConflict;
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
    fn int(self: *Stmt, index: c_int, value: i64) Error!void {
        try self.store.check(self.store.api.bind_int64(self.ptr, index, value));
    }
    fn signed(self: *Stmt, column: c_int) Error!i64 {
        if (self.store.api.column_type(self.ptr, column) != 1) return error.DatabaseFailure;
        return self.store.api.column_int64(self.ptr, column);
    }
    fn optionalSigned(self: *Stmt, column: c_int) Error!?i64 {
        if (self.store.api.column_type(self.ptr, column) == 5) return null;
        return try self.signed(column);
    }
    fn row(self: *Stmt) Error!bool {
        try self.store.usable();
        const rc = self.store.api.step(self.ptr);
        return switch (rc) {
            100 => true,
            101 => false,
            else => blk: {
                try self.store.check(rc);
                break :blk error.DatabaseFailure;
            },
        };
    }
    fn done(self: *Stmt) Error!void {
        if (try self.row()) return error.DatabaseFailure;
    }
    fn boundedBytes(self: *Stmt, column: c_int, maximum: usize) Error![]const u8 {
        const value = try self.bytes(column);
        if (value.len > maximum) return error.StorageLimit;
        return value;
    }
    fn bytes(self: *Stmt, column: c_int) Error![]const u8 {
        // Fetch the blob before its byte count so any conversion cannot invalidate
        // the returned pointer. A failed conversion must not look like empty state.
        const data = self.store.api.column_blob(self.ptr, column);
        if (data == null) {
            if (self.store.api.extended_errcode(self.store.db) == 7) try self.store.check(7);
            return "";
        }
        const length = self.store.api.column_bytes(self.ptr, column);
        if (length <= 0) return "";
        const ptr: [*]const u8 = @ptrCast(data.?);
        return ptr[0..@intCast(length)];
    }
};

test "record store: extended SQLite failures retain distinct operational causes" {
    const cases = .{
        .{ 5 | (2 << 8), error.Busy },
        .{ 6 | (1 << 8), error.Busy },
        .{ 7, error.OutOfMemory },
        .{ 8 | (6 << 8), error.ReadOnly },
        .{ 9, error.Interrupted },
        .{ 10 | (4 << 8), error.StorageIo },
        .{ 11 | (3 << 8), error.CorruptDatabase },
        .{ 13, error.StorageFull },
        .{ 14 | (1 << 8), error.OpenFailed },
        .{ 18, error.StorageLimit },
        .{ 26, error.CorruptDatabase },
        .{ 23, error.AccessDenied },
        .{ 19, error.DatabaseFailure },
    };
    inline for (cases) |case| try std.testing.expectEqual(@as(Error, case[1]), sqliteError(case[0]));
}

test "record store: oversized restored values fail before caller allocation and leave saved bytes intact" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(a, ".");
    defer a.free(base);
    const path = try std.fs.path.join(a, &.{ base, "restore-limits.sqlite" });
    defer a.free(path);
    var store = try Store.open(a, path);
    defer store.close();
    _ = try store.commitRecord(.{ .jail = "fixture", .source = "file", .occurrence = "1", .cursor = "1", .raw_hash = [_]u8{1} ** 32, .disposition = "counted", .checkpoint = "saved", .shared_state = .{ .name = "shared", .expected_revision = 0, .payload = "saved" } });
    var no_memory = std.heap.FixedBufferAllocator.init(&.{});
    const denied = no_memory.allocator();
    // Direct SQL stands in for a foreign/older writer. Public writes reject these.
    try store.exec("UPDATE checkpoints SET payload=zeroblob(16777217);");
    try std.testing.expectError(error.StorageLimit, store.snapshot(denied, "fixture"));
    try std.testing.expectError(error.StorageLimit, store.checkpoint(denied, "fixture"));
    try std.testing.expectEqual(@as(i64, Limits.checkpoint_bytes + 1), try store.integer("SELECT length(payload) FROM checkpoints;"));
    try store.exec("UPDATE shared_checkpoints SET payload=zeroblob(4194305);");
    try std.testing.expectError(error.StorageLimit, store.sharedSnapshot(denied, "shared"));
    try store.exec("UPDATE source_cursors SET cursor=zeroblob(65537);");
    try std.testing.expectError(error.StorageLimit, store.sourceCursor(denied, "fixture", "file"));
    const Visitor = struct {
        fn visit(_: []const u8, _: []const u8, _: []const u8, context: ?*anyopaque) !void {
            const called: *bool = @ptrCast(@alignCast(context.?));
            called.* = true;
        }
    };
    var called = false;
    try std.testing.expectError(error.StorageLimit, store.visitSources("fixture", Visitor.visit, &called));
    try std.testing.expect(!called);
    try store.exec("UPDATE checkpoints SET payload=x''; UPDATE shared_checkpoints SET payload=x''; UPDATE source_cursors SET cursor=x'31';");
    const empty = try store.snapshot(denied, "fixture");
    defer empty.deinit(denied);
    try std.testing.expectEqual(@as(usize, 0), empty.payload.?.len);
    try std.testing.expectEqual(@as(u64, 1), empty.revision);
    // A valid nonempty value still reports caller OOM, not a size violation.
    try std.testing.expectError(error.OutOfMemory, store.sourceCursor(denied, "fixture", "file"));
}

test "record store: SQLite row bound permits maximum admitted record and rejects oversized stored rows" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(a, ".");
    defer a.free(base);
    const path = try std.fs.path.join(a, &.{ base, "row-limit.sqlite" });
    defer a.free(path);
    var store = try Store.open(a, path);
    defer store.close();
    const payload = try a.alloc(u8, Limits.checkpoint_bytes);
    defer a.free(payload);
    @memset(payload, 'x');
    const record = Record{ .jail = payload[0..4096], .source = payload[0..Limits.source_bytes], .source_path = payload[0..Limits.source_bytes], .occurrence = payload[0..16384], .cursor = payload[0..Limits.cursor_bytes], .raw_hash = [_]u8{1} ** 32, .disposition = payload[0..64], .checkpoint = payload, .action_intent = payload[0 .. 1024 * 1024], .shared_state = .{ .name = payload[0..4096], .expected_revision = 0, .payload = payload[0..Limits.shared_bytes] } };
    try std.testing.expectEqual(CommitResult.committed, try store.commitRecord(record));
    const saved = try store.snapshot(a, record.jail);
    defer saved.deinit(a);
    try std.testing.expectEqualSlices(u8, payload, saved.payload.?);
    try std.testing.expectEqual(@as(c_int, Limits.sqlite_row_bytes), store.api.limit(store.db, 0, -1));
    // Simulate an older connection with larger limits, then restore our bound.
    _ = store.api.limit(store.db, 0, 32 * 1024 * 1024);
    try store.exec("UPDATE checkpoints SET payload=zeroblob(17825792);");
    _ = store.api.limit(store.db, 0, Limits.sqlite_row_bytes);
    var no_memory = std.heap.FixedBufferAllocator.init(&.{});
    try std.testing.expectError(error.StorageLimit, store.snapshot(no_memory.allocator(), record.jail));
    try std.testing.expectEqual(@as(?c_int, 18), store.last_error_code);
    try std.testing.expectEqual(@as(i64, 17825792), try store.integer("SELECT length(payload) FROM checkpoints;"));
}

test "record store: SQLite heap budget feasibility and recovery after allocation denial" {
    const Memory = struct {
        extern "c" fn sqlite3_hard_heap_limit64(i64) i64;
        extern "c" fn sqlite3_soft_heap_limit64(i64) i64;
        extern "c" fn sqlite3_memory_used() i64;
        extern "c" fn sqlite3_memory_highwater(c_int) i64;
    };
    // Test-only process-wide ceiling. Production configuration must own this
    // once, before opening connections; it is not a per-Store or RSS limit.
    const old_soft = Memory.sqlite3_soft_heap_limit64(-1);
    const old_hard = Memory.sqlite3_hard_heap_limit64(64 * 1024 * 1024);
    defer {
        _ = Memory.sqlite3_hard_heap_limit64(old_hard);
        _ = Memory.sqlite3_soft_heap_limit64(old_soft);
    }
    _ = Memory.sqlite3_memory_highwater(1);
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(a, ".");
    defer a.free(base);
    const path = try std.fs.path.join(a, &.{ base, "heap-budget.sqlite" });
    defer a.free(path);
    const large = try a.alloc(u8, Limits.checkpoint_bytes);
    defer a.free(large);
    @memset(large, 'x');
    var record = Record{ .jail = "fixture", .source = "file", .occurrence = "1", .cursor = "1", .raw_hash = [_]u8{1} ** 32, .disposition = "counted", .checkpoint = large, .action_intent = "saved-intent" };
    {
        var store = try Store.open(a, path);
        defer store.close();
        _ = try store.commitRecord(record);
        const saved = try store.snapshot(a, "fixture");
        defer saved.deinit(a);
        try std.testing.expectEqualSlices(u8, large, saved.payload.?);
        const peak = Memory.sqlite3_memory_highwater(0);
        try std.testing.expect(peak <= 64 * 1024 * 1024);
        std.debug.print("SQLite heap peak for 16 MiB checkpoint commit/restore: {d} bytes\n", .{peak});
        // Deny a new allocation using SQLite's actual allocator, not an injected rc.
        _ = Memory.sqlite3_hard_heap_limit64(Memory.sqlite3_memory_used());
        record.occurrence = "2";
        record.cursor = "2";
        record.expected_revision = 1;
        try std.testing.expectError(error.OutOfMemory, store.commitRecord(record));
        _ = Memory.sqlite3_hard_heap_limit64(64 * 1024 * 1024);
    }
    var recovered = try Store.open(a, path);
    defer recovered.close();
    try std.testing.expectEqual(@as(u64, 1), try recovered.revision("fixture"));
    try std.testing.expect(!try recovered.hasRecord("fixture", "file", "2", record.raw_hash, "2"));
    try std.testing.expectEqual(@as(i64, 1), try recovered.pendingIntents());
    try std.testing.expectEqual(CommitResult.committed, try recovered.commitRecord(record));
    try std.testing.expectEqual(CommitResult.already_committed, try recovered.commitRecord(record));
    try std.testing.expectEqual(@as(i64, 2), try recovered.pendingIntents());
}

test "record store: SQLite work budget feasibility interrupts excessive query and releases statements" {
    const Progress = struct {
        remaining: u32,
        extern "c" fn sqlite3_progress_handler(*Db, c_int, ?*const fn (?*anyopaque) callconv(.c) c_int, ?*anyopaque) void;
        fn tick(context: ?*anyopaque) callconv(.c) c_int {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.remaining -|= 1;
            return @intFromBool(self.remaining == 0);
        }
    };
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(a, ".");
    defer a.free(base);
    const path = try std.fs.path.join(a, &.{ base, "work-budget.sqlite" });
    defer a.free(path);
    var store = try Store.open(a, path);
    defer store.close();
    var budget = Progress{ .remaining = 1000 };
    Progress.sqlite3_progress_handler(store.db, 1000, Progress.tick, &budget);
    defer Progress.sqlite3_progress_handler(store.db, 0, null, null);
    const record = Record{ .jail = "fixture", .source = "file", .occurrence = "1", .cursor = "1", .raw_hash = [_]u8{1} ** 32, .disposition = "counted", .checkpoint = "saved", .action_intent = "saved-intent" };
    _ = try store.commitRecord(record);
    // This read deliberately exceeds the test allowance. No external SQL input.
    try std.testing.expectError(error.Interrupted, store.integer("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<10000000) SELECT sum(x) FROM n;"));
    try std.testing.expectEqual(@as(u32, 0), budget.remaining);
    try std.testing.expectEqual(@as(?c_int, 9), store.last_error_code);
    budget.remaining = 1000;
    try std.testing.expectEqual(@as(u64, 1), try store.revision("fixture"));
    try std.testing.expectEqual(@as(i64, 1), try store.pendingIntents());
    try std.testing.expectEqual(CommitResult.already_committed, try store.commitRecord(record));
}

test "record store: capacity failure preserves every committed component and retry is atomic" {
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const path = try std.fs.path.join(allocator, &.{ base, "capacity.sqlite" });
    defer allocator.free(path);
    var store = try Store.open(allocator, path);
    defer store.close();
    var record = Record{ .jail = "fixture", .source = "file", .occurrence = "1", .cursor = "1", .raw_hash = [_]u8{1} ** 32, .disposition = "counted", .checkpoint = "saved", .action_intent = "saved-intent", .shared_state = .{ .name = "shared", .expected_revision = 0, .payload = "saved-shared" } };
    _ = try store.commitRecord(record);
    // Exercise real SQLITE_FULL without filling the host disk. This page ceiling
    // is a test constraint, not a production disk/WAL quota or an OS ENOSPC test.
    const pages = try store.integer("PRAGMA page_count;");
    var sql: [80]u8 = undefined;
    try std.testing.expectEqual(pages, try store.integer(try std.fmt.bufPrintZ(&sql, "PRAGMA max_page_count={d};", .{pages})));
    const large = try allocator.alloc(u8, 256 * 1024);
    defer allocator.free(large);
    @memset(large, 'x');
    record.occurrence = "2";
    record.cursor = "2";
    record.checkpoint = "next";
    record.expected_revision = 1;
    record.shared_state.?.expected_revision = 1;
    record.shared_state.?.payload = "next-shared";
    // Fail at the last write, after record/state/shared-state/cursor changes.
    record.action_intent = large;
    try std.testing.expectError(error.StorageFull, store.commitRecord(record));
    try std.testing.expectEqual(@as(?c_int, 13), store.last_error_code);
    try std.testing.expect(store.api.get_autocommit(store.db) != 0);
    try std.testing.expect(!store.reopen_required);
    try std.testing.expectEqual(@as(?c_int, null), store.rollback_error_code);
    try std.testing.expect(!try store.hasRecord("fixture", "file", "2", record.raw_hash, "2"));
    const saved = try store.snapshot(allocator, "fixture");
    defer saved.deinit(allocator);
    try std.testing.expectEqualStrings("saved", saved.payload.?);
    try std.testing.expectEqual(@as(u64, 1), saved.revision);
    const shared = try store.sharedSnapshot(allocator, "shared");
    defer shared.deinit(allocator);
    try std.testing.expectEqualStrings("saved-shared", shared.payload.?);
    try std.testing.expectEqual(@as(u64, 1), shared.revision);
    const cursor = (try store.sourceCursor(allocator, "fixture", "file")).?;
    defer allocator.free(cursor);
    try std.testing.expectEqualStrings("1", cursor);
    try std.testing.expectEqual(@as(i64, 1), try store.pendingIntents());
    try std.testing.expectEqual(@as(?c_int, 13), store.last_error_code);
    _ = try store.integer("PRAGMA max_page_count=10000;");
    try std.testing.expectEqual(CommitResult.committed, try store.commitRecord(record));
    try std.testing.expectEqual(CommitResult.already_committed, try store.commitRecord(record));
    try std.testing.expectEqual(@as(u64, 2), try store.revision("fixture"));
    try std.testing.expectEqual(@as(i64, 2), try store.pendingIntents());
}

test "record store: rollback failure blocks reads and writes until close and recovery" {
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const path = try std.fs.path.join(allocator, &.{ base, "rollback.sqlite" });
    defer allocator.free(path);
    const record = Record{ .jail = "fixture", .source = "file", .occurrence = "1", .cursor = "1", .raw_hash = [_]u8{1} ** 32, .disposition = "counted", .checkpoint = "uncommitted", .action_intent = "uncommitted-intent" };
    {
        var store = try Store.open(allocator, path);
        defer store.close();
        const Fault = struct {
            fn exec(db: *Db, sql: [*:0]const u8, callback: ?*anyopaque, context: ?*anyopaque, message: ?*?[*:0]u8) callconv(.c) c_int {
                if (std.mem.eql(u8, std.mem.span(sql), "COMMIT;")) return 10 | (3 << 8);
                if (std.mem.eql(u8, std.mem.span(sql), "ROLLBACK;")) return 10 | (4 << 8);
                return embedded_api.exec(db, sql, callback, context, message);
            }
        };
        // Per-connection fault injection; no global VFS or live disk changes.
        store.api.exec = Fault.exec;
        try std.testing.expectError(error.StorageIo, store.commitRecord(record));
        try std.testing.expectEqual(@as(?c_int, 10 | (3 << 8)), store.last_error_code);
        try std.testing.expectEqual(@as(?c_int, 10 | (4 << 8)), store.rollback_error_code);
        try std.testing.expect(store.api.get_autocommit(store.db) == 0);
        try std.testing.expectError(error.ReopenRequired, store.snapshot(allocator, "fixture"));
        try std.testing.expectError(error.ReopenRequired, store.sourceCursor(allocator, "fixture", "file"));
        try std.testing.expectError(error.ReopenRequired, store.pendingIntents());
        try std.testing.expectError(error.ReopenRequired, store.commitRecord(record));
    }
    var recovered = try Store.open(allocator, path);
    defer recovered.close();
    try std.testing.expectEqual(@as(u64, 0), try recovered.revision("fixture"));
    try std.testing.expectEqual(@as(i64, 0), try recovered.pendingIntents());
    try std.testing.expectEqual(CommitResult.committed, try recovered.commitRecord(record));
}

test "record store: malformed database is reported without replacing its contents" {
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const path = try std.fs.path.join(allocator, &.{ base, "malformed.sqlite" });
    defer allocator.free(path);
    const original = [_]u8{'x'} ** 4096;
    var file = try temp.dir.createFile("malformed.sqlite", .{ .mode = 0o600 });
    try file.writeAll(&original);
    file.close();
    try std.testing.expectError(error.CorruptDatabase, Store.open(allocator, path));
    const after = try temp.dir.readFileAlloc(allocator, "malformed.sqlite", original.len + 1);
    defer allocator.free(after);
    try std.testing.expectEqualSlices(u8, &original, after);
}

test "record store: embedded release and extension loading policy" {
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const path = try std.fs.path.join(std.testing.allocator, &.{ base, "embedded.sqlite" });
    defer std.testing.allocator.free(path);
    var store = try Store.open(std.testing.allocator, path);
    defer store.close();
    var version = try store.statement("SELECT sqlite_version();");
    defer version.deinit();
    try std.testing.expect(try version.row());
    try std.testing.expectEqualStrings("3.53.4", try version.bytes(0));
    try std.testing.expectEqual(@as(i64, 1), try store.integer("SELECT sqlite_compileoption_used('OMIT_LOAD_EXTENSION');"));
    try std.testing.expectEqual(@as(i64, 1), try store.integer("SELECT sqlite_compileoption_used('THREADSAFE=1');"));
}

test "record store: killed writer preserves committed WAL and rolls back unfinished updates" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const path = try std.fs.path.join(allocator, &.{ base, "crash.sqlite" });
    defer allocator.free(path);
    for ([_]bool{ false, true }) |uncommitted| {
        const pid = try std.posix.fork();
        if (pid == 0) {
            var store = Store.open(std.heap.page_allocator, path) catch std.process.exit(2);
            if (!uncommitted) {
                _ = store.commitRecord(.{ .jail = "crash", .source = "file", .occurrence = "1", .cursor = "durable-cursor", .raw_hash = [_]u8{1} ** 32, .disposition = "matched", .checkpoint = "durable-state", .action_intent = "durable-intent" }) catch std.process.exit(3);
            } else {
                store.exec("BEGIN IMMEDIATE; UPDATE checkpoints SET payload='uncommitted-state'; DELETE FROM source_cursors; DELETE FROM action_intents;") catch std.process.exit(4);
            }
            // No close/checkpoint/destructor: exercise SQLite recovery after process death.
            std.posix.kill(std.os.linux.getpid(), std.posix.SIG.KILL) catch std.process.exit(5);
            unreachable;
        }
        const result = std.posix.waitpid(pid, 0);
        try std.testing.expect(std.os.linux.W.IFSIGNALED(result.status));
        try std.testing.expectEqual(@as(u32, std.posix.SIG.KILL), std.os.linux.W.TERMSIG(result.status));
        var recovered = try Store.open(allocator, path);
        defer recovered.close();
        const snapshot = try recovered.snapshot(allocator, "crash");
        defer snapshot.deinit(allocator);
        try std.testing.expectEqualStrings("durable-state", snapshot.payload.?);
        const cursor = (try recovered.sourceCursor(allocator, "crash", "file")).?;
        defer allocator.free(cursor);
        try std.testing.expectEqualStrings("durable-cursor", cursor);
        try std.testing.expectEqual(@as(i64, 1), try recovered.pendingIntents());
        try std.testing.expectEqual(@as(u64, 1), snapshot.revision);
    }
}

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
        try std.testing.expectEqualSlices(u8, &.{ 0x80, 0, 0, 0, 0, 0, 0, 0 }, try value.bytes(0));
        try std.testing.expectEqualStrings("18446744073709551615", try value.bytes(1));
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

const ReceiptFixture = struct {
    const identity = ReceiptIdentity{ .jail = "fixture", .source = "ordinary", .occurrence = "one", .cursor = "next", .raw_hash = [_]u8{7} ** 32, .generation = [_]u8{9} ** 32 };
    fn record(stamp: i64) Record {
        return .{ .jail = identity.jail, .source = identity.source, .occurrence = identity.occurrence, .cursor = identity.cursor, .raw_hash = identity.raw_hash, .receipt = .{ .time = .{ .us = stamp }, .generation = identity.generation }, .disposition = "ordinary", .checkpoint = "state", .action_intent = "inert-fixture-intent" };
    }
};

test "clock recovery: pending verification releases its read before source work and rejects concurrent changes" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "detached.sqlite" });
    defer a.free(path);
    var store = try Store.open(a, path);
    defer store.close();
    try store.enableReceipts(3);
    _ = try store.beginReceipt(ReceiptFixture.identity, .{ .us = 100 }, 0);
    var writer = try Store.open(a, path);
    defer writer.close();
    try writer.enableReceipts(3);
    const Visitor = struct {
        writer: *Store,
        checkpoint: bool = false,
        mutate: bool = false,
        count: usize = 0,
        fn check(identity: ReceiptIdentity, stamp: native_time.Timestamp, context: ?*anyopaque) !void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.count += 1;
            // An active SQLite read snapshot would make this return busy.
            if (self.checkpoint) try std.testing.expectEqual(@as(i64, 0), try self.writer.integer("PRAGMA wal_checkpoint(TRUNCATE);"));
            if (self.mutate) {
                var next = identity;
                next.source = "second";
                _ = try self.writer.beginReceipt(next, .{ .us = 200 }, 0);
            }
            try std.testing.expectEqualStrings("fixture", identity.jail);
            try std.testing.expectEqualStrings("ordinary", identity.source);
            try std.testing.expectEqualStrings("next", identity.cursor);
            try std.testing.expectEqual(@as(i64, 100), stamp.us);
        }
    };
    var visitor = Visitor{ .writer = &writer };
    try store.visitPendingReceipts(Visitor.check, &visitor);
    try std.testing.expectEqual(@as(usize, 1), visitor.count);
    visitor.count = 0;
    visitor.checkpoint = true;
    // SQLite also changes data_version when this checkpoint resets the WAL.
    // Conservatively restart validation, even though no logical row changed.
    try std.testing.expectError(error.StaleCheckpoint, store.visitPendingReceipts(Visitor.check, &visitor));
    try std.testing.expectEqual(@as(usize, 1), visitor.count);
    try std.testing.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
    visitor.count = 0;
    visitor.checkpoint = false;
    visitor.mutate = true;
    try std.testing.expectError(error.StaleCheckpoint, store.visitPendingReceipts(Visitor.check, &visitor));
    try std.testing.expectEqual(@as(usize, 1), visitor.count);
    try std.testing.expectEqual(@as(usize, 2), try store.pendingReceiptCount());
}

test "clock recovery: detached pending traversal stays bounded and cleans allocation failure" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "bounded.sqlite" });
    defer a.free(path);
    var store = try Store.open(a, path);
    defer store.close();
    try store.enableReceipts(3);
    for ([_][]const u8{ "a", "b", "c" }) |source| {
        var identity = ReceiptFixture.identity;
        identity.source = source;
        _ = try store.beginReceipt(identity, .{ .us = 100 }, 0);
    }
    const Visitor = struct {
        count: usize = 0,
        fn check(identity: ReceiptIdentity, _: native_time.Timestamp, context: ?*anyopaque) !void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            try std.testing.expectEqual(@as(u8, @intCast('a' + self.count)), identity.source[0]);
            self.count += 1;
        }
        fn allocate(allocator: std.mem.Allocator, target: *Store) !void {
            const prior = target.allocator;
            target.allocator = allocator;
            defer target.allocator = prior;
            var visitor = @This(){};
            try target.visitPendingReceipts(check, &visitor);
            try std.testing.expectEqual(@as(usize, 3), visitor.count);
        }
    };
    try std.testing.checkAllAllocationFailures(a, Visitor.allocate, .{&store});
    store.receipt_limit = 1;
    var visitor = Visitor{};
    try std.testing.expectError(error.ReceiptLimit, store.visitPendingReceipts(Visitor.check, &visitor));
    try std.testing.expectEqual(@as(usize, 1), visitor.count);
    try std.testing.expectEqual(@as(u64, 0), try store.revision("fixture"));
}

test "clock recovery: schema seven seeds exact durable floor and receipt failures cannot change it" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "clock.sqlite" });
    defer a.free(path);
    var store = try Store.open(a, path);
    defer store.close();
    try DetectionFixture.admit(&store);
    try store.enableDetection();
    _ = try store.commitRecord(try DetectionFixture.record());
    var next = ReceiptFixture.identity;
    next.source = "pending";
    next.occurrence = "two";
    next.cursor = "later";
    try store.enableReceipts(2);
    const greatest = DetectionFixture.stamp + 17;
    _ = try store.beginReceipt(next, .{ .us = greatest }, 1);
    store.fail_at = .before_clock_schema_commit;
    try std.testing.expectError(error.InjectedFailure, store.enableClockRecovery());
    try std.testing.expectEqual(@as(i64, 6), try store.integer("PRAGMA user_version;"));
    try std.testing.expectEqual(@as(i64, 0), try store.integer("SELECT count(*) FROM sqlite_master WHERE name='receipt_clock';"));
    store.fail_at = null;
    try store.enableClockRecovery();
    try std.testing.expectEqual(greatest, (try store.receiptClock()).?.us);
    try store.enableDetection();
    try store.enableYearInference();
    try store.enableNativeTime();
    try std.testing.expectEqual(@as(i64, 7), store.schema_version);
    var third = next;
    third.source = "third";
    third.occurrence = "three";
    third.cursor = "last";
    store.fail_at = .before_receipt_commit;
    try std.testing.expectError(error.InjectedFailure, store.beginReceipt(third, .{ .us = greatest + 1 }, 1));
    try std.testing.expectEqual(greatest, (try store.receiptClock()).?.us);
    try std.testing.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
    store.fail_at = .after_receipt_commit;
    try std.testing.expectError(error.InjectedFailure, store.beginReceipt(third, .{ .us = greatest + 1 }, 1));
    try std.testing.expectEqual(greatest + 1, (try store.receiptClock()).?.us);
    store.fail_at = null;
    try std.testing.expectEqual(greatest + 1, (try store.beginReceipt(third, .{ .us = 1 }, 1)).us);
    // The floor is independent of eventual detailed-ledger retention. This is
    // a storage invariant check, not an implemented compaction policy.
    try store.exec("DELETE FROM record_detections; DELETE FROM source_cursors; DELETE FROM records; DELETE FROM pending_receipts;");
    var reopened = try Store.open(a, path);
    defer reopened.close();
    try std.testing.expectEqual(greatest + 1, (try reopened.receiptClock()).?.us);
}

test "clock recovery: empty store and corrupt clock metadata remain distinguishable" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "empty.sqlite" });
    defer a.free(path);
    var store = try Store.open(a, path);
    defer store.close();
    try store.enableReceipts(1);
    try store.enableNativeTime();
    try std.testing.expectError(error.UnsupportedSchema, store.enableClockRecovery());
    try store.enableDetection();
    try store.enableClockRecovery();
    try std.testing.expect((try store.receiptClock()) == null);
    _ = try store.beginReceipt(ReceiptFixture.identity, .{ .us = std.math.minInt(i64) }, 0);
    try std.testing.expectEqual(std.math.minInt(i64), (try store.receiptClock()).?.us);
    try store.exec("PRAGMA ignore_check_constraints=ON; UPDATE receipt_clock SET floor_us='bad';");
    try std.testing.expectError(error.DatabaseFailure, store.receiptClock());
    try std.testing.expectError(error.DatabaseFailure, store.beginReceipt(ReceiptFixture.identity, .{ .us = 0 }, 0));
    try store.exec("DELETE FROM receipt_clock;");
    try std.testing.expectError(error.DatabaseFailure, store.receiptClock());
    try std.testing.expectError(error.DatabaseFailure, store.enableClockRecovery());
}

test "clock recovery: killed migration and receipt transaction preserve the durable floor" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = std.testing.allocator;
    for (0..3) |phase| {
        var temp = std.testing.tmpDir(.{});
        defer temp.cleanup();
        const root = try temp.dir.realpathAlloc(a, ".");
        defer a.free(root);
        const path = try std.fs.path.join(a, &.{ root, "crash-clock.sqlite" });
        defer a.free(path);
        {
            var store = try Store.open(a, path);
            defer store.close();
            try store.enableReceipts(1);
            try store.enableNativeTime();
            try store.enableDetection();
            if (phase != 0) try store.enableClockRecovery();
        }
        const pid = try std.posix.fork();
        if (pid == 0) {
            var child = Store.open(std.heap.page_allocator, path) catch std.process.exit(2);
            child.enableReceipts(1) catch std.process.exit(3);
            const Kill = struct {
                var after: bool = false;
                fn exec(db: *Db, sql: [*:0]const u8, callback: ?*anyopaque, context: ?*anyopaque, message: ?*?[*:0]u8) callconv(.c) c_int {
                    if (!std.mem.eql(u8, std.mem.span(sql), "COMMIT;")) return embedded_api.exec(db, sql, callback, context, message);
                    if (after and embedded_api.exec(db, sql, callback, context, message) != 0) std.process.exit(4);
                    std.posix.kill(std.os.linux.getpid(), std.posix.SIG.KILL) catch std.process.exit(5);
                    unreachable;
                }
            };
            Kill.after = phase == 2;
            child.api.exec = Kill.exec;
            if (phase == 0) child.enableClockRecovery() catch std.process.exit(6) else {
                _ = child.beginReceipt(ReceiptFixture.identity, .{ .us = DetectionFixture.stamp }, 0) catch std.process.exit(7);
            }
            std.process.exit(8);
        }
        const status = std.posix.waitpid(pid, 0).status;
        try std.testing.expect(std.os.linux.W.IFSIGNALED(status));
        try std.testing.expectEqual(@as(u32, std.posix.SIG.KILL), std.os.linux.W.TERMSIG(status));
        var reopened = try Store.open(a, path);
        defer reopened.close();
        try std.testing.expectEqual(@as(i64, if (phase == 0) 6 else 7), reopened.schema_version);
        try reopened.enableReceipts(1);
        try reopened.enableClockRecovery();
        const floor = try reopened.receiptClock();
        if (phase == 2) try std.testing.expectEqual(DetectionFixture.stamp, floor.?.us) else try std.testing.expect(floor == null);
        try std.testing.expectEqual(@as(usize, if (phase == 2) 1 else 0), try reopened.pendingReceiptCount());
        try std.testing.expectEqual(@as(u64, 0), try reopened.revision("fixture"));
    }
}

const DetectionFixture = struct {
    const stamp: i64 = 9_007_199_254_740_993;
    fn record() !Record {
        var value = ReceiptFixture.record(stamp);
        value.action_intent = null;
        value.native_time_outcome = try time_policy.evaluate(.timestamped, .{ .parsed = .{ .us = stamp } }, .{ .us = stamp }, .{ .us = stamp }, 600_000_000);
        value.disposition = value.native_time_outcome.?.disposition();
        value.native_detection = .{ .kind = .candidate, .generation = [_]u8{3} ** 32, .filter = try detection.Name.init("sshd"), .pattern = try detection.Name.init("invalid-user"), .pattern_index = 2, .subject = .{ .v4 = .{ 203, 0, 113, 7 } } };
        return value;
    }
    fn admit(store: *Store) !void {
        try store.enableReceipts(1);
        try store.enableNativeTime();
        _ = try store.beginReceipt(ReceiptFixture.identity, .{ .us = stamp }, 0);
    }
};

test "native detection: journal schema migration preserves prior evidence and clock through rollback" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "journal-upgrade.sqlite" });
    defer a.free(path);
    var store = try Store.open(a, path);
    defer store.close();
    try DetectionFixture.admit(&store);
    try store.enableDetection();
    try std.testing.expectError(error.UnsupportedSchema, store.enableJournalDetection());
    const record = try DetectionFixture.record();
    _ = try store.commitRecord(record);
    try store.enableClockRecovery();
    // Real SQLite capacity refusal during table replacement must leave the
    // previous schema/evidence usable; migration must never prune to make room.
    const original_maximum = try store.integer("PRAGMA max_page_count;");
    const pages = try store.integer("PRAGMA page_count;");
    const limited = try std.fmt.allocPrintZ(a, "PRAGMA max_page_count={d};", .{pages});
    defer a.free(limited);
    try store.exec(limited);
    try std.testing.expectError(error.StorageFull, store.enableJournalDetection());
    try std.testing.expectEqual(@as(i64, 7), try store.integer("PRAGMA user_version;"));
    try std.testing.expectEqualDeep(record.native_detection.?, (try store.nativeDetection("fixture", "ordinary", null)).?);
    const unlimited = try std.fmt.allocPrintZ(a, "PRAGMA max_page_count={d};", .{original_maximum});
    defer a.free(unlimited);
    try store.exec(unlimited);
    store.fail_at = .before_journal_detection_schema_commit;
    try std.testing.expectError(error.InjectedFailure, store.enableJournalDetection());
    try std.testing.expectEqual(@as(i64, 7), try store.integer("PRAGMA user_version;"));
    try std.testing.expectEqual(@as(i64, 0), try store.integer("SELECT count(*) FROM sqlite_master WHERE name='record_detections_v8';"));
    try std.testing.expectEqualDeep(record.native_detection.?, (try store.nativeDetection("fixture", "ordinary", null)).?);
    try std.testing.expectEqual(DetectionFixture.stamp, (try store.receiptClock()).?.us);
    store.fail_at = null;
    try store.enableJournalDetection();
    try store.enableDetection();
    try store.enableNativeTime();
    try store.enableClockRecovery();
    try store.enableJournalDetection();
    try std.testing.expectEqual(@as(i64, 8), store.schema_version);
    var reopened = try Store.open(a, path);
    defer reopened.close();
    try std.testing.expectEqual(@as(i64, 8), reopened.schema_version);
    try std.testing.expectEqualDeep(record.native_detection.?, (try reopened.nativeDetection("fixture", "ordinary", null)).?);
    try std.testing.expectEqual(DetectionFixture.stamp, (try reopened.receiptClock()).?.us);
    try std.testing.expectEqual(@as(u64, 1), try reopened.revision("fixture"));
}

test "native detection: killed journal schema migration is atomic on reopen" {
    const a = std.testing.allocator;
    for ([_]bool{ false, true }) |after| {
        var temp = std.testing.tmpDir(.{});
        defer temp.cleanup();
        const root = try temp.dir.realpathAlloc(a, ".");
        defer a.free(root);
        const path = try std.fs.path.join(a, &.{ root, "killed-journal.sqlite" });
        defer a.free(path);
        {
            var store = try Store.open(a, path);
            defer store.close();
            try DetectionFixture.admit(&store);
            try store.enableDetection();
            _ = try store.commitRecord(try DetectionFixture.record());
            try store.enableClockRecovery();
        }
        const pid = try std.posix.fork();
        if (pid == 0) {
            var child = Store.open(std.heap.page_allocator, path) catch std.process.exit(2);
            child.enableReceipts(1) catch std.process.exit(3);
            const Kill = struct {
                var after_commit: bool = false;
                fn exec(db: *Db, sql: [*:0]const u8, callback: ?*anyopaque, context: ?*anyopaque, message: ?*?[*:0]u8) callconv(.c) c_int {
                    if (!std.mem.eql(u8, std.mem.span(sql), "COMMIT;")) return embedded_api.exec(db, sql, callback, context, message);
                    if (after_commit and embedded_api.exec(db, sql, callback, context, message) != 0) std.process.exit(4);
                    std.posix.kill(std.os.linux.getpid(), std.posix.SIG.KILL) catch std.process.exit(5);
                    unreachable;
                }
            };
            Kill.after_commit = after;
            child.api.exec = Kill.exec;
            child.enableJournalDetection() catch std.process.exit(6);
            std.process.exit(7);
        }
        const status = std.posix.waitpid(pid, 0).status;
        try std.testing.expect(std.os.linux.W.IFSIGNALED(status));
        try std.testing.expectEqual(@as(u32, std.posix.SIG.KILL), std.os.linux.W.TERMSIG(status));
        var recovered = try Store.open(a, path);
        defer recovered.close();
        try std.testing.expectEqual(@as(i64, if (after) 8 else 7), recovered.schema_version);
        try std.testing.expectEqualDeep((try DetectionFixture.record()).native_detection.?, (try recovered.nativeDetection("fixture", "ordinary", null)).?);
        try std.testing.expectEqual(DetectionFixture.stamp, (try recovered.receiptClock()).?.us);
        try std.testing.expectEqual(@as(u64, 1), try recovered.revision("fixture"));
    }
}

test "native detection: schema six migration and typed outcomes commit atomically" {
    const a = std.testing.allocator;
    for ([_]bool{ false, true }) |inference| {
        var temp = std.testing.tmpDir(.{});
        defer temp.cleanup();
        const root = try temp.dir.realpathAlloc(a, ".");
        defer a.free(root);
        const path = try std.fs.path.join(a, &.{ root, "detection.sqlite" });
        defer a.free(path);
        var store = try Store.open(a, path);
        defer store.close();
        try DetectionFixture.admit(&store);
        if (inference) try store.enableYearInference();
        var old_reader = try Store.open(a, path);
        defer old_reader.close();
        const record = try DetectionFixture.record();
        try std.testing.expectError(error.DetectionStorageRequired, store.commitRecord(record));
        store.fail_at = .before_detection_schema_commit;
        try std.testing.expectError(error.InjectedFailure, store.enableDetection());
        try std.testing.expectEqual(@as(i64, if (inference) 5 else 4), try store.integer("PRAGMA user_version;"));
        try std.testing.expectEqual(@as(i64, 0), try store.integer("SELECT count(*) FROM sqlite_master WHERE name='record_detections';"));
        try std.testing.expectEqual(@as(i64, if (inference) 14 else 13), try store.integer("SELECT count(*) FROM pragma_table_info('records');"));
        store.fail_at = null;
        try store.enableDetection();
        try store.enableNativeTime();
        try store.enableYearInference();
        try std.testing.expectEqual(@as(i64, 6), store.schema_version);
        for ([_]CommitStage{ .after_record, .after_detection, .after_checkpoint, .after_receipt_delete, .before_commit }) |stage| {
            store.fail_at = stage;
            try std.testing.expectError(error.InjectedFailure, store.commitRecord(record));
            try std.testing.expect((try old_reader.nativeDetection("fixture", "ordinary", "one")) == null);
            try std.testing.expectEqual(@as(u64, 0), try store.revision("fixture"));
            try std.testing.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
        }
        store.fail_at = null;
        try std.testing.expectEqual(CommitResult.committed, try store.commitRecord(record));
        try std.testing.expectEqual(CommitResult.already_committed, try store.commitRecord(record));
        try std.testing.expectEqualDeep(record.native_detection.?, (try old_reader.nativeDetection("fixture", "ordinary", null)).?);
        try std.testing.expectEqualDeep(record.native_time_outcome.?, (try old_reader.nativeTime("fixture", "ordinary", null)).?);
        try std.testing.expectEqual(@as(i64, 1), try store.integer("SELECT count(*) FROM record_detections;"));
        try std.testing.expectEqual(@as(i64, 0), try store.pendingIntents());
        try std.testing.expectEqual(@as(usize, 0), try store.pendingReceiptCount());
        var reopened = try Store.open(a, path);
        defer reopened.close();
        try std.testing.expectEqualDeep(record.native_detection.?, (try reopened.nativeDetection("fixture", "ordinary", "one")).?);
    }
}

test "native detection: all typed outcomes preserve nulls and address family on reopen" {
    const a = std.testing.allocator;
    for (std.enums.values(detection.Kind)) |kind| {
        var temp = std.testing.tmpDir(.{});
        defer temp.cleanup();
        const root = try temp.dir.realpathAlloc(a, ".");
        defer a.free(root);
        const path = try std.fs.path.join(a, &.{ root, "outcome.sqlite" });
        defer a.free(path);
        var record = try DetectionFixture.record();
        record.native_detection.?.kind = kind;
        switch (kind) {
            .time_excluded, .malformed_body, .no_match, .origin_missing, .origin_ambiguous, .origin_machine, .origin_uid, .origin_executable, .origin_transport => {
                record.native_detection.?.subject = null;
                record.native_detection.?.pattern = null;
                record.native_detection.?.pattern_index = null;
            },
            .unenforceable => record.native_detection.?.subject = .{ .v4 = .{ 127, 0, 0, 1 } },
            .candidate => record.native_detection.?.subject = .{ .v6 = .{ 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7 } },
            .ignored => {},
        }
        if (kind == .time_excluded) {
            record.native_time_outcome = .{ .obsolete = record.native_time_outcome.?.eligible };
            record.disposition = record.native_time_outcome.?.disposition();
        }
        {
            var store = try Store.open(a, path);
            defer store.close();
            try DetectionFixture.admit(&store);
            try store.enableDetection();
            if (@intFromEnum(kind) >= 7) {
                try std.testing.expectError(error.DetectionStorageRequired, store.commitRecord(record));
                try store.enableClockRecovery();
                try store.enableJournalDetection();
            }
            _ = try store.commitRecord(record);
        }
        var reopened = try Store.open(a, path);
        defer reopened.close();
        try std.testing.expectEqualDeep(record.native_detection.?, (try reopened.nativeDetection("fixture", "ordinary", null)).?);
        try std.testing.expectEqual(@as(i64, 0), try reopened.pendingIntents());
    }
}

test "native detection: invalid typed evidence cannot advance progress" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "invalid.sqlite" });
    defer a.free(path);
    var store = try Store.open(a, path);
    defer store.close();
    try DetectionFixture.admit(&store);
    try store.enableDetection();
    for (0..7) |case| {
        var record = try DetectionFixture.record();
        switch (case) {
            0 => record.native_time_outcome = null,
            1 => {
                record.native_time_outcome = .{ .obsolete = record.native_time_outcome.?.eligible };
                record.disposition = record.native_time_outcome.?.disposition();
            },
            2 => record.native_detection.?.subject = null,
            3 => record.native_detection.?.subject = .{ .v4 = .{ 127, 0, 0, 1 } },
            4 => record.native_detection.?.pattern = null,
            5 => record.native_detection.?.filter.len = 65,
            6 => record.native_detection.?.kind = .no_match,
            else => unreachable,
        }
        try std.testing.expectError(error.InvalidRecord, store.commitRecord(record));
        try std.testing.expectEqual(@as(u64, 0), try store.revision("fixture"));
        try std.testing.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
    }
}

test "native detection: malformed stored fields and inconsistent time refuse reads" {
    const a = std.testing.allocator;
    const changes = [_][:0]const u8{
        "UPDATE record_detections SET version=2;",
        "UPDATE record_detections SET kind=99;",
        "UPDATE record_detections SET generation='12345678901234567890123456789012';",
        "UPDATE record_detections SET filter=CAST('sshd' AS BLOB);",
        "UPDATE record_detections SET pattern_index='bad';",
        "UPDATE record_detections SET pattern_index=65536;",
        "UPDATE record_detections SET family=5;",
        "UPDATE record_detections SET family=NULL;",
        "UPDATE record_detections SET subject=x'7f000001';",
        "UPDATE record_detections SET subject=zeroblob(3);",
        "UPDATE record_detections SET family=6,subject=x'00000000000000000000ffffcb007107';",
        "UPDATE record_detections SET filter='invalid name';",
        "UPDATE record_detections SET pattern=NULL;",
        "UPDATE records SET native_time_kind=4,disposition='time-obsolete-event';",
    };
    for (changes) |change| {
        var temp = std.testing.tmpDir(.{});
        defer temp.cleanup();
        const root = try temp.dir.realpathAlloc(a, ".");
        defer a.free(root);
        const path = try std.fs.path.join(a, &.{ root, "corrupt.sqlite" });
        defer a.free(path);
        var store = try Store.open(a, path);
        defer store.close();
        try DetectionFixture.admit(&store);
        try store.enableDetection();
        _ = try store.commitRecord(try DetectionFixture.record());
        try store.exec("PRAGMA ignore_check_constraints=ON;");
        try store.exec(change);
        try std.testing.expectError(error.DatabaseFailure, store.nativeDetection("fixture", "ordinary", null));
    }
}

test "native detection: process death around migration and outcome commit preserves acknowledgment" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = std.testing.allocator;
    for (0..3) |phase| {
        var temp = std.testing.tmpDir(.{});
        defer temp.cleanup();
        const root = try temp.dir.realpathAlloc(a, ".");
        defer a.free(root);
        const path = try std.fs.path.join(a, &.{ root, "crash.sqlite" });
        defer a.free(path);
        {
            var store = try Store.open(a, path);
            defer store.close();
            try DetectionFixture.admit(&store);
            if (phase != 0) try store.enableDetection();
        }
        const pid = try std.posix.fork();
        if (pid == 0) {
            var child = Store.open(std.heap.page_allocator, path) catch std.process.exit(2);
            child.enableReceipts(1) catch std.process.exit(3);
            const Kill = struct {
                var after: bool = false;
                fn exec(db: *Db, sql: [*:0]const u8, callback: ?*anyopaque, context: ?*anyopaque, message: ?*?[*:0]u8) callconv(.c) c_int {
                    if (!std.mem.eql(u8, std.mem.span(sql), "COMMIT;")) return embedded_api.exec(db, sql, callback, context, message);
                    if (after and embedded_api.exec(db, sql, callback, context, message) != 0) std.process.exit(4);
                    std.posix.kill(std.os.linux.getpid(), std.posix.SIG.KILL) catch std.process.exit(5);
                    unreachable;
                }
            };
            Kill.after = phase == 2;
            child.api.exec = Kill.exec;
            if (phase == 0) child.enableDetection() catch std.process.exit(6) else {
                const record = DetectionFixture.record() catch std.process.exit(7);
                _ = child.commitRecord(record) catch std.process.exit(8);
            }
            std.process.exit(9);
        }
        const status = std.posix.waitpid(pid, 0).status;
        try std.testing.expect(std.os.linux.W.IFSIGNALED(status));
        try std.testing.expectEqual(@as(u32, std.posix.SIG.KILL), std.os.linux.W.TERMSIG(status));
        var recovered = try Store.open(a, path);
        defer recovered.close();
        try std.testing.expectEqual(@as(i64, if (phase == 0) 4 else 6), recovered.schema_version);
        try recovered.enableReceipts(1);
        try recovered.enableDetection();
        try std.testing.expectEqual(@as(usize, if (phase == 2) 0 else 1), try recovered.pendingReceiptCount());
        try std.testing.expectEqual(@as(u64, if (phase == 2) 1 else 0), try recovered.revision("fixture"));
        const found = try recovered.nativeDetection("fixture", "ordinary", null);
        if (phase == 2) try std.testing.expectEqualDeep((try DetectionFixture.record()).native_detection.?, found.?) else try std.testing.expect(found == null);
        _ = try recovered.commitRecord(try DetectionFixture.record());
        try std.testing.expectEqual(@as(u64, 1), try recovered.revision("fixture"));
        try std.testing.expectEqual(@as(i64, 0), try recovered.pendingIntents());
    }
}

test "receipt recovery: explicit schema activation rolls back and preserves candidate data" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    defer a.free(path);
    {
        var store = try Store.open(a, path);
        defer store.close();
        var old_record = ReceiptFixture.record(0);
        old_record.receipt = null;
        _ = try store.commitRecord(old_record);
        try std.testing.expectError(error.ReceiptStorageRequired, store.beginReceipt(ReceiptFixture.identity, .{ .us = 0 }, 1));
        store.fail_at = .before_receipt_schema_commit;
        try std.testing.expectError(error.InjectedFailure, store.enableReceipts(2));
        try std.testing.expectEqual(@as(i64, 2), try store.integer("PRAGMA user_version;"));
        try std.testing.expectEqual(@as(i64, 0), try store.integer("SELECT count(*) FROM sqlite_master WHERE name='pending_receipts';"));
        try std.testing.expectEqual(@as(i64, 8), try store.integer("SELECT count(*) FROM pragma_table_info('records');"));
        try std.testing.expect(store.receipt_limit == null);
    }
    var store = try Store.open(a, path);
    defer store.close();
    try std.testing.expectEqual(@as(i64, 2), store.schema_version);
    try store.enableReceipts(2);
    try std.testing.expectEqual(@as(i64, 3), try store.integer("PRAGMA user_version;"));
    try std.testing.expectEqual(@as(i64, 10), try store.integer("SELECT count(*) FROM pragma_table_info('records');"));
    try std.testing.expectEqual(@as(u64, 1), try store.revision("fixture"));
    const snapshot = try store.snapshot(a, "fixture");
    defer snapshot.deinit(a);
    try std.testing.expectEqualStrings("state", snapshot.payload.?);
    try std.testing.expectEqual(@as(i64, 1), try store.pendingIntents());
    try std.testing.expectEqual(@as(i64, 1), try store.integer("SELECT count(*) FROM records WHERE receipt_us IS NULL AND receipt_generation IS NULL;"));
    var reopened = try Store.open(a, path);
    defer reopened.close();
    try std.testing.expectEqual(@as(i64, 3), try reopened.integer("PRAGMA user_version;"));
    try std.testing.expect(reopened.receipt_limit == null);
    try reopened.enableReceipts(2);
    try std.testing.expectEqual(@as(usize, 0), try reopened.pendingReceiptCount());
}

test "receipt recovery: identity limits atomic deletion and signed receipt history" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    defer a.free(path);
    var store = try Store.open(a, path);
    defer store.close();
    // This connection predates schema activation and must not bypass a pending receipt.
    var earlier = try Store.open(a, path);
    defer earlier.close();
    try store.enableReceipts(1);
    for ([_]i64{ std.math.minInt(i64), -1, 0, 9_007_199_254_740_993, std.math.maxInt(i64) }, 0..) |stamp, index| {
        var id = ReceiptFixture.identity;
        var key: [32]u8 = undefined;
        id.occurrence = try std.fmt.bufPrint(&key, "ordinary-{d}", .{index});
        var record = ReceiptFixture.record(stamp);
        record.occurrence = id.occurrence;
        record.expected_revision = index;
        store.fail_at = .before_receipt_commit;
        try std.testing.expectError(error.InjectedFailure, store.beginReceipt(id, .{ .us = stamp }, index));
        try std.testing.expectEqual(@as(usize, 0), try store.pendingReceiptCount());
        store.fail_at = .after_receipt_commit;
        try std.testing.expectError(error.InjectedFailure, store.beginReceipt(id, .{ .us = stamp }, index));
        try std.testing.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
        try std.testing.expectEqual(@as(u64, index), try store.revision("fixture"));
        store.fail_at = null;
        try std.testing.expectEqual(stamp, (try store.beginReceipt(id, .{ .us = 123 }, index)).us);
        try std.testing.expectError(error.StaleCheckpoint, store.beginReceipt(id, .{ .us = 123 }, index + 1));
        for (0..4) |variant| {
            var changed = id;
            switch (variant) {
                0 => changed.generation[0] ^= 1,
                1 => changed.raw_hash[0] ^= 1,
                2 => changed.occurrence = "other",
                3 => changed.cursor = "changed",
                else => unreachable,
            }
            try std.testing.expectError(error.ReceiptConflict, store.beginReceipt(changed, .{ .us = 123 }, index));
        }
        var another = id;
        another.source = "other-source";
        try std.testing.expectError(error.ReceiptLimit, store.beginReceipt(another, .{ .us = 123 }, index));
        try std.testing.expectError(error.ReceiptConflict, store.validateReceiptGeneration(id.jail, [_]u8{0} ** 32));
        var missing = record;
        missing.receipt = null;
        try std.testing.expectError(error.ReceiptRequired, earlier.commitRecord(missing));
        var wrong = record;
        wrong.receipt.?.time.us = stamp ^ 1;
        try std.testing.expectError(error.ReceiptConflict, store.commitRecord(wrong));
        for ([_]CommitStage{ .after_record, .after_checkpoint, .after_receipt_delete, .before_commit }) |stage| {
            store.fail_at = stage;
            try std.testing.expectError(error.InjectedFailure, store.commitRecord(record));
            try std.testing.expectEqual(stamp, (try store.pendingReceipt(id)).?.us);
            try std.testing.expectEqual(@as(u64, index), try store.revision("fixture"));
            try std.testing.expectEqual(@as(i64, @intCast(index)), try store.pendingIntents());
            try std.testing.expect(!try store.hasRecord(id.jail, id.source, id.occurrence, id.raw_hash, id.cursor));
        }
        store.fail_at = null;
        _ = try store.commitRecord(record);
        try std.testing.expectEqual(@as(usize, 0), try store.pendingReceiptCount());
        try std.testing.expectEqual(stamp, (try store.committedReceipt(id)).?.us);
        try std.testing.expectEqual(CommitResult.already_committed, try store.commitRecord(record));
        try std.testing.expectError(error.ReceiptConflict, store.commitRecord(wrong));
        try std.testing.expectError(error.ReceiptAlreadyCommitted, store.beginReceipt(id, .{ .us = 123 }, index + 1));
    }
}

test "receipt recovery: real read-only and capacity errors preserve the observation boundary" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    defer a.free(path);
    var store = try Store.open(a, path);
    defer store.close();
    try store.enableReceipts(2);
    try store.exec("PRAGMA query_only=ON;");
    try std.testing.expectError(error.ReadOnly, store.beginReceipt(ReceiptFixture.identity, .{ .us = 100 }, 0));
    try std.testing.expectEqual(@as(usize, 0), try store.pendingReceiptCount());
    try store.exec("PRAGMA query_only=OFF;");
    const pages = try store.integer("PRAGMA page_count;");
    var sql: [80]u8 = undefined;
    _ = try store.integer(try std.fmt.bufPrintZ(&sql, "PRAGMA max_page_count={d};", .{pages}));
    var large_id = ReceiptFixture.identity;
    const large_cursor = [_]u8{'x'} ** Limits.cursor_bytes;
    large_id.cursor = &large_cursor;
    try std.testing.expectError(error.StorageFull, store.beginReceipt(large_id, .{ .us = 100 }, 0));
    try std.testing.expectEqual(@as(usize, 0), try store.pendingReceiptCount());
    try std.testing.expectEqual(@as(u64, 0), try store.revision("fixture"));
    _ = try store.integer("PRAGMA max_page_count=10000;");
    _ = try store.beginReceipt(ReceiptFixture.identity, .{ .us = 100 }, 0);
    try store.exec("PRAGMA query_only=ON;");
    try std.testing.expectError(error.ReadOnly, store.commitRecord(ReceiptFixture.record(100)));
    try std.testing.expectEqual(@as(i64, 100), (try store.pendingReceipt(ReceiptFixture.identity)).?.us);
    try std.testing.expectEqual(@as(i64, 0), try store.pendingIntents());
    try store.exec("PRAGMA query_only=OFF;");
    _ = try store.commitRecord(ReceiptFixture.record(100));
    try std.testing.expectEqual(@as(usize, 0), try store.pendingReceiptCount());
}

test "receipt recovery: killed writer preserves pending time and atomic final publication" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    defer a.free(path);
    // Each child dies without closing SQLite. The next phase recovers that WAL.
    for (0..4) |phase| {
        const pid = try std.posix.fork();
        if (pid == 0) {
            var child = Store.open(std.heap.page_allocator, path) catch std.process.exit(2);
            child.enableReceipts(1) catch std.process.exit(3);
            if (phase == 0) {
                // Crash before the first observation transaction commits.
                child.exec("BEGIN IMMEDIATE; INSERT INTO pending_receipts VALUES('fixture','ordinary',zeroblob(32),'one',zeroblob(32),'next',100);") catch std.process.exit(4);
            } else if (phase == 1) {
                _ = child.beginReceipt(ReceiptFixture.identity, .{ .us = 100 }, 0) catch std.process.exit(5);
            } else if (phase == 2) {
                // Kill inside the real outcome transaction after pending removal.
                const Kill = struct {
                    fn exec(db: *Db, sql: [*:0]const u8, callback: ?*anyopaque, context: ?*anyopaque, message: ?*?[*:0]u8) callconv(.c) c_int {
                        if (std.mem.eql(u8, std.mem.span(sql), "COMMIT;")) {
                            std.posix.kill(std.os.linux.getpid(), std.posix.SIG.KILL) catch std.process.exit(6);
                            unreachable;
                        }
                        return embedded_api.exec(db, sql, callback, context, message);
                    }
                };
                child.api.exec = Kill.exec;
                _ = child.commitRecord(ReceiptFixture.record(100)) catch std.process.exit(7);
            } else {
                _ = child.commitRecord(ReceiptFixture.record(100)) catch std.process.exit(8);
            }
            std.posix.kill(std.os.linux.getpid(), std.posix.SIG.KILL) catch std.process.exit(9);
            unreachable;
        }
        const result = std.posix.waitpid(pid, 0);
        try std.testing.expect(std.os.linux.W.IFSIGNALED(result.status));
        try std.testing.expectEqual(@as(u32, std.posix.SIG.KILL), std.os.linux.W.TERMSIG(result.status));
        var recovered = try Store.open(a, path);
        defer recovered.close();
        try recovered.enableReceipts(1);
        if (phase == 0) {
            try std.testing.expectEqual(@as(usize, 0), try recovered.pendingReceiptCount());
        } else if (phase < 3) {
            try std.testing.expectEqual(@as(i64, 100), (try recovered.pendingReceipt(ReceiptFixture.identity)).?.us);
            try std.testing.expectEqual(@as(i64, 100), (try recovered.beginReceipt(ReceiptFixture.identity, .{ .us = 900 }, 0)).us);
        } else {
            try std.testing.expectEqual(@as(usize, 0), try recovered.pendingReceiptCount());
            try std.testing.expectEqual(@as(i64, 100), (try recovered.committedReceipt(ReceiptFixture.identity)).?.us);
        }
        try std.testing.expectEqual(@as(u64, if (phase == 3) 1 else 0), try recovered.revision("fixture"));
        try std.testing.expectEqual(@as(i64, if (phase == 3) 1 else 0), try recovered.pendingIntents());
    }
}

test "receipt recovery: recovery enumeration is bounded and rejects malformed stored values" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    defer a.free(path);
    var store = try Store.open(a, path);
    defer store.close();
    try store.enableReceipts(2);
    _ = try store.beginReceipt(ReceiptFixture.identity, .{ .us = -123 }, 0);
    const Visitor = struct {
        fn visit(identity: ReceiptIdentity, stamp: native_time.Timestamp, context: ?*anyopaque) !void {
            const called: *bool = @ptrCast(@alignCast(context.?));
            try std.testing.expectEqualDeep(ReceiptFixture.identity, identity);
            try std.testing.expectEqual(@as(i64, -123), stamp.us);
            called.* = true;
        }
        fn fail(_: ReceiptIdentity, _: native_time.Timestamp, _: ?*anyopaque) !void {
            return error.OutOfMemory;
        }
    };
    var called = false;
    try store.visitPendingReceipts(Visitor.visit, &called);
    try std.testing.expect(called);
    try std.testing.expectError(error.OutOfMemory, store.visitPendingReceipts(Visitor.fail, null));
    try std.testing.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
    var second = ReceiptFixture.identity;
    second.source = "second";
    _ = try store.beginReceipt(second, .{ .us = 456 }, 0);
    try std.testing.expectError(error.ReceiptLimit, store.enableReceipts(1));
    // Foreign/corrupt values must not be reinterpreted through SQLite coercion.
    try store.exec("PRAGMA ignore_check_constraints=ON; UPDATE pending_receipts SET receipt_us='not-an-integer' WHERE source='ordinary';");
    called = false;
    try std.testing.expectError(error.DatabaseFailure, store.visitPendingReceipts(Visitor.visit, &called));
    try std.testing.expect(!called);
    try std.testing.expectError(error.DatabaseFailure, store.pendingReceipt(ReceiptFixture.identity));
    try store.exec("UPDATE pending_receipts SET receipt_us=-123,cursor=zeroblob(65537) WHERE source='ordinary';");
    try std.testing.expectError(error.StorageLimit, store.visitPendingReceipts(Visitor.visit, &called));
    try std.testing.expect(!called);
}

test "receipt recovery: killed schema upgrade leaves version two data usable" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    defer a.free(path);
    {
        var store = try Store.open(a, path);
        defer store.close();
        var record = ReceiptFixture.record(0);
        record.receipt = null;
        _ = try store.commitRecord(record);
    }
    const pid = try std.posix.fork();
    if (pid == 0) {
        var child = Store.open(std.heap.page_allocator, path) catch std.process.exit(2);
        const Kill = struct {
            fn exec(db: *Db, sql: [*:0]const u8, callback: ?*anyopaque, context: ?*anyopaque, message: ?*?[*:0]u8) callconv(.c) c_int {
                if (std.mem.eql(u8, std.mem.span(sql), "COMMIT;")) {
                    std.posix.kill(std.os.linux.getpid(), std.posix.SIG.KILL) catch std.process.exit(3);
                    unreachable;
                }
                return embedded_api.exec(db, sql, callback, context, message);
            }
        };
        child.api.exec = Kill.exec;
        child.enableReceipts(1) catch std.process.exit(4);
        std.process.exit(5);
    }
    const result = std.posix.waitpid(pid, 0);
    try std.testing.expect(std.os.linux.W.IFSIGNALED(result.status));
    try std.testing.expectEqual(@as(u32, std.posix.SIG.KILL), std.os.linux.W.TERMSIG(result.status));
    var recovered = try Store.open(a, path);
    defer recovered.close();
    try std.testing.expectEqual(@as(i64, 2), try recovered.integer("PRAGMA user_version;"));
    try std.testing.expectEqual(@as(i64, 8), try recovered.integer("SELECT count(*) FROM pragma_table_info('records');"));
    try std.testing.expectEqual(@as(u64, 1), try recovered.revision("fixture"));
    try std.testing.expectEqual(@as(i64, 1), try recovered.pendingIntents());
    try recovered.enableReceipts(1);
    try std.testing.expectEqual(@as(i64, 3), try recovered.integer("PRAGMA user_version;"));
}

test "native processor: schema four preserves pending receipts and typed time is atomic and validated" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    defer a.free(path);
    var store = try Store.open(a, path);
    defer store.close();
    try store.enableReceipts(1);
    const stamp: i64 = 9_007_199_254_740_993;
    _ = try store.beginReceipt(ReceiptFixture.identity, .{ .us = stamp }, 0);
    store.fail_at = .before_native_time_schema_commit;
    try std.testing.expectError(error.InjectedFailure, store.enableNativeTime());
    try std.testing.expectEqual(@as(i64, 3), try store.integer("PRAGMA user_version;"));
    try std.testing.expectEqual(@as(i64, 10), try store.integer("SELECT count(*) FROM pragma_table_info('records');"));
    try std.testing.expectEqual(stamp, (try store.pendingReceipt(ReceiptFixture.identity)).?.us);
    store.fail_at = null;
    try store.enableNativeTime();
    var record = ReceiptFixture.record(stamp);
    record.native_time_outcome = try time_policy.evaluate(.timestamped, .{ .parsed = .{ .us = stamp + 1 } }, .{ .us = stamp }, .{ .us = stamp }, 600_000_000);
    record.disposition = record.native_time_outcome.?.disposition();
    store.fail_at = .after_checkpoint;
    try std.testing.expectError(error.InjectedFailure, store.commitRecord(record));
    try std.testing.expect((try store.nativeTime("fixture", "ordinary", "one")) == null);
    try std.testing.expectEqual(@as(usize, 1), try store.pendingReceiptCount());
    store.fail_at = null;
    _ = try store.commitRecord(record);
    try std.testing.expectEqualDeep(record.native_time_outcome.?, (try store.nativeTime("fixture", "ordinary", "one")).?);
    try std.testing.expectEqual(@as(i64, 1), try store.integer("SELECT count(*) FROM records WHERE typeof(original_us)='integer' AND typeof(effective_us)='integer' AND event_time IS NULL;"));
    {
        var reopened = try Store.open(a, path);
        defer reopened.close();
        try reopened.enableReceipts(1);
        try std.testing.expectEqual(@as(i64, 4), reopened.schema_version);
        try std.testing.expectEqualDeep(record.native_time_outcome.?, (try reopened.nativeTime("fixture", "ordinary", null)).?);
    }
    try store.exec("PRAGMA ignore_check_constraints=ON; UPDATE records SET native_time_kind=99;");
    try std.testing.expectError(error.DatabaseFailure, store.nativeTime("fixture", "ordinary", null));
    try store.exec("UPDATE records SET native_time_kind=3,effective_us='bad';");
    try std.testing.expectError(error.DatabaseFailure, store.nativeTime("fixture", "ordinary", null));
    try store.exec("UPDATE records SET native_time_kind=NULL;");
    try std.testing.expectError(error.DatabaseFailure, store.nativeTime("fixture", "ordinary", null));
}

test "native processor: killed native time migration preserves version three and its pending observation" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    defer a.free(path);
    {
        var store = try Store.open(a, path);
        defer store.close();
        try store.enableReceipts(1);
        _ = try store.beginReceipt(ReceiptFixture.identity, .{ .us = 123 }, 0);
    }
    const pid = try std.posix.fork();
    if (pid == 0) {
        var child = Store.open(std.heap.page_allocator, path) catch std.process.exit(2);
        child.enableReceipts(1) catch std.process.exit(3);
        const Kill = struct {
            fn exec(db: *Db, sql: [*:0]const u8, callback: ?*anyopaque, context: ?*anyopaque, message: ?*?[*:0]u8) callconv(.c) c_int {
                if (std.mem.eql(u8, std.mem.span(sql), "COMMIT;")) {
                    std.posix.kill(std.os.linux.getpid(), std.posix.SIG.KILL) catch std.process.exit(4);
                    unreachable;
                }
                return embedded_api.exec(db, sql, callback, context, message);
            }
        };
        child.api.exec = Kill.exec;
        child.enableNativeTime() catch std.process.exit(5);
        std.process.exit(6);
    }
    const result = std.posix.waitpid(pid, 0);
    try std.testing.expect(std.os.linux.W.IFSIGNALED(result.status));
    try std.testing.expectEqual(@as(u32, std.posix.SIG.KILL), std.os.linux.W.TERMSIG(result.status));
    var recovered = try Store.open(a, path);
    defer recovered.close();
    try recovered.enableReceipts(1);
    try std.testing.expectEqual(@as(i64, 3), recovered.schema_version);
    try std.testing.expectEqual(@as(i64, 123), (try recovered.pendingReceipt(ReceiptFixture.identity)).?.us);
    try recovered.enableNativeTime();
    try std.testing.expectEqual(@as(i64, 4), recovered.schema_version);
}

test "year inference: explicit schema five migration preserves old rows and atomically stores provenance" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    defer a.free(path);
    var store = try Store.open(a, path);
    defer store.close();
    try store.enableReceipts(1);
    try std.testing.expectError(error.UnsupportedSchema, store.enableYearInference());
    try store.enableNativeTime();
    const stamp = (try native_time.parse(.iso8601, "2026-01-01T00:00:10Z", .{})).us;
    _ = try store.beginReceipt(ReceiptFixture.identity, .{ .us = stamp }, 0);
    var old = ReceiptFixture.record(stamp);
    old.action_intent = null;
    old.native_time_outcome = try time_policy.evaluate(.timestamped, .{ .parsed = .{ .us = stamp } }, .{ .us = stamp }, .{ .us = stamp }, 600_000_000);
    old.disposition = old.native_time_outcome.?.disposition();
    _ = try store.commitRecord(old);
    var identity = ReceiptFixture.identity;
    identity.occurrence = "two";
    identity.cursor = "later";
    _ = try store.beginReceipt(identity, .{ .us = stamp }, 1);
    var record = old;
    record.occurrence = identity.occurrence;
    record.cursor = identity.cursor;
    record.expected_revision = 1;
    record.native_time_outcome.?.eligible.inferred_year = 2026;
    try std.testing.expectError(error.InferenceStorageRequired, store.commitRecord(record));
    var prior_reader = try Store.open(a, path);
    defer prior_reader.close();
    try std.testing.expectEqual(@as(i64, 4), prior_reader.schema_version);
    store.fail_at = .before_inference_schema_commit;
    try std.testing.expectError(error.InjectedFailure, store.enableYearInference());
    try std.testing.expectEqual(@as(i64, 4), try store.integer("PRAGMA user_version;"));
    try std.testing.expectEqual(@as(i64, 13), try store.integer("SELECT count(*) FROM pragma_table_info('records');"));
    try std.testing.expectEqual(stamp, (try store.pendingReceipt(identity)).?.us);
    store.fail_at = null;
    try store.enableYearInference();
    try std.testing.expectEqual(@as(i64, 5), store.schema_version);
    try std.testing.expectEqualDeep(old.native_time_outcome.?, (try store.nativeTime("fixture", "ordinary", "one")).?);
    store.fail_at = .after_receipt_delete;
    try std.testing.expectError(error.InjectedFailure, store.commitRecord(record));
    try std.testing.expect((try store.nativeTime("fixture", "ordinary", "two")) == null);
    try std.testing.expectEqual(@as(u64, 1), try store.revision("fixture"));
    try std.testing.expectEqual(stamp, (try store.pendingReceipt(identity)).?.us);
    store.fail_at = null;
    _ = try store.commitRecord(record);
    try std.testing.expectEqual(@as(i64, 1), try store.integer("SELECT count(*) FROM records WHERE inferred_year=2026 AND typeof(inferred_year)='integer';"));
    try std.testing.expectEqualDeep(record.native_time_outcome.?, (try prior_reader.nativeTime("fixture", "ordinary", "two")).?);
    try std.testing.expectEqual(@as(i64, 5), prior_reader.schema_version);
    {
        var reopened = try Store.open(a, path);
        defer reopened.close();
        try reopened.enableReceipts(1);
        try reopened.enableNativeTime();
        try reopened.enableYearInference();
        try std.testing.expectEqual(@as(i64, 5), reopened.schema_version);
        try std.testing.expectEqualDeep(record.native_time_outcome.?, (try reopened.nativeTime("fixture", "ordinary", null)).?);
        try std.testing.expectEqualDeep(old.native_time_outcome.?, (try reopened.nativeTime("fixture", "ordinary", "one")).?);
    }
    try store.exec("PRAGMA ignore_check_constraints=ON;");
    for ([_][:0]const u8{
        "UPDATE records SET inferred_year='bad' WHERE occurrence='two';",
        "UPDATE records SET inferred_year=-1 WHERE occurrence='two';",
        "UPDATE records SET inferred_year=0 WHERE occurrence='two';",
        "UPDATE records SET inferred_year=10000 WHERE occurrence='two';",
        "UPDATE records SET inferred_year=65536 WHERE occurrence='two';",
        "UPDATE records SET inferred_year=2026,original_us=NULL WHERE occurrence='two';",
        "UPDATE records SET native_time_kind=NULL,effective_us=NULL WHERE occurrence='two';",
    }) |sql| {
        try store.exec(sql);
        try std.testing.expectError(error.DatabaseFailure, store.nativeTime("fixture", "ordinary", "two"));
    }
}

test "year inference: killed migration leaves schema four and pending receipt recoverable" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "state.sqlite" });
    defer a.free(path);
    {
        var store = try Store.open(a, path);
        defer store.close();
        try store.enableReceipts(1);
        try store.enableNativeTime();
        _ = try store.beginReceipt(ReceiptFixture.identity, .{ .us = 123 }, 0);
    }
    const pid = try std.posix.fork();
    if (pid == 0) {
        var child = Store.open(std.heap.page_allocator, path) catch std.process.exit(2);
        child.enableReceipts(1) catch std.process.exit(3);
        const Kill = struct {
            fn exec(db: *Db, sql: [*:0]const u8, callback: ?*anyopaque, context: ?*anyopaque, message: ?*?[*:0]u8) callconv(.c) c_int {
                if (std.mem.eql(u8, std.mem.span(sql), "COMMIT;")) {
                    std.posix.kill(std.os.linux.getpid(), std.posix.SIG.KILL) catch std.process.exit(4);
                    unreachable;
                }
                return embedded_api.exec(db, sql, callback, context, message);
            }
        };
        child.api.exec = Kill.exec;
        child.enableYearInference() catch std.process.exit(5);
        std.process.exit(6);
    }
    const result = std.posix.waitpid(pid, 0);
    try std.testing.expect(std.os.linux.W.IFSIGNALED(result.status));
    try std.testing.expectEqual(@as(u32, std.posix.SIG.KILL), std.os.linux.W.TERMSIG(result.status));
    var recovered = try Store.open(a, path);
    defer recovered.close();
    try recovered.enableReceipts(1);
    try std.testing.expectEqual(@as(i64, 4), recovered.schema_version);
    try std.testing.expectEqual(@as(i64, 13), try recovered.integer("SELECT count(*) FROM pragma_table_info('records');"));
    try std.testing.expectEqual(@as(i64, 123), (try recovered.pendingReceipt(ReceiptFixture.identity)).?.us);
    try recovered.enableYearInference();
    try std.testing.expectEqual(@as(i64, 5), recovered.schema_version);
}

test "native retry: runtime SQL limits interrupt bounded work and WAL maintenance refuses pinned readers" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "budgets.sqlite" });
    defer a.free(path);
    var store = try Store.open(a, path);
    defer store.close();
    const hard_limit = @extern(*const fn (i64) callconv(.c) i64, .{ .name = "sqlite3_hard_heap_limit64" });
    const prior = hard_limit(-1);
    defer _ = hard_limit(prior);
    try store.configureRuntimeLimits();
    try std.testing.expectEqual(@as(i64, 0), try store.integer("PRAGMA wal_autocheckpoint;"));
    try std.testing.expectEqual(@as(i64, -2048), try store.integer("PRAGMA cache_size;"));
    try std.testing.expectError(error.Interrupted, store.integer("WITH RECURSIVE work(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM work WHERE n<2000000) SELECT sum(n) FROM work;"));
    try std.testing.expectEqual(@as(i64, 1), try store.integer("SELECT 1;"));
    try store.exec("CREATE TABLE volume(payload BLOB);");
    var reader = try Store.open(a, path);
    defer reader.close();
    try reader.exec("BEGIN;");
    _ = try reader.integer("SELECT count(*) FROM volume;");
    try store.exec("INSERT INTO volume WITH RECURSIVE data(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM data WHERE n<18000) SELECT zeroblob(1024) FROM data;");
    try std.testing.expectError(error.Busy, store.maintainWal(path));
    try reader.exec("COMMIT;");
    try store.maintainWal(path);
    const wal = try std.fmt.allocPrint(a, "{s}-wal", .{path});
    defer a.free(wal);
    try std.testing.expectEqual(@as(u64, 0), (try std.fs.cwd().statFile(wal)).size);
    try std.testing.expectEqual(@as(i64, 18000), try store.integer("SELECT count(*) FROM volume;"));
}

test "native retry: killed schema and decision commits reopen wholly before or after the boundary" {
    const a = std.testing.allocator;
    const policy = retry.Policy{ .maxretry = 1, .window_us = 600_000_000, .bantime_us = 60_000_000, .max_subjects = 8 };
    for ([_]bool{ false, true }) |migration| for ([_]bool{ false, true }) |after| {
        var temp = std.testing.tmpDir(.{});
        defer temp.cleanup();
        const root = try temp.dir.realpathAlloc(a, ".");
        defer a.free(root);
        const path = try std.fs.path.join(a, &.{ root, "killed-retry.sqlite" });
        defer a.free(path);
        {
            var store = try Store.open(a, path);
            defer store.close();
            try store.enableReceipts(1);
            try store.enableNativeTime();
            try store.enableDetection();
            try store.enableClockRecovery();
            try store.enableJournalDetection();
            if (!migration) {
                try store.enableRetry();
                try store.admitRetry("fixture", ReceiptFixture.identity.generation, policy);
            }
        }
        const pid = try std.posix.fork();
        if (pid == 0) {
            var child = Store.open(std.heap.page_allocator, path) catch std.process.exit(2);
            child.enableReceipts(1) catch std.process.exit(3);
            var record = DetectionFixture.record() catch std.process.exit(4);
            record.native_retry = .{ .generation = ReceiptFixture.identity.generation, .policy = policy, .processing_us = DetectionFixture.stamp };
            if (!migration) _ = child.beginReceipt(ReceiptFixture.identity, .{ .us = DetectionFixture.stamp }, 0) catch std.process.exit(5);
            const Kill = struct {
                var after_commit: bool = false;
                fn exec(db: *Db, sql: [*:0]const u8, callback: ?*anyopaque, context: ?*anyopaque, message: ?*?[*:0]u8) callconv(.c) c_int {
                    if (!std.mem.eql(u8, std.mem.span(sql), "COMMIT;")) return embedded_api.exec(db, sql, callback, context, message);
                    if (after_commit and embedded_api.exec(db, sql, callback, context, message) != 0) std.process.exit(6);
                    std.posix.kill(std.os.linux.getpid(), std.posix.SIG.KILL) catch std.process.exit(7);
                    unreachable;
                }
            };
            Kill.after_commit = after;
            child.api.exec = Kill.exec;
            if (migration) child.enableRetry() catch std.process.exit(8) else _ = child.commitRecord(record) catch std.process.exit(9);
            std.process.exit(10);
        }
        const ended = std.posix.waitpid(pid, 0);
        try std.testing.expect(std.posix.W.IFSIGNALED(ended.status));
        try std.testing.expectEqual(@as(u32, std.posix.SIG.KILL), std.posix.W.TERMSIG(ended.status));
        var restored = try Store.open(a, path);
        defer restored.close();
        if (migration) {
            try std.testing.expectEqual(@as(i64, if (after) 9 else 8), restored.schema_version);
            try std.testing.expectEqual(@as(i64, if (after) 1 else 0), try restored.integer("SELECT count(*) FROM sqlite_master WHERE name='retry_states';"));
        } else {
            try std.testing.expectEqual(@as(u64, @intFromBool(after)), try restored.revision("fixture"));
            const state = try restored.retryState("fixture", .{ .v4 = .{ 203, 0, 113, 7 } });
            const decision = try restored.retryDecision("fixture", "ordinary", null);
            try std.testing.expectEqual(after, state != null);
            try std.testing.expectEqual(after, decision != null);
            if (decision) |value| {
                try std.testing.expectEqual(DetectionFixture.stamp + policy.bantime_us, value.expiry_us);
                try std.testing.expectEqual(@as(u64, 1), state.?.decisions);
            }
            try std.testing.expectEqual(@as(usize, @intFromBool(!after)), try restored.pendingReceiptCount());
        }
    };
}
