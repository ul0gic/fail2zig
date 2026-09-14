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
const consumers = @import("native_consumer.zig");
const effects = @import("native_effect.zig");
const effect_history = @import("native_effect_history.zig");
pub const latest_schema: i64 = 15;
pub const max_native_detections = 16;
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
pub const Error = retry.Error || consumers.Error || effects.Error || effect_history.Error || error{ MaintenancePinned, StaleMaintenance, PrunedReplay, InvalidMaintenanceState, MaintenanceStorageRequired, ConsumerManifestRequired, ConsumerManifestMismatch, ConsumerManifestMissing, ConsumerManifestExists, ConsumerMigrationRequired, MissingRequiredConsumer, AmbiguousNativeDetection, AmbiguousRetryDecision, ConsumerStorageRequired, StaleConsumerCheckpoint, OpenFailed, UnsafePermissions, ForeignDatabase, UnsupportedSchema, DatabaseFailure, Busy, StorageFull, ReadOnly, StorageIo, CorruptDatabase, StorageLimit, Interrupted, AccessDenied, ReopenRequired, InvalidRecord, OccurrenceConflict, StaleCheckpoint, StaleSharedCheckpoint, InjectedFailure, OutOfMemory, ReceiptStorageRequired, InferenceStorageRequired, DetectionStorageRequired, ReceiptConflict, ReceiptRequired, ReceiptAlreadyCommitted, ReceiptLimit, RetryStorageRequired, RetryAdmissionRequired, RetryGenerationMismatch, RetryMigrationRequired, RetryCapacity, ReceiptClockReversed };

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
pub const CommitStage = enum { before_cleanup_schema_commit, after_cleanup_mark, after_cleanup_delete, after_retry_retire, before_maintenance_schema_commit, after_source_sequence, after_replay_guard, after_record, after_checkpoint, after_shared_checkpoint, before_commit, before_receipt_commit, after_receipt_commit, after_receipt_delete, before_receipt_schema_commit, before_native_time_schema_commit, before_inference_schema_commit, before_detection_schema_commit, after_detection, before_clock_schema_commit, before_journal_detection_schema_commit, before_retry_schema_commit, after_retry_state, after_retry_decision, before_consumer_schema_commit, after_consumer_delta, before_effect_schema_commit, after_effect_owner, after_effect_intent, before_effect_dispatch_commit, before_effect_receipt_commit, before_manifest_schema_commit, before_manifest_commit, after_manifest_ready, before_consumer_input_commit };
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
    /// Every outcome belongs to this one source occurrence; scalar and vector are exclusive.
    native_detections: ?[]const detection.Outcome = null,
    consumer_manifest: ?consumers.Manifest = null,
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
    consumers: ?consumers.Batch = null,
    zone_provenance: ?native_record.Provenance = null,
    effects_clock: ?effects.Clock = null,
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
    consumer_clock_floor_us: ?i64 = null,
    /// Process-local publication fence. Saturation invalidates detached expiry caches.
    effect_publication_epoch: u64 = 0,
    reopen_required: bool = false,
    // Startup state is private until the coordinator commits all admissions.
    startup_admission: bool = false,
    startup_operation: bool = false,
    /// Tests inject an ordinary transaction error; no crash or external action is required.
    fail_at: ?CommitStage = null,
    schema_version: i64 = 2,
    receipt_limit: ?usize = null,
    runtime_limits: bool = false,
    runtime_path: ?[]const u8 = null,
    work_remaining: u32 = 1000,

    /// One daemon-wide SQLite heap ceiling and per-transaction VM allowance.
    /// These exclude Zig/OS/helper allocations and do not promise a disk quota.
    fn configureHeapLimit() void {
        const hard_limit = @extern(*const fn (i64) callconv(.c) i64, .{ .name = "sqlite3_hard_heap_limit64" });
        const prior = hard_limit(-1);
        _ = hard_limit(if (prior > 0) @min(prior, 64 * 1024 * 1024) else 64 * 1024 * 1024);
    }
    pub fn configureRuntimeLimits(self: *Store) Error!void {
        configureHeapLimit();
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
    pub fn maintainWal(self: *Store, database_path: []const u8) Error!void {
        try self.usable();
        if (self.api.get_autocommit(self.db) == 0) return error.DatabaseFailure;
        if (database_path.len == 0 or std.mem.indexOfScalar(u8, database_path, 0) != null) return error.OpenFailed;
        var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buffer, "{s}-wal", .{database_path}) catch return error.StorageLimit;
        const stat = std.fs.cwd().statFile(path) catch |err| switch (err) {
            error.FileNotFound => return,
            error.AccessDenied => return error.AccessDenied,
            error.NameTooLong => return error.StorageLimit,
            else => return error.StorageIo,
        };
        if (stat.size < 16 * 1024 * 1024) return;
        // This checkpoint is a separate unit of SQL work. The subsequent BEGIN
        // resets the writer allowance; exhaustion here cannot borrow from it.
        self.work_remaining = 1000;
        var row = try self.statement("PRAGMA wal_checkpoint(TRUNCATE);");
        defer row.deinit();
        if (!try row.row()) return error.DatabaseFailure;
        if (try row.signed(0) != 0) {
            self.last_error_code = 5; // checkpoint's explicit SQLITE_BUSY result
            return error.Busy;
        }
    }

    /// Every runtime writer crosses the same WAL barrier before acquiring its
    /// transaction. Reads and rollback remain usable while a reader pins WAL.
    fn beginWrite(self: *Store) Error!void {
        try self.usable();
        if (self.startup_admission) return error.DatabaseFailure;
        if (self.runtime_path) |path| try self.maintainWal(path);
        try self.exec("BEGIN IMMEDIATE;");
    }

    /// Startup only: caller must keep all constructed owners unpublished and
    /// destroy them on abort. No source, DNS request or effect dispatch is allowed.
    pub fn beginStartupAdmission(self: *Store) Error!void {
        try self.beginWrite();
        self.startup_admission = true;
    }
    pub fn finishStartupAdmission(self: *Store) Error!void {
        if (!self.startup_admission or self.startup_operation) return error.DatabaseFailure;
        try self.exec("COMMIT;");
        self.startup_admission = false;
    }
    pub fn abortStartupAdmission(self: *Store) void {
        if (!self.startup_admission) return;
        self.startup_admission = false;
        self.startup_operation = false;
        self.rollback();
    }
    pub fn startupAdmissionActive(self: *const Store) bool {
        return self.startup_admission and !self.startup_operation and !self.reopen_required and self.api.get_autocommit(self.db) == 0;
    }
    fn beginStartupOperation(self: *Store) Error!void {
        try self.usable();
        if (!self.startupAdmissionActive()) return error.DatabaseFailure;
        // Separate bounded SQL allowance per existing operation. The outer
        // startup loop has its own fixed owner/source/turn bound.
        self.work_remaining = 1000;
        try self.exec("SAVEPOINT native_startup_operation;");
        self.startup_operation = true;
    }
    fn beginAdmissionWrite(self: *Store) Error!void {
        if (self.startup_admission) return self.beginStartupOperation();
        try self.beginWrite();
    }
    fn beginRead(self: *Store) Error!void {
        if (self.startup_admission) return self.beginStartupOperation();
        try self.exec("BEGIN;");
    }
    fn commitTransaction(self: *Store) Error!void {
        if (!self.startup_admission) return self.exec("COMMIT;");
        if (!self.startup_operation or self.api.get_autocommit(self.db) != 0) return error.DatabaseFailure;
        try self.exec("RELEASE native_startup_operation;");
        self.startup_operation = false;
    }

    pub fn open(allocator: std.mem.Allocator, path: []const u8) Error!Store {
        return openImpl(allocator, path, false);
    }

    /// Runtime reopen must cross the WAL barrier before its initial schema
    /// transaction too. The borrowed path must outlive this Store.
    pub fn openRuntime(allocator: std.mem.Allocator, path: []const u8) Error!Store {
        return openImpl(allocator, path, true);
    }

    fn openImpl(allocator: std.mem.Allocator, path: []const u8, runtime: bool) Error!Store {
        if (path.len == 0 or std.mem.indexOfScalar(u8, path, 0) != null) return error.OpenFailed;
        var parent = std.fs.cwd().openDir(std.fs.path.dirname(path) orelse ".", .{ .no_follow = true }) catch return error.OpenFailed;
        defer parent.close();
        const parent_stat = std.posix.fstat(parent.fd) catch return error.OpenFailed;
        if (parent_stat.uid != std.os.linux.geteuid() or parent_stat.mode & 0o022 != 0) return error.UnsafePermissions;
        // Closing any descriptor for this inode releases the process's POSIX
        // locks, including locks held by SQLite on another descriptor. Inspect
        // existing files without opening them; create only absent files, before
        // SQLite owns any locks. Never manually close an existing database FD.
        const stat = std.posix.fstatat(std.posix.AT.FDCWD, path, std.posix.AT.SYMLINK_NOFOLLOW) catch |failure| blk: {
            if (failure != error.FileNotFound) return error.OpenFailed;
            const created = std.posix.open(path, .{ .ACCMODE = .RDWR, .CREAT = true, .EXCL = true, .CLOEXEC = true, .NOFOLLOW = true }, 0o600) catch return error.OpenFailed;
            defer std.posix.close(created);
            break :blk std.posix.fstat(created) catch return error.OpenFailed;
        };
        if (!std.posix.S.ISREG(stat.mode) or stat.mode & 0o077 != 0 or stat.uid != std.os.linux.geteuid())
            return error.UnsafePermissions;
        const api = embedded_api;
        const filename = allocator.dupeZ(u8, path) catch return error.OutOfMemory;
        defer allocator.free(filename);
        var db: ?*Db = null;
        const opened = api.open(filename, &db, 2 | 0x10000 | 0x01000000, null);
        if (opened != 0 or db == null) {
            if (db) |handle| _ = api.close(handle);
            return if (opened != 0) sqliteError(opened) else error.OpenFailed;
        }
        var self = Store{ .allocator = allocator, .api = api, .db = db.? };
        errdefer _ = self.api.close(self.db);
        // A rejected database is not ours to checkpoint, including implicitly
        // when SQLite closes its last connection after reading a foreign WAL.
        const db_config = @extern(*const fn (*Db, c_int, ...) callconv(.c) c_int, .{ .name = "sqlite3_db_config" });
        try self.check(db_config(self.db, 1006, @as(c_int, 1), @as(?*c_int, null))); // NO_CKPT_ON_CLOSE
        // Bind preflight to SQLite's actual file before any schema/WAL mutation.
        // HAS_MOVED also catches a swap-back between open and pathname recheck.
        const selected = std.posix.fstatat(std.posix.AT.FDCWD, path, std.posix.AT.SYMLINK_NOFOLLOW) catch return error.OpenFailed;
        if (selected.dev != stat.dev or selected.ino != stat.ino or selected.uid != stat.uid or selected.mode != stat.mode) return error.OpenFailed;
        const file_control = @extern(*const fn (*Db, ?[*:0]const u8, c_int, ?*anyopaque) callconv(.c) c_int, .{ .name = "sqlite3_file_control" });
        var moved: c_int = 1;
        try self.check(file_control(self.db, "main", 20, &moved)); // SQLITE_FCNTL_HAS_MOVED
        if (moved != 0) return error.OpenFailed;
        _ = api.limit(self.db, 0, Limits.sqlite_row_bytes); // SQLITE_LIMIT_LENGTH
        if (api.limit(self.db, 0, -1) != Limits.sqlite_row_bytes) return error.StorageLimit;
        try self.check(api.busy_timeout(self.db, 1000));
        // During opening this local Store is stable. Remove its callback before
        // returning by value; the coordinator reinstalls it at its final address.
        const progress = @extern(*const fn (*Db, c_int, ?*const fn (?*anyopaque) callconv(.c) c_int, ?*anyopaque) callconv(.c) void, .{ .name = "sqlite3_progress_handler" });
        defer if (runtime) progress(self.db, 0, null, null);
        if (runtime) {
            self.runtime_path = path;
            configureHeapLimit();
            self.runtime_limits = true;
            progress(self.db, 1000, workProgress, &self);
        }
        try self.exec("PRAGMA trusted_schema=OFF;");
        const application = try self.integer("PRAGMA application_id;");
        const schema = try self.integer("PRAGMA user_version;");
        if (application == 0) {
            if (schema != 0 or try self.integer("SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%';") != 0) return error.ForeignDatabase;
        } else if (application != 0x46325a31) return error.ForeignDatabase;
        if (schema < 0 or schema > latest_schema) return error.UnsupportedSchema;
        self.schema_version = @max(schema, 2);
        // Only an admitted application/schema may change database limits or WAL.
        if (runtime) {
            try self.configureRuntimeLimits();
            try self.maintainWal(path);
        }
        try self.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;");
        {
            var mode = try self.statement("PRAGMA journal_mode;");
            defer mode.deinit();
            if (!try mode.row() or !std.mem.eql(u8, try mode.bytes(0), "wal") or try self.integer("PRAGMA synchronous;") != 2)
                return error.DatabaseFailure;
        }
        try self.beginWrite();
        self.exec(
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
        self.commitTransaction() catch |err| {
            self.rollback();
            return err;
        };
        try self.check(db_config(self.db, 1006, @as(c_int, 0), @as(?*c_int, null)));
        if (runtime) self.runtime_limits = false;
        return self;
    }

    /// Explicit native admission; ordinary open does not upgrade a schema-2
    /// database to receipt storage. No worker checkpoint conversion is implied.
    /// The caller budgets one pending row per admitted source before activation.
    pub fn enableReceipts(self: *Store, maximum_pending: usize) Error!void {
        if (maximum_pending == 0 or maximum_pending > Limits.pending_receipts) return error.ReceiptLimit;
        try self.beginWrite();
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
        try self.commitTransaction();
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
        try self.beginWrite();
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
        try self.commitTransaction();
        self.schema_version = @max(schema, 4);
    }

    /// Explicit opt-in preserves inference provenance. Ordinary schema-4 opens
    /// and native-time admission never silently enable this migration.
    pub fn enableYearInference(self: *Store) Error!void {
        if (self.receipt_limit == null) return error.ReceiptStorageRequired;
        try self.beginWrite();
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema == 4) {
            try self.exec("ALTER TABLE records ADD COLUMN inferred_year INTEGER CHECK(inferred_year IS NULL OR (typeof(inferred_year)='integer' AND inferred_year BETWEEN 1 AND 9999 AND original_us IS NOT NULL AND native_time_kind IN (1,3,4,6,11))); PRAGMA user_version=5;");
        } else if (schema < 5 or schema > latest_schema) return error.UnsupportedSchema;
        try self.fault(.before_inference_schema_commit);
        try self.commitTransaction();
        self.schema_version = @max(schema, 5);
    }

    /// Explicit native detection admission. A schema-4 upgrade adds inference
    /// provenance and detection rows in ONE transaction; failure leaves schema 4.
    /// Merely opening a prior store or enabling time never admits detection.
    pub fn enableDetection(self: *Store) Error!void {
        if (self.receipt_limit == null) return error.ReceiptStorageRequired;
        try self.beginWrite();
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
        try self.commitTransaction();
        self.schema_version = @max(schema, 6);
    }

    /// Explicit startup migration. The scan of old receipts happens once while
    /// no ingestion is admitted, never in the record-processing loop. The floor
    /// survives later ledger retention and does not replace any event timestamp.
    pub fn enableClockRecovery(self: *Store) Error!void {
        if (self.receipt_limit == null) return error.ReceiptStorageRequired;
        try self.beginWrite();
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
        try self.commitTransaction();
        self.schema_version = @max(schema, 7);
    }

    /// Explicit schema-7 admission for typed journal-origin exclusions. Preserve
    /// all previous detection rows and the durable clock floor atomically.
    pub fn enableJournalDetection(self: *Store) Error!void {
        if (self.receipt_limit == null) return error.ReceiptStorageRequired;
        try self.beginWrite();
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
        try self.commitTransaction();
        self.schema_version = @max(schema, 8);
    }

    /// Explicit admission; opening a schema-8 database does not upgrade it.
    pub fn enableRetry(self: *Store) Error!void {
        if (self.receipt_limit == null) return error.ReceiptStorageRequired;
        try self.beginWrite();
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
        try self.commitTransaction();
        self.schema_version = @max(schema, 9);
    }

    /// Add typed native consumer rows without activating any new consumer. The
    /// coordinator still admits the exact required consumer set and generation.
    pub fn enableConsumers(self: *Store) Error!void {
        try self.beginWrite();
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 9 or schema > latest_schema) return error.UnsupportedSchema;
        if (schema == 9) try self.exec(
            \\CREATE TABLE consumer_checkpoints(kind INTEGER NOT NULL CHECK(typeof(kind)='integer' AND kind BETWEEN 1 AND 5),jail TEXT NOT NULL,source TEXT NOT NULL,rule TEXT NOT NULL,generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=32),format INTEGER NOT NULL CHECK(typeof(format)='integer' AND format BETWEEN 1 AND 65535),revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision>0),payload BLOB NOT NULL CHECK(typeof(payload)='blob' AND length(payload)<=65536),valid_until_us INTEGER CHECK(valid_until_us IS NULL OR typeof(valid_until_us)='integer'),PRIMARY KEY(kind,jail,source,rule,generation));
            \\CREATE TABLE consumer_clock(id INTEGER PRIMARY KEY CHECK(id=1),floor_us INTEGER CHECK(floor_us IS NULL OR typeof(floor_us)='integer'));
            \\INSERT INTO consumer_clock VALUES(1,NULL);
            \\PRAGMA user_version=10;
        );
        try self.fault(.before_consumer_schema_commit);
        try self.commitTransaction();
        self.schema_version = @max(schema, 10);
    }

    /// Explicit schema12 admission preserves old scalar rows at ordinal zero.
    pub fn enableConsumerManifests(self: *Store) Error!void {
        try self.beginWrite();
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 11 or schema > latest_schema) return error.UnsupportedSchema;
        if (schema == 11) try self.exec(
            \\CREATE TABLE record_detections_v12(
            \\jail TEXT NOT NULL,source TEXT NOT NULL,occurrence TEXT NOT NULL,ordinal INTEGER NOT NULL CHECK(typeof(ordinal)='integer' AND ordinal BETWEEN 0 AND 15),
            \\version INTEGER NOT NULL CHECK(typeof(version)='integer' AND version=1),
            \\kind INTEGER NOT NULL CHECK(typeof(kind)='integer' AND kind BETWEEN 1 AND 12),
            \\generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=32),
            \\filter TEXT NOT NULL CHECK(typeof(filter)='text' AND length(filter) BETWEEN 1 AND 64),
            \\pattern TEXT CHECK(pattern IS NULL OR (typeof(pattern)='text' AND length(pattern) BETWEEN 1 AND 64)),
            \\pattern_index INTEGER CHECK(pattern_index IS NULL OR (typeof(pattern_index)='integer' AND pattern_index BETWEEN 0 AND 65535)),
            \\family INTEGER CHECK(family IS NULL OR (typeof(family)='integer' AND family IN (4,6))),
            \\subject BLOB CHECK(subject IS NULL OR (typeof(subject)='blob' AND ((family=4 AND length(subject)=4) OR (family=6 AND length(subject)=16)))),
            \\CHECK(((kind<=3 OR kind>=7) AND pattern IS NULL AND pattern_index IS NULL AND family IS NULL AND subject IS NULL) OR (kind BETWEEN 4 AND 6 AND pattern IS NOT NULL AND pattern_index IS NOT NULL AND family IS NOT NULL AND subject IS NOT NULL)),
            \\PRIMARY KEY(jail,source,occurrence,ordinal),FOREIGN KEY(jail,source,occurrence) REFERENCES records(jail,source,occurrence));
            \\INSERT INTO record_detections_v12 SELECT jail,source,occurrence,0,version,kind,generation,filter,pattern,pattern_index,family,subject FROM record_detections;
            \\DROP TABLE record_detections;
            \\ALTER TABLE record_detections_v12 RENAME TO record_detections;
            \\CREATE TABLE retry_decisions_v12(jail TEXT NOT NULL,source TEXT NOT NULL,occurrence TEXT NOT NULL,family INTEGER NOT NULL CHECK(typeof(family)='integer' AND family IN (4,6)),subject BLOB NOT NULL CHECK(typeof(subject)='blob' AND length(subject)=CASE family WHEN 4 THEN 4 ELSE 16 END),decided_us INTEGER NOT NULL CHECK(typeof(decided_us)='integer'),expiry_us INTEGER NOT NULL CHECK(typeof(expiry_us)='integer' AND expiry_us>decided_us),ordinal INTEGER NOT NULL CHECK(typeof(ordinal)='integer' AND ordinal>0),enforce INTEGER NOT NULL CHECK(typeof(enforce)='integer' AND enforce IN (0,1)),PRIMARY KEY(jail,source,occurrence,family,subject),FOREIGN KEY(jail,source,occurrence) REFERENCES records(jail,source,occurrence));
            \\INSERT INTO retry_decisions_v12 SELECT * FROM retry_decisions;
            \\DROP TABLE retry_decisions;
            \\ALTER TABLE retry_decisions_v12 RENAME TO retry_decisions;
            \\CREATE TABLE consumer_manifests(jail TEXT NOT NULL,source TEXT NOT NULL,generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=32),digest BLOB NOT NULL CHECK(typeof(digest)='blob' AND length(digest)=32),ready INTEGER NOT NULL CHECK(typeof(ready)='integer' AND ready IN(0,1)),required_count INTEGER NOT NULL CHECK(typeof(required_count)='integer' AND required_count BETWEEN 0 AND 16),PRIMARY KEY(jail,source));
            \\CREATE TABLE consumer_requirements(manifest_jail TEXT NOT NULL,manifest_source TEXT NOT NULL,kind INTEGER NOT NULL,jail TEXT NOT NULL,source TEXT NOT NULL,rule TEXT NOT NULL,generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=32),format INTEGER NOT NULL CHECK(typeof(format)='integer' AND format BETWEEN 1 AND 65535),PRIMARY KEY(manifest_jail,manifest_source,kind,jail,source,rule,generation),FOREIGN KEY(manifest_jail,manifest_source) REFERENCES consumer_manifests(jail,source));
            \\CREATE INDEX consumer_requirement_identity ON consumer_requirements(kind,jail,source,rule,generation,format);
            \\CREATE TABLE consumer_revision(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision>=0));
            \\INSERT INTO consumer_revision VALUES(1,0);
            \\PRAGMA user_version=12;
        );
        try self.fault(.before_manifest_schema_commit);
        try self.commitTransaction();
        self.schema_version = @max(schema, 12);
    }

    /// Establish one persistent append order before any history consumer exists.
    /// The trigger appends only for a newly inserted confirmed event, in the same
    /// transaction as its qualified effect receipt. Reconciliation dedup adds none.
    pub fn enableConfirmedHistory(self: *Store) Error!void {
        try self.beginWrite();
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 12 or schema > latest_schema) return error.UnsupportedSchema;
        if (schema == 12) {
            if (try self.integer("SELECT count(*) FROM confirmed_effect_events;") > effects.max_confirmed_events) return error.EffectCapacity;
            if (try self.integer("SELECT EXISTS(SELECT 1 FROM consumer_checkpoints WHERE kind=5) OR EXISTS(SELECT 1 FROM consumer_requirements WHERE kind=5);") != 0) return error.ConsumerMigrationRequired;
            try self.exec(
                \\CREATE TABLE confirmed_history_stream(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision>=0 AND revision<9223372036854775807),head INTEGER NOT NULL CHECK(typeof(head)='integer' AND head>=0 AND head<9223372036854775807),retained_from INTEGER NOT NULL CHECK(typeof(retained_from)='integer' AND retained_from>=1 AND retained_from<=head+1));
                \\INSERT INTO confirmed_history_stream VALUES(1,1,0,1);
                \\CREATE TABLE confirmed_history_sequence(sequence INTEGER PRIMARY KEY CHECK(sequence>0),event_id BLOB UNIQUE NOT NULL CHECK(typeof(event_id)='blob' AND length(event_id)=32),FOREIGN KEY(event_id) REFERENCES confirmed_effect_events(event_id));
                \\INSERT INTO confirmed_history_sequence SELECT row_number() OVER(ORDER BY confirmed_us,event_id),event_id FROM confirmed_effect_events;
                \\UPDATE confirmed_history_stream SET head=(SELECT count(*) FROM confirmed_history_sequence),revision=1+(SELECT count(*) FROM confirmed_history_sequence) WHERE id=1;
                \\CREATE TRIGGER confirmed_history_append AFTER INSERT ON confirmed_effect_events BEGIN SELECT CASE WHEN (SELECT count(*) FROM confirmed_history_stream WHERE id=1)!=1 THEN RAISE(ABORT,'missing confirmed history stream') END; UPDATE confirmed_history_stream SET head=head+1,revision=revision+1 WHERE id=1; INSERT INTO confirmed_history_sequence SELECT head,NEW.event_id FROM confirmed_history_stream WHERE id=1; END;
                \\PRAGMA user_version=13;
            );
        }
        try self.fault(.before_consumer_input_commit);
        try self.commitTransaction();
        self.schema_version = @max(schema, 13);
    }

    /// Schema admission only. Legacy records retain NULL ordering and stay pinned.
    /// No cleanup marker, guard, record deletion or inferred ordering is created.
    pub fn enableMaintenance(self: *Store) Error!void {
        try self.beginWrite();
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 13 or schema > latest_schema) return error.UnsupportedSchema;
        if (schema == 13) try self.exec(
            \\CREATE TABLE source_maintenance(jail TEXT NOT NULL,source TEXT NOT NULL,generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=32),head_sequence INTEGER NOT NULL CHECK(typeof(head_sequence)='integer' AND head_sequence>=1 AND head_sequence<9223372036854775807),reject_below_sequence INTEGER NOT NULL CHECK(typeof(reject_below_sequence)='integer' AND reject_below_sequence>=1 AND reject_below_sequence<=head_sequence+1),cleanup_revision INTEGER NOT NULL CHECK(typeof(cleanup_revision)='integer' AND cleanup_revision>=0),sweep_sequence INTEGER NOT NULL CHECK(typeof(sweep_sequence)='integer' AND sweep_sequence>=0 AND sweep_sequence<reject_below_sequence),PRIMARY KEY(jail,source,generation));
            \\ALTER TABLE records ADD COLUMN source_generation BLOB;
            \\ALTER TABLE records ADD COLUMN source_sequence INTEGER;
            \\CREATE UNIQUE INDEX records_source_order ON records(jail,source,source_generation,source_sequence) WHERE source_sequence IS NOT NULL;
            \\CREATE TRIGGER records_source_order_insert BEFORE INSERT ON records WHEN NOT ((NEW.source_generation IS NULL AND NEW.source_sequence IS NULL) OR (typeof(NEW.source_generation)='blob' AND length(NEW.source_generation)=32 AND typeof(NEW.source_sequence)='integer' AND NEW.source_sequence>0)) BEGIN SELECT RAISE(ABORT,'invalid source order'); END;
            \\CREATE TRIGGER records_source_order_update BEFORE UPDATE OF source_generation,source_sequence ON records WHEN NOT ((NEW.source_generation IS NULL AND NEW.source_sequence IS NULL) OR (typeof(NEW.source_generation)='blob' AND length(NEW.source_generation)=32 AND typeof(NEW.source_sequence)='integer' AND NEW.source_sequence>0)) BEGIN SELECT RAISE(ABORT,'invalid source order'); END;
            \\CREATE TABLE replay_guards(jail TEXT NOT NULL,source TEXT NOT NULL,generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=32),occurrence_key BLOB NOT NULL CHECK(typeof(occurrence_key)='blob' AND length(occurrence_key)=32),identity_key BLOB NOT NULL CHECK(typeof(identity_key)='blob' AND length(identity_key)=32),receipt_us INTEGER CHECK(receipt_us IS NULL OR typeof(receipt_us)='integer'),source_sequence INTEGER NOT NULL CHECK(typeof(source_sequence)='integer' AND source_sequence>0),PRIMARY KEY(jail,source,generation,occurrence_key),UNIQUE(jail,source,occurrence_key),UNIQUE(jail,source,generation,source_sequence),FOREIGN KEY(jail,source,generation) REFERENCES source_maintenance(jail,source,generation));
            \\PRAGMA user_version=14;
        );
        try self.fault(.before_maintenance_schema_commit);
        try self.commitTransaction();
        self.schema_version = @max(schema, 14);
    }

    pub const SourceMaintenance = struct {
        head_sequence: u64,
        reject_below_sequence: u64,
        cleanup_revision: u64,
        sweep_sequence: u64,
    };
    pub const RecordSequence = struct { generation: [32]u8, sequence: u64 };
    fn maintenanceKey(jail: []const u8, source: []const u8) Error!void {
        if (jail.len == 0 or jail.len > 4096 or source.len == 0 or source.len > Limits.source_bytes or
            std.mem.indexOfScalar(u8, jail, 0) != null or std.mem.indexOfScalar(u8, source, 0) != null) return error.InvalidRecord;
    }
    /// One detached typed point read; no cursor text or receipt time defines order.
    pub fn sourceMaintenance(self: *Store, jail: []const u8, source: []const u8, generation: [32]u8) Error!?SourceMaintenance {
        try maintenanceKey(jail, source);
        if (self.schema_version < 14) return error.MaintenanceStorageRequired;
        var row = try self.statement("SELECT head_sequence,reject_below_sequence,cleanup_revision,sweep_sequence FROM source_maintenance WHERE jail=?1 AND source=?2 AND generation=?3;");
        defer row.deinit();
        try row.text(1, jail);
        try row.text(2, source);
        try row.blob(3, &generation);
        if (!try row.row()) return null;
        const head = try row.signed(0);
        const floor = try row.signed(1);
        const revision_value = try row.signed(2);
        const sweep = try row.signed(3);
        if (head < 1 or head == std.math.maxInt(i64) or floor < 1 or floor > head + 1 or revision_value < 0 or sweep < 0 or sweep >= floor) return error.InvalidMaintenanceState;
        return .{ .head_sequence = @intCast(head), .reject_below_sequence = @intCast(floor), .cleanup_revision = @intCast(revision_value), .sweep_sequence = @intCast(sweep) };
    }
    pub fn recordSequence(self: *Store, jail: []const u8, source: []const u8, occurrence: []const u8) Error!?RecordSequence {
        try maintenanceKey(jail, source);
        if (occurrence.len == 0 or occurrence.len > 16384) return error.InvalidRecord;
        if (self.schema_version < 14) return error.MaintenanceStorageRequired;
        var row = try self.statement("SELECT source_generation,source_sequence FROM records WHERE jail=?1 AND source=?2 AND occurrence=?3;");
        defer row.deinit();
        try row.text(1, jail);
        try row.text(2, source);
        try row.text(3, occurrence);
        if (!try row.row()) return null;
        const generation_null = self.api.column_type(row.ptr, 0) == 5;
        const sequence_null = self.api.column_type(row.ptr, 1) == 5;
        if (generation_null and sequence_null) return null;
        if (generation_null or sequence_null) return error.InvalidMaintenanceState;
        const generation = try effectBlob(&row, 0, 32);
        const sequence = try row.signed(1);
        const state = try self.sourceMaintenance(jail, source, generation) orelse return error.InvalidMaintenanceState;
        if (sequence <= 0 or sequence > state.head_sequence) return error.InvalidMaintenanceState;
        return .{ .generation = generation, .sequence = @intCast(sequence) };
    }
    fn recordGeneration(record: *const Record) Error!?[32]u8 {
        var result: ?[32]u8 = if (record.receipt) |value| value.generation else null;
        const other = [_]?[32]u8{ if (record.native_retry) |value| value.generation else null, if (record.consumer_manifest) |value| value.source_generation else null };
        for (other) |candidate| if (candidate) |value| {
            if (result) |known| if (!std.mem.eql(u8, &known, &value)) return error.OccurrenceConflict;
            result = value;
        };
        return result;
    }
    fn advanceSourceSequence(self: *Store, record: *const Record, generation: [32]u8) Error!u64 {
        if (self.schema_version >= 15) _ = try self.maintenanceRevision();
        const old = try self.sourceMaintenance(record.jail, record.source, generation);
        if (old == null) {
            // A missing head is corruption once any ordered detail/guard exists.
            var retained = try self.statement("SELECT 1 FROM records WHERE jail=?1 AND source=?2 AND source_generation=?3 AND source_sequence IS NOT NULL UNION ALL SELECT 1 FROM replay_guards WHERE jail=?1 AND source=?2 AND generation=?3 LIMIT 1;");
            defer retained.deinit();
            try retained.text(1, record.jail);
            try retained.text(2, record.source);
            try retained.blob(3, &generation);
            if (try retained.row()) return error.InvalidMaintenanceState;
        }
        const prior: u64 = if (old) |value| value.head_sequence else 0;
        if (old != null) {
            // Detail and guards have separate unique indexes. Validate their
            // shared durable high-water mark before allocating another sequence.
            var maximum: u64 = 0;
            for ([_][:0]const u8{
                "SELECT source_sequence FROM records WHERE jail=?1 AND source=?2 AND source_generation=?3 AND source_sequence IS NOT NULL ORDER BY source_sequence DESC LIMIT 1;",
                "SELECT source_sequence FROM replay_guards WHERE jail=?1 AND source=?2 AND generation=?3 ORDER BY source_sequence DESC LIMIT 1;",
            }) |query| {
                var retained = try self.statement(query);
                defer retained.deinit();
                try retained.text(1, record.jail);
                try retained.text(2, record.source);
                try retained.blob(3, &generation);
                if (try retained.row()) {
                    const sequence = try retained.signed(0);
                    if (sequence <= 0) return error.InvalidMaintenanceState;
                    maximum = @max(maximum, @as(u64, @intCast(sequence)));
                }
            }
            if (maximum != prior) return error.InvalidMaintenanceState;
        }
        if (prior >= std.math.maxInt(i64) - 1) return error.StorageLimit;
        const next = prior + 1;
        var row = try self.statement("INSERT INTO source_maintenance VALUES(?1,?2,?3,?4,1,0,0) ON CONFLICT(jail,source,generation) DO UPDATE SET head_sequence=excluded.head_sequence WHERE source_maintenance.head_sequence=?5;");
        defer row.deinit();
        try row.text(1, record.jail);
        try row.text(2, record.source);
        try row.blob(3, &generation);
        try row.int(4, @intCast(next));
        try row.int(5, @intCast(prior));
        try row.done();
        if (self.api.changes(self.db) != 1) return error.InvalidMaintenanceState;
        var detail = try self.statement("UPDATE records SET source_generation=?4,source_sequence=?5 WHERE jail=?1 AND source=?2 AND occurrence=?3 AND source_generation IS NULL AND source_sequence IS NULL;");
        defer detail.deinit();
        try detail.text(1, record.jail);
        try detail.text(2, record.source);
        try detail.text(3, record.occurrence);
        try detail.blob(4, &generation);
        try detail.int(5, @intCast(next));
        try detail.done();
        if (self.api.changes(self.db) != 1) return error.InvalidMaintenanceState;
        try self.fault(.after_source_sequence);
        return next;
    }
    fn occurrenceGuardKey(occurrence: []const u8) [32]u8 {
        return effects.hashParts("fail2zig-replay-occurrence-v1", &.{occurrence});
    }
    fn identityGuardKey(identity: ReceiptIdentity) [32]u8 {
        return effects.hashParts("fail2zig-replay-identity-v1", &.{ identity.jail, identity.source, &identity.generation, identity.occurrence, &identity.raw_hash, identity.cursor });
    }
    /// Absence permits normal lookup. Any existing guard prevents replay even
    /// while its marked detail is still present. Guards are never reset/evicted.
    fn checkReplayGuard(self: *Store, jail: []const u8, source: []const u8, occurrence: []const u8, raw_hash: [32]u8, cursor: []const u8, supplied_generation: ?[32]u8, receipt_us: ?i64) Error!void {
        if (self.schema_version < 14) {
            const schema = try self.integer("PRAGMA user_version;");
            if (schema > latest_schema) return error.UnsupportedSchema;
            if (schema < 14) return;
            self.schema_version = schema;
        }
        try maintenanceKey(jail, source);
        if (occurrence.len == 0 or occurrence.len > 16384 or cursor.len == 0 or cursor.len > Limits.cursor_bytes) return error.InvalidRecord;
        const occurrence_key = occurrenceGuardKey(occurrence);
        var row = try self.statement("SELECT generation,identity_key,receipt_us,source_sequence FROM replay_guards WHERE jail=?1 AND source=?2 AND occurrence_key=?3;");
        defer row.deinit();
        try row.text(1, jail);
        try row.text(2, source);
        try row.blob(3, &occurrence_key);
        if (!try row.row()) return;
        const generation = try effectBlob(&row, 0, 32);
        const saved_identity = try effectBlob(&row, 1, 32);
        const original_receipt = try row.optionalSigned(2);
        const sequence = try row.signed(3);
        const state = try self.sourceMaintenance(jail, source, generation) orelse return error.InvalidMaintenanceState;
        if (sequence <= 0 or sequence > state.head_sequence) return error.InvalidMaintenanceState;
        const expected_identity = identityGuardKey(.{ .jail = jail, .source = source, .occurrence = occurrence, .raw_hash = raw_hash, .cursor = cursor, .generation = generation });
        if (!std.mem.eql(u8, &expected_identity, &saved_identity)) return error.OccurrenceConflict;
        if (supplied_generation) |wanted| if (!std.mem.eql(u8, &wanted, &generation)) return error.OccurrenceConflict;
        if (receipt_us) |wanted| if (original_receipt == null or original_receipt.? != wanted) return error.OccurrenceConflict;
        return error.PrunedReplay;
    }
    /// Test-only seed of the future marker's guard insert. No production marking
    /// or deletion API exists until reference/watermark validation is integrated.
    pub fn fixtureReplayGuard(self: *Store, jail: []const u8, source: []const u8, occurrence: []const u8) Error!void {
        if (!builtin.is_test) @compileError("fixtureReplayGuard is test-only");
        try self.beginWrite();
        errdefer self.rollback();
        const position = try self.recordSequence(jail, source, occurrence) orelse return error.InvalidMaintenanceState;
        var row = try self.statement("SELECT raw_hash,cursor,receipt_us,receipt_generation FROM records WHERE jail=?1 AND source=?2 AND occurrence=?3;");
        defer row.deinit();
        try row.text(1, jail);
        try row.text(2, source);
        try row.text(3, occurrence);
        if (!try row.row()) return error.InvalidMaintenanceState;
        const identity = ReceiptIdentity{ .jail = jail, .source = source, .occurrence = occurrence, .raw_hash = try effectBlob(&row, 0, 32), .cursor = try row.boundedBytes(1, Limits.cursor_bytes), .generation = position.generation };
        const receipt = try row.optionalSigned(2);
        if (receipt != null and !std.mem.eql(u8, &try effectBlob(&row, 3, 32), &position.generation)) return error.InvalidMaintenanceState;
        const occurrence_key = occurrenceGuardKey(occurrence);
        const identity_key = identityGuardKey(identity);
        var insert = try self.statement("INSERT INTO replay_guards VALUES(?1,?2,?3,?4,?5,?6,?7);");
        defer insert.deinit();
        try insert.text(1, jail);
        try insert.text(2, source);
        try insert.blob(3, &position.generation);
        try insert.blob(4, &occurrence_key);
        try insert.blob(5, &identity_key);
        if (receipt) |value| try insert.int(6, value);
        try insert.int(7, @intCast(position.sequence));
        try insert.done();
        try self.fault(.after_replay_guard);
        try self.commitTransaction();
    }

    /// Explicit production cleanup admission. Replay guards are never reclaimed.
    pub fn enableCleanup(self: *Store) Error!void {
        try self.beginWrite();
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 14 or schema > latest_schema) return error.UnsupportedSchema;
        if (schema == 14) try self.exec(
            \\CREATE TABLE maintenance_clock(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision>=0),floor_us INTEGER CHECK(floor_us IS NULL OR typeof(floor_us)='integer'));
            \\INSERT INTO maintenance_clock VALUES(1,0,NULL);
            \\CREATE TABLE retry_retired(jail TEXT NOT NULL,family INTEGER NOT NULL CHECK(family IN (4,6)),subject BLOB NOT NULL CHECK(typeof(subject)='blob' AND length(subject)=CASE family WHEN 4 THEN 4 ELSE 16 END),generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=32),last_processed_us INTEGER NOT NULL CHECK(typeof(last_processed_us)='integer'),decisions INTEGER NOT NULL CHECK(typeof(decisions)='integer' AND decisions>=0),PRIMARY KEY(jail,family,subject),FOREIGN KEY(jail) REFERENCES retry_policies(jail));
            \\CREATE TABLE retry_retired_totals(jail TEXT PRIMARY KEY,total INTEGER NOT NULL CHECK(typeof(total)='integer' AND total>=0),FOREIGN KEY(jail) REFERENCES retry_policies(jail));
            \\CREATE TRIGGER maintenance_source_insert AFTER INSERT ON source_maintenance BEGIN UPDATE maintenance_clock SET revision=revision+1 WHERE id=1; END;
            \\CREATE TRIGGER maintenance_source_update AFTER UPDATE ON source_maintenance BEGIN UPDATE maintenance_clock SET revision=revision+1 WHERE id=1; END;
            \\CREATE INDEX effect_owners_jail ON effect_owners(jail,scope_key);
            \\PRAGMA user_version=15;
        );
        try self.fault(.before_cleanup_schema_commit);
        try self.commitTransaction();
        self.schema_version = @max(schema, 15);
    }
    pub const CleanupFence = struct {
        jail: []const u8,
        source: []const u8,
        generation: [32]u8,
        jail_revision: u64,
        consumer_revision: u64,
        effect_revision: u64,
        history: ?effect_history.PageToken = null,
        manifest: ?consumers.Manifest = null,
        clock: effects.Clock,
        /// Caller has released ALL candidate receipts and consumer preparations
        /// for this jail on the serialized worker. SQL independently checks pins.
        preparations: enum { held, released } = .held,
    };
    pub const CleanupToken = struct { binding: [32]u8, state: SourceMaintenance };
    pub const CleanupProgress = struct { deleted_rows: u8, more: bool, state: SourceMaintenance };
    pub fn maintenanceRevision(self: *Store) Error!u64 {
        if (self.schema_version < 15) return error.MaintenanceStorageRequired;
        var row = try self.statement("SELECT revision FROM maintenance_clock WHERE id=1;");
        defer row.deinit();
        if (!try row.row()) return error.InvalidMaintenanceState;
        const value = try row.signed(0);
        if (value < 0 or value == std.math.maxInt(i64)) return error.InvalidMaintenanceState;
        return @intCast(value);
    }
    pub fn maintenanceConsumerRevision(self: *Store) Error!u64 {
        return self.consumerRevision();
    }
    pub fn cleanupResume(self: *Store, jail: []const u8, source: []const u8, generation: [32]u8) Error!?CleanupToken {
        _ = try self.maintenanceRevision();
        const state = try self.sourceMaintenance(jail, source, generation) orelse return null;
        if (state.sweep_sequence + 1 >= state.reject_below_sequence) return null;
        return .{ .binding = effects.hashParts("fail2zig-cleanup-source-v1", &.{ jail, source, &generation }), .state = state };
    }
    pub fn maintenanceEffectRevision(self: *Store) Error!u64 {
        const value = try self.integer("SELECT revision FROM effect_clock WHERE singleton=1;");
        if (value < 0) return error.InvalidEffect;
        return @intCast(value);
    }
    fn cleanupClock(self: *Store, clock: effects.Clock) Error!i64 {
        const now = clock.read(clock.context);
        if (now < clock.prepared_us) return error.ReceiptClockReversed;
        if (try self.readAdmissionClock(self.schema_version)) |floor| if (now < floor.us) return error.ReceiptClockReversed;
        return now;
    }
    fn finishCleanupClock(self: *Store, clock: effects.Clock, initial: i64) Error!void {
        const now = try self.cleanupClock(clock);
        if (now < initial) return error.ReceiptClockReversed;
        _ = try self.maintenanceRevision();
        var row = try self.statement("UPDATE maintenance_clock SET floor_us=?1,revision=revision+1 WHERE id=1 AND revision<9223372036854775806;");
        defer row.deinit();
        try row.int(1, now);
        try row.done();
        if (self.api.changes(self.db) != 1) return error.StorageLimit;
    }
    fn checkCleanupFence(self: *Store, fence: CleanupFence) Error!i64 {
        _ = try self.maintenanceRevision();
        try maintenanceKey(fence.jail, fence.source);
        if (fence.preparations != .released) return error.MaintenancePinned;
        if (try self.revision(fence.jail) != fence.jail_revision or try self.consumerRevision() != fence.consumer_revision or
            try self.maintenanceEffectRevision() != fence.effect_revision) return error.StaleMaintenance;
        if (try self.readRetryPolicy(fence.jail)) |policy| if (!std.mem.eql(u8, &policy.generation, &fence.generation)) return error.RetryGenerationMismatch;
        var pending = try self.statement("SELECT 1 FROM pending_receipts WHERE jail=?1 LIMIT 1;");
        defer pending.deinit();
        try pending.text(1, fence.jail);
        if (try pending.row()) return error.MaintenancePinned;
        if (try self.manifestExists(fence.jail, fence.source) != (fence.manifest != null)) return error.ConsumerManifestRequired;
        if (fence.manifest) |manifest| {
            if (!std.mem.eql(u8, manifest.jail, fence.jail) or !std.mem.eql(u8, manifest.source, fence.source) or
                !std.mem.eql(u8, &manifest.source_generation, &fence.generation)) return error.ConsumerManifestMismatch;
            if (try self.checkManifest(manifest) != .ready) return error.MissingRequiredConsumer;
            for (manifest.required) |requirement| try self.checkRequiredState(requirement, false);
        }
        if (try self.readInstallation()) |installation| {
            const token = fence.history orelse return error.HistoryGap;
            if (token.after_sequence != token.head_sequence or token.last_sequence != token.head_sequence) return error.HistoryGap;
            try self.validateConfirmedEffectPageTx(token);
            var owner = try effect_history.Consumer.init(installation, effects.hashParts("fail2zig-native-confirmed-history-v1", &.{}));
            const manifest = owner.manifest();
            if (try self.checkManifest(manifest) != .ready) return error.MissingRequiredConsumer;
            try self.checkRequiredState(manifest.required[0], false);
            var row = try self.statement("SELECT payload FROM consumer_checkpoints WHERE kind=?1 AND jail=?2 AND source=?3 AND rule=?4 AND generation=?5;");
            defer row.deinit();
            try bindConsumerKey(&row, &manifest.required[0].key);
            if (!try row.row() or self.api.column_type(row.ptr, 0) != 4) return error.MissingRequiredConsumer;
            const saved = try effect_history.Checkpoint.decode(try row.boundedBytes(0, effect_history.checkpoint_bytes));
            if (saved.last_sequence != token.head_sequence or !std.mem.eql(u8, &saved.installation, &installation.id) or
                !std.mem.eql(u8, &saved.generation, &manifest.source_generation)) return error.HistoryGap;
        } else if (fence.history != null or try self.integer("SELECT EXISTS(SELECT 1 FROM native_effects);") != 0) return error.InvalidEffect;
        return self.cleanupClock(fence.clock);
    }
    fn subjectEffectPinned(self: *Store, subject: detection.Subject) Error!bool {
        const installation = try self.readInstallation() orelse return false;
        const scope = try effects.Scope.host(subject);
        if (try self.readEffect(try scope.key(installation), installation)) |entry| {
            // Conservatively keep detail until the entire physical scope is
            // settled absent, including protection shared with another jail.
            return entry.desired != .absent or entry.status != .absent;
        }
        return false;
    }
    fn recordCleanupPinned(self: *Store, fence: CleanupFence, occurrence: []const u8, now: i64) Error!bool {
        var anchor = try self.statement("SELECT occurrence FROM source_cursors WHERE jail=?1 AND source=?2;");
        defer anchor.deinit();
        try anchor.text(1, fence.jail);
        try anchor.text(2, fence.source);
        if (!try anchor.row() or self.api.column_type(anchor.ptr, 0) != 3) return error.InvalidMaintenanceState;
        if (std.mem.eql(u8, try anchor.boundedBytes(0, 16384), occurrence)) return true;
        var action = try self.statement("SELECT 1 FROM action_intents WHERE jail=?1 AND source=?2 AND occurrence=?3 LIMIT 1;");
        defer action.deinit();
        try action.text(1, fence.jail);
        try action.text(2, fence.source);
        try action.text(3, occurrence);
        if (try action.row()) return true;
        const policy = try self.readRetryPolicy(fence.jail);
        const occurrence_key = retry.occurrenceKey(fence.source, occurrence);
        var detections = try self.statement("SELECT family,subject FROM record_detections WHERE jail=?1 AND source=?2 AND occurrence=?3;");
        defer detections.deinit();
        try detections.text(1, fence.jail);
        try detections.text(2, fence.source);
        try detections.text(3, occurrence);
        var count: usize = 0;
        while (try detections.row()) {
            count += 1;
            if (count > max_native_detections) return error.InvalidRecord;
            if (self.api.column_type(detections.ptr, 0) == 5 and self.api.column_type(detections.ptr, 1) == 5) continue;
            const subject = try self.decodeRetrySubject(&detections, 0, 1);
            if (try self.subjectEffectPinned(subject)) return true;
            if (policy) |admission| if (try self.readRetryState(fence.jail, subject, admission.policy)) |state| {
                for (state.attempts[0..state.count]) |attempt| if (@as(i128, attempt.at_us) >= @as(i128, now) - admission.policy.window_us and std.mem.eql(u8, &attempt.occurrence, &occurrence_key)) return true;
            };
        }
        var decisions: [max_native_detections]retry.Decision = undefined;
        const decision_count = try self.retryDecisions(fence.jail, fence.source, occurrence, &decisions);
        for (decisions[0..decision_count]) |decision| if (decision.expiry_us > now or try self.subjectEffectPinned(decision.subject)) return true;
        return false;
    }
    fn orderRecord(self: *Store, fence: CleanupFence, sequence: u64) Error!Stmt {
        var row = try self.statement("SELECT occurrence,raw_hash,cursor,receipt_us,receipt_generation FROM records WHERE jail=?1 AND source=?2 AND source_generation=?3 AND source_sequence=?4 AND source_sequence IS NOT NULL;");
        errdefer row.deinit();
        try row.text(1, fence.jail);
        try row.text(2, fence.source);
        try row.blob(3, &fence.generation);
        try row.int(4, @intCast(sequence));
        return row;
    }
    fn orderedIdentity(row: *Stmt, fence: CleanupFence) Error!ReceiptIdentity {
        if (row.store.api.column_type(row.ptr, 0) != 3 or row.store.api.column_type(row.ptr, 2) != 4) return error.InvalidMaintenanceState;
        const receipt = try row.optionalSigned(3);
        if (receipt != null) {
            if (!std.mem.eql(u8, &try effectBlob(row, 4, 32), &fence.generation)) return error.InvalidMaintenanceState;
        } else if (row.store.api.column_type(row.ptr, 4) != 5) return error.InvalidMaintenanceState;
        const id = ReceiptIdentity{ .jail = fence.jail, .source = fence.source, .generation = fence.generation, .occurrence = try row.boundedBytes(0, 16384), .raw_hash = try effectBlob(row, 1, 32), .cursor = try row.boundedBytes(2, Limits.cursor_bytes) };
        try validateReceiptIdentity(id);
        return id;
    }
    fn insertReplayGuard(self: *Store, id: ReceiptIdentity, receipt: ?i64, sequence: u64) Error!void {
        const occurrence_key = occurrenceGuardKey(id.occurrence);
        const identity_key = identityGuardKey(id);
        var row = try self.statement("INSERT INTO replay_guards VALUES(?1,?2,?3,?4,?5,?6,?7);");
        defer row.deinit();
        try row.text(1, id.jail);
        try row.text(2, id.source);
        try row.blob(3, &id.generation);
        try row.blob(4, &occurrence_key);
        try row.blob(5, &identity_key);
        if (receipt) |value| try row.int(6, value);
        try row.int(7, @intCast(sequence));
        try row.done();
    }
    fn updateCleanupState(self: *Store, fence: CleanupFence, old: SourceMaintenance, next: SourceMaintenance) Error!void {
        if (old.cleanup_revision >= std.math.maxInt(i64) - 1) return error.StorageLimit;
        var row = try self.statement("UPDATE source_maintenance SET reject_below_sequence=?4,cleanup_revision=?5,sweep_sequence=?6 WHERE jail=?1 AND source=?2 AND generation=?3 AND head_sequence=?7 AND cleanup_revision=?8;");
        defer row.deinit();
        try row.text(1, fence.jail);
        try row.text(2, fence.source);
        try row.blob(3, &fence.generation);
        try row.int(4, @intCast(next.reject_below_sequence));
        try row.int(5, @intCast(next.cleanup_revision));
        try row.int(6, @intCast(next.sweep_sequence));
        try row.int(7, @intCast(old.head_sequence));
        try row.int(8, @intCast(old.cleanup_revision));
        try row.done();
        if (self.api.changes(self.db) != 1) return error.StaleMaintenance;
    }
    pub fn cleanupAdvance(self: *Store, fence: CleanupFence, expected: SourceMaintenance, cutoff_sequence: u64) Error!?CleanupToken {
        try self.beginWrite();
        errdefer self.rollback();
        const now = try self.checkCleanupFence(fence);
        const current = try self.sourceMaintenance(fence.jail, fence.source, fence.generation) orelse return error.InvalidMaintenanceState;
        if (!std.meta.eql(current, expected) or cutoff_sequence > current.head_sequence) return error.StaleMaintenance;
        var next = current;
        var keys: usize = 0;
        var count: usize = 0;
        while (next.reject_below_sequence <= cutoff_sequence and count < 64) : (count += 1) {
            var row = try self.orderRecord(fence, next.reject_below_sequence);
            defer row.deinit();
            if (!try row.row()) return error.InvalidMaintenanceState;
            const id = try orderedIdentity(&row, fence);
            const bytes = id.jail.len + id.source.len + id.occurrence.len + id.cursor.len + 64;
            if (bytes > 1024 * 1024 - keys) break;
            if (try self.recordCleanupPinned(fence, id.occurrence, now)) break;
            try self.insertReplayGuard(id, try row.optionalSigned(3), next.reject_below_sequence);
            keys += bytes;
            next.reject_below_sequence += 1;
        }
        if (next.reject_below_sequence == current.reject_below_sequence) {
            try self.commitTransaction();
            return null;
        }
        next.cleanup_revision = std.math.add(u64, current.cleanup_revision, 1) catch return error.StorageLimit;
        try self.updateCleanupState(fence, current, next);
        try self.fault(.after_cleanup_mark);
        try self.finishCleanupClock(fence.clock, now);
        try self.commitTransaction();
        return .{ .binding = effects.hashParts("fail2zig-cleanup-source-v1", &.{ fence.jail, fence.source, &fence.generation }), .state = next };
    }
    fn countRecordChildren(self: *Store, fence: CleanupFence, occurrence: []const u8, comptime table: []const u8) Error!usize {
        var row = try self.statement("SELECT count(*) FROM " ++ table ++ " WHERE jail=?1 AND source=?2 AND occurrence=?3;");
        defer row.deinit();
        try row.text(1, fence.jail);
        try row.text(2, fence.source);
        try row.text(3, occurrence);
        if (!try row.row()) return error.InvalidMaintenanceState;
        const count = try row.signed(0);
        if (count < 0 or count > max_native_detections) return error.InvalidRecord;
        return @intCast(count);
    }
    pub fn cleanupDelete(self: *Store, fence: CleanupFence, token: CleanupToken) Error!CleanupProgress {
        try self.beginWrite();
        errdefer self.rollback();
        const now = try self.checkCleanupFence(fence);
        const current = try self.sourceMaintenance(fence.jail, fence.source, fence.generation) orelse return error.InvalidMaintenanceState;
        const binding = effects.hashParts("fail2zig-cleanup-source-v1", &.{ fence.jail, fence.source, &fence.generation });
        if (!std.mem.eql(u8, &binding, &token.binding) or !std.meta.eql(current, token.state)) return error.StaleMaintenance;
        var next = current;
        var deleted: usize = 0;
        var keys: usize = 0;
        while (next.sweep_sequence + 1 < next.reject_below_sequence and deleted < 64) {
            var row = try self.orderRecord(fence, next.sweep_sequence + 1);
            defer row.deinit();
            if (!try row.row()) return error.InvalidMaintenanceState;
            const id = try orderedIdentity(&row, fence);
            const bytes = id.jail.len + id.source.len + id.occurrence.len + id.cursor.len + 64;
            if (bytes > 1024 * 1024 - keys) break;
            var guarded = false;
            self.checkReplayGuard(id.jail, id.source, id.occurrence, id.raw_hash, id.cursor, id.generation, try row.optionalSigned(3)) catch |failure| {
                if (failure != error.PrunedReplay) return failure;
                guarded = true;
            };
            if (!guarded) return error.InvalidMaintenanceState;
            if (try self.recordCleanupPinned(fence, id.occurrence, now)) break;
            const group_rows = 1 + try self.countRecordChildren(fence, id.occurrence, "record_detections") + try self.countRecordChildren(fence, id.occurrence, "retry_decisions");
            if (group_rows > 64 - deleted) break;
            // Copy the key before deleting the row that owns SQLite's bytes.
            var occurrence_buffer: [16384]u8 = undefined;
            @memcpy(occurrence_buffer[0..id.occurrence.len], id.occurrence);
            const occurrence = occurrence_buffer[0..id.occurrence.len];
            const deleted_before = deleted;
            inline for (.{ "record_detections", "retry_decisions", "records" }) |table| {
                var remove = try self.statement("DELETE FROM " ++ table ++ " WHERE jail=?1 AND source=?2 AND occurrence=?3;");
                defer remove.deinit();
                try remove.text(1, fence.jail);
                try remove.text(2, fence.source);
                try remove.text(3, occurrence);
                try remove.done();
                const changed = self.api.changes(self.db);
                if (changed < 0 or changed > 64 - deleted) return error.InvalidMaintenanceState;
                deleted += @intCast(changed);
                try self.fault(.after_cleanup_delete);
            }
            if (deleted - deleted_before != group_rows) return error.InvalidMaintenanceState;
            keys += bytes;
            next.sweep_sequence += 1;
        }
        if (deleted != 0) {
            next.cleanup_revision = std.math.add(u64, current.cleanup_revision, 1) catch return error.StorageLimit;
            try self.updateCleanupState(fence, current, next);
            try self.finishCleanupClock(fence.clock, now);
        }
        try self.commitTransaction();
        return .{ .deleted_rows = @intCast(deleted), .more = next.sweep_sequence + 1 < next.reject_below_sequence, .state = next };
    }
    pub const RetryRetirementCandidate = struct { subject: detection.Subject, last_processed_us: i64, decisions: u64 };
    pub fn retryRetirementCandidate(self: *Store, jail: []const u8, after: ?detection.Subject) Error!?RetryRetirementCandidate {
        _ = try self.maintenanceRevision();
        try maintenanceKey(jail, "@retired");
        var row = try self.statement(if (after == null)
            "SELECT family,subject,last_processed_us,decisions FROM retry_states WHERE jail=?1 ORDER BY family,subject LIMIT 1;"
        else
            "SELECT family,subject,last_processed_us,decisions FROM retry_states WHERE jail=?1 AND (family,subject)>(?2,?3) ORDER BY family,subject LIMIT 1;");
        defer row.deinit();
        try row.text(1, jail);
        if (after) |*subject| try bindSubject(&row, subject);
        if (!try row.row()) return null;
        const decisions = try row.signed(3);
        if (decisions < 0) return error.InvalidRetryState;
        return .{ .subject = try self.decodeRetrySubject(&row, 0, 1), .last_processed_us = try row.signed(2), .decisions = @intCast(decisions) };
    }
    fn retiredTotal(self: *Store, jail: []const u8) Error!u64 {
        var row = try self.statement("SELECT total FROM retry_retired_totals WHERE jail=?1;");
        defer row.deinit();
        try row.text(1, jail);
        if (!try row.row()) {
            var retained = try self.statement("SELECT 1 FROM retry_retired WHERE jail=?1 LIMIT 1;");
            defer retained.deinit();
            try retained.text(1, jail);
            if (try retained.row()) return error.InvalidRetryState;
            return 0;
        }
        const total = try row.signed(0);
        if (total < 0) return error.InvalidRetryState;
        return @intCast(total);
    }
    fn changeRetiredTotal(self: *Store, jail: []const u8, decisions: u64, add: bool) Error!void {
        const prior = try self.retiredTotal(jail);
        const next = if (add) std.math.add(u64, prior, decisions) catch return error.StorageLimit else std.math.sub(u64, prior, decisions) catch return error.InvalidRetryState;
        if (next > std.math.maxInt(i64)) return error.StorageLimit;
        var row = try self.statement("INSERT INTO retry_retired_totals VALUES(?1,?2) ON CONFLICT(jail) DO UPDATE SET total=excluded.total;");
        defer row.deinit();
        try row.text(1, jail);
        try row.int(2, @intCast(next));
        try row.done();
    }
    fn readRetired(self: *Store, jail: []const u8, subject: detection.Subject) Error!?retry.State {
        if (self.schema_version < 15) return null;
        var row = try self.statement("SELECT generation,last_processed_us,decisions FROM retry_retired WHERE jail=?1 AND family=?2 AND subject=?3;");
        defer row.deinit();
        try row.text(1, jail);
        try bindSubject(&row, &subject);
        if (!try row.row()) return null;
        const policy = try self.readRetryPolicy(jail) orelse return error.InvalidRetryState;
        if (!std.mem.eql(u8, &try effectBlob(&row, 0, 32), &policy.generation)) return error.InvalidRetryState;
        const decisions = try row.signed(2);
        const last = try row.signed(1);
        if (decisions < 0 or last > ((try self.readRetryClock()) orelse return error.InvalidRetryState)) return error.InvalidRetryState;
        return .{ .last_processed_us = last, .decisions = @intCast(decisions) };
    }
    pub fn retireRetrySubject(self: *Store, fence: CleanupFence, candidate: RetryRetirementCandidate) Error!bool {
        try self.beginWrite();
        errdefer self.rollback();
        const now = try self.checkCleanupFence(fence);
        const admission = try self.readRetryPolicy(fence.jail) orelse return error.RetryAdmissionRequired;
        if (try self.readRetired(fence.jail, candidate.subject) != null) return error.StaleMaintenance;
        const state = try self.readRetryState(fence.jail, candidate.subject, admission.policy) orelse return error.StaleMaintenance;
        if (state.last_processed_us != candidate.last_processed_us or state.decisions != candidate.decisions) return error.StaleMaintenance;
        var pinned = if (state.expiry_us) |expiry| expiry > now else false;
        for (state.attempts[0..state.count]) |attempt| if (@as(i128, attempt.at_us) >= @as(i128, now) - admission.policy.window_us) {
            pinned = true;
        };
        if (pinned or try self.subjectEffectPinned(candidate.subject)) {
            try self.commitTransaction();
            return false;
        }
        try self.changeRetiredTotal(fence.jail, state.decisions, true);
        var saved = try self.statement("INSERT INTO retry_retired VALUES(?1,?2,?3,?4,?5,?6);");
        defer saved.deinit();
        try saved.text(1, fence.jail);
        try bindSubject(&saved, &candidate.subject);
        try saved.blob(4, &fence.generation);
        try saved.int(5, state.last_processed_us);
        try saved.int(6, @intCast(state.decisions));
        try saved.done();
        var remove = try self.statement("DELETE FROM retry_states WHERE jail=?1 AND family=?2 AND subject=?3;");
        defer remove.deinit();
        try remove.text(1, fence.jail);
        try bindSubject(&remove, &candidate.subject);
        try remove.done();
        if (self.api.changes(self.db) != 1) return error.StaleMaintenance;
        var floor = try self.statement("UPDATE retry_clock SET floor_us=?1 WHERE id=1;");
        defer floor.deinit();
        try floor.int(1, now);
        try floor.done();
        if (self.api.changes(self.db) != 1) return error.InvalidRetryState;
        try self.fault(.after_retry_retire);
        try self.finishCleanupClock(fence.clock, now);
        try self.commitTransaction();
        return true;
    }

    /// Fixed owned keyset cursor. One call visits <=16 indexed entries and
    /// <=1MiB identity bytes. Cursor publication follows the read COMMIT.
    pub const MaintenanceValidation = struct {
        phase: enum { headers, records, guards, retired, totals, done } = .headers,
        revision: ?u64 = null,
        data_version: i64 = 0,
        jail: [4096]u8 = undefined,
        jail_len: usize = 0,
        source: [Limits.source_bytes]u8 = undefined,
        source_len: usize = 0,
        generation: [32]u8 = undefined,
        sequence: u64 = 0,
        expected_end: u64 = 0,
        retired_sum: u64 = 0,
        subject: ?detection.Subject = null,
        fn resetKey(self: *MaintenanceValidation) void {
            self.jail_len = 0;
            self.source_len = 0;
            self.subject = null;
            self.sequence = 0;
            self.expected_end = 0;
            self.retired_sum = 0;
        }
        fn setKey(self: *MaintenanceValidation, jail: []const u8, source: []const u8, generation: [32]u8, sequence: u64) void {
            @memcpy(self.jail[0..jail.len], jail);
            self.jail_len = jail.len;
            @memcpy(self.source[0..source.len], source);
            self.source_len = source.len;
            self.generation = generation;
            self.sequence = sequence;
        }
        fn sameSource(self: *const MaintenanceValidation, jail: []const u8, source: []const u8, generation: [32]u8) bool {
            return self.jail_len != 0 and std.mem.eql(u8, self.jail[0..self.jail_len], jail) and
                std.mem.eql(u8, self.source[0..self.source_len], source) and std.mem.eql(u8, &self.generation, &generation);
        }
    };
    fn validateMaintenanceHeader(self: *Store, jail: []const u8, source: []const u8, generation: [32]u8) Error!void {
        const state = try self.sourceMaintenance(jail, source, generation) orelse return error.InvalidMaintenanceState;
        // Separate indexed endpoint seeks. The paged record/guard walks below
        // prove contiguity; aggregates here would scan an unbounded source.
        for ([_][:0]const u8{
            "SELECT source_sequence FROM records WHERE jail=?1 AND source=?2 AND source_generation=?3 AND source_sequence IS NOT NULL ORDER BY source_sequence LIMIT 1;",
            "SELECT source_sequence FROM records WHERE jail=?1 AND source=?2 AND source_generation=?3 AND source_sequence IS NOT NULL ORDER BY source_sequence DESC LIMIT 1;",
            "SELECT source_sequence FROM replay_guards WHERE jail=?1 AND source=?2 AND generation=?3 ORDER BY source_sequence LIMIT 1;",
            "SELECT source_sequence FROM replay_guards WHERE jail=?1 AND source=?2 AND generation=?3 ORDER BY source_sequence DESC LIMIT 1;",
        }, 0..) |query, index| {
            var row = try self.statement(query);
            defer row.deinit();
            try row.text(1, jail);
            try row.text(2, source);
            try row.blob(3, &generation);
            const expected: u64 = switch (index) {
                0 => state.sweep_sequence + 1,
                1 => state.head_sequence,
                2 => 1,
                3 => state.reject_below_sequence - 1,
                else => unreachable,
            };
            const empty = if (index < 2) state.head_sequence == state.sweep_sequence else state.reject_below_sequence == 1;
            if (try row.row()) {
                const value = try row.signed(0);
                if (empty or value <= 0 or value != expected) return error.InvalidMaintenanceState;
            } else if (!empty) return error.InvalidMaintenanceState;
        }
        if ((state.cleanup_revision == 0) != (state.reject_below_sequence == 1 and state.sweep_sequence == 0)) return error.InvalidMaintenanceState;
    }
    pub fn validateMaintenanceTurn(self: *Store, cursor: *MaintenanceValidation) Error!bool {
        if (cursor.jail_len > cursor.jail.len or cursor.source_len > cursor.source.len or cursor.sequence > std.math.maxInt(i64) or
            (cursor.phase == .retired and cursor.jail_len != 0 and cursor.subject == null)) return error.InvalidMaintenanceState;
        try self.beginRead();
        errdefer self.rollback();
        const revision_value = try self.maintenanceRevision();
        const data_version = try self.integer("PRAGMA data_version;");
        var next = cursor.*;
        if (next.revision) |expected| {
            if (expected != revision_value or next.data_version != data_version) return error.StaleMaintenance;
        } else {
            next.revision = revision_value;
            next.data_version = data_version;
        }
        var key_bytes: usize = 0;
        for (0..16) |_| switch (next.phase) {
            .done => break,
            .headers, .records, .guards => {
                const headers = next.phase == .headers;
                const records = next.phase == .records;
                const query: [:0]const u8 = if (headers)
                    (if (next.jail_len == 0) "SELECT jail,source,generation FROM source_maintenance ORDER BY jail,source,generation LIMIT 1;" else "SELECT jail,source,generation FROM source_maintenance WHERE (jail,source,generation)>(?1,?2,?3) ORDER BY jail,source,generation LIMIT 1;")
                else if (records)
                    (if (next.jail_len == 0) "SELECT jail,source,source_generation,source_sequence FROM records WHERE source_sequence IS NOT NULL ORDER BY jail,source,source_generation,source_sequence LIMIT 1;" else "SELECT jail,source,source_generation,source_sequence FROM records WHERE source_sequence IS NOT NULL AND (jail,source,source_generation,source_sequence)>(?1,?2,?3,?4) ORDER BY jail,source,source_generation,source_sequence LIMIT 1;")
                else
                    (if (next.jail_len == 0) "SELECT jail,source,generation,source_sequence,occurrence_key,identity_key,receipt_us FROM replay_guards ORDER BY jail,source,generation,source_sequence LIMIT 1;" else "SELECT jail,source,generation,source_sequence,occurrence_key,identity_key,receipt_us FROM replay_guards WHERE (jail,source,generation,source_sequence)>(?1,?2,?3,?4) ORDER BY jail,source,generation,source_sequence LIMIT 1;");
                var row = try self.statement(query);
                defer row.deinit();
                if (next.jail_len != 0) {
                    try row.text(1, next.jail[0..next.jail_len]);
                    try row.text(2, next.source[0..next.source_len]);
                    try row.blob(3, &next.generation);
                    if (!headers) try row.int(4, @intCast(next.sequence));
                }
                if (!try row.row()) {
                    if (!headers and next.jail_len != 0 and next.sequence != next.expected_end) return error.InvalidMaintenanceState;
                    next.phase = if (headers) .records else if (records) .guards else .retired;
                    next.resetKey();
                    continue;
                }
                if (self.api.column_type(row.ptr, 0) != 3 or self.api.column_type(row.ptr, 1) != 3) return error.InvalidMaintenanceState;
                const jail = try row.boundedBytes(0, 4096);
                const source = try row.boundedBytes(1, Limits.source_bytes);
                const generation = try effectBlob(&row, 2, 32);
                try maintenanceKey(jail, source);
                var sequence: u64 = 0;
                var bytes = jail.len + source.len + 104;
                if (headers) {
                    try self.validateMaintenanceHeader(jail, source, generation);
                } else {
                    const stored_sequence = try row.signed(3);
                    const state = try self.sourceMaintenance(jail, source, generation) orelse return error.InvalidMaintenanceState;
                    const first = if (records) state.sweep_sequence + 1 else 1;
                    const end = if (records) state.head_sequence else state.reject_below_sequence - 1;
                    const same = next.sameSource(jail, source, generation);
                    if (!same and next.jail_len != 0 and next.sequence != next.expected_end) return error.InvalidMaintenanceState;
                    if (stored_sequence <= 0 or stored_sequence != (if (same) next.sequence + 1 else first) or stored_sequence > end) return error.InvalidMaintenanceState;
                    sequence = @intCast(stored_sequence);
                    const fence = CleanupFence{ .jail = jail, .source = source, .generation = generation, .jail_revision = 0, .consumer_revision = 0, .effect_revision = 0, .clock = .{ .prepared_us = 0 } };
                    var detail = try self.orderRecord(fence, sequence);
                    defer detail.deinit();
                    if (try detail.row()) {
                        if (sequence <= state.sweep_sequence) return error.InvalidMaintenanceState;
                        const id = try orderedIdentity(&detail, fence);
                        bytes += id.occurrence.len + id.cursor.len;
                        if (!records and (!std.mem.eql(u8, &try effectBlob(&row, 4, 32), &occurrenceGuardKey(id.occurrence)) or
                            !std.mem.eql(u8, &try effectBlob(&row, 5, 32), &identityGuardKey(id)) or try row.optionalSigned(6) != try detail.optionalSigned(3))) return error.InvalidMaintenanceState;
                    } else {
                        if (records or sequence > state.sweep_sequence) return error.InvalidMaintenanceState;
                        _ = try effectBlob(&row, 4, 32);
                        _ = try effectBlob(&row, 5, 32);
                        _ = try row.optionalSigned(6);
                    }
                    if (bytes > 1024 * 1024 - key_bytes) break;
                    next.expected_end = end;
                }
                if (bytes > 1024 * 1024 - key_bytes) break;
                key_bytes += bytes;
                next.setKey(jail, source, generation, sequence);
            },
            .retired, .totals => {
                const totals = next.phase == .totals;
                var row = try self.statement(if (totals)
                    (if (next.jail_len == 0) "SELECT jail,total FROM retry_retired_totals ORDER BY jail LIMIT 1;" else "SELECT jail,total FROM retry_retired_totals WHERE jail>?1 ORDER BY jail LIMIT 1;")
                else if (next.jail_len == 0)
                    "SELECT jail,family,subject FROM retry_retired ORDER BY jail,family,subject LIMIT 1;"
                else
                    "SELECT jail,family,subject FROM retry_retired WHERE (jail,family,subject)>(?1,?2,?3) ORDER BY jail,family,subject LIMIT 1;");
                defer row.deinit();
                if (next.jail_len != 0) {
                    try row.text(1, next.jail[0..next.jail_len]);
                    if (!totals) try bindSubject(&row, &next.subject.?);
                }
                if (!try row.row()) {
                    if (!totals and next.jail_len != 0 and next.retired_sum != try self.retiredTotal(next.jail[0..next.jail_len])) return error.InvalidRetryState;
                    next.phase = if (totals) .done else .totals;
                    next.resetKey();
                    continue;
                }
                if (self.api.column_type(row.ptr, 0) != 3) return error.InvalidRetryState;
                const jail = try row.boundedBytes(0, 4096);
                try maintenanceKey(jail, "@retired");
                if (totals) {
                    _ = try self.readRetryPolicy(jail) orelse return error.InvalidRetryState;
                    const total = try row.signed(1);
                    if (total < 0) return error.InvalidRetryState;
                    var existing = try self.statement("SELECT 1 FROM retry_retired WHERE jail=?1 LIMIT 1;");
                    defer existing.deinit();
                    try existing.text(1, jail);
                    if (!try existing.row() and total != 0) return error.InvalidRetryState;
                } else {
                    const same = std.mem.eql(u8, next.jail[0..next.jail_len], jail);
                    if (!same) {
                        if (next.jail_len != 0 and next.retired_sum != try self.retiredTotal(next.jail[0..next.jail_len])) return error.InvalidRetryState;
                        next.retired_sum = 0;
                    }
                    const subject = try self.decodeRetrySubject(&row, 1, 2);
                    const state = try self.readRetired(jail, subject) orelse return error.InvalidRetryState;
                    var live = try self.statement("SELECT 1 FROM retry_states WHERE jail=?1 AND family=?2 AND subject=?3;");
                    defer live.deinit();
                    try live.text(1, jail);
                    try bindSubject(&live, &subject);
                    if (try live.row()) return error.InvalidRetryState;
                    next.retired_sum = std.math.add(u64, next.retired_sum, state.decisions) catch return error.InvalidRetryState;
                    next.subject = subject;
                }
                @memcpy(next.jail[0..jail.len], jail);
                next.jail_len = jail.len;
            },
        };
        if (try self.maintenanceRevision() != revision_value or try self.integer("PRAGMA data_version;") != data_version) return error.StaleMaintenance;
        try self.commitTransaction();
        cursor.* = next;
        return next.phase == .done;
    }
    pub fn finishMaintenanceValidation(self: *Store, cursor: *const MaintenanceValidation) Error!void {
        if (cursor.phase != .done or cursor.revision == null or cursor.revision.? != try self.maintenanceRevision() or
            cursor.data_version != try self.integer("PRAGMA data_version;")) return error.StaleMaintenance;
    }

    fn historyHead(self: *Store, installation: effects.Installation, after: u64) Error!effect_history.PageToken {
        if (self.schema_version < 13) return error.ConsumerStorageRequired;
        try installation.validate();
        const admitted = try self.readInstallation() orelse return error.InstallationRequired;
        if (!std.meta.eql(admitted, installation)) return error.InstallationMismatch;
        var row = try self.statement("SELECT revision,head,retained_from FROM confirmed_history_stream WHERE id=1;");
        defer row.deinit();
        if (!try row.row()) return error.HistoryGap;
        const stream_revision = try row.signed(0);
        const head = try row.signed(1);
        const floor = try row.signed(2);
        if (stream_revision <= 0 or head < 0 or floor <= 0) return error.InvalidHistoryPage;
        const token = effect_history.PageToken{ .installation = installation.id, .stream_revision = @intCast(stream_revision), .head_sequence = @intCast(head), .retained_from_sequence = @intCast(floor), .after_sequence = after, .last_sequence = after };
        try token.validate();
        return token;
    }
    fn confirmedEffectPageTx(self: *Store, installation: effects.Installation, after: u64, expected_revision: ?u64, output: []effect_history.Event) Error!effect_history.Page {
        if (output.len == 0 or output.len > effect_history.max_page) return error.InvalidHistoryPage;
        var token = try self.historyHead(installation, after);
        if (expected_revision) |wanted_revision| if (wanted_revision != token.stream_revision) return error.StaleHistoryPage;
        var row = try self.statement("SELECT s.sequence,e.event_id,e.scope_key,n.scope,e.jail,e.decision_id,e.confirmed_us FROM confirmed_history_sequence s JOIN confirmed_effect_events e ON e.event_id=s.event_id JOIN native_effects n ON n.scope_key=e.scope_key WHERE s.sequence>?1 ORDER BY s.sequence LIMIT ?2;");
        defer row.deinit();
        try row.int(1, @intCast(after));
        try row.int(2, @intCast(output.len));
        var count: usize = 0;
        while (try row.row()) {
            const sequence = try row.signed(0);
            if (sequence <= 0 or sequence != after + count + 1 or sequence > token.head_sequence) return error.HistoryGap;
            const event = effect_history.Event{ .sequence = @intCast(sequence), .event_id = try effectBlob(&row, 1, 32), .installation = installation, .scope_key = try effectBlob(&row, 2, 32), .scope = try effects.Scope.decode(&try effectBlob(&row, 3, effects.Scope.encoded_bytes)), .jail = detection.Name.init(try row.boundedBytes(4, 64)) catch return error.InvalidHistoryEvent, .decision_id = try effectBlob(&row, 5, 32), .confirmed_us = try row.signed(6) };
            try event.validate();
            output[count] = event;
            count += 1;
        }
        if (count != @min(output.len, token.head_sequence - after)) return error.HistoryGap;
        token.last_sequence = after + count;
        const page = effect_history.Page{ .token = token, .count = count, .more = token.last_sequence < token.head_sequence };
        try page.validate();
        return page;
    }
    /// Detached original events in one coherent bounded read. No transaction or
    /// SQLite-owned slice survives this call. Sequence order survives equal times.
    pub fn confirmedEffectPage(self: *Store, installation: effects.Installation, after_sequence: u64, expected_revision: ?u64, output: []effect_history.Event) Error!effect_history.Page {
        try self.beginRead();
        errdefer self.rollback();
        const page = try self.confirmedEffectPageTx(installation, after_sequence, expected_revision, output);
        try self.commitTransaction();
        return page;
    }
    fn validateConfirmedEffectPageTx(self: *Store, token: effect_history.PageToken) Error!void {
        try token.validate();
        const installation = try self.readInstallation() orelse return error.InstallationRequired;
        const current = try self.historyHead(installation, token.after_sequence);
        if (!std.mem.eql(u8, &current.installation, &token.installation)) return error.InstallationMismatch;
        if (current.stream_revision != token.stream_revision or current.head_sequence != token.head_sequence or current.retained_from_sequence != token.retained_from_sequence) return error.StaleHistoryPage;
        var events: [effect_history.max_page]effect_history.Event = undefined;
        // Token validation bounds the difference to max_page on every target.
        const size: usize = @intCast(token.last_sequence - token.after_sequence);
        const page = try self.confirmedEffectPageTx(installation, token.after_sequence, token.stream_revision, events[0..@max(1, size)]);
        if (page.token.last_sequence != token.last_sequence) return error.StaleHistoryPage;
    }
    pub fn validateConfirmedEffectPage(self: *Store, token: effect_history.PageToken) Error!void {
        try self.beginRead();
        errdefer self.rollback();
        try self.validateConfirmedEffectPageTx(token);
        try self.commitTransaction();
    }
    fn canonicalHistoryManifest(manifest: consumers.Manifest) bool {
        return std.mem.eql(u8, manifest.jail, "@history") and std.mem.eql(u8, manifest.source, "confirmed-effects") and manifest.required.len == 1 and
            manifest.required[0].format_version == effect_history.version and consumers.Key.eql(manifest.required[0].key, effect_history.key(manifest.source_generation));
    }
    fn checkHistoryBatch(manifest: consumers.Manifest, batch: consumers.Batch, installation: [16]u8) Error!effect_history.Checkpoint {
        try batch.validate();
        _ = try manifest.digest();
        if (!canonicalHistoryManifest(manifest) or batch.deltas.len != 1 or batch.dependencies.len != 0) return error.InvalidHistoryTransition;
        const delta = batch.deltas[0];
        if (!consumers.Key.eql(delta.key, manifest.required[0].key) or delta.format_version != effect_history.version or delta.valid_until_us != null) return error.InvalidHistoryTransition;
        const history_checkpoint = try effect_history.Checkpoint.decode(delta.payload);
        if (!std.mem.eql(u8, &history_checkpoint.generation, &manifest.source_generation) or !std.mem.eql(u8, &history_checkpoint.installation, &installation)) return error.HistoryGenerationMismatch;
        return history_checkpoint;
    }
    /// Generic record and consumer-input writers cannot initialize or advance
    /// history. First use must retain the complete unread stream from sequence1.
    pub fn bootstrapConfirmedHistory(self: *Store, manifest: consumers.Manifest, batch: consumers.Batch, installation: effects.Installation) Error!void {
        const history_checkpoint = try checkHistoryBatch(manifest, batch, installation.id);
        if (history_checkpoint.last_sequence != 0 or batch.deltas[0].expected_revision != 0) return error.InvalidHistoryTransition;
        try self.beginAdmissionWrite();
        errdefer self.rollback();
        _ = try self.historyHead(installation, 0);
        try self.admitManifestTx(manifest);
        try self.checkManifestBatch(manifest, batch, true, true);
        try self.writeConsumerBatch(batch);
        try self.readyManifest(manifest);
        try self.fault(.before_consumer_input_commit);
        try self.commitConsumerClock(batch);
        try self.commitTransaction();
    }
    /// Re-read the exact producer page under the writer lock before admitting its
    /// checkpoint. Stream fence, consumer CAS/count/digest and clock commit once.
    pub fn commitConfirmedHistory(self: *Store, manifest: consumers.Manifest, batch: consumers.Batch, token: effect_history.PageToken) Error!void {
        const next = try checkHistoryBatch(manifest, batch, token.installation);
        try self.beginWrite();
        errdefer self.rollback();
        try self.validateConfirmedEffectPageTx(token);
        try self.checkManifestBatch(manifest, batch, false, true);
        if (token.last_sequence == token.after_sequence) return error.HistoryCaughtUp;
        var row = try self.statement("SELECT payload FROM consumer_checkpoints WHERE kind=?1 AND jail=?2 AND source=?3 AND rule=?4 AND generation=?5;");
        defer row.deinit();
        const required_key = manifest.required[0].key;
        try bindConsumerKey(&row, &required_key);
        if (!try row.row()) return error.MissingRequiredConsumer;
        const previous = try effect_history.Checkpoint.decode(try row.boundedBytes(0, effect_history.checkpoint_bytes));
        var events: [effect_history.max_page]effect_history.Event = undefined;
        const installation = try self.readInstallation() orelse return error.InstallationRequired;
        const size: usize = @intCast(token.last_sequence - token.after_sequence);
        const page = try self.confirmedEffectPageTx(installation, token.after_sequence, token.stream_revision, events[0..size]);
        for (events[0..page.count]) |event| if (event.confirmed_us > batch.prepared_us) return error.InvalidHistoryEvent;
        try effect_history.validateTransition(previous, next, page, events[0..page.count]);
        try self.writeConsumerBatch(batch);
        try self.fault(.before_consumer_input_commit);
        try self.commitConsumerClock(batch);
        try self.commitTransaction();
    }

    /// Schema admission creates no installation and authorizes no transport I/O.
    pub fn enableEffects(self: *Store) Error!void {
        try self.beginWrite();
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 10 or schema > latest_schema) return error.UnsupportedSchema;
        if (schema == 10) try self.exec(
            \\CREATE TABLE effect_installation(singleton INTEGER PRIMARY KEY CHECK(singleton=1),identity BLOB NOT NULL CHECK(typeof(identity)='blob' AND length(identity)=16),backend INTEGER NOT NULL CHECK(typeof(backend)='integer' AND backend BETWEEN 1 AND 3),selector TEXT NOT NULL CHECK(typeof(selector)='text' AND length(selector) BETWEEN 1 AND 256));
            \\CREATE TABLE effect_clock(singleton INTEGER PRIMARY KEY CHECK(singleton=1),floor_us INTEGER CHECK(floor_us IS NULL OR typeof(floor_us)='integer'),revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision>=0));
            \\INSERT INTO effect_clock VALUES(1,NULL,0);
            \\CREATE TABLE native_effects(scope_key BLOB PRIMARY KEY NOT NULL CHECK(typeof(scope_key)='blob' AND length(scope_key)=32),scope BLOB NOT NULL CHECK(typeof(scope)='blob' AND length(scope)=24),revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision>=0),lease_kind INTEGER NOT NULL CHECK(typeof(lease_kind)='integer' AND lease_kind BETWEEN 0 AND 2),deadline_us INTEGER CHECK(deadline_us IS NULL OR typeof(deadline_us)='integer'),intent_id BLOB CHECK(intent_id IS NULL OR (typeof(intent_id)='blob' AND length(intent_id)=32)),CHECK((lease_kind=1)=(deadline_us IS NOT NULL)));
            \\CREATE TABLE effect_owners(scope_key BLOB NOT NULL,jail TEXT NOT NULL CHECK(length(jail) BETWEEN 1 AND 64),generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=32),decision_id BLOB NOT NULL CHECK(typeof(decision_id)='blob' AND length(decision_id)=32),revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision>0),lease_kind INTEGER NOT NULL CHECK(typeof(lease_kind)='integer' AND lease_kind BETWEEN 0 AND 2),deadline_us INTEGER CHECK(deadline_us IS NULL OR typeof(deadline_us)='integer'),decided_us INTEGER NOT NULL CHECK(typeof(decided_us)='integer'),PRIMARY KEY(scope_key,jail),FOREIGN KEY(scope_key) REFERENCES native_effects(scope_key),CHECK((lease_kind=1)=(deadline_us IS NOT NULL)),CHECK(deadline_us IS NULL OR deadline_us>decided_us));
            \\CREATE TABLE effect_owner_revisions(scope_key BLOB NOT NULL,jail TEXT NOT NULL,generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=32),decision_id BLOB NOT NULL CHECK(typeof(decision_id)='blob' AND length(decision_id)=32),revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision>0),lease_kind INTEGER NOT NULL CHECK(typeof(lease_kind)='integer' AND lease_kind BETWEEN 0 AND 2),deadline_us INTEGER CHECK(deadline_us IS NULL OR typeof(deadline_us)='integer'),decided_us INTEGER NOT NULL CHECK(typeof(decided_us)='integer'),PRIMARY KEY(scope_key,jail,revision),FOREIGN KEY(scope_key) REFERENCES native_effects(scope_key),CHECK((lease_kind=1)=(deadline_us IS NOT NULL)));
            \\CREATE TRIGGER effect_owner_insert AFTER INSERT ON effect_owners BEGIN INSERT INTO effect_owner_revisions VALUES(NEW.scope_key,NEW.jail,NEW.generation,NEW.decision_id,NEW.revision,NEW.lease_kind,NEW.deadline_us,NEW.decided_us); END;
            \\CREATE TRIGGER effect_owner_update AFTER UPDATE ON effect_owners BEGIN INSERT INTO effect_owner_revisions VALUES(NEW.scope_key,NEW.jail,NEW.generation,NEW.decision_id,NEW.revision,NEW.lease_kind,NEW.deadline_us,NEW.decided_us); END;
            \\CREATE TABLE effect_intents(intent_id BLOB PRIMARY KEY NOT NULL CHECK(typeof(intent_id)='blob' AND length(intent_id)=32),scope_key BLOB NOT NULL,revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision>0),decision_id BLOB NOT NULL CHECK(typeof(decision_id)='blob' AND length(decision_id)=32),lease_kind INTEGER NOT NULL CHECK(typeof(lease_kind)='integer' AND lease_kind BETWEEN 0 AND 2),deadline_us INTEGER CHECK(deadline_us IS NULL OR typeof(deadline_us)='integer'),status INTEGER NOT NULL CHECK(typeof(status)='integer' AND status BETWEEN 1 AND 6),created_us INTEGER NOT NULL CHECK(typeof(created_us)='integer'),dispatch_us INTEGER CHECK(dispatch_us IS NULL OR typeof(dispatch_us)='integer'),observed_us INTEGER CHECK(observed_us IS NULL OR typeof(observed_us)='integer'),fingerprint BLOB CHECK(fingerprint IS NULL OR (typeof(fingerprint)='blob' AND length(fingerprint)=32)),FOREIGN KEY(scope_key) REFERENCES native_effects(scope_key),UNIQUE(scope_key,revision),CHECK((lease_kind=1)=(deadline_us IS NOT NULL)));
            \\CREATE TABLE effect_observations(observation_id BLOB PRIMARY KEY NOT NULL CHECK(typeof(observation_id)='blob' AND length(observation_id)=32),intent_id BLOB NOT NULL,dispatch_us INTEGER NOT NULL,observed_us INTEGER NOT NULL,fingerprint BLOB NOT NULL CHECK(typeof(fingerprint)='blob' AND length(fingerprint)=32),state_kind INTEGER NOT NULL CHECK(state_kind BETWEEN 0 AND 3),deadline_us INTEGER,outcome INTEGER NOT NULL CHECK(outcome BETWEEN 1 AND 6),FOREIGN KEY(intent_id) REFERENCES effect_intents(intent_id),CHECK(observed_us>=dispatch_us),CHECK((state_kind=1)=(deadline_us IS NOT NULL)));
            \\CREATE TABLE confirmed_effect_events(event_id BLOB PRIMARY KEY NOT NULL CHECK(typeof(event_id)='blob' AND length(event_id)=32),scope_key BLOB NOT NULL,jail TEXT NOT NULL,decision_id BLOB NOT NULL CHECK(typeof(decision_id)='blob' AND length(decision_id)=32),confirmed_us INTEGER NOT NULL CHECK(typeof(confirmed_us)='integer'),UNIQUE(scope_key,jail,decision_id),FOREIGN KEY(scope_key) REFERENCES native_effects(scope_key));
            \\ALTER TABLE records ADD COLUMN zone_digest BLOB CHECK(zone_digest IS NULL OR (typeof(zone_digest)='blob' AND length(zone_digest)=32 AND native_time_kind IS NOT NULL));
            \\ALTER TABLE records ADD COLUMN zone_offset_seconds INTEGER CHECK(zone_offset_seconds IS NULL OR (typeof(zone_offset_seconds)='integer' AND zone_offset_seconds BETWEEN -2147483647 AND 2147483647));
            \\ALTER TABLE records ADD COLUMN zone_ambiguity INTEGER CHECK(zone_ambiguity IS NULL OR (typeof(zone_ambiguity)='integer' AND zone_ambiguity BETWEEN 0 AND 2));
            \\ALTER TABLE records ADD COLUMN zone_fold INTEGER CHECK(zone_fold IS NULL OR (typeof(zone_fold)='integer' AND zone_fold BETWEEN 0 AND 1));
            \\CREATE TRIGGER zone_provenance_update BEFORE UPDATE OF zone_digest,zone_offset_seconds,zone_ambiguity,zone_fold ON records WHEN NOT ((NEW.zone_digest IS NULL AND NEW.zone_offset_seconds IS NULL AND NEW.zone_ambiguity IS NULL AND NEW.zone_fold IS NULL) OR (NEW.zone_digest IS NOT NULL AND NEW.zone_offset_seconds IS NOT NULL AND NEW.zone_ambiguity IS NOT NULL AND NEW.zone_fold IS NOT NULL)) BEGIN SELECT RAISE(ABORT,'incomplete zone provenance'); END;
            \\PRAGMA user_version=11;
        );
        try self.fault(.before_effect_schema_commit);
        try self.commitTransaction();
        self.schema_version = @max(schema, 11);
    }

    fn effectSchema(self: *Store) Error!void {
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 11) return error.EffectStorageRequired;
        if (schema > latest_schema) return error.UnsupportedSchema;
        self.schema_version = schema;
    }
    pub fn enableTimeProvenance(self: *Store) Error!void {
        return self.enableEffects();
    }
    fn effectBlob(row: *Stmt, column: c_int, comptime length: usize) Error![length]u8 {
        if (row.store.api.column_type(row.ptr, column) != 4) return error.InvalidEffect;
        const bytes = try row.boundedBytes(column, length);
        if (bytes.len != length) return error.InvalidEffect;
        return bytes[0..length].*;
    }
    fn effectLease(row: *Stmt, kind_col: c_int, deadline_col: c_int) Error!effects.Lease {
        const kind = try row.signed(kind_col);
        const deadline = try row.optionalSigned(deadline_col);
        return switch (kind) {
            0 => if (deadline == null) .absent else error.InvalidEffect,
            1 => .{ .finite = deadline orelse return error.InvalidEffect },
            2 => if (deadline == null) .permanent else error.InvalidEffect,
            else => error.InvalidEffect,
        };
    }
    fn bindEffectLease(row: *Stmt, index: c_int, lease: effects.Lease) Error!void {
        try row.int(index, @intFromEnum(lease));
        if (lease == .finite) try row.int(index + 1, lease.finite) else try row.store.check(row.store.api.bind_null(row.ptr, index + 1));
    }
    pub fn readInstallation(self: *Store) Error!?effects.Installation {
        try self.effectSchema();
        var row = try self.statement("SELECT singleton,identity,backend,selector FROM effect_installation ORDER BY singleton;");
        defer row.deinit();
        if (!try row.row()) return null;
        if (try row.signed(0) != 1 or self.api.column_type(row.ptr, 3) != 3) return error.InvalidEffect;
        const backend = std.meta.intToEnum(effects.Backend, try row.signed(2)) catch return error.InvalidEffect;
        const result = try effects.Installation.init(try effectBlob(&row, 1, 16), backend, try row.boundedBytes(3, 256));
        if (try row.row()) return error.InvalidEffect;
        return result;
    }
    pub fn admitInstallation(self: *Store, installation: effects.Installation, admission: effects.NamespaceAdmission) Error!void {
        try installation.validate();
        if (!std.mem.eql(u8, installation.selector(), admission.selector)) return error.NamespaceAdmissionRequired;
        try self.beginWrite();
        errdefer self.rollback();
        if (try self.readInstallation()) |saved| {
            if (!std.meta.eql(saved, installation)) return error.InstallationMismatch;
        } else {
            if (admission.disposition != .verified_absent) return error.NamespaceAdmissionRequired;
            if (try self.integer("SELECT count(*) FROM native_effects;") != 0) return error.InvalidEffect;
            var row = try self.statement("INSERT INTO effect_installation VALUES(1,?1,?2,?3);");
            defer row.deinit();
            try row.blob(1, &installation.id);
            try row.int(2, @intFromEnum(installation.backend));
            try row.text(3, installation.selector());
            try row.done();
        }
        try self.commitTransaction();
    }
    fn effectClock(self: *Store, clock: effects.Clock) Error!i64 {
        const floor = try self.readAdmissionClock(self.schema_version);
        return clock.checked(if (floor) |value| value.us else null);
    }
    fn commitEffectClock(self: *Store, clock: effects.Clock) Error!i64 {
        const now = try self.effectClock(clock);
        var row = try self.statement("UPDATE effect_clock SET floor_us=?1 WHERE singleton=1;");
        defer row.deinit();
        try row.int(1, now);
        try row.done();
        if (self.api.changes(self.db) != 1) return error.InvalidEffect;
        return now;
    }
    fn advanceEffectSnapshot(self: *Store) Error!void {
        try self.exec("UPDATE effect_clock SET revision=revision+1 WHERE singleton=1 AND revision<9223372036854775807;");
        if (self.api.changes(self.db) != 1) return error.EffectCapacity;
    }
    fn decodeEffect(self: *Store, row: *Stmt, installation: effects.Installation) Error!effects.Entry {
        const scope_key = try effectBlob(row, 0, 32);
        const scope = try effects.Scope.decode(&try effectBlob(row, 1, 24));
        if (!std.mem.eql(u8, &scope_key, &try scope.key(installation))) return error.InvalidEffect;
        const effect_revision = try row.signed(2);
        if (effect_revision <= 0 or effect_revision != try row.signed(8)) return error.InvalidEffect;
        const desired = try effectLease(row, 3, 4);
        const intent_id = try effectBlob(row, 5, 32);
        const status = std.meta.intToEnum(effects.Status, try row.signed(6)) catch return error.InvalidEffect;
        const decision_id = try effectBlob(row, 7, 32);
        if (!effects.Lease.eql(desired, try effectLease(row, 9, 10)) or !std.mem.eql(u8, &intent_id, &effects.intentId(installation.id, scope_key, decision_id, @intCast(effect_revision), desired))) return error.InvalidEffect;
        const created = try row.signed(11);
        const dispatched = try row.optionalSigned(12);
        const observed = try row.optionalSigned(13);
        if (dispatched) |at| if (at < created) return error.InvalidEffect;
        if (observed) |at| {
            if (at < (dispatched orelse return error.InvalidEffect)) return error.InvalidEffect;
            _ = try effectBlob(row, 14, 32);
        } else if (self.api.column_type(row.ptr, 14) != 5) return error.InvalidEffect;
        if (status != .pending and dispatched == null) return error.InvalidEffect;
        if ((status == .applied or status == .absent or status == .expired) and observed == null) return error.InvalidEffect;
        if (status == .applied and desired == .absent) return error.InvalidEffect;
        if (status == .absent and desired != .absent) return error.InvalidEffect;
        if (status == .superseded) return error.InvalidEffect;
        var floor_row = try self.statement("SELECT floor_us FROM effect_clock WHERE singleton=1;");
        defer floor_row.deinit();
        if (!try floor_row.row()) return error.InvalidEffect;
        const effect_floor = try floor_row.optionalSigned(0) orelse return error.InvalidEffect;
        if (created > effect_floor or (dispatched != null and dispatched.? > effect_floor) or (observed != null and observed.? > effect_floor)) return error.InvalidEffect;

        var owner_rows: [effects.max_page]effects.Owner = undefined;
        const owner_count = try self.readOwners(scope_key, &owner_rows);
        if (owner_count == 0) return error.InvalidEffect;
        var aggregate: effects.Lease = .absent;
        for (owner_rows[0..owner_count]) |owner| {
            if (owner.decided_us > created or owner.revision > effect_revision) return error.InvalidEffect;
            switch (owner.lease) {
                .absent => {},
                .permanent => aggregate = .permanent,
                .finite => |deadline| if (deadline > created and aggregate != .permanent and (aggregate == .absent or deadline > aggregate.finite)) {
                    aggregate = .{ .finite = deadline };
                },
            }
        }
        if (!effects.Lease.eql(aggregate, desired)) return error.InvalidEffect;
        return .{ .installation = installation, .scope = scope, .scope_key = scope_key, .revision = @intCast(effect_revision), .desired = desired, .intent_id = intent_id, .status = status };
    }
    const effect_select = "SELECT e.scope_key,e.scope,e.revision,e.lease_kind,e.deadline_us,e.intent_id,i.status,i.decision_id,i.revision,i.lease_kind,i.deadline_us,i.created_us,i.dispatch_us,i.observed_us,i.fingerprint FROM native_effects e LEFT JOIN effect_intents i ON i.intent_id=e.intent_id ";
    fn readEffect(self: *Store, key: effects.Hash, installation: effects.Installation) Error!?effects.Entry {
        var row = try self.statement(effect_select ++ "WHERE e.scope_key=?1;");
        defer row.deinit();
        try row.blob(1, &key);
        if (!try row.row()) return null;
        return try self.decodeEffect(&row, installation);
    }
    pub fn effectPage(self: *Store, after: ?effects.Hash, expected_revision: ?u64, output: []effects.Entry) Error!effects.Page {
        if (output.len == 0 or output.len > effects.max_page) return error.EffectCapacity;
        try self.beginRead();
        errdefer self.rollback();
        const installation = try self.readInstallation() orelse return error.InstallationRequired;
        const effect_revision = try self.integer("SELECT revision FROM effect_clock WHERE singleton=1;");
        if (effect_revision < 0) return error.InvalidEffect;
        if (expected_revision) |expected| if (expected != effect_revision) return error.StaleEffect;
        var row = try self.statement(effect_select ++ "WHERE (?1 IS NULL OR e.scope_key>?1) ORDER BY e.scope_key LIMIT ?2;");
        defer row.deinit();
        const after_key = after orelse ([_]u8{0} ** 32);
        if (after != null) try row.blob(1, &after_key);
        try row.int(2, @intCast(output.len + 1));
        var count: usize = 0;
        var more = false;
        while (try row.row()) {
            if (count == output.len) {
                more = true;
                break;
            }
            output[count] = try self.decodeEffect(&row, installation);
            count += 1;
        }
        try self.commitTransaction();
        return .{ .revision = @intCast(effect_revision), .count = count, .more = more };
    }
    fn readOwners(self: *Store, key: effects.Hash, output: []effects.Owner) Error!usize {
        var row = try self.statement("SELECT o.jail,o.generation,o.decision_id,o.revision,o.lease_kind,o.deadline_us,o.decided_us,EXISTS(SELECT 1 FROM effect_owner_revisions h WHERE h.scope_key=o.scope_key AND h.jail=o.jail AND h.revision=o.revision AND h.generation=o.generation AND h.decision_id=o.decision_id AND h.lease_kind=o.lease_kind AND h.deadline_us IS o.deadline_us AND h.decided_us=o.decided_us) FROM effect_owners o WHERE o.scope_key=?1 ORDER BY o.jail LIMIT 65;");
        defer row.deinit();
        try row.blob(1, &key);
        var count: usize = 0;
        while (try row.row()) {
            if (count == output.len or count == effects.max_page) return error.EffectCapacity;
            if (self.api.column_type(row.ptr, 0) != 3 or try row.signed(7) != 1) return error.InvalidEffect;
            const effect_revision = try row.signed(3);
            if (effect_revision <= 0) return error.InvalidEffect;
            const lease = try effectLease(&row, 4, 5);
            const decided = try row.signed(6);
            if (lease == .finite and lease.finite <= decided) return error.InvalidEffect;
            output[count] = .{ .jail = detection.Name.init(try row.boundedBytes(0, 64)) catch return error.InvalidEffect, .generation = try effectBlob(&row, 1, 32), .decision_id = try effectBlob(&row, 2, 32), .revision = @intCast(effect_revision), .lease = lease, .decided_us = decided };
            count += 1;
        }
        return count;
    }
    pub fn effectOwners(self: *Store, key: effects.Hash, expected_revision: u64, output: []effects.Owner) Error!usize {
        if (output.len > effects.max_page) return error.EffectCapacity;
        try self.beginRead();
        errdefer self.rollback();
        const installation = try self.readInstallation() orelse return error.InstallationRequired;
        const entry = try self.readEffect(key, installation) orelse return error.StaleEffect;
        if (entry.revision != expected_revision) return error.StaleEffect;
        const count = try self.readOwners(key, output);
        try self.commitTransaction();
        return count;
    }

    fn replaceEffectIntent(self: *Store, installation: effects.Installation, scope: effects.Scope, key: effects.Hash, effect_revision: u64, decision_id: effects.Hash, now: i64) Error!effects.Entry {
        var owners: [effects.max_page]effects.Owner = undefined;
        const count = try self.readOwners(key, &owners);
        var lease: effects.Lease = .absent;
        for (owners[0..count]) |owner| switch (owner.lease) {
            .absent => {},
            .permanent => lease = .permanent,
            .finite => |deadline| if (deadline > now and lease != .permanent and (lease == .absent or deadline > lease.finite)) {
                lease = .{ .finite = deadline };
            },
        };
        const id = effects.intentId(installation.id, key, decision_id, effect_revision, lease);
        if (try self.integer("SELECT count(*) FROM effect_intents;") >= effects.max_intents) return error.EffectCapacity;
        {
            var old = try self.statement("UPDATE effect_intents SET status=CASE WHEN lease_kind=1 AND deadline_us<=?2 THEN 6 ELSE 5 END WHERE scope_key=?1 AND status=1;");
            defer old.deinit();
            try old.blob(1, &key);
            try old.int(2, now);
            try old.done();
            var intent = try self.statement("INSERT INTO effect_intents(intent_id,scope_key,revision,decision_id,lease_kind,deadline_us,status,created_us) VALUES(?1,?2,?3,?4,?5,?6,1,?7);");
            defer intent.deinit();
            try intent.blob(1, &id);
            try intent.blob(2, &key);
            try intent.int(3, @intCast(effect_revision));
            try intent.blob(4, &decision_id);
            try bindEffectLease(&intent, 5, lease);
            try intent.int(7, now);
            try intent.done();
            var aggregate = try self.statement("UPDATE native_effects SET revision=?2,lease_kind=?3,deadline_us=?4,intent_id=?5 WHERE scope_key=?1;");
            defer aggregate.deinit();
            try aggregate.blob(1, &key);
            try aggregate.int(2, @intCast(effect_revision));
            try bindEffectLease(&aggregate, 3, lease);
            try aggregate.blob(5, &id);
            try aggregate.done();
            if (self.api.changes(self.db) != 1) return error.InvalidEffect;
        }
        try self.advanceEffectSnapshot();
        try self.fault(.after_effect_intent);
        return .{ .installation = installation, .scope = scope, .scope_key = key, .revision = effect_revision, .desired = lease, .intent_id = id, .status = .pending };
    }
    fn setOwnerTx(self: *Store, change: effects.OwnerChange, now: i64) Error!effects.Entry {
        const jail = detection.Name.init(change.jail) catch return error.InvalidEffect;
        if (change.expected_revision >= std.math.maxInt(i64) or change.decided_us > now or (change.lease == .finite and change.lease.finite <= change.decided_us)) return error.InvalidEffect;
        if (change.lease != .absent and !change.lease.live(now)) return error.EffectExpired;
        const installation = try self.readInstallation() orelse return error.InstallationRequired;
        const key = try change.scope.key(installation);
        const previous = try self.readEffect(key, installation);
        if (previous) |entry| if (entry.status == .dispatched) return error.EffectReconciliationRequired;
        var owners: [effects.max_page]effects.Owner = undefined;
        const count = try self.readOwners(key, &owners);
        var owner_revision: u64 = 0;
        for (owners[0..count]) |owner| if (std.mem.eql(u8, owner.jail.slice(), jail.slice())) {
            owner_revision = owner.revision;
            if (!std.mem.eql(u8, &owner.generation, &change.generation)) return error.EffectGenerationMismatch;
            if (std.mem.eql(u8, &owner.decision_id, &change.decision_id)) {
                if (!effects.Lease.eql(owner.lease, change.lease) or owner.decided_us != change.decided_us) return error.InvalidEffect;
                return previous orelse error.InvalidEffect;
            }
        };
        if (owner_revision != change.expected_revision) return error.StaleEffect;
        if (try self.integer("SELECT count(*) FROM effect_owner_revisions;") >= effects.max_owner_revisions) return error.EffectCapacity;
        if (owner_revision == 0) {
            if (count == effects.max_page or try self.integer("SELECT count(*) FROM effect_owners;") >= effects.max_owners) return error.EffectCapacity;
        }
        const effect_revision = if (previous) |entry| std.math.add(u64, entry.revision, 1) catch return error.EffectCapacity else 1;
        if (effect_revision > std.math.maxInt(i64)) return error.EffectCapacity;
        if (previous == null) {
            if (try self.integer("SELECT count(*) FROM native_effects;") >= effects.max_effects) return error.EffectCapacity;
            const wire = try change.scope.encode();
            var row = try self.statement("INSERT INTO native_effects(scope_key,scope,revision,lease_kind) VALUES(?1,?2,0,0);");
            defer row.deinit();
            try row.blob(1, &key);
            try row.blob(2, &wire);
            try row.done();
        }
        {
            var owner = try self.statement("INSERT INTO effect_owners VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(scope_key,jail) DO UPDATE SET decision_id=excluded.decision_id,revision=excluded.revision,lease_kind=excluded.lease_kind,deadline_us=excluded.deadline_us,decided_us=excluded.decided_us;");
            defer owner.deinit();
            try owner.blob(1, &key);
            try owner.text(2, change.jail);
            try owner.blob(3, &change.generation);
            try owner.blob(4, &change.decision_id);
            try owner.int(5, @intCast(owner_revision + 1));
            try bindEffectLease(&owner, 6, change.lease);
            try owner.int(8, change.decided_us);
            try owner.done();
        }
        try self.fault(.after_effect_owner);
        return self.replaceEffectIntent(installation, change.scope, key, effect_revision, change.decision_id, now);
    }
    pub fn setOwner(self: *Store, change: effects.OwnerChange, clock: effects.Clock) Error!effects.Entry {
        try self.beginWrite();
        errdefer self.rollback();
        try self.effectSchema();
        const now = try self.effectClock(clock);
        const entry = try self.setOwnerTx(change, now);
        const final = try self.commitEffectClock(clock);
        if (change.lease == .finite and !change.lease.live(final)) return error.EffectExpired;
        if (entry.desired == .finite and !entry.desired.live(final)) return error.EffectExpired;
        try self.commitTransaction();
        self.effect_publication_epoch +|= 1;
        return entry;
    }
    fn checkedEffectToken(self: *Store, token: effects.Token) Error!effects.Entry {
        const installation = try self.readInstallation() orelse return error.InstallationRequired;
        if (!std.mem.eql(u8, &installation.id, &token.installation)) return error.InstallationMismatch;
        const entry = try self.readEffect(token.scope_key, installation) orelse return error.StaleEffect;
        if (entry.revision != token.revision or !std.mem.eql(u8, &entry.intent_id, &token.intent_id)) return error.StaleEffect;
        return entry;
    }
    pub fn markDispatched(self: *Store, token: effects.Token, clock: effects.Clock) Error!void {
        try self.beginWrite();
        errdefer self.rollback();
        const entry = try self.checkedEffectToken(token);
        if (entry.status == .dispatched) return error.EffectReconciliationRequired;
        if (entry.status != .pending) return error.StaleEffect;
        const now = try self.effectClock(clock);
        if (entry.desired == .finite and !entry.desired.live(now)) return error.EffectExpired;
        var row = try self.statement("UPDATE effect_intents SET status=2,dispatch_us=?2,observed_us=NULL,fingerprint=NULL WHERE intent_id=?1 AND status=1;");
        defer row.deinit();
        try row.blob(1, &token.intent_id);
        try row.int(2, now);
        try row.done();
        if (self.api.changes(self.db) != 1) return error.StaleEffect;
        try self.advanceEffectSnapshot();
        try self.fault(.before_effect_dispatch_commit);
        const final = try self.commitEffectClock(clock);
        if (entry.desired == .finite and !entry.desired.live(final)) return error.EffectExpired;
        try self.commitTransaction();
        self.effect_publication_epoch +|= 1;
    }
    pub fn settleVerified(self: *Store, token: effects.Token, observation: effects.Observation, clock: effects.Clock) Error!effects.Settlement {
        if (observation.qualification != .complete_owned or !std.mem.eql(u8, &observation.installation, &token.installation) or !std.mem.eql(u8, &observation.scope_key, &token.scope_key)) return error.IncompleteEffectObservation;
        try self.beginWrite();
        errdefer self.rollback();
        const entry = try self.checkedEffectToken(token);
        if (entry.status != .dispatched and entry.status != .applied and entry.status != .absent and entry.status != .expired) return error.StaleEffect;
        const now = try self.effectClock(clock);
        if (observation.observed_us > now) return error.InvalidEffect;
        var dispatch = try self.statement("SELECT dispatch_us,observed_us,fingerprint FROM effect_intents WHERE intent_id=?1;");
        defer dispatch.deinit();
        try dispatch.blob(1, &token.intent_id);
        if (!try dispatch.row() or observation.observed_us < (try dispatch.optionalSigned(0) orelse return error.InvalidEffect)) return error.InvalidEffect;
        const previous_observed = try dispatch.optionalSigned(1);
        if (previous_observed) |previous| {
            if (observation.observed_us < previous) return error.StaleEffect;
            if (observation.observed_us == previous and !std.mem.eql(u8, &observation.fingerprint, &try effectBlob(&dispatch, 2, 32))) return error.StaleEffect;
        }
        const expired = entry.desired == .finite and !entry.desired.live(now);
        const matches = if (observation.state) |state| effects.Lease.eql(entry.desired, state) else false;
        const status: effects.Status = if (expired) .expired else if (!matches) .pending else if (entry.desired == .absent) .absent else .applied;
        if (previous_observed != null and observation.observed_us == previous_observed.? and status != entry.status) return error.StaleEffect;
        // Complete fresh readback may reopen a settled intent after drift; its
        // immutable identity/deadline and confirmed-event dedup remain intact.
        var stamps: [16]u8 = undefined;
        const dispatch_time = (try dispatch.optionalSigned(0)).?;
        std.mem.writeInt(i64, stamps[0..8], dispatch_time, .little);
        std.mem.writeInt(i64, stamps[8..16], observation.observed_us, .little);
        var observed_state: [10]u8 = [_]u8{0} ** 10;
        observed_state[0] = if (observation.state) |state| @intFromEnum(state) else 3;
        if (observation.state) |state| if (state == .finite) {
            std.mem.writeInt(i64, observed_state[1..9], state.finite, .little);
        };
        observed_state[9] = @intFromEnum(status);
        const observation_id = effects.hashParts("fail2zig-native-effect-observation-v1", &.{ &token.intent_id, &stamps, &observation.fingerprint, &observed_state });
        {
            var prior = try self.statement("SELECT 1 FROM effect_observations WHERE observation_id=?1;");
            defer prior.deinit();
            try prior.blob(1, &observation_id);
            if (!try prior.row()) {
                if (try self.integer("SELECT count(*) FROM effect_observations;") >= effects.max_observations) return error.EffectCapacity;
                var receipt = try self.statement("INSERT INTO effect_observations VALUES(?1,?2,?3,?4,?5,?6,?7,?8);");
                defer receipt.deinit();
                try receipt.blob(1, &observation_id);
                try receipt.blob(2, &token.intent_id);
                try receipt.int(3, dispatch_time);
                try receipt.int(4, observation.observed_us);
                try receipt.blob(5, &observation.fingerprint);
                try receipt.int(6, observed_state[0]);
                if (observation.state) |state| if (state == .finite) {
                    try receipt.int(7, state.finite);
                };
                try receipt.int(8, @intFromEnum(status));
                try receipt.done();
            }
        }
        var row = try self.statement("UPDATE effect_intents SET status=?2,observed_us=?3,fingerprint=?4 WHERE intent_id=?1;");
        defer row.deinit();
        try row.blob(1, &token.intent_id);
        try row.int(2, @intFromEnum(status));
        try row.int(3, observation.observed_us);
        try row.blob(4, &observation.fingerprint);
        try row.done();
        if (status == .applied) {
            var owners: [effects.max_page]effects.Owner = undefined;
            const count = try self.readOwners(token.scope_key, &owners);
            for (owners[0..count]) |owner| if (owner.lease.live(now)) {
                const event_id = effects.hashParts("fail2zig-native-confirmed-owner-v1", &.{ &token.installation, &token.scope_key, owner.jail.slice(), &owner.decision_id });
                var existing = try self.statement("SELECT event_id FROM confirmed_effect_events WHERE scope_key=?1 AND jail=?2 AND decision_id=?3;");
                defer existing.deinit();
                try existing.blob(1, &token.scope_key);
                try existing.text(2, owner.jail.slice());
                try existing.blob(3, &owner.decision_id);
                if (try existing.row()) {
                    if (!std.mem.eql(u8, &event_id, &try effectBlob(&existing, 0, 32))) return error.InvalidEffect;
                    continue;
                }
                if (try self.integer("SELECT count(*) FROM confirmed_effect_events;") >= effects.max_confirmed_events) return error.EffectCapacity;
                var event = try self.statement("INSERT INTO confirmed_effect_events VALUES(?1,?2,?3,?4,?5) ON CONFLICT(scope_key,jail,decision_id) DO NOTHING;");
                defer event.deinit();
                try event.blob(1, &event_id);
                try event.blob(2, &token.scope_key);
                try event.text(3, owner.jail.slice());
                try event.blob(4, &owner.decision_id);
                try event.int(5, observation.observed_us);
                try event.done();
                if (self.schema_version >= 13) {
                    // A missing or changed append trigger must roll back the
                    // receipt rather than publish an event outside the stream.
                    var sequenced = try self.statement("SELECT s.event_id FROM confirmed_history_stream h JOIN confirmed_history_sequence s ON s.sequence=h.head WHERE h.id=1;");
                    defer sequenced.deinit();
                    if (!try sequenced.row() or !std.mem.eql(u8, &try effectBlob(&sequenced, 0, 32), &event_id)) return error.HistoryGap;
                }
            };
        }
        try self.advanceEffectSnapshot();
        try self.fault(.before_effect_receipt_commit);
        const final = try self.commitEffectClock(clock);
        // Crossing expiry during receipt commit cannot publish a live confirmation.
        if (status == .applied and entry.desired == .finite and !entry.desired.live(final)) return error.EffectExpired;
        try self.commitTransaction();
        self.effect_publication_epoch +|= 1;
        return if (expired) .expired else if (matches) .verified else .retry_same_intent;
    }
    pub fn prepareExpiry(self: *Store, key: effects.Hash, expected_revision: u64, clock: effects.Clock) Error!effects.Entry {
        try self.beginWrite();
        errdefer self.rollback();
        const installation = try self.readInstallation() orelse return error.InstallationRequired;
        const prior = try self.readEffect(key, installation) orelse return error.StaleEffect;
        if (prior.revision != expected_revision) return error.StaleEffect;
        if (prior.status == .dispatched) return error.EffectReconciliationRequired;
        const now = try self.effectClock(clock);
        var owners: [effects.max_page]effects.Owner = undefined;
        const count = try self.readOwners(key, &owners);
        var expired: u64 = 0;
        var expiring_count: u64 = 0;
        for (owners[0..count]) |owner| if (owner.lease == .finite and !owner.lease.live(now)) {
            expiring_count += 1;
        };
        if (try self.integer("SELECT count(*) FROM effect_owner_revisions;") > effects.max_owner_revisions - expiring_count) return error.EffectCapacity;
        for (owners[0..count]) |owner| if (owner.lease == .finite and !owner.lease.live(now)) {
            if (owner.revision == std.math.maxInt(i64)) return error.EffectCapacity;
            var row = try self.statement("UPDATE effect_owners SET lease_kind=0,deadline_us=NULL,revision=revision+1 WHERE scope_key=?1 AND jail=?2;");
            defer row.deinit();
            try row.blob(1, &key);
            try row.text(2, owner.jail.slice());
            try row.done();
            expired += 1;
        };
        var entry = prior;
        if (expired != 0) {
            const effect_revision = std.math.add(u64, prior.revision, expired) catch return error.EffectCapacity;
            if (effect_revision > std.math.maxInt(i64)) return error.EffectCapacity;
            // Last immutable intent binds this expiry transition, never current duration.
            entry = try self.replaceEffectIntent(installation, prior.scope, key, effect_revision, prior.intent_id, now);
        }
        _ = try self.commitEffectClock(clock);
        try self.commitTransaction();
        if (expired != 0) self.effect_publication_epoch +|= 1;
        return entry;
    }
    pub fn confirmedEffectEvents(self: *Store) Error!u64 {
        const count = try self.integer("SELECT count(*) FROM confirmed_effect_events;");
        return std.math.cast(u64, count) orelse error.InvalidEffect;
    }
    /// Exact historical finite authorization survives expiry/release and sharing.
    pub fn ownerRevision(self: *Store, key: effects.Hash, jail: []const u8, owner_revision: u64) Error!?effects.Owner {
        if (owner_revision == 0 or owner_revision > std.math.maxInt(i64)) return error.InvalidEffect;
        var row = try self.statement("SELECT generation,decision_id,lease_kind,deadline_us,decided_us FROM effect_owner_revisions WHERE scope_key=?1 AND jail=?2 AND revision=?3;");
        defer row.deinit();
        try row.blob(1, &key);
        try row.text(2, jail);
        try row.int(3, @intCast(owner_revision));
        if (!try row.row()) return null;
        const lease = try effectLease(&row, 2, 3);
        const decided = try row.signed(4);
        if (lease == .finite and lease.finite <= decided) return error.InvalidEffect;
        return .{ .jail = detection.Name.init(jail) catch return error.InvalidEffect, .generation = try effectBlob(&row, 0, 32), .decision_id = try effectBlob(&row, 1, 32), .revision = owner_revision, .lease = lease, .decided_us = decided };
    }

    pub const ManifestMode = enum { first_use, @"resume" };
    pub const ManifestStatus = enum { first_use, ready };
    pub const ManifestSnapshot = struct {
        status: ManifestStatus,
        digest: [32]u8,
        revision: u64,
        count: usize = 0,
        states: [consumers.max_dependencies]ConsumerSnapshot = undefined,
        pub fn deinit(self: *ManifestSnapshot, allocator: std.mem.Allocator) void {
            for (self.states[0..self.count]) |state| state.deinit(allocator);
            self.count = 0;
        }
    };
    pub const ManifestKey = struct {
        source: []u8,
        generation: [32]u8,
        digest: [32]u8,
        status: ManifestStatus,
        pub fn deinit(self: ManifestKey, allocator: std.mem.Allocator) void {
            allocator.free(self.source);
        }
    };
    pub const ManifestPage = struct { revision: u64, count: usize, more: bool };
    fn consumerHash(row: *Stmt, column: c_int) Error![32]u8 {
        if (row.store.api.column_type(row.ptr, column) != 4) return error.InvalidConsumer;
        const bytes = try row.boundedBytes(column, 32);
        if (bytes.len != 32) return error.InvalidConsumer;
        return bytes[0..32].*;
    }
    fn consumerRevision(self: *Store) Error!u64 {
        var row = try self.statement("SELECT revision FROM consumer_revision WHERE id=1;");
        defer row.deinit();
        if (!try row.row()) return error.InvalidConsumer;
        const current_revision = try row.signed(0);
        if (current_revision < 0) return error.InvalidConsumer;
        return @intCast(current_revision);
    }
    fn bumpConsumerRevision(self: *Store) Error!void {
        if (try self.consumerRevision() == std.math.maxInt(i64)) return error.ConsumerCapacity;
        try self.exec("UPDATE consumer_revision SET revision=revision+1 WHERE id=1;");
        if (self.api.changes(self.db) != 1) return error.InvalidConsumer;
    }
    /// Detached discovery for dynamically admitted DNS keys. Every page belongs
    /// to the same durable consumer revision; retain even expired checkpoint keys.
    pub fn consumerManifestKeysPage(self: *Store, allocator: std.mem.Allocator, jail: []const u8, after_source: ?[]const u8, expected_revision: ?u64, output: []ManifestKey) Error!ManifestPage {
        if (output.len == 0 or output.len > consumers.max_dependencies or jail.len == 0 or jail.len > 64 or std.mem.indexOfScalar(u8, jail, 0) != null) return error.InvalidConsumer;
        if (after_source) |after| if (after.len == 0 or after.len > Limits.source_bytes or std.mem.indexOfScalar(u8, after, 0) != null) return error.InvalidConsumer;
        try self.beginRead();
        errdefer self.rollback();
        try self.requireManifestSchema();
        const current_revision = try self.consumerRevision();
        if (expected_revision) |expected| if (expected != current_revision) return error.StaleConsumerCheckpoint;
        var row = try self.statement("SELECT source,generation,digest,ready,required_count FROM consumer_manifests WHERE jail=?1 AND source>COALESCE(?2,'') ORDER BY source LIMIT ?3;");
        defer row.deinit();
        try row.text(1, jail);
        if (after_source) |after| try row.text(2, after);
        try row.int(3, @intCast(output.len + 1));
        var count: usize = 0;
        errdefer for (output[0..count]) |entry| entry.deinit(allocator);
        while (try row.row()) {
            if (count == output.len) {
                try self.commitTransaction();
                return .{ .revision = current_revision, .count = count, .more = true };
            }
            if (self.api.column_type(row.ptr, 0) != 3) return error.InvalidConsumer;
            const source = try row.boundedBytes(0, Limits.source_bytes);
            if (source.len == 0 or std.mem.indexOfScalar(u8, source, 0) != null) return error.InvalidConsumer;
            const generation = try consumerHash(&row, 1);
            const digest = try consumerHash(&row, 2);
            const ready = try row.signed(3);
            const required = try row.signed(4);
            if (ready < 0 or ready > 1 or required < 0 or required > consumers.max_dependencies) return error.InvalidConsumer;
            output[count] = .{ .source = try allocator.dupe(u8, source), .generation = generation, .digest = digest, .status = if (ready == 1) .ready else .first_use };
            count += 1;
        }
        try self.commitTransaction();
        return .{ .revision = current_revision, .count = count, .more = false };
    }
    fn requireManifestSchema(self: *Store) Error!void {
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 12 or schema > latest_schema) return error.ConsumerStorageRequired;
        self.schema_version = schema;
    }
    fn manifestExists(self: *Store, jail: []const u8, source: []const u8) Error!bool {
        var row = try self.statement("SELECT 1 FROM consumer_manifests WHERE jail=?1 AND source=?2;");
        defer row.deinit();
        try row.text(1, jail);
        try row.text(2, source);
        return row.row();
    }
    /// Validate both the manifest digest and every normalized required key. A
    /// digest alone cannot conceal missing, added or corrupted requirement rows.
    fn checkManifest(self: *Store, manifest: consumers.Manifest) Error!ManifestStatus {
        const digest = try manifest.digest();
        var row = try self.statement("SELECT generation,digest,ready,required_count FROM consumer_manifests WHERE jail=?1 AND source=?2;");
        defer row.deinit();
        try row.text(1, manifest.jail);
        try row.text(2, manifest.source);
        if (!try row.row()) return error.ConsumerManifestMissing;
        if (!std.mem.eql(u8, &try consumerHash(&row, 0), &manifest.source_generation) or
            !std.mem.eql(u8, &try consumerHash(&row, 1), &digest)) return error.ConsumerManifestMismatch;
        const ready = try row.signed(2);
        if (ready < 0 or ready > 1 or try row.signed(3) != manifest.required.len) return error.InvalidConsumer;
        var count = try self.statement("SELECT count(*) FROM consumer_requirements WHERE manifest_jail=?1 AND manifest_source=?2;");
        defer count.deinit();
        try count.text(1, manifest.jail);
        try count.text(2, manifest.source);
        if (!try count.row() or try count.signed(0) != manifest.required.len) return error.InvalidConsumer;
        for (manifest.required) |requirement| {
            var item = try self.statement("SELECT format FROM consumer_requirements WHERE kind=?1 AND jail=?2 AND source=?3 AND rule=?4 AND generation=?5 AND manifest_jail=?6 AND manifest_source=?7;");
            defer item.deinit();
            try bindConsumerKey(&item, &requirement.key);
            try item.text(6, manifest.jail);
            try item.text(7, manifest.source);
            if (!try item.row() or try item.signed(0) != requirement.format_version) return error.InvalidConsumer;
        }
        if (ready == 0) {
            var history = try self.statement("SELECT 1 FROM records WHERE jail=?1 AND source=?2 LIMIT 1;");
            defer history.deinit();
            try history.text(1, manifest.jail);
            try history.text(2, manifest.source);
            if (try history.row()) return error.MissingRequiredConsumer;
        }
        return if (ready == 1) .ready else .first_use;
    }
    fn checkRequiredState(self: *Store, requirement: consumers.Requirement, missing_allowed: bool) Error!void {
        var row = try self.statement("SELECT format,revision,typeof(payload),length(payload),valid_until_us,payload FROM consumer_checkpoints WHERE kind=?1 AND jail=?2 AND source=?3 AND rule=?4 AND generation=?5;");
        defer row.deinit();
        try bindConsumerKey(&row, &requirement.key);
        if (!try row.row()) {
            if (!missing_allowed) return error.MissingRequiredConsumer;
            return;
        }
        if (try row.signed(0) != requirement.format_version or try row.signed(1) <= 0 or
            !std.mem.eql(u8, try row.boundedBytes(2, 8), "blob") or try row.signed(3) > consumers.max_payload)
            return error.InvalidConsumer;
        const expiry = try row.optionalSigned(4);
        if (dnsAuthority(requirement.key) and (requirement.format_version != 1 or try row.signed(1) != 1 or expiry != null or
            !std.mem.eql(u8, try row.boundedBytes(5, 32), &requirement.key.generation))) return error.InvalidConsumer;
    }
    fn admitManifestTx(self: *Store, manifest: consumers.Manifest) Error!void {
        const digest = try manifest.digest();
        if (try self.manifestExists(manifest.jail, manifest.source)) return error.ConsumerManifestExists;
        if (try self.integer("SELECT count(*) FROM consumer_manifests;") >= 4096 or
            try self.integer("SELECT count(*) FROM consumer_requirements;") > 65536 - manifest.required.len) return error.ConsumerCapacity;
        // First use is an explicit empty source boundary, never adoption of
        // acknowledged history or a pending observation under another generation.
        var old = try self.statement("SELECT 1 FROM records WHERE jail=?1 AND source=?2 UNION ALL SELECT 1 FROM pending_receipts WHERE jail=?1 AND source=?2 LIMIT 1;");
        defer old.deinit();
        try old.text(1, manifest.jail);
        try old.text(2, manifest.source);
        if (try old.row()) return error.ConsumerMigrationRequired;
        for (manifest.required) |requirement| {
            // Refuse incompatible retained generations/formats. No history is
            // deleted or reinterpreted as part of ordinary restart admission.
            var incompatible = try self.statement("SELECT 1 FROM consumer_checkpoints WHERE kind=?1 AND jail=?2 AND source=?3 AND rule=?4 AND (generation!=?5 OR format!=?6) UNION ALL SELECT 1 FROM consumer_requirements WHERE kind=?1 AND jail=?2 AND source=?3 AND rule=?4 AND (generation!=?5 OR format!=?6) LIMIT 1;");
            defer incompatible.deinit();
            try bindConsumerKey(&incompatible, &requirement.key);
            try incompatible.int(6, requirement.format_version);
            if (try incompatible.row()) return error.ConsumerMigrationRequired;
            var prior = try self.statement("SELECT 1 FROM consumer_checkpoints c WHERE kind=?1 AND jail=?2 AND source=?3 AND rule=?4 AND generation=?5 AND NOT EXISTS(SELECT 1 FROM consumer_requirements r WHERE r.kind=c.kind AND r.jail=c.jail AND r.source=c.source AND r.rule=c.rule AND r.generation=c.generation AND r.format=c.format);");
            defer prior.deinit();
            try bindConsumerKey(&prior, &requirement.key);
            if (try prior.row()) return error.ConsumerMigrationRequired;
            try self.checkRequiredState(requirement, true);
        }
        var insert = try self.statement("INSERT INTO consumer_manifests VALUES(?1,?2,?3,?4,0,?5);");
        defer insert.deinit();
        try insert.text(1, manifest.jail);
        try insert.text(2, manifest.source);
        try insert.blob(3, &manifest.source_generation);
        try insert.blob(4, &digest);
        try insert.int(5, @intCast(manifest.required.len));
        try insert.done();
        for (manifest.required) |requirement| {
            var item = try self.statement("INSERT INTO consumer_requirements(kind,jail,source,rule,generation,manifest_jail,manifest_source,format) VALUES(?1,?2,?3,?4,?5,?6,?7,?8);");
            defer item.deinit();
            try bindConsumerKey(&item, &requirement.key);
            try item.text(6, manifest.jail);
            try item.text(7, manifest.source);
            try item.int(8, requirement.format_version);
            try item.done();
        }
    }
    pub fn admitConsumerManifest(self: *Store, manifest: consumers.Manifest, mode: ManifestMode) Error!void {
        _ = try manifest.digest();
        try self.beginWrite();
        errdefer self.rollback();
        try self.requireManifestSchema();
        switch (mode) {
            .first_use => try self.admitManifestTx(manifest),
            .@"resume" => {
                const status = try self.checkManifest(manifest);
                for (manifest.required) |requirement| try self.checkRequiredState(requirement, status == .first_use);
            },
        }
        if (mode == .first_use) try self.bumpConsumerRevision();
        try self.fault(.before_manifest_commit);
        try self.commitTransaction();
    }
    pub fn consumerManifestSnapshot(self: *Store, allocator: std.mem.Allocator, manifest: consumers.Manifest) Error!ManifestSnapshot {
        try self.beginRead();
        errdefer self.rollback();
        try self.requireManifestSchema();
        var result = ManifestSnapshot{ .status = try self.checkManifest(manifest), .digest = try manifest.digest(), .revision = try self.consumerRevision() };
        errdefer result.deinit(allocator);
        var bytes: usize = 0;
        for (manifest.required) |requirement| {
            try self.checkRequiredState(requirement, result.status == .first_use);
            const state = try self.consumerSnapshot(allocator, requirement.key);
            result.states[result.count] = state;
            result.count += 1;
            bytes += if (state.payload) |payload| payload.len else 0;
            if (bytes > consumers.max_prepared_bytes) return error.ConsumerCapacity;
        }
        try self.commitTransaction();
        return result;
    }
    /// Recheck every detached restore revision immediately before publication.
    /// Caller serialization still owns the interval after this method returns.
    pub fn validateConsumerManifestSnapshot(self: *Store, manifest: consumers.Manifest, saved_snapshot: *const ManifestSnapshot) Error!void {
        if (saved_snapshot.count != manifest.required.len or !std.mem.eql(u8, &saved_snapshot.digest, &try manifest.digest())) return error.ConsumerManifestMismatch;
        try self.beginRead();
        errdefer self.rollback();
        try self.requireManifestSchema();
        if (try self.checkManifest(manifest) != saved_snapshot.status or try self.consumerRevision() != saved_snapshot.revision) return error.StaleConsumerCheckpoint;
        for (manifest.required, saved_snapshot.states[0..saved_snapshot.count]) |requirement, state| {
            try self.checkRequiredState(requirement, saved_snapshot.status == .first_use);
            if (state.revision != 0 and state.format_version != requirement.format_version) return error.InvalidConsumer;
            try self.checkConsumerRevision(requirement.key, state.revision, .{ .value = state.valid_until_us });
        }
        try self.commitTransaction();
    }
    fn checkManifestBatch(self: *Store, manifest: consumers.Manifest, batch: consumers.Batch, allow_first_use: bool, allow_history: bool) Error!void {
        const status = try self.checkManifest(manifest);
        if (!allow_first_use and status == .first_use) return error.MissingRequiredConsumer;
        for (manifest.required) |requirement| {
            try self.checkRequiredState(requirement, status == .first_use);
            var covered = false;
            for (batch.deltas) |delta| if (consumers.Key.eql(requirement.key, delta.key)) {
                if (delta.format_version != requirement.format_version) return error.InvalidConsumer;
                covered = true;
            };
            for (batch.dependencies) |dependency| if (consumers.Key.eql(requirement.key, dependency.key)) {
                if (dependency.expected_revision == 0 and !covered) return error.MissingRequiredConsumer;
                covered = true;
            };
            if (!covered) return error.MissingRequiredConsumer;
        }
        for (batch.deltas) |delta| {
            for (manifest.required) |requirement| {
                if (consumers.Key.eql(requirement.key, delta.key)) break;
            } else return error.ConsumerManifestMismatch;
        }
        for (batch.dependencies) |dependency| {
            for (manifest.required) |requirement| {
                if (consumers.Key.eql(requirement.key, dependency.key)) break;
            } else try self.checkSharedDnsDependency(manifest, batch, dependency);
        }
        try self.checkConsumerBatch(batch, allow_history);
    }
    fn dnsAuthority(key: consumers.Key) bool {
        return key.kind == .dns and std.mem.eql(u8, key.jail, "@shared") and std.mem.eql(u8, key.source, "@resolver") and std.mem.eql(u8, key.rule, "authority");
    }
    fn checkSharedDnsDependency(self: *Store, manifest: consumers.Manifest, batch: consumers.Batch, dependency: consumers.Dependency) Error!void {
        const key = dependency.key;
        if (key.kind != .dns or !std.mem.eql(u8, key.jail, "@shared") or key.source.len > 253 or
            !(std.mem.eql(u8, key.rule, "v4") or std.mem.eql(u8, key.rule, "v6") or std.mem.eql(u8, key.rule, "both")) or dependency.expected_revision == 0 or dependency.valid_until_us == null) return error.ConsumerManifestMismatch;
        var bound = false;
        for (manifest.required) |requirement| {
            if (!dnsAuthority(requirement.key) or requirement.format_version != 1 or !std.mem.eql(u8, &requirement.key.generation, &key.generation)) continue;
            try self.checkRequiredState(requirement, false);
            for (batch.dependencies) |read| if (consumers.Key.eql(read.key, requirement.key) and read.expected_revision == 1 and read.valid_until_us == null) {
                bound = true;
                break;
            };
        }
        if (!bound) return error.ConsumerManifestMismatch;
        // Only an exact ready shared-input manifest can grant a dynamic read.
        // The source's immutable resolver authority binds its permitted generation.
        var name: [260]u8 = undefined;
        const source = std.fmt.bufPrint(&name, "{s}:{s}", .{ key.rule, key.source }) catch return error.ConsumerManifestMismatch;
        const required = [_]consumers.Requirement{.{ .key = key, .format_version = 1 }};
        const shared_manifest = consumers.Manifest{ .jail = "@shared", .source = source, .source_generation = key.generation, .required = &required };
        if (try self.checkManifest(shared_manifest) != .ready) return error.MissingRequiredConsumer;
        try self.checkRequiredState(required[0], false);
    }
    fn readyManifest(self: *Store, manifest: consumers.Manifest) Error!void {
        for (manifest.required) |requirement| try self.checkRequiredState(requirement, false);
        var row = try self.statement("UPDATE consumer_manifests SET ready=1 WHERE jail=?1 AND source=?2;");
        defer row.deinit();
        try row.text(1, manifest.jail);
        try row.text(2, manifest.source);
        try row.done();
        if (self.api.changes(self.db) != 1) return error.ConsumerManifestMissing;
        try self.fault(.after_manifest_ready);
    }
    /// DNS/shared inputs own an independent durable checkpoint transaction. It
    /// never updates source receipts, source cursors or jail record revisions.
    pub fn commitConsumerInput(self: *Store, manifest: consumers.Manifest, batch: consumers.Batch) Error!void {
        try self.consumerInput(manifest, batch, false);
    }
    /// First-use initializers and their required manifest appear atomically.
    pub fn bootstrapConsumerManifest(self: *Store, manifest: consumers.Manifest, batch: consumers.Batch) Error!void {
        try self.consumerInput(manifest, batch, true);
    }
    fn consumerInput(self: *Store, manifest: consumers.Manifest, batch: consumers.Batch, initialize: bool) Error!void {
        try batch.validate();
        _ = try manifest.digest();
        if (initialize) try self.beginAdmissionWrite() else try self.beginWrite();
        errdefer self.rollback();
        try self.requireManifestSchema();
        if (initialize) try self.admitManifestTx(manifest);
        try self.checkManifestBatch(manifest, batch, initialize, false);
        try self.writeConsumerBatch(batch);
        try self.readyManifest(manifest);
        try self.fault(.before_consumer_input_commit);
        try self.commitConsumerClock(batch);
        try self.commitTransaction();
    }

    pub const ConsumerSnapshot = struct {
        revision: u64 = 0,
        format_version: u16 = 0,
        valid_until_us: ?i64 = null,
        payload: ?[]u8 = null,
        pub fn deinit(self: ConsumerSnapshot, allocator: std.mem.Allocator) void {
            if (self.payload) |bytes| allocator.free(bytes);
        }
    };
    // SQLITE_STATIC borrows generation bytes until step/finalize; never bind a
    // by-value helper copy whose lifetime ends when this helper returns.
    fn bindConsumerKey(row: *Stmt, key: *const consumers.Key) Error!void {
        try key.validate();
        try row.int(1, @intFromEnum(key.kind));
        try row.text(2, key.jail);
        try row.text(3, key.source);
        try row.text(4, key.rule);
        try row.blob(5, &key.generation);
    }
    /// A detached bounded single row. Multi-owner restore must hold a coherent
    /// snapshot/revision protocol around these reads before publishing anything.
    pub fn consumerSnapshot(self: *Store, allocator: std.mem.Allocator, key: consumers.Key) Error!ConsumerSnapshot {
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 10 or schema > latest_schema) return error.ConsumerStorageRequired;
        self.schema_version = schema;
        var row = try self.statement("SELECT revision,format,valid_until_us,payload FROM consumer_checkpoints WHERE kind=?1 AND jail=?2 AND source=?3 AND rule=?4 AND generation=?5;");
        defer row.deinit();
        try bindConsumerKey(&row, &key);
        if (!try row.row()) return .{};
        const revision_value = try row.signed(0);
        const format = try row.signed(1);
        if (revision_value <= 0 or format <= 0 or format > std.math.maxInt(u16)) return error.DatabaseFailure;
        const expiry: ?i64 = if (self.api.column_type(row.ptr, 2) == 5) null else try row.signed(2);
        if (self.api.column_type(row.ptr, 3) != 4) return error.InvalidConsumer;
        const bytes = try row.boundedBytes(3, consumers.max_payload);
        return .{ .revision = @intCast(revision_value), .format_version = @intCast(format), .valid_until_us = expiry, .payload = try allocator.dupe(u8, bytes) };
    }
    fn checkConsumerRevision(self: *Store, key: consumers.Key, expected: u64, deadline: ?struct { value: ?i64 }) Error!void {
        var row = try self.statement("SELECT revision,valid_until_us FROM consumer_checkpoints WHERE kind=?1 AND jail=?2 AND source=?3 AND rule=?4 AND generation=?5;");
        defer row.deinit();
        try bindConsumerKey(&row, &key);
        var current: u64 = 0;
        var expiry: ?i64 = null;
        if (try row.row()) {
            const saved = try row.signed(0);
            if (saved <= 0) return error.DatabaseFailure;
            current = @intCast(saved);
            if (self.api.column_type(row.ptr, 1) != 5) expiry = try row.signed(1);
        }
        if (current != expected) return error.StaleConsumerCheckpoint;
        if (deadline) |required| if (required.value != expiry) return error.StaleConsumerCheckpoint;
    }
    fn checkConsumerBatch(self: *Store, batch: consumers.Batch, allow_history: bool) Error!void {
        for (batch.dependencies) |dependency|
            try self.checkConsumerRevision(dependency.key, dependency.expected_revision, .{ .value = dependency.valid_until_us });
        for (batch.deltas) |delta| {
            if (delta.key.kind == .history and !allow_history) return error.InvalidHistoryTransition;
            if (dnsAuthority(delta.key) and (delta.expected_revision != 0 or delta.format_version != 1 or delta.valid_until_us != null or !std.mem.eql(u8, delta.payload, &delta.key.generation))) return error.InvalidConsumer;
            try self.checkConsumerRevision(delta.key, delta.expected_revision, null);
        }
        _ = try self.checkConsumerTime(batch);
    }
    fn checkConsumerTime(self: *Store, batch: consumers.Batch) Error!i64 {
        const durable_floor = try self.readAdmissionClock(self.schema_version);
        self.consumer_clock_floor_us = if (durable_floor) |floor| @max(batch.prepared_us, floor.us) else batch.prepared_us;
        return batch.checkedTime(self.consumer_clock_floor_us);
    }
    fn commitConsumerClock(self: *Store, batch: consumers.Batch) Error!void {
        const now = try self.checkConsumerTime(batch);
        var row = try self.statement("UPDATE consumer_clock SET floor_us=?1 WHERE id=1 AND (floor_us IS NULL OR floor_us<=?1);");
        defer row.deinit();
        try row.int(1, now);
        try row.done();
        if (self.api.changes(self.db) != 1) return error.ConsumerClockReversed;
    }
    fn writeConsumerBatch(self: *Store, batch: consumers.Batch) Error!void {
        for (batch.deltas) |delta| {
            var row = try self.statement("INSERT INTO consumer_checkpoints VALUES(?1,?2,?3,?4,?5,?6,1,?7,?8) ON CONFLICT(kind,jail,source,rule,generation) DO UPDATE SET format=excluded.format,revision=consumer_checkpoints.revision+1,payload=excluded.payload,valid_until_us=excluded.valid_until_us;");
            defer row.deinit();
            try bindConsumerKey(&row, &delta.key);
            try row.int(6, delta.format_version);
            try row.blob(7, delta.payload);
            if (delta.valid_until_us) |expiry| try row.int(8, expiry);
            try row.done();
            try self.fault(.after_consumer_delta);
        }
        if (self.schema_version >= 12) try self.bumpConsumerRevision();
    }

    /// Register the entire jail before source activation. Enabling retry on an
    /// already acknowledged evidence-only jail requires a migration boundary;
    /// silently starting with an empty window would lose protection history.
    pub fn admitRetry(self: *Store, jail: []const u8, generation: [32]u8, policy: retry.Policy) Error!void {
        if (jail.len == 0 or jail.len > 64 or std.mem.indexOfScalar(u8, jail, 0) != null) return error.InvalidRecord;
        _ = try policy.encode();
        try self.beginAdmissionWrite();
        errdefer self.rollback();
        if (!try self.checkRetryAdmission(jail, generation, policy)) {
            const encoded = try policy.encode();
            var insert = try self.statement("INSERT INTO retry_policies VALUES(?1,?2,?3);");
            defer insert.deinit();
            try insert.text(1, jail);
            try insert.blob(2, &generation);
            try insert.blob(3, &encoded);
            try insert.done();
        }
        try self.commitTransaction();
    }

    /// The same read-only predicate is used by the all-jail startup fence and
    /// by each eventual registration transaction. False means genuinely fresh.
    fn checkRetryAdmission(self: *Store, jail: []const u8, generation: [32]u8, policy: retry.Policy) Error!bool {
        if (jail.len == 0 or jail.len > 64 or std.mem.indexOfScalar(u8, jail, 0) != null) return error.InvalidRecord;
        const encoded = try policy.encode();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 9 or schema > latest_schema) return error.RetryStorageRequired;
        if (try self.readRetryPolicy(jail)) |saved| {
            if (!std.mem.eql(u8, &saved.generation, &generation) or !std.mem.eql(u8, &try saved.policy.encode(), &encoded)) return error.RetryGenerationMismatch;
            return true;
        }
        if (try self.revision(jail) != 0) return error.RetryMigrationRequired;
        var pending = try self.statement("SELECT 1 FROM pending_receipts WHERE jail=?1 LIMIT 1;");
        defer pending.deinit();
        try pending.text(1, jail);
        if (try pending.row()) return error.RetryMigrationRequired;
        return false;
    }

    pub const RuntimeAdmission = struct {
        jail: []const u8,
        generation: [32]u8,
        policy: retry.Policy,
        custom: bool = false,
    };
    /// Refuse any retained incompatible owner before first-use registrations.
    /// One bounded read transaction observes all configured generations together;
    /// per-owner write transactions still recheck their own exact admission.
    pub fn validateRuntimeAdmissions(self: *Store, admissions: []const RuntimeAdmission, resolver_generation: ?[32]u8) !void {
        if (admissions.len == 0 or admissions.len > 64) return error.InvalidRecord;
        try self.beginRead();
        errdefer self.rollback();
        var names: [64][]const u8 = undefined;
        for (admissions, 0..) |binding, i| {
            names[i] = binding.jail;
            for (names[0..i]) |prior| if (std.mem.eql(u8, prior, binding.jail)) return error.InvalidRecord;
            _ = try self.checkRetryAdmission(binding.jail, binding.generation, binding.policy);
            var pending = try self.statement("SELECT 1 FROM pending_receipts WHERE jail=?1 AND generation!=?2 LIMIT 1;");
            defer pending.deinit();
            try pending.text(1, binding.jail);
            try pending.blob(2, &binding.generation);
            if (try pending.row()) return error.SourceGenerationMismatch;
        }
        try self.validateOwnerNamesTx(names[0..admissions.len]);
        try self.requireManifestSchema();
        var manifests = try self.statement("SELECT jail,generation FROM consumer_manifests GROUP BY jail,generation;");
        defer manifests.deinit();
        var count: usize = 0;
        while (try manifests.row()) {
            count += 1;
            if (count > admissions.len + 2) return error.ConsumerGenerationMismatch;
            const jail = try manifests.boundedBytes(0, 64);
            const saved = try effectBlob(&manifests, 1, 32);
            if (std.mem.eql(u8, jail, "@history")) continue;
            if (std.mem.eql(u8, jail, "@shared")) {
                const expected = resolver_generation orelse return error.UnconfiguredStateOwner;
                if (!std.mem.eql(u8, &saved, &expected)) return error.ConsumerGenerationMismatch;
                continue;
            }
            for (admissions) |binding| {
                if (!std.mem.eql(u8, jail, binding.jail)) continue;
                if (!binding.custom) return error.UnconfiguredStateOwner;
                if (!std.mem.eql(u8, &saved, &binding.generation)) return error.ConsumerGenerationMismatch;
                break;
            } else return error.UnconfiguredStateOwner;
        }
        try self.commitTransaction();
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
        const retired = try self.readRetired(jail, subject);
        if (!try row.row()) return retired;
        if (retired != null) return error.InvalidRetryState;
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
        try self.beginRead();
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 9 or schema > latest_schema) return error.RetryStorageRequired;
        const admission = (try self.readRetryPolicy(jail)) orelse return error.RetryAdmissionRequired;
        const result = try self.readRetryState(jail, subject, admission.policy);
        try self.commitTransaction();
        return result;
    }

    pub fn validateRuntimeOwners(self: *Store, names: []const []const u8) !void {
        return self.validateOwners(names, null);
    }
    /// Complete configured manifest admission. This is a structural fence;
    /// callers must still restore/decode/recheck every consumer before polling.
    pub fn validateRuntimeOwnersWithManifests(self: *Store, names: []const []const u8, manifests: []const consumers.Manifest) !void {
        return self.validateOwners(names, manifests);
    }
    fn validateOwners(self: *Store, names: []const []const u8, manifests: ?[]const consumers.Manifest) !void {
        if (names.len == 0 or names.len > 64) return error.InvalidRecord;
        try self.beginRead();
        errdefer self.rollback();
        if (manifests) |required| {
            try self.requireManifestSchema();
            if (required.len > 4096) return error.ConsumerCapacity;
            if (try self.integer("SELECT count(*) FROM consumer_manifests;") != required.len) return error.ConsumerManifestMismatch;
            for (required, 0..) |manifest, i| {
                for (required[0..i]) |prior| if (std.mem.eql(u8, prior.jail, manifest.jail) and std.mem.eql(u8, prior.source, manifest.source)) return error.ConsumerManifestMismatch;
                if (!std.mem.eql(u8, manifest.jail, "@shared") and !canonicalHistoryManifest(manifest)) {
                    for (names) |name| {
                        if (std.mem.eql(u8, name, manifest.jail)) break;
                    } else return error.UnconfiguredStateOwner;
                }
                const status = try self.checkManifest(manifest);
                for (manifest.required) |requirement| try self.checkRequiredState(requirement, status == .first_use);
            }
            if (try self.integer("SELECT EXISTS(SELECT 1 FROM consumer_checkpoints c WHERE NOT EXISTS(SELECT 1 FROM consumer_requirements r WHERE r.kind=c.kind AND r.jail=c.jail AND r.source=c.source AND r.rule=c.rule AND r.generation=c.generation AND r.format=c.format));") != 0) return error.ConsumerManifestMismatch;
        } else if (try self.integer("PRAGMA user_version;") >= 10 and
            try self.integer("SELECT EXISTS(SELECT 1 FROM consumer_checkpoints);") != 0)
            return error.NativeConsumersNotIntegrated;
        try self.validateOwnerNamesTx(names);
        try self.commitTransaction();
    }

    /// Preliminary structural check only. This never authorizes source polling;
    /// final consumer ownership and all decoded state fences remain mandatory.
    pub fn validateRuntimeOwnerNames(self: *Store, names: []const []const u8) !void {
        if (names.len == 0 or names.len > 64) return error.InvalidRecord;
        try self.beginRead();
        errdefer self.rollback();
        try self.validateOwnerNamesTx(names);
        try self.commitTransaction();
    }
    /// A persisted source position or receipt proves this is not first use.
    /// Required custom consumers must already have their durable manifest before
    /// startup can reconcile effects, even if the source is currently absent.
    pub fn validateCustomSourceManifests(self: *Store, jail: []const u8) Error!void {
        if (jail.len == 0 or jail.len > 64) return error.InvalidConsumer;
        try self.beginRead();
        errdefer self.rollback();
        try self.requireManifestSchema();
        var missing = try self.statement("SELECT 1 FROM (SELECT source FROM source_cursors WHERE jail=?1 UNION SELECT source FROM pending_receipts WHERE jail=?1) s LEFT JOIN consumer_manifests m ON m.jail=?1 AND m.source=s.source WHERE m.source IS NULL OR m.ready!=1 LIMIT 1;");
        defer missing.deinit();
        try missing.text(1, jail);
        if (try missing.row()) return error.MissingRequiredConsumer;
        try self.commitTransaction();
    }
    fn validateOwnerNamesTx(self: *Store, names: []const []const u8) !void {
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
    }
    /// Call immediately after the runtime's coherent source/shared scans and
    /// before publishing its global recovery gate, with no intervening writes.
    pub fn validateConsumerOwnership(self: *Store, names: []const []const u8, expected_manifest_count: usize, expected_consumer_revision: u64, allow_history: bool) !void {
        if (names.len == 0 or names.len > 64 or expected_manifest_count > 4096) return error.InvalidRecord;
        try self.beginRead();
        errdefer self.rollback();
        try self.requireManifestSchema();
        if (try self.consumerRevision() != expected_consumer_revision) return error.StaleConsumerCheckpoint;
        if (try self.integer("SELECT count(*) FROM consumer_manifests;") != expected_manifest_count) return error.ConsumerManifestMismatch;
        var rows = try self.statement("SELECT jail,source,generation,ready FROM consumer_manifests ORDER BY jail,source;");
        defer rows.deinit();
        var count: usize = 0;
        while (try rows.row()) {
            count += 1;
            if (count > expected_manifest_count) return error.ConsumerCapacity;
            const jail = try rows.boundedBytes(0, 64);
            if (try rows.signed(3) != 1) return error.MissingRequiredConsumer;
            if (std.mem.eql(u8, jail, "@history")) {
                if (!allow_history or !std.mem.eql(u8, try rows.boundedBytes(1, 16384), "confirmed-effects")) return error.UnconfiguredStateOwner;
                const binding = try effectBlob(&rows, 2, 32);
                const required = [_]consumers.Requirement{.{ .key = effect_history.key(binding), .format_version = effect_history.version }};
                const manifest = consumers.Manifest{ .jail = "@history", .source = "confirmed-effects", .source_generation = binding, .required = &required };
                if (try self.checkManifest(manifest) != .ready) return error.MissingRequiredConsumer;
                try self.checkRequiredState(required[0], false);
            } else if (!std.mem.eql(u8, jail, "@shared")) {
                for (names) |name| {
                    if (std.mem.eql(u8, jail, name)) break;
                } else return error.UnconfiguredStateOwner;
            }
        }
        if (try self.integer("SELECT EXISTS(SELECT 1 FROM consumer_checkpoints c WHERE NOT EXISTS(SELECT 1 FROM consumer_requirements r WHERE r.kind=c.kind AND r.jail=c.jail AND r.source=c.source AND r.rule=c.rule AND r.generation=c.generation AND r.format=c.format));") != 0) return error.ConsumerManifestMismatch;
        try self.validateOwnerNamesTx(names);
        try self.commitTransaction();
    }

    pub const ActiveDecision = struct { subject: detection.Subject, expiry_us: i64, ordinal: u64 };
    pub const RetrySummary = struct { subjects: usize = 0, active: usize = 0, decisions: u64 = 0 };
    /// Detached, capacity-admitted status data. No read transaction survives the
    /// call, and expired decisions are excluded without rewriting their deadlines.
    pub fn retrySummary(self: *Store, jail: []const u8, now_us: i64, output: []ActiveDecision) Error!RetrySummary {
        try self.beginRead();
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
        if (self.schema_version >= 15)
            summary.decisions = std.math.add(u64, summary.decisions, try self.retiredTotal(jail)) catch return error.InvalidRetryState;
        try self.commitTransaction();
        return summary;
    }

    /// Bounded startup validation, with no publication or callbacks while the
    /// SQLite snapshot is open. The coordinator serializes this with ingestion.
    pub fn validateRetry(self: *Store, jail: []const u8, generation: [32]u8, policy: retry.Policy) Error!void {
        try self.beginRead();
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 9 or schema > latest_schema) return error.RetryStorageRequired;
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
        try self.commitTransaction();
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
        var output: [max_native_detections]retry.Decision = undefined;
        const count = try self.retryDecisions(jail, source, occurrence, &output);
        if (count > 1) return error.AmbiguousRetryDecision;
        return if (count == 0) null else output[0];
    }
    pub fn retryDecisions(self: *Store, jail: []const u8, source: []const u8, occurrence: ?[]const u8, output: []retry.Decision) Error!usize {
        if (output.len == 0 or output.len > max_native_detections) return error.ConsumerCapacity;
        var row = try self.statement(if (occurrence != null)
            "SELECT family,subject,decided_us,expiry_us,ordinal,enforce FROM retry_decisions WHERE jail=?1 AND source=?2 AND occurrence=?3;"
        else
            "SELECT d.family,d.subject,d.decided_us,d.expiry_us,d.ordinal,d.enforce FROM retry_decisions d JOIN source_cursors c USING(jail,source,occurrence) WHERE d.jail=?1 AND d.source=?2;");
        defer row.deinit();
        try row.text(1, jail);
        try row.text(2, source);
        if (occurrence) |value| try row.text(3, value);
        var count: usize = 0;
        while (try row.row()) {
            if (count >= output.len) return error.ConsumerCapacity;
            const ordinal = try row.signed(4);
            const enforce = try row.signed(5);
            const now = try row.signed(2);
            const expiry = try row.signed(3);
            if (ordinal <= 0 or enforce < 0 or enforce > 1 or expiry <= now) return error.InvalidRetryState;
            output[count] = .{ .subject = try self.decodeRetrySubject(&row, 0, 1), .decided_us = now, .expiry_us = expiry, .ordinal = @intCast(ordinal), .enforce = enforce == 1 };
            count += 1;
        }
        return count;
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
        const retired = try self.readRetired(record.jail, subject);
        if (previous == null or retired != null) {
            var count = try self.statement("SELECT count(*) FROM retry_states WHERE jail=?1;");
            defer count.deinit();
            try count.text(1, record.jail);
            if (!try count.row()) return error.DatabaseFailure;
            if (try count.signed(0) >= admission.policy.max_subjects) return error.RetryCapacity;
        }
        const next = try retry.advance(admission.policy, previous, subject, .{ .at_us = outcome.eligible.timestamp.us, .occurrence = retry.occurrenceKey(record.source, record.occurrence) }, now);
        if (retired) |prior| {
            try self.changeRetiredTotal(record.jail, prior.decisions, false);
            var remove = try self.statement("DELETE FROM retry_retired WHERE jail=?1 AND family=?2 AND subject=?3;");
            defer remove.deinit();
            try remove.text(1, record.jail);
            try bindSubject(&remove, &subject);
            try remove.done();
            if (self.api.changes(self.db) != 1) return error.InvalidRetryState;
        }
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
            if (decision.enforce) {
                if (self.schema_version < 11) return error.EffectStorageRequired;
                const clock = record.effects_clock orelse return error.InstallationRequired;
                const effect_now = try self.effectClock(clock);
                const installation = try self.readInstallation() orelse return error.InstallationRequired;
                const scope = try effects.Scope.host(subject);
                const key = try scope.key(installation);
                var owners: [effects.max_page]effects.Owner = undefined;
                const count = try self.readOwners(key, &owners);
                var effect_revision: u64 = 0;
                for (owners[0..count]) |owner| if (std.mem.eql(u8, owner.jail.slice(), record.jail)) {
                    effect_revision = owner.revision;
                };
                const identity = if (self.schema_version >= 12)
                    effects.hashParts("fail2zig-native-effect-decision-v2", &.{ record.jail, record.source, record.occurrence, &admission.generation, &key })
                else
                    effects.hashParts("fail2zig-native-effect-decision-v1", &.{ record.jail, record.source, record.occurrence, &admission.generation });
                _ = try self.setOwnerTx(.{ .scope = scope, .jail = record.jail, .generation = admission.generation, .decision_id = identity, .expected_revision = effect_revision, .lease = .{ .finite = decision.expiry_us }, .decided_us = decision.decided_us }, effect_now);
            }
        }
    }

    /// Null is an empty admitted store, not a missing/corrupt singleton. The
    /// signed floor is the greatest durably accepted receipt across all owners.
    pub fn receiptClock(self: *Store) Error!?native_time.Timestamp {
        try self.beginRead();
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 7 or schema > latest_schema) return error.UnsupportedSchema;
        const value = try self.readReceiptClock();
        try self.commitTransaction();
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
        try self.beginRead();
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 7 or schema > latest_schema) return error.UnsupportedSchema;
        const value = try self.readAdmissionClock(schema);
        try self.commitTransaction();
        return value;
    }
    fn readAdmissionClock(self: *Store, schema: i64) Error!?native_time.Timestamp {
        var value = try self.readReceiptClock();
        if (schema >= 9) if (try self.readRetryClock()) |floor| {
            value = .{ .us = if (value) |receipt| @max(receipt.us, floor) else floor };
        };
        if (schema >= 10) {
            var row = try self.statement("SELECT id,floor_us FROM consumer_clock ORDER BY id;");
            defer row.deinit();
            if (!try row.row() or try row.signed(0) != 1) return error.InvalidConsumer;
            if (try row.optionalSigned(1)) |floor| value = .{ .us = if (value) |prior| @max(prior.us, floor) else floor };
            if (try row.row()) return error.InvalidConsumer;
        }
        if (schema >= 11) {
            var row = try self.statement("SELECT singleton,floor_us,revision FROM effect_clock ORDER BY singleton;");
            defer row.deinit();
            if (!try row.row() or try row.signed(0) != 1 or try row.signed(2) < 0) return error.InvalidEffect;
            if (try row.optionalSigned(1)) |floor| value = .{ .us = if (value) |prior| @max(prior.us, floor) else floor };
            if (try row.row()) return error.InvalidEffect;
        }
        if (schema >= 15) {
            var row = try self.statement("SELECT revision,floor_us FROM maintenance_clock WHERE id=1;");
            defer row.deinit();
            if (!try row.row() or try row.signed(0) < 0) return error.InvalidMaintenanceState;
            if (try row.optionalSigned(1)) |floor| value = .{ .us = if (value) |prior| @max(prior.us, floor) else floor };
        }
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
        var output: [max_native_detections]detection.Outcome = undefined;
        const count = try self.nativeDetections(jail, source, occurrence, &output);
        if (count > 1) return error.AmbiguousNativeDetection;
        return if (count == 0) null else output[0];
    }
    pub fn nativeDetections(self: *Store, jail: []const u8, source: []const u8, occurrence: ?[]const u8, output: []detection.Outcome) Error!usize {
        if (output.len == 0 or output.len > max_native_detections) return error.ConsumerCapacity;
        try self.beginRead();
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema > latest_schema) return error.UnsupportedSchema;
        if (schema < 6) return error.DetectionStorageRequired;
        self.schema_version = schema;
        const value = try self.readDetections(jail, source, occurrence, output);
        try self.commitTransaction();
        return value;
    }
    fn readDetections(self: *Store, jail: []const u8, source: []const u8, occurrence: ?[]const u8, output: []detection.Outcome) Error!usize {
        var row = try self.statement(if (self.schema_version >= 12)
            "SELECT version,kind,generation,filter,pattern,pattern_index,family,subject,ordinal FROM record_detections WHERE jail=?1 AND source=?2 AND occurrence=COALESCE(?3,(SELECT occurrence FROM source_cursors WHERE jail=?1 AND source=?2)) ORDER BY ordinal;"
        else
            "SELECT version,kind,generation,filter,pattern,pattern_index,family,subject,0 FROM record_detections WHERE jail=?1 AND source=?2 AND occurrence=COALESCE(?3,(SELECT occurrence FROM source_cursors WHERE jail=?1 AND source=?2));");
        defer row.deinit();
        try row.text(1, jail);
        try row.text(2, source);
        if (occurrence) |value| try row.text(3, value) else try self.check(self.api.bind_null(row.ptr, 3));
        var count: usize = 0;
        while (try row.row()) {
            if (count >= output.len) return error.ConsumerCapacity;
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
            if (try row.signed(8) != count) return error.InvalidRecord;
            if (result.subject) |subject| for (output[0..count]) |prior| {
                if (prior.subject) |previous| if (std.meta.eql(subject, previous)) return error.InvalidRecord;
            };
            output[count] = result;
            count += 1;
        }
        return count;
    }

    /// Null occurrence reads the latest committed source position, including a
    /// baseline (which has no native time). No long-lived reader escapes here.
    pub fn nativeTime(self: *Store, jail: []const u8, source: []const u8, occurrence: ?[]const u8) Error!?time_policy.Result {
        // Pin schema and row to one read snapshot. Another connection may have
        // upgraded since open; stale schema-4 knowledge must not erase provenance.
        try self.beginRead();
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 4 or schema > latest_schema) return error.UnsupportedSchema;
        self.schema_version = schema;
        const outcome = try self.readNativeTime(jail, source, occurrence);
        try self.commitTransaction();
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
            if (self.schema_version >= 11) _ = try self.readTimeProvenance(jail, source, occurrence);
            return null;
        }
        const kind = std.meta.intToEnum(native_record.Kind, try row.signed(0)) catch return error.DatabaseFailure;
        const inferred_year = if (try row.optionalSigned(5)) |year| std.math.cast(u16, year) orelse return error.DatabaseFailure else null;
        const stored = native_record.Stored{ .kind = kind, .original_us = try row.optionalSigned(1), .effective_us = try row.optionalSigned(2), .inferred_year = inferred_year, .zone = if (self.schema_version >= 11) try self.readTimeProvenance(jail, source, occurrence) else null };
        const outcome = stored.outcome(.{ .us = try row.signed(3) }) catch return error.DatabaseFailure;
        if (!std.mem.eql(u8, outcome.disposition(), try row.boundedBytes(4, 64))) return error.DatabaseFailure;
        return outcome;
    }

    fn readTimeProvenance(self: *Store, jail: []const u8, source: []const u8, occurrence: ?[]const u8) Error!?native_record.Provenance {
        var row = try self.statement("SELECT zone_digest,zone_offset_seconds,zone_ambiguity,zone_fold,native_time_kind,original_us FROM records WHERE jail=?1 AND source=?2 AND occurrence=COALESCE(?3,(SELECT occurrence FROM source_cursors WHERE jail=?1 AND source=?2));");
        defer row.deinit();
        try row.text(1, jail);
        try row.text(2, source);
        if (occurrence) |value| try row.text(3, value);
        if (!try row.row()) return null;
        if (self.api.column_type(row.ptr, 0) == 5) {
            if (try row.optionalSigned(1) != null or try row.optionalSigned(2) != null or try row.optionalSigned(3) != null) return error.InvalidRecord;
            return null;
        }
        if (try row.optionalSigned(4) == null or try row.optionalSigned(5) == null) return error.InvalidRecord;
        const ambiguity = std.meta.intToEnum(@FieldType(native_record.Provenance, "ambiguity"), try row.signed(2)) catch return error.InvalidRecord;
        const fold = try row.signed(3);
        if (fold < 0 or fold > 1) return error.InvalidRecord;
        const result = native_record.Provenance{ .zone_digest = try effectBlob(&row, 0, 32), .offset_seconds = std.math.cast(i32, try row.signed(1)) orelse return error.InvalidRecord, .ambiguity = ambiguity, .fold_selected = fold == 1 };
        result.validate() catch return error.InvalidRecord;
        return result;
    }
    pub fn nativeTimeProvenance(self: *Store, jail: []const u8, source: []const u8, occurrence: ?[]const u8) Error!?native_record.Provenance {
        try self.beginRead();
        errdefer self.rollback();
        try self.effectSchema();
        _ = try self.readNativeTime(jail, source, occurrence);
        const value = try self.readTimeProvenance(jail, source, occurrence);
        try self.commitTransaction();
        return value;
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
        try self.checkReplayGuard(identity.jail, identity.source, identity.occurrence, identity.raw_hash, identity.cursor, identity.generation, null);
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
        try self.beginWrite();
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 3 or schema > latest_schema) return error.UnsupportedSchema;
        self.schema_version = schema;
        try self.checkReplayGuard(identity.jail, identity.source, identity.occurrence, identity.raw_hash, identity.cursor, identity.generation, null);
        if (schema >= 7) _ = try self.readReceiptClock();
        if (expected_revision >= std.math.maxInt(i64) or try self.revision(identity.jail) != expected_revision) return error.StaleCheckpoint;
        try self.validateReceiptGeneration(identity.jail, identity.generation);
        if (try self.hasRecord(identity.jail, identity.source, identity.occurrence, identity.raw_hash, identity.cursor)) return error.ReceiptAlreadyCommitted;
        if (try self.pendingReceipt(identity)) |saved| {
            try self.commitTransaction();
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
        try self.commitTransaction();
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
        if (self.api.get_autocommit(self.db) != 0) {
            if (self.startup_admission) self.reopen_required = true;
            self.startup_operation = false;
            return;
        }
        if (self.startup_admission) {
            if (!self.startup_operation) {
                self.reopen_required = true;
                return;
            }
            const rc = self.api.exec(self.db, "ROLLBACK TO native_startup_operation; RELEASE native_startup_operation;", null, null, null);
            self.startup_operation = false;
            if (rc != 0) {
                self.rollback_error_code = self.failureCode(rc);
                self.reopen_required = true;
            }
            return;
        }
        const rc = self.api.exec(self.db, "ROLLBACK;", null, null, null);
        if (rc != 0) self.rollback_error_code = self.failureCode(rc);
        // Never expose this connection's uncommitted state after failed cleanup.
        if (rc != 0 or self.api.get_autocommit(self.db) == 0) self.reopen_required = true;
    }
    fn exec(self: *Store, sql: [:0]const u8) Error!void {
        try self.usable();
        if (self.runtime_limits and self.api.get_autocommit(self.db) != 0) self.work_remaining = 1000;
        const rc = self.api.exec(self.db, sql, null, null, null);
        // A failed COMMIT does not prove rollback. In particular an IO failure
        // can leave autocommit enabled without establishing whether durable
        // owners changed. Invalidate all process-local publication authority;
        // reopening and coherent restoration must settle that uncertainty.
        if (rc != 0 and std.mem.eql(u8, sql, "COMMIT;") and
            (self.api.get_autocommit(self.db) != 0 or rc & 0xff == 10 or rc & 0xff == 11)) self.reopen_required = true;
        try self.check(rc);
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
    fn recordDetections(record: *const Record) Error![]const detection.Outcome {
        if (record.native_detections) |values| {
            if (record.native_detection != null or values.len == 0 or values.len > max_native_detections) return error.InvalidRecord;
            for (values, 0..) |value, i| if (value.subject) |subject| {
                for (values[0..i]) |prior| if (prior.subject) |previous| {
                    if (std.meta.eql(subject, previous)) return error.InvalidRecord;
                };
            };
            return values;
        }
        if (record.native_detection) |*value| return @as(*const [1]detection.Outcome, @ptrCast(value));
        return &.{};
    }
    pub fn commitRecord(self: *Store, record: Record) Error!CommitResult {
        try self.usable();
        const detections = try recordDetections(&record);
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
        if (record.consumers) |batch| try batch.validate();
        try self.beginWrite();
        errdefer self.rollback();
        // Never let an old adapter or a baseline skip unresolved native input.
        // Another connection may have activated native storage since open.
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 2 or schema > latest_schema) return error.UnsupportedSchema;
        self.schema_version = schema;
        const source_generation = if (schema >= 14) try recordGeneration(&record) else null;
        try self.checkReplayGuard(record.jail, record.source, record.occurrence, record.raw_hash, record.cursor, source_generation, if (record.receipt) |value| value.time.us else null);
        if (schema >= 9) {
            const registered = try self.readRetryPolicy(record.jail);
            if ((registered != null) != (record.native_retry != null)) return error.RetryAdmissionRequired;
            if (registered) |saved| {
                const supplied = record.native_retry.?;
                if (!std.mem.eql(u8, &saved.generation, &supplied.generation) or !std.mem.eql(u8, &try saved.policy.encode(), &try supplied.policy.encode())) return error.RetryGenerationMismatch;
                if (record.receipt) |receipt| {
                    if (!std.mem.eql(u8, &receipt.generation, &supplied.generation) or detections.len == 0 or
                        (supplied.processing_us orelse return error.InvalidRecord) < receipt.time.us) return error.InvalidRecord;
                } else if (detections.len != 0 or supplied.processing_us != null) return error.InvalidRecord;
            }
        } else if (record.native_retry != null) return error.RetryStorageRequired;
        const native_values: ?native_record.Stored = if (record.native_time_outcome) |outcome| blk: {
            if (schema < 4 or record.event_time != null) return error.InvalidRecord;
            const receipt = record.receipt orelse return error.ReceiptRequired;
            if (!std.mem.eql(u8, outcome.disposition(), record.disposition)) return error.InvalidRecord;
            var values = native_record.Stored.fromOutcome(outcome, receipt.time) catch return error.InvalidRecord;
            if (record.zone_provenance) |zone| {
                if (schema < 11) return error.EffectStorageRequired;
                values.zone = zone;
                _ = values.outcome(receipt.time) catch return error.InvalidRecord;
            }
            if (values.inferred_year != null and schema < 5) return error.InferenceStorageRequired;
            break :blk values;
        } else if (record.zone_provenance != null) return error.InvalidRecord else null;
        if (record.native_detections != null and schema < 12) return error.DetectionStorageRequired;
        for (detections) |value| {
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
        if (schema >= 12) {
            if (try self.manifestExists(record.jail, record.source) != (record.consumer_manifest != null)) return error.ConsumerManifestRequired;
            if (record.consumer_manifest) |manifest| {
                if (!std.mem.eql(u8, manifest.jail, record.jail) or !std.mem.eql(u8, manifest.source, record.source)) return error.ConsumerManifestMismatch;
                const status = try self.checkManifest(manifest);
                for (manifest.required) |requirement| try self.checkRequiredState(requirement, status == .first_use);
                if (record.receipt) |receipt| if (!std.mem.eql(u8, &receipt.generation, &manifest.source_generation)) return error.ConsumerManifestMismatch;
            }
        }
        {
            var prior = try self.statement("SELECT raw_hash,cursor FROM records WHERE jail=?1 AND source=?2 AND occurrence=?3;");
            defer prior.deinit();
            try prior.text(1, record.jail);
            try prior.text(2, record.source);
            try prior.text(3, record.occurrence);
            if (try prior.row()) {
                if (!std.mem.eql(u8, try prior.boundedBytes(0, 32), &record.raw_hash) or !std.mem.eql(u8, try prior.boundedBytes(1, Limits.cursor_bytes), record.cursor)) return error.OccurrenceConflict;
                if (schema >= 11 and !std.meta.eql(try self.readTimeProvenance(record.jail, record.source, record.occurrence), record.zone_provenance)) return error.OccurrenceConflict;
                if (schema >= 14) if (try self.recordSequence(record.jail, record.source, record.occurrence)) |ordered| {
                    const supplied = source_generation orelse return error.OccurrenceConflict;
                    if (!std.mem.eql(u8, &supplied, &ordered.generation)) return error.OccurrenceConflict;
                };
                try self.commitTransaction();
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
        if (schema >= 12) {
            const registered = try self.manifestExists(record.jail, record.source);
            if (registered != (record.consumer_manifest != null)) return error.ConsumerManifestRequired;
            if (record.consumer_manifest) |manifest| {
                if (!std.mem.eql(u8, manifest.jail, record.jail) or !std.mem.eql(u8, manifest.source, record.source)) return error.ConsumerManifestMismatch;
                if (record.receipt) |receipt| if (!std.mem.eql(u8, &receipt.generation, &manifest.source_generation)) return error.ConsumerManifestMismatch;
                if (record.receipt == null and detections.len != 0) return error.ReceiptRequired;
                const batch = record.consumers orelse return error.ConsumerManifestRequired;
                try self.checkManifestBatch(manifest, batch, true, false);
            } else if (record.consumers != null) return error.ConsumerManifestRequired;
        } else if (record.consumer_manifest != null) return error.ConsumerStorageRequired;
        if (record.consumers) |batch| {
            if (schema < 10) return error.ConsumerStorageRequired;
            try self.checkConsumerBatch(batch, false);
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
        if (source_generation) |value| _ = try self.advanceSourceSequence(&record, value);
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
        if (record.zone_provenance) |zone| {
            var row = try self.statement("UPDATE records SET zone_digest=?4,zone_offset_seconds=?5,zone_ambiguity=?6,zone_fold=?7 WHERE jail=?1 AND source=?2 AND occurrence=?3;");
            defer row.deinit();
            try row.text(1, record.jail);
            try row.text(2, record.source);
            try row.text(3, record.occurrence);
            try row.blob(4, &zone.zone_digest);
            try row.int(5, zone.offset_seconds);
            try row.int(6, @intFromEnum(zone.ambiguity));
            try row.int(7, @intFromBool(zone.fold_selected));
            try row.done();
        }
        for (detections, 0..) |value, ordinal| {
            var row = try self.statement(if (schema >= 12)
                "INSERT INTO record_detections(jail,source,occurrence,version,kind,generation,filter,pattern,pattern_index,family,subject,ordinal) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12);"
            else
                "INSERT INTO record_detections(jail,source,occurrence,version,kind,generation,filter,pattern,pattern_index,family,subject) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11);");
            if (schema >= 12) try row.int(12, @intCast(ordinal));
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
        if (record.native_retry) |admission| {
            if (detections.len == 0) try self.commitRetry(record, admission);
            for (detections) |value| {
                var scalar = record;
                scalar.native_detection = value;
                scalar.native_detections = null;
                try self.commitRetry(scalar, admission);
            }
        }
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
        if (record.consumers) |batch| try self.writeConsumerBatch(batch);
        if (record.consumer_manifest) |manifest| try self.readyManifest(manifest);
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
        if (record.consumers) |batch| try self.commitConsumerClock(batch);
        if (record.effects_clock) |clock| {
            if (schema < 11) return error.EffectStorageRequired;
            const now = try self.commitEffectClock(clock);
            var decisions: [max_native_detections]retry.Decision = undefined;
            const count = try self.retryDecisions(record.jail, record.source, record.occurrence, &decisions);
            for (decisions[0..count]) |decision| if (decision.enforce and now >= decision.expiry_us) return error.EffectExpired;
        }
        const effect_changed = if (record.native_retry) |admission| admission.policy.enforce and try self.hasEnforcingDecision(record) else false;
        try self.commitTransaction();
        if (effect_changed) self.effect_publication_epoch +|= 1;
        return .committed;
    }
    fn hasEnforcingDecision(self: *Store, record: Record) Error!bool {
        var row = try self.statement("SELECT EXISTS(SELECT 1 FROM retry_decisions WHERE jail=?1 AND source=?2 AND occurrence=?3 AND enforce=1);");
        defer row.deinit();
        try row.text(1, record.jail);
        try row.text(2, record.source);
        try row.text(3, record.occurrence);
        if (!try row.row()) return error.DatabaseFailure;
        return try row.signed(0) == 1;
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

    pub const SourcePosition = struct {
        source: []u8,
        path: []u8,
        cursor: []u8,
        pub fn deinit(self: SourcePosition, a: std.mem.Allocator) void {
            a.free(self.source);
            a.free(self.path);
            a.free(self.cursor);
        }
    };
    /// One coherent detached row. No read transaction remains across source IO.
    pub fn readSourcePosition(self: *Store, a: std.mem.Allocator, jail: []const u8, after_source: ?[]const u8, expected_revision: u64) Error!?SourcePosition {
        try self.beginRead();
        errdefer self.rollback();
        if (try self.revision(jail) != expected_revision) return error.StaleCheckpoint;
        const result: ?SourcePosition = blk: {
            var row = try self.statement("SELECT source,COALESCE(path,''),cursor FROM source_cursors WHERE jail=?1 AND (?2 IS NULL OR source>?2) ORDER BY source LIMIT 1;");
            defer row.deinit();
            try row.text(1, jail);
            if (after_source) |value| try row.text(2, value) else try self.check(self.api.bind_null(row.ptr, 2));
            if (!try row.row()) break :blk null;
            inline for (0..3) |i| if (self.api.column_type(row.ptr, i) != (if (i == 2) @as(c_int, 4) else 3)) return error.InvalidRecord;
            const source = try a.dupe(u8, try row.boundedBytes(0, Limits.source_bytes));
            errdefer a.free(source);
            const path = try a.dupe(u8, try row.boundedBytes(1, Limits.source_bytes));
            errdefer a.free(path);
            const cursor = try a.dupe(u8, try row.boundedBytes(2, Limits.cursor_bytes));
            break :blk .{ .source = source, .path = path, .cursor = cursor };
        };
        errdefer if (result) |value| value.deinit(a);
        try self.commitTransaction();
        return result;
    }
    pub const PendingSource = struct {
        identity: ReceiptIdentity,
        receipt_us: i64,
        pub fn deinit(self: PendingSource, a: std.mem.Allocator) void {
            a.free(self.identity.jail);
            a.free(self.identity.source);
            a.free(self.identity.occurrence);
            a.free(self.identity.cursor);
        }
    };
    pub fn readPendingSource(self: *Store, a: std.mem.Allocator, jail: []const u8, source: []const u8) Error!?PendingSource {
        return self.readPending(a, jail, source, false);
    }
    pub fn readPendingPosition(self: *Store, a: std.mem.Allocator, jail: []const u8, after_source: ?[]const u8) Error!?PendingSource {
        return self.readPending(a, jail, after_source, true);
    }
    fn readPending(self: *Store, a: std.mem.Allocator, jail: []const u8, selected: ?[]const u8, after: bool) Error!?PendingSource {
        if (self.receipt_limit == null) return error.ReceiptStorageRequired;
        var row = try self.statement(if (after)
            "SELECT jail,source,occurrence,cursor,raw_hash,generation,receipt_us FROM pending_receipts WHERE jail=?1 AND (?2 IS NULL OR source>?2) ORDER BY source LIMIT 1;"
        else
            "SELECT jail,source,occurrence,cursor,raw_hash,generation,receipt_us FROM pending_receipts WHERE jail=?1 AND source=?2;");
        defer row.deinit();
        try row.text(1, jail);
        if (selected) |value| try row.text(2, value) else try self.check(self.api.bind_null(row.ptr, 2));
        if (!try row.row()) return null;
        inline for (0..6) |i| if (self.api.column_type(row.ptr, i) != (if (i < 3) @as(c_int, 3) else 4)) return error.InvalidRecord;
        var copied: [4][]u8 = undefined;
        var count: usize = 0;
        errdefer for (copied[0..count]) |value| a.free(value);
        inline for (.{ 4096, Limits.source_bytes, 16384, Limits.cursor_bytes }, 0..) |limit, i| {
            copied[i] = try a.dupe(u8, try row.boundedBytes(i, limit));
            count += 1;
        }
        const raw_hash = try row.boundedBytes(4, 32);
        const generation = try row.boundedBytes(5, 32);
        if (raw_hash.len != 32 or generation.len != 32) return error.InvalidRecord;
        const identity = ReceiptIdentity{ .jail = copied[0], .source = copied[1], .occurrence = copied[2], .cursor = copied[3], .raw_hash = raw_hash[0..32].*, .generation = generation[0..32].* };
        try validateReceiptIdentity(identity);
        return .{ .identity = identity, .receipt_us = try row.signed(6) };
    }

    pub fn hasRecord(self: *Store, jail: []const u8, source: []const u8, occurrence: []const u8, raw_hash: [32]u8, cursor: []const u8) Error!bool {
        try self.checkReplayGuard(jail, source, occurrence, raw_hash, cursor, null, null);
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

test "record store: opening and closing peers preserves SQLite process locks" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(a, ".");
    defer a.free(base);
    const path = try std.fs.path.join(a, &.{ base, "locks.sqlite" });
    defer a.free(path);
    var store = try Store.open(a, path);
    defer store.close();
    for (0..2) |pass| {
        if (pass == 1) {
            var peer = try Store.open(a, path);
            peer.close();
        }
        const pid = try std.posix.fork();
        if (pid == 0) {
            // No SQLite use after fork: independently probe its documented
            // main-file shared-lock range from a different process.
            const fd = std.posix.open(path, .{ .ACCMODE = .RDWR, .CLOEXEC = true }, 0) catch std.process.exit(2);
            var lock: std.posix.Flock = std.mem.zeroes(std.posix.Flock);
            lock.type = std.posix.F.WRLCK;
            lock.whence = std.posix.SEEK.SET;
            lock.start = 0x40000002;
            lock.len = 510;
            _ = std.posix.fcntl(fd, std.posix.F.SETLK, @intFromPtr(&lock)) catch |failure| {
                std.posix.close(fd);
                std.process.exit(if (failure == error.Locked or failure == error.AccessDenied) 0 else 3);
            };
            std.posix.close(fd);
            std.process.exit(4); // Acquiring this lock could permit WAL unlink.
        }
        const result = std.posix.waitpid(pid, 0);
        try std.testing.expectEqual(@as(u32, 0), result.status);
    }
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

test "native consumers: killed migration and multi-state commits retain original receipt" {
    const a = std.testing.allocator;
    for ([_]bool{ false, true }) |migration| for ([_]bool{ false, true }) |after| {
        var temp = std.testing.tmpDir(.{});
        defer temp.cleanup();
        const root = try temp.dir.realpathAlloc(a, ".");
        defer a.free(root);
        const path = try std.fs.path.join(a, &.{ root, "consumer-kill.sqlite" });
        defer a.free(path);
        const identity = ReceiptIdentity{ .jail = "fixture", .source = "file", .occurrence = "1", .cursor = "1", .raw_hash = [_]u8{1} ** 32, .generation = [_]u8{2} ** 32 };
        const key = consumers.Key{ .kind = .correlation, .jail = "fixture", .source = "file", .rule = "pair", .generation = [_]u8{3} ** 32 };
        {
            var store = try Store.open(a, path);
            defer store.close();
            try store.enableReceipts(1);
            try store.enableNativeTime();
            try store.enableDetection();
            try store.enableClockRecovery();
            try store.enableJournalDetection();
            try store.enableRetry();
            if (!migration) {
                try store.enableConsumers();
                _ = try store.beginReceipt(identity, .{ .us = 100 }, 0);
            }
        }
        const pid = try std.posix.fork();
        if (pid == 0) {
            var child = Store.open(std.heap.page_allocator, path) catch std.process.exit(2);
            const Kill = struct {
                var after_commit: bool = false;
                fn exec(db: *Db, sql: [*:0]const u8, callback: ?*anyopaque, context: ?*anyopaque, message: ?*?[*:0]u8) callconv(.c) c_int {
                    if (!std.mem.eql(u8, std.mem.span(sql), "COMMIT;")) return embedded_api.exec(db, sql, callback, context, message);
                    if (after_commit and embedded_api.exec(db, sql, callback, context, message) != 0) std.process.exit(3);
                    std.posix.kill(std.os.linux.getpid(), std.posix.SIG.KILL) catch std.process.exit(4);
                    unreachable;
                }
                fn clock(_: ?*anyopaque) i64 {
                    return 100;
                }
            };
            Kill.after_commit = after;
            child.api.exec = Kill.exec;
            if (migration) child.enableConsumers() catch std.process.exit(5) else {
                _ = child.commitRecord(.{ .jail = identity.jail, .source = identity.source, .occurrence = identity.occurrence, .cursor = identity.cursor, .raw_hash = identity.raw_hash, .receipt = .{ .time = .{ .us = 100 }, .generation = identity.generation }, .disposition = "counted", .checkpoint = "source", .consumers = .{ .prepared_us = 100, .clock = Kill.clock, .deltas = &.{.{ .key = key, .format_version = 1, .expected_revision = 0, .payload = "context" }} } }) catch std.process.exit(6);
            }
            std.process.exit(7);
        }
        const ended = std.posix.waitpid(pid, 0);
        try std.testing.expect(std.posix.W.IFSIGNALED(ended.status));
        try std.testing.expectEqual(@as(u32, std.posix.SIG.KILL), std.posix.W.TERMSIG(ended.status));
        var restored = try Store.open(a, path);
        defer restored.close();
        if (migration) {
            try std.testing.expectEqual(@as(i64, if (after) 10 else 9), restored.schema_version);
            try std.testing.expectEqual(@as(i64, @intFromBool(after)), try restored.integer("SELECT count(*) FROM sqlite_master WHERE name='consumer_checkpoints';"));
        } else {
            const state = try restored.consumerSnapshot(a, key);
            defer state.deinit(a);
            try std.testing.expectEqual(@as(u64, @intFromBool(after)), state.revision);
            try std.testing.expectEqual(@as(u64, @intFromBool(after)), try restored.revision("fixture"));
            try std.testing.expectEqual(@as(usize, @intFromBool(!after)), try restored.pendingReceiptCount());
            const original = if (after) try restored.committedReceipt(identity) else try restored.pendingReceipt(identity);
            try std.testing.expectEqual(@as(i64, 100), original.?.us);
            if (after) {
                var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
                try std.testing.expectError(error.OutOfMemory, restored.consumerSnapshot(failing.allocator(), key));
                try restored.exec("PRAGMA ignore_check_constraints=ON; UPDATE consumer_checkpoints SET payload='foreign-text';");
                try std.testing.expectError(error.InvalidConsumer, restored.consumerSnapshot(a, key));
                // Type rejection does not destroy the authoritative checkpoint.
                try std.testing.expectEqual(@as(i64, 1), try restored.integer("SELECT count(*) FROM consumer_checkpoints;"));
            }
        }
    };
}
