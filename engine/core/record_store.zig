// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const builtin = @import("builtin");
const native_time = @import("native_time.zig");
const time_policy = @import("source_time_policy.zig");
const native_record = @import("native_time_record.zig");
const detection = @import("native_detection_record.zig");
const retry = @import("native_retry.zig");
const action_context = @import("native_action_context.zig");
const consumers = @import("native_consumer.zig");
const effects = @import("native_effect.zig");
const effect_history = @import("native_effect_history.zig");
const application_history = @import("native_application_history.zig");
const action_outcome = @import("native_action_outcome.zig");
pub const latest_schema: i64 = 23;
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
pub const Error = application_history.Error || action_outcome.Error || retry.Error || consumers.Error || effects.Error || effect_history.Error || action_context.Error || error{ MaintenancePinned, StaleMaintenance, PrunedReplay, InvalidMaintenanceState, MaintenanceStorageRequired, ConsumerManifestRequired, ConsumerManifestMismatch, ConsumerManifestMissing, ConsumerManifestExists, ConsumerMigrationRequired, MissingRequiredConsumer, AmbiguousNativeDetection, AmbiguousRetryDecision, ConsumerStorageRequired, StaleConsumerCheckpoint, OpenFailed, UnsafePermissions, ForeignDatabase, UnsupportedSchema, DatabaseFailure, Busy, StorageFull, ReadOnly, StorageIo, CorruptDatabase, StorageLimit, Interrupted, AccessDenied, ReopenRequired, InvalidRecord, OccurrenceConflict, StaleCheckpoint, StaleSharedCheckpoint, InjectedFailure, OutOfMemory, ReceiptStorageRequired, InferenceStorageRequired, DetectionStorageRequired, ReceiptConflict, ReceiptRequired, ReceiptAlreadyCommitted, ReceiptLimit, RetryStorageRequired, RetryAdmissionRequired, RetryGenerationMismatch, RetryMigrationRequired, RetryCapacity, ReceiptClockReversed, HistoryResetStorageRequired, InvalidHistoryReset, StaleHistoryReset, AdminStorageRequired, MigrationStorageRequired, StaleAdminRevision, InvalidAdminRequest, AdminRequestCapacity, RetryPolicyInFlight, StalePolicyTransition, ConfigGenerationExists, ConfigGenerationMissing, MigrationRunExists, MigrationRunMissing, MigrationStepMissing, MigrationStepOpen, MigrationStepOrder, InvalidMigrationRow, InvalidMigrationState, MigrationJailUnknown };

pub const OpenStage = enum {
    path_validation,
    parent_open,
    parent_stat,
    parent_permissions,
    file_stat,
    file_create,
    created_file_stat,
    file_type,
    file_permissions,
    path_copy,
    sqlite_open,
    connection_setup,
    file_identity_recheck,
    file_identity_changed,
    sqlite_file_identity,
    sqlite_limits,
    schema_inspection,
    schema_validation,
    runtime_setup,
    schema_setup,
    installation_read,
};

pub const OpenPosixCause = enum {
    access_denied,
    file_not_found,
    not_directory,
    symbolic_link_loop,
    name_too_long,
    path_already_exists,
    no_space_left,
    process_file_descriptor_limit,
    system_file_descriptor_limit,
    no_device,
    system_resources,
    file_too_big,
    is_directory,
    device_busy,
    invalid_path,
    unexpected,
};

pub const OpenDiagnostic = struct {
    stage: ?OpenStage = null,
    public_error: ?Error = null,
    posix_cause: ?OpenPosixCause = null,
    sqlite_code: ?c_int = null,
};

fn openPosixCause(failure: anyerror) OpenPosixCause {
    if (failure == error.AccessDenied) return .access_denied;
    if (failure == error.FileNotFound) return .file_not_found;
    if (failure == error.NotDir) return .not_directory;
    if (failure == error.SymLinkLoop) return .symbolic_link_loop;
    if (failure == error.NameTooLong) return .name_too_long;
    if (failure == error.PathAlreadyExists) return .path_already_exists;
    if (failure == error.NoSpaceLeft) return .no_space_left;
    if (failure == error.ProcessFdQuotaExceeded) return .process_file_descriptor_limit;
    if (failure == error.SystemFdQuotaExceeded) return .system_file_descriptor_limit;
    if (failure == error.NoDevice) return .no_device;
    if (failure == error.SystemResources) return .system_resources;
    if (failure == error.FileTooBig) return .file_too_big;
    if (failure == error.IsDir) return .is_directory;
    if (failure == error.DeviceBusy or failure == error.FileBusy) return .device_busy;
    if (failure == error.BadPathName) return .invalid_path;
    return .unexpected;
}

fn openFailure(diagnostic: *OpenDiagnostic, stage: OpenStage, failure: Error, posix_cause: ?OpenPosixCause, sqlite_code: ?c_int) Error {
    diagnostic.* = .{
        .stage = stage,
        .public_error = failure,
        .posix_cause = posix_cause,
        .sqlite_code = sqlite_code,
    };
    return failure;
}

fn sqliteError(rc: c_int) Error {
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
pub const CommitStage = enum { before_admin_schema_commit, before_migration_schema_commit, after_admin_request, after_migration_step_intent, after_migration_step_outcome, before_migration_activation_commit, before_policy_transition_commit, before_config_generation_commit, before_config_generation_publish, before_action_target_schema_commit, after_action_target_intent, before_action_target_dispatch_commit, before_action_target_settlement_commit, before_history_reset_schema_commit, after_history_reset, before_canonical_effect_schema_commit, after_history_detail_delete, after_history_event_delete, before_escalation_schema_commit, before_application_history_schema_commit, before_cleanup_schema_commit, before_retry_lease_schema_commit, after_cleanup_mark, after_cleanup_delete, after_retry_retire, before_maintenance_schema_commit, after_source_sequence, after_replay_guard, after_record, after_checkpoint, after_shared_checkpoint, before_commit, before_receipt_commit, after_receipt_commit, after_receipt_delete, before_receipt_schema_commit, before_native_time_schema_commit, before_inference_schema_commit, before_detection_schema_commit, after_detection, before_clock_schema_commit, before_journal_detection_schema_commit, before_retry_schema_commit, after_retry_state, after_retry_decision, before_consumer_schema_commit, after_consumer_delta, before_effect_schema_commit, after_effect_owner, after_effect_intent, before_effect_dispatch_commit, before_effect_receipt_commit, before_manifest_schema_commit, before_manifest_commit, after_manifest_ready, before_consumer_input_commit };
pub const Limits = struct {
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
pub const HistoryResetScope = union(enum) { jail: []const u8, overall };
pub const HistoryResetIntent = struct {
    scope: HistoryResetScope,
    subject: detection.Subject,
    expected_revision: u64,
    intent_id: [32]u8,
};
pub const HistoryResetResult = struct { revision: u64, through_sequence: u64, reset_us: i64 };
pub const SharedState = struct {
    name: []const u8,
    expected_revision: u64,
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
    native_detections: ?[]const detection.Outcome = null,
    consumer_manifest: ?consumers.Manifest = null,
    native_retry: ?retry.Admission = null,
    retry_suspended: bool = false,
    retry_evidence: retry.Evidence = .{},
    expected_revision: u64 = 0,
    disposition: []const u8,
    checkpoint: []const u8,
    action_intent: ?[]const u8 = null,
    shared_state: ?SharedState = null,
    consumers: ?consumers.Batch = null,
    zone_provenance: ?native_record.Provenance = null,
    effects_clock: ?effects.Clock = null,
};
pub const CommitResult = enum { committed, already_committed };
pub const EscalationSelection = struct {
    scope: retry.EscalationScope,
    prior_confirmed: u64,
    latest_confirmed_us: ?i64,
    chosen_duration_us: i64,
    jitter_us: i64,
};
pub const EffectInvalidation = struct {
    context: ?*anyopaque,
    invalidate: *const fn (?*anyopaque) void,
};
pub const Store = struct {
    allocator: std.mem.Allocator,
    api: Api,
    db: *Db,
    last_error_code: ?c_int = null,
    rollback_error_code: ?c_int = null,
    consumer_clock_floor_us: ?i64 = null,
    effect_publication_epoch: u64 = 0,
    effect_invalidation: ?EffectInvalidation = null,
    reopen_required: bool = false,
    startup_admission: bool = false,
    startup_operation: bool = false,
    fail_at: ?CommitStage = null,
    rekeyed_owners: bool = false,
    schema_version: i64 = 2,
    receipt_limit: ?usize = null,
    runtime_limits: bool = false,
    runtime_path: ?[]const u8 = null,
    work_remaining: u32 = 1000,
    escalation_jitter_context: ?*anyopaque = null,
    escalation_jitter: *const fn (?*anyopaque, u64) u64 = systemEscalationJitter,

    fn systemEscalationJitter(_: ?*anyopaque, maximum_seconds: u64) u64 {
        return std.crypto.random.uintAtMost(u64, maximum_seconds);
    }

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
        self.work_remaining = 1000;
        var row = try self.statement("PRAGMA wal_checkpoint(TRUNCATE);");
        defer row.deinit();
        if (!try row.row()) return error.DatabaseFailure;
        if (try row.signed(0) != 0) {
            self.last_error_code = 5;
            return error.Busy;
        }
    }

    fn beginWrite(self: *Store) Error!void {
        try self.usable();
        if (self.startup_admission) return error.DatabaseFailure;
        if (self.runtime_path) |path| try self.maintainWal(path);
        try self.exec("BEGIN IMMEDIATE;");
    }

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

    // Invalidate before durable publication; a failed COMMIT stays conservatively
    // uncertain until the caller republishes a verified view. Never restore here.
    fn commitEffectTransaction(self: *Store, changed: bool) Error!void {
        if (changed) if (self.effect_invalidation) |hook| hook.invalidate(hook.context);
        try self.commitTransaction();
        if (changed) self.effect_publication_epoch +|= 1;
    }

    pub fn open(allocator: std.mem.Allocator, path: []const u8) Error!Store {
        var ignored = OpenDiagnostic{};
        return openImpl(allocator, path, .plain, &ignored, .{});
    }

    pub fn openDetailed(allocator: std.mem.Allocator, path: []const u8, diagnostic: *OpenDiagnostic) Error!Store {
        return openImpl(allocator, path, .plain, diagnostic, .{});
    }

    pub fn openRuntime(allocator: std.mem.Allocator, path: []const u8) Error!Store {
        var ignored = OpenDiagnostic{};
        return openImpl(allocator, path, .runtime, &ignored, .{});
    }
    pub fn openRuntimeDetailed(allocator: std.mem.Allocator, path: []const u8, diagnostic: *OpenDiagnostic) Error!Store {
        return openImpl(allocator, path, .runtime, diagnostic, .{});
    }
    pub fn openReadOnly(allocator: std.mem.Allocator, path: []const u8) Error!Store {
        var ignored = OpenDiagnostic{};
        return openImpl(allocator, path, .readonly, &ignored, .{});
    }
    pub fn openReadOnlyDetailed(allocator: std.mem.Allocator, path: []const u8, diagnostic: *OpenDiagnostic) Error!Store {
        return openImpl(allocator, path, .readonly, diagnostic, .{});
    }

    pub const InstallationSnapshot = struct {
        schema_version: i64,
        installation: ?effects.Installation,
    };

    pub fn installationSnapshot(allocator: std.mem.Allocator, path: []const u8) Error!InstallationSnapshot {
        var ignored = OpenDiagnostic{};
        return installationSnapshotDetailed(allocator, path, &ignored);
    }

    pub fn installationSnapshotDetailed(allocator: std.mem.Allocator, path: []const u8, diagnostic: *OpenDiagnostic) Error!InstallationSnapshot {
        var store = try openImpl(allocator, path, .preflight, diagnostic, .{});
        defer store.close();
        store.last_error_code = null;
        const installation = if (store.schema_version >= 11)
            store.readInstallation() catch |failure| return openFailure(diagnostic, .installation_read, failure, null, store.last_error_code)
        else
            null;
        return .{
            .schema_version = store.schema_version,
            .installation = installation,
        };
    }

    const OpenMode = enum { plain, runtime, readonly, preflight };
    const OpenHooks = struct {
        context: ?*anyopaque = null,
        before_identity_recheck: ?*const fn (?*anyopaque) void = null,
    };
    fn openImpl(allocator: std.mem.Allocator, path: []const u8, open_mode: OpenMode, diagnostic: *OpenDiagnostic, hooks: OpenHooks) Error!Store {
        diagnostic.* = .{};
        const runtime = open_mode == .runtime;
        if (path.len == 0 or std.mem.indexOfScalar(u8, path, 0) != null)
            return openFailure(diagnostic, .path_validation, error.OpenFailed, null, null);
        var parent = std.fs.cwd().openDir(std.fs.path.dirname(path) orelse ".", .{ .no_follow = true }) catch |failure|
            return openFailure(diagnostic, .parent_open, error.OpenFailed, openPosixCause(failure), null);
        defer parent.close();
        const parent_stat = std.posix.fstat(parent.fd) catch |failure|
            return openFailure(diagnostic, .parent_stat, error.OpenFailed, openPosixCause(failure), null);
        if (parent_stat.uid != std.os.linux.geteuid() or parent_stat.mode & 0o022 != 0)
            return openFailure(diagnostic, .parent_permissions, error.UnsafePermissions, null, null);
        const stat = std.posix.fstatat(std.posix.AT.FDCWD, path, std.posix.AT.SYMLINK_NOFOLLOW) catch |failure| blk: {
            if (failure != error.FileNotFound or open_mode == .readonly or open_mode == .preflight)
                return openFailure(diagnostic, .file_stat, error.OpenFailed, openPosixCause(failure), null);
            const created = std.posix.open(path, .{ .ACCMODE = .RDWR, .CREAT = true, .EXCL = true, .CLOEXEC = true, .NOFOLLOW = true }, 0o600) catch |create_failure|
                return openFailure(diagnostic, .file_create, error.OpenFailed, openPosixCause(create_failure), null);
            defer std.posix.close(created);
            break :blk std.posix.fstat(created) catch |stat_failure|
                return openFailure(diagnostic, .created_file_stat, error.OpenFailed, openPosixCause(stat_failure), null);
        };
        if (!std.posix.S.ISREG(stat.mode))
            return openFailure(diagnostic, .file_type, error.UnsafePermissions, null, null);
        if (stat.mode & 0o077 != 0 or stat.uid != std.os.linux.geteuid())
            return openFailure(diagnostic, .file_permissions, error.UnsafePermissions, null, null);
        const api = embedded_api;
        const filename = allocator.dupeZ(u8, path) catch
            return openFailure(diagnostic, .path_copy, error.OutOfMemory, null, null);
        defer allocator.free(filename);
        var db: ?*Db = null;
        const access_flags: c_int = if (open_mode == .readonly or open_mode == .preflight) 1 else 2;
        const opened = api.open(filename, &db, access_flags | 0x10000 | 0x01000000, null);
        if (opened != 0 or db == null) {
            if (db) |handle| _ = api.close(handle);
            const failure = if (opened != 0) sqliteError(opened) else error.OpenFailed;
            return openFailure(diagnostic, .sqlite_open, failure, null, if (opened != 0) opened else null);
        }
        var self = Store{ .allocator = allocator, .api = api, .db = db.? };
        errdefer _ = self.api.close(self.db);
        const db_config = @extern(*const fn (*Db, c_int, ...) callconv(.c) c_int, .{ .name = "sqlite3_db_config" });
        self.last_error_code = null;
        self.check(db_config(self.db, 1006, @as(c_int, 1), @as(?*c_int, null))) catch |failure|
            return openFailure(diagnostic, .connection_setup, failure, null, self.last_error_code);
        if (builtin.is_test) if (hooks.before_identity_recheck) |hook| hook(hooks.context);
        const selected = std.posix.fstatat(std.posix.AT.FDCWD, path, std.posix.AT.SYMLINK_NOFOLLOW) catch |failure|
            return openFailure(diagnostic, .file_identity_recheck, error.OpenFailed, openPosixCause(failure), null);
        if (selected.dev != stat.dev or selected.ino != stat.ino or selected.uid != stat.uid or selected.mode != stat.mode)
            return openFailure(diagnostic, .file_identity_changed, error.OpenFailed, null, null);
        const file_control = @extern(*const fn (*Db, ?[*:0]const u8, c_int, ?*anyopaque) callconv(.c) c_int, .{ .name = "sqlite3_file_control" });
        var moved: c_int = 1;
        self.last_error_code = null;
        self.check(file_control(self.db, "main", 20, &moved)) catch |failure|
            return openFailure(diagnostic, .sqlite_file_identity, failure, null, self.last_error_code);
        if (moved != 0) return openFailure(diagnostic, .sqlite_file_identity, error.OpenFailed, null, null);
        _ = api.limit(self.db, 0, Limits.sqlite_row_bytes);
        if (api.limit(self.db, 0, -1) != Limits.sqlite_row_bytes)
            return openFailure(diagnostic, .sqlite_limits, error.StorageLimit, null, null);
        self.last_error_code = null;
        self.check(api.busy_timeout(self.db, 1000)) catch |failure|
            return openFailure(diagnostic, .sqlite_limits, failure, null, self.last_error_code);
        const progress = @extern(*const fn (*Db, c_int, ?*const fn (?*anyopaque) callconv(.c) c_int, ?*anyopaque) callconv(.c) void, .{ .name = "sqlite3_progress_handler" });
        defer if (runtime) progress(self.db, 0, null, null);
        if (runtime) {
            self.runtime_path = path;
            configureHeapLimit();
            self.runtime_limits = true;
            progress(self.db, 1000, workProgress, &self);
        }
        self.last_error_code = null;
        self.exec("PRAGMA trusted_schema=OFF;") catch |failure|
            return openFailure(diagnostic, .schema_inspection, failure, null, self.last_error_code);
        const application = self.integer("PRAGMA application_id;") catch |failure|
            return openFailure(diagnostic, .schema_inspection, failure, null, self.last_error_code);
        const schema = self.integer("PRAGMA user_version;") catch |failure|
            return openFailure(diagnostic, .schema_inspection, failure, null, self.last_error_code);
        if (application == 0) {
            if (schema != 0)
                return openFailure(diagnostic, .schema_validation, error.ForeignDatabase, null, null);
            const objects = self.integer("SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%';") catch |failure|
                return openFailure(diagnostic, .schema_inspection, failure, null, self.last_error_code);
            if (objects != 0) return openFailure(diagnostic, .schema_validation, error.ForeignDatabase, null, null);
        } else if (application != 0x46325a31) return openFailure(diagnostic, .schema_validation, error.ForeignDatabase, null, null);
        if (schema < 0 or schema > latest_schema)
            return openFailure(diagnostic, .schema_validation, error.UnsupportedSchema, null, null);
        self.schema_version = if (open_mode == .preflight) schema else @max(schema, 2);
        if (open_mode == .readonly or open_mode == .preflight) {
            if (application == 0 and open_mode == .readonly)
                return openFailure(diagnostic, .schema_validation, error.ForeignDatabase, null, null);
            self.last_error_code = null;
            self.exec("PRAGMA foreign_keys=ON;") catch |failure|
                return openFailure(diagnostic, .schema_setup, failure, null, self.last_error_code);
            diagnostic.* = .{};
            return self;
        }
        if (runtime) {
            self.last_error_code = null;
            self.configureRuntimeLimits() catch |failure|
                return openFailure(diagnostic, .runtime_setup, failure, null, self.last_error_code);
            self.last_error_code = null;
            self.maintainWal(path) catch |failure|
                return openFailure(diagnostic, .runtime_setup, failure, null, self.last_error_code);
        }
        self.last_error_code = null;
        self.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;") catch |failure|
            return openFailure(diagnostic, .schema_setup, failure, null, self.last_error_code);
        {
            var mode = self.statement("PRAGMA journal_mode;") catch |failure|
                return openFailure(diagnostic, .schema_setup, failure, null, self.last_error_code);
            defer mode.deinit();
            const has_mode = mode.row() catch |failure|
                return openFailure(diagnostic, .schema_setup, failure, null, self.last_error_code);
            if (!has_mode) return openFailure(diagnostic, .schema_setup, error.DatabaseFailure, null, null);
            const mode_name = mode.bytes(0) catch |failure|
                return openFailure(diagnostic, .schema_setup, failure, null, self.last_error_code);
            if (!std.mem.eql(u8, mode_name, "wal"))
                return openFailure(diagnostic, .schema_setup, error.DatabaseFailure, null, null);
            const synchronous = self.integer("PRAGMA synchronous;") catch |failure|
                return openFailure(diagnostic, .schema_setup, failure, null, self.last_error_code);
            if (synchronous != 2) return openFailure(diagnostic, .schema_setup, error.DatabaseFailure, null, null);
        }
        self.beginWrite() catch |failure|
            return openFailure(diagnostic, .schema_setup, failure, null, self.last_error_code);
        self.exec(
            \\CREATE TABLE IF NOT EXISTS records(jail TEXT NOT NULL,source TEXT NOT NULL,occurrence TEXT NOT NULL,raw_hash BLOB NOT NULL CHECK(length(raw_hash)=32),cursor BLOB NOT NULL,event_time BLOB CHECK(event_time IS NULL OR length(event_time)=8),timestamp_us TEXT,disposition TEXT NOT NULL,PRIMARY KEY(jail,source,occurrence));
            \\CREATE TABLE IF NOT EXISTS source_cursors(jail TEXT NOT NULL,source TEXT NOT NULL,cursor BLOB NOT NULL,occurrence TEXT NOT NULL,path TEXT,PRIMARY KEY(jail,source));
            \\CREATE TABLE IF NOT EXISTS checkpoints(jail TEXT PRIMARY KEY NOT NULL,payload BLOB NOT NULL,revision INTEGER NOT NULL CHECK(revision>0));
            \\CREATE TABLE IF NOT EXISTS shared_checkpoints(name TEXT PRIMARY KEY NOT NULL,payload BLOB NOT NULL,revision INTEGER NOT NULL CHECK(revision>0));
            \\CREATE TABLE IF NOT EXISTS action_intents(jail TEXT NOT NULL,source TEXT NOT NULL,occurrence TEXT NOT NULL,payload BLOB NOT NULL,status TEXT NOT NULL DEFAULT 'pending',PRIMARY KEY(jail,source,occurrence),FOREIGN KEY(jail,source,occurrence) REFERENCES records(jail,source,occurrence));
            \\PRAGMA application_id=1177705009;
        ) catch |err| {
            self.rollback();
            return openFailure(diagnostic, .schema_setup, err, null, self.last_error_code);
        };
        if (schema < 2) self.exec("PRAGMA user_version=2;") catch |err| {
            self.rollback();
            return openFailure(diagnostic, .schema_setup, err, null, self.last_error_code);
        };
        self.commitTransaction() catch |err| {
            self.rollback();
            return openFailure(diagnostic, .schema_setup, err, null, self.last_error_code);
        };
        self.last_error_code = null;
        self.check(db_config(self.db, 1006, @as(c_int, 0), @as(?*c_int, null))) catch |failure|
            return openFailure(diagnostic, .connection_setup, failure, null, self.last_error_code);
        if (runtime) self.runtime_limits = false;
        diagnostic.* = .{};
        return self;
    }

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

    pub fn enableClockRecovery(self: *Store) Error!void {
        if (self.receipt_limit == null) return error.ReceiptStorageRequired;
        try self.beginWrite();
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 6 or schema > latest_schema) return error.UnsupportedSchema;
        if (schema == 6) {
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
            var retained = try self.statement("SELECT 1 FROM records WHERE jail=?1 AND source=?2 AND source_generation=?3 AND source_sequence IS NOT NULL UNION ALL SELECT 1 FROM replay_guards WHERE jail=?1 AND source=?2 AND generation=?3 LIMIT 1;");
            defer retained.deinit();
            try retained.text(1, record.jail);
            try retained.text(2, record.source);
            try retained.blob(3, &generation);
            if (try retained.row()) return error.InvalidMaintenanceState;
        }
        const prior: u64 = if (old) |value| value.head_sequence else 0;
        if (old != null) {
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

    pub fn enableRetryLeases(self: *Store) Error!void {
        try self.beginWrite();
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 15 or schema > latest_schema) return error.UnsupportedSchema;
        if (schema == 15) {
            var names: [64][64]u8 = undefined;
            var lengths: [64]u8 = undefined;
            var policies: [64][retry.policy_bytes]u8 = undefined;
            var count: usize = 0;
            {
                var rows = try self.statement("SELECT jail,policy FROM retry_policies ORDER BY jail;");
                defer rows.deinit();
                while (try rows.row()) {
                    if (count == names.len or self.api.column_type(rows.ptr, 0) != 3) return error.InvalidRetryState;
                    const jail = try rows.boundedBytes(0, 64);
                    if (jail.len == 0) return error.InvalidRetryState;
                    const raw = try rows.boundedBytes(1, retry.policy_bytes);
                    if (raw.len != retry.policy_bytes or (raw[4] != 1 and raw[4] != 2)) return error.InvalidRetryPolicy;
                    const policy = try retry.Policy.decode(raw);
                    if (policy.duration == .permanent) return error.InvalidRetryPolicy;
                    lengths[count] = @intCast(jail.len);
                    @memcpy(names[count][0..jail.len], jail);
                    policies[count] = try policy.encode();
                    count += 1;
                }
            }
            try self.exec(
                \\CREATE TABLE retry_states_v16(jail TEXT NOT NULL,family INTEGER NOT NULL CHECK(typeof(family)='integer' AND family IN (4,6)),subject BLOB NOT NULL CHECK(typeof(subject)='blob' AND length(subject)=CASE family WHEN 4 THEN 4 ELSE 16 END),last_processed_us INTEGER NOT NULL CHECK(typeof(last_processed_us)='integer'),lease_kind INTEGER NOT NULL CHECK(typeof(lease_kind)='integer' AND lease_kind BETWEEN 0 AND 2),deadline_us INTEGER CHECK(deadline_us IS NULL OR typeof(deadline_us)='integer'),decisions INTEGER NOT NULL CHECK(typeof(decisions)='integer' AND decisions>=0),attempts BLOB NOT NULL CHECK(typeof(attempts)='blob' AND length(attempts)<=5120 AND length(attempts)%40=0),PRIMARY KEY(jail,family,subject),FOREIGN KEY(jail) REFERENCES retry_policies(jail),CHECK((lease_kind=1)=(deadline_us IS NOT NULL)),CHECK(lease_kind=0 OR decisions>0),CHECK(lease_kind=0 OR length(attempts)=0),CHECK(deadline_us IS NULL OR deadline_us>last_processed_us));
                \\INSERT INTO retry_states_v16 SELECT jail,family,subject,last_processed_us,CASE WHEN expiry_us IS NULL THEN 0 ELSE 1 END,expiry_us,decisions,attempts FROM retry_states;
                \\DROP TABLE retry_states;
                \\ALTER TABLE retry_states_v16 RENAME TO retry_states;
                \\CREATE TABLE retry_decisions_v16(jail TEXT NOT NULL,source TEXT NOT NULL,occurrence TEXT NOT NULL,family INTEGER NOT NULL CHECK(typeof(family)='integer' AND family IN (4,6)),subject BLOB NOT NULL CHECK(typeof(subject)='blob' AND length(subject)=CASE family WHEN 4 THEN 4 ELSE 16 END),decided_us INTEGER NOT NULL CHECK(typeof(decided_us)='integer'),lease_kind INTEGER NOT NULL CHECK(typeof(lease_kind)='integer' AND lease_kind IN (1,2)),deadline_us INTEGER CHECK(deadline_us IS NULL OR typeof(deadline_us)='integer'),ordinal INTEGER NOT NULL CHECK(typeof(ordinal)='integer' AND ordinal>0),enforce INTEGER NOT NULL CHECK(typeof(enforce)='integer' AND enforce IN (0,1)),PRIMARY KEY(jail,source,occurrence,family,subject),UNIQUE(jail,family,subject,ordinal),FOREIGN KEY(jail,source,occurrence) REFERENCES records(jail,source,occurrence),CHECK((lease_kind=1)=(deadline_us IS NOT NULL)),CHECK(deadline_us IS NULL OR deadline_us>decided_us));
                \\INSERT INTO retry_decisions_v16 SELECT jail,source,occurrence,family,subject,decided_us,1,expiry_us,ordinal,enforce FROM retry_decisions;
                \\DROP TABLE retry_decisions;
                \\ALTER TABLE retry_decisions_v16 RENAME TO retry_decisions;
            );
            for (0..count) |index| {
                var update = try self.statement("UPDATE retry_policies SET policy=?2 WHERE jail=?1;");
                defer update.deinit();
                try update.text(1, names[index][0..lengths[index]]);
                try update.blob(2, &policies[index]);
                try update.done();
                if (self.api.changes(self.db) != 1) return error.InvalidRetryState;
            }
            try self.exec("PRAGMA user_version=16;");
        }
        try self.fault(.before_retry_lease_schema_commit);
        try self.commitTransaction();
        self.schema_version = @max(schema, 16);
    }

    pub fn enableApplicationHistory(self: *Store) Error!void {
        try self.beginWrite();
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 16 or schema > latest_schema) return error.UnsupportedSchema;
        if (schema == 16) try self.exec(
            \\CREATE TABLE retry_decision_details(jail TEXT NOT NULL,source TEXT NOT NULL,occurrence TEXT NOT NULL,family INTEGER NOT NULL CHECK(typeof(family)='integer' AND family IN (4,6)),subject BLOB NOT NULL CHECK(typeof(subject)='blob' AND length(subject)=CASE family WHEN 4 THEN 4 ELSE 16 END),ordinal INTEGER NOT NULL CHECK(typeof(ordinal)='integer' AND ordinal>0),decided_us INTEGER NOT NULL CHECK(typeof(decided_us)='integer'),effect_decision_id BLOB UNIQUE CHECK(effect_decision_id IS NULL OR (typeof(effect_decision_id)='blob' AND length(effect_decision_id)=32)),evidence TEXT CHECK(evidence IS NULL OR (typeof(evidence)='text' AND length(CAST(evidence AS BLOB)) BETWEEN 1 AND 2048)),PRIMARY KEY(jail,source,occurrence,family,subject));
            \\CREATE TABLE confirmed_event_details(event_id BLOB PRIMARY KEY NOT NULL CHECK(typeof(event_id)='blob' AND length(event_id)=32),source TEXT NOT NULL,occurrence TEXT NOT NULL,decided_us INTEGER NOT NULL CHECK(typeof(decided_us)='integer'),ordinal INTEGER NOT NULL CHECK(typeof(ordinal)='integer' AND ordinal>0),evidence TEXT CHECK(evidence IS NULL OR (typeof(evidence)='text' AND length(CAST(evidence AS BLOB)) BETWEEN 1 AND 2048)),FOREIGN KEY(event_id) REFERENCES confirmed_effect_events(event_id));
            \\CREATE INDEX confirmed_effect_events_jail_time ON confirmed_effect_events(jail,confirmed_us,event_id);
            \\CREATE INDEX confirmed_effect_events_time ON confirmed_effect_events(confirmed_us,event_id);
            \\CREATE TABLE policy_summary_clock(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision BETWEEN 1 AND 9223372036854775806));
            \\INSERT INTO policy_summary_clock VALUES(1,1);
            \\CREATE TRIGGER policy_summary_state_insert AFTER INSERT ON retry_states BEGIN UPDATE policy_summary_clock SET revision=revision+1 WHERE id=1; END;
            \\CREATE TRIGGER policy_summary_state_update AFTER UPDATE ON retry_states BEGIN UPDATE policy_summary_clock SET revision=revision+1 WHERE id=1; END;
            \\CREATE TRIGGER policy_summary_state_delete AFTER DELETE ON retry_states BEGIN UPDATE policy_summary_clock SET revision=revision+1 WHERE id=1; END;
            \\CREATE TRIGGER policy_summary_retired_insert AFTER INSERT ON retry_retired BEGIN UPDATE policy_summary_clock SET revision=revision+1 WHERE id=1; END;
            \\CREATE TRIGGER policy_summary_retired_update AFTER UPDATE ON retry_retired BEGIN UPDATE policy_summary_clock SET revision=revision+1 WHERE id=1; END;
            \\CREATE TRIGGER policy_summary_retired_delete AFTER DELETE ON retry_retired BEGIN UPDATE policy_summary_clock SET revision=revision+1 WHERE id=1; END;
            \\PRAGMA user_version=17;
        );
        try self.fault(.before_application_history_schema_commit);
        try self.commitTransaction();
        self.schema_version = @max(schema, 17);
    }

    pub fn enableEscalation(self: *Store) Error!void {
        try self.beginWrite();
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 17 or schema > latest_schema) return error.UnsupportedSchema;
        if (schema == 17) {
            try self.exec(
                \\CREATE TABLE retry_escalation_policies(jail TEXT PRIMARY KEY NOT NULL,generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=32),policy BLOB NOT NULL CHECK(typeof(policy)='blob' AND length(policy)=40),FOREIGN KEY(jail) REFERENCES retry_policies(jail));
                \\CREATE TABLE confirmed_policy_summaries(jail TEXT NOT NULL,family INTEGER NOT NULL CHECK(family IN (4,6)),subject BLOB NOT NULL CHECK(typeof(subject)='blob' AND length(subject)=CASE family WHEN 4 THEN 4 ELSE 16 END),confirmed_count INTEGER NOT NULL CHECK(typeof(confirmed_count)='integer' AND confirmed_count>0),latest_confirmed_us INTEGER NOT NULL CHECK(typeof(latest_confirmed_us)='integer'),PRIMARY KEY(jail,family,subject),FOREIGN KEY(jail) REFERENCES retry_policies(jail));
                \\CREATE TABLE retry_decision_escalations(jail TEXT NOT NULL,source TEXT NOT NULL,occurrence TEXT NOT NULL,family INTEGER NOT NULL CHECK(family IN (4,6)),subject BLOB NOT NULL CHECK(typeof(subject)='blob' AND length(subject)=CASE family WHEN 4 THEN 4 ELSE 16 END),scope INTEGER NOT NULL CHECK(scope IN (1,2)),prior_confirmed INTEGER NOT NULL CHECK(typeof(prior_confirmed)='integer' AND prior_confirmed>=0),latest_confirmed_us INTEGER CHECK(latest_confirmed_us IS NULL OR typeof(latest_confirmed_us)='integer'),chosen_duration_us INTEGER NOT NULL CHECK(typeof(chosen_duration_us)='integer' AND chosen_duration_us>0 AND chosen_duration_us%1000000=0),jitter_us INTEGER NOT NULL CHECK(typeof(jitter_us)='integer' AND jitter_us>=0 AND jitter_us%1000000=0),PRIMARY KEY(jail,source,occurrence,family,subject),FOREIGN KEY(jail,source,occurrence,family,subject) REFERENCES retry_decisions(jail,source,occurrence,family,subject),CHECK((prior_confirmed=0)=(latest_confirmed_us IS NULL)));
            );
            const detailed = try self.integer("SELECT count(*) FROM confirmed_event_details;");
            const joinable = try self.integer("SELECT count(*) FROM confirmed_event_details d JOIN confirmed_effect_events e USING(event_id) JOIN retry_decision_details r ON r.jail=e.jail AND r.effect_decision_id=e.decision_id;");
            if (detailed != joinable) return error.RetryMigrationRequired;
            try self.exec("INSERT INTO confirmed_policy_summaries SELECT r.jail,r.family,r.subject,count(*),max(e.confirmed_us) FROM confirmed_event_details d JOIN confirmed_effect_events e USING(event_id) JOIN retry_decision_details r ON r.jail=e.jail AND r.effect_decision_id=e.decision_id GROUP BY r.jail,r.family,r.subject;");
            var names: [64][64]u8 = undefined;
            var lengths: [64]u8 = undefined;
            var generations: [64][32]u8 = undefined;
            var count: usize = 0;
            {
                var rows = try self.statement("SELECT jail,generation FROM retry_policies ORDER BY jail;");
                defer rows.deinit();
                while (try rows.row()) {
                    if (count == names.len or self.api.column_type(rows.ptr, 0) != 3) return error.InvalidRetryState;
                    const jail = try rows.boundedBytes(0, 64);
                    const generation = try rows.boundedBytes(1, 32);
                    if (jail.len == 0 or generation.len != 32) return error.InvalidRetryState;
                    lengths[count] = @intCast(jail.len);
                    @memcpy(names[count][0..jail.len], jail);
                    @memcpy(&generations[count], generation);
                    count += 1;
                }
            }
            const disabled = try (retry.Escalation{}).encode();
            for (0..count) |index| {
                var insert = try self.statement("INSERT INTO retry_escalation_policies VALUES(?1,?2,?3);");
                defer insert.deinit();
                try insert.text(1, names[index][0..lengths[index]]);
                try insert.blob(2, &generations[index]);
                try insert.blob(3, &disabled);
                try insert.done();
            }
            try self.exec("PRAGMA user_version=18;");
        }
        try self.fault(.before_escalation_schema_commit);
        try self.commitTransaction();
        self.schema_version = @max(schema, 18);
    }

    pub fn enableCanonicalEffects(self: *Store) Error!void {
        try self.beginWrite();
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 18 or schema > latest_schema) return error.UnsupportedSchema;
        if (schema == 18) {
            const installation = try self.readInstallation();
            var count: usize = 0;
            {
                var rows = try self.statement("SELECT scope_key,scope FROM native_effects ORDER BY scope_key;");
                defer rows.deinit();
                while (try rows.row()) {
                    count += 1;
                    if (count > effects.max_effects) return error.EffectCapacity;
                    const scope = try effects.Scope.decode(&try effectBlob(&rows, 1, effects.Scope.encoded_bytes));
                    const admitted = installation orelse return error.InstallationRequired;
                    if (!std.mem.eql(u8, &try effectBlob(&rows, 0, 32), &try scope.key(admitted))) return error.InvalidEffect;
                }
            }
            try self.exec(
                \\ALTER TABLE native_effects ADD COLUMN canonical_scope BLOB CHECK(canonical_scope IS NULL OR (typeof(canonical_scope)='blob' AND length(canonical_scope)=92));
                \\UPDATE native_effects SET canonical_scope=CAST(x'02'||substr(scope,2,1)||x'01'||substr(scope,3,1)||x'010000010101010101010100'||substr(scope,9,16)||zeroblob(60) AS BLOB);
                \\CREATE TRIGGER native_effect_scope_v2_insert BEFORE INSERT ON native_effects WHEN NEW.canonical_scope IS NULL BEGIN SELECT RAISE(ABORT,'canonical effect scope required'); END;
                \\CREATE TRIGGER native_effect_scope_v2_update BEFORE UPDATE OF canonical_scope ON native_effects WHEN NEW.canonical_scope IS NULL OR NEW.canonical_scope IS NOT OLD.canonical_scope BEGIN SELECT RAISE(ABORT,'canonical effect scope immutable'); END;
                \\PRAGMA user_version=19;
            );
            var verified: usize = 0;
            {
                var canonical_rows = try self.statement("SELECT canonical_scope FROM native_effects ORDER BY scope_key;");
                defer canonical_rows.deinit();
                while (try canonical_rows.row()) {
                    verified += 1;
                    _ = try effects.Scope.decodeCanonical(&try effectBlob(&canonical_rows, 0, effects.Scope.canonical_encoded_bytes));
                }
            }
            if (verified != count) return error.InvalidEffect;
        }
        try self.fault(.before_canonical_effect_schema_commit);
        try self.commitTransaction();
        self.schema_version = @max(schema, 19);
    }

    pub fn enableHistoryResets(self: *Store) Error!void {
        try self.beginWrite();
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 19 or schema > latest_schema) return error.UnsupportedSchema;
        if (schema == 19) try self.exec(
            \\CREATE TABLE history_reset_watermarks(scope INTEGER NOT NULL CHECK(scope IN(1,2)),jail TEXT NOT NULL CHECK((scope=1 AND length(jail) BETWEEN 1 AND 64) OR (scope=2 AND jail='')),family INTEGER NOT NULL CHECK(family IN(4,6)),subject BLOB NOT NULL CHECK(typeof(subject)='blob' AND length(subject)=CASE family WHEN 4 THEN 4 ELSE 16 END),through_sequence INTEGER NOT NULL CHECK(typeof(through_sequence)='integer' AND through_sequence>=0),reset_us INTEGER NOT NULL CHECK(typeof(reset_us)='integer'),revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision>0),intent_id BLOB NOT NULL CHECK(typeof(intent_id)='blob' AND length(intent_id)=32),PRIMARY KEY(scope,jail,family,subject));
            \\PRAGMA user_version=20;
        );
        try self.fault(.before_history_reset_schema_commit);
        try self.commitTransaction();
        self.schema_version = @max(schema, 20);
    }

    pub fn enableActionTargets(self: *Store) Error!void {
        try self.beginWrite();
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 20 or schema > latest_schema) return error.UnsupportedSchema;
        if (schema == 20) {
            const owner_count = try self.integer("SELECT count(*) FROM effect_owners;");
            if (owner_count < 0 or owner_count > action_outcome.max_rows / action_outcome.max_targets_per_action) return error.ActionTargetCapacity;
            try self.exec(
                \\CREATE TABLE action_targets(action_id BLOB NOT NULL CHECK(typeof(action_id)='blob' AND length(action_id)=32),kind INTEGER NOT NULL CHECK(kind IN(1,2)),scope_key BLOB NOT NULL CHECK(typeof(scope_key)='blob' AND length(scope_key)=32),jail TEXT NOT NULL CHECK(length(jail) BETWEEN 1 AND 64),required INTEGER NOT NULL CHECK(required IN(0,1) AND required=(kind=1)),restored INTEGER NOT NULL CHECK(restored IN(0,1)),status INTEGER NOT NULL CHECK(status BETWEEN 1 AND 6),intent_us INTEGER NOT NULL CHECK(typeof(intent_us)='integer'),dispatch_us INTEGER CHECK(dispatch_us IS NULL OR (typeof(dispatch_us)='integer' AND dispatch_us>=intent_us)),settled_us INTEGER CHECK(settled_us IS NULL OR (typeof(settled_us)='integer' AND settled_us>=dispatch_us)),metadata TEXT CHECK(metadata IS NULL OR (typeof(metadata)='text' AND length(CAST(metadata AS BLOB)) BETWEEN 1 AND 512)),PRIMARY KEY(action_id,kind),CHECK((status=1 AND dispatch_us IS NULL AND settled_us IS NULL) OR (status=2 AND dispatch_us IS NOT NULL AND settled_us IS NULL) OR (status BETWEEN 3 AND 5 AND dispatch_us IS NOT NULL AND settled_us IS NOT NULL) OR (status=6 AND kind=2 AND restored=1 AND dispatch_us IS NULL AND settled_us=intent_us)),CHECK(kind!=1 OR status!=6),CHECK(kind!=2 OR restored=0 OR status=6));
                \\INSERT INTO action_targets(action_id,kind,scope_key,jail,required,restored,status,intent_us) SELECT decision_id,1,scope_key,jail,1,1,1,decided_us FROM effect_owners;
                \\INSERT INTO action_targets(action_id,kind,scope_key,jail,required,restored,status,intent_us,settled_us) SELECT decision_id,2,scope_key,jail,0,1,6,decided_us,decided_us FROM effect_owners;
                \\PRAGMA user_version=21;
            );
        }
        try self.fault(.before_action_target_schema_commit);
        try self.commitTransaction();
        self.schema_version = @max(schema, 21);
    }
    pub fn enableAdminState(self: *Store) Error!void {
        try self.beginWrite();
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 21 or schema > latest_schema) return error.UnsupportedSchema;
        if (schema == 21) try self.exec(
            \\CREATE TABLE config_generations(generation BLOB NOT NULL PRIMARY KEY CHECK(typeof(generation)='blob' AND length(generation)=32),config_digest BLOB NOT NULL CHECK(typeof(config_digest)='blob' AND length(config_digest)=32),config_path TEXT NOT NULL CHECK(typeof(config_path)='text' AND length(config_path) BETWEEN 1 AND 4096),committed_us INTEGER NOT NULL CHECK(typeof(committed_us)='integer' AND committed_us>=0),published INTEGER NOT NULL CHECK(published IN(0,1)),mutation_revision INTEGER NOT NULL CHECK(typeof(mutation_revision)='integer' AND mutation_revision>=0)) WITHOUT ROWID;
            \\CREATE TABLE config_generation_jails(generation BLOB NOT NULL REFERENCES config_generations(generation) ON DELETE CASCADE,jail TEXT NOT NULL CHECK(typeof(jail)='text' AND length(jail) BETWEEN 1 AND 64),digest BLOB NOT NULL CHECK(typeof(digest)='blob' AND length(digest)=32),allowlist_snapshot BLOB NOT NULL CHECK(typeof(allowlist_snapshot)='blob' AND length(allowlist_snapshot)<=65536),PRIMARY KEY(generation,jail)) WITHOUT ROWID;
            \\CREATE TABLE jail_admin_states(jail TEXT NOT NULL PRIMARY KEY CHECK(typeof(jail)='text' AND length(jail) BETWEEN 1 AND 64),enabled INTEGER NOT NULL CHECK(enabled IN(0,1)),paused INTEGER NOT NULL CHECK(paused IN(0,1)),generation BLOB NOT NULL REFERENCES config_generations(generation),changed_us INTEGER NOT NULL CHECK(typeof(changed_us)='integer' AND changed_us>=0),request_id BLOB NOT NULL CHECK(typeof(request_id)='blob' AND length(request_id)=32)) WITHOUT ROWID;
            \\CREATE TABLE admin_requests(request_id BLOB NOT NULL PRIMARY KEY CHECK(typeof(request_id)='blob' AND length(request_id)=32),kind INTEGER NOT NULL CHECK(kind BETWEEN 1 AND 10),subject BLOB NOT NULL CHECK(typeof(subject)='blob' AND length(subject)<=4096),outcome INTEGER NOT NULL CHECK(outcome BETWEEN 1 AND 5),generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=32),mutation_revision INTEGER NOT NULL CHECK(typeof(mutation_revision)='integer' AND mutation_revision>=0),committed_us INTEGER NOT NULL CHECK(typeof(committed_us)='integer' AND committed_us>=0),detail BLOB NOT NULL CHECK(typeof(detail)='blob' AND length(detail)<=4096)) WITHOUT ROWID;
            \\CREATE INDEX admin_requests_by_revision ON admin_requests(mutation_revision);
            \\CREATE TABLE admin_revision(id INTEGER NOT NULL PRIMARY KEY CHECK(id=1),mutation_revision INTEGER NOT NULL CHECK(typeof(mutation_revision)='integer' AND mutation_revision>=0));
            \\INSERT INTO admin_revision(id,mutation_revision) VALUES(1,0);
            \\PRAGMA user_version=22;
        );
        try self.fault(.before_admin_schema_commit);
        try self.commitTransaction();
        self.schema_version = @max(schema, 22);
    }

    pub fn enableMigrationState(self: *Store) Error!void {
        try self.beginWrite();
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 22 or schema > latest_schema) return error.UnsupportedSchema;
        if (schema == 22) try self.exec(
            \\CREATE TABLE migration_runs(run_id BLOB NOT NULL PRIMARY KEY CHECK(typeof(run_id)='blob' AND length(run_id)=32),host_id BLOB NOT NULL CHECK(typeof(host_id)='blob' AND length(host_id)=32),source_db_fp BLOB NOT NULL CHECK(typeof(source_db_fp)='blob' AND length(source_db_fp)=32),source_cfg_fp BLOB NOT NULL CHECK(typeof(source_cfg_fp)='blob' AND length(source_cfg_fp)=32),plan_fp BLOB NOT NULL CHECK(typeof(plan_fp)='blob' AND length(plan_fp)=32),recovery_point TEXT NOT NULL CHECK(typeof(recovery_point)='text' AND length(recovery_point)<=4096),generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=32),state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 9),created_us INTEGER NOT NULL CHECK(typeof(created_us)='integer' AND created_us>=0),updated_us INTEGER NOT NULL CHECK(typeof(updated_us)='integer' AND updated_us>=created_us)) WITHOUT ROWID;
            \\CREATE TABLE migration_steps(run_id BLOB NOT NULL REFERENCES migration_runs(run_id),seq INTEGER NOT NULL CHECK(typeof(seq)='integer' AND seq>=1),step INTEGER NOT NULL CHECK(step BETWEEN 1 AND 9),intent BLOB NOT NULL CHECK(typeof(intent)='blob' AND length(intent)<=4096),outcome INTEGER NOT NULL CHECK(outcome BETWEEN 0 AND 7),detail BLOB NOT NULL CHECK(typeof(detail)='blob' AND length(detail)<=4096),started_us INTEGER NOT NULL CHECK(typeof(started_us)='integer' AND started_us>=0),finished_us INTEGER CHECK(finished_us IS NULL OR (typeof(finished_us)='integer' AND finished_us>=started_us)),PRIMARY KEY(run_id,seq),CHECK((outcome=0 AND finished_us IS NULL) OR (outcome>0 AND finished_us IS NOT NULL))) WITHOUT ROWID;
            \\CREATE TABLE migration_deltas(run_id BLOB NOT NULL REFERENCES migration_runs(run_id),seq INTEGER NOT NULL CHECK(typeof(seq)='integer' AND seq>=1),kind INTEGER NOT NULL CHECK(kind BETWEEN 1 AND 3),scope BLOB NOT NULL CHECK(typeof(scope)='blob' AND length(scope)=92),jail TEXT NOT NULL CHECK(typeof(jail)='text' AND length(jail) BETWEEN 1 AND 64),lease_kind INTEGER NOT NULL CHECK(lease_kind BETWEEN 0 AND 2),deadline_us INTEGER CHECK(deadline_us IS NULL OR typeof(deadline_us)='integer'),carry_back INTEGER NOT NULL CHECK(carry_back BETWEEN 1 AND 3),applied INTEGER NOT NULL CHECK(applied IN(0,1)),recorded_us INTEGER NOT NULL CHECK(typeof(recorded_us)='integer' AND recorded_us>=0),PRIMARY KEY(run_id,seq),CHECK((lease_kind=1 AND deadline_us IS NOT NULL) OR (lease_kind!=1 AND deadline_us IS NULL))) WITHOUT ROWID;
            \\CREATE TABLE migration_staged_owners(run_id BLOB NOT NULL REFERENCES migration_runs(run_id),seq INTEGER NOT NULL CHECK(typeof(seq)='integer' AND seq>=1),jail TEXT NOT NULL CHECK(typeof(jail)='text' AND length(jail) BETWEEN 1 AND 64),scope BLOB NOT NULL CHECK(typeof(scope)='blob' AND length(scope)=92),lease_kind INTEGER NOT NULL CHECK(lease_kind BETWEEN 1 AND 2),deadline_us INTEGER CHECK(deadline_us IS NULL OR typeof(deadline_us)='integer'),source_event_us INTEGER NOT NULL CHECK(typeof(source_event_us)='integer'),source_row INTEGER NOT NULL CHECK(typeof(source_row)='integer' AND source_row>=0),PRIMARY KEY(run_id,seq),CHECK((lease_kind=1 AND deadline_us IS NOT NULL) OR (lease_kind=2 AND deadline_us IS NULL))) WITHOUT ROWID;
            \\CREATE TABLE migration_staged_history(run_id BLOB NOT NULL REFERENCES migration_runs(run_id),seq INTEGER NOT NULL CHECK(typeof(seq)='integer' AND seq>=1),jail TEXT NOT NULL CHECK(typeof(jail)='text' AND length(jail) BETWEEN 1 AND 64),scope BLOB NOT NULL CHECK(typeof(scope)='blob' AND length(scope)=92),event_kind INTEGER NOT NULL CHECK(event_kind BETWEEN 1 AND 3),event_us INTEGER NOT NULL CHECK(typeof(event_us)='integer'),bancount INTEGER NOT NULL CHECK(typeof(bancount)='integer' AND bancount>=0),source_row INTEGER NOT NULL CHECK(typeof(source_row)='integer' AND source_row>=0),PRIMARY KEY(run_id,seq)) WITHOUT ROWID;
            \\PRAGMA user_version=23;
        );
        try self.fault(.before_migration_schema_commit);
        try self.commitTransaction();
        self.schema_version = @max(schema, 23);
    }

    pub const CursorRebinding = struct { old: [32]u8, new: [32]u8 };
    pub const PolicyTransition = struct { jail: []const u8, generation: [32]u8, next_generation: [32]u8, expected: retry.Policy, next: retry.Policy, cursor_rebinding: ?CursorRebinding = null };
    pub fn transitionRetryPolicy(self: *Store, jail: []const u8, generation: [32]u8, expected: retry.Policy, next: retry.Policy) Error!void {
        try self.beginWrite();
        errdefer self.rollback();
        if (self.schema_version < 22) return error.AdminStorageRequired;
        try self.transitionJailGenerationTx(.{ .jail = jail, .generation = generation, .next_generation = generation, .expected = expected, .next = next }, std.time.microTimestamp());
        try self.bumpAdminRevisionTx();
        try self.fault(.before_policy_transition_commit);
        try self.commitTransaction();
    }
    fn transitionJailGenerationTx(self: *Store, change: PolicyTransition, now_us: i64) Error!void {
        const jail = change.jail;
        if (jail.len == 0 or jail.len > 64 or std.mem.indexOfScalar(u8, jail, 0) != null) return error.InvalidRecord;
        const encoded = try change.next.encode();
        const escalation = try change.next.escalation.encode();
        const saved = try self.readRetryPolicy(jail) orelse return error.RetryAdmissionRequired;
        if (!std.mem.eql(u8, &saved.generation, &change.generation)) return error.RetryGenerationMismatch;
        if (!try retryPoliciesEqual(saved.policy, change.expected)) return error.StalePolicyTransition;
        var pending = try self.statement("SELECT 1 FROM pending_receipts WHERE jail=?1 LIMIT 1;");
        defer pending.deinit();
        try pending.text(1, jail);
        if (try pending.row()) return error.RetryPolicyInFlight;
        {
            var update = try self.statement("UPDATE retry_policies SET generation=?4,policy=?2 WHERE jail=?1 AND generation=?3;");
            defer update.deinit();
            try update.text(1, jail);
            try update.blob(2, &encoded);
            try update.blob(3, &change.generation);
            try update.blob(4, &change.next_generation);
            try update.done();
            if (self.api.changes(self.db) != 1) return error.StalePolicyTransition;
        }
        {
            var update = try self.statement("UPDATE retry_escalation_policies SET generation=?4,policy=?2 WHERE jail=?1 AND generation=?3;");
            defer update.deinit();
            try update.text(1, jail);
            try update.blob(2, &escalation);
            try update.blob(3, &change.generation);
            try update.blob(4, &change.next_generation);
            try update.done();
            if (self.api.changes(self.db) != 1) return error.StalePolicyTransition;
        }
        if (std.mem.eql(u8, &change.generation, &change.next_generation)) return;
        try self.exec("PRAGMA defer_foreign_keys=ON;");
        const rekeyed = [_][:0]const u8{
            "UPDATE records SET source_generation=?3 WHERE jail=?1 AND source_generation=?2;",
            "UPDATE checkpoints SET payload=substr(payload,1,8)||?3||substr(payload,41) WHERE jail=?1 AND substr(payload,1,4)=CAST('F2NT' AS BLOB) AND substr(payload,9,32)=?2;",
            "UPDATE checkpoints SET payload=substr(payload,1,6)||?3||substr(payload,39) WHERE jail=?1 AND substr(payload,1,4)=CAST('F2JC' AS BLOB) AND substr(payload,7,32)=?2;",
            "UPDATE source_maintenance SET generation=?3 WHERE jail=?1 AND generation=?2;",
            "UPDATE replay_guards SET generation=?3 WHERE jail=?1 AND generation=?2;",
            "UPDATE consumer_checkpoints SET generation=?3 WHERE jail=?1 AND generation=?2;",
            "UPDATE consumer_manifests SET generation=?3 WHERE jail=?1 AND generation=?2;",
            "UPDATE consumer_requirements SET generation=?3 WHERE jail=?1 AND generation=?2;",
        };
        for (rekeyed) |sql| {
            var update = try self.statement(sql);
            defer update.deinit();
            try update.text(1, jail);
            try update.blob(2, &change.generation);
            try update.blob(3, &change.next_generation);
            try update.done();
        }
        if (change.cursor_rebinding) |rebinding| {
            var old_fragment: [256]u8 = undefined;
            var new_fragment: [256]u8 = undefined;
            const old_text = try cursorBindingFragment(&old_fragment, rebinding.old);
            const new_text = try cursorBindingFragment(&new_fragment, rebinding.new);
            var update = try self.statement("UPDATE source_cursors SET cursor=CAST(replace(CAST(cursor AS TEXT),?2,?3) AS BLOB) WHERE jail=?1;");
            defer update.deinit();
            try update.text(1, jail);
            try update.text(2, old_text);
            try update.text(3, new_text);
            try update.done();
        }
        const canonical_scope = @import("../firewall/scope.zig");
        const Held = struct { key: [32]u8, revision: u64, scope: [canonical_scope.encoded_bytes]u8 };
        var held = std.ArrayListUnmanaged(Held){};
        defer held.deinit(self.allocator);
        {
            var owners = try self.statement("SELECT o.scope_key,o.revision,n.canonical_scope FROM effect_owners o JOIN native_effects n USING(scope_key) WHERE o.jail=?1 AND o.generation=?2 ORDER BY o.scope_key;");
            defer owners.deinit();
            try owners.text(1, jail);
            try owners.blob(2, &change.generation);
            while (try owners.row()) {
                if (held.items.len == effects.max_effects) return error.EffectCapacity;
                const owner_revision = try owners.signed(1);
                if (owner_revision <= 0) return error.InvalidEffect;
                try held.append(self.allocator, .{ .key = try effectBlob(&owners, 0, 32), .revision = @intCast(owner_revision), .scope = try effectBlob(&owners, 2, canonical_scope.encoded_bytes) });
            }
        }
        for (held.items) |owner| {
            const scope = canonical_scope.Scope.decode(&owner.scope) catch return error.InvalidEffect;
            const transition_id = effects.hashParts("fail2zig-generation-rekey-v1", &.{ &change.next_generation, &owner.key });
            _ = try self.transitionOwnerTx(.{ .scope = scope, .jail = jail, .current_generation = change.generation, .next_generation = change.next_generation, .expected_owner_revision = owner.revision, .transition_id = transition_id, .mode = .retain, .occurred_us = now_us }, now_us);
        }
        if (held.items.len != 0) self.rekeyed_owners = true;
        var stale = try self.statement("SELECT 1 FROM effect_owners WHERE jail=?1 AND generation!=?2 LIMIT 1;");
        defer stale.deinit();
        try stale.text(1, jail);
        try stale.blob(2, &change.next_generation);
        if (try stale.row()) return error.StalePolicyTransition;
    }

    pub fn commitReloadGeneration(self: *Store, transitions: []const PolicyTransition, record: ConfigGenerationRecord, jails: []const ConfigGenerationJail, clock: effects.Clock) Error!void {
        if (transitions.len > 64) return error.InvalidAdminRequest;
        try self.beginWrite();
        errdefer self.rollback();
        if (self.schema_version < 22) return error.AdminStorageRequired;
        self.rekeyed_owners = false;
        const now = try self.effectClock(clock);
        for (transitions) |change| try self.transitionJailGenerationTx(change, now);
        if (self.rekeyed_owners) _ = try self.commitEffectClock(clock);
        try self.bumpAdminRevisionTx();
        const mutation_revision = try self.integer("SELECT mutation_revision FROM admin_revision WHERE id=1;");
        var pinned = record;
        pinned.mutation_revision = @intCast(mutation_revision);
        pinned.published = true;
        try self.exec("UPDATE config_generations SET published=0 WHERE published=1;");
        try self.recordConfigGenerationTx(pinned, jails);
        try self.fault(.before_config_generation_commit);
        try self.commitEffectTransaction(self.rekeyed_owners);
        self.rekeyed_owners = false;
    }

    fn cursorBindingFragment(buffer: []u8, binding: [32]u8) Error![]const u8 {
        var stream = std.io.fixedBufferStream(buffer);
        const w = stream.writer();
        w.writeAll("\"codec_configuration_hash\":[") catch return error.InvalidAdminRequest;
        for (binding, 0..) |byte, i| {
            if (i != 0) w.writeByte(',') catch return error.InvalidAdminRequest;
            w.print("{d}", .{byte}) catch return error.InvalidAdminRequest;
        }
        w.writeByte(']') catch return error.InvalidAdminRequest;
        return stream.getWritten();
    }
    fn bumpAdminRevisionTx(self: *Store) Error!void {
        const current = try self.integer("SELECT mutation_revision FROM admin_revision WHERE id=1;");
        if (current < 0 or current == std.math.maxInt(i64)) return error.DatabaseFailure;
        var update = try self.statement("UPDATE admin_revision SET mutation_revision=?1 WHERE id=1;");
        defer update.deinit();
        try update.int(1, current + 1);
        try update.done();
        if (self.api.changes(self.db) != 1) return error.DatabaseFailure;
    }

    pub const ConfigGenerationRecord = struct {
        generation: [32]u8,
        config_digest: [32]u8,
        config_path: []const u8,
        committed_us: i64,
        published: bool,
        mutation_revision: u64,
    };
    pub const ConfigGenerationJail = struct {
        jail: []const u8,
        digest: [32]u8,
        allowlist_snapshot: []const u8,
    };

    pub fn recordConfigGeneration(self: *Store, record: ConfigGenerationRecord, jails: []const ConfigGenerationJail) Error!void {
        try self.beginWrite();
        errdefer self.rollback();
        if (self.schema_version < 22) return error.AdminStorageRequired;
        try self.recordConfigGenerationTx(record, jails);
        try self.fault(.before_config_generation_commit);
        try self.commitTransaction();
    }
    fn recordConfigGenerationTx(self: *Store, record: ConfigGenerationRecord, jails: []const ConfigGenerationJail) Error!void {
        if (record.config_path.len == 0 or record.config_path.len > 4096 or record.committed_us < 0 or record.mutation_revision > std.math.maxInt(i64) or jails.len > 64) return error.InvalidAdminRequest;
        for (jails) |jail| if (jail.jail.len == 0 or jail.jail.len > 64 or jail.allowlist_snapshot.len > 65536) return error.InvalidAdminRequest;
        {
            var exists = try self.statement("SELECT 1 FROM config_generations WHERE generation=?1;");
            defer exists.deinit();
            try exists.blob(1, &record.generation);
            if (try exists.row()) return error.ConfigGenerationExists;
        }
        {
            var insert = try self.statement("INSERT INTO config_generations VALUES(?1,?2,?3,?4,?5,?6);");
            defer insert.deinit();
            try insert.blob(1, &record.generation);
            try insert.blob(2, &record.config_digest);
            try insert.text(3, record.config_path);
            try insert.int(4, record.committed_us);
            try insert.int(5, @intFromBool(record.published));
            try insert.int(6, @intCast(record.mutation_revision));
            try insert.done();
        }
        for (jails) |jail| {
            var insert = try self.statement("INSERT INTO config_generation_jails VALUES(?1,?2,?3,?4);");
            defer insert.deinit();
            try insert.blob(1, &record.generation);
            try insert.text(2, jail.jail);
            try insert.blob(3, &jail.digest);
            try insert.blob(4, jail.allowlist_snapshot);
            try insert.done();
        }
    }

    pub fn publishConfigGeneration(self: *Store, generation: [32]u8) Error!void {
        try self.beginWrite();
        errdefer self.rollback();
        if (self.schema_version < 22) return error.AdminStorageRequired;
        try self.exec("UPDATE config_generations SET published=0 WHERE published=1;");
        var update = try self.statement("UPDATE config_generations SET published=1 WHERE generation=?1;");
        defer update.deinit();
        try update.blob(1, &generation);
        try update.done();
        if (self.api.changes(self.db) != 1) return error.ConfigGenerationMissing;
        try self.fault(.before_config_generation_publish);
        try self.commitTransaction();
    }

    pub fn discardUnpublishedConfigGeneration(self: *Store, generation: [32]u8) Error!void {
        try self.beginWrite();
        errdefer self.rollback();
        if (self.schema_version < 22) return error.AdminStorageRequired;
        var delete = try self.statement("DELETE FROM config_generations WHERE generation=?1 AND published=0;");
        defer delete.deinit();
        try delete.blob(1, &generation);
        try delete.done();
        try self.commitTransaction();
    }

    pub const ConfigGenerationHead = struct { generation: [32]u8, config_digest: [32]u8, published: bool, committed_us: i64 };
    pub fn latestConfigGeneration(self: *Store) Error!?ConfigGenerationHead {
        if (self.schema_version < 22) return error.AdminStorageRequired;
        var row = try self.statement("SELECT generation,config_digest,published,committed_us FROM config_generations ORDER BY committed_us DESC, generation DESC LIMIT 1;");
        defer row.deinit();
        if (!try row.row()) return null;
        return .{ .generation = try effectBlob(&row, 0, 32), .config_digest = try effectBlob(&row, 1, 32), .published = (try row.signed(2)) == 1, .committed_us = try row.signed(3) };
    }

    pub const AdminKind = enum(u8) { group_enable = 1, group_disable, group_pause, group_resume, setting_batch, ban, unban, history_reset, migration_activate, migration_rollback };
    pub const AdminOutcome = enum(u8) { applied = 1, rejected, absent, partial, uncertain };
    pub const admin_request_retention = 4096;
    pub const admin_request_max_age_us: i64 = 30 * 24 * 60 * 60 * 1_000_000;
    pub const AdminRequestRecord = struct {
        request_id: [32]u8,
        kind: AdminKind,
        subject: []const u8,
        outcome: AdminOutcome,
        generation: [32]u8,
        committed_us: i64,
        detail: []const u8,
    };
    pub const AdminReplay = struct { kind: AdminKind, outcome: AdminOutcome, mutation_revision: u64 };
    pub const AdminAdmission = union(enum) { fresh, replayed: AdminReplay };
    pub const JailAdminState = struct {
        jail: []const u8,
        enabled: bool,
        paused: bool,
        generation: [32]u8,
        changed_us: i64,
        request_id: [32]u8,
    };

    pub fn admitAdminRequest(self: *Store, request_id: [32]u8, expected_mutation_revision: u64) Error!AdminAdmission {
        if (std.mem.allEqual(u8, &request_id, 0)) return error.InvalidAdminRequest;
        try self.beginRead();
        errdefer self.rollback();
        if (self.schema_version < 22) return error.AdminStorageRequired;
        var row = try self.statement("SELECT kind,outcome,mutation_revision FROM admin_requests WHERE request_id=?1;");
        defer row.deinit();
        try row.blob(1, &request_id);
        if (try row.row()) {
            const kind = std.meta.intToEnum(AdminKind, try row.signed(0)) catch return error.DatabaseFailure;
            const outcome = std.meta.intToEnum(AdminOutcome, try row.signed(1)) catch return error.DatabaseFailure;
            const recorded_revision = try row.signed(2);
            try self.commitTransaction();
            return .{ .replayed = .{ .kind = kind, .outcome = outcome, .mutation_revision = @intCast(recorded_revision) } };
        }
        const current = try self.integer("SELECT mutation_revision FROM admin_revision WHERE id=1;");
        try self.commitTransaction();
        if (current < 0 or @as(u64, @intCast(current)) != expected_mutation_revision) return error.StaleAdminRevision;
        return .fresh;
    }

    pub fn finishAdminRequest(self: *Store, record: AdminRequestRecord, state: ?JailAdminState) Error!u64 {
        if (std.mem.allEqual(u8, &record.request_id, 0) or record.subject.len > 4096 or record.detail.len > 4096 or record.committed_us < 0) return error.InvalidAdminRequest;
        if (state) |value| if (value.jail.len == 0 or value.jail.len > 64 or value.changed_us < 0) return error.InvalidAdminRequest;
        try self.beginWrite();
        errdefer self.rollback();
        if (self.schema_version < 22) return error.AdminStorageRequired;
        if (record.outcome != .rejected) try self.bumpAdminRevisionTx();
        const mutation_revision = try self.integer("SELECT mutation_revision FROM admin_revision WHERE id=1;");
        if (mutation_revision < 0) return error.DatabaseFailure;
        {
            var insert = try self.statement("INSERT INTO admin_requests VALUES(?1,?2,?3,?4,?5,?6,?7,?8);");
            defer insert.deinit();
            try insert.blob(1, &record.request_id);
            try insert.int(2, @intFromEnum(record.kind));
            try insert.blob(3, record.subject);
            try insert.int(4, @intFromEnum(record.outcome));
            try insert.blob(5, &record.generation);
            try insert.int(6, mutation_revision);
            try insert.int(7, record.committed_us);
            try insert.blob(8, record.detail);
            try insert.done();
        }
        if (state) |value| {
            var upsert = try self.statement("INSERT INTO jail_admin_states VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(jail) DO UPDATE SET enabled=excluded.enabled,paused=excluded.paused,generation=excluded.generation,changed_us=excluded.changed_us,request_id=excluded.request_id;");
            defer upsert.deinit();
            try upsert.text(1, value.jail);
            try upsert.int(2, @intFromBool(value.enabled));
            try upsert.int(3, @intFromBool(value.paused));
            try upsert.blob(4, &value.generation);
            try upsert.int(5, value.changed_us);
            try upsert.blob(6, &value.request_id);
            try upsert.done();
        }
        {
            var age = try self.statement("DELETE FROM admin_requests WHERE committed_us<?1;");
            defer age.deinit();
            try age.int(1, record.committed_us -| admin_request_max_age_us);
            try age.done();
        }
        {
            var overflow = try self.statement("DELETE FROM admin_requests WHERE request_id IN (SELECT request_id FROM admin_requests ORDER BY mutation_revision ASC, committed_us ASC LIMIT max(0,(SELECT count(*) FROM admin_requests)-?1));");
            defer overflow.deinit();
            try overflow.int(1, admin_request_retention);
            try overflow.done();
        }
        try self.fault(.after_admin_request);
        try self.commitTransaction();
        return @intCast(mutation_revision);
    }

    pub fn jailAdminState(self: *Store, jail: []const u8, output: *JailAdminState) Error!bool {
        if (self.schema_version < 22) return error.AdminStorageRequired;
        var row = try self.statement("SELECT enabled,paused,generation,changed_us,request_id FROM jail_admin_states WHERE jail=?1;");
        defer row.deinit();
        try row.text(1, jail);
        if (!try row.row()) return false;
        output.* = .{ .jail = jail, .enabled = (try row.signed(0)) == 1, .paused = (try row.signed(1)) == 1, .generation = try effectBlob(&row, 2, 32), .changed_us = try row.signed(3), .request_id = try effectBlob(&row, 4, 32) };
        return true;
    }

    pub fn currentOwner(self: *Store, key: effects.Hash, jail: []const u8) Error!?effects.Owner {
        try self.beginRead();
        errdefer self.rollback();
        var row = try self.statement("SELECT generation,decision_id,revision,lease_kind,deadline_us,decided_us FROM effect_owners WHERE scope_key=?1 AND jail=?2;");
        defer row.deinit();
        try row.blob(1, &key);
        try row.text(2, jail);
        if (!try row.row()) {
            try self.commitTransaction();
            return null;
        }
        const effect_revision = try row.signed(2);
        if (effect_revision <= 0) return error.InvalidEffect;
        const owner = effects.Owner{ .jail = detection.Name.init(jail) catch return error.InvalidEffect, .generation = try effectBlob(&row, 0, 32), .decision_id = try effectBlob(&row, 1, 32), .revision = @intCast(effect_revision), .lease = try effectLease(&row, 3, 4), .decided_us = try row.signed(5) };
        try self.commitTransaction();
        return owner;
    }

    pub fn historyResetRevision(self: *Store, scope: HistoryResetScope, subject: detection.Subject) Error!u64 {
        if (self.schema_version < 20) return error.HistoryResetStorageRequired;
        const scope_value: i64 = switch (scope) {
            .jail => 1,
            .overall => 2,
        };
        const jail = switch (scope) {
            .jail => |name| name,
            .overall => "",
        };
        try self.beginRead();
        errdefer self.rollback();
        var row = try self.statement("SELECT revision FROM history_reset_watermarks WHERE scope=?1 AND jail=?2 AND family=?3 AND subject=?4;");
        defer row.deinit();
        try row.int(1, scope_value);
        try row.text(2, jail);
        try bindSubjectAt(&row, &subject, 3);
        const prior: u64 = if (try row.row()) @intCast(@max(0, try row.signed(0))) else 0;
        try self.commitTransaction();
        return prior;
    }

    pub const MigrationState = enum(u8) { planned = 1, validated, recovery_point, quiesced, staged, activating, complete, rolled_back, failed };
    pub const MigrationStep = enum(u8) { validate_plan = 1, check_drift, capture_recovery_point, quiesce_source, stage_destination, activate_owners, verify_protection, complete, rollback };
    pub const MigrationOutcome = enum(u8) { pending = 0, success, incompatible, validation_failed, operational_failure, uncertain, rollback_failed, partial };
    pub const MigrationRun = struct {
        run_id: [32]u8,
        host_id: [32]u8,
        source_db_fp: [32]u8,
        source_cfg_fp: [32]u8,
        plan_fp: [32]u8,
        recovery_point: []const u8,
        generation: [32]u8,
        state: MigrationState,
        created_us: i64,
        updated_us: i64,
    };
    pub const MigrationStepRow = struct { seq: u64, step: MigrationStep, outcome: MigrationOutcome, started_us: i64, finished_us: ?i64 };

    pub fn createMigrationRun(self: *Store, run: MigrationRun) Error!void {
        if (run.recovery_point.len > 4096 or run.created_us < 0 or run.updated_us < run.created_us) return error.InvalidMigrationRow;
        try self.beginWrite();
        errdefer self.rollback();
        if (self.schema_version < 23) return error.MigrationStorageRequired;
        {
            var exists = try self.statement("SELECT 1 FROM migration_runs WHERE run_id=?1;");
            defer exists.deinit();
            try exists.blob(1, &run.run_id);
            if (try exists.row()) return error.MigrationRunExists;
        }
        var insert = try self.statement("INSERT INTO migration_runs VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10);");
        defer insert.deinit();
        try insert.blob(1, &run.run_id);
        try insert.blob(2, &run.host_id);
        try insert.blob(3, &run.source_db_fp);
        try insert.blob(4, &run.source_cfg_fp);
        try insert.blob(5, &run.plan_fp);
        try insert.text(6, run.recovery_point);
        try insert.blob(7, &run.generation);
        try insert.int(8, @intFromEnum(run.state));
        try insert.int(9, run.created_us);
        try insert.int(10, run.updated_us);
        try insert.done();
        try self.commitTransaction();
    }

    pub fn migrationRun(self: *Store, allocator: std.mem.Allocator, run_id: [32]u8) Error!?MigrationRun {
        if (self.schema_version < 23) return error.MigrationStorageRequired;
        try self.beginRead();
        errdefer self.rollback();
        var row = try self.statement("SELECT host_id,source_db_fp,source_cfg_fp,plan_fp,recovery_point,generation,state,created_us,updated_us FROM migration_runs WHERE run_id=?1;");
        defer row.deinit();
        try row.blob(1, &run_id);
        if (!try row.row()) {
            try self.commitTransaction();
            return null;
        }
        const recovery = try allocator.dupe(u8, try row.boundedBytes(4, 4096));
        errdefer allocator.free(recovery);
        const state = std.meta.intToEnum(MigrationState, try row.signed(6)) catch return error.InvalidMigrationRow;
        const run = MigrationRun{ .run_id = run_id, .host_id = try effectBlob(&row, 0, 32), .source_db_fp = try effectBlob(&row, 1, 32), .source_cfg_fp = try effectBlob(&row, 2, 32), .plan_fp = try effectBlob(&row, 3, 32), .recovery_point = recovery, .generation = try effectBlob(&row, 5, 32), .state = state, .created_us = try row.signed(7), .updated_us = try row.signed(8) };
        try self.commitTransaction();
        return run;
    }

    pub fn beginMigrationStep(self: *Store, run_id: [32]u8, step: MigrationStep, intent: []const u8, now_us: i64) Error!u64 {
        if (intent.len > 4096 or now_us < 0) return error.InvalidMigrationRow;
        try self.beginWrite();
        errdefer self.rollback();
        if (self.schema_version < 23) return error.MigrationStorageRequired;
        {
            var exists = try self.statement("SELECT 1 FROM migration_runs WHERE run_id=?1;");
            defer exists.deinit();
            try exists.blob(1, &run_id);
            if (!try exists.row()) return error.MigrationRunMissing;
        }
        var pending_step = try self.statement("SELECT seq FROM migration_steps WHERE run_id=?1 AND outcome=0;");
        defer pending_step.deinit();
        try pending_step.blob(1, &run_id);
        if (try pending_step.row()) return error.MigrationStepOpen;
        var last = try self.statement("SELECT coalesce(max(seq),0) FROM migration_steps WHERE run_id=?1;");
        defer last.deinit();
        try last.blob(1, &run_id);
        if (!try last.row()) return error.DatabaseFailure;
        const next_seq = std.math.add(i64, try last.signed(0), 1) catch return error.InvalidMigrationRow;
        const seq = std.math.cast(u64, next_seq) orelse return error.InvalidMigrationRow;
        {
            var insert = try self.statement("INSERT INTO migration_steps VALUES(?1,?2,?3,?4,0,zeroblob(0),?5,NULL);");
            defer insert.deinit();
            try insert.blob(1, &run_id);
            try insert.int(2, @intCast(seq));
            try insert.int(3, @intFromEnum(step));
            try insert.blob(4, intent);
            try insert.int(5, now_us);
            try insert.done();
        }
        try self.touchMigrationRunTx(run_id, null, now_us);
        try self.fault(.after_migration_step_intent);
        try self.commitTransaction();
        return seq;
    }

    pub fn finishMigrationStep(self: *Store, run_id: [32]u8, seq: u64, outcome: MigrationOutcome, detail: []const u8, state: ?MigrationState, now_us: i64) Error!void {
        if (outcome == .pending or detail.len > 4096 or now_us < 0 or seq == 0 or seq > std.math.maxInt(i64)) return error.InvalidMigrationRow;
        try self.beginWrite();
        errdefer self.rollback();
        if (self.schema_version < 23) return error.MigrationStorageRequired;
        var update = try self.statement("UPDATE migration_steps SET outcome=?3,detail=?4,finished_us=?5 WHERE run_id=?1 AND seq=?2 AND outcome=0 AND started_us<=?5;");
        defer update.deinit();
        try update.blob(1, &run_id);
        try update.int(2, @intCast(seq));
        try update.int(3, @intFromEnum(outcome));
        try update.blob(4, detail);
        try update.int(5, now_us);
        try update.done();
        if (self.api.changes(self.db) != 1) return error.MigrationStepMissing;
        try self.touchMigrationRunTx(run_id, state, now_us);
        try self.fault(.after_migration_step_outcome);
        try self.commitTransaction();
    }

    fn touchMigrationRunTx(self: *Store, run_id: [32]u8, state: ?MigrationState, now_us: i64) Error!void {
        var update = try self.statement(if (state != null) "UPDATE migration_runs SET state=?2,updated_us=max(updated_us,?3) WHERE run_id=?1;" else "UPDATE migration_runs SET updated_us=max(updated_us,?3) WHERE run_id=?1;");
        defer update.deinit();
        try update.blob(1, &run_id);
        if (state) |value| try update.int(2, @intFromEnum(value));
        try update.int(3, now_us);
        try update.done();
        if (self.api.changes(self.db) != 1) return error.MigrationRunMissing;
    }

    pub fn migrationSteps(self: *Store, run_id: [32]u8, output: []MigrationStepRow) Error!usize {
        if (self.schema_version < 23) return error.MigrationStorageRequired;
        try self.beginRead();
        errdefer self.rollback();
        var row = try self.statement("SELECT seq,step,outcome,started_us,finished_us FROM migration_steps WHERE run_id=?1 ORDER BY seq LIMIT ?2;");
        defer row.deinit();
        try row.blob(1, &run_id);
        try row.int(2, @intCast(output.len));
        var count: usize = 0;
        while (try row.row()) {
            output[count] = .{ .seq = std.math.cast(u64, try row.signed(0)) orelse return error.InvalidMigrationRow, .step = std.meta.intToEnum(MigrationStep, try row.signed(1)) catch return error.InvalidMigrationRow, .outcome = std.meta.intToEnum(MigrationOutcome, try row.signed(2)) catch return error.InvalidMigrationRow, .started_us = try row.signed(3), .finished_us = try row.optionalSigned(4) };
            count += 1;
        }
        try self.commitTransaction();
        return count;
    }

    pub const StagedOwnerRow = struct { jail: []const u8, scope: [canonical_scope_bytes]u8, lease_kind: u8, deadline_us: ?i64, source_event_us: i64, source_row: u64 };
    pub const StagedHistoryRow = struct { jail: []const u8, scope: [canonical_scope_bytes]u8, event_kind: u8, event_us: i64, bancount: i64, source_row: u64 };
    pub const canonical_scope_bytes = 92;

    pub fn stageMigrationRows(self: *Store, run_id: [32]u8, owners: []const StagedOwnerRow, history: []const StagedHistoryRow) Error!void {
        if (owners.len > 200_000 or history.len > 200_000) return error.InvalidMigrationRow;
        try self.beginWrite();
        errdefer self.rollback();
        if (self.schema_version < 23) return error.MigrationStorageRequired;
        for ([_][:0]const u8{ "DELETE FROM migration_staged_owners WHERE run_id=?1;", "DELETE FROM migration_staged_history WHERE run_id=?1;" }) |sql| {
            var delete = try self.statement(sql);
            defer delete.deinit();
            try delete.blob(1, &run_id);
            try delete.done();
        }
        for (owners, 1..) |owner, seq| {
            if (owner.jail.len == 0 or owner.jail.len > 64 or owner.lease_kind < 1 or owner.lease_kind > 2 or (owner.lease_kind == 1) != (owner.deadline_us != null)) return error.InvalidMigrationRow;
            var insert = try self.statement("INSERT INTO migration_staged_owners VALUES(?1,?2,?3,?4,?5,?6,?7,?8);");
            defer insert.deinit();
            try insert.blob(1, &run_id);
            try insert.int(2, @intCast(seq));
            try insert.text(3, owner.jail);
            try insert.blob(4, &owner.scope);
            try insert.int(5, owner.lease_kind);
            if (owner.deadline_us) |deadline| try insert.int(6, deadline);
            try insert.int(7, owner.source_event_us);
            try insert.int(8, @intCast(owner.source_row));
            try insert.done();
        }
        for (history, 1..) |event, seq| {
            if (event.jail.len == 0 or event.jail.len > 64 or event.event_kind < 1 or event.event_kind > 3 or event.bancount < 0) return error.InvalidMigrationRow;
            var insert = try self.statement("INSERT INTO migration_staged_history VALUES(?1,?2,?3,?4,?5,?6,?7,?8);");
            defer insert.deinit();
            try insert.blob(1, &run_id);
            try insert.int(2, @intCast(seq));
            try insert.text(3, event.jail);
            try insert.blob(4, &event.scope);
            try insert.int(5, event.event_kind);
            try insert.int(6, event.event_us);
            try insert.int(7, event.bancount);
            try insert.int(8, @intCast(event.source_row));
            try insert.done();
        }
        try self.commitTransaction();
    }

    pub const StagedCounts = struct { owners: u64, history: u64 };
    pub fn stagedMigrationCounts(self: *Store, run_id: [32]u8) Error!StagedCounts {
        if (self.schema_version < 23) return error.MigrationStorageRequired;
        try self.beginRead();
        errdefer self.rollback();
        var owners = try self.statement("SELECT count(*) FROM migration_staged_owners WHERE run_id=?1;");
        defer owners.deinit();
        try owners.blob(1, &run_id);
        if (!try owners.row()) return error.DatabaseFailure;
        const owner_count: u64 = @intCast(try owners.signed(0));
        var history = try self.statement("SELECT count(*) FROM migration_staged_history WHERE run_id=?1;");
        defer history.deinit();
        try history.blob(1, &run_id);
        if (!try history.row()) return error.DatabaseFailure;
        const history_count: u64 = @intCast(try history.signed(0));
        try self.commitTransaction();
        return .{ .owners = owner_count, .history = history_count };
    }

    pub const JailGeneration = struct { jail: []const u8, generation: [32]u8 };
    pub fn activateStagedOwners(self: *Store, run_id: [32]u8, generations: []const JailGeneration, clock: effects.Clock) Error!u64 {
        try self.beginWrite();
        errdefer self.rollback();
        if (self.schema_version < 23) return error.MigrationStorageRequired;
        try self.effectSchema();
        const now = try self.effectClock(clock);
        {
            var state = try self.statement("SELECT state FROM migration_runs WHERE run_id=?1;");
            defer state.deinit();
            try state.blob(1, &run_id);
            if (!try state.row()) return error.MigrationRunMissing;
            const current = try state.signed(0);
            if (current != @intFromEnum(MigrationState.staged) and current != @intFromEnum(MigrationState.activating)) return error.InvalidMigrationState;
        }
        {
            var mark = try self.statement("UPDATE migration_runs SET state=?2,updated_us=max(updated_us,?3) WHERE run_id=?1;");
            defer mark.deinit();
            try mark.blob(1, &run_id);
            try mark.int(2, @intFromEnum(MigrationState.activating));
            try mark.int(3, @max(0, now));
            try mark.done();
        }
        const Staged = struct { seq: u64, jail: [64]u8, jail_len: u8, scope: [canonical_scope_bytes]u8, lease_kind: u8, deadline_us: ?i64, decided_us: i64 };
        var held = std.ArrayListUnmanaged(Staged){};
        defer held.deinit(self.allocator);
        {
            var rows = try self.statement("SELECT seq,jail,scope,lease_kind,deadline_us,source_event_us FROM migration_staged_owners WHERE run_id=?1 ORDER BY seq;");
            defer rows.deinit();
            try rows.blob(1, &run_id);
            while (try rows.row()) {
                if (held.items.len == effects.max_effects) return error.EffectCapacity;
                var item = Staged{ .seq = std.math.cast(u64, try rows.signed(0)) orelse return error.InvalidMigrationRow, .jail = undefined, .jail_len = 0, .scope = try effectBlob(&rows, 2, canonical_scope_bytes), .lease_kind = std.math.cast(u8, try rows.signed(3)) orelse return error.InvalidMigrationRow, .deadline_us = try rows.optionalSigned(4), .decided_us = try rows.signed(5) };
                const jail = try rows.boundedBytes(1, 64);
                @memcpy(item.jail[0..jail.len], jail);
                item.jail_len = @intCast(jail.len);
                try held.append(self.allocator, item);
            }
        }
        const canonical_scope = @import("../firewall/scope.zig");
        const installation = try self.readInstallation() orelse return error.InstallationRequired;
        var activated: u64 = 0;
        var effect_changed = false;
        for (held.items) |item| {
            const scope = canonical_scope.Scope.decode(&item.scope) catch return error.InvalidMigrationRow;
            const lease: effects.Lease = if (item.lease_kind == 2) .permanent else .{ .finite = item.deadline_us orelse return error.InvalidMigrationRow };
            if (lease == .finite and lease.finite <= now) continue;
            var counter: [8]u8 = undefined;
            std.mem.writeInt(u64, &counter, item.seq, .little);
            const decision_id = effects.hashParts("fail2zig-migration-owner-v1", &.{ &run_id, &counter });
            const key = try (try effects.Scope.exact(scope)).key(installation);
            const jail = item.jail[0..item.jail_len];
            const generation = for (generations) |candidate| {
                if (std.mem.eql(u8, candidate.jail, jail)) break candidate.generation;
            } else return error.MigrationJailUnknown;
            var existing_revision: u64 = 0;
            var replay = false;
            var native: ?struct { decision_id: [32]u8, permanent: bool, deadline_us: ?i64, decided_us: i64 } = null;
            {
                var row = try self.statement("SELECT decision_id,revision,lease_kind,deadline_us,decided_us FROM effect_owners WHERE scope_key=?1 AND jail=?2;");
                defer row.deinit();
                try row.blob(1, &key);
                try row.text(2, jail);
                if (try row.row()) {
                    const saved = try effectBlob(&row, 0, 32);
                    existing_revision = std.math.cast(u64, try row.signed(1)) orelse return error.InvalidMigrationRow;
                    const kind = try row.signed(2);
                    replay = std.mem.eql(u8, &saved, &decision_id) and kind != 0;
                    if (!replay and kind != 0) native = .{ .decision_id = saved, .permanent = kind == 2, .deadline_us = try row.optionalSigned(3), .decided_us = try row.signed(4) };
                }
            }
            if (replay) {
                activated += 1;
                continue;
            }
            if (native) |owner| {
                const native_live = owner.permanent or (owner.deadline_us orelse 0) > now;
                if (native_live) {
                    try self.recordMigrationConflictTx(run_id, item.seq, &item.scope, jail, item.lease_kind, item.deadline_us, now);
                    const extend = !owner.permanent and lease == .finite and (owner.deadline_us orelse 0) < lease.finite;
                    if (extend) {
                        _ = try self.setOwnerTx(try (effects.CanonicalOwnerChange{ .scope = scope, .jail = jail, .generation = generation, .decision_id = effects.hashParts("fail2zig-migration-extend-v1", &.{ &run_id, &counter }), .expected_revision = existing_revision, .lease = lease, .decided_us = @min(owner.decided_us, now) }).exact(), now);
                        effect_changed = true;
                    }
                    continue;
                }
            }
            _ = try self.setOwnerTx(try (effects.CanonicalOwnerChange{ .scope = scope, .jail = jail, .generation = generation, .decision_id = decision_id, .expected_revision = existing_revision, .lease = lease, .decided_us = @min(item.decided_us, now) }).exact(), now);
            effect_changed = true;
            activated += 1;
        }
        _ = try self.commitEffectClock(clock);
        try self.fault(.before_migration_activation_commit);
        try self.commitEffectTransaction(effect_changed);
        return activated;
    }

    fn recordMigrationConflictTx(self: *Store, run_id: [32]u8, seq: u64, scope: *const [canonical_scope_bytes]u8, jail: []const u8, lease_kind: u8, deadline_us: ?i64, now: i64) Error!void {
        {
            var exists = try self.statement("SELECT 1 FROM migration_deltas WHERE run_id=?1 AND seq=?2;");
            defer exists.deinit();
            try exists.blob(1, &run_id);
            try exists.int(2, @intCast(seq));
            if (try exists.row()) return;
        }
        var insert = try self.statement("INSERT INTO migration_deltas VALUES(?1,?2,3,?3,?4,?5,?6,1,0,?7);");
        defer insert.deinit();
        try insert.blob(1, &run_id);
        try insert.int(2, @intCast(seq));
        try insert.blob(3, scope);
        try insert.text(4, jail);
        try insert.int(5, lease_kind);
        if (deadline_us) |deadline| try insert.int(6, deadline) else try self.check(self.api.bind_null(insert.ptr, 6));
        try insert.int(7, @max(0, now));
        try insert.done();
    }

    pub const MigrationDeltaKind = enum(u8) { ban = 1, unban = 2, conflict = 3 };
    pub const MigrationCarryBack = enum(u8) { mapped = 1, unsupported = 2, expired = 3 };
    pub const MigrationDelta = struct {
        kind: MigrationDeltaKind,
        jail: [64]u8,
        jail_len: u8,
        scope: [canonical_scope_bytes]u8,
        lease_kind: u8,
        deadline_us: ?i64,
        decided_us: i64,
        carry_back: MigrationCarryBack,
        pub fn jailName(self: *const MigrationDelta) []const u8 {
            return self.jail[0..self.jail_len];
        }
    };
    pub fn planMigrationDeltas(self: *Store, run_id: [32]u8, jails: []const []const u8, now_us: i64, output: []MigrationDelta) Error!usize {
        if (self.schema_version < 23) return error.MigrationStorageRequired;
        const installation = try self.readInstallation() orelse return error.InstallationRequired;
        const canonical_scope = @import("../firewall/scope.zig");
        var count: usize = 0;
        var staged = try self.statement("SELECT jail,scope,lease_kind,deadline_us,seq FROM migration_staged_owners WHERE run_id=?1 ORDER BY seq;");
        defer staged.deinit();
        try staged.blob(1, &run_id);
        while (try staged.row()) {
            const jail = try staged.boundedBytes(0, 64);
            const scope_bytes = try effectBlob(&staged, 1, canonical_scope_bytes);
            const scope = canonical_scope.Scope.decode(&scope_bytes) catch return error.InvalidMigrationRow;
            const key = try (try effects.Scope.exact(scope)).key(installation);
            var live = false;
            var native_decision = false;
            var live_kind: u8 = 0;
            var live_deadline: ?i64 = null;
            var live_decided: i64 = now_us;
            {
                var owner = try self.statement("SELECT lease_kind,deadline_us,decided_us,decision_id FROM effect_owners WHERE scope_key=?1 AND jail=?2 AND lease_kind!=0 AND (lease_kind=2 OR deadline_us>?3);");
                defer owner.deinit();
                try owner.blob(1, &key);
                try owner.text(2, jail);
                try owner.int(3, now_us);
                if (try owner.row()) {
                    live = true;
                    live_kind = std.math.cast(u8, try owner.signed(0)) orelse return error.InvalidMigrationRow;
                    live_deadline = try owner.optionalSigned(1);
                    live_decided = try owner.signed(2);
                    var seq_counter: [8]u8 = undefined;
                    std.mem.writeInt(u64, &seq_counter, std.math.cast(u64, try staged.signed(4)) orelse return error.InvalidMigrationRow, .little);
                    const migration_decision = effects.hashParts("fail2zig-migration-owner-v1", &.{ &run_id, &seq_counter });
                    const extension_decision = effects.hashParts("fail2zig-migration-extend-v1", &.{ &run_id, &seq_counter });
                    const decision = try effectBlob(&owner, 3, 32);
                    native_decision = !std.mem.eql(u8, &decision, &migration_decision) and !std.mem.eql(u8, &decision, &extension_decision);
                }
            }
            if (live and !native_decision) continue;
            if (count == output.len) return error.EffectCapacity;
            if (live) {
                var delta = MigrationDelta{ .kind = .ban, .jail = undefined, .jail_len = @intCast(jail.len), .scope = scope_bytes, .lease_kind = live_kind, .deadline_us = live_deadline, .decided_us = live_decided, .carry_back = if (scope.protocols.isAll() and scope.ports.isAll()) .mapped else .unsupported };
                @memcpy(delta.jail[0..jail.len], jail);
                output[count] = delta;
                count += 1;
                continue;
            }
            const staged_kind = std.math.cast(u8, try staged.signed(2)) orelse return error.InvalidMigrationRow;
            const staged_deadline = try staged.optionalSigned(3);
            const expired = staged_kind == 1 and (staged_deadline orelse 0) <= now_us;
            var delta = MigrationDelta{ .kind = .unban, .jail = undefined, .jail_len = @intCast(jail.len), .scope = scope_bytes, .lease_kind = 0, .deadline_us = null, .decided_us = now_us, .carry_back = if (expired) .expired else .mapped };
            @memcpy(delta.jail[0..jail.len], jail);
            output[count] = delta;
            count += 1;
        }
        for (jails) |jail| {
            var owners = try self.statement("SELECT n.canonical_scope,o.lease_kind,o.deadline_us,o.decided_us FROM effect_owners o JOIN native_effects n USING(scope_key) WHERE o.jail=?1 AND o.lease_kind!=0 AND (o.lease_kind=2 OR o.deadline_us>?2) AND NOT EXISTS (SELECT 1 FROM migration_staged_owners s WHERE s.run_id=?3 AND s.jail=o.jail AND s.scope=n.canonical_scope) ORDER BY o.decided_us;");
            defer owners.deinit();
            try owners.text(1, jail);
            try owners.int(2, now_us);
            try owners.blob(3, &run_id);
            while (try owners.row()) {
                if (count == output.len) return error.EffectCapacity;
                const scope_bytes = try effectBlob(&owners, 0, canonical_scope_bytes);
                const scope = canonical_scope.Scope.decode(&scope_bytes) catch return error.InvalidMigrationRow;
                const mapped = scope.protocols.isAll() and scope.ports.isAll();
                var delta = MigrationDelta{ .kind = .ban, .jail = undefined, .jail_len = @intCast(jail.len), .scope = scope_bytes, .lease_kind = std.math.cast(u8, try owners.signed(1)) orelse return error.InvalidMigrationRow, .deadline_us = try owners.optionalSigned(2), .decided_us = try owners.signed(3), .carry_back = if (mapped) .mapped else .unsupported };
                @memcpy(delta.jail[0..jail.len], jail);
                output[count] = delta;
                count += 1;
            }
        }
        return count;
    }
    pub fn recordMigrationDeltas(self: *Store, run_id: [32]u8, deltas: []const MigrationDelta, applied: bool, now_us: i64) Error!void {
        try self.beginWrite();
        errdefer self.rollback();
        if (self.schema_version < 23) return error.MigrationStorageRequired;
        {
            var stale = try self.statement("DELETE FROM migration_deltas WHERE run_id=?1 AND kind IN (1,2) AND applied=0;");
            defer stale.deinit();
            try stale.blob(1, &run_id);
            try stale.done();
        }
        var last = try self.statement("SELECT coalesce(max(seq),0) FROM migration_deltas WHERE run_id=?1;");
        defer last.deinit();
        try last.blob(1, &run_id);
        if (!try last.row()) return error.DatabaseFailure;
        var seq: i64 = try last.signed(0);
        for (deltas) |delta| {
            seq += 1;
            var insert = try self.statement("INSERT INTO migration_deltas VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10);");
            defer insert.deinit();
            try insert.blob(1, &run_id);
            try insert.int(2, seq);
            try insert.int(3, @intFromEnum(delta.kind));
            try insert.blob(4, &delta.scope);
            try insert.text(5, delta.jailName());
            try insert.int(6, delta.lease_kind);
            if (delta.lease_kind == 1) try insert.int(7, delta.deadline_us orelse return error.InvalidMigrationRow) else try self.check(self.api.bind_null(insert.ptr, 7));
            try insert.int(8, @intFromEnum(delta.carry_back));
            try insert.int(9, @intFromBool(applied));
            try insert.int(10, @max(0, now_us));
            try insert.done();
        }
        try self.commitTransaction();
    }
    pub fn releaseMigrationOwners(self: *Store, run_id: [32]u8, clock: effects.Clock) Error!u64 {
        if (self.schema_version < 23) return error.MigrationStorageRequired;
        const installation = try self.readInstallation() orelse return error.InstallationRequired;
        const canonical_scope = @import("../firewall/scope.zig");
        var released: u64 = 0;
        var seq_index: u64 = 0;
        var staged = try self.statement("SELECT seq,jail,scope FROM migration_staged_owners WHERE run_id=?1 ORDER BY seq;");
        defer staged.deinit();
        try staged.blob(1, &run_id);
        var pending = std.ArrayListUnmanaged(struct { seq: u64, jail: [64]u8, jail_len: u8, scope: [canonical_scope_bytes]u8 }){};
        defer pending.deinit(self.allocator);
        while (try staged.row()) {
            if (pending.items.len == effects.max_effects) return error.EffectCapacity;
            const jail = try staged.boundedBytes(1, 64);
            var item: @TypeOf(pending.items[0]) = .{ .seq = std.math.cast(u64, try staged.signed(0)) orelse return error.InvalidMigrationRow, .jail = undefined, .jail_len = @intCast(jail.len), .scope = try effectBlob(&staged, 2, canonical_scope_bytes) };
            @memcpy(item.jail[0..jail.len], jail);
            try pending.append(self.allocator, item);
        }
        for (pending.items) |item| {
            seq_index += 1;
            const scope = canonical_scope.Scope.decode(&item.scope) catch return error.InvalidMigrationRow;
            const key = try (try effects.Scope.exact(scope)).key(installation);
            const jail = item.jail[0..item.jail_len];
            const owner = (try self.currentOwner(key, jail)) orelse continue;
            if (owner.lease == .absent) continue;
            var counter: [8]u8 = undefined;
            std.mem.writeInt(u64, &counter, item.seq, .little);
            _ = try self.transitionOwner(.{ .scope = scope, .jail = jail, .current_generation = owner.generation, .next_generation = owner.generation, .expected_owner_revision = owner.revision, .transition_id = effects.hashParts("fail2zig-migration-release-v1", &.{ &run_id, &counter }), .mode = .release, .occurred_us = clock.prepared_us }, clock);
            released += 1;
        }
        return released;
    }

    pub const PendingStep = struct { seq: u64, step: MigrationStep };
    pub fn pendingMigrationStep(self: *Store, run_id: [32]u8) Error!?PendingStep {
        if (self.schema_version < 23) return error.MigrationStorageRequired;
        var row = try self.statement("SELECT seq,step FROM migration_steps WHERE run_id=?1 AND outcome=0;");
        defer row.deinit();
        try row.blob(1, &run_id);
        if (!try row.row()) return null;
        const step = std.meta.intToEnum(MigrationStep, try row.signed(1)) catch return error.InvalidMigrationRow;
        return .{ .seq = std.math.cast(u64, try row.signed(0)) orelse return error.InvalidMigrationRow, .step = step };
    }
    pub fn migrationStagedKeys(self: *Store, run_id: [32]u8, output: [][32]u8) Error!usize {
        if (self.schema_version < 23) return error.MigrationStorageRequired;
        const installation = try self.readInstallation() orelse return error.InstallationRequired;
        const canonical_scope = @import("../firewall/scope.zig");
        var count: usize = 0;
        var staged = try self.statement("SELECT scope FROM migration_staged_owners WHERE run_id=?1 ORDER BY seq;");
        defer staged.deinit();
        try staged.blob(1, &run_id);
        while (try staged.row()) {
            if (count == output.len) return error.EffectCapacity;
            const scope = canonical_scope.Scope.decode(&try effectBlob(&staged, 0, canonical_scope_bytes)) catch return error.InvalidMigrationRow;
            output[count] = try (try effects.Scope.exact(scope)).key(installation);
            count += 1;
        }
        return count;
    }
    pub fn markMigrationDeltasApplied(self: *Store, run_id: [32]u8) Error!void {
        try self.beginWrite();
        errdefer self.rollback();
        if (self.schema_version < 23) return error.MigrationStorageRequired;
        var update = try self.statement("UPDATE migration_deltas SET applied=1 WHERE run_id=?1 AND kind IN (1,2);");
        defer update.deinit();
        try update.blob(1, &run_id);
        try update.done();
        try self.commitTransaction();
    }
    pub fn migrationStepSucceeded(self: *Store, run_id: [32]u8, step: MigrationStep) Error!bool {
        if (self.schema_version < 23) return error.MigrationStorageRequired;
        var row = try self.statement("SELECT 1 FROM migration_steps WHERE run_id=?1 AND step=?2 AND outcome=?3;");
        defer row.deinit();
        try row.blob(1, &run_id);
        try row.int(2, @intFromEnum(step));
        try row.int(3, @intFromEnum(MigrationOutcome.success));
        return try row.row();
    }

    pub fn migrationActivatedKeys(self: *Store, run_id: [32]u8, now_us: i64, output: [][32]u8) Error!struct { expected: u64, found: usize } {
        if (self.schema_version < 23) return error.MigrationStorageRequired;
        const installation = try self.readInstallation() orelse return error.InstallationRequired;
        const canonical_scope = @import("../firewall/scope.zig");
        var expected: u64 = 0;
        var found: usize = 0;
        var staged = try self.statement("SELECT jail,scope FROM migration_staged_owners WHERE run_id=?1 AND (lease_kind=2 OR deadline_us>?2) ORDER BY seq;");
        defer staged.deinit();
        try staged.blob(1, &run_id);
        try staged.int(2, now_us);
        while (try staged.row()) {
            expected += 1;
            const jail = try staged.boundedBytes(0, 64);
            const scope = canonical_scope.Scope.decode(&try effectBlob(&staged, 1, canonical_scope_bytes)) catch return error.InvalidMigrationRow;
            const key = try (try effects.Scope.exact(scope)).key(installation);
            var owner = try self.statement("SELECT scope_key FROM effect_owners WHERE scope_key=?1 AND jail=?2 AND lease_kind!=0 AND (lease_kind=2 OR deadline_us>?3);");
            defer owner.deinit();
            try owner.blob(1, &key);
            try owner.text(2, jail);
            try owner.int(3, now_us);
            if (try owner.row()) {
                if (found == output.len) return error.EffectCapacity;
                output[found] = try effectBlob(&owner, 0, 32);
                found += 1;
            }
        }
        return .{ .expected = expected, .found = found };
    }

    pub fn inspectInteger(self: *Store, sql: [:0]const u8) Error!i64 {
        if (!@import("builtin").is_test) @compileError("inspectInteger is test-only");
        return self.integer(sql);
    }
    pub fn inspectExec(self: *Store, sql: [:0]const u8) Error!void {
        if (!@import("builtin").is_test) @compileError("inspectExec is test-only");
        return self.exec(sql);
    }

    pub fn adminRevision(self: *Store) Error!u64 {
        if (self.schema_version < 22) return error.AdminStorageRequired;
        const value = try self.integer("SELECT mutation_revision FROM admin_revision WHERE id=1;");
        if (value < 0) return error.DatabaseFailure;
        return @intCast(value);
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
        for (decisions[0..decision_count]) |decision| if (decision.lease.live(now) or try self.subjectEffectPinned(decision.subject)) return true;
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
        const logical = (try retry.prune(admission.policy, state, now)).state;
        const pinned = logical.lease != .absent or logical.count != 0;
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
        var row = try self.statement(if (self.schema_version >= 19)
            "SELECT s.sequence,e.event_id,e.scope_key,n.canonical_scope,e.jail,e.decision_id,e.confirmed_us,EXISTS(SELECT 1 FROM confirmed_event_details d WHERE d.event_id=e.event_id) FROM confirmed_history_sequence s JOIN confirmed_effect_events e ON e.event_id=s.event_id JOIN native_effects n ON n.scope_key=e.scope_key WHERE s.sequence>?1 ORDER BY s.sequence LIMIT ?2;"
        else if (self.schema_version >= 17)
            "SELECT s.sequence,e.event_id,e.scope_key,n.scope,e.jail,e.decision_id,e.confirmed_us,EXISTS(SELECT 1 FROM confirmed_event_details d WHERE d.event_id=e.event_id) FROM confirmed_history_sequence s JOIN confirmed_effect_events e ON e.event_id=s.event_id JOIN native_effects n ON n.scope_key=e.scope_key WHERE s.sequence>?1 ORDER BY s.sequence LIMIT ?2;"
        else
            "SELECT s.sequence,e.event_id,e.scope_key,n.scope,e.jail,e.decision_id,e.confirmed_us FROM confirmed_history_sequence s JOIN confirmed_effect_events e ON e.event_id=s.event_id JOIN native_effects n ON n.scope_key=e.scope_key WHERE s.sequence>?1 ORDER BY s.sequence LIMIT ?2;");
        defer row.deinit();
        try row.int(1, @intCast(after));
        try row.int(2, @intCast(output.len));
        var count: usize = 0;
        while (try row.row()) {
            const sequence = try row.signed(0);
            if (sequence <= 0 or sequence != after + count + 1 or sequence > token.head_sequence) return error.HistoryGap;
            const native_retry = if (self.schema_version >= 17) blk: {
                const value = try row.signed(7);
                if (value < 0 or value > 1) return error.InvalidHistoryEvent;
                break :blk value == 1;
            } else false;
            const event = effect_history.Event{ .sequence = @intCast(sequence), .event_id = try effectBlob(&row, 1, 32), .installation = installation, .scope_key = try effectBlob(&row, 2, 32), .scope = try self.decodeStoredScope(&row, 3), .jail = detection.Name.init(try row.boundedBytes(4, 64)) catch return error.InvalidHistoryEvent, .decision_id = try effectBlob(&row, 5, 32), .confirmed_us = try row.signed(6), .native_retry = native_retry };
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
    pub fn confirmedEffectPage(self: *Store, installation: effects.Installation, after_sequence: u64, expected_revision: ?u64, output: []effect_history.Event) Error!effect_history.Page {
        try self.beginRead();
        errdefer self.rollback();
        const page = try self.confirmedEffectPageTx(installation, after_sequence, expected_revision, output);
        try self.commitTransaction();
        return page;
    }

    pub fn historyEventEligible(self: *Store, event: effect_history.Event) Error!bool {
        try event.validate();
        if (self.schema_version < 20) return true;
        if (event.scope.canonical.subject.kind != .host) return error.InvalidHistoryReset;
        const subject: detection.Subject = switch (event.scope.canonical.subject.family) {
            .v4 => .{ .v4 = event.scope.canonical.subject.address[0..4].* },
            .v6 => .{ .v6 = event.scope.canonical.subject.address },
        };
        try self.beginRead();
        errdefer self.rollback();
        var row = try self.statement("SELECT max(through_sequence) FROM history_reset_watermarks WHERE family=?1 AND subject=?2 AND ((scope=1 AND jail=?3) OR (scope=2 AND jail=''));");
        defer row.deinit();
        try bindSubjectAt(&row, &subject, 1);
        try row.text(3, event.jail.slice());
        if (!try row.row()) return error.InvalidHistoryReset;
        const through = try row.optionalSigned(0);
        if (try row.row()) return error.InvalidHistoryReset;
        try self.commitTransaction();
        if (through) |value| {
            if (value < 0) return error.InvalidHistoryReset;
            return event.sequence > @as(u64, @intCast(value));
        }
        return true;
    }

    pub fn resetHistory(self: *Store, intent: HistoryResetIntent, clock: effects.Clock) Error!HistoryResetResult {
        intent.subject.validate() catch return error.InvalidHistoryReset;
        if (intent.subject.unenforceable() or intent.expected_revision > std.math.maxInt(i64) or std.mem.allEqual(u8, &intent.intent_id, 0)) return error.InvalidHistoryReset;
        const scope_value: i64 = switch (intent.scope) {
            .jail => |name| blk: {
                _ = detection.Name.init(name) catch return error.InvalidHistoryReset;
                break :blk 1;
            },
            .overall => 2,
        };
        const jail = switch (intent.scope) {
            .jail => |name| name,
            .overall => "",
        };
        try self.beginWrite();
        errdefer self.rollback();
        if (self.schema_version < 20) return error.HistoryResetStorageRequired;
        var existing = try self.statement("SELECT through_sequence,reset_us,revision,intent_id FROM history_reset_watermarks WHERE scope=?1 AND jail=?2 AND family=?3 AND subject=?4;");
        defer existing.deinit();
        try existing.int(1, scope_value);
        try existing.text(2, jail);
        try bindSubjectAt(&existing, &intent.subject, 3);
        var prior_revision: u64 = 0;
        if (try existing.row()) {
            const through = try existing.signed(0);
            const reset_us = try existing.signed(1);
            const saved_revision = try existing.signed(2);
            const prior_intent = try effectBlob(&existing, 3, 32);
            if (through < 0 or saved_revision <= 0 or try existing.row()) return error.InvalidHistoryReset;
            if (std.mem.eql(u8, &prior_intent, &intent.intent_id)) {
                try self.commitTransaction();
                return .{ .revision = @intCast(saved_revision), .through_sequence = @intCast(through), .reset_us = reset_us };
            }
            prior_revision = @intCast(saved_revision);
        }
        if (prior_revision != intent.expected_revision) return error.StaleHistoryReset;
        if (prior_revision == std.math.maxInt(i64)) return error.InvalidHistoryReset;
        if (prior_revision == 0 and try self.integer("SELECT count(*) FROM history_reset_watermarks;") >= effects.max_effects) return error.EffectCapacity;
        const now = try self.effectClock(clock);
        const head_value = try self.integer("SELECT head FROM confirmed_history_stream WHERE id=1;");
        if (head_value < 0) return error.InvalidHistoryReset;
        const head: u64 = @intCast(head_value);
        {
            var write = try self.statement("INSERT INTO history_reset_watermarks VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(scope,jail,family,subject) DO UPDATE SET through_sequence=excluded.through_sequence,reset_us=excluded.reset_us,revision=excluded.revision,intent_id=excluded.intent_id;");
            defer write.deinit();
            try write.int(1, scope_value);
            try write.text(2, jail);
            try bindSubjectAt(&write, &intent.subject, 3);
            try write.int(5, @intCast(head));
            try write.int(6, now);
            try write.int(7, @intCast(prior_revision + 1));
            try write.blob(8, &intent.intent_id);
            try write.done();
            if (self.api.changes(self.db) != 1) return error.InvalidHistoryReset;
        }
        {
            var summaries = try self.statement(if (scope_value == 1)
                "DELETE FROM confirmed_policy_summaries WHERE jail=?1 AND family=?2 AND subject=?3;"
            else
                "DELETE FROM confirmed_policy_summaries WHERE family=?1 AND subject=?2;");
            defer summaries.deinit();
            if (scope_value == 1) {
                try summaries.text(1, jail);
                try bindSubjectAt(&summaries, &intent.subject, 2);
            } else try bindSubjectAt(&summaries, &intent.subject, 1);
            try summaries.done();
        }
        try self.fault(.after_history_reset);
        _ = try self.commitEffectClock(clock);
        try self.commitTransaction();
        return .{ .revision = prior_revision + 1, .through_sequence = head, .reset_us = now };
    }

    fn readActionTargetsTx(self: *Store, action_id: [32]u8, output: *[action_outcome.max_targets_per_action]action_outcome.Target) Error!usize {
        var row = try self.statement("SELECT scope_key,jail,kind,required,restored,status,intent_us,dispatch_us,settled_us,metadata FROM action_targets WHERE action_id=?1 ORDER BY kind;");
        defer row.deinit();
        try row.blob(1, &action_id);
        var count: usize = 0;
        while (try row.row()) {
            if (count == output.len) return error.InvalidActionTarget;
            const kind_value = try row.signed(2);
            const required = try row.signed(3);
            const restored = try row.signed(4);
            const status_value = try row.signed(5);
            const intent_us = try row.signed(6);
            const dispatch_us = try row.optionalSigned(7);
            const settled_us = try row.optionalSigned(8);
            if (required < 0 or required > 1 or restored < 0 or restored > 1) return error.InvalidActionTarget;
            const kind = std.meta.intToEnum(action_outcome.Kind, kind_value) catch return error.InvalidActionTarget;
            const status = std.meta.intToEnum(action_outcome.Status, status_value) catch return error.InvalidActionTarget;
            const jail = detection.Name.init(try row.boundedBytes(1, 64)) catch return error.InvalidActionTarget;
            var target = action_outcome.Target{ .action_id = action_id, .scope_key = try effectBlob(&row, 0, 32), .jail = jail, .kind = kind, .required = required == 1, .restored = restored == 1, .status = status, .intent_us = intent_us, .dispatch_us = dispatch_us, .settled_us = settled_us, .metadata_len = 0 };
            if (self.api.column_type(row.ptr, 9) != 5) {
                const metadata = try row.boundedBytes(9, action_outcome.max_metadata_bytes);
                if (metadata.len == 0 or !std.unicode.utf8ValidateSlice(metadata)) return error.InvalidActionTarget;
                target.metadata_len = @intCast(metadata.len);
                @memcpy(target.metadata_bytes[0..metadata.len], metadata);
            }
            output[count] = target;
            count += 1;
        }
        return count;
    }

    fn prepareActionTargetsTx(self: *Store, intent: action_outcome.Intent, now: i64) Error!void {
        try intent.validate();
        var existing: [action_outcome.max_targets_per_action]action_outcome.Target = undefined;
        const existing_count = try self.readActionTargetsTx(intent.action_id, &existing);
        if (existing_count != 0) {
            if (existing_count != action_outcome.max_targets_per_action) return error.InvalidActionTarget;
            for (existing, 0..) |target, index| {
                if (target.kind != @as(action_outcome.Kind, if (index == 0) .enforcement else .notification) or
                    !std.mem.eql(u8, &target.scope_key, &intent.scope_key) or !std.mem.eql(u8, target.jail.slice(), intent.jail) or
                    target.restored != intent.restored or !std.mem.eql(u8, target.metadata(), intent.metadata orelse "")) return error.InvalidActionTarget;
            }
            return;
        }
        if (try self.integer("SELECT count(*) FROM action_targets;") > action_outcome.max_rows - action_outcome.max_targets_per_action) return error.ActionTargetCapacity;
        for ([_]action_outcome.Kind{ .enforcement, .notification }) |kind| {
            const suppressed = kind == .notification and intent.restored;
            var insert = try self.statement("INSERT INTO action_targets VALUES(?1,?2,?3,?4,?5,?6,?7,?8,NULL,?9,?10);");
            defer insert.deinit();
            try insert.blob(1, &intent.action_id);
            try insert.int(2, @intFromEnum(kind));
            try insert.blob(3, &intent.scope_key);
            try insert.text(4, intent.jail);
            try insert.int(5, if (kind == .enforcement) 1 else 0);
            try insert.int(6, @intFromBool(intent.restored));
            try insert.int(7, @intFromEnum(if (suppressed) action_outcome.Status.suppressed_restored else .pending));
            try insert.int(8, now);
            if (suppressed) try insert.int(9, now);
            if (intent.metadata) |metadata| try insert.text(10, metadata);
            try insert.done();
        }
        try self.fault(.after_action_target_intent);
    }

    pub fn prepareActionTargets(self: *Store, intent: action_outcome.Intent, clock: effects.Clock) Error!void {
        try self.beginWrite();
        errdefer self.rollback();
        if (self.schema_version < 21) return error.ActionTargetStorageRequired;
        const now = try self.effectClock(clock);
        try self.prepareActionTargetsTx(intent, now);
        _ = try self.commitEffectClock(clock);
        try self.commitTransaction();
    }

    pub fn actionTargets(self: *Store, action_id: [32]u8, output: *[action_outcome.max_targets_per_action]action_outcome.Target) Error!usize {
        if (std.mem.allEqual(u8, &action_id, 0) or self.schema_version < 21) return error.InvalidActionTarget;
        try self.beginRead();
        errdefer self.rollback();
        const count = try self.readActionTargetsTx(action_id, output);
        try self.commitTransaction();
        return count;
    }

    pub fn markActionTargetDispatched(self: *Store, action_id: [32]u8, kind: action_outcome.Kind, clock: effects.Clock) Error!void {
        try self.beginWrite();
        errdefer self.rollback();
        if (self.schema_version < 21) return error.ActionTargetStorageRequired;
        const now = try self.effectClock(clock);
        var row = try self.statement("SELECT status FROM action_targets WHERE action_id=?1 AND kind=?2;");
        defer row.deinit();
        try row.blob(1, &action_id);
        try row.int(2, @intFromEnum(kind));
        if (!try row.row()) return error.StaleActionTarget;
        const status = std.meta.intToEnum(action_outcome.Status, try row.signed(0)) catch return error.InvalidActionTarget;
        if (try row.row()) return error.InvalidActionTarget;
        if (status == .dispatched) {
            try self.commitTransaction();
            return;
        }
        if (status != .pending and status != .uncertain) return error.StaleActionTarget;
        var update = try self.statement("UPDATE action_targets SET status=2,dispatch_us=?3,settled_us=NULL WHERE action_id=?1 AND kind=?2 AND status IN(1,5);");
        defer update.deinit();
        try update.blob(1, &action_id);
        try update.int(2, @intFromEnum(kind));
        try update.int(3, now);
        try update.done();
        if (self.api.changes(self.db) != 1) return error.StaleActionTarget;
        try self.fault(.before_action_target_dispatch_commit);
        _ = try self.commitEffectClock(clock);
        try self.commitTransaction();
    }

    pub fn settleActionTarget(self: *Store, action_id: [32]u8, kind: action_outcome.Kind, settlement: action_outcome.Settlement, clock: effects.Clock) Error!void {
        try self.beginWrite();
        errdefer self.rollback();
        if (self.schema_version < 21) return error.ActionTargetStorageRequired;
        var targets: [action_outcome.max_targets_per_action]action_outcome.Target = undefined;
        const count = try self.readActionTargetsTx(action_id, &targets);
        var selected: ?action_outcome.Target = null;
        for (targets[0..count]) |target| {
            if (target.kind == kind) selected = target;
        }
        const target = selected orelse return error.StaleActionTarget;
        const wanted: action_outcome.Status = switch (settlement) {
            .confirmed => .confirmed,
            .failed => .failed,
            .uncertain => .uncertain,
        };
        if (target.status == wanted) {
            try self.commitTransaction();
            return;
        }
        if (target.status != .dispatched) return error.StaleActionTarget;
        if (kind == .enforcement and settlement == .confirmed) {
            var proof = try self.statement("SELECT count(*) FROM confirmed_effect_events WHERE scope_key=?1 AND jail=?2 AND decision_id=?3;");
            defer proof.deinit();
            try proof.blob(1, &target.scope_key);
            try proof.text(2, target.jail.slice());
            try proof.blob(3, &action_id);
            if (!try proof.row() or try proof.signed(0) != 1 or try proof.row()) return error.ActionTargetProofRequired;
        }
        const now = try self.effectClock(clock);
        var update = try self.statement("UPDATE action_targets SET status=?3,settled_us=?4 WHERE action_id=?1 AND kind=?2 AND status=2;");
        defer update.deinit();
        try update.blob(1, &action_id);
        try update.int(2, @intFromEnum(kind));
        try update.int(3, @intFromEnum(wanted));
        try update.int(4, now);
        try update.done();
        if (self.api.changes(self.db) != 1) return error.StaleActionTarget;
        try self.fault(.before_action_target_settlement_commit);
        _ = try self.commitEffectClock(clock);
        try self.commitTransaction();
    }

    pub fn applicationHistoryPage(self: *Store, allocator: std.mem.Allocator, installation: effects.Installation, query: application_history.EventQuery, output: []application_history.Event) Error!application_history.EventPage {
        try query.validate();
        if (output.len == 0 or output.len > application_history.max_page or self.schema_version < 17) return error.InvalidApplicationHistoryQuery;
        try self.beginRead();
        errdefer self.rollback();
        const head = try self.historyHead(installation, query.after_sequence);
        if (query.expected_stream_revision) |expected| if (expected != head.stream_revision) return error.StaleHistoryPage;
        var row = try self.statement(if (self.schema_version >= 19)
            "SELECT s.sequence,e.event_id,e.scope_key,n.canonical_scope,e.jail,e.decision_id,e.confirmed_us,d.source,d.occurrence,d.decided_us,d.ordinal,d.evidence FROM confirmed_history_sequence s JOIN confirmed_effect_events e ON e.event_id=s.event_id JOIN native_effects n ON n.scope_key=e.scope_key LEFT JOIN confirmed_event_details d ON d.event_id=e.event_id WHERE s.sequence>?1 AND s.sequence<=?2 AND (?3 IS NULL OR e.jail=?3) AND (?4 IS NULL OR e.confirmed_us>=?4) AND (?5 IS NULL OR e.confirmed_us<?5) ORDER BY s.sequence LIMIT ?6;"
        else
            "SELECT s.sequence,e.event_id,e.scope_key,n.scope,e.jail,e.decision_id,e.confirmed_us,d.source,d.occurrence,d.decided_us,d.ordinal,d.evidence FROM confirmed_history_sequence s JOIN confirmed_effect_events e ON e.event_id=s.event_id JOIN native_effects n ON n.scope_key=e.scope_key LEFT JOIN confirmed_event_details d ON d.event_id=e.event_id WHERE s.sequence>?1 AND s.sequence<=?2 AND (?3 IS NULL OR e.jail=?3) AND (?4 IS NULL OR e.confirmed_us>=?4) AND (?5 IS NULL OR e.confirmed_us<?5) ORDER BY s.sequence LIMIT ?6;");
        defer row.deinit();
        try row.int(1, @intCast(query.after_sequence));
        try row.int(2, @intCast(head.head_sequence));
        if (query.jail) |jail| try row.text(3, jail) else try self.check(self.api.bind_null(row.ptr, 3));
        if (query.range.from_us) |stamp| try row.int(4, stamp) else try self.check(self.api.bind_null(row.ptr, 4));
        if (query.range.to_us) |stamp| try row.int(5, stamp) else try self.check(self.api.bind_null(row.ptr, 5));
        try row.int(6, @intCast(output.len + 1));
        var count: usize = 0;
        var more = false;
        var last = query.after_sequence;
        errdefer for (output[0..count]) |*event| event.deinit(allocator);
        while (try row.row()) {
            if (count == output.len) {
                more = true;
                break;
            }
            const sequence = try row.signed(0);
            if (sequence <= 0 or sequence <= last or sequence > head.head_sequence) return error.InvalidApplicationHistoryRow;
            const confirmed = effect_history.Event{ .sequence = @intCast(sequence), .event_id = try effectBlob(&row, 1, 32), .installation = installation, .scope_key = try effectBlob(&row, 2, 32), .scope = try self.decodeStoredScope(&row, 3), .jail = detection.Name.init(try row.boundedBytes(4, 64)) catch return error.InvalidApplicationHistoryRow, .decision_id = try effectBlob(&row, 5, 32), .confirmed_us = try row.signed(6) };
            confirmed.validate() catch return error.InvalidApplicationHistoryRow;
            output[count] = .{ .confirmed = confirmed };
            if (self.api.column_type(row.ptr, 7) == 5) {
                for (8..12) |column| if (self.api.column_type(row.ptr, @intCast(column)) != 5) return error.InvalidApplicationHistoryRow;
            } else {
                if (self.api.column_type(row.ptr, 7) != 3 or self.api.column_type(row.ptr, 8) != 3) return error.InvalidApplicationHistoryRow;
                const source = try row.boundedBytes(7, Limits.source_bytes);
                const occurrence = try row.boundedBytes(8, Limits.source_bytes);
                const decided = try row.signed(9);
                const ordinal = try row.signed(10);
                if (source.len == 0 or occurrence.len == 0 or decided > confirmed.confirmed_us or ordinal <= 0) return error.InvalidApplicationHistoryRow;
                const source_copy = allocator.dupe(u8, source) catch return error.OutOfMemory;
                errdefer allocator.free(source_copy);
                const occurrence_copy = allocator.dupe(u8, occurrence) catch return error.OutOfMemory;
                errdefer allocator.free(occurrence_copy);
                var evidence_copy: ?[]u8 = null;
                if (self.api.column_type(row.ptr, 11) != 5) {
                    if (self.api.column_type(row.ptr, 11) != 3) return error.InvalidApplicationHistoryRow;
                    const evidence = try row.boundedBytes(11, retry.max_evidence_text_bytes);
                    if (evidence.len == 0 or !std.unicode.utf8ValidateSlice(evidence)) return error.InvalidApplicationHistoryRow;
                    evidence_copy = allocator.dupe(u8, evidence) catch return error.OutOfMemory;
                }
                output[count].detail = .{ .source = source_copy, .occurrence = occurrence_copy, .decided_us = decided, .ordinal = @intCast(ordinal), .evidence = evidence_copy };
            }
            count += 1;
            last = @intCast(sequence);
        }
        try self.commitTransaction();
        return .{ .stream_revision = head.stream_revision, .head_sequence = head.head_sequence, .last_sequence = last, .count = count, .more = more };
    }

    pub fn applicationHistoryAggregates(self: *Store, installation: effects.Installation, query: application_history.AggregateQuery, output: []application_history.Aggregate) Error!application_history.AggregatePage {
        try query.validate();
        if (output.len == 0 or output.len > application_history.max_page + 1 or self.schema_version < 17) return error.InvalidApplicationHistoryQuery;
        try self.beginRead();
        errdefer self.rollback();
        const head = try self.historyHead(installation, 0);
        if (query.expected_stream_revision) |expected| if (expected != head.stream_revision) return error.StaleHistoryPage;
        const predicate = " FROM confirmed_effect_events WHERE (?1 IS NULL OR jail=?1) AND (?2 IS NULL OR confirmed_us>=?2) AND (?3 IS NULL OR confirmed_us<?3)";
        var overall = try self.statement("SELECT count(*),min(confirmed_us),max(confirmed_us)" ++ predicate ++ ";");
        defer overall.deinit();
        if (query.jail) |jail| try overall.text(1, jail) else try self.check(self.api.bind_null(overall.ptr, 1));
        if (query.range.from_us) |stamp| try overall.int(2, stamp) else try self.check(self.api.bind_null(overall.ptr, 2));
        if (query.range.to_us) |stamp| try overall.int(3, stamp) else try self.check(self.api.bind_null(overall.ptr, 3));
        if (!try overall.row()) return error.InvalidApplicationHistoryRow;
        const total = try overall.signed(0);
        if (total < 0) return error.InvalidApplicationHistoryRow;
        output[0] = .{ .jail = null, .confirmed = @intCast(total), .first_confirmed_us = try overall.optionalSigned(1), .latest_confirmed_us = try overall.optionalSigned(2) };
        if ((total == 0) != (output[0].first_confirmed_us == null and output[0].latest_confirmed_us == null)) return error.InvalidApplicationHistoryRow;

        var groups = try self.statement("SELECT jail,count(*),min(confirmed_us),max(confirmed_us)" ++ predicate ++ " GROUP BY jail ORDER BY jail LIMIT ?4;");
        defer groups.deinit();
        if (query.jail) |jail| try groups.text(1, jail) else try self.check(self.api.bind_null(groups.ptr, 1));
        if (query.range.from_us) |stamp| try groups.int(2, stamp) else try self.check(self.api.bind_null(groups.ptr, 2));
        if (query.range.to_us) |stamp| try groups.int(3, stamp) else try self.check(self.api.bind_null(groups.ptr, 3));
        try groups.int(4, @intCast(output.len));
        var count: usize = 1;
        var more = false;
        while (try groups.row()) {
            if (count == output.len) {
                more = true;
                break;
            }
            const group_count = try groups.signed(1);
            if (self.api.column_type(groups.ptr, 0) != 3 or group_count <= 0) return error.InvalidApplicationHistoryRow;
            output[count] = .{ .jail = detection.Name.init(try groups.boundedBytes(0, 64)) catch return error.InvalidApplicationHistoryRow, .confirmed = @intCast(group_count), .first_confirmed_us = try groups.optionalSigned(2), .latest_confirmed_us = try groups.optionalSigned(3) };
            if (output[count].first_confirmed_us == null or output[count].latest_confirmed_us == null) return error.InvalidApplicationHistoryRow;
            count += 1;
        }
        try self.commitTransaction();
        return .{ .stream_revision = head.stream_revision, .head_sequence = head.head_sequence, .count = count, .more = more };
    }
    fn validateConfirmedEffectPageTx(self: *Store, token: effect_history.PageToken) Error!void {
        try token.validate();
        const installation = try self.readInstallation() orelse return error.InstallationRequired;
        const current = try self.historyHead(installation, token.after_sequence);
        if (!std.mem.eql(u8, &current.installation, &token.installation)) return error.InstallationMismatch;
        if (current.stream_revision != token.stream_revision or current.head_sequence != token.head_sequence or current.retained_from_sequence != token.retained_from_sequence) return error.StaleHistoryPage;
        var events: [effect_history.max_page]effect_history.Event = undefined;
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
    pub const HistoryRetention = struct {
        age_us: i64 = 86_400 * 1_000_000,
        max_matches: u16 = 10,

        pub fn validate(self: HistoryRetention) Error!void {
            if (self.age_us < 0 or @mod(self.age_us, 1_000_000) != 0 or self.max_matches > 1024) return error.InvalidApplicationHistoryQuery;
        }
    };

    pub fn cleanupConfirmedHistoryOne(self: *Store, policy: HistoryRetention, now_us: i64) Error!bool {
        try policy.validate();
        try self.beginWrite();
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 18) return error.MaintenanceStorageRequired;
        if (schema > latest_schema) return error.UnsupportedSchema;
        var checkpoint_row = try self.statement("SELECT payload FROM consumer_checkpoints WHERE kind=5 AND jail='@history' AND source='confirmed-effects' AND rule='checkpoint';");
        defer checkpoint_row.deinit();
        if (!try checkpoint_row.row()) {
            try self.commitTransaction();
            return false;
        }
        const history_checkpoint = effect_history.Checkpoint.decode(try checkpoint_row.boundedBytes(0, effect_history.checkpoint_bytes)) catch return error.InvalidHistoryCheckpoint;
        if (try checkpoint_row.row()) return error.InvalidHistoryCheckpoint;
        const installation = try self.readInstallation() orelse return error.InstallationRequired;
        if (!std.mem.eql(u8, &history_checkpoint.installation, &installation.id)) return error.InvalidHistoryCheckpoint;
        const cutoff = std.math.sub(i64, now_us, policy.age_us) catch std.math.minInt(i64);
        var detail_candidate = try self.statement(
            "SELECT d.event_id FROM confirmed_event_details d JOIN confirmed_effect_events e USING(event_id) JOIN confirmed_history_sequence s USING(event_id) LEFT JOIN retry_decision_details r ON r.jail=e.jail AND r.effect_decision_id=e.decision_id WHERE s.sequence<=?1 AND (e.confirmed_us<=?2 OR (r.effect_decision_id IS NOT NULL AND ((SELECT count(*) FROM confirmed_event_details d2 JOIN confirmed_effect_events e2 USING(event_id) JOIN retry_decision_details r2 ON r2.jail=e2.jail AND r2.effect_decision_id=e2.decision_id WHERE r2.family=r.family AND r2.subject=r.subject)>?3 OR (d.evidence IS NOT NULL AND (SELECT coalesce(sum(length(CAST(d3.evidence AS BLOB))),0) FROM confirmed_event_details d3 JOIN confirmed_effect_events e3 USING(event_id) JOIN retry_decision_details r3 ON r3.jail=e3.jail AND r3.effect_decision_id=e3.decision_id WHERE r3.family=r.family AND r3.subject=r.subject)>16384)))) ORDER BY s.sequence LIMIT 1;",
        );
        defer detail_candidate.deinit();
        try detail_candidate.int(1, std.math.cast(i64, history_checkpoint.last_sequence) orelse return error.InvalidHistoryCheckpoint);
        try detail_candidate.int(2, cutoff);
        try detail_candidate.int(3, policy.max_matches);
        if (try detail_candidate.row()) {
            const detail_event = try effectBlob(&detail_candidate, 0, 32);
            var prune_detail = try self.statement("DELETE FROM confirmed_event_details WHERE event_id=?1;");
            defer prune_detail.deinit();
            try prune_detail.blob(1, &detail_event);
            try prune_detail.done();
            if (self.api.changes(self.db) != 1) return error.HistoryGap;
            try self.fault(.after_history_detail_delete);
            try self.commitTransaction();
            return true;
        }
        var candidate = try self.statement("SELECT s.sequence,e.event_id,e.scope_key,e.jail,e.decision_id,e.confirmed_us FROM confirmed_history_sequence s JOIN confirmed_effect_events e USING(event_id) WHERE s.sequence=(SELECT retained_from FROM confirmed_history_stream WHERE id=1);");
        defer candidate.deinit();
        if (!try candidate.row()) {
            try self.commitTransaction();
            return false;
        }
        const sequence_value = try candidate.signed(0);
        const confirmed_us = try candidate.signed(5);
        if (sequence_value <= 0 or @as(u64, @intCast(sequence_value)) > history_checkpoint.last_sequence) {
            try self.commitTransaction();
            return false;
        }
        if (confirmed_us > cutoff) {
            try self.commitTransaction();
            return false;
        }
        const event_id = try effectBlob(&candidate, 1, 32);
        const scope_key = try effectBlob(&candidate, 2, 32);
        if (self.api.column_type(candidate.ptr, 3) != 3) return error.InvalidHistoryEvent;
        const jail = try candidate.boundedBytes(3, 64);
        const decision_id = try effectBlob(&candidate, 4, 32);
        var owner = try self.statement("SELECT lease_kind,deadline_us FROM effect_owners WHERE scope_key=?1 AND jail=?2 AND decision_id=?3;");
        defer owner.deinit();
        try owner.blob(1, &scope_key);
        try owner.text(2, jail);
        try owner.blob(3, &decision_id);
        if (try owner.row()) {
            const lease = try effectLease(&owner, 0, 1);
            if (lease.live(now_us)) {
                try self.commitTransaction();
                return false;
            }
        }
        var pending = try self.statement("SELECT 1 FROM effect_intents WHERE scope_key=?1 AND status IN(1,2) LIMIT 1;");
        defer pending.deinit();
        try pending.blob(1, &scope_key);
        if (try pending.row()) {
            try self.commitTransaction();
            return false;
        }
        var detail = try self.statement("DELETE FROM confirmed_event_details WHERE event_id=?1;");
        defer detail.deinit();
        try detail.blob(1, &event_id);
        try detail.done();
        try self.fault(.after_history_detail_delete);
        var sequence = try self.statement("DELETE FROM confirmed_history_sequence WHERE sequence=?1 AND event_id=?2;");
        defer sequence.deinit();
        try sequence.int(1, sequence_value);
        try sequence.blob(2, &event_id);
        try sequence.done();
        if (self.api.changes(self.db) != 1) return error.HistoryGap;
        var event = try self.statement("DELETE FROM confirmed_effect_events WHERE event_id=?1;");
        defer event.deinit();
        try event.blob(1, &event_id);
        try event.done();
        if (self.api.changes(self.db) != 1) return error.HistoryGap;
        try self.fault(.after_history_event_delete);
        var stream = try self.statement("UPDATE confirmed_history_stream SET retained_from=?1,revision=revision+1 WHERE id=1 AND retained_from=?2;");
        defer stream.deinit();
        try stream.int(1, sequence_value + 1);
        try stream.int(2, sequence_value);
        try stream.done();
        if (self.api.changes(self.db) != 1) return error.HistoryGap;
        try self.commitTransaction();
        return true;
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
    fn decodeStoredScope(self: *Store, row: *Stmt, column: c_int) Error!effects.Scope {
        if (self.api.column_type(row.ptr, column) != 4) return error.InvalidEffect;
        const bytes = try row.boundedBytes(column, effects.Scope.canonical_encoded_bytes);
        return if (self.schema_version >= 19)
            effects.Scope.decodeCanonical(bytes)
        else
            effects.Scope.decode(bytes);
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
        const scope = try self.decodeStoredScope(row, 1);
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
    fn readEffect(self: *Store, key: effects.Hash, installation: effects.Installation) Error!?effects.Entry {
        var row = try self.statement(if (self.schema_version >= 19)
            "SELECT e.scope_key,e.canonical_scope,e.revision,e.lease_kind,e.deadline_us,e.intent_id,i.status,i.decision_id,i.revision,i.lease_kind,i.deadline_us,i.created_us,i.dispatch_us,i.observed_us,i.fingerprint FROM native_effects e LEFT JOIN effect_intents i ON i.intent_id=e.intent_id WHERE e.scope_key=?1;"
        else
            "SELECT e.scope_key,e.scope,e.revision,e.lease_kind,e.deadline_us,e.intent_id,i.status,i.decision_id,i.revision,i.lease_kind,i.deadline_us,i.created_us,i.dispatch_us,i.observed_us,i.fingerprint FROM native_effects e LEFT JOIN effect_intents i ON i.intent_id=e.intent_id WHERE e.scope_key=?1;");
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
        var row = try self.statement(if (self.schema_version >= 19)
            "SELECT e.scope_key,e.canonical_scope,e.revision,e.lease_kind,e.deadline_us,e.intent_id,i.status,i.decision_id,i.revision,i.lease_kind,i.deadline_us,i.created_us,i.dispatch_us,i.observed_us,i.fingerprint FROM native_effects e LEFT JOIN effect_intents i ON i.intent_id=e.intent_id WHERE (?1 IS NULL OR e.scope_key>?1) ORDER BY e.scope_key LIMIT ?2;"
        else
            "SELECT e.scope_key,e.scope,e.revision,e.lease_kind,e.deadline_us,e.intent_id,i.status,i.decision_id,i.revision,i.lease_kind,i.deadline_us,i.created_us,i.dispatch_us,i.observed_us,i.fingerprint FROM native_effects e LEFT JOIN effect_intents i ON i.intent_id=e.intent_id WHERE (?1 IS NULL OR e.scope_key>?1) ORDER BY e.scope_key LIMIT ?2;");
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

    pub const OperatorOwner = struct {
        jail: detection.Name,
        scope: effects.Scope,
        lease: effects.Lease,
        decision_id: effects.Hash,
        ordinal: u64,
    };
    pub fn operatorOwners(self: *Store, now_us: i64, output: []OperatorOwner) Error!usize {
        if (output.len == 0 or output.len > effects.max_owners) return error.EffectCapacity;
        try self.beginRead();
        errdefer self.rollback();
        const installation = try self.readInstallation() orelse return error.InstallationRequired;
        if (self.schema_version < 19) return error.EffectStorageRequired;
        const floor = try self.readAdmissionClock(self.schema_version);
        if (floor) |value| if (now_us < value.us) return error.EffectClockReversed;
        var row = try self.statement(
            "SELECT o.scope_key,n.canonical_scope,o.jail,o.decision_id,o.lease_kind,o.deadline_us,o.decided_us,d.ordinal," ++
                "EXISTS(SELECT 1 FROM effect_owner_revisions h WHERE h.scope_key=o.scope_key AND h.jail=o.jail AND h.revision=o.revision AND h.generation=o.generation AND h.decision_id=o.decision_id AND h.lease_kind=o.lease_kind AND h.deadline_us IS o.deadline_us AND h.decided_us=o.decided_us) " ++
                "FROM effect_owners o JOIN native_effects n USING(scope_key) LEFT JOIN retry_decision_details d ON d.jail=o.jail AND d.effect_decision_id=o.decision_id " ++
                "WHERE o.lease_kind=2 OR (o.lease_kind=1 AND o.deadline_us>?1) ORDER BY o.jail,o.scope_key LIMIT ?2;",
        );
        defer row.deinit();
        try row.int(1, now_us);
        try row.int(2, @intCast(output.len + 1));
        var count: usize = 0;
        while (try row.row()) {
            if (count == output.len) return error.EffectCapacity;
            const key = try effectBlob(&row, 0, 32);
            const scope = try self.decodeStoredScope(&row, 1);
            if (!std.mem.eql(u8, &key, &try scope.key(installation))) return error.InvalidEffect;
            if (self.api.column_type(row.ptr, 2) != 3 or try row.signed(8) != 1) return error.InvalidEffect;
            const lease = try effectLease(&row, 4, 5);
            const decided_us = try row.signed(6);
            if (!lease.live(now_us) or decided_us > (if (floor) |value| value.us else return error.InvalidEffect)) return error.InvalidEffect;
            const stored_ordinal = try row.optionalSigned(7);
            if (stored_ordinal) |ordinal| if (ordinal <= 0) return error.InvalidEffect;
            output[count] = .{
                .jail = detection.Name.init(try row.boundedBytes(2, 64)) catch return error.InvalidEffect,
                .scope = scope,
                .lease = lease,
                .decision_id = try effectBlob(&row, 3, 32),
                .ordinal = if (stored_ordinal) |ordinal| @intCast(ordinal) else 1,
            };
            count += 1;
        }
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
        if (self.schema_version < 19) _ = try change.scope.encode();
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
            const legacy_wire = change.scope.encode() catch [_]u8{0} ** effects.Scope.encoded_bytes;
            const canonical_wire = try change.scope.encodeCanonical();
            var row = try self.statement(if (self.schema_version >= 19)
                "INSERT INTO native_effects(scope_key,scope,revision,lease_kind,canonical_scope) VALUES(?1,?2,0,0,?3);"
            else
                "INSERT INTO native_effects(scope_key,scope,revision,lease_kind) VALUES(?1,?2,0,0);");
            defer row.deinit();
            try row.blob(1, &key);
            try row.blob(2, &legacy_wire);
            if (self.schema_version >= 19) try row.blob(3, &canonical_wire);
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
        const prior_revision = try self.integer("SELECT revision FROM effect_clock WHERE singleton=1;");
        const entry = try self.setOwnerTx(change, now);
        const changed = prior_revision != try self.integer("SELECT revision FROM effect_clock WHERE singleton=1;");
        const final = try self.commitEffectClock(clock);
        if (change.lease == .finite and !change.lease.live(final)) return error.EffectExpired;
        if (entry.desired == .finite and !entry.desired.live(final)) return error.EffectExpired;
        try self.commitEffectTransaction(changed);
        return entry;
    }
    pub fn setOwnerFromCanonical(self: *Store, change: effects.CanonicalOwnerChange, clock: effects.Clock) Error!effects.Entry {
        change.scope.validate() catch return error.InvalidEffect;
        const projected = if (self.schema_version >= 19) try change.exact() else try change.legacy();
        return self.setOwner(projected, clock);
    }
    const OwnerTransitionTx = struct { entry: effects.Entry, changed: bool };
    fn transitionOwnerTx(self: *Store, change: effects.OwnerTransition, now: i64) Error!OwnerTransitionTx {
        change.scope.validate() catch return error.InvalidEffect;
        _ = detection.Name.init(change.jail) catch return error.InvalidEffect;
        if (change.expected_owner_revision == 0 or change.expected_owner_revision >= std.math.maxInt(i64) or change.occurred_us > now or std.mem.allEqual(u8, &change.transition_id, 0)) return error.InvalidEffect;
        if (change.mode == .retain and std.mem.eql(u8, &change.current_generation, &change.next_generation)) return error.InvalidEffect;
        const installation = try self.readInstallation() orelse return error.InstallationRequired;
        const scope = try effects.Scope.exact(change.scope);
        const key = try scope.key(installation);
        const prior = try self.readEffect(key, installation) orelse return error.StaleEffect;
        if (prior.status == .dispatched) return error.EffectReconciliationRequired;
        var owners: [effects.max_page]effects.Owner = undefined;
        const count = try self.readOwners(key, &owners);
        var selected: ?effects.Owner = null;
        for (owners[0..count]) |owner| if (std.mem.eql(u8, owner.jail.slice(), change.jail)) {
            if (selected != null) return error.InvalidEffect;
            selected = owner;
        };
        const owner = selected orelse return error.StaleEffect;
        if (owner.revision == change.expected_owner_revision + 1 and std.mem.eql(u8, &owner.generation, &change.next_generation)) {
            const wanted_lease: effects.Lease = if (change.mode == .release) .absent else owner.lease;
            const replay_id = effects.intentId(installation.id, key, change.transition_id, prior.revision, prior.desired);
            if (effects.Lease.eql(owner.lease, wanted_lease) and std.mem.eql(u8, &prior.intent_id, &replay_id)) return .{ .entry = prior, .changed = false };
        }
        if (owner.revision != change.expected_owner_revision) return error.StaleEffect;
        if (!std.mem.eql(u8, &owner.generation, &change.current_generation)) return error.EffectGenerationMismatch;
        if (owner.lease == .absent) return error.StaleEffect;
        if (try self.integer("SELECT count(*) FROM effect_owner_revisions;") >= effects.max_owner_revisions) return error.EffectCapacity;
        const effect_revision = std.math.add(u64, prior.revision, 1) catch return error.EffectCapacity;
        if (effect_revision > std.math.maxInt(i64)) return error.EffectCapacity;
        {
            var update = try self.statement("UPDATE effect_owners SET generation=?4,revision=?5,lease_kind=?6,deadline_us=?7 WHERE scope_key=?1 AND jail=?2 AND revision=?3;");
            defer update.deinit();
            try update.blob(1, &key);
            try update.text(2, change.jail);
            try update.int(3, @intCast(owner.revision));
            try update.blob(4, &change.next_generation);
            try update.int(5, @intCast(owner.revision + 1));
            try bindEffectLease(&update, 6, if (change.mode == .release) .absent else owner.lease);
            try update.done();
            if (self.api.changes(self.db) != 1) return error.StaleEffect;
        }
        try self.fault(.after_effect_owner);
        return .{ .entry = try self.replaceEffectIntent(installation, scope, key, effect_revision, change.transition_id, now), .changed = true };
    }
    pub fn transitionOwner(self: *Store, change: effects.OwnerTransition, clock: effects.Clock) Error!effects.Entry {
        try self.beginWrite();
        errdefer self.rollback();
        try self.effectSchema();
        if (self.schema_version < 19) return error.EffectStorageRequired;
        const now = try self.effectClock(clock);
        const result = try self.transitionOwnerTx(change, now);
        _ = try self.commitEffectClock(clock);
        try self.commitEffectTransaction(result.changed);
        return result.entry;
    }
    pub fn flushJailOwner(self: *Store, jail: []const u8, generation: effects.Hash, transition_id: effects.Hash, clock: effects.Clock) Error!?effects.Entry {
        _ = detection.Name.init(jail) catch return error.InvalidEffect;
        if (std.mem.allEqual(u8, &transition_id, 0)) return error.InvalidEffect;
        try self.beginWrite();
        errdefer self.rollback();
        try self.effectSchema();
        if (self.schema_version < 19) return error.EffectStorageRequired;
        const now = try self.effectClock(clock);
        var row = try self.statement("SELECT n.canonical_scope,o.revision FROM effect_owners o JOIN native_effects n USING(scope_key) WHERE o.jail=?1 AND o.generation=?2 AND o.lease_kind!=0 ORDER BY o.scope_key LIMIT 1;");
        defer row.deinit();
        try row.text(1, jail);
        try row.blob(2, &generation);
        if (!try row.row()) {
            _ = try self.commitEffectClock(clock);
            try self.commitTransaction();
            return null;
        }
        const scope = (try effects.Scope.decodeCanonical(&try effectBlob(&row, 0, effects.Scope.canonical_encoded_bytes))).canonical;
        const owner_revision_value = try row.signed(1);
        if (owner_revision_value <= 0 or try row.row()) return error.InvalidEffect;
        const result = try self.transitionOwnerTx(.{ .scope = scope, .jail = jail, .current_generation = generation, .next_generation = generation, .expected_owner_revision = @intCast(owner_revision_value), .transition_id = transition_id, .mode = .release, .occurred_us = now }, now);
        _ = try self.commitEffectClock(clock);
        try self.commitEffectTransaction(result.changed);
        return result.entry;
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
        try self.commitEffectTransaction(true);
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
                if (self.schema_version >= 17) {
                    var detail_inserted = false;
                    var detail = try self.statement("INSERT INTO confirmed_event_details(event_id,source,occurrence,decided_us,ordinal,evidence) SELECT ?1,source,occurrence,decided_us,ordinal,evidence FROM retry_decision_details WHERE jail=?2 AND effect_decision_id=?3;");
                    defer detail.deinit();
                    try detail.blob(1, &event_id);
                    try detail.text(2, owner.jail.slice());
                    try detail.blob(3, &owner.decision_id);
                    try detail.done();
                    if (self.api.changes(self.db) > 1) return error.InvalidApplicationHistoryRow;
                    detail_inserted = self.api.changes(self.db) == 1;
                    if (self.schema_version >= 18 and detail_inserted) {
                        var summary = try self.statement("INSERT INTO confirmed_policy_summaries(jail,family,subject,confirmed_count,latest_confirmed_us) SELECT jail,family,subject,1,?3 FROM retry_decision_details WHERE jail=?1 AND effect_decision_id=?2 ON CONFLICT(jail,family,subject) DO UPDATE SET confirmed_count=confirmed_count+1,latest_confirmed_us=max(latest_confirmed_us,excluded.latest_confirmed_us);");
                        defer summary.deinit();
                        try summary.text(1, owner.jail.slice());
                        try summary.blob(2, &owner.decision_id);
                        try summary.int(3, observation.observed_us);
                        try summary.done();
                        if (self.api.changes(self.db) != 1) return error.InvalidRetryState;
                    }
                }
                if (self.schema_version >= 13) {
                    var sequenced = try self.statement("SELECT s.event_id FROM confirmed_history_stream h JOIN confirmed_history_sequence s ON s.sequence=h.head WHERE h.id=1;");
                    defer sequenced.deinit();
                    if (!try sequenced.row() or !std.mem.eql(u8, &try effectBlob(&sequenced, 0, 32), &event_id)) return error.HistoryGap;
                }
            };
        }
        try self.advanceEffectSnapshot();
        try self.fault(.before_effect_receipt_commit);
        const final = try self.commitEffectClock(clock);
        if (status == .applied and entry.desired == .finite and !entry.desired.live(final)) return error.EffectExpired;
        try self.commitEffectTransaction(true);
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
            entry = try self.replaceEffectIntent(installation, prior.scope, key, effect_revision, prior.intent_id, now);
        }
        _ = try self.commitEffectClock(clock);
        try self.commitEffectTransaction(expired != 0);
        return entry;
    }
    pub fn confirmedEffectEvents(self: *Store) Error!u64 {
        const count = try self.integer("SELECT count(*) FROM confirmed_effect_events;");
        return std.math.cast(u64, count) orelse error.InvalidEffect;
    }
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
        var old = try self.statement("SELECT 1 FROM records WHERE jail=?1 AND source=?2 UNION ALL SELECT 1 FROM pending_receipts WHERE jail=?1 AND source=?2 LIMIT 1;");
        defer old.deinit();
        try old.text(1, manifest.jail);
        try old.text(2, manifest.source);
        if (try old.row()) return error.ConsumerMigrationRequired;
        for (manifest.required) |requirement| {
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
    pub fn commitConsumerInput(self: *Store, manifest: consumers.Manifest, batch: consumers.Batch) Error!void {
        try self.consumerInput(manifest, batch, false);
    }
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
    fn bindConsumerKey(row: *Stmt, key: *const consumers.Key) Error!void {
        try key.validate();
        try row.int(1, @intFromEnum(key.kind));
        try row.text(2, key.jail);
        try row.text(3, key.source);
        try row.text(4, key.rule);
        try row.blob(5, &key.generation);
    }
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
            if (self.schema_version >= 18) {
                const escalation = try policy.escalation.encode();
                var escalation_insert = try self.statement("INSERT INTO retry_escalation_policies VALUES(?1,?2,?3);");
                defer escalation_insert.deinit();
                try escalation_insert.text(1, jail);
                try escalation_insert.blob(2, &generation);
                try escalation_insert.blob(3, &escalation);
                try escalation_insert.done();
            }
        }
        try self.commitTransaction();
    }

    fn checkRetryAdmission(self: *Store, jail: []const u8, generation: [32]u8, policy: retry.Policy) Error!bool {
        if (jail.len == 0 or jail.len > 64 or std.mem.indexOfScalar(u8, jail, 0) != null) return error.InvalidRecord;
        _ = try policy.encode();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 9 or schema > latest_schema) return error.RetryStorageRequired;
        if (schema < 16 and policy.duration == .permanent) return error.RetryStorageRequired;
        if (schema < 18 and policy.escalation.enabled) return error.RetryStorageRequired;
        if (try self.readRetryPolicy(jail)) |saved| {
            if (!std.mem.eql(u8, &saved.generation, &generation) or !try retryPoliciesEqual(saved.policy, policy)) return error.RetryGenerationMismatch;
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
        var row = try self.statement(if (self.schema_version >= 18)
            "SELECT p.generation,p.policy,e.generation,e.policy FROM retry_policies p JOIN retry_escalation_policies e USING(jail) WHERE p.jail=?1;"
        else
            "SELECT generation,policy FROM retry_policies WHERE jail=?1;");
        defer row.deinit();
        try row.text(1, jail);
        if (!try row.row()) return null;
        if (self.api.column_type(row.ptr, 0) != 4 or self.api.column_type(row.ptr, 1) != 4) return error.InvalidRetryState;
        const generation = try row.boundedBytes(0, 32);
        if (generation.len != 32) return error.InvalidRetryState;
        const raw = try row.boundedBytes(1, retry.policy_bytes);
        if (self.schema_version >= 16 and (raw.len != retry.policy_bytes or raw[4] != 2)) return error.InvalidRetryPolicy;
        var result = retry.Admission{ .generation = undefined, .policy = try retry.Policy.decode(raw) };
        @memcpy(&result.generation, generation);
        if (self.schema_version >= 18) {
            if (self.api.column_type(row.ptr, 2) != 4 or self.api.column_type(row.ptr, 3) != 4) return error.InvalidRetryState;
            const escalation_generation = try row.boundedBytes(2, 32);
            const escalation_raw = try row.boundedBytes(3, retry.escalation_bytes);
            if (escalation_generation.len != 32 or !std.mem.eql(u8, generation, escalation_generation)) return error.InvalidRetryState;
            result.policy.escalation = try retry.Escalation.decode(escalation_raw);
            try result.policy.validate();
        }
        return result;
    }

    fn retryPoliciesEqual(left: retry.Policy, right: retry.Policy) Error!bool {
        const left_base = try left.encode();
        const right_base = try right.encode();
        if (!std.mem.eql(u8, &left_base, &right_base)) return false;
        const left_escalation = try left.escalation.encode();
        const right_escalation = try right.escalation.encode();
        return std.mem.eql(u8, &left_escalation, &right_escalation);
    }

    fn bindSubjectAt(row: *Stmt, subject: *const detection.Subject, family_index: c_int) Error!void {
        subject.validate() catch return error.InvalidRetryState;
        if (subject.unenforceable()) return error.InvalidRetryState;
        switch (subject.*) {
            .v4 => {
                try row.int(family_index, 4);
                try row.blob(family_index + 1, &subject.v4);
            },
            .v6 => {
                try row.int(family_index, 6);
                try row.blob(family_index + 1, &subject.v6);
            },
        }
    }
    fn bindSubject(row: *Stmt, subject: *const detection.Subject) Error!void {
        return bindSubjectAt(row, subject, 2);
    }

    fn retryLease(row: *Stmt, kind_col: c_int, deadline_col: c_int) Error!retry.Lease {
        const kind = try row.signed(kind_col);
        const deadline = try row.optionalSigned(deadline_col);
        return switch (kind) {
            0 => if (deadline == null) .absent else error.InvalidRetryState,
            1 => .{ .finite = deadline orelse return error.InvalidRetryState },
            2 => if (deadline == null) .permanent else error.InvalidRetryState,
            else => error.InvalidRetryState,
        };
    }

    fn bindRetryLease(row: *Stmt, index: c_int, lease: retry.Lease) Error!void {
        try row.int(index, @intFromEnum(lease));
        if (lease == .finite) try row.int(index + 1, lease.finite) else try row.store.check(row.store.api.bind_null(row.ptr, index + 1));
    }

    fn readWorkingRetryState(self: *Store, jail: []const u8, subject: detection.Subject, policy: retry.Policy) Error!?retry.State {
        var row = try self.statement(if (self.schema_version >= 16)
            "SELECT last_processed_us,lease_kind,deadline_us,decisions,attempts FROM retry_states WHERE jail=?1 AND family=?2 AND subject=?3;"
        else
            "SELECT last_processed_us,CASE WHEN expiry_us IS NULL THEN 0 ELSE 1 END,expiry_us,decisions,attempts FROM retry_states WHERE jail=?1 AND family=?2 AND subject=?3;");
        defer row.deinit();
        try row.text(1, jail);
        try bindSubject(&row, &subject);
        if (!try row.row()) return null;
        const result = try self.decodeRetryState(&row, policy);
        if (result.last_processed_us > ((try self.readRetryClock()) orelse return error.InvalidRetryState)) return error.InvalidRetryState;
        return result;
    }

    fn readRetryState(self: *Store, jail: []const u8, subject: detection.Subject, policy: retry.Policy) Error!?retry.State {
        const working = try self.readWorkingRetryState(jail, subject, policy);
        const retired = try self.readRetired(jail, subject);
        if (working != null and retired != null) return error.InvalidRetryState;
        return working orelse retired;
    }

    fn decodeRetryState(self: *Store, row: *Stmt, policy: retry.Policy) Error!retry.State {
        const decisions = try row.signed(3);
        if (decisions < 0 or self.api.column_type(row.ptr, 4) != 4) return error.InvalidRetryState;
        var result = retry.State{ .last_processed_us = try row.signed(0), .lease = try retryLease(row, 1, 2), .decisions = @intCast(decisions) };
        try result.decodeAttempts(try row.boundedBytes(4, retry.max_attempts * retry.attempt_bytes), policy);
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

    pub fn retryStateAt(self: *Store, jail: []const u8, subject: detection.Subject, now_us: i64) Error!?retry.State {
        try self.beginRead();
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 9 or schema > latest_schema) return error.RetryStorageRequired;
        const admission = (try self.readRetryPolicy(jail)) orelse return error.RetryAdmissionRequired;
        if (try self.readRetryClock()) |floor| if (now_us < floor) return error.ReceiptClockReversed;
        const working = try self.readWorkingRetryState(jail, subject, admission.policy);
        const retired = try self.readRetired(jail, subject);
        if (working != null and retired != null) return error.InvalidRetryState;
        const result = if (working) |state| (try retry.prune(admission.policy, state, now_us)).state else retired;
        try self.commitTransaction();
        return result;
    }

    pub fn validateRuntimeOwners(self: *Store, names: []const []const u8) !void {
        return self.validateOwners(names, null);
    }
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

    pub fn validateRuntimeOwnerNames(self: *Store, names: []const []const u8) !void {
        if (names.len == 0 or names.len > 64) return error.InvalidRecord;
        try self.beginRead();
        errdefer self.rollback();
        try self.validateOwnerNamesTx(names);
        try self.commitTransaction();
    }
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

    pub const ActiveDecision = struct { subject: detection.Subject, lease: retry.Lease, ordinal: u64 };
    pub const RetrySummary = struct { subjects: usize = 0, active: usize = 0, decisions: u64 = 0 };
    pub fn retrySummary(self: *Store, jail: []const u8, now_us: i64, output: []ActiveDecision) Error!RetrySummary {
        try self.beginRead();
        errdefer self.rollback();
        const admission = (try self.readRetryPolicy(jail)) orelse return error.RetryAdmissionRequired;
        if (output.len < admission.policy.max_subjects) return error.RetryCapacity;
        const floor = try self.readRetryClock();
        if (floor) |value| if (now_us < value) return error.ReceiptClockReversed;
        var row = try self.statement(if (self.schema_version >= 16)
            "SELECT last_processed_us,lease_kind,deadline_us,decisions,attempts,family,subject FROM retry_states WHERE jail=?1 ORDER BY family,subject;"
        else
            "SELECT last_processed_us,CASE WHEN expiry_us IS NULL THEN 0 ELSE 1 END,expiry_us,decisions,attempts,family,subject FROM retry_states WHERE jail=?1 ORDER BY family,subject;");
        defer row.deinit();
        try row.text(1, jail);
        var summary = RetrySummary{};
        while (try row.row()) {
            summary.subjects += 1;
            if (summary.subjects > admission.policy.max_subjects) return error.RetryCapacity;
            const stored = try self.decodeRetryState(&row, admission.policy);
            if (stored.last_processed_us > (floor orelse return error.InvalidRetryState)) return error.InvalidRetryState;
            const state = (try retry.prune(admission.policy, stored, now_us)).state;
            const subject = try self.decodeRetrySubject(&row, 5, 6);
            summary.decisions = std.math.add(u64, summary.decisions, state.decisions) catch return error.InvalidRetryState;
            if (state.lease.live(now_us)) {
                output[summary.active] = .{ .subject = subject, .lease = state.lease, .ordinal = state.decisions };
                summary.active += 1;
            }
        }
        if (self.schema_version >= 15)
            summary.decisions = std.math.add(u64, summary.decisions, try self.retiredTotal(jail)) catch return error.InvalidRetryState;
        try self.commitTransaction();
        return summary;
    }

    pub fn retryPolicySummaryPage(self: *Store, query: application_history.PolicyQuery, output: []application_history.PolicySummary) Error!application_history.PolicyPage {
        try query.validate();
        if (output.len == 0 or output.len > application_history.max_page or self.schema_version < 17) return error.InvalidPolicySummary;
        try self.beginRead();
        errdefer self.rollback();
        const revision_value = try self.integer("SELECT revision FROM policy_summary_clock WHERE id=1;");
        if (revision_value <= 0) return error.InvalidPolicySummary;
        const current_revision: u64 = @intCast(revision_value);
        if (query.expected_revision) |expected| if (expected != current_revision) return error.StalePolicySummary;
        var row = try self.statement("WITH summaries(jail,family,subject,generation,last_processed_us,lease_kind,deadline_us,decisions,retired) AS (SELECT s.jail,s.family,s.subject,p.generation,s.last_processed_us,s.lease_kind,s.deadline_us,s.decisions,0 FROM retry_states s JOIN retry_policies p ON p.jail=s.jail UNION ALL SELECT r.jail,r.family,r.subject,r.generation,r.last_processed_us,0,NULL,r.decisions,1 FROM retry_retired r) SELECT jail,family,subject,generation,last_processed_us,lease_kind,deadline_us,decisions,retired FROM summaries WHERE (?1 IS NULL OR jail=?1) AND (?2 IS NULL OR jail>?2 OR (jail=?2 AND (family>?3 OR (family=?3 AND subject>?4)))) ORDER BY jail,family,subject LIMIT ?5;");
        defer row.deinit();
        if (query.jail) |jail| try row.text(1, jail) else try self.check(self.api.bind_null(row.ptr, 1));
        if (query.after) |after| {
            try row.text(2, after.jail.slice());
            switch (after.subject) {
                .v4 => |address| {
                    try row.int(3, 4);
                    try row.blob(4, &address);
                },
                .v6 => |address| {
                    try row.int(3, 6);
                    try row.blob(4, &address);
                },
            }
        } else {
            try self.check(self.api.bind_null(row.ptr, 2));
            try self.check(self.api.bind_null(row.ptr, 3));
            try self.check(self.api.bind_null(row.ptr, 4));
        }
        try row.int(5, @intCast(output.len + 1));
        var count: usize = 0;
        var more = false;
        while (try row.row()) {
            if (count == output.len) {
                more = true;
                break;
            }
            if (self.api.column_type(row.ptr, 0) != 3) return error.InvalidPolicySummary;
            const jail = detection.Name.init(try row.boundedBytes(0, 64)) catch return error.InvalidPolicySummary;
            const subject = try self.decodeRetrySubject(&row, 1, 2);
            const generation = try effectBlob(&row, 3, 32);
            const decisions = try row.signed(7);
            const retired = try row.signed(8);
            const lease = try retryLease(&row, 5, 6);
            if (decisions < 0 or retired < 0 or retired > 1 or (retired == 1 and lease != .absent)) return error.InvalidPolicySummary;
            if (count > 0 and std.mem.eql(u8, output[count - 1].jail.slice(), jail.slice()) and std.meta.eql(output[count - 1].subject, subject)) return error.InvalidPolicySummary;
            output[count] = .{ .jail = jail, .subject = subject, .generation = generation, .last_processed_us = try row.signed(4), .lease = lease, .decisions = @intCast(decisions), .retired = retired == 1 };
            count += 1;
        }
        try self.commitTransaction();
        return .{ .revision = current_revision, .count = count, .more = more };
    }

    pub fn validateRetry(self: *Store, jail: []const u8, generation: [32]u8, policy: retry.Policy) Error!void {
        try self.beginRead();
        errdefer self.rollback();
        const schema = try self.integer("PRAGMA user_version;");
        if (schema < 9 or schema > latest_schema) return error.RetryStorageRequired;
        const admission = (try self.readRetryPolicy(jail)) orelse return error.RetryAdmissionRequired;
        if (!std.mem.eql(u8, &admission.generation, &generation) or !try retryPoliciesEqual(admission.policy, policy)) return error.RetryGenerationMismatch;
        const floor = try self.readRetryClock();
        var row = try self.statement(if (self.schema_version >= 16)
            "SELECT last_processed_us,lease_kind,deadline_us,decisions,attempts,family,subject FROM retry_states WHERE jail=?1;"
        else
            "SELECT last_processed_us,CASE WHEN expiry_us IS NULL THEN 0 ELSE 1 END,expiry_us,decisions,attempts,family,subject FROM retry_states WHERE jail=?1;");
        defer row.deinit();
        try row.text(1, jail);
        var count: usize = 0;
        while (try row.row()) {
            count += 1;
            if (count > policy.max_subjects) return error.RetryCapacity;
            const state = try self.decodeRetryState(&row, policy);
            if (state.last_processed_us > (floor orelse return error.InvalidRetryState)) return error.InvalidRetryState;
            _ = try self.decodeRetrySubject(&row, 5, 6);
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
        var row = try self.statement(if (self.schema_version >= 16)
            if (occurrence != null)
                "SELECT family,subject,decided_us,lease_kind,deadline_us,ordinal,enforce FROM retry_decisions WHERE jail=?1 AND source=?2 AND occurrence=?3;"
            else
                "SELECT d.family,d.subject,d.decided_us,d.lease_kind,d.deadline_us,d.ordinal,d.enforce FROM retry_decisions d JOIN source_cursors c USING(jail,source,occurrence) WHERE d.jail=?1 AND d.source=?2;"
        else if (occurrence != null)
            "SELECT family,subject,decided_us,1,expiry_us,ordinal,enforce FROM retry_decisions WHERE jail=?1 AND source=?2 AND occurrence=?3;"
        else
            "SELECT d.family,d.subject,d.decided_us,1,d.expiry_us,d.ordinal,d.enforce FROM retry_decisions d JOIN source_cursors c USING(jail,source,occurrence) WHERE d.jail=?1 AND d.source=?2;");
        defer row.deinit();
        try row.text(1, jail);
        try row.text(2, source);
        if (occurrence) |value| try row.text(3, value);
        var count: usize = 0;
        while (try row.row()) {
            if (count >= output.len) return error.ConsumerCapacity;
            const ordinal = try row.signed(5);
            const enforce = try row.signed(6);
            const now = try row.signed(2);
            const lease = try retryLease(&row, 3, 4);
            if (ordinal <= 0 or enforce < 0 or enforce > 1 or lease == .absent or (lease == .finite and lease.finite <= now)) return error.InvalidRetryState;
            output[count] = .{ .subject = try self.decodeRetrySubject(&row, 0, 1), .decided_us = now, .lease = lease, .ordinal = @intCast(ordinal), .enforce = enforce == 1 };
            count += 1;
        }
        return count;
    }

    pub fn retryEscalationDecision(self: *Store, jail: []const u8, source: []const u8, occurrence: []const u8, subject: detection.Subject) Error!?EscalationSelection {
        if (self.schema_version < 18) return error.RetryStorageRequired;
        var row = try self.statement("SELECT scope,prior_confirmed,latest_confirmed_us,chosen_duration_us,jitter_us FROM retry_decision_escalations WHERE jail=?1 AND family=?2 AND subject=?3 AND source=?4 AND occurrence=?5;");
        defer row.deinit();
        try row.text(1, jail);
        try bindSubject(&row, &subject);
        try row.text(4, source);
        try row.text(5, occurrence);
        if (!try row.row()) return null;
        const scope_value = try row.signed(0);
        const prior = try row.signed(1);
        const latest = try row.optionalSigned(2);
        const chosen = try row.signed(3);
        const jitter = try row.signed(4);
        if (prior < 0 or (prior == 0) != (latest == null) or chosen <= 0 or @mod(chosen, 1_000_000) != 0 or jitter < 0 or @mod(jitter, 1_000_000) != 0 or try row.row()) return error.InvalidRetryState;
        return .{
            .scope = std.meta.intToEnum(retry.EscalationScope, scope_value) catch return error.InvalidRetryState,
            .prior_confirmed = @intCast(prior),
            .latest_confirmed_us = latest,
            .chosen_duration_us = chosen,
            .jitter_us = jitter,
        };
    }

    pub const RetryProlongation = struct {
        jail: []const u8,
        generation: [32]u8,
        subject: detection.Subject,
        ordinal: u64,
        expected_owner_revision: u64,
        requested: retry.Lease,
    };
    pub const RetryProlongationResult = struct { changed: bool, lease: retry.Lease, effect: effects.Entry };

    pub fn prolongRetryDecision(self: *Store, change: RetryProlongation, clock: effects.Clock) Error!RetryProlongationResult {
        if (change.ordinal == 0 or change.ordinal > std.math.maxInt(i64) or change.requested == .absent) return error.InvalidRetryState;
        try self.beginWrite();
        errdefer self.rollback();
        try self.effectSchema();
        if (self.schema_version < 16) return error.RetryStorageRequired;
        const now = try self.effectClock(clock);
        if (!change.requested.live(now)) return error.LeaseExpired;
        const admission = (try self.readRetryPolicy(change.jail)) orelse return error.RetryAdmissionRequired;
        if (!std.mem.eql(u8, &admission.generation, &change.generation)) return error.RetryGenerationMismatch;

        var decision_row = try self.statement("SELECT d.source,d.occurrence,d.decided_us,d.lease_kind,d.deadline_us,d.enforce,s.lease_kind,s.deadline_us,s.decisions FROM retry_decisions d JOIN retry_states s ON s.jail=d.jail AND s.family=d.family AND s.subject=d.subject WHERE d.jail=?1 AND d.family=?2 AND d.subject=?3 AND d.ordinal=?4;");
        defer decision_row.deinit();
        try decision_row.text(1, change.jail);
        try bindSubject(&decision_row, &change.subject);
        try decision_row.int(4, @intCast(change.ordinal));
        if (!try decision_row.row() or self.api.column_type(decision_row.ptr, 0) != 3 or self.api.column_type(decision_row.ptr, 1) != 3) return error.InvalidRetryState;
        const source = try decision_row.boundedBytes(0, Limits.source_bytes);
        const occurrence = try decision_row.boundedBytes(1, Limits.source_bytes);
        const decided_us = try decision_row.signed(2);
        const current = try retryLease(&decision_row, 3, 4);
        const enforce = try decision_row.signed(5);
        const state_lease = try retryLease(&decision_row, 6, 7);
        const decisions = try decision_row.signed(8);
        if (enforce != 1 or decisions != change.ordinal or !retry.Lease.eql(current, state_lease)) return error.InvalidRetryState;
        const prolonged = try current.prolonged(change.requested, now);

        const installation = try self.readInstallation() orelse return error.InstallationRequired;
        const scope = try effects.Scope.host(change.subject);
        const key = try scope.key(installation);
        const entry = try self.readEffect(key, installation) orelse return error.StaleEffect;
        if (entry.status == .dispatched) return error.EffectReconciliationRequired;
        const decision_id = effects.hashParts("fail2zig-native-effect-decision-v2", &.{ change.jail, source, occurrence, &change.generation, &key });
        var owners: [effects.max_page]effects.Owner = undefined;
        const owner_count = try self.readOwners(key, &owners);
        var owner: ?effects.Owner = null;
        for (owners[0..owner_count]) |candidate| if (std.mem.eql(u8, candidate.jail.slice(), change.jail)) {
            if (owner != null) return error.InvalidEffect;
            owner = candidate;
        };
        const existing = owner orelse return error.StaleEffect;
        if (existing.revision != change.expected_owner_revision) return error.StaleEffect;
        if (!std.mem.eql(u8, &existing.generation, &change.generation) or !std.mem.eql(u8, &existing.decision_id, &decision_id)) return error.EffectGenerationMismatch;
        if (existing.decided_us != decided_us or !effects.Lease.eql(existing.lease, current)) return error.InvalidEffect;
        if (!prolonged.changed) {
            try self.commitTransaction();
            return .{ .changed = false, .lease = current, .effect = entry };
        }

        {
            var state = try self.statement("UPDATE retry_states SET lease_kind=?4,deadline_us=?5 WHERE jail=?1 AND family=?2 AND subject=?3;");
            defer state.deinit();
            try state.text(1, change.jail);
            try bindSubject(&state, &change.subject);
            try bindRetryLease(&state, 4, prolonged.lease);
            try state.done();
            if (self.api.changes(self.db) != 1) return error.InvalidRetryState;
        }
        try self.fault(.after_retry_state);
        {
            var decision = try self.statement("UPDATE retry_decisions SET lease_kind=?5,deadline_us=?6 WHERE jail=?1 AND family=?2 AND subject=?3 AND ordinal=?4;");
            defer decision.deinit();
            try decision.text(1, change.jail);
            try bindSubject(&decision, &change.subject);
            try decision.int(4, @intCast(change.ordinal));
            try bindRetryLease(&decision, 5, prolonged.lease);
            try decision.done();
            if (self.api.changes(self.db) != 1) return error.InvalidRetryState;
        }
        try self.fault(.after_retry_decision);
        if (existing.revision >= std.math.maxInt(i64) or entry.revision >= std.math.maxInt(i64) or try self.integer("SELECT count(*) FROM effect_owner_revisions;") >= effects.max_owner_revisions) return error.EffectCapacity;
        {
            var update = try self.statement("UPDATE effect_owners SET revision=?4,lease_kind=?5,deadline_us=?6 WHERE scope_key=?1 AND jail=?2 AND revision=?3;");
            defer update.deinit();
            try update.blob(1, &key);
            try update.text(2, change.jail);
            try update.int(3, @intCast(existing.revision));
            try update.int(4, @intCast(existing.revision + 1));
            try bindEffectLease(&update, 5, prolonged.lease);
            try update.done();
            if (self.api.changes(self.db) != 1) return error.StaleEffect;
        }
        try self.fault(.after_effect_owner);
        const next = try self.replaceEffectIntent(installation, scope, key, entry.revision + 1, decision_id, now);
        const final = try self.commitEffectClock(clock);
        if (!prolonged.lease.live(final) or (next.desired == .finite and !next.desired.live(final))) return error.EffectExpired;
        try self.commitEffectTransaction(true);
        return .{ .changed = true, .lease = prolonged.lease, .effect = next };
    }

    fn readEscalationHistory(self: *Store, jail: []const u8, subject: detection.Subject, scope: retry.EscalationScope) Error!retry.EscalationHistoryInput {
        var row = try self.statement(switch (scope) {
            .per_jail => "SELECT confirmed_count,latest_confirmed_us FROM confirmed_policy_summaries WHERE jail=?1 AND family=?2 AND subject=?3;",
            .overall => "SELECT coalesce(sum(confirmed_count),0),max(latest_confirmed_us) FROM confirmed_policy_summaries WHERE ?1 IS NOT NULL AND family=?2 AND subject=?3;",
        });
        defer row.deinit();
        try row.text(1, jail);
        try bindSubject(&row, &subject);
        if (!try row.row()) return .{};
        const signed_count = try row.signed(0);
        if (signed_count < 0) return error.InvalidRetryState;
        const count: u64 = @intCast(signed_count);
        const latest = try row.optionalSigned(1);
        if ((count == 0) != (latest == null) or try row.row()) return error.InvalidRetryState;
        return .{ .prior_confirmed = count, .latest_confirmed_us = latest };
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
        const current_attempt = retry.Attempt{ .at_us = outcome.eligible.timestamp.us, .occurrence = retry.occurrenceKey(record.source, record.occurrence) };
        var next = try retry.advanceWithEvidence(admission.policy, previous, subject, current_attempt, now, record.retry_evidence);
        var escalation_selection: ?EscalationSelection = null;
        if (next.decision != null and admission.policy.escalation.enabled) {
            if (self.schema_version < 18) return error.RetryStorageRequired;
            const history = try self.readEscalationHistory(record.jail, subject, admission.policy.escalation.scope);
            var sampled_seconds: u64 = 0;
            if (history.prior_confirmed > 0 and admission.policy.escalation.jitter_us > 0) {
                const maximum: u64 = @intCast(@divExact(admission.policy.escalation.jitter_us, 1_000_000));
                sampled_seconds = self.escalation_jitter(self.escalation_jitter_context, maximum);
                if (sampled_seconds > maximum) return error.InvalidEscalationInput;
            }
            const sampled_us = std.math.mul(i64, @as(i64, @intCast(sampled_seconds)), 1_000_000) catch return error.InvalidEscalationInput;
            const chosen = try admission.policy.escalation.duration(admission.policy.duration, history.prior_confirmed, sampled_us);
            const chosen_us = switch (chosen) {
                .finite_us => |value| value,
                .permanent => return error.InvalidEscalationInput,
            };
            var selected_policy = admission.policy;
            selected_policy.duration = chosen;
            next = try retry.advanceWithEvidence(selected_policy, previous, subject, current_attempt, now, record.retry_evidence);
            if (next.decision == null) return error.InvalidRetryState;
            escalation_selection = .{
                .scope = admission.policy.escalation.scope,
                .prior_confirmed = history.prior_confirmed,
                .latest_confirmed_us = history.latest_confirmed_us,
                .chosen_duration_us = chosen_us,
                .jitter_us = sampled_us,
            };
        }
        if (next.decision) |*decision| decision.enforce = admission.enforces();
        var prepared_context: ?action_context.Context = null;
        if (next.decision) |decision| {
            const confirmed_history_count: ?u64 = if (self.schema_version >= 18)
                (try self.readEscalationHistory(record.jail, subject, .per_jail)).prior_confirmed
            else
                null;
            prepared_context = try action_context.fromRetry(
                record.jail,
                record.source,
                record.occurrence,
                detected,
                outcome.eligible.timestamp.us,
                decision,
                @intCast(admission.policy.maxretry),
                confirmed_history_count,
            );
        }
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
        if (self.schema_version < 16 and next.state.lease == .permanent) return error.RetryStorageRequired;
        var row = try self.statement(if (self.schema_version >= 16)
            "INSERT INTO retry_states VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(jail,family,subject) DO UPDATE SET last_processed_us=excluded.last_processed_us,lease_kind=excluded.lease_kind,deadline_us=excluded.deadline_us,decisions=excluded.decisions,attempts=excluded.attempts;"
        else
            "INSERT INTO retry_states VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(jail,family,subject) DO UPDATE SET last_processed_us=excluded.last_processed_us,expiry_us=excluded.expiry_us,decisions=excluded.decisions,attempts=excluded.attempts;");
        defer row.deinit();
        try row.text(1, record.jail);
        try bindSubject(&row, &subject);
        try row.int(4, next.state.last_processed_us);
        if (self.schema_version >= 16) {
            try bindRetryLease(&row, 5, next.state.lease);
            try row.int(7, @intCast(next.state.decisions));
            try row.blob(8, next.state.encodeAttempts(&bytes));
        } else {
            if (next.state.lease == .finite) try row.int(5, next.state.lease.finite);
            try row.int(6, @intCast(next.state.decisions));
            try row.blob(7, next.state.encodeAttempts(&bytes));
        }
        try row.done();
        try self.fault(.after_retry_state);
        if (next.decision) |decision| {
            var effect_identity: ?effects.Hash = null;
            const context = prepared_context orelse return error.InvalidActionContext;
            var decision_row = try self.statement(if (self.schema_version >= 16)
                "INSERT INTO retry_decisions(jail,family,subject,source,occurrence,decided_us,lease_kind,deadline_us,ordinal,enforce) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10);"
            else
                "INSERT INTO retry_decisions(jail,family,subject,source,occurrence,decided_us,expiry_us,ordinal,enforce) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9);");
            defer decision_row.deinit();
            try decision_row.text(1, record.jail);
            try bindSubject(&decision_row, &subject);
            try decision_row.text(4, record.source);
            try decision_row.text(5, record.occurrence);
            try decision_row.int(6, decision.decided_us);
            if (self.schema_version >= 16) {
                try bindRetryLease(&decision_row, 7, decision.lease);
                try decision_row.int(9, @intCast(decision.ordinal));
                try decision_row.int(10, @intFromBool(decision.enforce));
            } else {
                if (decision.lease != .finite) return error.RetryStorageRequired;
                try decision_row.int(7, decision.lease.finite);
                try decision_row.int(8, @intCast(decision.ordinal));
                try decision_row.int(9, @intFromBool(decision.enforce));
            }
            try decision_row.done();
            if (escalation_selection) |selection| {
                var selected = try self.statement("INSERT INTO retry_decision_escalations(jail,family,subject,source,occurrence,scope,prior_confirmed,latest_confirmed_us,chosen_duration_us,jitter_us) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10);");
                defer selected.deinit();
                try selected.text(1, record.jail);
                try bindSubject(&selected, &subject);
                try selected.text(4, record.source);
                try selected.text(5, record.occurrence);
                try selected.int(6, @intFromEnum(selection.scope));
                try selected.int(7, std.math.cast(i64, selection.prior_confirmed) orelse return error.InvalidEscalationInput);
                if (selection.latest_confirmed_us) |latest| try selected.int(8, latest);
                try selected.int(9, selection.chosen_duration_us);
                try selected.int(10, selection.jitter_us);
                try selected.done();
            }
            try self.fault(.after_retry_decision);
            if (decision.enforce) {
                if (self.schema_version < 11) return error.EffectStorageRequired;
                const clock = record.effects_clock orelse return error.InstallationRequired;
                const effect_now = try self.effectClock(clock);
                const installation = try self.readInstallation() orelse return error.InstallationRequired;
                const scope = try context.legacyEffectScope();
                const key = try scope.key(installation);
                var owners: [effects.max_page]effects.Owner = undefined;
                const count = try self.readOwners(key, &owners);
                var effect_revision: u64 = 0;
                var kept_existing = false;
                for (owners[0..count]) |owner| if (std.mem.eql(u8, owner.jail.slice(), record.jail)) {
                    effect_revision = owner.revision;
                    kept_existing = owner.lease.live(effect_now);
                };
                const identity = if (self.schema_version >= 12)
                    effects.hashParts("fail2zig-native-effect-decision-v2", &.{ record.jail, record.source, record.occurrence, &admission.generation, &key })
                else
                    effects.hashParts("fail2zig-native-effect-decision-v1", &.{ record.jail, record.source, record.occurrence, &admission.generation });
                effect_identity = identity;
                if (!kept_existing) {
                    _ = try self.setOwnerTx(.{ .scope = scope, .jail = record.jail, .generation = admission.generation, .decision_id = identity, .expected_revision = effect_revision, .lease = decision.lease, .decided_us = decision.decided_us }, effect_now);
                    if (self.schema_version >= 21) try self.prepareActionTargetsTx(.{ .action_id = identity, .scope_key = key, .jail = record.jail }, effect_now);
                }
            }
            if (self.schema_version >= 17) {
                if (try self.integer("SELECT count(*) FROM retry_decision_details;") >= application_history.max_details) return error.HistoryCapacity;
                var detail = try self.statement("INSERT INTO retry_decision_details(jail,family,subject,source,occurrence,ordinal,decided_us,effect_decision_id,evidence) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9);");
                defer detail.deinit();
                try detail.text(1, record.jail);
                try bindSubject(&detail, &subject);
                try detail.text(4, record.source);
                try detail.text(5, record.occurrence);
                try detail.int(6, @intCast(decision.ordinal));
                try detail.int(7, decision.decided_us);
                if (effect_identity) |identity| try detail.blob(8, &identity);
                if (record.retry_evidence.text) |evidence| try detail.text(9, evidence);
                try detail.done();
            }
        }
    }

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

    pub fn nativeTime(self: *Store, jail: []const u8, source: []const u8, occurrence: ?[]const u8) Error!?time_policy.Result {
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

    pub fn visitPendingReceipts(self: *Store, callback: *const fn (ReceiptIdentity, native_time.Timestamp, ?*anyopaque) anyerror!void, context: ?*anyopaque) !void {
        const maximum = self.receipt_limit orelse return error.ReceiptStorageRequired;
        const initial_version = try self.integer("PRAGMA data_version;");
        if (try self.pendingReceiptCount() == 0) {
            if (try self.integer("PRAGMA data_version;") != initial_version) return error.StaleCheckpoint;
            return;
        }
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
        if (rc != 0 or self.api.get_autocommit(self.db) == 0) self.reopen_required = true;
    }
    fn exec(self: *Store, sql: [:0]const u8) Error!void {
        try self.usable();
        if (self.runtime_limits and self.api.get_autocommit(self.db) != 0) self.work_remaining = 1000;
        const rc = self.api.exec(self.db, sql, null, null, null);
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
        try record.retry_evidence.validate();
        if (record.retry_evidence.text != null and record.native_retry == null) return error.InvalidRecord;
        if (record.shared_state) |shared| {
            if (shared.name.len == 0 or shared.name.len > 4096 or std.mem.indexOfScalar(u8, shared.name, 0) != null) return error.InvalidRecord;
            if (shared.payload) |payload| if (payload.len > Limits.shared_bytes) return error.InvalidRecord;
        }
        if (record.consumers) |batch| try batch.validate();
        try self.beginWrite();
        errdefer self.rollback();
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
                if (!std.mem.eql(u8, &saved.generation, &supplied.generation) or !try retryPoliciesEqual(saved.policy, supplied.policy)) return error.RetryGenerationMismatch;
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
            if (!record.retry_suspended) {
                if (detections.len == 0) try self.commitRetry(record, admission);
                for (detections) |value| {
                    var scalar = record;
                    scalar.native_detection = value;
                    scalar.native_detections = null;
                    try self.commitRetry(scalar, admission);
                }
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
            for (decisions[0..count]) |decision| if (decision.enforce and !decision.lease.live(now)) return error.EffectExpired;
        }
        const effect_changed = if (record.native_retry != null) try self.hasEnforcingDecision(record) else false;
        try self.commitEffectTransaction(effect_changed);
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

test "record store: detailed open resets caller diagnostics and preserves allocation failure" {
    const t = std.testing;
    const a = t.allocator;
    var temp = t.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(a, ".");
    defer a.free(base);
    const path = try std.fs.path.join(a, &.{ base, "diagnostic.sqlite" });
    defer a.free(path);

    var diagnostic = OpenDiagnostic{
        .stage = .sqlite_open,
        .public_error = error.StorageFull,
        .posix_cause = .no_space_left,
        .sqlite_code = 13,
    };
    var store = try Store.openDetailed(a, path, &diagnostic);
    store.close();
    try t.expectEqualDeep(OpenDiagnostic{}, diagnostic);

    diagnostic = .{ .stage = .path_validation, .public_error = error.OpenFailed };
    var runtime = try Store.openRuntimeDetailed(a, path, &diagnostic);
    runtime.close();
    try t.expectEqualDeep(OpenDiagnostic{}, diagnostic);

    diagnostic = .{ .stage = .path_validation, .public_error = error.OpenFailed };
    var reader = try Store.openReadOnlyDetailed(a, path, &diagnostic);
    reader.close();
    try t.expectEqualDeep(OpenDiagnostic{}, diagnostic);

    diagnostic = .{ .stage = .path_validation, .public_error = error.OpenFailed };
    _ = try Store.installationSnapshotDetailed(a, path, &diagnostic);
    try t.expectEqualDeep(OpenDiagnostic{}, diagnostic);

    var failing = t.FailingAllocator.init(a, .{ .fail_index = 0 });
    try t.expectError(error.OutOfMemory, Store.openDetailed(failing.allocator(), path, &diagnostic));
    try t.expectEqual(OpenStage.path_copy, diagnostic.stage.?);
    try t.expectEqual(@as(Error, error.OutOfMemory), diagnostic.public_error.?);
    try t.expectEqual(@as(?OpenPosixCause, null), diagnostic.posix_cause);
    try t.expectEqual(@as(?c_int, null), diagnostic.sqlite_code);

    var legacy_failing = t.FailingAllocator.init(a, .{ .fail_index = 0 });
    try t.expectError(error.OutOfMemory, Store.open(legacy_failing.allocator(), path));
}

test "record store: detailed open distinguishes path access type and permission failures" {
    const t = std.testing;
    const a = t.allocator;
    var temp = t.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(a, ".");
    defer a.free(base);
    var diagnostic = OpenDiagnostic{};

    try t.expectError(error.OpenFailed, Store.openDetailed(a, "invalid\x00path", &diagnostic));
    try t.expectEqual(OpenStage.path_validation, diagnostic.stage.?);
    try t.expectEqual(@as(Error, error.OpenFailed), diagnostic.public_error.?);
    try t.expectEqual(@as(?OpenPosixCause, null), diagnostic.posix_cause);
    try t.expectEqual(@as(?c_int, null), diagnostic.sqlite_code);

    const missing_parent = try std.fs.path.join(a, &.{ base, "missing", "state.sqlite" });
    defer a.free(missing_parent);
    try t.expectError(error.OpenFailed, Store.openDetailed(a, missing_parent, &diagnostic));
    try t.expectEqual(OpenStage.parent_open, diagnostic.stage.?);
    try t.expectEqual(OpenPosixCause.file_not_found, diagnostic.posix_cause.?);

    const parent_file = try std.fs.path.join(a, &.{ base, "ordinary-file" });
    defer a.free(parent_file);
    var ordinary = try std.fs.cwd().createFile(parent_file, .{ .mode = 0o600 });
    ordinary.close();
    const below_file = try std.fs.path.join(a, &.{ parent_file, "state.sqlite" });
    defer a.free(below_file);
    try t.expectError(error.OpenFailed, Store.openDetailed(a, below_file, &diagnostic));
    try t.expectEqual(OpenStage.parent_open, diagnostic.stage.?);
    try t.expectEqual(OpenPosixCause.not_directory, diagnostic.posix_cause.?);

    try temp.dir.makeDir("unsafe-parent");
    var unsafe_parent = try temp.dir.openDir("unsafe-parent", .{ .iterate = true });
    defer unsafe_parent.close();
    try unsafe_parent.chmod(0o770);
    defer unsafe_parent.chmod(0o700) catch {};
    const unsafe_parent_path = try std.fs.path.join(a, &.{ base, "unsafe-parent", "state.sqlite" });
    defer a.free(unsafe_parent_path);
    try t.expectError(error.UnsafePermissions, Store.openDetailed(a, unsafe_parent_path, &diagnostic));
    try t.expectEqual(OpenStage.parent_permissions, diagnostic.stage.?);
    try t.expectEqual(@as(Error, error.UnsafePermissions), diagnostic.public_error.?);
    try t.expectEqual(@as(?OpenPosixCause, null), diagnostic.posix_cause);

    try temp.dir.makeDir("create-denied");
    var create_denied = try temp.dir.openDir("create-denied", .{ .iterate = true });
    defer create_denied.close();
    try create_denied.chmod(0o500);
    defer create_denied.chmod(0o700) catch {};
    const create_denied_path = try std.fs.path.join(a, &.{ base, "create-denied", "state.sqlite" });
    defer a.free(create_denied_path);
    try t.expectError(error.OpenFailed, Store.openDetailed(a, create_denied_path, &diagnostic));
    try t.expectEqual(OpenStage.file_create, diagnostic.stage.?);
    try t.expectEqual(OpenPosixCause.access_denied, diagnostic.posix_cause.?);

    try temp.dir.makeDir("directory.sqlite");
    const directory_path = try std.fs.path.join(a, &.{ base, "directory.sqlite" });
    defer a.free(directory_path);
    try t.expectError(error.UnsafePermissions, Store.openDetailed(a, directory_path, &diagnostic));
    try t.expectEqual(OpenStage.file_type, diagnostic.stage.?);

    const permissive_path = try std.fs.path.join(a, &.{ base, "permissive.sqlite" });
    defer a.free(permissive_path);
    var permissive = try std.fs.cwd().createFile(permissive_path, .{ .mode = 0o640 });
    permissive.close();
    try t.expectError(error.UnsafePermissions, Store.openDetailed(a, permissive_path, &diagnostic));
    try t.expectEqual(OpenStage.file_permissions, diagnostic.stage.?);
    try t.expectEqual(@as(?c_int, null), diagnostic.sqlite_code);
}

test "record store: detailed open detects deterministic file identity replacement" {
    const t = std.testing;
    const a = t.allocator;
    var temp = t.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(a, ".");
    defer a.free(base);
    const path = try std.fs.path.join(a, &.{ base, "selected.sqlite" });
    defer a.free(path);
    const moved = try std.fs.path.join(a, &.{ base, "selected.sqlite.saved" });
    defer a.free(moved);
    var initial = try Store.open(a, path);
    initial.close();

    const Race = struct {
        path: []const u8,
        moved: []const u8,
        ran: bool = false,
        failed: bool = false,

        fn replace(context: ?*anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.ran = true;
            std.posix.rename(self.path, self.moved) catch {
                self.failed = true;
                return;
            };
            const replacement = std.posix.open(self.path, .{ .ACCMODE = .RDWR, .CREAT = true, .EXCL = true, .CLOEXEC = true, .NOFOLLOW = true }, 0o600) catch {
                self.failed = true;
                return;
            };
            std.posix.close(replacement);
        }
    };
    var race = Race{ .path = path, .moved = moved };
    var diagnostic = OpenDiagnostic{};
    try t.expectError(error.OpenFailed, Store.openImpl(a, path, .plain, &diagnostic, .{ .context = &race, .before_identity_recheck = Race.replace }));
    try t.expect(race.ran);
    try t.expect(!race.failed);
    try t.expectEqual(OpenStage.file_identity_changed, diagnostic.stage.?);
    try t.expectEqual(@as(Error, error.OpenFailed), diagnostic.public_error.?);
    try t.expectEqual(@as(?OpenPosixCause, null), diagnostic.posix_cause);
    try t.expectEqual(@as(?c_int, null), diagnostic.sqlite_code);
}

test "record store: detailed open separates corrupt foreign unsupported and installation failures" {
    const t = std.testing;
    const a = t.allocator;
    var temp = t.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(a, ".");
    defer a.free(base);
    var diagnostic = OpenDiagnostic{};

    const corrupt_path = try std.fs.path.join(a, &.{ base, "corrupt.sqlite" });
    defer a.free(corrupt_path);
    const corrupt_bytes = [_]u8{0xa5} ** 64;
    var corrupt_file = try std.fs.cwd().createFile(corrupt_path, .{ .mode = 0o600 });
    try corrupt_file.writeAll(&corrupt_bytes);
    corrupt_file.close();
    try t.expectError(error.CorruptDatabase, Store.openDetailed(a, corrupt_path, &diagnostic));
    try t.expectEqual(OpenStage.schema_inspection, diagnostic.stage.?);
    try t.expectEqual(@as(Error, error.CorruptDatabase), diagnostic.public_error.?);
    try t.expect(diagnostic.sqlite_code != null);
    try t.expectEqual(@as(Error, error.CorruptDatabase), sqliteError(diagnostic.sqlite_code.?));

    const foreign_path = try std.fs.path.join(a, &.{ base, "foreign.sqlite" });
    defer a.free(foreign_path);
    var foreign = try Store.open(a, foreign_path);
    try foreign.exec("PRAGMA application_id=1;");
    foreign.close();
    try t.expectError(error.ForeignDatabase, Store.openDetailed(a, foreign_path, &diagnostic));
    try t.expectEqual(OpenStage.schema_validation, diagnostic.stage.?);
    try t.expectEqual(@as(Error, error.ForeignDatabase), diagnostic.public_error.?);
    try t.expectEqual(@as(?c_int, null), diagnostic.sqlite_code);
    try t.expectError(error.ForeignDatabase, Store.open(a, foreign_path));

    const unsupported_path = try std.fs.path.join(a, &.{ base, "unsupported.sqlite" });
    defer a.free(unsupported_path);
    var unsupported = try Store.open(a, unsupported_path);
    var version_sql: [64]u8 = undefined;
    const set_version = try std.fmt.bufPrintZ(&version_sql, "PRAGMA user_version={d};", .{latest_schema + 1});
    try unsupported.exec(set_version);
    unsupported.close();
    try t.expectError(error.UnsupportedSchema, Store.openDetailed(a, unsupported_path, &diagnostic));
    try t.expectEqual(OpenStage.schema_validation, diagnostic.stage.?);
    try t.expectEqual(@as(Error, error.UnsupportedSchema), diagnostic.public_error.?);
    try t.expectEqual(@as(?c_int, null), diagnostic.sqlite_code);
    try t.expectError(error.UnsupportedSchema, Store.installationSnapshot(a, unsupported_path));

    const installation_path = try std.fs.path.join(a, &.{ base, "installation.sqlite" });
    defer a.free(installation_path);
    var installation = try Store.open(a, installation_path);
    try installation.exec("CREATE TABLE effect_installation(broken INTEGER); PRAGMA user_version=11;");
    installation.close();
    try t.expectError(error.DatabaseFailure, Store.installationSnapshotDetailed(a, installation_path, &diagnostic));
    try t.expectEqual(OpenStage.installation_read, diagnostic.stage.?);
    try t.expectEqual(@as(Error, error.DatabaseFailure), diagnostic.public_error.?);
    try t.expect(diagnostic.sqlite_code != null);
    try t.expectEqual(@as(c_int, 1), diagnostic.sqlite_code.? & 0xff);
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
            std.process.exit(4);
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
    for (0..4) |phase| {
        const pid = try std.posix.fork();
        if (pid == 0) {
            var child = Store.open(std.heap.page_allocator, path) catch std.process.exit(2);
            child.enableReceipts(1) catch std.process.exit(3);
            if (phase == 0) {
                child.exec("BEGIN IMMEDIATE; INSERT INTO pending_receipts VALUES('fixture','ordinary',zeroblob(32),'one',zeroblob(32),'next',100);") catch std.process.exit(4);
            } else if (phase == 1) {
                _ = child.beginReceipt(ReceiptFixture.identity, .{ .us = 100 }, 0) catch std.process.exit(5);
            } else if (phase == 2) {
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
    const policy = retry.Policy{ .maxretry = 1, .window_us = 600_000_000, .duration = .{ .finite_us = 60_000_000 }, .max_subjects = 8 };
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
                try std.testing.expectEqualDeep(retry.Lease{ .finite = DetectionFixture.stamp + policy.duration.finite_us }, value.lease);
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
                try std.testing.expectEqual(@as(i64, 1), try restored.integer("SELECT count(*) FROM consumer_checkpoints;"));
            }
        }
    };
}

const EffectPublicationProbe = struct {
    store: *Store,
    calls: usize = 0,
    epoch_at_invalidation: u64 = 0,
    inside_transaction: bool = false,
    fn invalidate(context: ?*anyopaque) void {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        self.calls += 1;
        self.epoch_at_invalidation = self.store.effect_publication_epoch;
        self.inside_transaction = self.store.api.get_autocommit(self.store.db) == 0;
    }
    fn clockRead(_: ?*anyopaque) i64 {
        return 100;
    }
    fn clock() effects.Clock {
        return .{ .prepared_us = 100, .context = null, .read = clockRead };
    }
    fn enable(store: *Store) !void {
        try store.enableReceipts(8);
        try store.enableNativeTime();
        try store.enableYearInference();
        try store.enableDetection();
        try store.enableClockRecovery();
        try store.enableJournalDetection();
        try store.enableRetry();
        try store.enableConsumers();
        try store.enableEffects();
        try store.admitInstallation(try effects.Installation.init([_]u8{7} ** 16, .nftables, "host-default"), .{ .selector = "host-default", .disposition = .verified_absent });
    }
    fn change() !effects.OwnerChange {
        return .{ .scope = try effects.Scope.host(.{ .v4 = .{ 192, 0, 2, 7 } }), .jail = "sshd", .generation = [_]u8{5} ** 32, .decision_id = [_]u8{6} ** 32, .expected_revision = 0, .lease = .{ .finite = 500 }, .decided_us = 100 };
    }
};

test "record store: effect invalidation precedes durable commit and unchanged owners keep authority" {
    const t = std.testing;
    var temp = t.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(base);
    const path = try std.fs.path.join(t.allocator, &.{ base, "publication.sqlite" });
    defer t.allocator.free(path);
    var store = try Store.open(t.allocator, path);
    defer store.close();
    try EffectPublicationProbe.enable(&store);
    var probe = EffectPublicationProbe{ .store = &store };
    store.effect_invalidation = .{ .context = &probe, .invalidate = EffectPublicationProbe.invalidate };
    const entry = try store.setOwner(try EffectPublicationProbe.change(), EffectPublicationProbe.clock());
    try t.expectEqual(@as(usize, 1), probe.calls);
    try t.expect(probe.inside_transaction);
    try t.expectEqual(@as(u64, 0), probe.epoch_at_invalidation);
    try t.expectEqual(@as(u64, 1), store.effect_publication_epoch);
    try t.expect(store.api.get_autocommit(store.db) != 0);
    _ = try store.setOwner(try EffectPublicationProbe.change(), EffectPublicationProbe.clock());
    _ = try store.prepareExpiry(entry.scope_key, entry.revision, EffectPublicationProbe.clock());
    try t.expectEqual(@as(usize, 1), probe.calls);
    try t.expectEqual(@as(u64, 1), store.effect_publication_epoch);
}

test "record store: failed effect commit retains invalidation without publishing an epoch and reopens unchanged" {
    const t = std.testing;
    var temp = t.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(base);
    const path = try std.fs.path.join(t.allocator, &.{ base, "failed-publication.sqlite" });
    defer t.allocator.free(path);
    for ([_]bool{ false, true }) |fail_rollback| {
        {
            var store = try Store.open(t.allocator, path);
            defer store.close();
            if (store.schema_version == 2) try EffectPublicationProbe.enable(&store);
            var probe = EffectPublicationProbe{ .store = &store };
            store.effect_invalidation = .{ .context = &probe, .invalidate = EffectPublicationProbe.invalidate };
            const Fault = struct {
                var active: *EffectPublicationProbe = undefined;
                var rollback_failure: bool = false;
                var saw_invalidated_commit: bool = false;
                fn exec(db: *Db, sql: [*:0]const u8, callback: ?*anyopaque, context: ?*anyopaque, message: ?*?[*:0]u8) callconv(.c) c_int {
                    if (std.mem.eql(u8, std.mem.span(sql), "COMMIT;")) {
                        saw_invalidated_commit = active.calls == 1 and active.store.effect_publication_epoch == 0;
                        return 10 | (3 << 8);
                    }
                    if (rollback_failure and std.mem.eql(u8, std.mem.span(sql), "ROLLBACK;")) return 10 | (4 << 8);
                    return embedded_api.exec(db, sql, callback, context, message);
                }
            };
            Fault.active = &probe;
            Fault.rollback_failure = fail_rollback;
            Fault.saw_invalidated_commit = false;
            store.api.exec = Fault.exec;
            try t.expectError(error.StorageIo, store.setOwner(try EffectPublicationProbe.change(), EffectPublicationProbe.clock()));
            try t.expect(Fault.saw_invalidated_commit and probe.inside_transaction);
            try t.expectEqual(@as(usize, 1), probe.calls);
            try t.expectEqual(@as(u64, 0), store.effect_publication_epoch);
            // COMMIT I/O uncertainty always requires reopen, even when rollback succeeds.
            try t.expect(store.reopen_required);
            try t.expectEqual(@as(?c_int, if (fail_rollback) 10 | (4 << 8) else null), store.rollback_error_code);
            try t.expectEqual(fail_rollback, store.api.get_autocommit(store.db) == 0);
            try t.expectEqual(@as(?c_int, 10 | (3 << 8)), store.last_error_code);
        }
        var reopened = try Store.open(t.allocator, path);
        defer reopened.close();
        try t.expectEqual(@as(i64, 0), try reopened.integer("SELECT count(*) FROM effect_owners;"));
    }
}

test "record store: extension-only staged activation invalidates effects despite zero fresh owners" {
    const t = std.testing;
    var temp = t.tmpDir(.{});
    defer temp.cleanup();
    const base = try temp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(base);
    const path = try std.fs.path.join(t.allocator, &.{ base, "extension-publication.sqlite" });
    defer t.allocator.free(path);
    var store = try Store.open(t.allocator, path);
    defer store.close();
    try EffectPublicationProbe.enable(&store);
    try store.enableTimeProvenance();
    try store.enableConsumerManifests();
    try store.enableConfirmedHistory();
    try store.enableMaintenance();
    try store.enableCleanup();
    try store.enableRetryLeases();
    try store.enableApplicationHistory();
    try store.enableEscalation();
    try store.enableCanonicalEffects();
    try store.enableHistoryResets();
    try store.enableActionTargets();
    try store.enableAdminState();
    try store.enableMigrationState();
    const change = try EffectPublicationProbe.change();
    _ = try store.setOwner(change, EffectPublicationProbe.clock());
    const run_id = [_]u8{9} ** 32;
    try store.createMigrationRun(.{ .run_id = run_id, .host_id = [_]u8{1} ** 32, .source_db_fp = [_]u8{2} ** 32, .source_cfg_fp = [_]u8{3} ** 32, .plan_fp = [_]u8{4} ** 32, .recovery_point = "/fixture/recovery.sqlite", .generation = change.generation, .state = .planned, .created_us = 100, .updated_us = 100 });
    try store.stageMigrationRows(run_id, &.{.{ .jail = change.jail, .scope = try (try change.scope.toCanonical()).encode(), .lease_kind = 1, .deadline_us = 1000, .source_event_us = 100, .source_row = 1 }}, &.{});
    const seq = try store.beginMigrationStep(run_id, .stage_destination, "", 100);
    try store.finishMigrationStep(run_id, seq, .success, "", .staged, 100);
    var probe = EffectPublicationProbe{ .store = &store };
    store.effect_invalidation = .{ .context = &probe, .invalidate = EffectPublicationProbe.invalidate };
    const epoch = store.effect_publication_epoch;
    try t.expectEqual(@as(u64, 0), try store.activateStagedOwners(run_id, &.{.{ .jail = change.jail, .generation = change.generation }}, EffectPublicationProbe.clock()));
    try t.expectEqual(@as(usize, 1), probe.calls);
    try t.expect(probe.inside_transaction);
    try t.expectEqual(epoch, probe.epoch_at_invalidation);
    try t.expectEqual(epoch + 1, store.effect_publication_epoch);
    try t.expectEqual(@as(i64, 1000), try store.integer("SELECT deadline_us FROM effect_owners;"));
    _ = try store.activateStagedOwners(run_id, &.{.{ .jail = change.jail, .generation = change.generation }}, EffectPublicationProbe.clock());
    try t.expectEqual(@as(usize, 1), probe.calls);
    try t.expectEqual(epoch + 1, store.effect_publication_epoch);
}
