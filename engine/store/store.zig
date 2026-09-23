// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const builtin = @import("builtin");
const native_time = @import("../core/native_time.zig");
const time_policy = @import("../core/source_time_policy.zig");
const native_record = @import("../core/native_time_record.zig");
const detection = @import("../core/native_detection_record.zig");
const retry = @import("../core/native_retry.zig");
const action_context = @import("../core/native_action_context.zig");
const consumers = @import("../core/native_consumer.zig");
const effects = @import("../core/native_effect.zig");
const effect_history = @import("../core/native_effect_history.zig");
const application_history = @import("../core/native_application_history.zig");
const action_outcome = @import("../core/native_action_outcome.zig");
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
pub const CommitStage = enum { after_retry_detail_prune, before_admin_schema_commit, before_migration_schema_commit, after_admin_request, after_migration_step_intent, after_migration_step_outcome, before_migration_activation_commit, before_policy_transition_commit, before_config_generation_commit, before_config_generation_publish, before_action_target_schema_commit, after_action_target_intent, before_action_target_dispatch_commit, before_action_target_settlement_commit, before_history_reset_schema_commit, after_history_reset, before_canonical_effect_schema_commit, after_history_detail_delete, after_history_event_delete, before_escalation_schema_commit, before_application_history_schema_commit, before_cleanup_schema_commit, before_retry_lease_schema_commit, after_cleanup_mark, before_cleanup_escalation_delete, after_cleanup_escalation_delete, before_cleanup_retry_delete, after_cleanup_retry_delete, after_cleanup_delete, before_cleanup_commit, after_retry_retire, before_maintenance_schema_commit, after_source_sequence, after_replay_guard, after_record, after_checkpoint, after_shared_checkpoint, before_commit, before_receipt_commit, after_receipt_commit, after_receipt_delete, before_receipt_schema_commit, before_native_time_schema_commit, before_inference_schema_commit, before_detection_schema_commit, after_detection, before_clock_schema_commit, before_journal_detection_schema_commit, before_retry_schema_commit, after_retry_state, after_retry_decision, before_consumer_schema_commit, after_consumer_delta, before_effect_schema_commit, after_effect_owner, after_effect_intent, before_effect_dispatch_commit, before_effect_receipt_commit, before_manifest_schema_commit, before_manifest_commit, after_manifest_ready, before_consumer_input_commit };
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

    pub fn beginWrite(self: *Store) Error!void {
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
    pub fn beginAdmissionWrite(self: *Store) Error!void {
        if (self.startup_admission) return self.beginStartupOperation();
        try self.beginWrite();
    }
    pub fn beginRead(self: *Store) Error!void {
        if (self.startup_admission) return self.beginStartupOperation();
        try self.exec("BEGIN;");
    }
    pub fn commitTransaction(self: *Store) Error!void {
        if (!self.startup_admission) return self.exec("COMMIT;");
        if (!self.startup_operation or self.api.get_autocommit(self.db) != 0) return error.DatabaseFailure;
        try self.exec("RELEASE native_startup_operation;");
        self.startup_operation = false;
    }

    // Invalidate before durable publication; a failed COMMIT stays conservatively
    // uncertain until the caller republishes a verified view. Never restore here.
    pub fn commitEffectTransaction(self: *Store, changed: bool) Error!void {
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

    pub fn validateReceiptIdentity(identity: ReceiptIdentity) Error!void {
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
    pub fn maintenanceKey(jail: []const u8, source: []const u8) Error!void {
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
        const generation = try Store.effectBlob(&row, 0, 32);
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
    pub fn occurrenceGuardKey(occurrence: []const u8) [32]u8 {
        return effects.hashParts("fail2zig-replay-occurrence-v1", &.{occurrence});
    }
    pub fn identityGuardKey(identity: ReceiptIdentity) [32]u8 {
        return effects.hashParts("fail2zig-replay-identity-v1", &.{ identity.jail, identity.source, &identity.generation, identity.occurrence, &identity.raw_hash, identity.cursor });
    }
    pub fn checkReplayGuard(self: *Store, jail: []const u8, source: []const u8, occurrence: []const u8, raw_hash: [32]u8, cursor: []const u8, supplied_generation: ?[32]u8, receipt_us: ?i64) Error!void {
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
        const generation = try Store.effectBlob(&row, 0, 32);
        const saved_identity = try Store.effectBlob(&row, 1, 32);
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
        const identity = ReceiptIdentity{ .jail = jail, .source = source, .occurrence = occurrence, .raw_hash = try Store.effectBlob(&row, 0, 32), .cursor = try row.boundedBytes(1, Limits.cursor_bytes), .generation = position.generation };
        const receipt = try row.optionalSigned(2);
        if (receipt != null and !std.mem.eql(u8, &try Store.effectBlob(&row, 3, 32), &position.generation)) return error.InvalidMaintenanceState;
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
        // Both are lookup keys for bounded detail reclamation. This additive
        // index change is safe for existing schema-17..23 databases and older
        // binaries; no stored record or checkpoint format changes.
        try self.exec(
            \\CREATE INDEX IF NOT EXISTS effect_owners_decision ON effect_owners(jail,decision_id);
            \\CREATE INDEX IF NOT EXISTS confirmed_effect_events_decision ON confirmed_effect_events(jail,decision_id);
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
                    const scope = try effects.Scope.decode(&try Store.effectBlob(&rows, 1, effects.Scope.encoded_bytes));
                    const admitted = installation orelse return error.InstallationRequired;
                    if (!std.mem.eql(u8, &try Store.effectBlob(&rows, 0, 32), &try scope.key(admitted))) return error.InvalidEffect;
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
                    _ = try effects.Scope.decodeCanonical(&try Store.effectBlob(&canonical_rows, 0, effects.Scope.canonical_encoded_bytes));
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
    pub usingnamespace @import("admin.zig").Methods(@This());

    pub usingnamespace @import("migration.zig").Methods(@This());

    pub fn inspectInteger(self: *Store, sql: [:0]const u8) Error!i64 {
        if (!@import("builtin").is_test) @compileError("inspectInteger is test-only");
        return self.integer(sql);
    }
    pub fn inspectExec(self: *Store, sql: [:0]const u8) Error!void {
        if (!@import("builtin").is_test) @compileError("inspectExec is test-only");
        return self.exec(sql);
    }

    pub usingnamespace @import("maintenance.zig").Methods(@This());

    pub usingnamespace @import("effects.zig").Methods(@This());

    pub usingnamespace @import("consumer_retry.zig").Methods(@This());

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
    pub fn readRetryClock(self: *Store) Error!?i64 {
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
    pub fn readAdmissionClock(self: *Store, schema: i64) Error!?native_time.Timestamp {
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
        const outcome = stored.outcomeWithDisposition(.{ .us = try row.signed(3) }, try row.boundedBytes(4, 64)) catch return error.DatabaseFailure;
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
        const result = native_record.Provenance{ .zone_digest = try Store.effectBlob(&row, 0, 32), .offset_seconds = std.math.cast(i32, try row.signed(1)) orelse return error.InvalidRecord, .ambiguity = ambiguity, .fold_selected = fold == 1 };
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
    pub fn check(self: *Store, rc: c_int) Error!void {
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
    pub fn rollback(self: *Store) void {
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
    pub fn exec(self: *Store, sql: [:0]const u8) Error!void {
        try self.usable();
        if (self.runtime_limits and self.api.get_autocommit(self.db) != 0) self.work_remaining = 1000;
        const rc = self.api.exec(self.db, sql, null, null, null);
        if (rc != 0 and std.mem.eql(u8, sql, "COMMIT;") and
            (self.api.get_autocommit(self.db) != 0 or rc & 0xff == 10 or rc & 0xff == 11)) self.reopen_required = true;
        try self.check(rc);
    }
    pub fn statement(self: *Store, sql: [:0]const u8) Error!Stmt {
        try self.usable();
        if (self.runtime_limits and self.api.get_autocommit(self.db) != 0) self.work_remaining = 1000;
        var ptr: ?*Statement = null;
        try self.check(self.api.prepare(self.db, sql, -1, &ptr, null));
        return .{ .store = self, .ptr = ptr orelse return error.DatabaseFailure };
    }
    pub fn integer(self: *Store, sql: [:0]const u8) Error!i64 {
        var stmt = try self.statement(sql);
        defer stmt.deinit();
        if (!try stmt.row()) return error.DatabaseFailure;
        return self.api.column_int64(stmt.ptr, 0);
    }
    pub fn fault(self: *Store, stage: CommitStage) Error!void {
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
                if (!std.mem.eql(u8, &saved.generation, &supplied.generation) or !try Store.retryPoliciesEqual(saved.policy, supplied.policy)) return error.RetryGenerationMismatch;
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
pub const Stmt = struct {
    store: *Store,
    ptr: *Statement,
    pub fn deinit(self: *Stmt) void {
        _ = self.store.api.finalize(self.ptr);
    }
    pub fn text(self: *Stmt, index: c_int, value: []const u8) Error!void {
        if (value.len > std.math.maxInt(c_int)) return error.InvalidRecord;
        try self.store.check(self.store.api.bind_text(self.ptr, index, value.ptr, @intCast(value.len), null));
    }
    pub fn blob(self: *Stmt, index: c_int, value: []const u8) Error!void {
        if (value.len > std.math.maxInt(c_int)) return error.InvalidRecord;
        try self.store.check(self.store.api.bind_blob(self.ptr, index, value.ptr, @intCast(value.len), null));
    }
    pub fn int(self: *Stmt, index: c_int, value: i64) Error!void {
        try self.store.check(self.store.api.bind_int64(self.ptr, index, value));
    }
    pub fn signed(self: *Stmt, column: c_int) Error!i64 {
        if (self.store.api.column_type(self.ptr, column) != 1) return error.DatabaseFailure;
        return self.store.api.column_int64(self.ptr, column);
    }
    pub fn optionalSigned(self: *Stmt, column: c_int) Error!?i64 {
        if (self.store.api.column_type(self.ptr, column) == 5) return null;
        return try self.signed(column);
    }
    pub fn row(self: *Stmt) Error!bool {
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
    pub fn done(self: *Stmt) Error!void {
        if (try self.row()) return error.DatabaseFailure;
    }
    pub fn reset(self: *Stmt) Error!void {
        const resetStatement = @extern(*const fn (*Statement) callconv(.c) c_int, .{ .name = "sqlite3_reset" });
        const clearBindings = @extern(*const fn (*Statement) callconv(.c) c_int, .{ .name = "sqlite3_clear_bindings" });
        try self.store.check(resetStatement(self.ptr));
        try self.store.check(clearBindings(self.ptr));
    }
    pub fn boundedBytes(self: *Stmt, column: c_int, maximum: usize) Error![]const u8 {
        const value = try self.bytes(column);
        if (value.len > maximum) return error.StorageLimit;
        return value;
    }
    pub fn bytes(self: *Stmt, column: c_int) Error![]const u8 {
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
