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
    pub const TestAccess = if (builtin.is_test) struct {
        pub const openImpl = Store.openImpl;
    } else struct {};
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

    pub usingnamespace @import("schema.zig").Methods(@This());

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
    pub fn readReceiptClock(self: *Store) Error!?native_time.Timestamp {
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
        try Store.validateReceiptIdentity(identity);
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
        try Store.validateReceiptIdentity(identity);
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
                try Store.validateReceiptIdentity(identity);
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
        try Store.validateReceiptIdentity(identity);
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
        try Store.validateReceiptIdentity(identity);
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

pub const testing = if (builtin.is_test) struct {
    pub const sqlite_error = sqliteError;
    pub const embedded = embedded_api;
    pub const db = Db;
} else struct {};
