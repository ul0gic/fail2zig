// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Owns the native SQLite state file's connection, transactions, statement cache and the storage types its methods share.
// Holds: A failed ROLLBACK or an uncertain COMMIT sets reopen_required, after which every exec, statement and step fails ReopenRequired.

const std = @import("std");
const build_options = @import("build_options");
const diag_mod = @import("../diag/diag.zig");
const native_time = @import("../time/time.zig");
const time_policy = @import("../source/source_time_policy.zig");
const native_record = @import("../time/time_record.zig");
const detection = @import("../detect/detection_record.zig");
const retry = @import("../detect/retry.zig");
const action_context = @import("../effect/action_context.zig");
const consumers = @import("../detect/consumer.zig");
const effects = @import("../effect/effect.zig");
const effect_history = @import("../effect/effect_history.zig");
const application_history = @import("../effect/application_history.zig");
const action_outcome = @import("../effect/action_outcome.zig");
const budget = @import("budget.zig");
pub const latest_schema: i64 = 29;
pub const load_repair_schema: i64 = 24;
pub const load_repair = @import("load_repair_migration.zig");
pub const SchemaReadyOptions = struct {
    maximum_pending: usize,
    migration: load_repair.Options,
    progress: ?@import("../platform/sd_notify.zig").Hook = null,
};
pub const max_native_detections = 16;
pub const Db = opaque {};
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
pub const embedded_api: Api = blk: {
    var api: Api = undefined;
    for (std.meta.fields(Api)) |field| {
        const symbol = if (std.mem.eql(u8, field.name, "open")) "sqlite3_open_v2" else if (std.mem.eql(u8, field.name, "close")) "sqlite3_close_v2" else if (std.mem.eql(
            u8,
            field.name,
            "prepare",
        )) "sqlite3_prepare_v2" else "sqlite3_" ++ field.name;
        @field(api, field.name) = @extern(field.type, .{ .name = symbol });
    }
    break :blk api;
};
pub const Error = application_history.Error || action_outcome.Error || retry.Error || consumers.Error || effects.Error || effect_history.Error || action_context.Error || error{
    MaintenancePinned,
    StaleMaintenance,
    InvalidMaintenanceState,
    MaintenanceStorageRequired,
    ConsumerManifestRequired,
    ConsumerManifestMismatch,
    ConsumerManifestMissing,
    ConsumerManifestExists,
    ConsumerMigrationRequired,
    MissingRequiredConsumer,
    AmbiguousNativeDetection,
    AmbiguousRetryDecision,
    ConsumerStorageRequired,
    StaleConsumerCheckpoint,
    OpenFailed,
    UnsafePermissions,
    ForeignDatabase,
    UnsupportedSchema,
    DatabaseFailure,
    Busy,
    StorageFull,
    ReadOnly,
    StorageIo,
    CorruptDatabase,
    StorageLimit,
    Interrupted,
    AccessDenied,
    ReopenRequired,
    InvalidRecord,
    OccurrenceConflict,
    StaleCheckpoint,
    StaleSharedCheckpoint,
    InjectedFailure,
    OutOfMemory,
    ReceiptStorageRequired,
    InferenceStorageRequired,
    DetectionStorageRequired,
    ReceiptConflict,
    ReceiptRequired,
    ReceiptAlreadyCommitted,
    ReceiptLimit,
    RetryStorageRequired,
    RetryAdmissionRequired,
    RetryGenerationMismatch,
    RetryMigrationRequired,
    RetryCapacity,
    RetryEligibilityPending,
    ReceiptClockReversed,
    HistoryResetStorageRequired,
    InvalidHistoryReset,
    StaleHistoryReset,
    AdminStorageRequired,
    MigrationStorageRequired,
    StaleAdminRevision,
    InvalidAdminRequest,
    AdminRequestCapacity,
    RetryPolicyInFlight,
    StalePolicyTransition,
    ConfigGenerationExists,
    ConfigGenerationMissing,
    MigrationRunExists,
    MigrationRunMissing,
    MigrationStepMissing,
    MigrationStepOpen,
    MigrationStepOrder,
    InvalidMigrationRow,
    InvalidMigrationState,
    MigrationJailUnknown,
    LoadRepairMigrationIncomplete,
    LoadRepairWritersPending,
    LoadRepairBackupExists,
    LoadRepairBackupInvalid,
    LoadRepairDiskSpace,
    LoadRepairVerificationFailed,
    LoadRepairInvalidState,
    SchemaBackupExists,
    IgnoreCapacity,
    InvalidIgnoreEntry,
    ReserveBackpressure,
    MaintenanceWorkExhausted,
    LiveOwnerCounterInvalid,
    CustomLegacyProofRequired,
    CustomLegacyIdentityMismatch,
    StorageCapacity,
};

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

pub fn sqliteError(rc: c_int) Error {
    // Why: The low byte of an extended result code is its primary code, whose values sqlite3.h fixes.
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
pub const CommitStage = enum {
    during_load_repair_events_swap,
    after_retry_detail_prune,
    before_admin_schema_commit,
    before_migration_schema_commit,
    after_admin_request,
    after_migration_step_intent,
    after_migration_step_outcome,
    before_migration_activation_commit,
    before_policy_transition_commit,
    before_config_generation_commit,
    before_config_generation_publish,
    before_action_target_schema_commit,
    after_action_target_intent,
    before_action_target_dispatch_commit,
    before_action_target_settlement_commit,
    before_history_reset_schema_commit,
    after_history_reset,
    before_canonical_effect_schema_commit,
    after_history_detail_delete,
    after_history_event_delete,
    before_history_retention_commit,
    before_escalation_schema_commit,
    before_application_history_schema_commit,
    before_cleanup_schema_commit,
    before_retry_lease_schema_commit,
    after_cleanup_mark,
    before_cleanup_escalation_delete,
    after_cleanup_escalation_delete,
    before_cleanup_retry_delete,
    after_cleanup_retry_delete,
    after_cleanup_delete,
    before_cleanup_commit,
    after_retry_retire,
    before_maintenance_schema_commit,
    after_source_sequence,
    after_record,
    after_checkpoint,
    after_shared_checkpoint,
    before_commit,
    before_receipt_commit,
    after_receipt_commit,
    after_receipt_delete,
    before_receipt_schema_commit,
    before_native_time_schema_commit,
    before_inference_schema_commit,
    before_detection_schema_commit,
    after_detection,
    before_clock_schema_commit,
    before_journal_detection_schema_commit,
    before_retry_schema_commit,
    after_retry_state,
    after_retry_decision,
    before_consumer_schema_commit,
    after_consumer_delta,
    before_effect_schema_commit,
    after_effect_owner,
    after_effect_intent,
    before_effect_dispatch_commit,
    before_effect_receipt_commit,
    before_manifest_schema_commit,
    before_manifest_commit,
    after_manifest_ready,
    before_consumer_input_commit,
};
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

    pub fn sameRecord(self: ReceiptIdentity, other: ReceiptIdentity) bool {
        return std.mem.eql(u8, self.jail, other.jail) and std.mem.eql(u8, self.source, other.source) and
            std.mem.eql(u8, self.occurrence, other.occurrence) and std.mem.eql(u8, &self.raw_hash, &other.raw_hash) and
            std.mem.eql(u8, &self.generation, &other.generation);
    }
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
    retirement_pending: ?*const fn (?*anyopaque, effects.Hash, []const effects.Owner, effects.Lease) void = null,
};
pub const max_retention_page: u16 = 256;
pub const ReclaimCursor = struct { phase: u2 = 0, cursor: i64 = 0, found: bool = false, rest: u8 = 0 };
const statement_cache_slots = 512;
const CachedStatement = struct { hash: u64 = 0, stmt: ?*Statement = null, in_use: bool = false };
pub const RowTallies = struct {
    effect_observations: ?i64 = null,
    confirmed_effect_events: ?i64 = null,
    effect_owners: ?i64 = null,
    native_effects: ?i64 = null,
    effect_owner_revisions: ?i64 = null,
    effect_intents: ?i64 = null,
    action_targets: ?i64 = null,
    confirmed_event_details: ?i64 = null,
    retry_states: ?i64 = null,
    retry_decision_details: ?i64 = null,
};
pub const TalliedTable = std.meta.FieldEnum(RowTallies);
pub const Store = struct {
    allocator: std.mem.Allocator,
    api: Api,
    db: *Db,
    last_error_code: ?c_int = null,
    rollback_error_code: ?c_int = null,
    consumer_clock_floor_us: ?i64 = null,
    effect_publication_epoch: u64 = 0,
    effect_invalidation: ?EffectInvalidation = null,
    attributed_changes: *[attribution_ring]AttributedChange,
    noted_keys: [attribution_batch]effects.Hash = undefined,
    noted_count: u8 = 0,
    noted_ambiguous: bool = false,
    row_tallies: RowTallies = .{},
    reopen_required: bool = false,
    startup_admission: bool = false,
    startup_operation: bool = false,
    startup_rebind_effects_changed: bool = false,
    fail_at: ?CommitStage = null,
    rekeyed_owners: bool = false,
    schema_version: i64 = 2,
    receipt_limit: ?usize = null,
    runtime_limits: bool = false,
    admission: budget.Class = .obligation,
    intake_closed: bool = false,
    runtime_path: ?[]const u8 = null,
    work_remaining: u32 = 1000,
    load_repair_backup_verified: bool = false,
    load_repair_migrated: bool = false,
    retention_page: u16 = max_retention_page,
    retention_aux_turn: u2 = 0,
    history_retention_rest: bool = false,
    cleanup_cursor: i64 = 0,
    cleanup_cycle_deleted: bool = false,
    retired_cursor: i64 = 0,
    retired_cycle_deleted: bool = false,
    retired_sweep_done: bool = false,
    source_header_cursor: i64 = 0,
    source_header_sweep_done: bool = false,
    reclaim: ReclaimCursor = .{},
    reclaim_turn: bool = false,
    prune_batch: u8 = attribution_batch,
    prune_after: ?effects.Hash = null,
    retry_detail_rest: u8 = 0,
    maintenance_operation: ?@import("../platform/storage_health.zig").MaintenanceOperation = null,
    history_overload_notice_us: ?i64 = null,
    escalation_jitter_context: ?*anyopaque = null,
    escalation_jitter: *const fn (?*anyopaque, u64) u64 = systemEscalationJitter,
    retry_evictions: @import("consumer_retry.zig").Evictions = .{},
    memory_evictions: @import("memory_caps.zig").Evictions = .{},
    retry_projection_initialized: bool = false,
    retry_admission_target_hint: ?i64 = null,
    retry_admission_work_left: u16 = 256,
    diag_changes: if (build_options.diag) i64 else void = if (build_options.diag) 0 else {},
    statement_cache: ?*[statement_cache_slots]CachedStatement = null,

    fn systemEscalationJitter(_: ?*anyopaque, maximum_seconds: u64) u64 {
        return std.crypto.random.uintAtMost(u64, maximum_seconds);
    }

    pub fn configureHeapLimit() void {
        const hard_limit = @extern(*const fn (i64) callconv(.c) i64, .{ .name = "sqlite3_hard_heap_limit64" });
        const prior = hard_limit(-1);
        _ = hard_limit(if (prior > 0) @min(prior, 64 * 1024 * 1024) else 64 * 1024 * 1024);
    }
    pub fn configurePageLimit(self: *Store) Error!void {
        if (try self.integer("PRAGMA page_count;") > budget.limit_pages) return error.StorageLimit;
        var sql: [80]u8 = undefined;
        const maximum = std.fmt.bufPrintZ(&sql, "PRAGMA max_page_count={d};", .{budget.limit_pages}) catch return error.StorageLimit;
        if (try self.integer(maximum) != budget.limit_pages) return error.StorageLimit;
    }
    pub fn configureRuntimeLimits(self: *Store) Error!void {
        configureHeapLimit();
        try self.exec("PRAGMA cache_size=-32768; PRAGMA wal_autocheckpoint=0;");
        try self.configurePageLimit();
        if (self.statement_cache == null) {
            const cache = try self.allocator.create([statement_cache_slots]CachedStatement);
            @memset(cache, .{});
            self.statement_cache = cache;
        }
        self.runtime_limits = true;
        const progress = @extern(*const fn (*Db, c_int, ?*const fn (?*anyopaque) callconv(.c) c_int, ?*anyopaque) callconv(.c) void, .{ .name = "sqlite3_progress_handler" });
        progress(self.db, 1000, workProgress, self);
    }
    pub fn workProgress(ctx: ?*anyopaque) callconv(.c) c_int {
        const self: *Store = @ptrCast(@alignCast(ctx.?));
        // Why: A nonzero return from the progress handler interrupts the running statement with SQLITE_INTERRUPT (sqlite3.h).
        if (self.work_remaining == 0) return 1;
        self.work_remaining -= 1;
        return 0;
    }
    pub fn maintainWal(self: *Store, database_path: []const u8) Error!void {
        const diag_span = if (comptime build_options.diag) diag_mod.enter(.wal) else {};
        defer if (comptime build_options.diag) diag_mod.leave(diag_span);
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
        if (comptime build_options.diag) diag_mod.gauge(.wal_bytes, stat.size);
        if (stat.size < 16 * 1024 * 1024) return;
        self.work_remaining = 1000;
        var row = try self.statement("PRAGMA wal_checkpoint(TRUNCATE);");
        defer row.deinit();
        if (!try row.row()) return error.DatabaseFailure;
        // Why: wal_checkpoint returns 1 in its first column when the checkpoint was blocked; 5 is SQLITE_BUSY (sqlite3.h).
        if (try row.signed(0) != 0) {
            self.last_error_code = 5;
            return error.Busy;
        }
    }

    pub fn beginWrite(self: *Store) Error!void {
        return self.beginClassWrite(.obligation);
    }
    pub fn beginIntakeWrite(self: *Store, pages: u64) Error!void {
        try self.beginClassWrite(.intake);
        self.admitIntake(pages) catch |failure| {
            self.rollback();
            return failure;
        };
    }
    pub fn beginClassWrite(self: *Store, class: budget.Class) Error!void {
        try self.usable();
        // Why: A startup admission already holds the write transaction; its operations nest as savepoints through beginAdmissionWrite.
        if (self.startup_admission) return error.DatabaseFailure;
        if (self.runtime_path) |path| try self.maintainWal(path);
        // Why: IMMEDIATE takes the write lock at BEGIN, so a busy database fails here rather than at the first write.
        try self.exec("BEGIN IMMEDIATE;");
        self.admission = class;
        self.retry_admission_work_left = 256;
        if (comptime build_options.diag) self.diagMarkChanges();
        self.row_tallies = .{};
        self.noted_count = 0;
        self.noted_ambiguous = false;
    }

    pub fn beginStartupAdmission(self: *Store) Error!void {
        try self.beginWrite();
        self.startup_admission = true;
        self.startup_rebind_effects_changed = false;
    }
    pub fn finishStartupAdmission(self: *Store) Error!void {
        if (!self.startup_admission or self.startup_operation) return error.DatabaseFailure;
        self.exec("COMMIT;") catch |failure| {
            if (self.startup_rebind_effects_changed) self.reopen_required = true;
            self.startup_rebind_effects_changed = false;
            return failure;
        };
        if (comptime build_options.diag) self.diagCommitted();
        self.startup_admission = false;
        const changed = self.startup_rebind_effects_changed;
        self.startup_rebind_effects_changed = false;
        if (changed) {
            if (self.effect_invalidation) |hook| hook.invalidate(hook.context);
            self.effect_publication_epoch +|= 1;
            const epoch = self.effect_publication_epoch;
            self.attributed_changes[@intCast(epoch % attribution_ring)] = .{ .epoch = epoch, .count = 0 };
        }
    }
    pub fn abortStartupAdmission(self: *Store) void {
        self.startup_rebind_effects_changed = false;
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
        self.retry_admission_work_left = 256;
        self.row_tallies = .{};
        try self.exec("SAVEPOINT native_startup_operation;");
        self.startup_operation = true;
        self.noted_count = 0;
        self.noted_ambiguous = false;
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
        const diag_span = if (comptime build_options.diag) diag_mod.enter(.commit) else {};
        defer if (comptime build_options.diag) diag_mod.leave(diag_span);
        self.row_tallies = .{};
        defer self.admission = .obligation;
        if (!self.startup_admission) {
            try self.assertIntake();
            try self.exec("COMMIT;");
            if (comptime build_options.diag) self.diagCommitted();
            return;
        }
        if (!self.startup_operation or self.api.get_autocommit(self.db) != 0) return error.DatabaseFailure;
        try self.exec("RELEASE native_startup_operation;");
        self.startup_operation = false;
    }

    // Holds: Effect views are invalidated before COMMIT and never restored here, so a failed COMMIT leaves them invalid.
    pub fn commitEffectTransaction(self: *Store, changed: bool) Error!void {
        if (comptime build_options.diag) self.diagRecountTallies();
        if (changed) if (self.effect_invalidation) |hook| hook.invalidate(hook.context);
        try self.commitTransaction();
        if (changed) {
            self.effect_publication_epoch +|= 1;
            const epoch = self.effect_publication_epoch;
            var slot = AttributedChange{ .epoch = epoch, .count = if (self.noted_ambiguous) 0 else self.noted_count };
            slot.keys = self.noted_keys;
            self.attributed_changes[@intCast(epoch % attribution_ring)] = slot;
        }
        self.noted_count = 0;
        self.noted_ambiguous = false;
    }
    fn diagRecountTallies(self: *Store) void {
        const diag_span = diag_mod.enter(.tally_check);
        defer diag_mod.leave(diag_span);
        const saved_work = self.work_remaining;
        const saved_error = self.last_error_code;
        defer {
            self.work_remaining = saved_work;
            self.last_error_code = saved_error;
        }
        inline for (comptime std.enums.values(TalliedTable)) |table| if (@field(self.row_tallies, @tagName(table))) |tallied| {
            self.work_remaining = 1000;
            if (self.integer("SELECT count(*) FROM " ++ @tagName(table) ++ ";")) |counted| {
                diag_mod.count(.consistency_checks, 1);
                if (counted != tallied) diag_mod.event(.consistency_mismatch, .{ .subject = @tagName(table), .cause = "row_tally", .value = @abs(counted - tallied) });
            } else |_| diag_mod.count(.consistency_skipped, 1);
        };
    }
    // Holds: A table is counted once per transaction; insertedRows and removedRows adjust the tally and deletedRows discards it.
    pub fn tableRows(self: *Store, table: TalliedTable) Error!i64 {
        switch (table) {
            inline else => |known| {
                const tally = &@field(self.row_tallies, @tagName(known));
                if (tally.* == null) {
                    const diag_span = if (comptime build_options.diag) diag_mod.enter(.capacity_count) else {};
                    defer if (comptime build_options.diag) diag_mod.leave(diag_span);
                    tally.* = try self.integer("SELECT count(*) FROM " ++ @tagName(known) ++ ";");
                }
                return tally.*.?;
            },
        }
    }
    pub fn insertedRows(self: *Store, table: TalliedTable, rows: i64) void {
        switch (table) {
            inline else => |known| if (@field(self.row_tallies, @tagName(known))) |*tally| {
                tally.* += rows;
            },
        }
    }
    pub fn removedRows(self: *Store, table: TalliedTable, rows: i64) void {
        switch (table) {
            inline else => |known| if (@field(self.row_tallies, @tagName(known))) |*tally| {
                tally.* -= rows;
            },
        }
    }
    pub fn deletedRows(self: *Store, table: TalliedTable) void {
        switch (table) {
            inline else => |known| @field(self.row_tallies, @tagName(known)) = null,
        }
    }
    pub const attribution_ring = 256;
    pub const attribution_batch = @import("group_commit.zig").max_batch_records;
    pub const AttributedChange = struct {
        epoch: u64 = 0,
        count: u8 = 0,
        keys: [attribution_batch]effects.Hash = undefined,
        pub fn slice(self: *const AttributedChange) []const effects.Hash {
            return self.keys[0..self.count];
        }
    };
    pub fn noteEffectChange(self: *Store, key: effects.Hash) void {
        for (self.noted_keys[0..self.noted_count]) |noted| if (std.mem.eql(u8, &noted, &key)) return;
        if (self.noted_count == attribution_batch) {
            self.noted_ambiguous = true;
            return;
        }
        self.noted_keys[self.noted_count] = key;
        self.noted_count += 1;
    }
    pub fn attributedChange(self: *const Store, epoch: u64) ?*const AttributedChange {
        if (epoch == 0) return null;
        const slot = &self.attributed_changes[@intCast(epoch % attribution_ring)];
        return if (slot.epoch == epoch and slot.count != 0) slot else null;
    }

    pub usingnamespace @import("schema.zig").Methods(@This());

    pub const CursorRebinding = struct { old: [32]u8, new: [32]u8 };
    pub const PolicyTransition = struct { jail: []const u8, generation: [32]u8, next_generation: [32]u8, expected: retry.Policy, next: retry.Policy, cursor_rebinding: ?CursorRebinding = null };
    pub usingnamespace @import("admin.zig").Methods(@This());

    pub usingnamespace @import("migration.zig").Methods(@This());

    pub usingnamespace @import("load_repair_migration.zig").Methods(@This());

    pub usingnamespace @import("ignore_entries.zig").Methods(@This());

    pub usingnamespace @import("continuity.zig").Methods(@This());

    pub usingnamespace @import("footprint.zig").Methods(@This());

    pub usingnamespace budget.Methods(@This());

    pub usingnamespace @import("ban_origins.zig").Methods(@This());

    pub usingnamespace @import("retry_release.zig").Methods(@This());

    pub usingnamespace @import("group_commit.zig").Methods(@This());

    pub usingnamespace @import("source_repair.zig").Methods(@This());

    pub usingnamespace @import("effect_repair.zig").Methods(@This());

    pub usingnamespace @import("jail_lifecycle.zig").Methods(@This());

    pub usingnamespace @import("config_deadlines.zig").Methods(@This());

    pub usingnamespace @import("diag_checks.zig").Methods(@This());

    pub fn inspectInteger(self: *Store, sql: [:0]const u8) Error!i64 {
        if (!@import("builtin").is_test) @compileError("inspectInteger is test-only");
        return self.integer(sql);
    }
    pub fn inspectExec(self: *Store, sql: [:0]const u8) Error!void {
        if (!@import("builtin").is_test) @compileError("inspectExec is test-only");
        return self.exec(sql);
    }

    pub usingnamespace @import("maintenance.zig").Methods(@This());

    pub usingnamespace @import("record_cleanup.zig").Methods(@This());

    pub usingnamespace @import("retry_retirement.zig").Methods(@This());

    pub usingnamespace @import("history.zig").Methods(@This());

    pub usingnamespace @import("history_retention.zig").Methods(@This());

    pub usingnamespace @import("action_targets.zig").Methods(@This());

    pub usingnamespace @import("prune.zig").Methods(@This());

    pub usingnamespace @import("effects.zig").Methods(@This());

    pub usingnamespace @import("effect_owners.zig").Methods(@This());

    pub usingnamespace @import("effect_settlement.zig").Methods(@This());

    pub usingnamespace @import("consumer_retry.zig").Methods(@This());

    pub usingnamespace @import("consumer_manifests.zig").Methods(@This());

    pub usingnamespace @import("shared_dns.zig").Methods(@This());

    pub usingnamespace @import("retry_projection.zig").Methods(@This());

    pub usingnamespace @import("custom_rebind.zig").Methods(@This());

    pub usingnamespace @import("open.zig").Methods(@This());

    pub usingnamespace @import("receipts.zig").Methods(@This());

    pub usingnamespace @import("record_commit.zig").Methods(@This());

    pub usingnamespace @import("source_positions.zig").Methods(@This());

    pub fn close(self: *Store) void {
        self.releaseStatementCache();
        _ = self.api.close(self.db);
        self.allocator.destroy(self.attributed_changes);
        self.* = undefined;
    }
    pub fn releaseStatementCache(self: *Store) void {
        const cache = self.statement_cache orelse return;
        for (cache) |slot| if (slot.stmt) |cached| {
            _ = self.api.finalize(cached);
        };
        self.allocator.destroy(cache);
        self.statement_cache = null;
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
    pub fn usable(self: *Store) Error!void {
        if (self.reopen_required) return error.ReopenRequired;
    }
    pub fn rollback(self: *Store) void {
        self.work_remaining = 1000;
        self.row_tallies = .{};
        self.admission = .obligation;
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
        if (!self.runtime_limits) return self.prepare(sql);
        const cache = self.statement_cache orelse return self.prepare(sql);
        const hash = std.hash.Wyhash.hash(0, sql);
        var index: usize = @intCast(hash % statement_cache_slots);
        const free = for (0..statement_cache_slots) |_| {
            const slot = &cache[index];
            const cached = slot.stmt orelse break index;
            // Why: Slots are keyed by a 64-bit hash, so the prepared text is compared to stop a collision returning the wrong statement.
            if (slot.hash == hash and preparedTextEql(cached, sql)) {
                if (slot.in_use) {
                    if (comptime build_options.diag) diag_mod.count(.statement_cache_bypasses, 1);
                    return self.prepare(sql);
                }
                slot.in_use = true;
                return .{ .store = self, .ptr = cached, .slot = slot };
            }
            index = (index + 1) % statement_cache_slots;
        } else {
            if (comptime build_options.diag) diag_mod.count(.statement_cache_bypasses, 1);
            return self.prepare(sql);
        };
        var stmt = try self.prepare(sql);
        if (!preparedTextEql(stmt.ptr, sql)) {
            if (comptime build_options.diag) diag_mod.count(.statement_cache_bypasses, 1);
            return stmt;
        }
        cache[free] = .{ .hash = hash, .stmt = stmt.ptr, .in_use = true };
        stmt.slot = &cache[free];
        return stmt;
    }
    fn prepare(self: *Store, sql: [:0]const u8) Error!Stmt {
        var ptr: ?*Statement = null;
        if (comptime build_options.diag) diag_mod.count(.statement_prepares, 1);
        try self.check(self.api.prepare(self.db, sql, -1, &ptr, null));
        return .{ .store = self, .ptr = ptr orelse return error.DatabaseFailure };
    }
    fn preparedTextEql(prepared: *Statement, sql: []const u8) bool {
        const sql_of = @extern(*const fn (*Statement) callconv(.c) ?[*:0]const u8, .{ .name = "sqlite3_sql" });
        const text = sql_of(prepared) orelse return false;
        return std.mem.eql(u8, std.mem.span(text), sql);
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
};
pub fn hashColumn(row: *Stmt, column: c_int) Error!?[32]u8 {
    const value = try row.boundedBytes(column, 32);
    return if (value.len == 32) value[0..32].* else null;
}
pub const Stmt = struct {
    store: *Store,
    ptr: *Statement,
    slot: ?*CachedStatement = null,
    pub fn deinit(self: *Stmt) void {
        const slot = self.slot orelse {
            _ = self.store.api.finalize(self.ptr);
            return;
        };
        const resetStatement = @extern(*const fn (*Statement) callconv(.c) c_int, .{ .name = "sqlite3_reset" });
        const clearBindings = @extern(*const fn (*Statement) callconv(.c) c_int, .{ .name = "sqlite3_clear_bindings" });
        _ = resetStatement(self.ptr);
        _ = clearBindings(self.ptr);
        slot.in_use = false;
    }
    // Why: A null destructor is SQLITE_STATIC (sqlite3.h): SQLite keeps the pointer, so bound bytes must outlive every step.
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
    // Why: Column type codes are SQLITE_INTEGER 1, SQLITE_TEXT 3, SQLITE_BLOB 4 and SQLITE_NULL 5 (sqlite3.h).
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
        // Why: 100 is SQLITE_ROW, 101 SQLITE_DONE and 9 SQLITE_INTERRUPT, which the work-budget progress handler raises (sqlite3.h).
        return switch (rc) {
            100 => true,
            101 => false,
            else => blk: {
                if (rc == 9) {
                    const sql_of = @extern(*const fn (*Statement) callconv(.c) ?[*:0]const u8, .{ .name = "sqlite3_sql" });
                    if (sql_of(self.ptr)) |sql_text| {
                        const sql = std.mem.span(sql_text);
                        std.log.warn("storage: work budget exhausted by: {s}", .{sql[0..@min(sql.len, 200)]});
                    }
                }
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
            // Why: A null pointer is an empty or NULL value or an allocation failure; only the error code tells them apart (sqlite3.h).
            if (self.store.api.extended_errcode(self.store.db) == 7) try self.store.check(7);
            return "";
        }
        const length = self.store.api.column_bytes(self.ptr, column);
        if (length <= 0) return "";
        const ptr: [*]const u8 = @ptrCast(data.?);
        return ptr[0..@intCast(length)];
    }
};
