// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Admits configuration, state and firewall at startup, then runs ingestion, enforcement and recovery on one worker thread.
// Holds: Only the worker writes the store, jails and firewall; IPC and HTTP handlers stage requests and read state under the mutex.

const std = @import("std");
const shared = @import("shared");
const config = @import("../config/config.zig");
const projection = @import("../config/file_detection.zig");
const retry_config = @import("../config/retry_policy.zig");
const retry = @import("../detect/retry.zig");
const detection = @import("../detect/detection_record.zig");
const timezone = @import("../time/timezone.zig");
const effect = @import("../effect/effect.zig");
const effect_runtime = @import("../runtime/effect_runtime.zig");
pub const firewall_observation = effect_runtime.observation;
const consumer_runtime = @import("../runtime/consumer_runtime.zig");
const consumer_plan = @import("../config/consumer_plan.zig");
const resource = @import("../runtime/resource_budget.zig");
const history = @import("../effect/effect_history.zig");
const firewall_backend = @import("../firewall/backend.zig");
const inspection = @import("../firewall/inspection.zig");
const path_guard = @import("../config/paths.zig");
const durable = @import("../store/store.zig");
const sessions = @import("../source/file_session.zig");
const journal_projection = @import("../config/journal_detection.zig");
const journal_profile = @import("../config/journal_profile.zig");
const filter_registry = @import("../filters/registry.zig");
const files = @import("../source/durable_file_source.zig");
const ignore_set = @import("../detect/ignore_set.zig");

// Why: The match list is hashed into the journal source generation, so editing either list fails admission of existing state.
const legacy_ssh_matches: []const []const u8 = &.{ "SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session", "+", "_COMM=sshd", "_COMM=sshd-session" };
const auth_ssh_matches: []const []const u8 = &.{
    "SYSLOG_IDENTIFIER=sshd",
    "SYSLOG_IDENTIFIER=sshd-session",
    "SYSLOG_IDENTIFIER=sshd-auth",
    "+",
    "_COMM=sshd",
    "_COMM=sshd-session",
    "_COMM=sshd-auth",
};
const journal_sessions = @import("../source/journal_session.zig");
const health = @import("../platform/storage_health.zig");
const recovery = @import("../source/recovery.zig");
const loop_mod = @import("../platform/event_loop.zig");
const ipc = @import("../net/ipc.zig");
const http = @import("../net/http.zig");
const build_options = @import("build_options");
pub const version = build_options.version;
const diag_mod = @import("../diag/diag.zig");
const clock_mod = @import("../time/clock.zig");
const reload_mod = @import("../runtime/reload.zig");
const custom_rebind = @import("../runtime/custom_rebind.zig");
const query_v1 = @import("../net/query_v1.zig");
const sd_notify = @import("../platform/sd_notify.zig");
const log_target = @import("../platform/log_target.zig");
const metrics_mod = @import("../diag/metrics.zig");
const source_repair = @import("../store/source_repair.zig");
pub const max_jails = 64;
pub const max_sources_per_jail = 8;
pub const max_source_status_per_jail = 2 * max_sources_per_jail + 1;
pub const recovery_validation_budget_ns = 100 * std.time.ns_per_ms;
pub const tick_wait_ns = 100 * std.time.ns_per_ms;

const Plan = union(enum) {
    file: projection.Plan,
    journal: *journal_projection.Plan,
    internal: [32]u8,
    pub fn deinit(self: *Plan, a: std.mem.Allocator) void {
        switch (self.*) {
            .file => |*plan| plan.deinit(a),
            .journal => |plan| plan.destroy(),
            .internal => {},
        }
    }
};
pub const Source = union(enum) {
    file: *sessions.Session,
    journal: *journal_sessions.Session,
    internal: [32]u8,
    pub fn destroy(self: Source) void {
        switch (self) {
            .file => |source| source.destroy(),
            .journal => |source| source.destroy(),
            .internal => {},
        }
    }
    pub fn generation(self: Source) [32]u8 {
        return switch (self) {
            .file => |source| source.processor.generation,
            .journal => |source| source.processor.generation,
            .internal => |value| value,
        };
    }
    const ingest_burst = 4;
    pub fn poll(self: Source) !usize {
        var admitted: usize = 0;
        var turns: usize = 0;
        while (turns < ingest_burst) : (turns += 1) {
            const delivered = switch (self) {
                .file => |source| file_turn: {
                    const diag_span = if (comptime build_options.diag) diag_mod.enter(.file) else {};
                    defer if (comptime build_options.diag) diag_mod.leave(diag_span);
                    break :file_turn try source.pollTurn(1);
                },
                .journal => |source| journal_turn: {
                    const diag_span = if (comptime build_options.diag) diag_mod.enter(.journal) else {};
                    defer if (comptime build_options.diag) diag_mod.leave(diag_span);
                    break :journal_turn try source.pollTurn(1);
                },
                .internal => return 0,
            };
            if (delivered == 0) break;
            if (comptime build_options.diag) diag_mod.count(if (self == .file) .file_records else .journal_records, delivered);
            admitted += delivered;
        }
        if (comptime build_options.diag) if (turns == ingest_burst) diag_mod.count(.ingest_full_bursts, 1);
        return admitted;
    }
    pub fn verify(self: Source) !bool {
        return switch (self) {
            .file => |source| try source.verifyRecoverySourcesTurn(),
            .journal => |source| try source.verifyRecoverySourcesTurn(),
            .internal => true,
        };
    }
    pub fn healthy(self: Source) bool {
        return switch (self) {
            .file => |source| source.admission_phase == .ready and (source.sources.sources.items.len > 0 or source.awaiting_discovery) and source.repairSnapshot().phase == .healthy and source.blocked_cause == null,
            .journal => |source| source.admission_phase == .ready and source.source_health == .healthy and source.repairSnapshot().phase == .healthy,
            .internal => true,
        };
    }
    pub fn exportRecovery(self: Source) !SourceSnapshot {
        return switch (self) {
            .file => |value| .{ .file = try value.exportRecovery() },
            .journal => |value| .{ .journal = try value.exportRecovery() },
            .internal => .internal,
        };
    }
    pub fn importRecovery(self: Source, snapshot: SourceSnapshot) !void {
        switch (self) {
            .file => |value| if (snapshot == .file) try value.importRecovery(snapshot.file) else return error.SourceGenerationMismatch,
            .journal => |value| if (snapshot == .journal) try value.importRecovery(snapshot.journal) else return error.SourceGenerationMismatch,
            .internal => if (snapshot != .internal) return error.SourceGenerationMismatch,
        }
    }
    pub fn resumeConsumer(self: Source, identity: []const u8) !void {
        switch (self) {
            .file => |value| _ = try value.resumeConsumerSource(identity),
            .journal => |value| _ = try value.resumeConsumerSource(identity),
            .internal => return error.ConsumerRuntimeNotReady,
        }
    }
};
const SourceSnapshot = union(enum) {
    file: *sessions.RecoverySnapshot,
    journal: *journal_sessions.RecoverySnapshot,
    internal,
    pub fn destroy(self: SourceSnapshot) void {
        switch (self) {
            .file => |value| value.destroy(),
            .journal => |value| value.destroy(),
            .internal => {},
        }
    }
};
pub const MaintenanceMark = struct { committed: u64, epoch: u64, retry_revision: u64 };
pub const EffectMark = struct { view_revision: u64, epoch: u64, trusted: bool, enforces: bool };
const RetirementPass = struct {
    after: ?detection.Subject = null,
    next_us: ?i64 = null,
    retry_revision: ?u64 = null,
    effect_revision: ?u64 = null,
    generation: ?[32]u8 = null,
    dirty: bool = false,
    parked: bool = false,
    max: usize = durable.Store.max_retirement_batch,
};
pub const DisableProgress = struct {
    request_id: effect.Hash,
    after: ?effect.Hash = null,
    phase: enum { releasing, verifying, complete } = .releasing,
    cause: ?anyerror = null,
};
pub const Jail = struct {
    name: []const u8,
    plan: Plan,
    policy: retry.Policy,
    session: ?Source = null,
    source_snapshot: ?SourceSnapshot = null,
    custom_plan: ?*consumer_plan.Prepared = null,
    consumer: ?*consumer_runtime.JailRuntime = null,
    active: []durable.Store.ActiveDecision = &.{},
    summary: struct { decisions: u64 = 0 } = .{},
    owner_range: OwnerRange = .{},
    retry_revision: ?u64 = null,
    published_once: bool = false,
    next_expiry_us: ?i64 = null,
    revision: u64 = 0,
    healthy: bool = false,
    source_error: ?anyerror = null,
    source_missing: bool = false,
    source_diagnostic: ?journal_sessions.FailureDiagnostic = null,
    last_journal_notice: ?journal_sessions.FailureDiagnostic = null,
    zone: ?*timezone.Zone = null,
    retirement: RetirementPass = .{},
    rekeyed: bool = false,
    admin_paused: bool = false,
    admin_enabled: bool = true,
    disable_progress: ?DisableProgress = null,
    disable_cleanup_pending: bool = false,
    on_truncation: config.TruncationPolicy = .refuse,
    ignore_runtime_only: u16 = 0,
    source_status: []SourceStatus = &.{},
    source_status_arena: ?std.heap.ArenaAllocator = null,
    source_signature: SourceSignature = .{},
    decay: retry.EscalationDecay = .{},
    banlist_pending: bool = true,
    banlist_waiting: u32 = 0,
    banlist_retry_ms: u64 = 0,
    retiring: bool = false,
    removal_cursor: durable.Store.JailRetirementCursor = .{},
    removal_withdrawal: effect_runtime.JailRetirementWithdrawalCursor = .{},
    removal_max_rows: u8 = 64,
    removal_bans_lifted: u32 = 0,
    removal_owners_released: u32 = 0,
    failures_carried: u64 = 0,
    ignored_carried: u64 = 0,
    manual_bans: u64 = 0,
    config_bans: u64 = 0,
    reservation: ?resource.Token = null,
};

pub const OwnerRange = struct { start: usize = 0, len: usize = 0 };
pub const PublishedRetryPool = struct { sample: ?durable.Store.RetryPoolSample = null, pending: bool = true };

pub const SourceStatus = struct {
    jail: []const u8,
    kind: enum { file, journal },
    path: ?[]const u8,
    on_truncation: ?config.TruncationPolicy,
    state: enum { paused, reading, missing, waiting, broken },
    cause: ?[]const u8,
    inode: ?u64,
    committed_offset: ?u64,
    observed_size: ?u64,
    repair: ?[]const u8,
    loss_events: u16,
    last_loss: ?files.LossEvent,
};

pub const SourceSignature = struct {
    sources: usize = 0,
    configured: usize = 0,
    presence_revision: u64 = 0,
    presence_known: bool = true,
    causes: [max_sources_per_jail + 1]?anyerror = [_]?anyerror{null} ** (max_sources_per_jail + 1),
    loss_sequence: u64 = 0,
    stuck: ?anyerror = null,
    built: bool = false,
};

pub const WritablePath = enum { state, socket };
pub fn logSandboxHint(err: anyerror, path: []const u8, kind: WritablePath) void {
    if (err != error.ReadOnlyFileSystem and err != error.AccessDenied) return;
    const dir = std.fs.path.dirname(path) orelse "/";
    std.log.err(
        "native: the service cannot write the {s} directory '{'}'; the shipped systemd unit allows writes only to directories it grants (ProtectSystem=strict); add the unit override from the installation guide, \"Custom state directory under systemd\" (the installer prints it for your configuration)",
        .{ @tagName(kind), std.zig.fmtEscapes(dir[0..@min(dir.len, 256)]) },
    );
}
pub fn destroyZone(a: std.mem.Allocator, zone: ?*timezone.Zone) void {
    if (zone) |value| {
        value.deinit();
        a.destroy(value);
    }
}
fn loadZone(a: std.mem.Allocator, root: []const u8, id: []const u8, ambiguity: timezone.Ambiguity) !*timezone.Zone {
    const zone = try a.create(timezone.Zone);
    errdefer a.destroy(zone);
    zone.* = try timezone.Zone.load(a, root, id, ambiguity);
    return zone;
}

const BackendAdmission = union(enum) {
    not_needed,
    selected: struct { installation: effect.Installation, persisted: bool },
    unavailable: anyerror,
};

fn requestedBackend(selection: config.FirewallSelection) ?firewall_backend.BackendTag {
    return switch (selection) {
        .auto => null,
        .nftables => .nftables,
        .ipset => .ipset,
        .iptables => .iptables,
    };
}

fn effectBackend(tag: firewall_backend.BackendTag) effect.Backend {
    return switch (tag) {
        .nftables => .nftables,
        .ipset => .ipset,
        .iptables => .iptables,
    };
}

fn transportBackend(tag: effect.Backend) firewall_backend.BackendTag {
    return switch (tag) {
        .nftables => .nftables,
        .ipset => .ipset,
        .iptables => .iptables,
    };
}

fn backendCauseName(cause: anyerror) []const u8 {
    return switch (cause) {
        error.KernelUnsupported => firewall_backend.causeName(error.KernelUnsupported),
        error.PermissionDenied => firewall_backend.causeName(error.PermissionDenied),
        error.Transient => firewall_backend.causeName(error.Transient),
        error.IpsetUnavailable => firewall_backend.causeName(error.IpsetUnavailable),
        error.IptablesUnavailable => firewall_backend.causeName(error.IptablesUnavailable),
        else => @errorName(cause),
    };
}

fn logInstallationConflict(cfg: *const config.Config, saved: effect.Installation) void {
    const fail_closed = cfg.global.on_no_backend == .@"fail-closed";
    const disposition = if (fail_closed)
        "refusing to run unprotected"
    else
        "running DEGRADED as log-only per on_no_backend";
    if (!std.mem.eql(u8, saved.selector(), cfg.global.firewall_namespace)) {
        const message = "firewall: saved namespace selector '{'}' conflicts with requested selector '{'}' (InstallationMismatch); restore the previous firewall_namespace with the existing state database; {s}";
        const args = .{ std.zig.fmtEscapes(saved.selector()), std.zig.fmtEscapes(cfg.global.firewall_namespace), disposition };
        if (fail_closed) std.log.err(message, args) else std.log.warn(message, args);
    } else {
        const message = "firewall: saved backend '{s}' conflicts with requested backend '{s}' (InstallationMismatch); restore firewall = \"{s}\" or \"auto\" with the existing state database; {s}";
        const args = .{ @tagName(saved.backend), @tagName(cfg.global.firewall), @tagName(saved.backend), disposition };
        if (fail_closed) std.log.err(message, args) else std.log.warn(message, args);
    }
}

pub fn logStateOpenFailure(operation: []const u8, path: []const u8, failure: anyerror, detail: durable.OpenDiagnostic) void {
    const prefix = path[0..@min(path.len, 256)];
    std.log.warn("native: state {s} failed: {s}; stage={s}; posix_cause={s}; sqlite_code={?d}; path='{'}'{s}", .{
        operation,                                                @errorName(failure),
        if (detail.stage) |stage| @tagName(stage) else "unknown", if (detail.posix_cause) |cause| @tagName(cause) else "none",
        detail.sqlite_code,                                       std.zig.fmtEscapes(prefix),
        if (prefix.len != path.len) " [path truncated]" else "",
    });
}

pub fn lockFirewallNamespace(cfg: *const config.Config) !std.fs.File {
    const file = try std.fs.openFileAbsolute(cfg.global.firewall_namespace, .{});
    errdefer file.close();
    const current = try std.fs.openFileAbsolute("/proc/self/ns/net", .{});
    defer current.close();
    const selected = try std.posix.fstat(file.handle);
    const active = try std.posix.fstat(current.handle);
    if (selected.dev != active.dev or selected.ino != active.ino) return error.FirewallNamespaceMismatch;
    // Why: The exclusive lock on the namespace file refuses a second daemon enforcing in the same network namespace.
    if (!try file.tryLock(.exclusive)) return error.NativeNamespaceAlreadyRunning;
    return file;
}
// Holds: Only reads the kernel; a saved installation whose selector or backend differs from the configuration is refused as a mismatch.
pub fn preflightBackend(a: std.mem.Allocator, cfg: *const config.Config, enforcing: bool, persisted: ?effect.Installation) BackendAdmission {
    if (!enforcing) {
        std.log.info("firewall: every enabled jail is log-only; backend detection skipped", .{});
        return .not_needed;
    }
    if (persisted) |saved| {
        if (!std.mem.eql(u8, saved.selector(), cfg.global.firewall_namespace)) return .{ .unavailable = error.InstallationMismatch };
        if (requestedBackend(cfg.global.firewall)) |requested| if (requested != transportBackend(saved.backend)) return .{ .unavailable = error.InstallationMismatch };
    }
    const selected = (if (persisted) |saved|
        firewall_backend.detectExact(a, transportBackend(saved.backend))
    else
        firewall_backend.detect(a, requestedBackend(cfg.global.firewall))) catch |cause| return .{ .unavailable = cause };
    var id: [16]u8 = undefined;
    std.crypto.random.bytes(&id);
    const candidate = persisted orelse effect.Installation.init(id, effectBackend(selected.tag()), cfg.global.firewall_namespace) catch |cause| return .{ .unavailable = cause };
    var probe = inspection.Inspector.open(a, effect_runtime.transportInstallation(candidate), .{}) catch |cause| {
        std.log.warn("firewall {s}: admission probe open failed ({s}); no mutation attempted", .{ @tagName(candidate.backend), @errorName(cause) });
        return .{ .unavailable = cause };
    };
    defer probe.close();
    var observed = probe.inspect() catch |cause| {
        std.log.warn("firewall {s}: admission readback failed ({s}); no mutation attempted", .{ @tagName(candidate.backend), @errorName(cause) });
        return .{ .unavailable = cause };
    };
    observed.deinit();
    if (persisted == null) {
        // Why: DumpInterrupted means the tables changed during the read, not that the backend is unusable, so it gets up to three attempts.
        var attempt: u8 = 1;
        while (true) : (attempt += 1) {
            probe.inspectReservedNamespace() catch |cause| {
                if (cause == error.DumpInterrupted and attempt < 3) continue;
                std.log.warn("firewall {s}: reserved namespace inspection failed ({s}); no mutation attempted", .{ @tagName(candidate.backend), @errorName(cause) });
                return .{ .unavailable = cause };
            };
            break;
        }
    }
    return .{ .selected = .{ .installation = candidate, .persisted = persisted != null } };
}

const PublishedView = struct {
    readback_ns: ?u64 = null,
    readback_wall_us: ?i64 = null,
    installed_live: u32 = 0,
    pending: u64 = 0,
    oldest_pending_us: ?i64 = null,
    overdue: u64 = 0,
    oldest_overdue_us: ?i64 = null,
    overdue_blocking: u64 = 0,
    oldest_overdue_blocking_us: ?i64 = null,
    dump_interrupted: u64 = 0,
    verify_interval_ns: u64 = 0,
    wake_interval_ns: u64 = 0,
    transient_uncertain: bool = false,
    events_subscribed: bool = false,
    events_healthy: bool = false,
};
pub const Knowledge = enum { fresh, stale, none };
pub const MaintenanceGates = struct {
    slow: u64 = 0,
    due: u64 = 0,
    turns: u64 = 0,
    unhealthy_gate: u64 = 0,
    step_progress: u64 = 0,
    step_returned: u64 = 0,
    step_wait: u64 = 0,
    record_passes: u64 = 0,
    record_deletes: u64 = 0,
    records_parked: u64 = 0,
};
pub const Coordinator = struct {
    allocator: std.mem.Allocator,
    cfg: *const config.Config,
    jails: []Jail,
    store: durable.Store,
    store_open: bool = false,
    last_open_failure: ?durable.OpenDiagnostic = null,
    last_identity_failure: ?anyerror = null,
    authority_lock: ?std.fs.File = null,
    namespace_lock: ?std.fs.File = null,
    retirement_effect_reservation: ?resource.Token = null,
    retirement_manager_only: bool = false,
    retirement_namespace_only: bool = false,
    effects: ?*effect_runtime.Manager = null,
    dns: ?*consumer_runtime.DnsRuntime = null,
    dns_generation: [32]u8 = [_]u8{0} ** 32,
    dns_server: ?std.net.Address = null,
    history_consumer: ?history.Consumer = null,
    history_page: ?history.PageToken = null,
    history_commit_pages: u8 = durable.Store.max_history_commit_pages,
    custom_jails: usize = 0,
    published_effects: ?effect_runtime.Health = null,
    published_view: PublishedView = .{},
    published_stats: query_v1.Stats = .{},
    stats_published_ms: ?u64 = null,
    stats_generation: [32]u8 = [_]u8{0} ** 32,
    published_backend: []const u8 = "none",
    startup_backend: ?effect.Backend = null,
    startup_installation: ?effect.Installation = null,
    startup_installation_persisted: bool = false,
    preflight_schema_version: i64 = 0,
    preflight_installation: ?effect.Installation = null,
    backend_failure: ?anyerror = null,
    suppress_enforcement: bool = false,
    published_confirmations: u64 = 0,
    confirmations_epoch: ?u64 = null,
    confirmations_count: u64 = 0,
    decision_scratch: []durable.Store.ActiveDecision = &.{},
    owner_scratch: []durable.Store.OperatorOwner = &.{},
    owner_active: []durable.Store.OperatorOwner = &.{},
    owner_scratch_confirmed: []bool = &.{},
    owner_confirmed: []bool = &.{},
    owner_count: usize = 0,
    owner_read_epoch: ?u64 = null,
    published_owners_mark: ?EffectMark = null,
    owner_publication_pending: bool = true,
    owner_rebuild: ?struct { epoch: u64, count: usize = 0, after: ?durable.Store.OperatorOwner = null } = null,
    clock: clock_mod.Clock,
    gate: health.Gate,
    published_health: health.Snapshot,
    worker_observation: health.WorkerObservation = .{},
    maintenance_validation: durable.Store.MaintenanceValidation = .{},
    maintenance_validated: bool = false,
    ownership_fenced: bool = false,
    fairness: health.Fairness = .{},
    mutex: std.Thread.Mutex = .{},
    stop_mutex: std.Thread.Mutex = .{},
    wake: std.Thread.Condition = .{},
    stopping: bool = false,
    effect_backlog: bool = false,
    disable_next_jail: usize = 0,
    last_view_report_ms: ?u64 = null,
    retire_jail: usize = 0,
    removal_next_jail: usize = 0,
    startup_retirement_progress: u64 = 0,
    last_slow_tick_ms: ?u64 = null,
    last_committed_records: u64 = 0,
    history_caught_up: bool = false,
    history_wait: ?anyerror = null,
    shed: durable.Store.ShedCounts = .{},
    shed_logged: durable.Store.ShedCounts = .{},
    shed_notice_ms: ?u64 = null,
    reclaim_ms: ?u64 = null,
    maintenance_progress: bool = false,
    maintenance_idle: ?MaintenanceMark = null,
    maintenance_idle_since_ms: u64 = 0,
    records_idle: ?MaintenanceMark = null,
    records_idle_since_ms: u64 = 0,
    last_history_ms: ?u64 = null,
    retire_batches: u64 = 0,
    retired_total: u64 = 0,
    retire_examined: u64 = 0,
    retire_pinned_state: u64 = 0,
    retire_pinned_effect: u64 = 0,
    retire_refused: u64 = 0,
    last_view_counters: effect_runtime.Counters = .{},
    gates: MaintenanceGates = .{},
    last_gate_report_ms: ?u64 = null,
    thread: ?std.Thread = null,
    start_us: i64,
    last_notice: u64 = 0,
    last_effect_notice: ?effect_runtime.EffectDiagnostic = null,
    recovery_generation: ?u64 = null,
    restore_jail: usize = 0,
    verify_jail: usize = 0,
    rebuild_phase: enum { maintenance, capture, drop, resolver, owners, consumers, history, validation, retry_projection, done } = .maintenance,
    validation_phase: enum { sources, begin, resolver, owners, final, done } = .sources,
    validation_jail: usize = 0,
    consumer_cursor: [durable.Limits.source_bytes]u8 = undefined,
    consumer_cursor_len: usize = 0,
    consumer_scan_revision: ?u64 = null,
    resources: resource.Ledger,
    resource_reservation: ?resource.Token = null,
    firewall_observation_cache: ?*firewall_observation.Cache = null,
    firewall_observation_unavailable: query_v1.FirewallUnavailableReason = .no_manager,
    config_path: []const u8 = "",
    live_cfg: *const config.Config,
    live_arena: ?*std.heap.ArenaAllocator = null,
    reload_request: ?*ReloadRequest = null,
    admin_request: ?*AdminRequest = null,
    reload_wake: std.Thread.Condition = .{},
    published_revision: u64 = 0,
    withdrawn_warned_ms: ?u64 = null,
    notifier: ?*const sd_notify.Notifier = null,
    notified_ready: bool = false,
    reload_ready_pending: bool = false,
    startup_progress: ?*sd_notify.Progress = null,
    readiness_progress_started_ns: ?i128 = null,
    readiness_progress_done: u64 = 0,
    readiness_history_pages: u64 = 0,
    readiness_history_head: ?u64 = null,
    history_reader: ?durable.Store = null,
    admin_serving: ?*const std.atomic.Value(bool) = null,
    published_generation: [32]u8 = [_]u8{0} ** 32,
    published_config_digest: [32]u8 = [_]u8{0} ** 32,
    generation_admitted: bool = false,
    jail_storage: []Jail = &.{},
    self_addresses: ?shared.self_addresses.SelfAddresses = null,
    metrics_state: metrics_mod.Metrics = .{},
    published_pool: PublishedRetryPool = .{},
    published_footprint: ?@import("../store/footprint.zig").StateFileFootprint = null,
    published_intake_waiting: bool = false,
    last_pool_ms: ?u64 = null,
    last_ignore_expiry_ms: ?u64 = null,

    pub const ReloadKind = enum { applied, noop, rejected, restart_required, uncertain, partial };
    pub const ReloadOutcome = struct {
        kind: ReloadKind,
        generation: [32]u8 = [_]u8{0} ** 32,
        reasons: [reload_mod.max_reasons]reload_mod.Reason = undefined,
        reason_count: u8 = 0,
        pub fn single(kind: ReloadKind, comptime fmt: []const u8, args: anytype) ReloadOutcome {
            var out = ReloadOutcome{ .kind = kind };
            var reason: reload_mod.Reason = .{};
            const written = std.fmt.bufPrint(&reason.bytes, fmt, args) catch reason.bytes[0..0];
            reason.len = @intCast(written.len);
            out.reasons[0] = reason;
            out.reason_count = 1;
            return out;
        }
        pub fn reasonSlice(self: *const ReloadOutcome) []const reload_mod.Reason {
            return self.reasons[0..self.reason_count];
        }
    };
    pub const ReloadRequest = struct {
        config_digest: [32]u8,
        proposed: *const config.Config,
        arena: ?*std.heap.ArenaAllocator,
        outcome: ?ReloadOutcome = null,
        done: bool = false,
        abandoned: bool = false,
    };

    pub fn monotonic(ctx: ?*anyopaque) u64 {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        return self.clock.monotonicMs();
    }

    pub const AdminOutcomeView = struct {
        outcome: durable.Store.AdminOutcome,
        kind: durable.Store.AdminKind,
        generation: [32]u8 = [_]u8{0} ** 32,
        mutation_revision: u64 = 0,
        enforced: bool = false,
        reason: reload_mod.Reason = .{},
        destination: ?[]const u8 = null,
        pub fn withOutcome(self: AdminOutcomeView, outcome: durable.Store.AdminOutcome) AdminOutcomeView {
            var out = self;
            out.outcome = outcome;
            return out;
        }
        pub fn withReason(self: AdminOutcomeView, comptime fmt: []const u8, args: anytype) AdminOutcomeView {
            var out = self;
            const written = std.fmt.bufPrint(&out.reason.bytes, fmt, args) catch out.reason.bytes[0..0];
            out.reason.len = @intCast(written.len);
            return out;
        }
    };
    pub const AdminPhase = enum { staged, executing, awaiting, done };
    pub const AdminRequest = struct {
        request_id: [32]u8,
        kind: durable.Store.AdminKind,
        jail: [64]u8 = undefined,
        jail_len: u8 = 0,
        address: ?shared.IpAddress = null,
        prefix: ?u8 = null,
        duration_s: ?u64 = null,
        all: bool = false,
        expected_generation: [32]u8,
        expected_revision: u64,
        phase: AdminPhase = .staged,
        deadline_ms: u64 = 0,
        scope_key: [32]u8 = [_]u8{0} ** 32,
        expect_absent: bool = false,
        pending_state: ?durable.Store.JailAdminState = null,
        mutation_committed: bool = false,
        committed_count: u64 = 0,
        disable_revision: u64 = 0,
        outcome: ?AdminOutcomeView = null,
        abandoned: bool = false,
        run_id: ?[32]u8 = null,
        verify_seq: u64 = 0,
        unban: bool = false,
        ignore_entry: ?shared.types.IgnoreEntry = null,
        ignore: ?*IgnoreWork = null,
        warning: reload_mod.Reason = .{},
        repair_path: [durable.Limits.source_bytes]u8 = undefined,
        repair_path_len: usize = 0,
        repair_token: [source_repair.max_token_bytes]u8 = undefined,
        repair_token_len: usize = 0,
        repair_shape: ?source_repair.Shape = null,
        resumed_offset: ?u64 = null,
        pub fn jailName(self: *const AdminRequest) []const u8 {
            return self.jail[0..self.jail_len];
        }
    };
    pub usingnamespace @import("admin.zig").Methods(@This());
    pub usingnamespace @import("admin_ignore.zig").Methods(@This());
    pub usingnamespace @import("admin_migration.zig").Methods(@This());
    pub const max_lifted_bans = 256;
    const max_wider_bans = 128;
    pub const IgnoreEntryState = enum { added, present, removed, config_only, absent, not_recorded, not_removed };
    pub const IgnoreRelation = enum { inside_entry, contains_entry };
    const IgnoreLift = enum { kept, pending, confirmed, incomplete, unknown, refused };
    const IgnoreBan = struct {
        canonical: inspection.CanonicalScope,
        key: [32]u8,
        deadline_us: ?i64,
        confirmed: bool,
        relation: IgnoreRelation,
        lift: IgnoreLift = .kept,
        reason: ?[]const u8 = null,
    };
    pub const IgnoreWork = struct {
        entry_state: IgnoreEntryState = .not_recorded,
        source: ?ignore_set.Source = null,
        configured: [ignore_set.max_entries_per_part]shared.types.IgnoreEntry = undefined,
        configured_count: usize = 0,
        bans: [max_lifted_bans + max_wider_bans]IgnoreBan = undefined,
        ban_count: usize = 0,
        bans_total: usize = 0,
        inside_total: usize = 0,
        lifting: bool = false,
        mutated: bool = false,
        expires_us: ?i64 = null,
        jail_enabled: bool = true,
        jail_paused: bool = false,
    };

    pub fn bindDecay(jail: *Jail) void {
        if (jail.session) |source| switch (source) {
            .file => |value| value.processor.retry_decay = jail.decay,
            .journal => |value| value.processor.retry_decay = jail.decay,
            .internal => {},
        };
    }
    pub fn setJailPaused(jail: *Jail, paused: bool) void {
        if (jail.session) |source| switch (source) {
            .file => |value| value.processor.paused = paused,
            .journal => |value| value.processor.paused = paused,
            .internal => {},
        };
    }
    pub fn leaveRealizedEffects(self: *Coordinator) void {
        const manager = self.effects orelse return;
        const phase = self.gate.snapshot().phase;
        const residual = manager.residualInstalled();
        if (phase != .healthy or !self.store_open or self.store.reopen_required) {
            if (residual.installed) |count| {
                std.log.warn("native: stop with storage {s} left {d} realized rules in place; restart reconciles them", .{ @tagName(phase), count });
            } else std.log.warn("native: stop with storage {s} left realized rules in place; inventory unreadable: {s}", .{ @tagName(phase), @errorName(residual.cause.?) });
            return;
        }
        if (residual.installed) |count| {
            std.log.info("native: stop left {d} realized rules in place; the next start reconciles them", .{count});
        } else std.log.warn("native: stop left realized rules in place; inventory unreadable: {s}; the next start reconciles them", .{@errorName(residual.cause.?)});
    }
    const withdrawn_warn_interval_ms: u64 = 60 * 60 * 1000;
    fn warnWithdrawn(self: *Coordinator, manager: *effect_runtime.Manager) void {
        const now = monotonic(self);
        if (self.withdrawn_warned_ms) |last| if (now -| last < withdrawn_warn_interval_ms) return;
        self.withdrawn_warned_ms = now;
        std.log.warn("native: enforcement withdrawn by firewall withdraw; {d} realized rules in the kernel; restart fail2zig to reinstall live bans", .{manager.installed_live});
    }
    pub fn stopRequested(ctx: ?*anyopaque) bool {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        self.stop_mutex.lock();
        defer self.stop_mutex.unlock();
        return self.stopping;
    }
    pub fn effectSlice(self: *Coordinator, manager: *effect_runtime.Manager) !bool {
        var bindings: [max_jails]effect_runtime.Binding = undefined;
        self.effectBindings(&bindings);
        const slice = manager.runSlice(bindings[0..self.jails.len], .{}, .{ .context = self, .requested = stopRequested });
        self.effect_backlog = slice.outcome == .progress;
        if (manager.withdrawn) self.warnWithdrawn(manager);
        return switch (slice.outcome) {
            .idle => true,
            .fatal => |failure| failure,
            .progress, .wait, .stop => false,
        };
    }
    pub fn wallClockEffect(ctx: ?*anyopaque) i64 {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        return self.clock.wallUs();
    }
    pub fn wallClock(ctx: ?*anyopaque) !i64 {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        return self.clock.wallUs();
    }
    pub fn observationMs() ?u64 {
        const sample = std.posix.clock_gettime(.MONOTONIC) catch return null;
        if (sample.sec < 0 or sample.nsec < 0 or sample.nsec >= std.time.ns_per_s) return null;
        return std.math.cast(u64, @as(i128, sample.sec) * 1000 + @divTrunc(sample.nsec, std.time.ns_per_ms));
    }
    pub fn observationWall(self: *Coordinator) ?i64 {
        return self.clock.wallUs();
    }
    pub fn observedWorker(self: *Coordinator) health.WorkerStatus {
        return self.worker_observation.read(observationMs(), self.observationWall());
    }
    pub fn observationSound(observation: health.WorkerStatus) bool {
        return !observation.stalled and !observation.clock_uncertain;
    }
    pub fn overBlocking(self: *const Coordinator) bool {
        return self.published_view.overdue_blocking != 0;
    }
    pub fn bindEffectInvalidation(self: *Coordinator) void {
        self.store.effect_invalidation = .{ .context = self, .invalidate = invalidateEffectPublication };
        self.refreshRetirementHook();
    }
    pub fn refreshRetirementHook(self: *Coordinator) void {
        if (self.store.effect_invalidation) |*hook| {
            hook.retirement_pending = null;
            for (self.jails) |jail| if (jail.retiring) {
                hook.retirement_pending = retirementPending;
                break;
            };
        }
    }
    fn retirementPending(ctx: ?*anyopaque, key: effect.Hash, owners: []const effect.Owner, desired: effect.Lease) void {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        for (owners) |owner| {
            if (owner.lease == .absent and desired != .absent) continue;
            const jail = self.findJail(owner.jail.slice()) orelse continue;
            if (!jail.retiring or jail.removal_cursor.phase != .finish) continue;
            const cursor = &jail.removal_withdrawal;
            const after = cursor.after orelse continue;
            if (std.mem.order(u8, &key, &after) == .gt) continue;
            if (cursor.revisit == null or std.mem.order(u8, &key, &cursor.revisit.?) == .lt) cursor.revisit = key;
        }
    }
    fn invalidateEffectPublication(ctx: ?*anyopaque) void {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        self.mutex.lock();
        defer self.mutex.unlock();
        // Why: The store calls this before an effect COMMIT; authority is withdrawn and the prior expiry kept until a current publication.
        self.worker_observation.publication(observationMs(), self.observationWall(), null, false);
    }
    fn resolverGeneration(server: ?std.net.Address) ![32]u8 {
        const selected = server orelse return [_]u8{0} ** 32;
        var bytes: [128]u8 = undefined;
        const canonical = try std.fmt.bufPrint(&bytes, "{}", .{selected});
        return effect.hashParts("fail2zig-native-resolver-udp-v1", &.{canonical});
    }
    pub fn internalGeneration(jail: []const u8, policy: retry.Policy, form: retry.HashForm) ![32]u8 {
        const base = try policy.hashBytes(form);
        const escalation = try policy.escalationBytes();
        return effect.hashParts("fail2zig-native-recidive-source-v1", &.{ jail, &base, &escalation });
    }
    fn resourceRequirements(cfg: *const config.Config, selected: []config.LogSource) !resource.OptionalRequirements {
        const environment = try resource.currentEnvironment();
        try resource.FdContext.raiseSoftLimit(cfg.global.native_fd_ceiling);
        const descriptors = try resource.FdContext.observe(cfg.global.native_fd_ceiling, 32);
        var plan: resource.Plan = .{};
        try plan.include(resource.storeWorkspace());
        try plan.include(try resource.controlCost(cfg.global.metrics_enabled, 2 * shared.protocol.max_payload_size));
        try plan.include(.{ .live = try @import("query.zig").queryCaptureCost().plus(.{ .bytes = max_jails * @sizeOf(JailListRow) }) });
        try plan.include(.{ .live = .{ .bytes = try std.math.add(usize, cfg.retained_capacity, 16 * resource.mib), .allocations = 2, .fds = 2 } });
        var custom: usize = 0;
        var internal_count: usize = 0;
        var enforcing = false;
        var index: usize = 0;
        for (cfg.jails) |jail| {
            if (!jail.enabled) continue;
            const source = resolvedSource(cfg, &jail);
            if (source == .internal) {
                internal_count += 1;
                if (internal_count > 1 or !config.filterSupportsInternal(jail.filter) or jail.logpath.len != 0 or jail.journal_executables.len != 0 or jail.rule_files.len != 0) return error.NativeInternalEventsRequired;
            } else if (config.filterSupportsInternal(jail.filter)) return error.NativeInternalEventsRequired;
            selected[index] = source;
            index += 1;
            if (jail.rule_files.len != 0) custom += 1;
            try includeJail(&plan, &jail, source, environment);
            enforcing = enforcing or jail.effectiveBanaction(cfg.defaults) != .@"log-only";
        }
        try plan.includeDetached(try resource.publicationCost(retry.max_pool_subjects, @sizeOf(Coordinator) + selected.len * @sizeOf(Jail)));
        if (enforcing) try plan.includeDetached(.{
            .bytes = try std.math.mul(usize, effect.max_live_owners, 2 * (@sizeOf(durable.Store.OperatorOwner) + @sizeOf(bool))),
            .allocations = 4,
        });
        const dns_server = if (cfg.global.dns_server) |server| try std.net.Address.parseIp(server, cfg.global.dns_port) else null;
        if (custom != 0) try plan.include(try resource.dnsCost(.{
            .generation = try resolverGeneration(dns_server),
            .server = dns_server,
            .capacity = 1024,
            .max_sources = custom * max_sources_per_jail,
            .max_owned_bytes = @as(usize, cfg.global.native_memory_ceiling_mb) * resource.mib,
            .clock = .{ .context = null, .read_us = wallClock, .read_ms = monotonic },
        }));
        if (enforcing) try plan.include(try resource.effectCost(environment));
        const limits = resource.Limits{ .zig_bytes = @as(usize, cfg.global.native_memory_ceiling_mb) * resource.mib, .descriptors = cfg.global.native_fd_ceiling };
        if (!enforcing) return .{ .requirements = try plan.finish(limits, descriptors), .admitted = false };
        return resource.finishWithOptional(plan, try resource.firewallObservationCost(firewall_observation.Cache, firewall_observation.Page), limits, descriptors);
    }
    pub fn includeJail(plan: *resource.Plan, jail: *const config.JailConfig, source: config.LogSource, environment: resource.Environment) !void {
        const capacity: usize = if (source == .journald) 1 else max_sources_per_jail;
        switch (source) {
            .file => try plan.include(try resource.fileCost(.{ .source_capacity = capacity, .spec_count = jail.logpath.len, .max_record_bytes = 2048, .max_decoded_bytes = 2048 })),
            .journald => {
                try plan.include(try resource.journalCost(.{ .max_record_bytes = 2048, .max_decoded_bytes = 2048, .batch_records = 1, .environment = environment }));
                try plan.include(.{
                    .live = .{ .bytes = 8 * (std.fs.max_path_bytes + @sizeOf([]const u8)), .allocations = 9 },
                    .workspace = .{ .bytes = 98304, .allocations = 16, .fds = 4 },
                    .workspace_kind = .configuration,
                });
            },
            .internal => try plan.include(.{ .workspace = .{ .bytes = 16 * 1024, .allocations = 4 }, .workspace_kind = .source }),
            .auto => return error.NativeInternalEventsRequired,
        }
        const projection_bytes = @sizeOf(Plan) + @sizeOf(journal_projection.Plan) + jail.logpath.len * @sizeOf(sessions.Spec) + 128 * @sizeOf(@import("../detect/cidr.zig").Cidr);
        var input_bytes = jail.name.len;
        if (source == .file) for (jail.logpath) |path| {
            input_bytes += path.len;
        };
        try plan.include(.{
            .live = .{ .bytes = projection_bytes + input_bytes, .allocations = 5 + if (source == .file) jail.logpath.len else @as(usize, 0) },
            .workspace = .{ .bytes = 65536, .allocations = 16, .fds = 2 },
            .workspace_kind = .configuration,
        });
        if (jail.timezone != null) try plan.include(try resource.timezoneCost(1));
        if (jail.rule_files.len != 0) {
            const prepared = try consumer_plan.reservationBytes(jail.rule_files.len);
            try plan.include(.{ .live = .{ .bytes = prepared, .allocations = 32 }, .workspace = .{ .bytes = prepared, .allocations = 32, .fds = 1 }, .workspace_kind = .configuration });
            try plan.include(try resource.consumerCost(try consumer_runtime.JailRuntime.capacityPlan(jail.rule_files.len, capacity), 64 + capacity * (8 + jail.rule_files.len * 2)));
        }
    }
    pub usingnamespace @import("reload.zig").Methods(@This());
    fn releaseResources(self: *Coordinator) void {
        if (self.resource_reservation) |reservation| self.resources.release(reservation) catch |failure| {
            std.log.err("native resource reservation release failed: {s}", .{@errorName(failure)});
        };
        self.resource_reservation = null;
    }

    // Holds: Locks and the read-only backend probe precede the store open; startup admission commits only once recovery reaches ownership.
    pub fn create(a: std.mem.Allocator, cfg: *const config.Config, config_path: []const u8, progress: ?*sd_notify.Progress) !*Coordinator {
        try config.validate(cfg);
        path_guard.validate(a, cfg) catch |err| {
            std.log.err("native: path admission state='{s}' socket='{s}': {s}", .{ cfg.global.state_file, cfg.global.socket_path, @errorName(err) });
            return err;
        };
        for (cfg.jails) |jail| {
            if (jail.enabled and jail.ignore_file != null and jail.rule_files.len == 0) return error.NativeConsumerRuntimeNotAdmitted;
        }
        if (cfg.global.compatibility_pending) return error.CompatibilityNotAdmitted;
        var count: usize = 0;
        var requested_enforcing = false;
        for (cfg.jails) |jail| if (jail.enabled) {
            count += 1;
            requested_enforcing = requested_enforcing or jail.effectiveBanaction(cfg.defaults) != .@"log-only";
        };
        if (count == 0 or count > max_jails) return error.NativeJailLimit;
        var namespace_lock: ?std.fs.File = null;
        errdefer if (namespace_lock) |file| file.close();
        if (requested_enforcing) namespace_lock = try lockFirewallNamespace(cfg);
        var authority_lock = path_guard.lockStateIfPresent(cfg.global.state_file) catch |err| {
            std.log.err(
                "native: state authority admission failed: {s}; path='{'}'{s}",
                .{ @errorName(err), std.zig.fmtEscapes(cfg.global.state_file[0..@min(cfg.global.state_file.len, 256)]), if (cfg.global.state_file.len > 256) " [path truncated]" else "" },
            );
            logSandboxHint(err, cfg.global.state_file, .state);
            return err;
        };
        errdefer if (authority_lock) |file| file.close();
        var open_diag: durable.OpenDiagnostic = .{};
        const snapshot: durable.Store.InstallationSnapshot = if (authority_lock != null)
            durable.Store.installationSnapshotDetailed(a, cfg.global.state_file, &open_diag) catch |err| {
                logStateOpenFailure("installation snapshot", cfg.global.state_file, err, open_diag);
                return err;
            }
        else
            .{ .schema_version = 0, .installation = null };
        const backend_admission = preflightBackend(a, cfg, requested_enforcing, snapshot.installation);
        if (backend_admission == .unavailable) {
            const failure = backend_admission.unavailable;
            const forced = cfg.global.firewall != .auto;
            const reason = backendCauseName(failure);
            if (failure == error.InstallationMismatch and snapshot.installation != null) {
                logInstallationConflict(cfg, snapshot.installation.?);
            } else if (cfg.global.on_no_backend == .@"fail-closed") {
                if (forced)
                    std.log.err("firewall: no usable backend (forced by config) ({s}); refusing to run unprotected", .{reason})
                else
                    std.log.err("firewall: no usable backend ({s}); refusing to run unprotected", .{reason});
            } else if (forced) {
                std.log.warn("firewall: no usable backend (forced by config) ({s}); running DEGRADED as log-only per on_no_backend", .{reason});
            } else {
                std.log.warn("firewall: no usable backend ({s}); running DEGRADED as log-only per on_no_backend", .{reason});
            }
        }
        const runtime_enforcing = switch (backend_admission) {
            .selected => true,
            .not_needed => false,
            .unavailable => |failure| switch (cfg.global.on_no_backend) {
                .@"fail-closed" => return failure,
                .@"log-only" => false,
            },
        };
        if (!runtime_enforcing and namespace_lock != null) {
            namespace_lock.?.close();
            namespace_lock = null;
        }
        var selected_sources: [max_jails]config.LogSource = undefined;
        const observation_admission = try resourceRequirements(cfg, selected_sources[0..count]);
        const requirements = observation_admission.requirements;
        const self = try a.create(Coordinator);
        errdefer a.destroy(self);
        var coordinator_clock = try clock_mod.Clock.init();
        if (comptime build_options.diag) if (runtime_enforcing and coordinator_clock.rate() == 0) {
            std.log.err("diag clock: step mode (F2Z_DIAG_CLOCK_RATE=0) needs log-only jails; a kernel enforcement backend is selected", .{});
            return error.DiagStepModeEnforcing;
        };
        const start_us = coordinator_clock.wallUs();
        self.* = .{ .allocator = a, .cfg = cfg, .live_cfg = cfg, .config_path = config_path, .jails = &.{}, .store = undefined, .clock = coordinator_clock, .gate = undefined, .published_health = undefined, .startup_backend = switch (backend_admission) {
            .selected => |selected| selected.installation.backend,
            .not_needed, .unavailable => null,
        }, .startup_installation = switch (backend_admission) {
            .selected => |selected| selected.installation,
            .not_needed, .unavailable => null,
        }, .startup_installation_persisted = switch (backend_admission) {
            .selected => |selected| selected.persisted,
            .not_needed, .unavailable => false,
        }, .backend_failure = switch (backend_admission) {
            .unavailable => |failure| failure,
            .not_needed, .selected => null,
        }, .preflight_schema_version = snapshot.schema_version, .preflight_installation = snapshot.installation, .suppress_enforcement = requested_enforcing and !runtime_enforcing, .authority_lock = authority_lock, .namespace_lock = namespace_lock, .start_us = start_us, .resources = .{ .limit_bytes = @as(usize, cfg.global.native_memory_ceiling_mb) * resource.mib, .limit_fds = requirements.descriptor_capacity } };
        self.startup_progress = progress;
        authority_lock = null;
        namespace_lock = null;
        errdefer if (self.namespace_lock) |file| file.close();
        errdefer if (self.authority_lock) |file| file.close();
        self.worker_observation = health.WorkerObservation.init(observationMs(), self.observationWall());
        self.resource_reservation = try self.resources.reserve(.other, requirements.cost);
        errdefer self.releaseResources();
        if (runtime_enforcing) self.initializeObservationCache(observation_admission.admitted, self.startup_installation.?);
        errdefer if (self.firewall_observation_cache) |cache| a.destroy(cache);
        if (runtime_enforcing) {
            self.owner_scratch = try a.alloc(durable.Store.OperatorOwner, effect.max_live_owners);
            errdefer a.free(self.owner_scratch);
            self.owner_active = try a.alloc(durable.Store.OperatorOwner, effect.max_live_owners);
            errdefer a.free(self.owner_active);
            self.owner_scratch_confirmed = try a.alloc(bool, effect.max_live_owners);
            errdefer a.free(self.owner_scratch_confirmed);
            self.owner_confirmed = try a.alloc(bool, effect.max_live_owners);
            errdefer a.free(self.owner_confirmed);
        }
        self.jail_storage = try a.alloc(Jail, max_jails);
        errdefer a.free(self.jail_storage);
        self.jails = self.jail_storage[0..count];
        if (cfg.global.dns_server) |server| {
            self.dns_server = try std.net.Address.parseIp(server, cfg.global.dns_port);
            self.dns_generation = try resolverGeneration(self.dns_server);
        }
        self.gate = health.Gate.init(.{ .context = self, .read = monotonic });
        self.published_health = self.gate.snapshot();
        var prepared: usize = 0;
        errdefer for (self.jails[0..prepared]) |*jail| {
            jail.plan.deinit(a);
            if (jail.custom_plan) |value| value.destroy();
            destroyZone(a, jail.zone);
        };
        for (cfg.jails) |*jail_cfg| {
            if (!jail_cfg.enabled) continue;
            self.jails[prepared] = try self.createJail(cfg, jail_cfg, selected_sources[prepared]);
            prepared += 1;
        }
        if (self.authority_lock == null) self.authority_lock = path_guard.lockAbsentState(cfg.global.state_file) catch |err| {
            std.log.err(
                "native: state authority admission failed: {s}; path='{'}'{s}",
                .{ @errorName(err), std.zig.fmtEscapes(cfg.global.state_file[0..@min(cfg.global.state_file.len, 256)]), if (cfg.global.state_file.len > 256) " [path truncated]" else "" },
            );
            logSandboxHint(err, cfg.global.state_file, .state);
            return err;
        };
        try self.verifyStateIdentity();
        self.reportStartup(.schema, "schema", 0, 0);
        self.store = durable.Store.openRuntimeDetailed(a, cfg.global.state_file, &open_diag) catch |err| {
            logStateOpenFailure("runtime open", cfg.global.state_file, err, open_diag);
            return err;
        };
        self.store_open = true;
        self.bindEffectInvalidation();
        errdefer self.store.close();
        if (comptime build_options.diag) {
            if (self.clock.origin == .floor and self.store.schema_version >= 7) if (try self.store.admissionClock()) |floor| {
                self.start_us = self.clock.raiseOriginTo(floor.us);
            };
            std.log.info("diag clock: mode={s} rate={d} origin={d}", .{ @tagName(self.clock.mode()), self.clock.rate(), self.start_us });
        }
        // Why: Checked again after the open, so a state file swapped in while it opened is refused.
        try self.verifyStateIdentity();
        try self.validatePreflightInstallation();
        self.self_addresses = self.readSelfAddresses();
        errdefer if (self.self_addresses) |*list| list.deinit(a);
        errdefer self.destroyEffects();
        try self.prepareStore();
        var validation_turns = self.startup_retirement_progress;
        self.reportStartup(.maintenance, "maintenance validation", validation_turns, 0);
        while (!try self.store.validateMaintenanceTurn(&self.maintenance_validation)) {
            validation_turns += 1;
            self.reportStartup(.maintenance, "maintenance validation", validation_turns, 0);
        }
        try self.store.finishMaintenanceValidation(&self.maintenance_validation);
        self.maintenance_validated = true;
        // Why: The recount commits before startup admission begins, so a start that fails later still keeps the mismatch streak.
        if (try self.store.reconcileLiveOwners()) |recount| {
            if (recount.prior_streak == 0)
                std.log.warn("native storage: live-owner counter {d} did not match {d} live owners; recounted", .{ recount.stored, recount.counted })
            else
                std.log.err(
                    "native storage: live-owner counter {d} did not match {d} live owners again ({d} consecutive startups); recounted, but a writer is bypassing the counter triggers",
                    .{ recount.stored, recount.counted, recount.prior_streak + 1 },
                );
        }
        errdefer self.destroyRuntime();
        try self.store.beginStartupAdmission();
        errdefer self.store.abortStartupAdmission();
        var custom_reclaim_completed = false;
        for (self.jails) |*jail| if (jail.custom_plan != null) {
            if (try custom_rebind.migrate(a, &self.store, jail, if (self.dns_server != null) self.dns_generation else null, try self.plannedGeneration(jail, .planned), &custom_reclaim_completed, .{ .context = self, .report = customRebindProgress, .monotonic_ms = monotonic })) {
                self.maintenance_validation = .{};
                self.maintenance_validated = false;
            }
        };
        try self.validateAdmission();
        const admitted_config = try self.admitConfigGeneration();
        try self.readAdminState();
        var recovery_driver = self.driver();
        const recovery_polls = max_jails * (max_sources_per_jail + 7) + 160;
        self.reportStartup(.recovery, "recovery", 0, recovery_polls);
        _ = try recovery_driver.poll();
        for (0..recovery_polls) |poll| {
            const startup_state = self.gate.snapshot();
            if (startup_state.phase != .recovering or startup_state.recovery_step != .state) break;
            self.reportStartup(.recovery, "recovery", poll + 1, recovery_polls);
            _ = try recovery_driver.poll();
        }
        const admitted_state = self.gate.snapshot();
        if (admitted_state.phase != .recovering or admitted_state.recovery_step != .ownership or self.rebuild_phase != .done) {
            if (admitted_state.receipt_clock_floor_us != null) return error.ReceiptClockReversed;
            return error.NativeRecoveryLimit;
        }
        var policies: [max_jails]?PreparedCustomPolicy = [_]?PreparedCustomPolicy{null} ** max_jails;
        defer for (&policies) |*value| if (value.*) |*policy| policy.deinit(self);
        for (self.jails, 0..) |*jail, i| {
            policies[i] = try self.prepareCustomPolicy(jail, self.live_cfg, self.clock.wallUs(), true);
            if (policies[i]) |*policy| if (policy.policy.update()) |update| try self.store.commitConsumerInput(update.manifest, update.batch);
        }
        try self.store.finishStartupAdmission();
        for (&policies) |*value| if (value.*) |*policy| policy.policy.publish();
        try self.prepareRetryProjection();
        var retry_pages: u64 = 0;
        while (try self.store.retryAdmissionStep(256) == .progressed) {
            retry_pages += 1;
            self.reportStartup(.recovery, "retry admission", retry_pages, 0);
        }
        self.published_generation = admitted_config.generation;
        self.published_config_digest = admitted_config.digest;
        self.generation_admitted = true;
        self.publishHealth();
        return self;
    }

    pub fn createJail(self: *Coordinator, cfg: *const config.Config, jail_cfg: *const config.JailConfig, source: config.LogSource) !Jail {
        const a = self.allocator;
        const policy = try retry_config.fromJail(jail_cfg, cfg.defaults, retry.max_pool_subjects);
        var selected = jail_cfg.*;
        selected.name = try a.dupe(u8, jail_cfg.name);
        errdefer a.free(selected.name);
        selected.source = source;
        var selected_cfg = cfg.*;
        selected_cfg.jails = @constCast((&selected)[0..1]);
        const assets = if (selected.rule_files.len != 0) try consumer_plan.Prepared.create(a, &selected_cfg, 0, self.dns_generation) else null;
        errdefer if (assets) |value| value.destroy();
        const parent_generation = if (assets) |value| value.parent_generation else [_]u8{0} ** 32;
        if (selected.timezone != null and (selected.source != .file or selected.timestamp != .syslog or selected.timezone_offset_minutes != null)) return error.InvalidNativeTimezone;
        if (selected.timezone_ambiguity != null and selected.timezone == null) return error.UnusedTimezoneAmbiguity;
        const zone = if (selected.timezone) |id| try loadZone(a, cfg.global.timezone_root, id, selected.timezone_ambiguity orelse .reject) else null;
        errdefer destroyZone(a, zone);
        var plan: Plan = switch (selected.source) {
            .file => blk: {
                if (selected.journal_executables.len != 0) return error.UnusedJournalProfile;
                const timestamp = selected.timestamp orelse return error.NativeTimestampRequired;
                if (timestamp != .syslog and selected.timezone_offset_minutes != null) return error.UnusedTimezoneOffset;
                var settings = projection.Settings{
                    .timestamp = undefined,
                    .body = if (assets == null and !filter_registry.requiresWholeRecord(selected.filter) and (timestamp == .iso8601 or timestamp == .syslog)) .syslog else .whole,
                    .start = if (timestamp == .undated) .tail else .head,
                    .max_sources = max_sources_per_jail,
                    .ignore_capacity = 128,
                    .custom = assets != null,
                };
                settings.timestamp = switch (timestamp) {
                    .undated => .undated,
                    .iso8601 => .{ .field = .{ .format = .iso8601, .boundary = .{ .delimiter = ' ' } } },
                    .syslog => .{ .field = .{
                        .format = .syslog,
                        .boundary = .{ .length = 15 },
                        .infer_year = true,
                        .zone = zone,
                        .context = .{ .offset_seconds = if (zone != null) null else @as(i32, selected.timezone_offset_minutes orelse return error.NativeTimezoneRequired) * 60 },
                    } },
                    .epoch_seconds => .{ .field = .{ .format = .epoch_seconds, .boundary = .{ .delimiter = ' ' } } },
                    .common_log => .{ .field = .{ .format = .common_log, .start = 1, .boundary = .{ .length = 26 } } },
                };
                break :blk .{ .file = try projection.Plan.init(a, &selected_cfg, 0, parent_generation, settings) };
            },
            .journald => blk: {
                if (selected.timestamp != null or selected.timezone_offset_minutes != null) return error.UnusedFileTimestamp;
                var discovered: ?journal_profile.Resolved = null;
                defer if (discovered) |*value| value.deinit();
                if (selected.journal_executables.len == 0) {
                    if (selected.journal_executables_explicit or assets != null or !std.mem.eql(u8, selected.filter, "sshd")) {
                        std.log.err("native: jail '{s}': journal_executables requires a nonempty explicit profile for this configuration", .{selected.name});
                        return error.InvalidJournalExecutables;
                    }
                    discovered = journal_profile.discover(a) catch |err| {
                        std.log.err(
                            "native: jail '{s}': cannot resolve trusted SSH journal executables: {s}; configure journal_executables explicitly for a nonstandard installation",
                            .{ selected.name, @errorName(err) },
                        );
                        return err;
                    };
                } else {
                    if (selected.journal_executables.len > 8) return error.InvalidJournalExecutables;
                    for (selected.journal_executables) |executable| {
                        journal_profile.qualifyExplicit(executable) catch |err| {
                            std.log.err("native: jail '{s}': journal executable '{s}': {s}", .{ selected.name, executable, @errorName(err) });
                            return err;
                        };
                    }
                }
                const executables = if (discovered) |*value| value.executables() else selected.journal_executables;
                const matches: []const []const u8 = if (discovered != null and discovered.?.has_auth_helper) auth_ssh_matches else legacy_ssh_matches;
                const machine = try std.fs.cwd().readFileAlloc(a, "/etc/machine-id", 33);
                defer a.free(machine);
                break :blk .{ .journal = try journal_projection.Plan.create(
                    a,
                    &selected_cfg,
                    0,
                    parent_generation,
                    .{
                        .machine_id = std.mem.trim(u8, machine, "\n"),
                        .executables = executables,
                        .ignore_capacity = 128,
                        .custom = assets != null,
                        .journal = .{ .batch_records = 1, .matches = matches },
                    },
                ) };
            },
            .auto => unreachable,
            .internal => .{ .internal = try internalGeneration(selected.name, policy, .identity) },
        };
        errdefer plan.deinit(a);
        const resolved = config.resolveJailFromConfig(jail_cfg, cfg.defaults);
        const decay = try decayWindow(resolved.bantime_increment_decay);
        if (assets != null) self.custom_jails += 1;
        _ = self.metrics_state.registerJail(selected.name);
        return .{ .name = selected.name, .plan = plan, .policy = policy, .zone = zone, .custom_plan = assets, .on_truncation = resolved.on_truncation, .decay = decay };
    }
    pub fn decayWindow(seconds: shared.Duration) !retry.EscalationDecay {
        const signed = std.math.cast(i64, seconds) orelse return error.InvalidEscalationInput;
        return .{ .window_us = std.math.mul(i64, signed, std.time.us_per_s) catch return error.InvalidEscalationInput };
    }
    pub fn resolvedSource(cfg: *const config.Config, jail: *const config.JailConfig) config.LogSource {
        const source = if (jail.source == .auto) cfg.defaults.source else jail.source;
        if (source != .auto) return source;
        return if (config.anyLogpathExists(jail.logpath)) .file else if (config.filterSupportsJournald(jail.filter) and config.journalctlPresent()) .journald else .file;
    }

    pub const readiness_progress_ceiling_ns: i128 = 300 * std.time.ns_per_s;
    pub const PreparedCustomPolicy = struct {
        policy: consumer_runtime.JailRuntime.PreparedPolicy,
        reservation: resource.Token,

        pub fn deinit(self: *PreparedCustomPolicy, owner: *Coordinator) void {
            self.policy.deinit();
            owner.resources.release(self.reservation) catch |failure| std.log.err("native: custom policy reservation release failed: {s}", .{@errorName(failure)});
        }
    };
    pub const DeadlineMode = enum { apply, read, preview };
    pub const PreparedIgnoreDeadlines = struct {
        entries: []shared.types.TimedEntry,
        stored: []?i64,
        literals: []?i64,

        pub fn deinit(self: PreparedIgnoreDeadlines, allocator: std.mem.Allocator) void {
            allocator.free(self.entries);
            allocator.free(self.stored);
            allocator.free(self.literals);
        }
        pub fn update(self: PreparedIgnoreDeadlines, name: []const u8) durable.Store.ConfigIgnoreUpdate {
            return .{ .jail = name, .entries = self.entries, .deadlines = self.stored };
        }
    };
    pub const ConfigAdmission = struct { generation: [32]u8, digest: [32]u8 };
    fn customRebindProgress(context: ?*anyopaque, completed: u64) void {
        const self: *Coordinator = @ptrCast(@alignCast(context.?));
        self.reportStartup(.recovery, "custom state rebind", completed, 0);
    }
    pub fn retentionUpdate(cfg: *const config.Config, rows: *[config.max_configured_jails]durable.Store.JailRetentionLimit) !durable.Store.RetentionUpdate {
        if (cfg.jails.len > rows.len) return error.TooManyJails;
        for (cfg.jails, rows[0..cfg.jails.len]) |jail, *row| row.* = .{ .jail = jail.name, .max_matches = jail.history_max_matches };
        return .{ .global_max_matches = cfg.global.history_max_matches, .jails = rows[0..cfg.jails.len] };
    }
    pub fn configDigest(self: *Coordinator) ![32]u8 {
        if (self.config_path.len == 0) return error.ConfigPathRequired;
        const bytes = try std.fs.cwd().readFileAlloc(self.allocator, self.config_path, 16 * 1024 * 1024);
        defer self.allocator.free(bytes);
        return reload_mod.digestBytes(bytes);
    }

    pub fn freeRequest(self: *Coordinator, request: *ReloadRequest) void {
        if (request.arena) |arena| {
            arena.deinit();
            self.allocator.destroy(arena);
        }
        self.allocator.destroy(request);
    }
    pub fn jailEnforces(self: *const Coordinator, jail: *const Jail) bool {
        return jail.policy.enforce and !self.suppress_enforcement;
    }
    pub fn findJail(self: *Coordinator, name: []const u8) ?*Jail {
        for (self.jails) |*jail| if (std.mem.eql(u8, jail.name, name)) return jail;
        return null;
    }
    pub const GenerationMode = enum { planned, legacy };
    pub fn sessionProcessor(jail: *const Jail) ?*const @import("../source/source_processor.zig").Processor {
        const source = jail.session orelse return null;
        return switch (source) {
            .file => |value| &value.processor,
            .journal => |value| &value.processor,
            .internal => null,
        };
    }
    pub const HistoryStep = enum { caught_up, behind, waiting };
    pub fn capacityWaiting(jail: *const Jail) bool {
        const cause = jail.source_error orelse return false;
        return cause == error.StorageCapacity;
    }
    pub const OptionalNumber = struct {
        value: ?u64,
        pub fn format(self: OptionalNumber, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
            if (self.value) |number| try writer.print("{d}", .{number}) else try writer.writeAll("unknown");
        }
    };
    pub const ControlEscaped = struct {
        text: []const u8,
        pub fn format(self: ControlEscaped, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
            for (self.text) |byte| {
                if (byte < 0x20 or byte == 0x7f) try writer.print("\\x{x:0>2}", .{byte}) else try writer.writeByte(byte);
            }
        }
    };
    pub const shell_safe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:/@%+=,-";
    pub fn jailPaused(jail: *const Jail) bool {
        for (jail.source_status) |entry| if (entry.state == .paused) return true;
        return false;
    }
    pub usingnamespace @import("query.zig").Methods(@This());
    pub usingnamespace @import("query_status.zig").Methods(@This());
    pub usingnamespace @import("query_bans.zig").Methods(@This());
    pub usingnamespace @import("query_history.zig").Methods(@This());
    pub const quiet_interval_ms: u64 = 1000;
    pub const maintenance_idle_ms: u64 = 30 * quiet_interval_ms;
    pub const verify_interval_ns: u64 = 5 * std.time.ns_per_s;
    pub const audit_interval_ns: u64 = 60 * std.time.ns_per_s;
    pub const stop_history_budget_ns: u64 = 2 * std.time.ns_per_s;
    pub const shed_notice_interval_ms: u64 = 60 * quiet_interval_ms;
    pub fn destroy(self: *Coordinator) void {
        self.stop();
        if (self.reload_request) |request| self.freeRequest(request);
        if (self.admin_request) |request| self.freeAdminRequest(request);
        if (self.history_reader) |*reader| reader.close();
        self.destroyEffects();
        if (self.firewall_observation_cache) |cache| self.allocator.destroy(cache);
        self.destroyRuntime();
        for (self.jails) |*jail| self.releaseJail(jail);
        if (self.live_arena) |arena| {
            arena.deinit();
            self.allocator.destroy(arena);
        }
        if (self.self_addresses) |*list| list.deinit(self.allocator);
        self.allocator.free(self.decision_scratch);
        if (self.owner_scratch.len != 0) self.allocator.free(self.owner_scratch);
        if (self.owner_active.len != 0) self.allocator.free(self.owner_active);
        if (self.owner_scratch_confirmed.len != 0) self.allocator.free(self.owner_scratch_confirmed);
        if (self.owner_confirmed.len != 0) self.allocator.free(self.owner_confirmed);
        if (self.store_open) self.store.close();
        if (self.authority_lock) |file| file.close();
        if (self.namespace_lock) |file| file.close();
        self.allocator.free(self.jail_storage);
        self.releaseResources();
        self.allocator.destroy(self);
    }
    pub const JailListRow = struct {
        name: detection.Name,
        healthy: bool,
        enabled: bool,
        paused: bool,
        disable_cleanup_pending: bool,
        active_bans: ?u32,
        maxretry: u32,
        findtime: i64,
        bantime: ?i64,
        action: []const u8,
        enforce_configured: bool,
        enforcing: bool,
        source: std.meta.Tag(Plan),
        source_healthy: bool,
        source_paused: bool,
        source_missing: bool,
        revision: u64,
        decisions: u64,
        cause: ?anyerror,
        diagnostic: ?journal_sessions.FailureDiagnostic,
    };
    pub usingnamespace @import("startup.zig").Methods(@This());
    pub usingnamespace @import("retirement.zig").Methods(@This());
    pub usingnamespace @import("ignore.zig").Methods(@This());
    pub usingnamespace @import("recovery.zig").Methods(@This());
    pub usingnamespace @import("publish.zig").Methods(@This());
    pub usingnamespace @import("worker.zig").Methods(@This());
    pub usingnamespace @import("command.zig").Methods(@This());
};

const Shutdown = struct { loop: *loop_mod.EventLoop, coordinator: *Coordinator };
fn terminate(_: *const std.os.linux.signalfd_siginfo, ctx: ?*anyopaque) void {
    const shutdown: *Shutdown = @ptrCast(@alignCast(ctx.?));
    if (shutdown.coordinator.notifier) |notifier| _ = notifier.stopping() catch {};
    shutdown.loop.stop();
}
pub var log_sink: ?*log_target.Sink = null;
fn reopenLogs(_: *const std.os.linux.signalfd_siginfo, _: ?*anyopaque) void {
    const sink = log_sink orelse return;
    sink.reopen() catch |err| std.log.warn("log target reopen failed: {s}; previous descriptor retained", .{@errorName(err)});
}
fn drainLogs(_: u64, _: ?*anyopaque) void {
    if (log_sink) |sink| sink.drain();
}
fn reloadSignal(info: *const std.os.linux.signalfd_siginfo, ctx: ?*anyopaque) void {
    const coordinator: *Coordinator = @ptrCast(@alignCast(ctx.?));
    const outcome = coordinator.stageReload(2000);
    Coordinator.auditReload(outcome.kind, info.uid);
    for (outcome.reasonSlice()) |reason| std.log.warn("native reload (SIGHUP): {s}", .{reason.slice()});
    std.log.info("native reload (SIGHUP): outcome={s}", .{@tagName(outcome.kind)});
}
pub fn run(a: std.mem.Allocator, cfg: *const config.Config, config_path: []const u8) !void {
    var notifier: ?sd_notify.Notifier = sd_notify.Notifier.fromEnvironment() catch |err| blk: {
        std.log.warn("sd_notify disabled: {s}", .{@errorName(err)});
        break :blk null;
    };
    defer if (notifier) |*value| value.deinit();
    var startup_progress = sd_notify.Progress{ .notifier = if (notifier) |*value| value else null };
    startup_progress.report(.admission, "admission", 0, 0);
    const coordinator = try Coordinator.create(a, cfg, config_path, &startup_progress);
    defer coordinator.destroy();
    var loop = try loop_mod.EventLoop.init(a);
    defer loop.deinit();
    coordinator.notifier = if (notifier) |*value| value else null;
    var shutdown = Shutdown{ .loop = &loop, .coordinator = coordinator };
    try loop.addSignalHandler(std.os.linux.SIG.TERM, terminate, &shutdown);
    try loop.addSignalHandler(std.os.linux.SIG.INT, terminate, &shutdown);
    try loop.addSignalHandler(std.os.linux.SIG.HUP, reloadSignal, coordinator);
    try loop.addSignalHandler(std.os.linux.SIG.USR1, reopenLogs, null);
    _ = try loop.addTimer(250, drainLogs, null, false);
    try path_guard.validate(a, cfg);
    try coordinator.verifyStateIdentity();
    var server = try ipc.IpcServer.init(a, &loop, cfg.global.socket_path);
    defer server.deinit();
    server.setCommandHandler(.{ .ctx = coordinator, .dispatch = Coordinator.command, .dispatch_auth = Coordinator.commandAuth });
    coordinator.admin_serving = &server.serving;
    try server.start();
    var web: ?http.HttpServer = null;
    defer if (web) |*value| value.deinit();
    if (cfg.global.metrics_enabled) {
        web = http.HttpServer.init(a, &loop, cfg.global.metrics_port, cfg.global.metrics_bind) catch |err| {
            std.log.err("native: HTTP listener {s}:{d}: {s}", .{ cfg.global.metrics_bind, cfg.global.metrics_port, @errorName(err) });
            return err;
        };
        web.?.setStatusSource(.{ .ctx = coordinator, .write = Coordinator.status });
        web.?.setHealthSource(.{ .ctx = coordinator, .write = Coordinator.healthView });
        web.?.setMetricsSource(.{ .ctx = coordinator, .write = Coordinator.metrics });
        try web.?.start();
    } else {
        std.log.info("http: disabled by config", .{});
    }
    var history_open_diag: durable.OpenDiagnostic = .{};
    coordinator.history_reader = durable.Store.openReadOnlyDetailed(a, cfg.global.state_file, &history_open_diag) catch |err| blk: {
        logStateOpenFailure("history reader open", cfg.global.state_file, err, history_open_diag);
        break :blk null;
    };
    if (comptime build_options.diag) std.log.warn("{s}", .{diag_mod.banner});
    try coordinator.start();
    defer coordinator.stop();
    const backend_name = if (coordinator.startup_backend) |selected| @tagName(selected) else "none";
    std.log.info(
        "fail2zig {s} running; backend={s}; native SQLite ingestion; protection admission pending; ipc={s}; http={s}",
        .{ version, backend_name, cfg.global.socket_path, if (cfg.global.metrics_enabled) cfg.global.metrics_bind else "off" },
    );
    try loop.run();
}
