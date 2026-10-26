// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const shared = @import("shared");
const config = @import("config/native.zig");
const projection = @import("config/native_file_detection.zig");
const retry_config = @import("config/native_retry_policy.zig");
const retry = @import("core/native_retry.zig");
const detection = @import("core/native_detection_record.zig");
const timezone = @import("core/native_timezone.zig");
const effect = @import("core/native_effect.zig");
const effect_runtime = @import("runtime/native_effect_runtime.zig");
const firewall_observation = effect_runtime.observation;
const consumer_runtime = @import("runtime/native_consumer_runtime.zig");
const consumer_plan = @import("config/native_consumer_plan.zig");
const consumer_bridge = @import("core/native_consumer_coordinator.zig");
const resource = @import("runtime/native_resource_budget.zig");
const history = @import("core/native_effect_history.zig");
const recurrence = @import("core/native_recurrence.zig");
const firewall_backend = @import("firewall/backend.zig");
const inspection = @import("firewall/inspection.zig");
const path_guard = @import("config/native_paths.zig");
const durable = @import("core/record_store.zig");
const sessions = @import("core/native_file_session.zig");
const pipeline = @import("core/record_pipeline.zig");
const journal_projection = @import("config/native_journal_detection.zig");
const journal_profile = @import("config/native_journal_profile.zig");
const filter_registry = @import("filters/registry.zig");
const files = @import("core/durable_file_source.zig");
const ignore_set = @import("core/native_ignore_set.zig");
const custom_ignore = @import("core/native_ignore.zig");
const native_banip = @import("config/native_banip.zig");
const RuntimeIgnoreEntry = @import("store/ignore_entries.zig").RuntimeIgnoreEntry;

// The released query is part of persistent source identity; changing an existing profile requires admission.
const legacy_ssh_matches: []const []const u8 = &.{ "SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session", "+", "_COMM=sshd", "_COMM=sshd-session" };
const auth_ssh_matches: []const []const u8 = &.{ "SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session", "SYSLOG_IDENTIFIER=sshd-auth", "+", "_COMM=sshd", "_COMM=sshd-session", "_COMM=sshd-auth" };
const journal_sessions = @import("core/native_journal_session.zig");
const health = @import("core/storage_health.zig");
const recovery = @import("core/native_recovery.zig");
const loop_mod = @import("core/event_loop.zig");
const ipc = @import("net/ipc.zig");
const http = @import("net/http.zig");
const build_options = @import("build_options");
const version = build_options.version;
const diag_mod = @import("core/diag.zig");
const clock_mod = @import("core/clock.zig");
const diag_command = @import("net/diag_command.zig");
const reload_mod = @import("runtime/native_reload.zig");
const custom_rebind = @import("runtime/native_custom_rebind.zig");
const query_v1 = @import("net/query_v1.zig");
const readiness = @import("core/readiness.zig");
const sd_notify = @import("core/sd_notify.zig");
const log_target = @import("core/log_target.zig");
const metrics_mod = @import("core/metrics.zig");
const ban_origin = @import("core/ban_origin.zig");
const source_repair = @import("store/source_repair.zig");
pub const max_jails = 64;
pub const max_sources_per_jail = 8;
pub const max_source_status_per_jail = 2 * max_sources_per_jail + 1;
const recovery_validation_budget_ns = 100 * std.time.ns_per_ms;
const tick_wait_ns = 100 * std.time.ns_per_ms;

const Plan = union(enum) {
    file: projection.Plan,
    journal: *journal_projection.Plan,
    internal: [32]u8,
    fn deinit(self: *Plan, a: std.mem.Allocator) void {
        switch (self.*) {
            .file => |*plan| plan.deinit(a),
            .journal => |plan| plan.destroy(),
            .internal => {},
        }
    }
};
const Source = union(enum) {
    file: *sessions.Session,
    journal: *journal_sessions.Session,
    internal: [32]u8,
    fn destroy(self: Source) void {
        switch (self) {
            .file => |source| source.destroy(),
            .journal => |source| source.destroy(),
            .internal => {},
        }
    }
    fn generation(self: Source) [32]u8 {
        return switch (self) {
            .file => |source| source.processor.generation,
            .journal => |source| source.processor.generation,
            .internal => |value| value,
        };
    }
    const ingest_burst = 4;
    fn poll(self: Source) !usize {
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
    fn verify(self: Source) !bool {
        return switch (self) {
            .file => |source| try source.verifyRecoverySourcesTurn(),
            .journal => |source| try source.verifyRecoverySourcesTurn(),
            .internal => true,
        };
    }
    fn healthy(self: Source) bool {
        return switch (self) {
            .file => |source| source.admission_phase == .ready and (source.sources.sources.items.len > 0 or source.awaiting_discovery) and source.repairSnapshot().phase == .healthy and source.blocked_cause == null,
            .journal => |source| source.admission_phase == .ready and source.source_health == .healthy and source.repairSnapshot().phase == .healthy,
            .internal => true,
        };
    }
    fn exportRecovery(self: Source) !SourceSnapshot {
        return switch (self) {
            .file => |value| .{ .file = try value.exportRecovery() },
            .journal => |value| .{ .journal = try value.exportRecovery() },
            .internal => .internal,
        };
    }
    fn importRecovery(self: Source, snapshot: SourceSnapshot) !void {
        switch (self) {
            .file => |value| if (snapshot == .file) try value.importRecovery(snapshot.file) else return error.SourceGenerationMismatch,
            .journal => |value| if (snapshot == .journal) try value.importRecovery(snapshot.journal) else return error.SourceGenerationMismatch,
            .internal => if (snapshot != .internal) return error.SourceGenerationMismatch,
        }
    }
    fn resumeConsumer(self: Source, identity: []const u8) !void {
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
    fn destroy(self: SourceSnapshot) void {
        switch (self) {
            .file => |value| value.destroy(),
            .journal => |value| value.destroy(),
            .internal => {},
        }
    }
};
const MaintenanceMark = struct { committed: u64, epoch: u64, retry_revision: u64 };
const EffectMark = struct { view_revision: u64, epoch: u64, trusted: bool, enforces: bool };
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
    maintenance_source: usize = 0,
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

const PendingWithdrawal = struct {
    name: [64]u8,
    name_len: u8,
    generation: [32]u8,
    bans_lifted: u32,
    pub fn jailName(self: *const PendingWithdrawal) []const u8 {
        return self.name[0..self.name_len];
    }
};

pub const OwnerRange = struct { start: usize = 0, len: usize = 0 };
pub const PublishedRetryPool = struct { sample: ?durable.Store.RetryPoolSample = null, pending: bool = true };

pub const SourceStatus = struct {
    jail: []const u8,
    kind: enum { file, journal },
    path: ?[]const u8,
    on_truncation: ?config.TruncationPolicy,
    state: enum { paused, reading, missing },
    cause: ?[]const u8,
    inode: ?u64,
    committed_offset: ?u64,
    observed_size: ?u64,
    repair: ?[]const u8,
    loss_events: u16,
    last_loss: ?files.LossEvent,
};

const SourceSignature = struct {
    sources: usize = 0,
    configured: usize = 0,
    presence_revision: u64 = 0,
    presence_known: bool = true,
    causes: [max_sources_per_jail + 1]?anyerror = [_]?anyerror{null} ** (max_sources_per_jail + 1),
    loss_sequence: u64 = 0,
    built: bool = false,
};

pub const WritablePath = enum { state, socket };
pub fn logSandboxHint(err: anyerror, path: []const u8, kind: WritablePath) void {
    if (err != error.ReadOnlyFileSystem and err != error.AccessDenied) return;
    const dir = std.fs.path.dirname(path) orelse "/";
    std.log.err("native: the service cannot write the {s} directory '{'}'; the shipped systemd unit allows writes only to directories it grants (ProtectSystem=strict); add the unit override from the installation guide, \"Custom state directory under systemd\" (the installer prints it for your configuration)", .{ @tagName(kind), std.zig.fmtEscapes(dir[0..@min(dir.len, 256)]) });
}
fn destroyZone(a: std.mem.Allocator, zone: ?*timezone.Zone) void {
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

fn logStateOpenFailure(operation: []const u8, path: []const u8, failure: anyerror, detail: durable.OpenDiagnostic) void {
    const prefix = path[0..@min(path.len, 256)];
    std.log.warn("native: state {s} failed: {s}; stage={s}; posix_cause={s}; sqlite_code={?d}; path='{'}'{s}", .{
        operation,                                                @errorName(failure),
        if (detail.stage) |stage| @tagName(stage) else "unknown", if (detail.posix_cause) |cause| @tagName(cause) else "none",
        detail.sqlite_code,                                       std.zig.fmtEscapes(prefix),
        if (prefix.len != path.len) " [path truncated]" else "",
    });
}

fn lockFirewallNamespace(cfg: *const config.Config) !std.fs.File {
    const file = try std.fs.openFileAbsolute(cfg.global.firewall_namespace, .{});
    errdefer file.close();
    const current = try std.fs.openFileAbsolute("/proc/self/ns/net", .{});
    defer current.close();
    const selected = try std.posix.fstat(file.handle);
    const active = try std.posix.fstat(current.handle);
    if (selected.dev != active.dev or selected.ino != active.ino) return error.FirewallNamespaceMismatch;
    if (!try file.tryLock(.exclusive)) return error.NativeNamespaceAlreadyRunning;
    return file;
}
fn preflightBackend(a: std.mem.Allocator, cfg: *const config.Config, enforcing: bool, persisted: ?effect.Installation) BackendAdmission {
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
        // An interrupted kernel dump is a concurrent change, not an unavailable backend.
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
const Knowledge = enum { fresh, stale, none };
const MaintenanceGates = struct {
    slow: u64 = 0,
    due: u64 = 0,
    turns: u64 = 0,
    unhealthy_gate: u64 = 0,
    step_progress: u64 = 0,
    step_returned: u64 = 0,
    step_wait: u64 = 0,
    unsettled: u64 = 0,
    no_session: u64 = 0,
    unhealthy: u64 = 0,
    candidate_receipt: u64 = 0,
    consumer_busy: u64 = 0,
    candidate_source: u64 = 0,
    no_sources: u64 = 0,
    history_missing: u64 = 0,
    history_behind: u64 = 0,
    walks: u64 = 0,
    resumes: u64 = 0,
    advances: u64 = 0,
    advance_token: u64 = 0,
    advance_null: u64 = 0,
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
    maintenance_jail: usize = 0,
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
    maintenance_progress: bool = false,
    maintenance_idle: ?MaintenanceMark = null,
    maintenance_idle_since_ms: u64 = 0,
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
    pending_withdrawals: std.ArrayListUnmanaged(PendingWithdrawal) = .{},
    self_addresses: ?shared.self_addresses.SelfAddresses = null,
    metrics_state: metrics_mod.Metrics = .{},
    published_pool: PublishedRetryPool = .{},
    published_footprint: ?@import("store/footprint.zig").StateFileFootprint = null,
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
    pub usingnamespace @import("daemon_admin.zig").Methods(@This());
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
    fn leaveRealizedEffects(self: *Coordinator) void {
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
    fn effectSlice(self: *Coordinator, manager: *effect_runtime.Manager) !bool {
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
    fn wallClock(ctx: ?*anyopaque) !i64 {
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
    fn bindEffectInvalidation(self: *Coordinator) void {
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
        // Fence readers before COMMIT; retain the prior deadline until readback verifies the new epoch.
        self.worker_observation.publication(observationMs(), self.observationWall(), null, false);
    }
    fn resolverGeneration(server: ?std.net.Address) ![32]u8 {
        const selected = server orelse return [_]u8{0} ** 32;
        var bytes: [128]u8 = undefined;
        const canonical = try std.fmt.bufPrint(&bytes, "{}", .{selected});
        return effect.hashParts("fail2zig-native-resolver-udp-v1", &.{canonical});
    }
    fn internalGeneration(jail: []const u8, policy: retry.Policy, form: retry.HashForm) ![32]u8 {
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
        try plan.include(.{ .live = try @import("daemon_query.zig").queryCaptureCost().plus(.{ .bytes = max_jails * @sizeOf(JailListRow) }) });
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
                try plan.include(.{ .live = .{ .bytes = 8 * (std.fs.max_path_bytes + @sizeOf([]const u8)), .allocations = 9 }, .workspace = .{ .bytes = 98304, .allocations = 16, .fds = 4 }, .workspace_kind = .configuration });
            },
            .internal => try plan.include(.{ .workspace = .{ .bytes = 16 * 1024, .allocations = 4 }, .workspace_kind = .source }),
            .auto => return error.NativeInternalEventsRequired,
        }
        const projection_bytes = @sizeOf(Plan) + @sizeOf(journal_projection.Plan) + jail.logpath.len * @sizeOf(sessions.Spec) + 128 * @sizeOf(@import("core/state.zig").Cidr);
        var input_bytes = jail.name.len;
        if (source == .file) for (jail.logpath) |path| {
            input_bytes += path.len;
        };
        try plan.include(.{ .live = .{ .bytes = projection_bytes + input_bytes, .allocations = 5 + if (source == .file) jail.logpath.len else @as(usize, 0) }, .workspace = .{ .bytes = 65536, .allocations = 16, .fds = 2 }, .workspace_kind = .configuration });
        if (jail.timezone != null) try plan.include(try resource.timezoneCost(1));
        if (jail.rule_files.len != 0) {
            const prepared = try consumer_plan.reservationBytes(jail.rule_files.len);
            try plan.include(.{ .live = .{ .bytes = prepared, .allocations = 32 }, .workspace = .{ .bytes = prepared, .allocations = 32, .fds = 1 }, .workspace_kind = .configuration });
            try plan.include(try resource.consumerCost(try consumer_runtime.JailRuntime.capacityPlan(jail.rule_files.len, capacity), 64 + capacity * (8 + jail.rule_files.len * 2)));
        }
    }
    pub usingnamespace @import("daemon_reload.zig").Methods(@This());
    fn releaseResources(self: *Coordinator) void {
        if (self.resource_reservation) |reservation| self.resources.release(reservation) catch |failure| {
            std.log.err("native resource reservation release failed: {s}", .{@errorName(failure)});
        };
        self.resource_reservation = null;
    }

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
            std.log.err("native: state authority admission failed: {s}; path='{'}'{s}", .{ @errorName(err), std.zig.fmtEscapes(cfg.global.state_file[0..@min(cfg.global.state_file.len, 256)]), if (cfg.global.state_file.len > 256) " [path truncated]" else "" });
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
            std.log.err("native: state authority admission failed: {s}; path='{'}'{s}", .{ @errorName(err), std.zig.fmtEscapes(cfg.global.state_file[0..@min(cfg.global.state_file.len, 256)]), if (cfg.global.state_file.len > 256) " [path truncated]" else "" });
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
        // Committed before startup admission so a failed start keeps the mismatch streak.
        if (try self.store.reconcileLiveOwners()) |recount| {
            if (recount.prior_streak == 0)
                std.log.warn("native storage: live-owner counter {d} did not match {d} live owners; recounted", .{ recount.stored, recount.counted })
            else
                std.log.err("native storage: live-owner counter {d} did not match {d} live owners again ({d} consecutive startups); recounted, but a writer is bypassing the counter triggers", .{ recount.stored, recount.counted, recount.prior_streak + 1 });
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
                var settings = projection.Settings{ .timestamp = undefined, .body = if (assets == null and !filter_registry.requiresWholeRecord(selected.filter) and (timestamp == .iso8601 or timestamp == .syslog)) .syslog else .whole, .start = .head, .max_sources = max_sources_per_jail, .ignore_capacity = 128, .custom = assets != null };
                settings.timestamp = switch (timestamp) {
                    .undated => .undated,
                    .iso8601 => .{ .field = .{ .format = .iso8601, .boundary = .{ .delimiter = ' ' } } },
                    .syslog => .{ .field = .{ .format = .syslog, .boundary = .{ .length = 15 }, .infer_year = true, .zone = zone, .context = .{ .offset_seconds = if (zone != null) null else @as(i32, selected.timezone_offset_minutes orelse return error.NativeTimezoneRequired) * 60 } } },
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
                        std.log.err("native: jail '{s}': cannot resolve trusted SSH journal executables: {s}; configure journal_executables explicitly for a nonstandard installation", .{ selected.name, @errorName(err) });
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
                break :blk .{ .journal = try journal_projection.Plan.create(a, &selected_cfg, 0, parent_generation, .{ .machine_id = std.mem.trim(u8, machine, "\n"), .executables = executables, .ignore_capacity = 128, .custom = assets != null, .journal = .{ .batch_records = 1, .matches = matches } }) };
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

    const readiness_progress_ceiling_ns: i128 = 300 * std.time.ns_per_s;
    fn reportStartup(self: *Coordinator, phase: sd_notify.Phase, label: []const u8, done: u64, total: u64) void {
        if (self.startup_progress) |progress| progress.report(phase, label, done, total);
    }
    fn reportReadinessProgress(self: *Coordinator, report: readiness.Report) void {
        var verified: u64 = 0;
        var pending: ?readiness.Component = null;
        for (report.components, 0..) |state, i| {
            if (state == .ok) verified += 1 else if (pending == null) pending = @enumFromInt(i);
        }
        const done = verified +| self.readiness_history_pages +| if (self.effects) |manager| manager.counters.install_batches else 0;
        const now = std.time.nanoTimestamp();
        if (self.readiness_progress_started_ns == null or done != self.readiness_progress_done) {
            self.readiness_progress_started_ns = now;
            self.readiness_progress_done = done;
        }
        // History pages count only up to the head seen when readiness began, so ingestion cannot extend the start; the ceiling bounds any stall.
        if (now - self.readiness_progress_started_ns.? > readiness_progress_ceiling_ns) return;
        self.reportStartup(.readiness, if (pending) |component| component.name() else "readiness", done, 0);
    }
    fn prepareStore(self: *Coordinator) !void {
        self.store.runtime_path = self.cfg.global.state_file;
        try self.store.configureRuntimeLimits();
        try self.store.prepareCurrentSchema(.{
            .maximum_pending = durable.Limits.pending_receipts,
            .migration = self.loadRepairOptions(),
            .progress = if (self.startup_progress) |progress| progress.migrationHook() else null,
        });
        try self.retireUnconfiguredJails();
        try self.retireUnusedSharedDns();
        try self.rekeySavedGenerations();
        try self.completeGenerationRekeys();
        try self.rebuildIgnoreLists();
        // Apply the new source capacity after retiring the old jail population.
        const maximum_pending = self.jails.len * max_sources_per_jail;
        if (try self.store.pendingReceiptCount() > maximum_pending) return error.ReceiptLimit;
        self.store.receipt_limit = maximum_pending;
    }
    fn admitStore(self: *Coordinator) !void {
        try self.prepareStore();
        try self.validateAdmission();
        if (!self.generation_admitted) {
            const admitted = try self.admitConfigGeneration();
            self.published_generation = admitted.generation;
            self.published_config_digest = admitted.digest;
            self.generation_admitted = true;
        }
        try self.readAdminState();
    }
    fn readAdminState(self: *Coordinator) !void {
        self.published_revision = try self.store.adminRevision();
        for (self.jails) |*jail| {
            var state: durable.Store.JailAdminState = undefined;
            if (try self.store.jailAdminState(jail.name, &state)) {
                jail.disable_progress = if (state.enabled) null else .{ .request_id = state.request_id };
                self.mutex.lock();
                jail.admin_paused = state.paused;
                jail.admin_enabled = state.enabled;
                jail.disable_cleanup_pending = !state.enabled;
                self.mutex.unlock();
            }
        }
    }

    fn retirementWait(self: *Coordinator) void {
        self.stop_mutex.lock();
        defer self.stop_mutex.unlock();
        if (!self.stopping) self.wake.timedWait(&self.stop_mutex, tick_wait_ns) catch {};
    }
    fn finishRetirementTurn(self: *Coordinator, intent: durable.Store.JailRetirementIntent, cursor: *effect_runtime.JailRetirementWithdrawalCursor) !?durable.Store.JailRetirementPage {
        const now = self.clock.wallUs();
        const clock: effect.Clock = .{ .prepared_us = now, .context = self, .read = wallClockEffect };
        if (try self.store.readInstallation() == null)
            return try self.store.finishJailRetirement(.{ .intent = intent, .verification = .no_installation }, clock);
        try self.ensureRetirementEffects();
        const manager = self.effects.?;
        const before = .{ self.store.effect_publication_epoch, manager.staged_count, manager.view_revision, manager.counters.full_readbacks, cursor.after };
        const outcome = manager.withdrawJailRetirement(intent, cursor);
        const after = .{ self.store.effect_publication_epoch, manager.staged_count, manager.view_revision, manager.counters.full_readbacks, cursor.after };
        if (self.gate.snapshot().phase != .healthy and !std.meta.eql(before, after)) {
            self.startup_retirement_progress +|= 1;
            self.reportStartup(.maintenance, "jail retirement withdrawal", self.startup_retirement_progress, 0);
        }
        switch (outcome) {
            .verified => |proof| return try self.store.finishJailRetirement(proof, clock),
            .step => |step| switch (step) {
                .fatal => |failure| return failure,
                .idle, .progress => return null,
                .stop => if (stopRequested(self)) return error.NativeStartupStopped else return null,
                .wait => {
                    if (self.gate.snapshot().phase != .healthy) self.retirementWait();
                    return null;
                },
            },
        }
    }
    fn completeStartupRetirement(self: *Coordinator, intent: durable.Store.JailRetirementIntent) !void {
        if (self.effects) |manager| manager.beginJailRetirementObservation();
        var cursor: durable.Store.JailRetirementCursor = .{};
        var withdrawal: effect_runtime.JailRetirementWithdrawalCursor = .{};
        var max_rows: u8 = 64;
        var owners_released: u32 = 0;
        var bans_lifted: u32 = 0;
        var deleted_rows: u64 = 0;
        while (true) {
            if (stopRequested(self)) return error.NativeStartupStopped;
            if (cursor.phase == .finish) {
                const finished = self.finishRetirementTurn(intent, &withdrawal) catch |failure| {
                    if (failure != error.StaleEffect) return failure;
                    cursor = .{};
                    withdrawal = .{};
                    continue;
                };
                if (finished != null) break;
                continue;
            }
            const now = self.clock.wallUs();
            const page = try self.store.retireJailPage(intent.jail.slice(), cursor, max_rows, now, .{ .prepared_us = now, .context = self, .read = wallClockEffect });
            if (page.yielded) {
                max_rows = @max(1, max_rows / 2);
                continue;
            }
            cursor = page.next;
            owners_released = std.math.add(u32, owners_released, page.owners_released) catch return error.EffectCapacity;
            bans_lifted = std.math.add(u32, bans_lifted, page.bans_lifted) catch return error.EffectCapacity;
            deleted_rows +|= page.deleted_rows;
            self.startup_retirement_progress +|= 1;
            var label: [96]u8 = undefined;
            self.reportStartup(.maintenance, std.fmt.bufPrint(&label, "jail retirement: {d} releases, {d} deleted", .{ owners_released, deleted_rows }) catch "jail retirement", self.startup_retirement_progress, 0);
            if (page.reconcile) |request| {
                try self.ensureRetirementEffects();
                while (true) {
                    if (stopRequested(self)) return error.NativeStartupStopped;
                    const manager = self.effects.?;
                    const before = .{ self.store.effect_publication_epoch, manager.staged_count, manager.view_revision, manager.counters.full_readbacks };
                    const outcome = manager.reconcileJailRetirement(request);
                    const after = .{ self.store.effect_publication_epoch, manager.staged_count, manager.view_revision, manager.counters.full_readbacks };
                    if (!std.meta.eql(before, after)) {
                        self.startup_retirement_progress +|= 1;
                        self.reportStartup(.maintenance, "jail retirement reconciliation", self.startup_retirement_progress, 0);
                    }
                    switch (outcome) {
                        .idle => break,
                        .progress => {},
                        .wait => self.retirementWait(),
                        .stop => if (stopRequested(self)) return error.NativeStartupStopped else self.retirementWait(),
                        .fatal => |failure| return failure,
                    }
                }
            }
        }
        std.log.info("native: jail={} retirement completed this start: {d} owner releases, {d} bans lifted, {d} operational rows deleted", .{ std.zig.fmtEscapes(intent.jail.slice()), owners_released, bans_lifted, deleted_rows });
        if (self.findJail(intent.jail.slice())) |jail| if (jail.retiring) {
            const index = (@intFromPtr(jail) - @intFromPtr(self.jails.ptr)) / @sizeOf(Jail);
            try self.removeJail(index);
        };
    }
    fn retireUnconfiguredJails(self: *Coordinator) !void {
        var intents: [max_jails]durable.Store.JailRetirementIntent = undefined;
        const pending = try self.store.jailRetirements(&intents);
        for (intents[0..pending]) |intent| try self.completeStartupRetirement(intent);
        const cfg = self.live_cfg;
        const names = try self.allocator.alloc([]const u8, cfg.jails.len + self.jails.len);
        defer self.allocator.free(names);
        var named: usize = 0;
        for (cfg.jails) |jail| if (jail.enabled) {
            names[named] = jail.name;
            named += 1;
        };
        for (self.jails) |jail| if (!jail.retiring) {
            names[named] = jail.name;
            named += 1;
        };
        var found: [max_jails][64]u8 = undefined;
        const count = try self.store.unconfiguredJails(names[0..named], &found);
        for (found[0..count]) |*raw| {
            const name = std.mem.sliceTo(raw, 0);
            const disabled = if (findConfigJail(cfg, name)) |jail| !jail.enabled else false;
            try self.store.beginJailRetirement(name, disabled);
            try self.completeStartupRetirement((try self.store.jailRetirement(name)).?);
        }
        if (self.retirement_manager_only) self.destroyEffects();
    }
    fn retireUnusedSharedDns(self: *Coordinator) !void {
        if (self.custom_jails != 0) return;
        if (self.dns) |resolver| {
            if (resolver.count != 0) return error.ConsumerBusy;
            resolver.destroy();
            self.dns = null;
        }
        while (true) {
            if (stopRequested(self)) return error.NativeStartupStopped;
            switch (try self.store.retireUnusedSharedDnsPage()) {
                .done => return,
                .pinned => return error.MaintenancePinned,
                .progressed => {
                    self.startup_retirement_progress +|= 1;
                    self.reportStartup(.maintenance, "unused shared DNS retirement", self.startup_retirement_progress, 0);
                },
            }
        }
    }
    fn ownedGeneration(self: *Coordinator, name: []const u8) !?[32]u8 {
        if (self.owner_scratch.len == 0 or try self.store.readInstallation() == null) return null;
        for ([_]shared.types.Origin{ .detection, .manual, .config }) |origin| {
            if (try self.store.ownersByOrigin(origin, name, self.owner_scratch) == 0) continue;
            const owner = try self.store.currentOwner(self.owner_scratch[0].key, name) orelse continue;
            return owner.generation;
        }
        return null;
    }
    fn queueWithdrawal(self: *Coordinator, name: []const u8, generation: ?[32]u8, bans_lifted: u32) !void {
        logJailRemoved(name, bans_lifted);
        const selected = generation orelse return;
        var pending = PendingWithdrawal{ .name = [_]u8{0} ** 64, .name_len = @intCast(name.len), .generation = selected, .bans_lifted = bans_lifted };
        @memcpy(pending.name[0..name.len], name);
        try self.pending_withdrawals.append(self.allocator, pending);
    }
    fn logJailRemoved(name: []const u8, bans_lifted: u32) void {
        std.log.info("native: jail={} removed: {d} bans lifted", .{ std.zig.fmtEscapes(name), bans_lifted });
    }
    fn withdrawRetiredJails(self: *Coordinator) !void {
        if (comptime build_options.diag) diag_mod.gauge(.withdraw_pending, self.pending_withdrawals.items.len);
        var index: usize = 0;
        while (index < self.pending_withdrawals.items.len) {
            const pending = &self.pending_withdrawals.items[index];
            if (self.effects) |manager| switch (manager.retireJail(pending.jailName(), pending.generation)) {
                .idle => {},
                .fatal => |failure| return failure,
                .progress, .wait, .stop => {
                    index += 1;
                    continue;
                },
            };
            _ = self.pending_withdrawals.orderedRemove(index);
            if (comptime build_options.diag) {
                diag_mod.count(.withdraw_completed, 1);
                diag_mod.gauge(.withdraw_pending, self.pending_withdrawals.items.len);
            }
        }
    }
    fn rekeySavedGenerations(self: *Coordinator) !void {
        var rekeyed_jails: u32 = 0;
        var rekeyed_rows: u32 = 0;
        for (self.jails) |*jail| {
            if (jail.custom_plan != null) continue;
            const live_policy = jail.policy;
            if (try self.store.readRetryPolicy(jail.name)) |saved| jail.policy.max_subjects = saved.policy.max_subjects;
            const legacy = self.plannedGeneration(jail, .legacy) catch |err| {
                jail.policy = live_policy;
                return err;
            };
            jail.policy = live_policy;
            const planned = try self.plannedGeneration(jail, .planned);
            const cursors: durable.Store.CursorRekey = switch (jail.plan) {
                .file => |*plan| blk: {
                    const processing = plan.sessionOptions().processing;
                    break :blk .{ .file = .{
                        .legacy = files.FileSource.framingBinding(processing.encoding, legacy, processing.max_record_bytes),
                        .planned = files.FileSource.framingBinding(processing.encoding, planned, processing.max_record_bytes),
                    } };
                },
                .journal => .journal,
                .internal => .none,
            };
            const report = try self.store.rekeySavedGenerations(jail.name, legacy, planned, cursors);
            const rows = @as(u64, report.retry_rows) + report.pending_receipts + report.manifests + report.cursors;
            if (rows == 0) continue;
            rekeyed_jails += 1;
            rekeyed_rows +|= @intCast(@min(rows, std.math.maxInt(u32)));
        }
        if (rekeyed_jails != 0) std.log.info("native storage: saved detection generations rekeyed without the ignore list or the subject share: jails={d} rows={d}; no ban, deadline, checkpoint or retry subject changed", .{ rekeyed_jails, rekeyed_rows });
    }
    fn completeGenerationRekeys(self: *Coordinator) !void {
        for (self.jails) |*jail| {
            if (jail.custom_plan) |assets| {
                const state = try self.store.customIgnoreState(self.allocator, jail.name) orelse continue;
                defer state.deinit(self.allocator);
                if (state.value.format_version != custom_ignore.version) continue;
                if (!std.mem.eql(u8, &state.parent, &assets.parent_generation)) return error.CustomLegacyIdentityMismatch;
                const current = try custom_ignore.Snapshot.restore(self.allocator, assets.ignore_options, state.value.payload.?);
                current.destroy();
                const policy = try self.store.readRetryPolicy(jail.name) orelse return error.RetryAdmissionRequired;
                if (!std.mem.eql(u8, &policy.generation, &try self.plannedGeneration(jail, .planned)) or !try durable.Store.retryPoliciesEqual(policy.policy, jail.policy)) return error.RetryGenerationMismatch;
            }
            const repair = try self.store.completeGenerationRekey(jail.name);
            if (repair.receipts == 0 and repair.retired == 0 and repair.cursors == 0 and repair.guards == 0) continue;
            std.log.info("native storage: generation rekey completed: jail={} receipts={d} retired={d} cursors={d} guards={d}; left by an earlier policy reload; no ban, deadline, checkpoint position or record changed", .{ std.zig.fmtEscapes(jail.name), repair.receipts, repair.retired, repair.cursors, repair.guards });
        }
    }
    pub fn ignoreCell(jail: *const Jail) ?**ignore_set.EffectiveIgnore {
        return switch (jail.plan) {
            .file => |plan| plan.ignore_cell,
            .journal => |plan| plan.ignore_cell,
            .internal => null,
        };
    }
    pub const PreparedCustomPolicy = struct {
        policy: consumer_runtime.JailRuntime.PreparedPolicy,
        reservation: resource.Token,

        pub fn deinit(self: *PreparedCustomPolicy, owner: *Coordinator) void {
            self.policy.deinit();
            owner.resources.release(self.reservation) catch |failure| std.log.err("native: custom policy reservation release failed: {s}", .{@errorName(failure)});
        }
    };
    pub fn prepareCustomPolicy(self: *Coordinator, jail: *Jail, cfg: *const config.Config, now_us: i64, initial: bool) !?PreparedCustomPolicy {
        const runtime = jail.consumer orelse return null;
        const assets = jail.custom_plan orelse return error.ConsumerRuntimeNotReady;
        const configured = findConfigJail(cfg, jail.name) orelse return error.UnknownJail;
        const cost = resource.Cost{ .bytes = @sizeOf(custom_ignore.Snapshot) + custom_ignore.max_entries * @sizeOf(custom_ignore.Entry) + 2 * custom_ignore.max_checkpoint_bytes + custom_ignore.max_file_bytes, .allocations = 4, .fds = @intFromBool(!initial and configured.ignore_file != null) };
        const token = try self.resources.reserve(.configuration, cost);
        var held = false;
        defer if (!held) self.resources.release(token) catch |failure| std.log.err("native: custom policy reservation release failed: {s}", .{@errorName(failure)});
        const next = if (initial)
            try custom_ignore.Snapshot.restore(self.allocator, assets.ignore_options, assets.initial_ignore.payload)
        else
            try consumer_plan.Prepared.buildIgnore(self.allocator, runtime.ignores.live.options, configured.ignoreip orelse cfg.defaults.ignoreip, configured.ignore_file);
        const policy = try runtime.preparePolicy(next, now_us) orelse return null;
        held = true;
        return .{ .policy = policy, .reservation = token };
    }
    const DeadlineMode = enum { apply, read, preview };
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
    fn ignoreLiterals(cfg: *const config.Config, jail_cfg: ?*const config.JailConfig) []const []const u8 {
        const value = jail_cfg orelse return &.{};
        return value.ignoreip orelse cfg.defaults.ignoreip;
    }
    pub fn configuredIgnoreDeadlines(allocator: std.mem.Allocator, store: *durable.Store, name: []const u8, literals: []const []const u8, ignoretime_s: ?u64, mode: DeadlineMode, now_us: i64) ![]?i64 {
        const prepared = try prepareIgnoreDeadlines(allocator, store, name, literals, ignoretime_s, mode, now_us);
        allocator.free(prepared.entries);
        allocator.free(prepared.stored);
        return prepared.literals;
    }
    pub fn prepareIgnoreDeadlines(allocator: std.mem.Allocator, store: *durable.Store, name: []const u8, literals: []const []const u8, ignoretime_s: ?u64, mode: DeadlineMode, now_us: i64) !PreparedIgnoreDeadlines {
        var timed = try allocator.alloc(shared.types.TimedEntry, literals.len);
        errdefer allocator.free(timed);
        const count = try ignore_set.configuredEntries(literals, ignoretime_s, timed);
        timed = try allocator.realloc(timed, count);
        const stored = try allocator.alloc(?i64, count);
        errdefer allocator.free(stored);
        switch (mode) {
            .apply => try store.applyConfigDeadlines(.ignoreip, name, timed, now_us, stored),
            .read => try store.configEntryDeadlines(.ignoreip, name, timed, stored),
            .preview => try store.previewConfigDeadlines(.ignoreip, name, timed, now_us, stored),
        }
        const deadlines = try allocator.alloc(?i64, literals.len);
        var next: usize = 0;
        for (literals, deadlines) |literal, *slot| {
            slot.* = null;
            _ = shared.types.TimedEntry.parse(literal, ignoretime_s) catch continue;
            slot.* = stored[next];
            next += 1;
        }
        return .{ .entries = timed, .stored = stored, .literals = deadlines };
    }
    pub fn selfAddressList(self: *const Coordinator) []const shared.IpAddress {
        return if (self.self_addresses) |list| list.addresses else &.{};
    }
    pub fn readSelfAddresses(self: *Coordinator) ?shared.self_addresses.SelfAddresses {
        return shared.self_addresses.read(self.allocator) catch |failure| {
            std.log.warn("native: this host's addresses could not be read: {s}; ignoreself covers no address until the next reload", .{@errorName(failure)});
            return null;
        };
    }
    pub fn effectiveIgnore(self: *Coordinator, cfg: *const config.Config, name: []const u8, own: []const shared.IpAddress, mode: DeadlineMode, now_us: i64) !*ignore_set.EffectiveIgnore {
        const jail_cfg = findConfigJail(cfg, name);
        const literals = ignoreLiterals(cfg, jail_cfg);
        const resolved: ?config.ResolvedJailConfig = if (jail_cfg) |value| config.resolveJailFromConfig(value, cfg.defaults) else null;
        const deadlines = try configuredIgnoreDeadlines(self.allocator, &self.store, name, literals, if (resolved) |value| value.ignoretime_s else null, mode, now_us);
        defer self.allocator.free(deadlines);
        return self.effectiveIgnoreWithDeadlines(cfg, name, own, deadlines, now_us);
    }
    pub fn effectiveIgnoreWithDeadlines(self: *Coordinator, cfg: *const config.Config, name: []const u8, own: []const shared.IpAddress, deadlines: []const ?i64, now_us: i64) !*ignore_set.EffectiveIgnore {
        var runtime: [ignore_set.max_entries_per_part]RuntimeIgnoreEntry = undefined;
        const count = try self.store.ignoreEntries(name, &runtime);
        const jail_cfg = findConfigJail(cfg, name);
        const literals = ignoreLiterals(cfg, jail_cfg);
        const resolved: ?config.ResolvedJailConfig = if (jail_cfg) |value| config.resolveJailFromConfig(value, cfg.defaults) else null;
        const listed: []const shared.IpAddress = if (resolved != null and resolved.?.ignoreself) own else &.{};
        return ignore_set.EffectiveIgnore.build(self.allocator, literals, deadlines, runtime[0..count], listed, now_us);
    }
    pub fn previewIgnoreDeadlines(self: *Coordinator, cfg: *const config.Config, name: []const u8, now_us: i64) !PreparedIgnoreDeadlines {
        const jail_cfg = findConfigJail(cfg, name);
        const ignoretime_s = if (jail_cfg) |value| config.resolveJailFromConfig(value, cfg.defaults).ignoretime_s else null;
        return prepareIgnoreDeadlines(self.allocator, &self.store, name, ignoreLiterals(cfg, jail_cfg), ignoretime_s, .preview, now_us);
    }
    pub fn replaceIgnoreList(self: *Coordinator, jail: *Jail, next: *ignore_set.EffectiveIgnore) void {
        const cell = ignoreCell(jail) orelse return next.deinit(self.allocator);
        var runtime_only: u16 = 0;
        for (next.entries) |item| runtime_only += @intFromBool(item.source == .runtime);
        self.mutex.lock();
        const previous = cell.*;
        cell.* = next;
        jail.ignore_runtime_only = runtime_only;
        self.mutex.unlock();
        previous.deinit(self.allocator);
    }
    pub fn applyIgnoreDeadlines(self: *Coordinator, cfg: *const config.Config, name: []const u8, now_us: i64) !void {
        const jail_cfg = findConfigJail(cfg, name);
        const ignoretime_s = if (jail_cfg) |value| config.resolveJailFromConfig(value, cfg.defaults).ignoretime_s else null;
        self.allocator.free(try configuredIgnoreDeadlines(self.allocator, &self.store, name, ignoreLiterals(cfg, jail_cfg), ignoretime_s, .apply, now_us));
    }
    fn rebuildIgnoreList(self: *Coordinator, jail: *Jail, now_us: i64) !void {
        if (ignoreCell(jail) == null) return;
        self.replaceIgnoreList(jail, try self.effectiveIgnore(self.live_cfg, jail.name, self.selfAddressList(), .read, now_us));
    }
    fn rebuildIgnoreLists(self: *Coordinator) !void {
        const now = self.clock.wallUs();
        for (self.jails) |*jail| {
            if (ignoreCell(jail) == null) {
                try self.applyIgnoreDeadlines(self.live_cfg, jail.name, now);
                continue;
            }
            const next = try self.effectiveIgnore(self.live_cfg, jail.name, self.selfAddressList(), .apply, now);
            if (next.over_bound) std.log.warn("native: jail={} has {d} ignore entries ({d} configured, {d} runtime-only), above the {d}-entry limit; all apply; fail2zig ignore add is refused until the count is {d} or less", .{ std.zig.fmtEscapes(jail.name), next.entries.len, next.configured_count, next.entries.len - next.configured_count, ignore_set.distinct_bound, ignore_set.distinct_bound });
            self.replaceIgnoreList(jail, next);
        }
        var stored: [256]durable.Store.IgnoreJailCount = undefined;
        const stored_count = try self.store.ignoreEntryJails(&stored);
        for (stored[0..stored_count]) |item| {
            const name = item.jail[0..item.jail_len];
            if (findConfigJail(self.live_cfg, name) != null) continue;
            std.log.warn("native: {d} runtime ignore entries are stored for jail {}, which is not configured; they are not effective", .{ item.count, std.zig.fmtEscapes(name) });
        }
    }
    fn loadRepairOptions(self: *Coordinator) durable.load_repair.Options {
        return .{ .state_path = self.cfg.global.state_file, .now_us = self.clock.wallUs(), .history_max_matches = self.cfg.global.history_max_matches };
    }
    fn validatePreflightInstallation(self: *Coordinator) !void {
        const expected = if (self.preflight_schema_version == 0) 0 else @max(self.preflight_schema_version, 2);
        if (self.store.schema_version != expected) return error.NativeStateChanged;
        if (self.preflight_schema_version < 11) return;
        const current = try self.store.readInstallation();
        if (!std.meta.eql(current, self.preflight_installation)) return error.InstallationMismatch;
    }
    const ConfigAdmission = struct { generation: [32]u8, digest: [32]u8 };
    fn admitConfigGeneration(self: *Coordinator) !ConfigAdmission {
        const digest = try self.configDigest();
        var retention_rows: [config.max_configured_jails]durable.Store.JailRetentionLimit = undefined;
        const retention = try retentionUpdate(self.live_cfg, &retention_rows);
        if (try self.store.latestConfigGeneration()) |head| {
            if (head.published and std.mem.eql(u8, &head.config_digest, &digest)) {
                _ = try self.store.setRetentionPolicies(retention);
                return .{ .generation = head.generation, .digest = digest };
            }
            if (!head.published) return error.ConfigGenerationUnpublished;
        }
        const now = self.clock.wallUs();
        const generation = reload_mod.generationId(digest, now);
        var jails: [max_jails]durable.Store.ConfigGenerationJail = undefined;
        for (self.jails, 0..) |*jail, i| jails[i] = .{ .jail = jail.name, .digest = try reload_mod.jailDigest(jail.name, jail.policy, try self.plannedGeneration(jail, .planned)), .allowlist_snapshot = if (jail.custom_plan) |assets| assets.initial_ignore.payload else "" };
        try self.store.recordConfigGeneration(.{ .generation = generation, .config_digest = digest, .config_path = self.config_path, .committed_us = now, .published = true, .mutation_revision = try self.store.adminRevision() }, jails[0..self.jails.len], retention);
        return .{ .generation = generation, .digest = digest };
    }
    fn customRebindProgress(context: ?*anyopaque, completed: u64) void {
        const self: *Coordinator = @ptrCast(@alignCast(context.?));
        self.reportStartup(.recovery, "custom state rebind", completed, 0);
    }
    pub fn retentionUpdate(cfg: *const config.Config, rows: *[config.max_configured_jails]durable.Store.JailRetentionLimit) !durable.Store.RetentionUpdate {
        if (cfg.jails.len > rows.len) return error.TooManyJails;
        for (cfg.jails, rows[0..cfg.jails.len]) |jail, *row| row.* = .{ .jail = jail.name, .max_matches = jail.history_max_matches };
        return .{ .global_max_matches = cfg.global.history_max_matches, .jails = rows[0..cfg.jails.len] };
    }
    fn configDigest(self: *Coordinator) ![32]u8 {
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
    pub fn ignoreSourceText(source: ?ignore_set.Source) ?[]const u8 {
        return switch (source orelse return null) {
            .config => "config",
            .runtime => "runtime",
            .both => "config+runtime",
            .self => "self",
        };
    }
    fn validateAdmission(self: *Coordinator) !void {
        var names: [max_jails][]const u8 = undefined;
        for (self.jails, 0..) |jail, i| names[i] = jail.name;
        try self.store.validateRuntimeOwnerNames(names[0..self.jails.len]);
        for (self.jails) |jail| if (jail.custom_plan != null) try self.store.validateCustomSourceManifests(jail.name);
        var admissions: [max_jails]durable.Store.RuntimeAdmission = undefined;
        for (self.jails, 0..) |*jail, i| admissions[i] = .{
            .jail = jail.name,
            .generation = try self.plannedGeneration(jail, .planned),
            .policy = jail.policy,
            .custom = jail.custom_plan != null,
        };
        self.store.validateRuntimeAdmissions(admissions[0..self.jails.len], if (self.custom_jails != 0 and self.dns_server != null) self.dns_generation else null) catch |err| {
            if (err == error.RetryGenerationMismatch) std.log.err("native: source/profile or policy differs from saved state; restore the previous source configuration and SSH executable layout before restarting; retain the database", .{});
            return err;
        };
        if (self.startup_installation) |selected| if (try self.store.readInstallation()) |saved| {
            if (!std.meta.eql(saved, selected)) return error.InstallationMismatch;
        } else if (self.startup_installation_persisted) return error.InstallationMismatch;
    }
    fn preflightSource(_: []const u8, _: [32]u8, _: ?*anyopaque) anyerror!void {
        return error.ConsumerRuntimeNotReady;
    }
    const GenerationMode = enum { planned, legacy };
    pub fn plannedGeneration(self: *Coordinator, jail: *Jail, mode: GenerationMode) ![32]u8 {
        var registry = consumer_bridge.Registry.init([_]u8{0} ** 32);
        if (jail.custom_plan) |assets| {
            var settings = assets.settings;
            settings.journal_origin = switch (jail.plan) {
                .file => null,
                .journal => |value| &value.profile,
                .internal => null,
            };
            settings.monotonic_ms = monotonic;
            settings.authority_revision = if (self.dns_server != null) 1 else 0;
            registry.generation = try consumer_bridge.generationFromPolicy(settings, assets.programs, assets.initial_ignore, if (self.dns_server != null) self.dns_generation else null);
        }
        var scratch: [2048]u8 = undefined;
        return switch (jail.plan) {
            .file => |*plan| blk: {
                var options = if (mode == .legacy) plan.legacySessionOptions() else plan.sessionOptions();
                options.retry = jail.policy;
                options.retry_hash = if (mode == .legacy) .stored else .identity;
                options.suppress_retry_enforcement = self.suppress_enforcement;
                if (jail.custom_plan != null) {
                    options.staged_detection = registry.consumer();
                    options.consumer_sources = .{ .context = null, .admit = preflightSource };
                }
                const processor = try sessions.Session.prepareProcessor(self.allocator, options, plan.specs, &scratch, .{ .us = 0 });
                break :blk processor.generation;
            },
            .journal => |plan| blk: {
                var options = if (mode == .legacy) plan.legacySessionOptions() else plan.sessionOptions();
                options.retry = jail.policy;
                options.retry_hash = if (mode == .legacy) .stored else .identity;
                options.suppress_retry_enforcement = self.suppress_enforcement;
                if (jail.custom_plan != null) {
                    options.staged_detection = registry.consumer();
                    options.consumer_sources = .{ .context = null, .admit = preflightSource };
                }
                const processor = try journal_sessions.Session.prepareProcessor(self.allocator, options, &scratch, .{ .us = 0 });
                break :blk processor.generation;
            },
            .internal => |generation| if (mode == .legacy) try internalGeneration(jail.name, jail.policy, .stored) else generation,
        };
    }
    fn driver(self: *Coordinator) recovery.Driver {
        return .{ .store = &self.store, .gate = &self.gate, .clock = .{ .generation = [_]u8{0} ** 32, .clock_context = &self.clock, .clock = clock_mod.wallTimestamp }, .hooks = .{ .context = self, .storage = recoverStorage, .state = recoverState, .ownership = recoverOwnership, .sources = recoverSources, .turn = recoverTurn } };
    }
    fn recoverTurn(stage: health.RecoveryStep, ctx: ?*anyopaque) !bool {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        const generation = self.gate.snapshot().generation;
        if (self.recovery_generation == null or self.recovery_generation.? != generation) {
            self.recovery_generation = generation;
            self.restore_jail = 0;
            self.verify_jail = 0;
            self.ownership_fenced = false;
            self.rebuild_phase = .maintenance;
            if (self.gate.snapshot().has_been_healthy) {
                self.maintenance_validation = .{};
                self.maintenance_validated = false;
            }
            self.validation_phase = .sources;
            self.validation_jail = 0;
            self.consumer_cursor_len = 0;
            self.consumer_scan_revision = null;
        }
        if (stage != .storage and self.store_open and !self.store.reopen_required and self.store.retry_projection_initialized and !self.store.startup_admission and self.store.retry_admission_target_hint != null) {
            if (try self.store.retryAdmissionStep(256) == .progressed) {
                self.retryPublicationPending(null);
                return false;
            }
        }
        switch (stage) {
            .storage => try recoverStorage(ctx),
            .state => {
                try recoverState(ctx);
                return self.rebuild_phase == .done;
            },
            .ownership => {
                if (!self.ownership_fenced) {
                    try self.store.finishMaintenanceValidation(&self.maintenance_validation);
                    self.ownership_fenced = true;
                }
                try self.ensureEffects();
                if (self.effects) |manager| if (!try self.effectSlice(manager)) return false;
                if (self.history_consumer == null) try self.restoreHistory();
                if (!(self.consumeHistory() catch |failure| {
                    if (failure == error.RetryEligibilityPending) {
                        self.retryPublicationPending(null);
                        return false;
                    }
                    return failure;
                })) return false;
                try recoverOwnership(ctx);
            },
            .sources => {
                recoverSources(ctx) catch |failure| {
                    if (failure == error.SourceRepairPending) return false;
                    return failure;
                };
                return self.validation_phase == .done;
            },
        }
        return true;
    }
    pub fn effectBindings(self: *Coordinator, output: *[max_jails]effect_runtime.Binding) void {
        for (self.jails, 0..) |jail, i| output[i] = .{ .jail = jail.name, .generation = jail.session.?.generation() };
    }
    fn verifyNamespace(self: *Coordinator) !void {
        const selected = try std.fs.openFileAbsolute(self.cfg.global.firewall_namespace, .{});
        defer selected.close();
        const current = try std.fs.openFileAbsolute("/proc/self/ns/net", .{});
        defer current.close();
        const a = try std.posix.fstat(selected.handle);
        const b = try std.posix.fstat(current.handle);
        if (a.dev != b.dev or a.ino != b.ino) return error.FirewallNamespaceMismatch;
        const held = try std.posix.fstat((self.namespace_lock orelse return error.NativeNamespaceLockRequired).handle);
        if (a.dev != held.dev or a.ino != held.ino) return error.FirewallNamespaceMismatch;
    }
    fn verifyStateIdentity(self: *Coordinator) !void {
        errdefer |failure| {
            if (!std.meta.eql(self.last_identity_failure, @as(?anyerror, failure))) {
                logStateOpenFailure("authority identity check", self.cfg.global.state_file, failure, .{});
                self.last_identity_failure = failure;
            }
        }
        const held = try std.posix.fstat((self.authority_lock orelse return error.NativeAuthorityLockRequired).handle);
        const selected = try std.posix.fstatat(std.posix.AT.FDCWD, self.cfg.global.state_file, std.posix.AT.SYMLINK_NOFOLLOW);
        if (held.dev != selected.dev or held.ino != selected.ino or !std.posix.S.ISREG(selected.mode)) return error.NativeStateReplaced;
        self.last_identity_failure = null;
    }
    fn ensureEffects(self: *Coordinator) !void {
        if (self.effects != null) {
            try self.verifyNamespace();
            return;
        }
        var enforcing = false;
        for (self.jails) |*jail| enforcing = enforcing or self.jailEnforces(jail);
        if (!enforcing) return;
        try self.verifyNamespace();
        var installation = try self.store.readInstallation();
        const selected = self.startup_installation orelse return error.NoFirewallBackend;
        if (installation) |saved| {
            if (!std.meta.eql(saved, selected)) return error.InstallationMismatch;
        } else if (self.startup_installation_persisted) return error.InstallationMismatch else {
            try self.store.admitInstallation(selected, .{ .selector = selected.selector(), .disposition = .verified_absent });
            installation = selected;
        }
        try self.constructEffects(installation.?);
    }
    fn constructEffects(self: *Coordinator, installation: effect.Installation) !void {
        const manager = try effect_runtime.Manager.create(self.allocator, &self.store, installation);
        manager.wall_context = &self.clock;
        manager.wall = clock_mod.wallRead;
        manager.monotonic_context = &self.clock;
        manager.monotonic = clock_mod.monotonicNsRead;
        manager.last_wall_us = self.clock.wallUs();
        if (comptime build_options.diag) manager.setClockRate(self.clock.rate());
        manager.verify_interval_ns = verify_interval_ns;
        if (manager.inspector.installation.transport == .nftables) {
            if (manager.inspector.subscribe()) {
                manager.events_subscribed = true;
                manager.verify_interval_ns = audit_interval_ns;
            } else |failure| std.log.warn("firewall nftables: kernel event subscription unavailable ({s}); verifying every {d} s instead", .{ @errorName(failure), verify_interval_ns / std.time.ns_per_s });
        }
        if (self.firewall_observation_cache) |cache| manager.attachObservationCache(cache);
        self.effects = manager;
    }
    fn destroyEffects(self: *Coordinator) void {
        if (self.effects) |manager| manager.destroy();
        self.effects = null;
        if (self.retirement_effect_reservation) |token| self.resources.release(token) catch |failure| {
            std.log.err("native: retirement effect reservation release failed: {s}", .{@errorName(failure)});
        };
        self.retirement_effect_reservation = null;
        self.retirement_manager_only = false;
        if (self.retirement_namespace_only) {
            if (self.namespace_lock) |file| file.close();
            self.namespace_lock = null;
            self.retirement_namespace_only = false;
        }
    }
    fn ensureRetirementEffects(self: *Coordinator) !void {
        if (self.effects != null) {
            try self.verifyNamespace();
            return;
        }
        var enforcing = false;
        for (self.jails) |*jail| enforcing = enforcing or self.jailEnforces(jail);
        if (enforcing) return self.ensureEffects();
        const saved = try self.store.readInstallation() orelse return error.InstallationRequired;
        if (!std.meta.eql(@as(?effect.Installation, saved), self.preflight_installation)) return error.InstallationMismatch;
        switch (preflightBackend(self.allocator, self.live_cfg, true, saved)) {
            .selected => |selected| if (!std.meta.eql(selected.installation, saved)) return error.InstallationMismatch,
            .unavailable => |failure| return failure,
            .not_needed => return error.NoFirewallBackend,
        }
        if (comptime build_options.diag) if (self.clock.rate() == 0) return error.DiagStepModeEnforcing;
        var included = false;
        for (self.cfg.jails) |jail| if (jail.enabled and jail.effectiveBanaction(self.cfg.defaults) != .@"log-only") {
            included = true;
            break;
        };
        var cost: resource.Cost = .{};
        if (!included) {
            const component = try resource.effectCost(try resource.currentEnvironment());
            cost = try component.live.plus(component.workspace);
        }
        if (self.namespace_lock == null) cost.fds = std.math.add(usize, cost.fds, 1) catch return error.ResourceOverflow;
        self.retirement_effect_reservation = try self.resources.reserve(.effect, cost);
        self.retirement_manager_only = true;
        errdefer self.destroyEffects();
        if (self.namespace_lock == null) {
            self.namespace_lock = try lockFirewallNamespace(self.live_cfg);
            self.retirement_namespace_only = true;
        }
        try self.verifyNamespace();
        try self.constructEffects(saved);
    }
    fn recoverStorage(ctx: ?*anyopaque) !void {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        errdefer if (self.retirement_manager_only) self.destroyEffects();
        if (self.gate.snapshot().has_been_healthy) {
            try self.verifyStateIdentity();
            if (!self.store_open or self.store.reopen_required) {
                self.clearRetryPublication();
                if (self.effects) |manager| manager.storageReopened();
                if (self.store_open) {
                    self.store.close();
                    self.store_open = false;
                    self.store.last_error_code = null;
                    self.store.rollback_error_code = null;
                    self.store.reopen_required = true;
                }
                var open_diag: durable.OpenDiagnostic = .{};
                self.store = durable.Store.openRuntimeDetailed(self.allocator, self.cfg.global.state_file, &open_diag) catch |err| {
                    if (!std.meta.eql(self.last_open_failure, @as(?durable.OpenDiagnostic, open_diag))) {
                        logStateOpenFailure("runtime reopen", self.cfg.global.state_file, err, open_diag);
                        self.last_open_failure = open_diag;
                    }
                    return err;
                };
                if (self.last_open_failure != null) std.log.info("native: state runtime reopened; recovery checks pending", .{});
                self.last_open_failure = null;
                self.store_open = true;
                self.bindEffectInvalidation();
                try self.verifyStateIdentity();
            }
            try self.admitStore();
        }
    }
    pub fn sessionProcessor(jail: *const Jail) ?*const @import("core/native_source_processor.zig").Processor {
        const source = jail.session orelse return null;
        return switch (source) {
            .file => |value| &value.processor,
            .journal => |value| &value.processor,
            .internal => null,
        };
    }
    fn dropRuntimeJail(jail: *Jail) void {
        if (sessionProcessor(jail)) |processor| {
            jail.failures_carried +|= processor.failures_counted;
            jail.ignored_carried +|= processor.ignored_detections;
        }
        if (jail.session) |value| value.destroy();
        jail.session = null;
        jail.source_signature = .{};
        if (jail.consumer) |value| value.destroy();
        jail.consumer = null;
    }
    fn destroyRuntime(self: *Coordinator) void {
        for (self.jails) |*jail| {
            dropRuntimeJail(jail);
            if (jail.source_snapshot) |value| value.destroy();
            jail.source_snapshot = null;
        }
        if (self.dns) |value| value.destroy();
        self.dns = null;
    }
    fn validateMaintenancePages(self: *Coordinator) !bool {
        var timer = std.time.Timer.start() catch return self.store.validateMaintenanceTurn(&self.maintenance_validation);
        while (!try self.store.validateMaintenanceTurn(&self.maintenance_validation)) {
            if (timer.read() >= recovery_validation_budget_ns) return false;
        }
        return true;
    }
    fn recoverState(ctx: ?*anyopaque) !void {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        switch (self.rebuild_phase) {
            .maintenance => {
                if (!self.maintenance_validated) {
                    if (!try self.validateMaintenancePages()) return;
                    try self.store.finishMaintenanceValidation(&self.maintenance_validation);
                    self.maintenance_validated = true;
                }
                self.rebuild_phase = .capture;
            },
            .capture => {
                if (self.restore_jail < self.jails.len) {
                    const jail = &self.jails[self.restore_jail];
                    if (jail.rekeyed) {
                        if (jail.source_snapshot) |old| old.destroy();
                        jail.source_snapshot = null;
                    } else if (jail.session) |source| {
                        const next = try source.exportRecovery();
                        if (jail.source_snapshot) |old| old.destroy();
                        jail.source_snapshot = next;
                    }
                    self.restore_jail += 1;
                } else {
                    self.restore_jail = 0;
                    self.rebuild_phase = .drop;
                }
            },
            .drop => {
                if (self.restore_jail < self.jails.len) {
                    dropRuntimeJail(&self.jails[self.restore_jail]);
                    self.restore_jail += 1;
                } else {
                    if (self.dns) |value| value.destroy();
                    self.dns = null;
                    self.history_consumer = null;
                    self.history_page = null;
                    self.restore_jail = 0;
                    self.rebuild_phase = .resolver;
                }
            },
            .resolver => {
                if (self.custom_jails != 0) {
                    if (self.dns == null) self.dns = try consumer_runtime.DnsRuntime.create(self.allocator, &self.store, .{
                        .generation = self.dns_generation,
                        .server = self.dns_server,
                        .capacity = 1024,
                        .max_sources = self.custom_jails * max_sources_per_jail,
                        .max_owned_bytes = @as(usize, self.cfg.global.native_memory_ceiling_mb) * 1024 * 1024,
                        .clock = .{ .context = self, .read_us = wallClock, .read_ms = monotonic },
                    });
                    if (!try self.dns.?.restoreTurn()) return;
                }
                self.rebuild_phase = .owners;
            },
            .owners => {
                if (self.restore_jail == self.jails.len) {
                    self.rebuild_phase = .history;
                    return;
                }
                const jail = &self.jails[self.restore_jail];
                if (jail.custom_plan) |assets| {
                    var settings = assets.settings;
                    settings.journal_origin = switch (jail.plan) {
                        .file => null,
                        .journal => |value| &value.profile,
                        .internal => null,
                    };
                    jail.consumer = try consumer_runtime.JailRuntime.create(self.allocator, &self.store, self.dns.?, .{
                        .settings = settings,
                        .programs = assets.programs,
                        .initial_ignore = assets.initial_ignore,
                        .ignore_options = assets.ignore_options,
                        .max_sources = if (jail.plan == .journal) 1 else max_sources_per_jail,
                        .max_owned_bytes = @as(usize, self.cfg.global.native_memory_ceiling_mb) * 1024 * 1024,
                    });
                }
                errdefer if (jail.consumer) |value| {
                    value.destroy();
                    jail.consumer = null;
                };
                const next: Source = switch (jail.plan) {
                    .file => |*plan| blk: {
                        var options = plan.sessionOptions();
                        options.retry = jail.policy;
                        options.on_truncation = jail.on_truncation;
                        options.suppress_retry_enforcement = self.suppress_enforcement;
                        options.gate = &self.gate;
                        options.monotonic_clock = .{ .context = self, .read = monotonic };
                        options.wall_clock = .{ .context = &self.clock, .read = clock_mod.wallRead };
                        options.clock = clock_mod.wallTimestamp;
                        options.clock_context = &self.clock;
                        if (jail.consumer) |value| {
                            options.staged_detection = value.stagedConsumer();
                            options.consumer_sources = value.consumerSources();
                        }
                        break :blk .{ .file = try sessions.Session.createDeferred(self.allocator, &self.store, options, plan.specs) };
                    },
                    .journal => |plan| blk: {
                        var options = plan.sessionOptions();
                        options.retry = jail.policy;
                        options.suppress_retry_enforcement = self.suppress_enforcement;
                        options.gate = &self.gate;
                        options.monotonic_clock = .{ .context = self, .read = monotonic };
                        options.clock = clock_mod.wallTimestamp;
                        options.clock_context = &self.clock;
                        if (jail.consumer) |value| {
                            options.staged_detection = value.stagedConsumer();
                            options.consumer_sources = value.consumerSources();
                        }
                        break :blk .{ .journal = try journal_sessions.Session.createDeferred(self.allocator, &self.store, options) };
                    },
                    .internal => |generation| .{ .internal = generation },
                };
                errdefer next.destroy();
                if (jail.source_snapshot) |snapshot| try next.importRecovery(snapshot);
                jail.session = next;
                jail.rekeyed = false;
                setJailPaused(jail, !jail.admin_enabled or jail.admin_paused);
                bindDecay(jail);
                if (jail.plan == .internal) try self.store.admitRetry(jail.name, next.generation(), jail.policy);
                if (jail.consumer != null) {
                    self.consumer_cursor_len = 0;
                    self.consumer_scan_revision = null;
                    self.rebuild_phase = .consumers;
                } else self.restore_jail += 1;
            },
            .consumers => {
                const jail = &self.jails[self.restore_jail];
                var keys: [1]durable.Store.ManifestKey = undefined;
                const page = try self.store.consumerManifestKeysPage(self.allocator, jail.name, if (self.consumer_cursor_len == 0) null else self.consumer_cursor[0..self.consumer_cursor_len], self.consumer_scan_revision, &keys);
                defer for (keys[0..page.count]) |key| key.deinit(self.allocator);
                self.consumer_scan_revision = page.revision;
                for (keys[0..page.count]) |key| {
                    if (key.status != .ready) return error.MissingRequiredConsumer;
                    const expected = jail.session.?.generation();
                    if (!std.mem.eql(u8, &key.generation, &expected)) return error.ConsumerGenerationMismatch;
                    try jail.consumer.?.admitSource(key.source, expected);
                    @memcpy(self.consumer_cursor[0..key.source.len], key.source);
                    self.consumer_cursor_len = key.source.len;
                }
                if (!page.more) {
                    self.restore_jail += 1;
                    self.rebuild_phase = .owners;
                }
            },
            .history => {
                try self.restoreHistory();
                self.validation_phase = .begin;
                self.validation_jail = 0;
                self.rebuild_phase = .validation;
            },
            .validation => {
                try recoverSources(ctx);
                if (self.validation_phase == .done) {
                    self.validation_phase = .sources;
                    self.validation_jail = 0;
                    self.rebuild_phase = if (self.store.startup_admission) .done else .retry_projection;
                }
            },
            .retry_projection => {
                if (!self.store.retry_projection_initialized) try self.prepareRetryProjection();
                if (try self.store.retryAdmissionStep(256) == .progressed) {
                    self.effect_backlog = true;
                    return;
                }
                self.rebuild_phase = .done;
            },
            .done => {},
        }
    }
    fn prepareRetryProjection(self: *Coordinator) !void {
        var names: [max_jails][]const u8 = undefined;
        for (self.jails, 0..) |jail, i| names[i] = jail.name;
        try self.store.prepareRetryAdmissionView(names[0..self.jails.len], self.clock.wallUs());
    }
    fn clearRetryPublication(self: *Coordinator) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.published_pool = .{};
        self.owner_publication_pending = true;
        self.published_owners_mark = null;
        self.owner_read_epoch = null;
        self.owner_rebuild = null;
        self.metrics_state.setPoolSample(false, true, null);
        for (self.jails) |*jail| jail.retry_revision = null;
    }
    fn processingClock(ctx: ?*anyopaque) i64 {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        return self.clock.wallUs();
    }
    fn restoreHistory(self: *Coordinator) !void {
        const installation = try self.store.readInstallation() orelse return;
        const generation = effect.hashParts("fail2zig-native-confirmed-history-v1", &.{});
        self.history_consumer = try history.Consumer.init(installation, generation);
        errdefer self.history_consumer = null;
        const owner = &self.history_consumer.?;
        const manifest = owner.manifest();
        var saved: ?durable.Store.ManifestSnapshot = self.store.consumerManifestSnapshot(self.allocator, manifest) catch |failure| blk: {
            if (failure != error.ConsumerManifestMissing) return failure;
            break :blk null;
        };
        defer if (saved) |*snapshot| snapshot.deinit(self.allocator);
        if (saved) |*snapshot| {
            if (snapshot.status != .ready or snapshot.count != 1) return error.MissingRequiredConsumer;
            const row = snapshot.states[0];
            if (row.format_version != history.version or row.valid_until_us != null) return error.InvalidHistoryCheckpoint;
            const stage = try owner.prepareRestore(row.revision, row.payload orelse return error.MissingRequiredConsumer);
            defer stage.release();
            var events: [1]history.Event = undefined;
            _ = try self.store.confirmedEffectPage(installation, owner.staged.last_sequence, null, &events);
            try self.store.validateConsumerManifestSnapshot(manifest, snapshot);
            stage.publish();
        } else {
            const stage = try owner.prepareInitial();
            defer stage.release();
            try self.store.bootstrapConfirmedHistory(manifest, try stage.batch(.{ .prepared_us = self.clock.wallUs(), .context = self, .read = processingClock }), installation);
            stage.publish();
        }
    }
    fn recidiveJail(self: *Coordinator) ?*Jail {
        for (self.jails) |*jail| if (!jail.retiring and jail.plan == .internal) return jail;
        return null;
    }
    fn consumeHistory(self: *Coordinator) !bool {
        const diag_span = if (comptime build_options.diag) diag_mod.enter(.history) else {};
        defer if (comptime build_options.diag) diag_mod.leave(diag_span);
        const owner = if (self.history_consumer) |*value| value else return true;
        var prepared: [durable.Store.max_history_commit_pages]history.Consumer = undefined;
        var commits: [durable.Store.max_history_commit_pages]durable.Store.HistoryCommit = undefined;
        var events: [history.max_page]history.Event = undefined;
        var count: usize = 0;
        while (count < self.history_commit_pages) {
            prepared[count] = if (count == 0) owner.* else prepared[count - 1];
            const next = &prepared[count];
            const page = try self.store.confirmedEffectPage(owner.installation, next.live.last_sequence, null, &events);
            if (page.count == 0) {
                if (count != 0) break;
                try self.store.validateConfirmedEffectPage(page.token);
                self.history_page = page.token;
                return true;
            }
            const now = self.clock.wallUs();
            const stage = try next.prepare(page, events[0..page.count], now);
            defer stage.release();
            if (self.recidiveJail()) |jail| {
                for (events[0..page.count]) |event| {
                    _ = try recurrence.consume(&self.store, .{ .jail = jail.name, .generation = jail.session.?.generation(), .policy = jail.policy, .suppress_enforcement = self.suppress_enforcement, .decay = jail.decay }, event, now, .{ .prepared_us = now, .context = self, .read = processingClock });
                }
            }
            commits[count] = .{ .batch = try stage.batch(.{ .prepared_us = now, .context = self, .read = processingClock }), .token = page.token };
            // Only the local copy advances; the published owner waits for the whole group's COMMIT.
            stage.publish();
            count += 1;
            if (!page.more) break;
        }
        if (!try self.store.commitConfirmedHistoryGroup(owner.manifest(), commits[0..count])) {
            self.history_commit_pages = @intCast(@max(@as(usize, 1), count / 2));
            self.history_page = null;
            return false;
        }
        owner.live = prepared[count - 1].live;
        owner.revision = prepared[count - 1].revision;
        owner.ready = true;
        self.maintenance_idle = null;
        if (self.readiness_progress_started_ns != null and !self.notified_ready) {
            const head = self.readiness_history_head orelse commits[0].token.head_sequence;
            self.readiness_history_head = head;
            for (commits[0..count]) |page| if (page.token.last_sequence <= head) {
                self.readiness_history_pages +|= 1;
            };
        }
        self.history_page = null;
        return false;
    }
    fn recoverOwnership(ctx: ?*anyopaque) !void {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        self.mutex.lock();
        self.owner_read_epoch = null;
        self.owner_publication_pending = true;
        self.owner_rebuild = null;
        for (self.jails) |*jail| jail.retry_revision = null;
        self.mutex.unlock();
        for (self.jails) |*jail| {
            try self.publishJail(jail);
        }
    }
    fn recoverSources(ctx: ?*anyopaque) !void {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        switch (self.validation_phase) {
            .sources => {
                if (self.verify_jail == self.jails.len) {
                    self.maintenance_validation = .{};
                    self.maintenance_validated = false;
                    self.validation_phase = .begin;
                    return;
                }
                const jail = &self.jails[self.verify_jail];
                const verified = jail.session.?.verify() catch |failure| {
                    if (try self.startupSourceRefusal(jail, failure)) return;
                    try self.publishSource(jail);
                    if (jail.source_error == null and jail.session.? == .journal)
                        logJournalFailure(jail, failure, journalFailureDetail(jail, failure));
                    return failure;
                };
                if (!verified) return;
                if (jail.session.? == .journal) {
                    try self.publishSource(jail);
                } else {
                    self.mutex.lock();
                    jail.source_error = null;
                    self.mutex.unlock();
                }
                self.verify_jail += 1;
            },
            .begin => {
                if (self.dns) |resolver| {
                    try resolver.beginValidation();
                    for (self.jails) |jail| if (jail.consumer) |owner| try owner.beginValidation();
                    self.validation_phase = .resolver;
                } else self.validation_phase = .final;
            },
            .resolver => {
                if (try self.dns.?.validateTurn()) self.validation_phase = .owners;
            },
            .owners => {
                if (self.validation_jail == self.jails.len) {
                    self.validation_phase = .final;
                    return;
                }
                if (self.jails[self.validation_jail].consumer) |owner| if (!try owner.validateTurn()) return;
                self.validation_jail += 1;
            },
            .final => {
                if (!self.maintenance_validated) {
                    if (!try self.validateMaintenancePages()) return;
                    self.maintenance_validated = true;
                }
                var names: [max_jails][]const u8 = undefined;
                for (self.jails, 0..) |jail, i| names[i] = jail.name;
                var manifests: usize = @intFromBool(self.history_consumer != null);
                var consumer_revision: u64 = undefined;
                if (self.dns) |resolver| {
                    var owners: [max_jails]*consumer_runtime.JailRuntime = undefined;
                    var count: usize = 0;
                    for (self.jails, 0..) |jail, i| {
                        names[i] = jail.name;
                        if (jail.consumer) |owner| {
                            owners[count] = owner;
                            count += 1;
                        }
                    }
                    try resolver.finishValidation(owners[0..count]);
                    manifests += resolver.count + resolver.validation.count + @intFromBool(resolver.authority_ready);
                    consumer_revision = resolver.validation.revision.?;
                } else {
                    var keys: [1]durable.Store.ManifestKey = undefined;
                    const page = try self.store.consumerManifestKeysPage(self.allocator, "@shared", null, null, &keys);
                    defer for (keys[0..page.count]) |key| key.deinit(self.allocator);
                    if (page.count != 0) return error.UnboundRequiredConsumer;
                    consumer_revision = page.revision;
                }
                if (self.history_consumer) |*owner| {
                    var snapshot = try self.store.consumerManifestSnapshot(self.allocator, owner.manifest());
                    defer snapshot.deinit(self.allocator);
                    const expected = try owner.live.encode();
                    if (snapshot.revision != consumer_revision or snapshot.count != 1 or snapshot.states[0].revision != owner.revision or !std.mem.eql(u8, snapshot.states[0].payload orelse return error.MissingRequiredConsumer, &expected)) return error.StaleConsumerCheckpoint;
                    try self.store.validateConsumerManifestSnapshot(owner.manifest(), &snapshot);
                    if (self.history_page) |page| try self.store.validateConfirmedEffectPage(page);
                }
                try self.store.validateConsumerOwnership(names[0..self.jails.len], manifests, consumer_revision, self.history_consumer != null);
                try self.store.finishMaintenanceValidation(&self.maintenance_validation);
                self.validation_phase = .done;
            },
            .done => {},
        }
    }
    pub fn publishPool(self: *Coordinator, now_ms: u64) !void {
        if (!self.published_pool.pending) if (self.last_pool_ms) |last| if (now_ms -| last < quiet_interval_ms) return;
        self.last_pool_ms = now_ms;
        const sample = try self.store.retryPoolOccupancy(self.clock.wallUs());
        if (sample) |value| self.metrics_state.setPoolOccupancy(value.occupancy.tracked, value.occupancy.banned);
        for (self.jails) |jail| {
            self.metrics_state.jailSetPoolEvictions(jail.name, self.store.evictionCount(jail.name));
            const processor = sessionProcessor(&jail);
            self.metrics_state.jailSetFailuresCounted(jail.name, jail.failures_carried +| if (processor) |value| value.failures_counted else 0);
            self.metrics_state.jailSetIgnoredDetections(jail.name, jail.ignored_carried +| if (processor) |value| value.ignored_detections else 0);
            self.metrics_state.jailSetBansTotal(jail.name, jail.summary.decisions +| jail.manual_bans +| jail.config_bans);
        }
        const footprint = try self.store.stateFileFootprint();
        const confirmations = try self.confirmedEvents();
        self.metrics_state.setStateFile(footprint.bytes, footprint.pages);
        self.mutex.lock();
        if (sample) |value| self.published_pool.sample = value;
        self.published_pool.pending = sample == null;
        if (comptime build_options.diag) diag_mod.gauge(.retry_projection_pending_state, @intFromBool(sample == null));
        self.metrics_state.setPoolSample(self.published_pool.sample != null, self.published_pool.pending, if (self.published_pool.sample) |value| value.as_of_us else null);
        self.published_footprint = footprint;
        self.published_confirmations = confirmations;
        self.mutex.unlock();
    }

    pub fn publishJail(self: *Coordinator, jail: *Jail) !void {
        const diag_span = if (comptime build_options.diag) diag_mod.enter(.publish) else {};
        defer if (comptime build_options.diag) diag_mod.leave(diag_span);
        const now = self.clock.wallUs();
        const summary = self.store.retryJailSummary(jail.name) catch |failure| {
            if (failure == error.RetryEligibilityPending) {
                self.retryPublicationPending(jail);
                return;
            }
            return failure;
        };
        const revision = try self.store.revision(jail.name);
        const expired = if (jail.next_expiry_us) |deadline| now >= deadline else false;
        const enforces = self.jailEnforces(jail);
        const healthy = jail.session.?.healthy();
        if (jail.published_once and !expired and jail.retry_revision == summary.revision) {
            self.mutex.lock();
            jail.revision = revision;
            jail.healthy = healthy;
            self.mutex.unlock();
            return;
        }
        var count: usize = 0;
        if (!enforces) {
            if (self.decision_scratch.len == 0) self.decision_scratch = try self.allocator.alloc(durable.Store.ActiveDecision, retry.max_pool_subjects);
            if (jail.retry_revision == summary.revision) {
                for (jail.active) |decision| if (decision.lease.live(now)) {
                    self.decision_scratch[count] = decision;
                    count += 1;
                };
            } else count = self.store.retryLiveDecisions(jail.name, now, self.decision_scratch) catch |failure| {
                if (failure == error.RetryEligibilityPending) {
                    self.retryPublicationPending(jail);
                    return;
                }
                return failure;
            };
        }
        const active = try self.allocator.dupe(durable.Store.ActiveDecision, self.decision_scratch[0..count]);
        var next_expiry: ?i64 = null;
        var prior: usize = 0;
        for (active) |decision| {
            if (decision.lease == .finite) next_expiry = if (next_expiry) |deadline| @min(deadline, decision.lease.finite) else decision.lease.finite;
            while (prior < jail.active.len and subjectOrder(jail.active[prior].subject, decision.subject) == .lt) prior += 1;
            const already_published = prior < jail.active.len and std.meta.eql(jail.active[prior].subject, decision.subject) and jail.active[prior].ordinal == decision.ordinal;
            if (jail.published_once and !already_published) {
                const address: shared.IpAddress = switch (decision.subject) {
                    .v4 => |v| .{ .ipv4 = std.mem.readInt(u32, &v, .big) },
                    .v6 => |v| .{ .ipv6 = std.mem.readInt(u128, &v, .big) },
                };
                std.log.info("would-ban: jail='{s}' ip={}", .{ jail.name, address });
            }
        }
        self.mutex.lock();
        defer self.mutex.unlock();
        self.allocator.free(jail.active);
        jail.active = active;
        jail.summary = .{ .decisions = summary.decisions };
        jail.retry_revision = summary.revision;
        jail.published_once = true;
        jail.next_expiry_us = next_expiry;
        jail.revision = revision;
        jail.healthy = healthy;
    }
    fn retryPublicationPending(self: *Coordinator, jail: ?*Jail) void {
        self.effect_backlog = true;
        self.mutex.lock();
        defer self.mutex.unlock();
        if (jail) |value| value.retry_revision = null;
        self.published_pool.pending = true;
        if (comptime build_options.diag) diag_mod.gauge(.retry_projection_pending_state, 1);
        self.metrics_state.setPoolSample(self.published_pool.sample != null, true, if (self.published_pool.sample) |value| value.as_of_us else null);
    }
    fn subjectOrder(a: detection.Subject, b: detection.Subject) std.math.Order {
        const tag = std.math.order(@intFromEnum(std.meta.activeTag(a)), @intFromEnum(std.meta.activeTag(b)));
        if (tag != .eq) return tag;
        return switch (a) {
            .v4 => |left| std.mem.order(u8, &left, &b.v4),
            .v6 => |left| std.mem.order(u8, &left, &b.v6),
        };
    }
    fn effectMark(self: *const Coordinator, enforces: bool) EffectMark {
        const epoch = self.store.effect_publication_epoch;
        const manager = self.effects orelse return .{ .view_revision = 0, .epoch = epoch, .trusted = false, .enforces = enforces };
        const trusted = !manager.status.uncertain or (manager.status.cause != null and effect_runtime.transientCause(manager.status.cause.?));
        return .{ .view_revision = manager.view_revision, .epoch = epoch, .trusted = trusted, .enforces = enforces };
    }
    fn confirmedEvents(self: *Coordinator) !u64 {
        if (self.effects == null) return 0;
        const epoch = self.store.effect_publication_epoch;
        if (self.confirmations_epoch == epoch) return self.confirmations_count;
        self.confirmations_count = try self.store.confirmedEffectEvents();
        self.confirmations_epoch = epoch;
        return self.confirmations_count;
    }
    fn ownerConfirmed(self: *const Coordinator, owner: durable.Store.OperatorOwner, now: i64) bool {
        const manager = self.effects orelse return false;
        if (manager.cached_epoch == null or manager.cached_epoch.? != self.store.effect_publication_epoch) return false;
        return owner.lease.live(now) and manager.confirmedKey(owner.key, now);
    }
    fn ownerLess(_: void, left: durable.Store.OperatorOwner, right: durable.Store.OperatorOwner) bool {
        const jail = std.mem.order(u8, left.jail.slice(), right.jail.slice());
        return if (jail == .eq) std.mem.order(u8, &left.key, &right.key) == .lt else jail == .lt;
    }
    fn ownerKeyLess(_: void, left: [32]u8, right: [32]u8) bool {
        return std.mem.order(u8, &left, &right) == .lt;
    }
    fn changedOwner(keys: []const [32]u8, key: [32]u8) bool {
        var first: usize = 0;
        var end = keys.len;
        while (first < end) {
            const middle = first + (end - first) / 2;
            switch (std.mem.order(u8, &keys[middle], &key)) {
                .lt => first = middle + 1,
                .gt => end = middle,
                .eq => return true,
            }
        }
        return false;
    }
    fn changedOwnerKeys(self: *Coordinator, epoch: u64, keys: [][32]u8) ?usize {
        const previous = self.owner_read_epoch orelse return null;
        if (epoch == std.math.maxInt(u64) or epoch <= previous or epoch - previous > durable.Store.attribution_ring) return null;
        var count: usize = 0;
        var next = previous + 1;
        while (next <= epoch) : (next += 1) {
            const change = self.store.attributedChange(next) orelse return null;
            if (change.count > keys.len - count) return null;
            @memcpy(keys[count..][0..change.count], change.slice());
            count += change.count;
        }
        std.sort.pdq([32]u8, keys[0..count], {}, ownerKeyLess);
        var unique: usize = 0;
        for (keys[0..count]) |key| {
            if (unique != 0 and std.mem.eql(u8, &keys[unique - 1], &key)) continue;
            keys[unique] = key;
            unique += 1;
        }
        return unique;
    }
    fn replaceChangedOwners(self: *Coordinator, keys: []const [32]u8, now: i64) !usize {
        var replacements: usize = 0;
        for (keys) |key| {
            const available = @min(effect.max_page, self.owner_scratch.len - replacements);
            replacements += try self.store.operatorOwnersForScope(key, now, self.owner_scratch[replacements..][0..available]);
        }
        std.sort.pdq(durable.Store.OperatorOwner, self.owner_scratch[0..replacements], {}, ownerLess);
        var retained: usize = 0;
        for (self.owner_active[0..self.owner_count]) |owner| if (owner.lease.live(now) and !changedOwner(keys, owner.key)) {
            retained += 1;
        };
        if (retained > self.owner_scratch.len - replacements) return error.EffectCapacity;
        const count = retained + replacements;
        var old = self.owner_count;
        var incoming = replacements;
        var write = count;
        while (write != 0) {
            while (old != 0 and (!self.owner_active[old - 1].lease.live(now) or changedOwner(keys, self.owner_active[old - 1].key))) old -= 1;
            write -= 1;
            if (incoming != 0 and (old == 0 or ownerLess({}, self.owner_active[old - 1], self.owner_scratch[incoming - 1]))) {
                incoming -= 1;
                self.owner_scratch[write] = self.owner_scratch[incoming];
            } else {
                old -= 1;
                self.owner_scratch[write] = self.owner_active[old];
            }
        }
        return count;
    }
    fn publishOwnerRanges(self: *Coordinator, count: usize) void {
        var slots: [max_jails]usize = undefined;
        for (self.jails, 0..) |*jail, i| {
            jail.owner_range = .{};
            slots[i] = i;
        }
        const Order = struct {
            fn less(jails: []const Jail, left: usize, right: usize) bool {
                return std.mem.order(u8, jails[left].name, jails[right].name) == .lt;
            }
        };
        std.sort.pdq(usize, slots[0..self.jails.len], @as([]const Jail, self.jails), Order.less);
        var cursor: usize = 0;
        for (slots[0..self.jails.len]) |slot| {
            const jail = &self.jails[slot];
            while (cursor < count and std.mem.order(u8, self.owner_scratch[cursor].jail.slice(), jail.name) == .lt) cursor += 1;
            const first = cursor;
            while (cursor < count and std.mem.eql(u8, self.owner_scratch[cursor].jail.slice(), jail.name)) cursor += 1;
            jail.owner_range = .{ .start = first, .len = cursor - first };
        }
    }
    pub fn publishOwners(self: *Coordinator) !void {
        const diag_span = if (comptime build_options.diag) diag_mod.enter(.owners) else {};
        defer if (comptime build_options.diag) diag_mod.leave(diag_span);
        const manager = self.effects orelse return;
        if (manager.withdrawn) {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.owner_rebuild = null;
            self.owner_publication_pending = false;
            @memset(self.owner_confirmed[0..self.owner_count], false);
            self.published_owners_mark = null;
            return;
        }
        const expected_epoch = manager.cached_epoch orelse return error.StaleEffect;
        const fatal = manager.status.uncertain and !(manager.status.cause != null and effect_runtime.transientCause(manager.status.cause.?));
        if (fatal or expected_epoch != self.store.effect_publication_epoch) return error.StaleEffect;
        const mark = self.effectMark(true);
        const reread = self.owner_read_epoch != expected_epoch;
        if (self.owner_rebuild == null and !reread and std.meta.eql(self.published_owners_mark, mark)) return;
        const now = self.clock.wallUs();
        var count: usize = 0;
        if (self.owner_rebuild) |state| {
            if (state.epoch != expected_epoch) self.owner_rebuild = null;
        }
        if (self.owner_rebuild == null and reread) {
            var keys: [durable.Store.attribution_ring * durable.Store.attribution_batch][32]u8 = undefined;
            if (self.changedOwnerKeys(expected_epoch, &keys)) |changed| {
                count = try self.replaceChangedOwners(keys[0..changed], now);
            } else {
                self.owner_rebuild = .{ .epoch = expected_epoch };
                self.mutex.lock();
                self.owner_publication_pending = true;
                self.mutex.unlock();
            }
        } else if (self.owner_rebuild == null) for (self.owner_active[0..self.owner_count]) |owner| if (owner.lease.live(now)) {
            self.owner_scratch[count] = owner;
            count += 1;
        };
        if (self.owner_rebuild) |*state| {
            const remaining = self.owner_scratch.len - state.count;
            if (remaining == 0) {
                var probe: [1]durable.Store.OperatorOwner = undefined;
                if (try self.store.operatorOwnerPage(now, &probe, state.after) != 0) return error.EffectCapacity;
            } else {
                const want = @min(durable.Store.owner_page_rows, remaining);
                const got = try self.store.operatorOwnerPage(now, self.owner_scratch[state.count..][0..want], state.after);
                state.count += got;
                if (got == want) {
                    state.after = self.owner_scratch[state.count - 1];
                    self.effect_backlog = true;
                    return;
                }
            }
            for (self.owner_scratch[0..state.count]) |owner| if (owner.lease.live(now)) {
                self.owner_scratch[count] = owner;
                count += 1;
            };
            self.owner_rebuild = null;
        }
        for (self.owner_scratch[0..count], 0..) |owner, i| self.owner_scratch_confirmed[i] = self.ownerConfirmed(owner, now);
        if (expected_epoch != self.store.effect_publication_epoch or manager.cached_epoch == null or manager.cached_epoch.? != expected_epoch) return error.StaleEffect;
        self.mutex.lock();
        defer self.mutex.unlock();
        self.publishOwnerRanges(count);
        @memcpy(self.owner_active[0..count], self.owner_scratch[0..count]);
        @memcpy(self.owner_confirmed[0..count], self.owner_scratch_confirmed[0..count]);
        self.owner_count = count;
        self.owner_read_epoch = expected_epoch;
        self.published_owners_mark = mark;
        self.owner_publication_pending = false;
    }
    fn publishSource(self: *Coordinator, jail: *Jail) !void {
        const source = jail.session.?;
        const cause: ?anyerror = switch (source) {
            .file => |value| value.repairSnapshot().last_cause orelse value.blocked_cause,
            .journal => |value| value.repairSnapshot().last_cause orelse value.blockedCause(),
            .internal => null,
        };
        const healthy = source.healthy();
        const missing = source == .file and source.file.awaitingPath();
        const diagnostic = switch (source) {
            .journal => |value| if (value.failureDiagnostic()) |detail|
                (if (cause != null and detail.cause == cause.?) detail else null)
            else
                null,
            else => null,
        };
        self.mutex.lock();
        const previous_cause = jail.source_error;
        const previous_diagnostic = jail.source_diagnostic;
        const changed = jail.healthy != healthy or previous_cause != cause or !std.meta.eql(previous_diagnostic, diagnostic);
        jail.healthy = healthy;
        jail.source_missing = missing;
        jail.source_error = cause;
        jail.source_diagnostic = diagnostic;
        self.mutex.unlock();
        if (source == .file) for (0..2 * source.file.sources.max_sources) |_| {
            const report = source.file.nextUnreportedContinuityFailure() orelse break;
            if (comptime build_options.diag) diag_mod.event(.source_paused, .{ .subject = jail.name, .cause = @tagName(report.failure.kind) });
            std.log.err("file source for jail '{'}' path '{'}' cannot resume its checkpoint: {}; unknown extent of unread data lost; source paused pending repair", .{ std.zig.fmtEscapes(jail.name), std.zig.fmtEscapes(report.path), report.failure });
        };
        if (source == .journal and changed) {
            if (cause) |failure| {
                if (!pipeline.Pipeline.commitBlocked(failure)) logJournalFailure(jail, failure, diagnostic);
            } else if (healthy and jail.last_journal_notice != null) {
                jail.last_journal_notice = null;
                std.log.info("journal source for jail '{'}' recovered", .{std.zig.fmtEscapes(jail.name)});
            }
        }
        try self.refreshSourceStatus(jail);
    }
    fn publishBlocked(self: *Coordinator, jail: *Jail, cause: anyerror) !void {
        if (jail.healthy or jail.source_error == null or jail.source_error.? != cause) try self.publishSource(jail);
    }
    fn startupSourceRefusal(self: *Coordinator, jail: *Jail, failure: anyerror) !bool {
        if (failure != error.SourceInterventionRequired) return false;
        const source = jail.session.?;
        if (source == .file) for (0..2 * source.file.sources.max_sources) |_| {
            _ = source.file.nextUnreportedContinuityFailure() orelse break;
        };
        try self.publishSource(jail);
        try self.logPausedAtStartup(jail);
        self.verify_jail += 1;
        return true;
    }
    const OptionalNumber = struct {
        value: ?u64,
        pub fn format(self: OptionalNumber, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
            if (self.value) |number| try writer.print("{d}", .{number}) else try writer.writeAll("unknown");
        }
    };
    const ControlEscaped = struct {
        text: []const u8,
        pub fn format(self: ControlEscaped, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
            for (self.text) |byte| {
                if (byte < 0x20 or byte == 0x7f) try writer.print("\\x{x:0>2}", .{byte}) else try writer.writeByte(byte);
            }
        }
    };
    fn logPausedAtStartup(self: *Coordinator, jail: *Jail) !void {
        const tail_unrepairable = "; other jails enforce; no offline repair applies to this cause; see fail2zig status";
        var logged = false;
        if (jail.session.? == .file) {
            const session = jail.session.?.file;
            for (session.repair_states[0..@min(session.repair_count, session.sources.sources.items.len)], 0..) |*state, index| {
                const facts = session.pausedSource(index) orelse continue;
                logged = true;
                const cause = @errorName(state.snapshot().last_cause orelse error.SourceInterventionRequired);
                var detail_buffer: [192]u8 = undefined;
                const detail = switch (facts.cause) {
                    .resume_lost => try std.fmt.bufPrint(&detail_buffer, " (inode={d} committed_offset={d} size={})", .{ facts.inode, facts.committed_offset, OptionalNumber{ .value = facts.observed_size } }),
                    .rotated_incarnation_lost => try std.fmt.bufPrint(&detail_buffer, " (removed inode={d} committed_offset={d} last_size={}; current inode={})", .{ facts.inode, facts.committed_offset, OptionalNumber{ .value = facts.observed_size }, OptionalNumber{ .value = facts.current_inode } }),
                    .other => "",
                };
                const repair_line = if (facts.repair_token) |token| try repairCommand(self.allocator, jail.name, facts.path, token[0..facts.repair_token_len]) else null;
                defer if (repair_line) |text| self.allocator.free(text);
                if (repair_line != null and facts.path_absent)
                    std.log.warn("native: jail={} source=file path={} paused at startup: {s}{s}; the file is absent; other jails enforce; once a file exists at the path, stop fail2zig and run: {}", .{ std.zig.fmtEscapes(jail.name), std.zig.fmtEscapes(facts.path), cause, detail, ControlEscaped{ .text = repair_line.? } })
                else if (repair_line) |text|
                    std.log.warn("native: jail={} source=file path={} paused at startup: {s}{s}; other jails enforce; to repair, stop fail2zig and run: {}", .{ std.zig.fmtEscapes(jail.name), std.zig.fmtEscapes(facts.path), cause, detail, ControlEscaped{ .text = text } })
                else
                    std.log.warn("native: jail={} source=file path={} paused at startup: {s}{s}" ++ tail_unrepairable, .{ std.zig.fmtEscapes(jail.name), std.zig.fmtEscapes(facts.path), cause, detail });
            }
        }
        if (logged) return;
        const snapshot = switch (jail.session.?) {
            .file => |session| session.repairSnapshot(),
            .journal => |session| session.repairSnapshot(),
            .internal => return,
        };
        std.log.warn("native: jail={} source={s} paused at startup: {s}" ++ tail_unrepairable, .{ std.zig.fmtEscapes(jail.name), @tagName(jail.plan), @errorName(snapshot.last_cause orelse error.SourceInterventionRequired) });
    }
    fn sourceSignature(source: Source) SourceSignature {
        var signature = SourceSignature{ .built = true };
        switch (source) {
            .file => |session| {
                signature.sources = session.sources.sources.items.len;
                signature.configured = session.sources.configuredCount();
                signature.presence_revision = session.sources.presence_revision;
                for (0..signature.configured) |i| {
                    const presence = session.sources.configuredStatus(i).?.presence;
                    if (presence == .unknown or presence == .failed) signature.presence_known = false;
                }
                for (session.repair_states[0..@min(session.repair_count, max_sources_per_jail)], 0..) |*state, index| {
                    const snapshot = state.snapshot();
                    if (snapshot.phase == .intervention) signature.causes[index] = snapshot.last_cause orelse error.SourceInterventionRequired;
                }
                const discovery = session.discovery_repair.snapshot();
                if (discovery.phase == .intervention) signature.causes[max_sources_per_jail] = discovery.last_cause orelse error.SourceInterventionRequired;
                if (session.recorded_loss) |loss| signature.loss_sequence = loss.sequence;
            },
            .journal => |session| {
                const snapshot = session.repairSnapshot();
                if (snapshot.phase == .intervention) signature.causes[max_sources_per_jail] = snapshot.last_cause orelse error.SourceInterventionRequired;
            },
            .internal => {},
        }
        return signature;
    }
    fn sameSignature(a: SourceSignature, b: SourceSignature) bool {
        return a.built == b.built and a.sources == b.sources and a.configured == b.configured and a.presence_revision == b.presence_revision and a.presence_known == b.presence_known and a.loss_sequence == b.loss_sequence and std.mem.eql(?anyerror, &a.causes, &b.causes);
    }
    fn refreshSourceStatus(self: *Coordinator, jail: *Jail) !void {
        const source = jail.session orelse return;
        const signature = sourceSignature(source);
        if (sameSignature(jail.source_signature, signature)) return self.refreshReadingOffsets(jail);
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        errdefer arena.deinit();
        const entries = try self.buildSourceStatus(jail, arena.allocator());
        self.mutex.lock();
        const previous = jail.source_status_arena;
        jail.source_status = entries;
        jail.source_status_arena = arena;
        jail.source_signature = signature;
        self.mutex.unlock();
        if (previous) |old| {
            var released = old;
            released.deinit();
        }
    }
    fn refreshReadingOffsets(self: *Coordinator, jail: *Jail) void {
        if (jail.source_status.len == 0) return;
        const session = switch (jail.session orelse return) {
            .file => |value| value,
            else => return,
        };
        self.mutex.lock();
        defer self.mutex.unlock();
        for (jail.source_status) |*entry| {
            if (entry.state != .reading) continue;
            const path = entry.path orelse continue;
            for (session.sources.sources.items) |source| {
                if (!std.mem.eql(u8, source.path, path)) continue;
                const saved = source.committed orelse break;
                entry.inode = saved.inode;
                entry.committed_offset = saved.offset;
                entry.observed_size = saved.observed_size;
                break;
            }
        }
    }
    fn buildSourceStatus(self: *Coordinator, jail: *Jail, arena: std.mem.Allocator) ![]SourceStatus {
        var list = std.ArrayListUnmanaged(SourceStatus){};
        switch (jail.session.?) {
            .file => |session| {
                var paused_seen = false;
                const count = @min(session.repair_count, session.sources.sources.items.len);
                for (session.sources.sources.items[0..count], session.repair_states[0..count], 0..) |source, *state, index| {
                    const facts = session.pausedSource(index);
                    var newest: files.LossEvent = undefined;
                    const events = try self.store.continuitySummary(jail.name, source.path, &newest);
                    if (facts == null and events == 0) continue;
                    const path = try arena.dupe(u8, source.path);
                    var entry = SourceStatus{ .jail = jail.name, .kind = .file, .path = path, .on_truncation = jail.on_truncation, .state = .reading, .cause = null, .inode = null, .committed_offset = null, .observed_size = null, .repair = null, .loss_events = events, .last_loss = null };
                    if (events != 0) {
                        newest.jail = jail.name;
                        newest.path = path;
                        newest.source_id = "";
                        entry.last_loss = newest;
                    }
                    if (facts) |paused| {
                        paused_seen = true;
                        entry.state = .paused;
                        entry.cause = @errorName(state.snapshot().last_cause orelse error.SourceInterventionRequired);
                        entry.inode = paused.inode;
                        entry.committed_offset = paused.committed_offset;
                        entry.observed_size = paused.observed_size;
                        if (paused.repair_token) |token| entry.repair = try repairCommand(arena, jail.name, source.path, token[0..paused.repair_token_len]);
                    } else if (source.committed) |saved| {
                        entry.inode = saved.inode;
                        entry.committed_offset = saved.offset;
                        entry.observed_size = saved.observed_size;
                    }
                    try list.append(arena, entry);
                }
                if (!paused_seen) {
                    const snapshot = session.repairSnapshot();
                    if (snapshot.phase == .intervention) try list.append(arena, pausedWithoutPath(jail, .file, snapshot.last_cause));
                }
                for (0..session.sources.configuredCount()) |i| {
                    const configured = session.sources.configuredStatus(i).?;
                    if (configured.presence != .missing) continue;
                    var paused = false;
                    for (list.items) |entry| if (entry.state == .paused and entry.path != null and std.mem.eql(u8, entry.path.?, configured.pattern)) {
                        paused = true;
                        break;
                    };
                    if (paused) continue;
                    try list.append(arena, .{ .jail = jail.name, .kind = .file, .path = try arena.dupe(u8, configured.pattern), .on_truncation = jail.on_truncation, .state = .missing, .cause = null, .inode = null, .committed_offset = null, .observed_size = null, .repair = null, .loss_events = 0, .last_loss = null });
                }
            },
            .journal => |session| {
                const snapshot = session.repairSnapshot();
                if (snapshot.phase == .intervention) try list.append(arena, pausedWithoutPath(jail, .journal, snapshot.last_cause));
            },
            .internal => {},
        }
        std.sort.pdq(SourceStatus, list.items, {}, sourceStatusLess);
        return list.toOwnedSlice(arena);
    }
    fn pausedWithoutPath(jail: *const Jail, kind: @FieldType(SourceStatus, "kind"), cause: ?anyerror) SourceStatus {
        return .{ .jail = jail.name, .kind = kind, .path = null, .on_truncation = if (kind == .file) jail.on_truncation else null, .state = .paused, .cause = @errorName(cause orelse error.SourceInterventionRequired), .inode = null, .committed_offset = null, .observed_size = null, .repair = null, .loss_events = 0, .last_loss = null };
    }
    fn sourceStatusLess(_: void, a: SourceStatus, b: SourceStatus) bool {
        return std.mem.lessThan(u8, a.path orelse "", b.path orelse "");
    }
    const shell_safe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:/@%+=,-";
    fn writeShellArgument(writer: anytype, argument: []const u8) !void {
        const bare = argument.len != 0 and for (argument) |byte| {
            if (std.mem.indexOfScalar(u8, shell_safe, byte) == null) break false;
        } else true;
        if (bare) return writer.writeAll(argument);
        try writer.writeByte('\'');
        for (argument) |byte| {
            if (byte == '\'') try writer.writeAll("'\\''") else try writer.writeByte(byte);
        }
        try writer.writeByte('\'');
    }
    fn repairCommand(allocator: std.mem.Allocator, jail: []const u8, path: []const u8, token: []const u8) ![]u8 {
        var text = std.ArrayList(u8).init(allocator);
        errdefer text.deinit();
        const writer = text.writer();
        try writer.writeAll("fail2zig repair-source --jail ");
        try writeShellArgument(writer, jail);
        try writer.writeAll(" --source ");
        try writeShellArgument(writer, path);
        try writer.writeAll(" --token ");
        try writeShellArgument(writer, token);
        try writer.writeAll(" --acknowledge-truncation");
        return text.toOwnedSlice();
    }
    pub fn jailPaused(jail: *const Jail) bool {
        for (jail.source_status) |entry| if (entry.state == .paused) return true;
        return false;
    }
    fn writePausedStatus(self: *Coordinator, writer: anytype) !bool {
        var paused: usize = 0;
        var first: ?SourceStatus = null;
        for (self.jails) |*jail| for (jail.source_status) |entry| if (entry.state == .paused) {
            if (first == null) first = entry;
            paused += 1;
        };
        const only = first orelse return false;
        if (paused == 1) {
            try writer.print("Enforcing; 1 source paused: {}", .{std.zig.fmtEscapes(only.jail)});
            if (only.path) |path| try writer.print(" {}", .{std.zig.fmtEscapes(path)});
            try writer.print(" ({s}); see fail2zig status", .{only.cause orelse "SourceInterventionRequired"});
            return true;
        }
        try writer.print("Enforcing; {d} sources paused (", .{paused});
        var listed: usize = 0;
        var previous: []const u8 = "";
        for (self.jails) |*jail| for (jail.source_status) |entry| if (entry.state == .paused) {
            if (listed != 0 and std.mem.eql(u8, previous, entry.jail)) continue;
            if (listed != 0) try writer.writeAll(", ");
            try writer.print("{}", .{std.zig.fmtEscapes(entry.jail)});
            previous = entry.jail;
            listed += 1;
        };
        try writer.writeAll("); see fail2zig status");
        return true;
    }
    fn journalFailureDetail(jail: *const Jail, failure: anyerror) ?journal_sessions.FailureDiagnostic {
        const source = jail.session orelse return null;
        return switch (source) {
            .journal => |value| if (value.failureDiagnostic()) |detail| (if (detail.cause == failure) detail else null) else null,
            else => null,
        };
    }
    fn logJournalFailure(jail: *Jail, failure: anyerror, diagnostic: ?journal_sessions.FailureDiagnostic) void {
        const notice = diagnostic orelse journal_sessions.FailureDiagnostic{ .cause = failure, .exit_code = null, .signal = null, .stderr_present = false };
        if (std.meta.eql(jail.last_journal_notice, @as(?journal_sessions.FailureDiagnostic, notice))) return;
        jail.last_journal_notice = notice;
        std.log.warn("journal source for jail '{'}' is unhealthy: {s}; journalctl exit={?d}, signal={?d}, stderr_present={}; inspect journal access and selection", .{
            std.zig.fmtEscapes(jail.name),                             @errorName(failure),
            if (diagnostic) |detail| detail.exit_code else null,       if (diagnostic) |detail| detail.signal else null,
            if (diagnostic) |detail| detail.stderr_present else false,
        });
    }
    fn publishHealth(self: *Coordinator) void {
        const snapshot = self.gate.snapshot();
        var next_expiry: ?i64 = null;
        var expiry_current = self.effects == null;
        if (self.effects) |manager| {
            expiry_current = !self.store.reopen_required and manager.cached_epoch != null and manager.cached_epoch.? == self.store.effect_publication_epoch;
            if (expiry_current) for (manager.live[0..manager.count]) |entry| {
                if (entry.status == .expired or entry.status == .absent or entry.status == .superseded) continue;
                if (entry.desired == .finite) next_expiry = if (next_expiry) |prior| @min(prior, entry.desired.finite) else entry.desired.finite;
            };
        }
        self.mutex.lock();
        var wall_floor = snapshot.receipt_clock_floor_us;
        if (self.effects) |manager| wall_floor = if (wall_floor) |floor| @max(floor, manager.last_wall_us) else manager.last_wall_us;
        if (self.store_open) {
            if (self.store.consumer_clock_floor_us) |floor| wall_floor = if (wall_floor) |prior| @max(prior, floor) else floor;
        }
        if (wall_floor) |floor| self.worker_observation.wall_floor_us = if (self.worker_observation.wall_floor_us) |prior| @max(prior, floor) else floor;
        self.worker_observation.publication(observationMs(), self.observationWall(), next_expiry, expiry_current);
        self.published_health = snapshot;
        if (self.effects) |manager| {
            self.published_effects = manager.status;
            if (manager.cached_epoch == null or manager.cached_epoch.? != self.store.effect_publication_epoch) self.published_effects.?.ready = false;
            self.published_backend = @tagName(manager.installation.backend);
            self.published_view = .{
                .readback_ns = manager.last_readback_ns,
                .readback_wall_us = manager.last_readback_wall_us,
                .installed_live = manager.installed_live,
                .pending = manager.counters.pending,
                .oldest_pending_us = manager.counters.oldest_pending_us,
                .overdue = manager.counters.overdue,
                .oldest_overdue_us = manager.counters.oldest_overdue_us,
                .overdue_blocking = manager.counters.overdue_blocking,
                .oldest_overdue_blocking_us = manager.counters.oldest_overdue_blocking_us,
                .dump_interrupted = manager.counters.dump_interrupted,
                .verify_interval_ns = manager.verify_interval_ns,
                .wake_interval_ns = manager.wake_interval_ns,
                .transient_uncertain = manager.status.uncertain and manager.status.cause != null and effect_runtime.transientCause(manager.status.cause.?),
                .events_subscribed = manager.events_subscribed,
                .events_healthy = manager.events_healthy,
            };
            self.published_stats = .{
                .available = true,
                .reason = null,
                .backend = @tagName(manager.installation.backend),
                .view_ready = self.published_effects.?.ready,
                .view_entries = manager.count,
                .last_observed_installed = manager.installed_live,
                .pending_live_dispatches = manager.counters.pending,
                .overdue_blocking_removals = manager.counters.overdue_blocking,
                .overdue_bookkeeping = manager.counters.overdue_bookkeeping,
                .accepted_readbacks = manager.counters.full_readbacks,
                .dump_interruptions = manager.counters.dump_interrupted,
                .acknowledged_batches = manager.counters.acknowledged_batches,
                .events_applied = manager.counters.events_applied,
                .events_dropped = manager.counters.events_dropped,
                .view_rebuilds = manager.counters.rebuilds_completed,
                .view_restarts = manager.counters.rebuild_restarts,
                .incremental_updates = manager.counters.incremental_updates,
                .expiry_batches = manager.counters.expiry_batches,
                .expiries_prepared = manager.counters.expiries_prepared,
                .retirement_batches = self.retire_batches,
                .retry_subjects_retired = self.retired_total,
                .retry_subjects_examined = self.retire_examined,
                .retirement_pinned_state = self.retire_pinned_state,
                .retirement_pinned_effect = self.retire_pinned_effect,
                .retirement_refused = self.retire_refused,
            };
            self.stats_published_ms = observationMs();
            self.stats_generation = self.published_generation;
        }
        self.mutex.unlock();
        if (self.effects) |manager| {
            const detail = manager.status.diagnostic;
            if (!std.meta.eql(self.last_effect_notice, detail)) {
                if (detail) |failure| {
                    std.log.warn("firewall {s}: {s} failed ({s}); mutation={s}; enforcement confirmation pending", .{
                        @tagName(failure.backend), @tagName(failure.stage), @errorName(failure.cause), @tagName(failure.mutation),
                    });
                } else if (manager.status.ready) {
                    std.log.info("firewall {s}: readback recovered", .{@tagName(manager.installation.backend)});
                }
                self.last_effect_notice = detail;
            }
        }
        if (snapshot.notice_sequence != self.last_notice) {
            self.last_notice = snapshot.notice_sequence;
            std.log.info("native ingestion: {s}; cause={s}; committed={d}", .{ @tagName(snapshot.phase), if (snapshot.last_failure) |failure| @errorName(failure.cause) else "none", snapshot.committed_records });
        }
        if (!self.notified_ready) {
            const report = self.readinessReport();
            if (report.ready) {
                self.notified_ready = true;
                if (comptime build_options.diag) diag_mod.startupReady();
                if (self.startup_progress) |progress| progress.finish();
                if (self.notifier) |notifier| {
                    var text_buffer: [4 * sd_notify.max_status_bytes]u8 = undefined;
                    var stream = std.io.fixedBufferStream(&text_buffer);
                    const paused = self.writePausedStatus(stream.writer()) catch |err| switch (err) {
                        error.NoSpaceLeft => true,
                    };
                    _ = (if (paused) notifier.readyWithStatus(stream.getWritten()) else notifier.ready()) catch |err| std.log.warn("sd_notify READY failed: {s}", .{@errorName(err)});
                }
                std.log.info("native: ready; all readiness components verified", .{});
            } else self.reportReadinessProgress(report);
        }
        self.notifyReloadReady();
    }
    pub fn start(self: *Coordinator) !void {
        self.thread = try std.Thread.spawn(.{ .stack_size = 16 * resource.mib }, work, .{self});
    }
    fn work(self: *Coordinator) void {
        if (comptime build_options.diag) diag_mod.attach();
        if (comptime build_options.diag) diag_mod.limit(.memory_plan, self.resources.limit_bytes, @as(u64, self.cfg.global.native_memory_ceiling_mb) * resource.mib);
        while (true) {
            if (comptime build_options.diag) diag_mod.count(.wakes, 1);
            self.stop_mutex.lock();
            if (self.stopping) {
                self.stop_mutex.unlock();
                self.leaveRealizedEffects();
                return;
            }
            self.stop_mutex.unlock();
            self.mutex.lock();
            self.worker_observation.begin(observationMs(), self.observationWall());
            if (self.reload_request) |request| {
                self.reload_request = null;
                self.mutex.unlock();
                self.applyReload(request);
                self.mutex.lock();
            }
            if (self.adminWorkLocked()) |work_item| {
                self.mutex.unlock();
                switch (work_item.phase) {
                    .executing => self.executeAdmin(work_item.request),
                    .awaiting => self.settleAdmin(work_item.request),
                    .staged, .done => {},
                }
                self.mutex.lock();
            }
            self.mutex.unlock();
            self.effect_backlog = false;
            self.tick() catch |failure| pending: {
                if (failure == error.NativeStartupStopped and stopRequested(self)) break :pending;
                if (failure == error.RetryEligibilityPending) {
                    self.retryPublicationPending(null);
                    break :pending;
                }
                if (!self.gate.snapshot().has_been_healthy and failure != error.ReceiptClockReversed) {
                    for (self.jails) |jail| if (jail.source_error) |cause| {
                        std.log.err("native: jail={s} source={s} continuity failure: {s}", .{ jail.name, @tagName(jail.plan), @errorName(cause) });
                    };
                    std.log.err("native: startup recovery failed: {s}; refusing to start", .{@errorName(failure)});
                    // Exit skips the main loop's periodic drain; a file log target would lose the refusal cause.
                    if (log_sink) |sink| sink.drain();
                    std.process.exit(1);
                }
                if (comptime build_options.diag) diag_mod.event(.storage_failed, .{ .cause = @errorName(failure) });
                if (!self.store_open or self.store.reopen_required) self.clearRetryPublication();
                if (self.gate.snapshot().phase == .healthy) self.gate.failed(failure, .{ .sqlite_code = if (self.store_open) self.store.last_error_code else null, .reopen_required = !self.store_open or self.store.reopen_required, .operation = if (self.store_open) self.store.maintenance_operation else null });
            };
            self.publishHealth();
            if (comptime build_options.diag) diag_mod.emitIfDue();
            self.mutex.lock();
            self.worker_observation.complete(observationMs(), self.observationWall());
            self.mutex.unlock();
            self.stop_mutex.lock();
            if (!self.stopping and !self.effect_backlog) self.wake.timedWait(&self.stop_mutex, if (comptime build_options.diag) self.clock.loopWaitNs(tick_wait_ns) else tick_wait_ns) catch {};
            const stopped = self.stopping;
            self.stop_mutex.unlock();
            if (stopped) {
                self.drainHistoryForStop();
                self.leaveRealizedEffects();
                return;
            }
        }
    }
    fn tick(self: *Coordinator) !void {
        if (comptime build_options.diag) if (self.effects) |manager| manager.setClockRate(self.clock.rate());
        if (self.gate.snapshot().phase != .healthy) {
            if (self.effects) |manager| manager.expireDuringOutage() catch |failure| {
                manager.status.cause = failure;
            };
            var recovery_driver = self.driver();
            _ = try recovery_driver.poll();
            return;
        }
        var view_idle = self.effects == null;
        if (self.effects) |manager| {
            view_idle = try self.effectSlice(manager);
            if (!view_idle and stopRequested(self)) return;
            self.reportViewProgress(manager);
        }
        if (self.store.retry_admission_target_hint != null) {
            if (try self.store.retryAdmissionStep(256) == .progressed) {
                self.retryPublicationPending(null);
                return;
            }
        }
        owner_page: {
            if (self.owner_rebuild != null) {
                self.publishOwners() catch |failure| {
                    if (failure != error.StaleEffect) return failure;
                    break :owner_page;
                };
                if (self.owner_rebuild != null) return;
            }
        }
        if (self.dns) |resolver| {
            const result = try resolver.pollDns();
            if (result.kind == .ready) {
                const owner = result.source orelse return error.UnboundRequiredConsumer;
                for (self.jails) |*jail| if (jail.consumer) |consumer| {
                    if (jail.retiring or !std.mem.eql(u8, consumer.settings.jail, owner.settings.jail)) continue;
                    jail.session.?.resumeConsumer(owner.incarnation) catch |failure| {
                        if (failure == error.SourceRepairPending or failure == error.SourceInterventionRequired) {
                            try self.publishSource(jail);
                            break;
                        }
                        if (pipeline.Pipeline.commitBlocked(failure)) {
                            try self.publishBlocked(jail, failure);
                            if (failure == error.RetryEligibilityPending) {
                                self.retryPublicationPending(null);
                                return;
                            }
                        } else if (failure != error.ConsumerPending and failure != error.ConsumerExpired and failure != error.EffectExpired) return failure;
                    };
                    try self.publishJail(jail);
                    break;
                };
            }
        }
        try self.withdrawRetiredJails();
        if (try self.retireRemovedJail()) return;
        try self.advanceDisabledJails();
        try self.applyBanLists();
        const now_ms = monotonic(self);
        try self.expireIgnoreEntries(now_ms);
        const committed = self.gate.snapshot().committed_records;
        const quiet = view_idle and !self.effect_backlog and self.history_caught_up and !self.maintenance_progress and committed == self.last_committed_records;
        const slow_due = self.published_pool.pending or !quiet or now_ms -| (self.last_slow_tick_ms orelse 0) >= quiet_interval_ms;
        self.last_committed_records = committed;
        if (slow_due) {
            self.last_slow_tick_ms = now_ms;
            if (self.effects) |manager| {
                if (view_idle or manager.last_readback_ns != null) {
                    const published = owners: {
                        self.publishOwners() catch |failure| {
                            if (failure != error.StaleEffect) return failure;
                            break :owners false;
                        };
                        break :owners true;
                    };
                    if (published and self.owner_rebuild != null) return;
                    for (self.jails) |*jail| if (!jail.retiring) try self.publishJail(jail);
                }
            } else for (self.jails) |*jail| if (!jail.retiring) try self.publishJail(jail);
            if (self.store.retry_admission_target_hint != null) {
                self.retryPublicationPending(null);
                return;
            }
            try self.publishPool(now_ms);
            if (self.store.retry_admission_target_hint != null) {
                self.retryPublicationPending(null);
                return;
            }
            if (now_ms -| (self.last_history_ms orelse 0) >= quiet_interval_ms) {
                self.last_history_ms = now_ms;
                self.history_caught_up = try self.consumeHistory();
            } else self.history_page = null;
        }
        for (self.jails) |*jail| {
            if (jail.retiring) continue;
            const admitted = jail.session.?.poll() catch |failure| {
                if (failure == error.SourceRepairPending or failure == error.SourceInterventionRequired) {
                    try self.publishSource(jail);
                    continue;
                }
                if (pipeline.Pipeline.commitBlocked(failure)) {
                    if (comptime build_options.diag) diag_mod.event(.commit_refused, .{ .subject = jail.name, .cause = @errorName(failure) });
                    try self.publishBlocked(jail, failure);
                    if (failure == error.RetryEligibilityPending) {
                        self.retryPublicationPending(null);
                        return;
                    }
                    continue;
                }
                if (failure == error.EffectExpired or failure == error.ConsumerExpired or failure == error.ConsumerPending) continue;
                if (self.gate.snapshot().phase != .healthy) return failure;
                const diagnostic = journalFailureDetail(jail, failure);
                self.mutex.lock();
                const changed = jail.source_error == null or jail.source_error.? != failure or !std.meta.eql(jail.source_diagnostic, diagnostic);
                jail.source_error = failure;
                jail.source_diagnostic = diagnostic;
                jail.healthy = false;
                self.mutex.unlock();
                if (changed) {
                    if (comptime build_options.diag) diag_mod.event(.source_paused, .{ .subject = jail.name, .cause = @errorName(failure) });
                    if (jail.session.? == .journal) logJournalFailure(jail, failure, diagnostic) else std.log.err("native jail {s}: {s}; source paused pending repair", .{ jail.name, @errorName(failure) });
                }
                continue;
            };
            try self.publishSource(jail);
            if (admitted != 0) try self.publishJail(jail);
            if (self.store.retry_admission_target_hint != null) {
                self.retryPublicationPending(null);
                return;
            }
        }
        if (slow_due) self.gates.slow += 1;
        if (slow_due and self.fairness.maintenanceDue(now_ms)) {
            self.gates.due += 1;
            self.fairness.maintained(now_ms);
            self.maintenanceTurn() catch |failure| switch (failure) {
                error.MaintenancePinned, error.StaleMaintenance => {},
                else => return failure,
            };
        }
        if (slow_due) self.reportMaintenanceGates(now_ms);
        if (slow_due) {
            if (try self.store.admissionClock()) |floor| {
                self.mutex.lock();
                self.worker_observation.wall_floor_us = if (self.worker_observation.wall_floor_us) |prior| @max(prior, floor.us) else floor.us;
                self.mutex.unlock();
            }
        }
        if (comptime build_options.diag) diag_mod.ingestBacklog(self.jails);
        if (comptime build_options.diag) self.store.diagSweep(self.clock.wallUs());
    }
    fn retireRemovedJail(self: *Coordinator) !bool {
        var visited: usize = 0;
        while (visited < self.jails.len) : (visited += 1) {
            const index = self.removal_next_jail % self.jails.len;
            self.removal_next_jail = (index + 1) % self.jails.len;
            const jail = &self.jails[index];
            if (!jail.retiring) continue;
            self.effect_backlog = true;
            const intent = try self.store.jailRetirement(jail.name) orelse return error.InvalidRecord;
            if (jail.removal_cursor.phase == .finish) {
                const finished = self.finishRetirementTurn(intent, &jail.removal_withdrawal) catch |failure| {
                    if (failure != error.StaleEffect) return failure;
                    jail.removal_cursor = .{};
                    jail.removal_withdrawal = .{};
                    return false;
                };
                if (finished == null) return false;
                logJailRemoved(jail.name, jail.removal_bans_lifted);
                try self.removeJail(index);
                return true;
            }
            const now = self.clock.wallUs();
            const page = self.store.retireJailPage(jail.name, jail.removal_cursor, jail.removal_max_rows, now, .{ .prepared_us = now, .context = self, .read = wallClockEffect }) catch |failure| {
                if (failure == error.EffectReconciliationRequired) return false;
                return failure;
            };
            if (page.yielded) {
                jail.removal_max_rows = @max(1, jail.removal_max_rows / 2);
                return false;
            }
            jail.removal_cursor = page.next;
            jail.removal_bans_lifted = std.math.add(u32, jail.removal_bans_lifted, page.bans_lifted) catch return error.EffectCapacity;
            jail.removal_owners_released = std.math.add(u32, jail.removal_owners_released, page.owners_released) catch return error.EffectCapacity;
            // A blocked live token settles through the ordinary Manager slice before this turn.
            return false;
        }
        return false;
    }
    fn removeJail(self: *Coordinator, index: usize) !void {
        for (self.jails[index + 1 ..]) |*later| if (later.session) |source| {
            const snapshot = try source.exportRecovery();
            if (later.source_snapshot) |old| old.destroy();
            later.source_snapshot = snapshot;
        };
        for (self.jails[index..]) |*jail| dropRuntimeJail(jail);
        const removed = &self.jails[index];
        if (removed.source_snapshot) |value| value.destroy();
        removed.source_snapshot = null;
        if (removed.custom_plan != null) self.custom_jails -= 1;
        self.mutex.lock();
        var gone = removed.*;
        std.mem.copyForwards(Jail, self.jails[index..], self.jails[index + 1 ..]);
        self.jails = self.jail_storage[0 .. self.jails.len - 1];
        self.refreshRetirementHook();
        self.owner_read_epoch = null;
        self.mutex.unlock();
        self.releaseJail(&gone);
        try self.gate.requestRebuild();
    }
    fn applyBanLists(self: *Coordinator) !void {
        for (self.jails) |*jail| {
            if (!jail.banlist_pending or jail.retiring or !jail.admin_enabled) continue;
            const jail_cfg = findConfigJail(self.live_cfg, jail.name) orelse {
                jail.banlist_pending = false;
                continue;
            };
            var entries: [native_banip.max_banip_entries]ban_origin.BanListEntry = undefined;
            const count = try native_banip.effectiveBanList(self.live_cfg, jail_cfg, &entries);
            if (self.effects == null or !self.jailEnforces(jail)) {
                if (count != 0) std.log.warn("native: jail={} is log-only; its {d} banip entries are not enforced", .{ std.zig.fmtEscapes(jail.name), count });
                jail.banlist_pending = false;
                continue;
            }
            const now = self.clock.wallUs();
            const change = self.store.applyBanList(jail.name, jail.session.?.generation(), entries[0..count], now, .{ .prepared_us = now, .context = self, .read = wallClockEffect }) catch |failure| {
                if (failure == error.EffectReconciliationRequired) continue;
                return failure;
            };
            jail.banlist_pending = false;
            jail.config_bans +|= change.added;
            if (change.added != 0 or change.lifted != 0 or change.expired != 0)
                std.log.info("native: jail={} banip applied: {d} added, {d} lifted, {d} unchanged, {d} expired", .{ std.zig.fmtEscapes(jail.name), change.added, change.lifted, change.unchanged, change.expired });
        }
    }
    fn expireIgnoreEntries(self: *Coordinator, now_ms: u64) !void {
        if (self.last_ignore_expiry_ms) |last| if (now_ms -| last < quiet_interval_ms) return;
        self.last_ignore_expiry_ms = now_ms;
        const now = self.clock.wallUs();
        var changed: [256]durable.Store.IgnoreJailCount = undefined;
        const count = try self.store.expireIgnoreEntries(now, &changed);
        for (changed[0..count]) |item| std.log.info("native: jail={} {d} runtime ignore entries expired", .{ std.zig.fmtEscapes(item.jail[0..item.jail_len]), item.count });
        for (self.jails) |*jail| {
            const cell = ignoreCell(jail) orelse continue;
            var due = if (cell.*.next_deadline_us) |deadline| deadline <= now else false;
            for (changed[0..count]) |item| due = due or std.mem.eql(u8, item.jail[0..item.jail_len], jail.name);
            if (due) try self.rebuildIgnoreList(jail, now);
        }
    }
    pub usingnamespace @import("daemon_query.zig").Methods(@This());
    fn reportMaintenanceGates(self: *Coordinator, now_ms: u64) void {
        if (self.last_gate_report_ms) |last| if (now_ms -| last < 10_000) return;
        const g = self.gates;
        if (std.meta.eql(g, MaintenanceGates{})) return;
        std.log.debug("native: maintenance gates: slow={d} due={d} turns={d} unhealthy_gate={d} step={d}/{d}/{d} unsettled={d} no_session={d} unhealthy={d} candidate_receipt={d} consumer_busy={d} candidate_source={d} no_sources={d} history_missing={d} history_behind={d} walks={d} resumes={d} advances={d} token={d} null={d}", .{ g.slow, g.due, g.turns, g.unhealthy_gate, g.step_progress, g.step_returned, g.step_wait, g.unsettled, g.no_session, g.unhealthy, g.candidate_receipt, g.consumer_busy, g.candidate_source, g.no_sources, g.history_missing, g.history_behind, g.walks, g.resumes, g.advances, g.advance_token, g.advance_null });
        self.last_gate_report_ms = now_ms;
        self.gates = .{};
    }
    fn reportViewProgress(self: *Coordinator, manager: *effect_runtime.Manager) void {
        const now_ms = monotonic(self);
        if (self.last_view_report_ms) |last| if (now_ms -| last < 10_000) return;
        const c = manager.counters;
        if (std.meta.eql(c, self.last_view_counters)) return;
        std.log.debug("native: effect view: rebuilds={d} restarted={d} incremental={d} readbacks={d} interrupted={d} entries={d} installed={d} ready={} pending={d} overdue={d} blocking={d} expiry_batches={d}/{d} retired={d}/{d} examined={d} pinned={d}/{d} refused={d}", .{ c.rebuilds_completed, c.rebuild_restarts, c.incremental_updates, c.full_readbacks, c.dump_interrupted, manager.count, manager.installed_live, manager.status.ready, c.pending, c.overdue, c.overdue_blocking, c.expiries_prepared, c.expiry_batches, self.retired_total, self.retire_batches, self.retire_examined, self.retire_pinned_state, self.retire_pinned_effect, self.retire_refused });
        self.last_view_report_ms = now_ms;
        self.last_view_counters = c;
    }
    fn retirementStep(self: *Coordinator) !void {
        var visited: usize = 0;
        while (visited < self.jails.len) : (visited += 1) {
            const jail = &self.jails[self.retire_jail % self.jails.len];
            self.retire_jail = (self.retire_jail + 1) % self.jails.len;
            if (jail.retiring) continue;
            const session = jail.session orelse continue;
            if (session == .internal) continue;
            const now_us = self.clock.wallUs();
            const generation = session.generation();
            const retry_revision = try self.store.retryStateRevision();
            const effect_revision = try self.store.maintenanceEffectRevision();
            var pass = jail.retirement;
            const changed = (if (pass.retry_revision) |mark| mark != retry_revision else false) or
                (if (pass.effect_revision) |mark| mark != effect_revision else false) or
                (if (pass.generation) |mark| !std.mem.eql(u8, &mark, &generation) else false);
            if (pass.parked) {
                if (!changed and (pass.next_us == null or now_us < pass.next_us.?)) continue;
                pass = .{ .max = pass.max };
            } else if (changed) pass.dirty = true;
            const fence = durable.Store.CleanupFence{
                .jail = jail.name,
                .source = "@retired",
                .generation = generation,
                .jail_revision = try self.store.revision(jail.name),
                .consumer_revision = try self.store.maintenanceConsumerRevision(),
                .effect_revision = effect_revision,
                .clock = .{ .prepared_us = now_us, .context = self, .read = wallClockEffect },
                .preparations = .released,
            };
            const batch = self.store.retireRetrySubjects(fence, pass.after, now_us, jail.policy.window_us, pass.max) catch |failure| switch (failure) {
                error.StaleMaintenance, error.MaintenancePinned, error.RetryAdmissionRequired => {
                    self.retire_refused += 1;
                    return;
                },
                else => return failure,
            };
            if (batch.yielded) {
                // A clean rollback retains every pass mark and cursor; only the next attempt shrinks.
                jail.retirement.max = @max(1, pass.max / 2);
                self.maintenance_progress = true;
                return;
            }
            if (batch.last) |last| pass.after = last;
            if (batch.next_check_us) |next| pass.next_us = if (pass.next_us) |prior| @min(prior, next) else next;
            pass.retry_revision = batch.retry_revision;
            pass.effect_revision = batch.effect_revision;
            pass.generation = generation;
            var restarted = false;
            if (batch.exhausted) {
                if (pass.dirty or (if (pass.next_us) |next| now_us >= next else false)) {
                    // Revisit keys behind the cursor once outside changes or elapsed time require it.
                    pass = .{ .retry_revision = batch.retry_revision, .effect_revision = batch.effect_revision, .generation = generation, .max = pass.max };
                    restarted = true;
                } else {
                    pass.after = null;
                    pass.parked = true;
                }
            }
            jail.retirement = pass;
            self.retire_examined += batch.examined;
            self.retire_pinned_state += batch.pinned_state;
            self.retire_pinned_effect += batch.pinned_effect;
            self.retire_batches += @intFromBool(batch.retired != 0);
            self.retired_total += batch.retired;
            if (batch.examined != 0 or restarted) {
                self.maintenance_progress = true;
                return;
            }
        }
    }
    pub const quiet_interval_ms: u64 = 1000;
    const maintenance_idle_ms: u64 = 30 * quiet_interval_ms;
    const verify_interval_ns: u64 = 5 * std.time.ns_per_s;
    const audit_interval_ns: u64 = 60 * std.time.ns_per_s;
    const stop_history_budget_ns: u64 = 2 * std.time.ns_per_s;
    fn drainHistoryForStop(self: *Coordinator) void {
        if (self.gate.snapshot().phase != .healthy or !self.store_open or self.store.reopen_required) return;
        var timer = std.time.Timer.start() catch |failure| {
            std.log.warn("native: stop left the history consumer behind the head: {s}; the next start resumes it", .{@errorName(failure)});
            return;
        };
        var groups: usize = 0;
        while (timer.read() < stop_history_budget_ns) : (groups += 1) {
            const caught_up = self.consumeHistory() catch |failure| {
                std.log.warn("native: stop left the history consumer behind the head: {s}; the next start resumes it", .{@errorName(failure)});
                return;
            };
            if (caught_up) return;
        }
        std.log.warn("native: stop left the history consumer behind the head after {d} groups in {d} ms; the next start resumes it", .{ groups, timer.read() / std.time.ns_per_ms });
    }
    fn maintenanceMark(self: *Coordinator) !MaintenanceMark {
        return .{ .committed = self.gate.snapshot().committed_records, .epoch = self.store.effect_publication_epoch, .retry_revision = try self.store.retryStateRevision() };
    }
    fn maintenanceTurn(self: *Coordinator) !void {
        const diag_span = if (comptime build_options.diag) diag_mod.enter(.maintenance) else {};
        defer if (comptime build_options.diag) diag_mod.leave(diag_span);
        self.gates.turns += 1;
        if (self.gate.snapshot().phase != .healthy or self.jails.len == 0) {
            self.gates.unhealthy_gate += 1;
            return;
        }
        self.maintenance_progress = false;
        try self.retirementStep();
        const age_us = std.math.mul(i64, std.math.cast(i64, self.cfg.global.history_retention) orelse return error.InvalidApplicationHistoryQuery, 1_000_000) catch return error.InvalidApplicationHistoryQuery;
        if (self.history_page == null and self.history_caught_up) _ = try self.consumeHistory();
        const caught_up = if (self.history_page) |page| page.after_sequence == page.head_sequence and page.last_sequence == page.head_sequence else self.history_consumer == null;
        const effects_settled = if (self.effects) |manager| manager.status.ready and !manager.status.uncertain else true;
        const effects_usable = if (self.effects) |manager| !manager.status.uncertain and !self.store.reopen_required else true;
        const now_ms = monotonic(self);
        const step_idle = std.meta.eql(self.maintenance_idle, try self.maintenanceMark()) and now_ms -| self.maintenance_idle_since_ms < maintenance_idle_ms;
        var record_idle = false;
        // The turn's own cleanup writes advance the mark; take it after them so only outside changes resume the step.
        defer if (record_idle or step_idle) {
            self.maintenance_idle = self.maintenanceMark() catch null;
            if (record_idle) self.maintenance_idle_since_ms = now_ms;
        };
        if (!step_idle) self.maintenance_idle = null;
        switch (if (step_idle) .idle else try self.store.maintenanceStep(.{ .retention = .{ .age_us = age_us, .max_matches = self.live_cfg.global.history_max_matches }, .now_us = self.clock.wallUs(), .history_caught_up = caught_up, .spent_scopes = effects_usable })) {
            .progress => |operation| {
                self.maintenance_progress = true;
                self.confirmations_epoch = null;
                self.gates.step_progress += 1;
                if (operation == .history_rebuild or operation == .history_details or operation == .history_prefix) {
                    self.history_page = null;
                    self.gates.step_returned += 1;
                    return;
                }
            },
            .wait => |operation| {
                self.maintenance_progress = true;
                self.gates.step_wait += 1;
                if (operation != .obsolete_rows and operation != .spent_scopes and operation != .history_details) return;
            },
            .idle => record_idle = !step_idle and caught_up,
        }
        if (!effects_settled) {
            self.gates.unsettled += 1;
            return;
        }
        if (self.effects != null) {
            const page = self.history_page orelse {
                self.gates.history_missing += 1;
                return;
            };
            if (page.after_sequence != page.head_sequence or page.last_sequence != page.head_sequence) {
                self.gates.history_behind += 1;
                return;
            }
        }
        const jail = &self.jails[self.maintenance_jail % self.jails.len];
        self.maintenance_jail = (self.maintenance_jail + 1) % self.jails.len;
        if (jail.retiring) return;
        const session = jail.session orelse {
            self.gates.no_session += 1;
            return;
        };
        if (!session.healthy()) {
            self.gates.unhealthy += 1;
            return;
        }
        switch (session) {
            .file => |value| if (value.pipe.candidate_receipt != null) {
                self.gates.candidate_receipt += 1;
                return;
            },
            .journal => |value| if (value.pipe.candidate_receipt != null) {
                self.gates.candidate_receipt += 1;
                return;
            },
            .internal => {
                self.gates.no_session += 1;
                return;
            },
        }
        if (jail.consumer) |owner| {
            if (owner.ignores.in_flight) {
                self.gates.consumer_busy += 1;
                return;
            }
            for (owner.registry.sources[0..owner.registry.count]) |source| {
                if (source.busy or source.pending != null or source.waiting_occurrence != null or source.dns_stage != null) {
                    self.gates.consumer_busy += 1;
                    return;
                }
            }
        }
        const source_count: usize = switch (session) {
            .file => |value| blk: {
                if (value.candidate_source != null) {
                    self.gates.candidate_source += 1;
                    return;
                }
                break :blk value.sources.sources.items.len;
            },
            .journal => 1,
            .internal => return,
        };
        if (source_count == 0) {
            self.gates.no_sources += 1;
            return;
        }
        const source_index = jail.maintenance_source % source_count;
        const source_id = switch (session) {
            .file => |value| value.sources.sources.items[source_index].source_id,
            .journal => |value| value.options.source_id,
            .internal => return,
        };
        const generation = switch (session) {
            .file => |value| value.processor.generation,
            .journal => |value| value.processor.generation,
            .internal => return,
        };
        self.gates.walks += 1;
        var manifest: ?@import("core/native_consumer.zig").Manifest = null;
        if (jail.consumer) |owner| manifest = try (try owner.registry.source(source_id)).manifest(generation);
        const fence = durable.Store.CleanupFence{
            .jail = jail.name,
            .source = source_id,
            .generation = generation,
            .jail_revision = try self.store.revision(jail.name),
            .consumer_revision = try self.store.maintenanceConsumerRevision(),
            .effect_revision = try self.store.maintenanceEffectRevision(),
            .history = self.history_page,
            .manifest = manifest,
            .clock = .{ .prepared_us = self.clock.wallUs(), .context = self, .read = wallClockEffect },
            .preparations = .released,
        };
        jail.maintenance_source = (source_index + 1) % source_count;
        if (try self.store.cleanupResume(jail.name, source_id, generation)) |token| {
            self.gates.resumes += 1;
            _ = try self.store.cleanupDelete(fence, token);
            self.maintenance_progress = true;
        } else if (try self.store.sourceMaintenance(jail.name, source_id, generation)) |state| {
            self.gates.advances += 1;
            if (try self.store.cleanupAdvance(fence, state, state.head_sequence) != null) {
                self.gates.advance_token += 1;
                self.maintenance_progress = true;
            } else self.gates.advance_null += 1;
        }
    }
    pub fn releaseJail(self: *Coordinator, jail: *Jail) void {
        if (jail.reservation) |token| self.resources.release(token) catch |failure| {
            std.log.err("native: jail={} reservation release failed: {s}", .{ std.zig.fmtEscapes(jail.name), @errorName(failure) });
        };
        jail.reservation = null;
        if (jail.custom_plan) |value| value.destroy();
        jail.plan.deinit(self.allocator);
        destroyZone(self.allocator, jail.zone);
        if (jail.source_status_arena) |*arena| arena.deinit();
        self.allocator.free(jail.active);
        self.allocator.free(jail.name);
    }
    pub fn stop(self: *Coordinator) void {
        self.stop_mutex.lock();
        self.stopping = true;
        self.wake.signal();
        self.stop_mutex.unlock();
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
    }
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
        self.pending_withdrawals.deinit(self.allocator);
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
    fn status(ctx: ?*anyopaque, out: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator) !void {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        try self.statusPayloadLimit(out, a, true, http.max_response_bytes);
    }
    pub fn knowledge(self: *const Coordinator, now_ms: ?u64) ?Knowledge {
        const effects = self.published_effects orelse return null;
        const view = self.published_view;
        if (effects.uncertain and !view.transient_uncertain) return .none;
        const readback = view.readback_ns orelse return if (effects.ready) .fresh else .none;
        if (view.events_subscribed and !view.events_healthy) return .stale;
        const now = now_ms orelse return .stale;
        const age_ns = (now *| std.time.ns_per_ms) -| readback;
        return if (age_ns <= view.verify_interval_ns +| view.wake_interval_ns) .fresh else .stale;
    }
    fn enforcementActive(self: *const Coordinator, observation: health.WorkerStatus, now_ms: ?u64) bool {
        if (!observationSound(observation) or self.published_health.phase != .healthy or self.backend_failure != null or self.overBlocking()) return false;
        if (self.published_effects) |effects| if (effects.withdrawn) return false;
        return (self.knowledge(now_ms) orelse return false) == .fresh;
    }
    pub fn confirmationKnown(self: *const Coordinator, now_ms: ?u64) bool {
        if (self.owner_publication_pending or self.published_owners_mark == null) return false;
        return if (self.knowledge(now_ms)) |known| known != .none else false;
    }
    pub fn confirmedCount(self: *const Coordinator, jail: Jail, now: i64, now_ms: ?u64) ?u32 {
        if (!self.jailEnforces(&jail)) return 0;
        if (!self.confirmationKnown(now_ms)) return null;
        if (self.knowledge(now_ms)) |known| if (known == .none) return null;
        var count: u32 = 0;
        const range = jail.owner_range;
        for (self.owner_active[range.start..][0..range.len], self.owner_confirmed[range.start..][0..range.len]) |owner, confirmed| if (confirmed and owner.lease.live(now)) {
            count += 1;
        };
        return count;
    }
    pub fn formatListSubject(subject: inspection.canonical_scope.Subject, buffer: *[64]u8) ![]const u8 {
        const address: shared.IpAddress = switch (subject.family) {
            .v4 => .{ .ipv4 = std.mem.readInt(u32, subject.address[0..4], .big) },
            .v6 => .{ .ipv6 = std.mem.readInt(u128, &subject.address, .big) },
        };
        return switch (subject.kind) {
            .host => std.fmt.bufPrint(buffer, "{}", .{address}),
            .network => std.fmt.bufPrint(buffer, "{}/{d}", .{ address, subject.prefix }),
        };
    }
    fn commandAuth(ctx: ?*anyopaque, cmd: shared.Command, peer: ipc.Peer, a: std.mem.Allocator) !shared.Response {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        if (cmd == .list and peer.class == .monitor) return .{ .err = .{ .code = 403, .message = try a.dupe(u8, "administrator required for ban details") } };
        if (cmd == .query_v1) return self.queryResponse(a, cmd.query_v1.slice(), switch (peer.class) {
            .admin => .admin,
            .monitor => .monitor,
        });
        if (cmd == .status) {
            var output: std.ArrayListUnmanaged(u8) = .{};
            defer output.deinit(a);
            try self.statusPayload(&output, a, peer.class == .monitor);
            return .{ .ok = .{ .payload = try output.toOwnedSlice(a) } };
        }
        if (cmd == .admin_v1 or cmd == .reload_v1) {
            var output: std.ArrayListUnmanaged(u8) = .{};
            defer output.deinit(a);
            return switch (cmd) {
                .admin_v1 => |request| self.adminResponse(&output, a, request, peer.uid),
                else => self.reloadResponse(&output, a, peer.uid),
            };
        }
        return command(ctx, cmd, a);
    }
    fn readinessInputs(self: *Coordinator, jails: *[max_jails]readiness.Jail) readiness.Inputs {
        const observation = self.observedWorker();
        for (self.jails, 0..) |jail, i| jails[i] = .{ .healthy = jail.healthy, .source_error = if (jail.source_error) |cause| !pipeline.Pipeline.commitBlocked(cause) else false, .enforce = self.jailEnforces(&jail), .source_paused = jailPaused(&jail) };
        return .{
            .config_loaded = self.generation_admitted,
            .storage_phase = self.published_health.phase,
            .worker = observation,
            .jails = jails[0..self.jails.len],
            .effects = if (self.published_effects) |effects| .{ .ready = effects.ready, .uncertain = effects.uncertain, .overdue = effects.overdue != 0 } else null,
            .admin_generation_admitted = self.generation_admitted,
            .admin_serving = if (self.admin_serving) |serving| serving.load(.acquire) else true,
        };
    }
    pub fn readinessReport(self: *Coordinator) readiness.Report {
        var jails: [max_jails]readiness.Jail = undefined;
        self.mutex.lock();
        defer self.mutex.unlock();
        return readiness.derive(self.readinessInputs(&jails));
    }
    fn initializeObservationCache(self: *Coordinator, admitted: bool, installation: effect.Installation) void {
        if (!admitted) {
            self.firewall_observation_unavailable = .memory_budget;
            return;
        }
        const cache = self.allocator.create(firewall_observation.Cache) catch {
            self.firewall_observation_unavailable = .allocation_failed;
            return;
        };
        var nonce: [16]u8 = undefined;
        std.crypto.random.bytes(&nonce);
        cache.* = firewall_observation.Cache.init(effect_runtime.transportInstallation(installation), nonce);
        self.firewall_observation_cache = cache;
        self.firewall_observation_unavailable = .not_observed;
    }

    pub fn findConfigJail(cfg: *const config.Config, name: []const u8) ?*const config.JailConfig {
        for (cfg.jails) |*jail| if (std.mem.eql(u8, jail.name, name)) return jail;
        return null;
    }
    const JailListRow = struct {
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
    fn writeJails(self: *Coordinator, output: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator) !void {
        var rows: [max_jails]JailListRow = undefined;
        const count = capture: {
            self.mutex.lock();
            defer self.mutex.unlock();
            const wall = self.observationWall();
            const ms = observationMs();
            const observation = self.worker_observation.read(ms, wall);
            for (self.jails, 0..) |jail, i| rows[i] = .{
                .name = try detection.Name.init(jail.name),
                .healthy = jail.healthy and self.published_health.phase == .healthy and observationSound(observation),
                .enabled = jail.admin_enabled,
                .paused = jail.admin_paused,
                .disable_cleanup_pending = jail.disable_cleanup_pending,
                .active_bans = self.confirmedCount(jail, wall orelse self.start_us, ms),
                .maxretry = jail.policy.maxretry,
                .findtime = @divTrunc(jail.policy.window_us, 1_000_000),
                .bantime = switch (jail.policy.duration) {
                    .finite_us => |value| @divTrunc(value, 1_000_000),
                    .permanent => null,
                },
                .action = if (self.jailEnforces(&jail)) self.published_backend else "log-only",
                .enforce_configured = jail.policy.enforce,
                .enforcing = self.jailEnforces(&jail) and self.enforcementActive(observation, ms),
                .source = std.meta.activeTag(jail.plan),
                .source_healthy = jail.healthy,
                .source_paused = jailPaused(&jail),
                .source_missing = jail.source_missing,
                .revision = jail.revision,
                .decisions = jail.summary.decisions,
                .cause = jail.source_error,
                .diagnostic = jail.source_diagnostic,
            };
            break :capture self.jails.len;
        };
        var sink = query_v1.ByteSink{ .out = output, .allocator = a, .limit = shared.protocol.max_payload_size - 16 };
        const w = sink.writer();
        w.writeByte('[') catch |failure| return if (failure == error.ResponseTooLarge) error.SnapshotLimit else failure;
        for (rows[0..count], 0..) |row, i| {
            if (i != 0) try w.writeByte(',');
            std.json.stringify(.{ .name = row.name.slice(), .healthy = row.healthy, .enabled = row.enabled, .paused = row.paused, .disable_cleanup_pending = row.disable_cleanup_pending, .active_bans = row.active_bans, .maxretry = row.maxretry, .findtime = row.findtime, .bantime = row.bantime, .bantime_permanent = row.bantime == null, .action = row.action, .enforce_configured = row.enforce_configured, .enforcing = row.enforcing, .log_source = @tagName(row.source), .source_healthy = row.source_healthy, .source_paused = row.source_paused, .source_missing = row.source_missing, .source = @tagName(row.source), .revision = row.revision, .decisions = row.decisions, .cause = if (row.cause) |cause| @errorName(cause) else "none", .source_exit_code = if (row.diagnostic) |detail| detail.exit_code else null, .source_signal = if (row.diagnostic) |detail| detail.signal else null, .source_stderr_present = if (row.diagnostic) |detail| @as(?bool, detail.stderr_present) else null }, .{}, w) catch |failure| return if (failure == error.ResponseTooLarge) error.SnapshotLimit else failure;
        }
        try w.writeByte(']');
    }
    fn command(ctx: ?*anyopaque, cmd: shared.Command, a: std.mem.Allocator) !shared.Response {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        var output: std.ArrayListUnmanaged(u8) = .{};
        defer output.deinit(a);
        switch (cmd) {
            .status => try self.statusPayload(&output, a, true),
            .version => try std.json.stringify(.{ .daemon_version = version }, .{}, output.writer(a)),
            .list => |selected| try self.writeBans(&output, a, selected.jail),
            .list_jails => try self.writeJails(&output, a),
            .ban, .unban => return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "legacy ban/unban are retired; use admin_v1") } },
            .reload => return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "legacy reload is retired; use reload_v1") } },
            .reload_v1, .admin_v1 => return error.MutationHandlerNotInstalled,
            .query_v1 => |body| return self.queryResponse(a, body.slice(), .monitor),
            .diag_v1 => |body| if (comptime build_options.diag) return self.diagResponse(a, body.slice()) else return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "diag commands need a diag build") } },
        }
        return .{ .ok = .{ .payload = try output.toOwnedSlice(a) } };
    }
    fn diagResponse(self: *Coordinator, a: std.mem.Allocator, body: []const u8) !shared.Response {
        self.mutex.lock();
        const effects_live = self.effects != null;
        const installed_live = self.published_view.installed_live;
        self.mutex.unlock();
        const response = try diag_command.handle(&self.clock, effects_live, installed_live, body, a);
        if (response == .ok) self.wake.signal();
        return response;
    }
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
    std.log.info("fail2zig {s} running; backend={s}; native SQLite ingestion; protection admission pending; ipc={s}; http={s}", .{ version, backend_name, cfg.global.socket_path, if (cfg.global.metrics_enabled) cfg.global.metrics_bind else "off" });
    try loop.run();
}
