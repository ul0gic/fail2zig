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
const log_level = @import("core/log_level.zig");
const query_v1 = @import("net/query_v1.zig");
const readiness = @import("core/readiness.zig");
const sd_notify = @import("core/sd_notify.zig");
const log_target = @import("core/log_target.zig");
const max_jails = 64;
const max_sources_per_jail = 8;
const recovery_validation_budget_ns = 100 * std.time.ns_per_ms;
const tick_wait_ns = 100 * std.time.ns_per_ms;

fn notifyReloadReady(report: readiness.Report, notifier: anytype) void {
    if (!report.ready) return;
    _ = notifier.ready() catch |err| std.log.warn("sd_notify READY failed after reload: {s}", .{@errorName(err)});
}

const AdminReadback = enum { pending, uncertain, coherent };

fn adminReadback(effect_health: effect_runtime.Health, cached_epoch: ?u64, store_epoch: u64) AdminReadback {
    if (effect_health.uncertain) return .uncertain;
    if (effect_health.ready and cached_epoch != null and cached_epoch.? == store_epoch) return .coherent;
    return .pending;
}

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
const Jail = struct {
    name: []const u8,
    plan: Plan,
    policy: retry.Policy,
    session: ?Source = null,
    source_snapshot: ?SourceSnapshot = null,
    custom_plan: ?*consumer_plan.Prepared = null,
    consumer: ?*consumer_runtime.JailRuntime = null,
    active: []durable.Store.ActiveDecision = &.{},
    confirmed: []bool = &.{},
    active_keys: []?[32]u8 = &.{},
    summary: durable.Store.RetrySummary = .{},
    retry_revision: ?u64 = null,
    published_once: bool = false,
    next_expiry_us: ?i64 = null,
    published_mark: ?EffectMark = null,
    revision: u64 = 0,
    healthy: bool = false,
    source_error: ?anyerror = null,
    source_missing: bool = false,
    source_diagnostic: ?journal_sessions.FailureDiagnostic = null,
    last_journal_notice: ?journal_sessions.FailureDiagnostic = null,
    zone: ?*timezone.Zone = null,
    maintenance_source: usize = 0,
    retire_after: ?detection.Subject = null,
    rekeyed: bool = false,
    admin_paused: bool = false,
    admin_enabled: bool = true,
    on_truncation: config.TruncationPolicy = .refuse,
    ignore_runtime_only: u16 = 0,
    source_status: []SourceStatus = &.{},
    source_status_arena: ?std.heap.ArenaAllocator = null,
    source_signature: SourceSignature = .{},
};

pub const SourceStatus = struct {
    jail: []const u8,
    kind: enum { file, journal },
    path: ?[]const u8,
    on_truncation: ?config.TruncationPolicy,
    state: enum { paused, reading },
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
    causes: [max_sources_per_jail + 1]?anyerror = [_]?anyerror{null} ** (max_sources_per_jail + 1),
    loss_sequence: u64 = 0,
    built: bool = false,
};

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
    effects: ?*effect_runtime.Manager = null,
    dns: ?*consumer_runtime.DnsRuntime = null,
    dns_generation: [32]u8 = [_]u8{0} ** 32,
    dns_server: ?std.net.Address = null,
    history_consumer: ?history.Consumer = null,
    history_page: ?history.PageToken = null,
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
    decision_scratch_confirmed: []bool = &.{},
    decision_scratch_keys: []?[32]u8 = &.{},
    owner_scratch: []durable.Store.OperatorOwner = &.{},
    owner_active: []durable.Store.OperatorOwner = &.{},
    owner_scratch_confirmed: []bool = &.{},
    owner_confirmed: []bool = &.{},
    owner_count: usize = 0,
    owner_read_epoch: ?u64 = null,
    published_owners_mark: ?EffectMark = null,
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
    last_view_report_ms: ?u64 = null,
    retire_jail: usize = 0,
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
    rebuild_phase: enum { maintenance, capture, drop, resolver, owners, consumers, history, validation, done } = .maintenance,
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
    startup_progress: ?*sd_notify.Progress = null,
    readiness_progress_started_ns: ?i128 = null,
    readiness_progress_done: u64 = 0,
    readiness_history_pages: u64 = 0,
    readiness_history_head: ?u64 = null,
    history_reader: ?durable.Store = null,
    ipc_server: ?*ipc.IpcServer = null,
    published_generation: [32]u8 = [_]u8{0} ** 32,
    published_config_digest: [32]u8 = [_]u8{0} ** 32,
    generation_admitted: bool = false,

    pub const ReloadKind = enum { applied, noop, rejected, restart_required, uncertain, partial };
    pub const ReloadOutcome = struct {
        kind: ReloadKind,
        generation: [32]u8 = [_]u8{0} ** 32,
        reasons: [reload_mod.max_reasons]reload_mod.Reason = undefined,
        reason_count: u8 = 0,
        fn single(kind: ReloadKind, comptime fmt: []const u8, args: anytype) ReloadOutcome {
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
    const ReloadRequest = struct {
        classification: reload_mod.Classification,
        config_digest: [32]u8,
        proposed: *const config.Config,
        arena: ?*std.heap.ArenaAllocator,
        outcome: ?ReloadOutcome = null,
        done: bool = false,
        abandoned: bool = false,
    };

    fn monotonic(ctx: ?*anyopaque) u64 {
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
        fn withOutcome(self: AdminOutcomeView, outcome: durable.Store.AdminOutcome) AdminOutcomeView {
            var out = self;
            out.outcome = outcome;
            return out;
        }
        fn withReason(self: AdminOutcomeView, comptime fmt: []const u8, args: anytype) AdminOutcomeView {
            var out = self;
            const written = std.fmt.bufPrint(&out.reason.bytes, fmt, args) catch out.reason.bytes[0..0];
            out.reason.len = @intCast(written.len);
            return out;
        }
    };
    const AdminPhase = enum { staged, executing, awaiting, done };
    const AdminRequest = struct {
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
        outcome: ?AdminOutcomeView = null,
        abandoned: bool = false,
        run_id: ?[32]u8 = null,
        verify_seq: u64 = 0,
        unban: bool = false,
        ignore_entry: ?shared.types.IgnoreEntry = null,
        ignore: ?*IgnoreWork = null,
        fn jailName(self: *const AdminRequest) []const u8 {
            return self.jail[0..self.jail_len];
        }
    };
    const max_listed_bans = 256;
    const max_lifted_bans = 256;
    const max_wider_bans = 128;
    const ignore_lift_budget_ms: u64 = 1000;
    const ignore_lift_settle_ms: u64 = 2000;
    const ignore_unban_wait_ms: u64 = 4000;
    const IgnoreEntryState = enum { added, present, removed, config_only, absent, not_recorded, not_removed };
    const IgnoreRelation = enum { inside_entry, contains_entry };
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
    const IgnoreWork = struct {
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
    };
    fn freeAdminRequest(self: *Coordinator, request: *AdminRequest) void {
        if (request.ignore) |ignore_state| self.allocator.destroy(ignore_state);
        self.allocator.destroy(request);
    }

    pub const Staged = struct { view: AdminOutcomeView, owned: bool };
    fn enqueueAdminLocked(self: *Coordinator, request: *AdminRequest) ?Staged {
        if (self.admin_request != null) return .{ .view = (AdminOutcomeView{ .outcome = .rejected, .kind = request.kind }).withReason("administration already in progress", .{}), .owned = true };
        self.admin_request = request;
        return null;
    }
    fn expireAdminWaitLocked(self: *Coordinator, request: *AdminRequest, wait_ms: u64) Staged {
        if (request.phase == .staged) {
            self.admin_request = null;
            return .{ .view = (AdminOutcomeView{ .outcome = .rejected, .kind = request.kind }).withReason("worker did not accept the request within {d} ms; no state was changed", .{wait_ms}), .owned = true };
        }
        request.abandoned = true;
        return .{ .view = (AdminOutcomeView{ .outcome = .uncertain, .kind = request.kind, .generation = self.published_generation }).withReason("worker is still executing the request; inspect status and the recorded outcome", .{}), .owned = false };
    }
    fn adminWorkLocked(self: *Coordinator) ?struct { request: *AdminRequest, phase: AdminPhase } {
        const request = self.admin_request orelse return null;
        if (request.phase == .staged) request.phase = .executing;
        return .{ .request = request, .phase = request.phase };
    }
    pub fn stageAdmin(self: *Coordinator, request: *AdminRequest, wait_ms: u64) Staged {
        self.mutex.lock();
        if (self.enqueueAdminLocked(request)) |rejected| {
            self.mutex.unlock();
            return rejected;
        }
        var timer = std.time.Timer.start() catch null;
        while (request.phase != .done) {
            const elapsed_ms: u64 = if (timer) |*t| t.read() / std.time.ns_per_ms else wait_ms;
            if (elapsed_ms >= wait_ms) break;
            self.reload_wake.timedWait(&self.mutex, (wait_ms - elapsed_ms) * std.time.ns_per_ms) catch {};
        }
        if (request.phase != .done) {
            const expired = self.expireAdminWaitLocked(request, wait_ms);
            self.mutex.unlock();
            return expired;
        }
        const out = request.outcome.?;
        self.mutex.unlock();
        return .{ .view = out, .owned = true };
    }
    fn completeAdmin(self: *Coordinator, request: *AdminRequest, outcome: AdminOutcomeView) void {
        self.mutex.lock();
        request.outcome = outcome;
        request.phase = .done;
        if (self.admin_request == request) self.admin_request = null;
        const abandoned = request.abandoned;
        self.reload_wake.broadcast();
        self.mutex.unlock();
        if (abandoned) self.freeAdminRequest(request);
        std.log.info("native admin: kind={s} outcome={s}", .{ @tagName(outcome.kind), @tagName(outcome.outcome) });
    }
    fn adminDetail(self: *Coordinator, request: *AdminRequest, view: AdminOutcomeView, state: ?durable.Store.JailAdminState) AdminOutcomeView {
        var out = view;
        out.generation = self.published_generation;
        const now = self.clock.wallUs();
        const revision = self.store.finishAdminRequest(.{ .request_id = request.request_id, .kind = request.kind, .subject = request.jailName(), .outcome = view.outcome, .generation = self.published_generation, .committed_us = @max(0, now), .detail = view.reason.slice(), .admission_revision = request.expected_revision }, state) catch |err| {
            std.log.err("native admin: outcome {s} could not be recorded: {s}", .{ @tagName(view.outcome), @errorName(err) });
            return (out.withOutcome(.uncertain)).withReason("{s} outcome not recorded: {s}; inspect before retrying", .{ @tagName(view.outcome), @errorName(err) });
        };
        self.mutex.lock();
        self.published_revision = revision;
        self.mutex.unlock();
        out.mutation_revision = revision;
        return out;
    }
    fn setJailPaused(jail: *Jail, paused: bool) void {
        if (jail.session) |source| switch (source) {
            .file => |value| value.processor.paused = paused,
            .journal => |value| value.processor.paused = paused,
            .internal => {},
        };
    }
    fn adminScope(self: *Coordinator, request: *AdminRequest) !@import("firewall/scope.zig").Scope {
        const address = request.address orelse return error.AdminAddressRequired;
        const canonical = @import("firewall/scope.zig");
        const subject = if (request.prefix) |prefix| blk: {
            const manager = self.effects orelse return error.AdminEnforcementRequired;
            if (manager.installation.backend == .iptables) return error.AdminNetworkScopeUnsupported;
            break :blk try canonical.Subject.network(address, prefix);
        } else canonical.Subject.host(address);
        return .{ .subject = subject };
    }
    fn executeAdmin(self: *Coordinator, request: *AdminRequest) void {
        const outcome = self.executeAdminInner(request) catch |err| blk: {
            if (request.mutation_committed) {
                const failed = switch (request.kind) {
                    .group_disable => (AdminOutcomeView{ .outcome = .partial, .kind = request.kind, .generation = self.published_generation }).withReason("{d} owner releases committed before {s}; inspect state before retrying", .{ request.committed_count, @errorName(err) }),
                    .migration_activate => (AdminOutcomeView{ .outcome = .partial, .kind = request.kind, .generation = self.published_generation }).withReason("migration owner activation committed before {s}; inspect state before retrying", .{@errorName(err)}),
                    else => (AdminOutcomeView{ .outcome = .partial, .kind = request.kind, .generation = self.published_generation }).withReason("mutation committed before {s}; inspect state before retrying", .{@errorName(err)}),
                };
                if (request.pending_state) |state| if (self.findJail(state.jail)) |jail| {
                    setJailPaused(jail, state.paused);
                    self.mutex.lock();
                    jail.admin_paused = state.paused;
                    jail.admin_enabled = state.enabled;
                    self.mutex.unlock();
                };
                break :blk self.adminDetail(request, failed, request.pending_state);
            }
            break :blk (AdminOutcomeView{ .outcome = .rejected, .kind = request.kind, .generation = self.published_generation }).withReason("{s}", .{@errorName(err)});
        };
        if (request.phase == .awaiting) return;
        self.completeAdmin(request, outcome);
    }
    fn executeAdminInner(self: *Coordinator, request: *AdminRequest) !AdminOutcomeView {
        const kind = request.kind;
        const base = AdminOutcomeView{ .outcome = .applied, .kind = kind, .generation = self.published_generation };
        if (kind == .firewall_withdraw) return self.withdrawFirewall(request);
        const ignore_kind = kind == .ignore_add or kind == .ignore_remove;
        if (ignore_kind) {
            const ignore_state = try self.allocator.create(IgnoreWork);
            ignore_state.* = .{};
            request.ignore = ignore_state;
        }
        self.gate.admitMutation() catch |failure| {
            if (!ignore_kind) return failure;
            const cause = if (self.gate.snapshot().last_failure) |last| @errorName(last.cause) else @errorName(failure);
            return base.withOutcome(.rejected).withReason("storage is not accepting changes ({s}); retry when fail2zig status shows storage healthy", .{cause});
        };
        switch (try self.store.admitAdminRequest(request.request_id, request.expected_revision)) {
            .replayed => |prior| return .{ .outcome = prior.outcome, .kind = prior.kind, .generation = self.published_generation, .mutation_revision = prior.mutation_revision },
            .fresh => {},
        }
        if (!std.mem.eql(u8, &request.expected_generation, &self.published_generation)) return self.adminDetail(request, base.withReason("stale generation; reload happened", .{}), null).withOutcome(.rejected);
        const now = self.clock.wallUs();
        switch (kind) {
            .setting_batch => return self.adminDetail(request, (AdminOutcomeView{ .outcome = .rejected, .kind = kind }).withReason("runtime-only settings are not supported; edit the configuration and reload", .{}), null),
            .ignore_add => return self.executeIgnoreAdd(request),
            .ignore_remove => return self.executeIgnoreRemove(request),
            .group_enable, .group_disable, .group_pause, .group_resume => {
                const jail = self.findJail(request.jailName()) orelse return self.adminDetail(request, (AdminOutcomeView{ .outcome = .absent, .kind = kind }).withReason("unknown jail", .{}), null);
                var state = durable.Store.JailAdminState{ .jail = jail.name, .enabled = true, .paused = false, .generation = self.published_generation, .changed_us = @max(0, now), .request_id = request.request_id };
                var existing: durable.Store.JailAdminState = undefined;
                if (try self.store.jailAdminState(jail.name, &existing)) {
                    state.enabled = existing.enabled;
                    state.paused = existing.paused;
                }
                switch (kind) {
                    .group_pause => state.paused = true,
                    .group_resume => state.paused = false,
                    .group_enable => {
                        state.enabled = true;
                        state.paused = false;
                    },
                    .group_disable => {
                        state.enabled = false;
                        state.paused = true;
                        request.pending_state = state;
                        var step: u32 = 0;
                        while (step < 4096) : (step += 1) {
                            var counter: [4]u8 = undefined;
                            std.mem.writeInt(u32, &counter, step, .little);
                            const transition = effect.hashParts("fail2zig-admin-disable-v1", &.{ &request.request_id, &counter });
                            const released = try self.store.flushJailOwner(jail.name, try self.plannedGeneration(jail, .planned), transition, .{ .prepared_us = now, .context = self, .read = wallClockEffect });
                            if (released == null) break;
                            request.mutation_committed = true;
                            request.committed_count += 1;
                        }
                    },
                    else => unreachable,
                }
                setJailPaused(jail, state.paused);
                self.mutex.lock();
                jail.admin_paused = state.paused;
                jail.admin_enabled = state.enabled;
                self.mutex.unlock();
                if (kind == .group_disable and self.effects != null) {
                    request.pending_state = state;
                    request.phase = .awaiting;
                    request.deadline_ms = monotonic(self) + 2000;
                    request.expect_absent = true;
                    request.scope_key = [_]u8{0} ** 32;
                    return base;
                }
                return self.adminDetail(request, base, state);
            },
            .ban, .unban => {
                const jail = self.findJail(request.jailName()) orelse return self.adminDetail(request, (AdminOutcomeView{ .outcome = .absent, .kind = kind }).withReason("unknown jail", .{}), null);
                const manager = self.effects orelse return self.adminDetail(request, (AdminOutcomeView{ .outcome = .rejected, .kind = kind }).withReason("jail is log-only; manual bans require an enforcing backend", .{}), null);
                const canonical = try self.adminScope(request);
                const scope = try effect.Scope.exact(canonical);
                const key = try scope.key(manager.installation);
                const generation = try self.plannedGeneration(jail, .planned);
                const current = try self.store.currentOwner(key, jail.name);
                const clock = effect.Clock{ .prepared_us = now, .context = self, .read = wallClockEffect };
                if (kind == .ban) {
                    const duration: @import("core/native_lease.zig").Duration = if (request.duration_s) |seconds| try @import("core/native_lease.zig").Duration.finiteSeconds(seconds) else jail.policy.duration;
                    const lease = try duration.lease(now);
                    _ = try self.store.setOwnerFromCanonical(.{ .scope = canonical, .jail = jail.name, .generation = generation, .decision_id = durable.Store.adminDecisionId(request.request_id, request.expected_revision), .expected_revision = if (current) |owner| owner.revision else 0, .lease = lease, .decided_us = now }, clock);
                    request.expect_absent = false;
                } else {
                    const owner = current orelse return self.adminDetail(request, (AdminOutcomeView{ .outcome = .absent, .kind = kind }).withReason("no owner for this scope in the jail", .{}), null);
                    if (owner.lease == .absent) return self.adminDetail(request, (AdminOutcomeView{ .outcome = .absent, .kind = kind }).withReason("owner already released", .{}), null);
                    _ = try self.store.transitionOwner(.{ .scope = canonical, .jail = jail.name, .current_generation = owner.generation, .next_generation = owner.generation, .expected_owner_revision = owner.revision, .transition_id = request.request_id, .mode = .release, .occurred_us = now }, clock);
                    request.expect_absent = true;
                }
                request.scope_key = key;
                request.phase = .awaiting;
                request.deadline_ms = monotonic(self) + 2000;
                return base;
            },
            .migration_activate => return self.activateMigration(request, base, now),
            .migration_rollback => return self.rollbackMigration(request, base, now),
            .firewall_withdraw => unreachable,
            .history_reset => {
                const address = request.address orelse return error.AdminAddressRequired;
                const subject: detection.Subject = switch (address) {
                    .ipv4 => |v| .{ .v4 = @bitCast(std.mem.nativeToBig(u32, v)) },
                    .ipv6 => |v| .{ .v6 = @bitCast(std.mem.nativeToBig(u128, v)) },
                };
                const scope: durable.HistoryResetScope = if (request.all) .overall else .{ .jail = request.jailName() };
                if (!request.all and self.findJail(request.jailName()) == null) return self.adminDetail(request, (AdminOutcomeView{ .outcome = .absent, .kind = kind }).withReason("unknown jail", .{}), null);
                const expected = try self.store.historyResetRevision(scope, subject);
                _ = try self.store.resetHistory(.{ .scope = scope, .subject = subject, .expected_revision = expected, .intent_id = request.request_id }, .{ .prepared_us = now, .context = self, .read = wallClockEffect });
                return self.adminDetail(request, base, null);
            },
        }
    }
    fn activateMigration(self: *Coordinator, request: *AdminRequest, base: AdminOutcomeView, now: i64) !AdminOutcomeView {
        const run_id = request.run_id orelse return error.AdminRunIdRequired;
        if (self.effects == null) return self.adminDetail(request, (AdminOutcomeView{ .outcome = .rejected, .kind = request.kind }).withReason("destination is log-only; migrated owners need an enforcing backend", .{}), null);
        const migration_run = (try self.store.migrationRun(self.allocator, run_id)) orelse return self.adminDetail(request, (AdminOutcomeView{ .outcome = .absent, .kind = request.kind }).withReason("unknown migration run", .{}), null);
        self.allocator.free(migration_run.recovery_point);
        if (migration_run.state == .complete) return self.adminDetail(request, base.withReason("migration run already complete", .{}), null);
        if (migration_run.state != .staged and migration_run.state != .activating) return self.adminDetail(request, (AdminOutcomeView{ .outcome = .rejected, .kind = request.kind }).withReason("migration run is {s}, not staged", .{@tagName(migration_run.state)}), null);
        try self.closeInterruptedMigrationStep(run_id, now);
        inline for (.{ durable.Store.MigrationStep.validate_plan, .check_drift, .capture_recovery_point, .quiesce_source, .stage_destination }) |required| {
            if (!try self.store.migrationStepSucceeded(run_id, required)) return self.adminDetail(request, (AdminOutcomeView{ .outcome = .rejected, .kind = request.kind }).withReason("validation_failed: step {s} has no recorded success", .{@tagName(required)}), null);
        }
        var generations: [64]durable.Store.JailGeneration = undefined;
        var count: usize = 0;
        for (self.jails) |*jail| {
            if (count == generations.len) return error.AdminJailCapacity;
            generations[count] = .{ .jail = jail.name, .generation = try self.plannedGeneration(jail, .planned) };
            count += 1;
        }
        const seq = try self.store.beginMigrationStep(run_id, .activate_owners, "", now);
        const clock = effect.Clock{ .prepared_us = now, .context = self, .read = wallClockEffect };
        const activated = self.store.activateStagedOwners(run_id, generations[0..count], clock) catch |err| {
            try self.store.finishMigrationStep(run_id, seq, .operational_failure, @errorName(err), null, self.clock.wallUs());
            return self.adminDetail(request, (AdminOutcomeView{ .outcome = .rejected, .kind = request.kind }).withReason("activation failed: {s}", .{@errorName(err)}), null);
        };
        request.mutation_committed = true;
        request.committed_count = activated;
        try self.store.finishMigrationStep(run_id, seq, .success, "", .activating, self.clock.wallUs());
        request.verify_seq = try self.store.beginMigrationStep(run_id, .verify_protection, "", self.clock.wallUs());
        request.scope_key = [_]u8{0} ** 32;
        request.phase = .awaiting;
        request.deadline_ms = monotonic(self) + 5000;
        return base;
    }
    fn rollbackMigration(self: *Coordinator, request: *AdminRequest, base: AdminOutcomeView, now: i64) !AdminOutcomeView {
        const run_id = request.run_id orelse return error.AdminRunIdRequired;
        if (self.effects == null) return self.adminDetail(request, (AdminOutcomeView{ .outcome = .rejected, .kind = request.kind }).withReason("destination is log-only; nothing is realized to release", .{}), null);
        const migration_run = (try self.store.migrationRun(self.allocator, run_id)) orelse return self.adminDetail(request, (AdminOutcomeView{ .outcome = .absent, .kind = request.kind }).withReason("unknown migration run", .{}), null);
        self.allocator.free(migration_run.recovery_point);
        if (migration_run.state != .complete and migration_run.state != .activating and migration_run.state != .rolled_back) return self.adminDetail(request, (AdminOutcomeView{ .outcome = .rejected, .kind = request.kind }).withReason("migration run is {s}; only an activated run can be rolled back", .{@tagName(migration_run.state)}), null);
        const open = try self.store.pendingMigrationStep(run_id);
        if (open == null or open.?.step != .rollback) return self.adminDetail(request, (AdminOutcomeView{ .outcome = .rejected, .kind = request.kind }).withReason("no rollback in progress for this run; restore the source with `migrate rollback` first", .{}), null);
        const clock = effect.Clock{ .prepared_us = now, .context = self, .read = wallClockEffect };
        _ = self.store.releaseMigrationOwners(run_id, clock) catch |err| {
            return self.adminDetail(request, (AdminOutcomeView{ .outcome = .rejected, .kind = request.kind }).withReason("release failed: {s}", .{@errorName(err)}), null);
        };
        request.scope_key = [_]u8{0} ** 32;
        request.phase = .awaiting;
        request.deadline_ms = monotonic(self) + 5000;
        return base;
    }
    fn closeInterruptedMigrationStep(self: *Coordinator, run_id: [32]u8, now: i64) !void {
        if (try self.store.pendingMigrationStep(run_id)) |open| {
            if (open.step == .rollback) return error.MigrationRollbackOpen;
            try self.store.finishMigrationStep(run_id, open.seq, .uncertain, "interrupted before its outcome was recorded", null, now);
        }
    }
    fn settleMigration(self: *Coordinator, request: *AdminRequest, manager: *effect_runtime.Manager) ?AdminOutcomeView {
        const run_id = request.run_id.?;
        var view = AdminOutcomeView{ .outcome = .partial, .kind = request.kind, .enforced = false };
        const now = self.clock.wallUs();
        const keys = self.allocator.alloc([32]u8, effect.max_effects) catch return view.withReason("out of memory during readback", .{});
        defer self.allocator.free(keys);
        const report = self.store.migrationActivatedKeys(run_id, now, keys) catch |err| return (view.withOutcome(.uncertain)).withReason("activated owners unreadable: {s}", .{@errorName(err)});
        var applied: usize = 0;
        for (keys[0..report.found]) |key| {
            for (manager.live[0..manager.count]) |entry| if (std.mem.eql(u8, &entry.scope_key, &key) and entry.status == .applied and entry.desired.live(now)) {
                applied += 1;
                break;
            };
        }
        if (manager.status.uncertain) {
            view.destination = "uncertain";
            return (view.withOutcome(.uncertain)).withReason("effect outcome uncertain: {s}", .{if (manager.status.cause) |cause| @errorName(cause) else "unknown"});
        }
        if (request.kind == .migration_rollback) {
            const remaining = self.store.migrationOwnersRemaining(run_id) catch |err| return (view.withOutcome(.uncertain)).withReason("migration owners unreadable: {s}", .{@errorName(err)});
            const staged_count = self.store.migrationStagedKeys(run_id, keys) catch |err| return (view.withOutcome(.uncertain)).withReason("staged scopes unreadable: {s}", .{@errorName(err)});
            var realized: usize = 0;
            for (keys[0..staged_count]) |key| {
                for (manager.live[0..manager.count]) |entry| if (std.mem.eql(u8, &entry.scope_key, &key) and entry.status == .applied and entry.desired.live(now)) {
                    realized += 1;
                    break;
                };
            }
            const coherent = manager.status.ready and manager.cached_epoch != null and manager.cached_epoch.? == self.store.effect_publication_epoch;
            if (coherent and remaining == 0) {
                view.outcome = .applied;
                view.destination = if (realized == 0) "absent" else "present";
                return view.withReason("migration owners released; {d} of {d} staged scopes remain protected by other owners", .{ realized, staged_count });
            }
            if (monotonic(self) < request.deadline_ms) return null;
            view.destination = "partial";
            return view.withReason("{d} migration owners remain; current protection not confirmed before the deadline", .{remaining});
        }
        if (report.found == report.expected and applied == report.found) {
            view.outcome = .applied;
            view.enforced = true;
            view.destination = "present";
            return view.withReason("{d} owners confirmed in the kernel", .{applied});
        }
        if (monotonic(self) < request.deadline_ms) return null;
        if (applied == 0) {
            view.destination = "absent";
            return (view.withOutcome(.uncertain)).withReason("none of {d} activated owners confirmed in the kernel within the deadline", .{report.expected});
        }
        view.destination = "partial";
        return view.withReason("{d} of {d} activated owners confirmed in the kernel within the deadline", .{ applied, report.expected });
    }
    fn finishMigrationVerify(self: *Coordinator, request: *AdminRequest, view: AdminOutcomeView) void {
        const run_id = request.run_id orelse return;
        if (request.kind == .migration_rollback) return;
        const outcome: durable.Store.MigrationOutcome = switch (view.outcome) {
            .applied => .success,
            .uncertain => .uncertain,
            else => .partial,
        };
        self.store.finishMigrationStep(run_id, request.verify_seq, outcome, view.reason.slice(), if (outcome == .success) .complete else null, self.clock.wallUs()) catch |err| {
            std.log.err("native migration: verify outcome {s} could not be recorded: {s}", .{ @tagName(outcome), @errorName(err) });
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
    fn withdrawFirewall(self: *Coordinator, request: *AdminRequest) AdminOutcomeView {
        const base = AdminOutcomeView{ .outcome = .applied, .kind = request.kind, .generation = self.published_generation, .mutation_revision = self.published_revision };
        const manager = self.effects orelse return base.withOutcome(.rejected).withReason("log-only: no enforcement backend holds rules", .{});
        if (manager.withdrawn and !manager.stopping) {
            std.log.info("native: firewall withdraw removed 0 realized rules; enforcement already withdrawn until the next start", .{});
            return base.withReason("0 rules removed; enforcement already withdrawn until the next start", .{});
        }
        const before = manager.residualInstalled();
        const installed = before.installed orelse return base.withOutcome(.rejected).withReason("firewall readback failed: {s}; no rules removed", .{@errorName(before.cause.?)});
        const healthy = self.gate.snapshot().phase == .healthy and self.store_open and !self.store.reopen_required;
        if (healthy and !manager.stopping) {
            var bindings: [max_jails]effect_runtime.Binding = undefined;
            self.effectBindings(&bindings);
            var settle: usize = 0;
            while (settle < 64) : (settle += 1) {
                if (manager.status.ready and manager.cached_epoch != null and manager.cached_epoch.? == self.store.effect_publication_epoch) break;
                switch (manager.runSlice(bindings[0..self.jails.len], .{}, null).outcome) {
                    .fatal => |err| return base.withOutcome(.rejected).withReason("firewall reconciliation failed: {s}; no rules removed", .{@errorName(err)}),
                    .progress, .wait, .idle, .stop => {},
                }
            }
        }
        const epoch = manager.repair_epoch;
        var cause: ?anyerror = error.WithdrawalBoundReached;
        var turns: usize = 0;
        while (turns <= effect.max_effects) : (turns += 1) {
            if (stopRequested(self)) {
                cause = error.StopRequested;
                break;
            }
            switch (manager.withdrawStep(epoch)) {
                .idle => {
                    cause = null;
                    break;
                },
                .fatal => |err| {
                    cause = err;
                    break;
                },
                .progress, .wait, .stop => {},
            }
        }
        if (manager.withdrawn) self.withdrawn_warned_ms = monotonic(self);
        const failure = cause orelse {
            std.log.info("native: firewall withdraw removed {d} realized rules in {d} turns; enforcement withdrawn until the next start; owners and deadlines retained", .{ installed, turns });
            return base.withReason("{d} rules removed; enforcement withdrawn until the next start", .{installed});
        };
        if (!manager.withdrawn) return base.withOutcome(.rejected).withReason("{s}; no rules removed", .{@errorName(failure)});
        const after = manager.residualInstalled();
        const remaining = after.installed orelse {
            std.log.warn("native: firewall withdraw stopped by {s}; remaining rules unreadable: {s}; enforcement withdrawn until the next start", .{ @errorName(failure), @errorName(after.cause.?) });
            return base.withOutcome(.uncertain).withReason("{s}; remaining rules unreadable: {s}", .{ @errorName(failure), @errorName(after.cause.?) });
        };
        const outcome: durable.Store.AdminOutcome = if (failure == error.WithdrawalBoundReached or failure == error.StopRequested or effect_runtime.transientCause(failure)) .partial else .uncertain;
        std.log.warn("native: firewall withdraw removed {d} of {d} realized rules: {s}; enforcement withdrawn until the next start", .{ installed -| remaining, installed, @errorName(failure) });
        return base.withOutcome(outcome).withReason("{d} of {d} rules removed: {s}; run firewall withdraw again", .{ installed -| remaining, installed, @errorName(failure) });
    }
    const withdrawn_warn_interval_ms: u64 = 60 * 60 * 1000;
    fn warnWithdrawn(self: *Coordinator, manager: *effect_runtime.Manager) void {
        const now = monotonic(self);
        if (self.withdrawn_warned_ms) |last| if (now -| last < withdrawn_warn_interval_ms) return;
        self.withdrawn_warned_ms = now;
        std.log.warn("native: enforcement withdrawn by firewall withdraw; {d} realized rules in the kernel; restart fail2zig to reinstall live bans", .{manager.installed_live});
    }
    fn stopRequested(ctx: ?*anyopaque) bool {
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
    fn wallClockEffect(ctx: ?*anyopaque) i64 {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        return self.clock.wallUs();
    }
    fn settleAdmin(self: *Coordinator, request: *AdminRequest) void {
        if (request.ignore) |ignore_state| if (ignore_state.lifting) return self.settleIgnoreLifts(request, ignore_state);
        const manager = self.effects orelse {
            const view = if (request.run_id != null) (AdminOutcomeView{ .outcome = .uncertain, .kind = request.kind, .destination = "uncertain" }).withReason("no enforcement backend to verify activation", .{}) else AdminOutcomeView{ .outcome = .applied, .kind = request.kind };
            if (request.run_id != null) self.finishMigrationVerify(request, view);
            self.completeAdmin(request, self.adminDetail(request, view, request.pending_state));
            return;
        };
        if (request.run_id != null) {
            const view = self.settleMigration(request, manager) orelse return;
            self.finishMigrationVerify(request, view);
            self.completeAdmin(request, self.adminDetail(request, view, null));
            return;
        }
        var view = AdminOutcomeView{ .outcome = .partial, .kind = request.kind, .enforced = false };
        var settled = false;
        const readback = adminReadback(manager.status, manager.cached_epoch, self.store.effect_publication_epoch);
        if (readback == .uncertain) {
            view.outcome = .uncertain;
            view = view.withReason("effect outcome uncertain: {s}", .{if (manager.status.cause) |cause| @errorName(cause) else "unknown"});
            settled = true;
        } else if (readback == .coherent) {
            if (std.mem.allEqual(u8, &request.scope_key, 0)) {
                view.outcome = .applied;
                settled = true;
            } else {
                var found: ?effect.Entry = null;
                for (manager.live[0..manager.count]) |entry| if (std.mem.eql(u8, &entry.scope_key, &request.scope_key)) {
                    found = entry;
                };
                const now = self.clock.wallUs();
                if (request.expect_absent) {
                    if (found == null or found.?.status == .absent or found.?.status == .expired or !found.?.desired.live(now)) {
                        view.outcome = .applied;
                        settled = true;
                    }
                } else if (found) |entry| if (entry.status == .applied and entry.desired.live(now)) {
                    view.outcome = .applied;
                    view.enforced = true;
                    settled = true;
                };
            }
        }
        if (!settled and monotonic(self) < request.deadline_ms) return;
        if (!settled) view = view.withReason("intent committed; kernel confirmation not observed within the deadline", .{});
        self.completeAdmin(request, self.adminDetail(request, view, request.pending_state));
    }
    fn wallClock(ctx: ?*anyopaque) !i64 {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        return self.clock.wallUs();
    }
    fn observationMs() ?u64 {
        const sample = std.posix.clock_gettime(.MONOTONIC) catch return null;
        if (sample.sec < 0 or sample.nsec < 0 or sample.nsec >= std.time.ns_per_s) return null;
        return std.math.cast(u64, @as(i128, sample.sec) * 1000 + @divTrunc(sample.nsec, std.time.ns_per_ms));
    }
    fn observationWall(self: *Coordinator) ?i64 {
        return self.clock.wallUs();
    }
    fn observedWorker(self: *Coordinator) health.WorkerStatus {
        return self.worker_observation.read(observationMs(), self.observationWall());
    }
    fn observationSound(observation: health.WorkerStatus) bool {
        return !observation.stalled and !observation.clock_uncertain;
    }
    fn overBlocking(self: *const Coordinator) bool {
        return self.published_view.overdue_blocking != 0;
    }
    fn bindEffectInvalidation(self: *Coordinator) void {
        self.store.effect_invalidation = .{ .context = self, .invalidate = invalidateEffectPublication };
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
        const descriptors = try resource.FdContext.observe(cfg.global.native_fd_ceiling, 32);
        var plan: resource.Plan = .{};
        try plan.include(resource.storeWorkspace());
        try plan.include(try resource.controlCost(cfg.global.metrics_enabled, 2 * shared.protocol.max_payload_size));
        try plan.include(.{ .live = .{ .bytes = try std.math.add(usize, cfg.retained_capacity, 16 * resource.mib), .allocations = 2, .fds = 2 } });
        var custom: usize = 0;
        var internal_count: usize = 0;
        var enforcing = false;
        var index: usize = 0;
        for (cfg.jails) |jail| {
            if (!jail.enabled) continue;
            var source = if (jail.source == .auto) cfg.defaults.source else jail.source;
            if (source == .auto) source = if (config.anyLogpathExists(jail.logpath)) .file else if (config.filterSupportsJournald(jail.filter) and config.journalctlPresent()) .journald else .file;
            if (source == .internal) {
                internal_count += 1;
                if (internal_count > 1 or !config.filterSupportsInternal(jail.filter) or jail.logpath.len != 0 or jail.journal_executables.len != 0 or jail.rule_files.len != 0) return error.NativeInternalEventsRequired;
            } else if (config.filterSupportsInternal(jail.filter)) return error.NativeInternalEventsRequired;
            selected[index] = source;
            index += 1;
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
            try plan.include(.{ .live = .{ .bytes = projection_bytes, .allocations = 4 }, .workspace = .{ .bytes = 65536, .allocations = 16, .fds = 2 }, .workspace_kind = .configuration });
            if (jail.timezone != null) try plan.include(try resource.timezoneCost(1));
            if (jail.rule_files.len != 0) {
                custom += 1;
                const prepared = try consumer_plan.reservationBytes(jail.rule_files.len);
                try plan.include(.{ .live = .{ .bytes = prepared, .allocations = 32 }, .workspace = .{ .bytes = prepared, .allocations = 32, .fds = 1 }, .workspace_kind = .configuration });
                try plan.include(try resource.consumerCost(try consumer_runtime.JailRuntime.capacityPlan(jail.rule_files.len, capacity), 64 + capacity * (8 + jail.rule_files.len * 2)));
            }
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
        if (requested_enforcing) {
            namespace_lock = try std.fs.openFileAbsolute(cfg.global.firewall_namespace, .{});
            const current = try std.fs.openFileAbsolute("/proc/self/ns/net", .{});
            defer current.close();
            const selected = try std.posix.fstat(namespace_lock.?.handle);
            const active = try std.posix.fstat(current.handle);
            if (selected.dev != active.dev or selected.ino != active.ino) return error.FirewallNamespaceMismatch;
            if (!try namespace_lock.?.tryLock(.exclusive)) return error.NativeNamespaceAlreadyRunning;
        }
        var authority_lock = path_guard.lockStateIfPresent(cfg.global.state_file) catch |err| {
            std.log.err("native: state authority admission failed: {s}; path='{'}'{s}", .{ @errorName(err), std.zig.fmtEscapes(cfg.global.state_file[0..@min(cfg.global.state_file.len, 256)]), if (cfg.global.state_file.len > 256) " [path truncated]" else "" });
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
        }, .preflight_schema_version = snapshot.schema_version, .preflight_installation = snapshot.installation, .suppress_enforcement = requested_enforcing and !runtime_enforcing, .authority_lock = authority_lock, .namespace_lock = namespace_lock, .start_us = start_us, .resources = resource.Ledger.init(requirements) };
        self.startup_progress = progress;
        authority_lock = null;
        namespace_lock = null;
        errdefer if (self.namespace_lock) |file| file.close();
        errdefer if (self.authority_lock) |file| file.close();
        self.worker_observation = health.WorkerObservation.init(observationMs(), self.observationWall());
        self.resource_reservation = try self.resources.reserve(.other, requirements.cost);
        errdefer self.releaseResources();
        self.decision_scratch = try a.alloc(durable.Store.ActiveDecision, retry.max_pool_subjects);
        errdefer a.free(self.decision_scratch);
        self.decision_scratch_confirmed = try a.alloc(bool, retry.max_pool_subjects);
        errdefer a.free(self.decision_scratch_confirmed);
        self.decision_scratch_keys = try a.alloc(?[32]u8, retry.max_pool_subjects);
        errdefer a.free(self.decision_scratch_keys);
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
        self.jails = try a.alloc(Jail, count);
        errdefer a.free(self.jails);
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
            const policy = try retry_config.fromJail(jail_cfg, cfg.defaults, retry.max_pool_subjects);
            var selected = jail_cfg.*;
            selected.source = selected_sources[prepared];
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
            self.jails[prepared] = .{ .name = selected.name, .plan = plan, .policy = policy, .zone = zone, .custom_plan = assets, .on_truncation = config.resolveJailFromConfig(jail_cfg, cfg.defaults).on_truncation };
            if (assets != null) self.custom_jails += 1;
            prepared += 1;
        }
        if (self.authority_lock == null) self.authority_lock = path_guard.lockAbsentState(cfg.global.state_file) catch |err| {
            std.log.err("native: state authority admission failed: {s}; path='{'}'{s}", .{ @errorName(err), std.zig.fmtEscapes(cfg.global.state_file[0..@min(cfg.global.state_file.len, 256)]), if (cfg.global.state_file.len > 256) " [path truncated]" else "" });
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
            if (self.clock.origin == .floor) if (try self.store.admissionClock()) |floor| {
                self.start_us = self.clock.raiseOriginTo(floor.us);
            };
            std.log.info("diag clock: mode={s} rate={d} origin={d}", .{ @tagName(self.clock.mode()), self.clock.rate(), self.start_us });
        }
        try self.verifyStateIdentity();
        try self.validatePreflightInstallation();
        try self.admitStore();
        var validation_turns: u64 = 0;
        self.reportStartup(.maintenance, "maintenance validation", 0, 0);
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
        errdefer if (self.effects) |manager| manager.destroy();
        errdefer self.destroyRuntime();
        try self.store.beginStartupAdmission();
        errdefer self.store.abortStartupAdmission();
        try self.validateAdmission();
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
        try self.store.finishStartupAdmission();
        self.publishHealth();
        return self;
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
    fn admitStore(self: *Coordinator) !void {
        self.store.runtime_path = self.cfg.global.state_file;
        try self.store.configureRuntimeLimits();
        try self.store.enableLoadRepair(self.loadRepairOptions(), if (self.startup_progress) |progress| progress.migrationHook() else null);
        try self.store.enableReceipts(self.jails.len * max_sources_per_jail);
        try self.store.enableNativeTime();
        try self.store.enableDetection();
        try self.store.enableClockRecovery();
        try self.store.enableJournalDetection();
        try self.store.enableRetry();
        try self.store.enableConsumers();
        try self.store.enableTimeProvenance();
        try self.store.enableConsumerManifests();
        try self.store.enableConfirmedHistory();
        try self.store.enableMaintenance();
        try self.store.enableCleanup();
        try self.store.enableRetryLeases();
        try self.store.enableApplicationHistory();
        try self.store.enableEscalation();
        try self.store.enableCanonicalEffects();
        try self.store.enableHistoryResets();
        try self.store.enableActionTargets();
        try self.store.enableAdminState();
        try self.store.enableMigrationState();
        try self.store.enableLoadRepair(self.loadRepairOptions(), if (self.startup_progress) |progress| progress.migrationHook() else null);
        try self.store.enableRuntimeState(self.loadRepairOptions(), !self.store.load_repair_migrated);
        _ = try self.store.setRetentionPolicy(self.cfg.global.history_max_matches);
        try self.rekeySavedGenerations();
        try self.completeGenerationRekeys();
        try self.rebuildIgnoreLists();
        try self.validateAdmission();
        if (!self.generation_admitted) {
            try self.admitConfigGeneration();
            self.generation_admitted = true;
        }
        self.published_revision = try self.store.adminRevision();
        for (self.jails) |*jail| {
            var state: durable.Store.JailAdminState = undefined;
            if (try self.store.jailAdminState(jail.name, &state)) {
                jail.admin_paused = state.paused;
                jail.admin_enabled = state.enabled;
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
            const repair = try self.store.completeGenerationRekey(jail.name);
            if (repair.receipts == 0 and repair.retired == 0 and repair.cursors == 0 and repair.guards == 0) continue;
            std.log.info("native storage: generation rekey completed: jail={} receipts={d} retired={d} cursors={d} guards={d}; left by an earlier policy reload; no ban, deadline, checkpoint position or record changed", .{ std.zig.fmtEscapes(jail.name), repair.receipts, repair.retired, repair.cursors, repair.guards });
        }
    }
    fn ignoreCell(jail: *const Jail) ?**ignore_set.EffectiveIgnore {
        return switch (jail.plan) {
            .file => |plan| plan.ignore_cell,
            .journal => |plan| plan.ignore_cell,
            .internal => null,
        };
    }
    fn effectiveIgnore(self: *Coordinator, cfg: *const config.Config, jail: *const Jail) !*ignore_set.EffectiveIgnore {
        var runtime: [ignore_set.max_entries_per_part]shared.types.IgnoreEntry = undefined;
        const count = try self.store.ignoreEntries(jail.name, &runtime);
        const literals = if (findConfigJail(cfg, jail.name)) |jail_cfg| jail_cfg.ignoreip orelse cfg.defaults.ignoreip else &[_][]const u8{};
        return ignore_set.EffectiveIgnore.build(self.allocator, literals, runtime[0..count]);
    }
    fn replaceIgnoreList(self: *Coordinator, jail: *Jail, next: *ignore_set.EffectiveIgnore) void {
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
    fn rebuildIgnoreLists(self: *Coordinator) !void {
        for (self.jails) |*jail| {
            if (ignoreCell(jail) == null) continue;
            const next = try self.effectiveIgnore(self.live_cfg, jail);
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
        if (self.store.schema_version != @max(self.preflight_schema_version, 2)) return error.NativeStateChanged;
        if (self.preflight_schema_version < 11) return;
        const current = try self.store.readInstallation();
        if (!std.meta.eql(current, self.preflight_installation)) return error.InstallationMismatch;
    }
    fn admitConfigGeneration(self: *Coordinator) !void {
        const digest = try self.configDigest();
        if (try self.store.latestConfigGeneration()) |head| {
            if (head.published and std.mem.eql(u8, &head.config_digest, &digest)) {
                self.published_generation = head.generation;
                self.published_config_digest = digest;
                return;
            }
            if (!head.published) return error.ConfigGenerationUnpublished;
        }
        const now = self.clock.wallUs();
        const generation = reload_mod.generationId(digest, now);
        var jails: [max_jails]durable.Store.ConfigGenerationJail = undefined;
        for (self.jails, 0..) |*jail, i| jails[i] = .{ .jail = jail.name, .digest = try reload_mod.jailDigest(jail.name, jail.policy, try self.plannedGeneration(jail, .planned)), .allowlist_snapshot = if (jail.custom_plan) |assets| assets.initial_ignore.payload else "" };
        try self.store.recordConfigGeneration(.{ .generation = generation, .config_digest = digest, .config_path = self.config_path, .committed_us = now, .published = true, .mutation_revision = try self.store.adminRevision() }, jails[0..self.jails.len]);
        self.published_generation = generation;
        self.published_config_digest = digest;
    }
    fn configDigest(self: *Coordinator) ![32]u8 {
        if (self.config_path.len == 0) return error.ConfigPathRequired;
        const bytes = try std.fs.cwd().readFileAlloc(self.allocator, self.config_path, 16 * 1024 * 1024);
        defer self.allocator.free(bytes);
        return reload_mod.digestBytes(bytes);
    }

    pub fn stageReload(self: *Coordinator, wait_ms: u64) ReloadOutcome {
        const arena = self.allocator.create(std.heap.ArenaAllocator) catch return ReloadOutcome.single(.rejected, "out of memory", .{});
        arena.* = std.heap.ArenaAllocator.init(self.allocator);
        var keep_arena = false;
        defer if (!keep_arena) {
            arena.deinit();
            self.allocator.destroy(arena);
        };
        var diag: config.Diagnostic = .{};
        const file = std.fs.cwd().openFile(self.config_path, .{}) catch |err| return ReloadOutcome.single(.rejected, "config: open: {s}", .{@errorName(err)});
        defer file.close();
        const stat = std.posix.fstat(file.handle) catch |err| return ReloadOutcome.single(.rejected, "config: stat: {s}", .{@errorName(err)});
        config.Config.checkConfigPerms(stat.mode, stat.gid) catch |err| return ReloadOutcome.single(.rejected, "config: {s}", .{@errorName(err)});
        const bytes = file.readToEndAlloc(arena.allocator(), 16 * 1024 * 1024) catch |err| return ReloadOutcome.single(.rejected, "config: read: {s}", .{@errorName(err)});
        const proposed = arena.allocator().create(config.Config) catch return ReloadOutcome.single(.rejected, "out of memory", .{});
        proposed.* = config.Config.parseDiag(arena.allocator(), bytes, &diag) catch |err| return ReloadOutcome.single(.rejected, "config: {s}:{d}:{d}: {s}", .{ self.config_path, diag.line, diag.col, @errorName(err) });
        var validation_diag: config.ValidationDiagnostic = .{};
        config.validateDiag(proposed, &validation_diag) catch |err| {
            var out = ReloadOutcome.single(.rejected, "config: validation failed: {s}", .{@errorName(err)});
            const detail = validation_diag.render(&out.reasons[1].bytes);
            out.reasons[1].len = @intCast(detail.len);
            out.reason_count = 2;
            return out;
        };
        const digest = reload_mod.digestBytes(bytes);
        const classified = self.inspectPublicationLocked(ReloadClassificationInput{ .proposed = proposed }, classifyReloadLocked);
        const current_generation = classified.generation;
        const classification = classified.classification;
        var out = ReloadOutcome{ .kind = switch (classification.kind) {
            .noop => .noop,
            .live => .applied,
            .restart_required => .restart_required,
            .rejected => .rejected,
        }, .generation = current_generation, .reasons = classification.reasons, .reason_count = classification.reason_count };
        if (classification.kind != .live and !(classification.kind == .noop and self.hasAllowlistFiles())) return out;
        const request = self.allocator.create(ReloadRequest) catch return ReloadOutcome.single(.rejected, "out of memory", .{});
        request.* = .{ .classification = classification, .config_digest = digest, .proposed = proposed, .arena = arena };
        keep_arena = true;
        self.mutex.lock();
        if (self.reload_request != null) {
            self.mutex.unlock();
            self.freeRequest(request);
            return ReloadOutcome.single(.rejected, "reload already in progress", .{});
        }
        self.reload_request = request;
        var timer = std.time.Timer.start() catch null;
        while (!request.done) {
            const elapsed_ms: u64 = if (timer) |*t| t.read() / std.time.ns_per_ms else wait_ms;
            if (elapsed_ms >= wait_ms) break;
            self.reload_wake.timedWait(&self.mutex, (wait_ms - elapsed_ms) * std.time.ns_per_ms) catch {};
        }
        if (!request.done) {
            if (self.reload_request == request) {
                self.reload_request = null;
                self.mutex.unlock();
                self.freeRequest(request);
                return ReloadOutcome.single(.rejected, "worker did not accept the reload within {d} ms; no state was changed", .{wait_ms});
            }
            request.abandoned = true;
            self.mutex.unlock();
            return ReloadOutcome.single(.uncertain, "worker is still applying the reload; inspect status generation", .{});
        }
        out = request.outcome.?;
        self.mutex.unlock();
        self.freeRequest(request);
        return out;
    }
    fn freeRequest(self: *Coordinator, request: *ReloadRequest) void {
        if (request.arena) |arena| {
            arena.deinit();
            self.allocator.destroy(arena);
        }
        self.allocator.destroy(request);
    }
    fn applyReload(self: *Coordinator, request: *ReloadRequest) void {
        const diag_span = if (comptime build_options.diag) diag_mod.enter(.reload) else {};
        defer if (comptime build_options.diag) diag_mod.leave(diag_span);
        const outcome = self.applyReloadInner(request) catch |err| ReloadOutcome.single(.rejected, "reload failed before publication: {s}; current generation retained", .{@errorName(err)});
        self.mutex.lock();
        request.outcome = outcome;
        request.done = true;
        const abandoned = request.abandoned;
        self.reload_wake.broadcast();
        self.mutex.unlock();
        if (abandoned) self.freeRequest(request);
        std.log.info("native reload: outcome={s}", .{@tagName(outcome.kind)});
    }
    fn jailEnforces(self: *const Coordinator, jail: *const Jail) bool {
        return jail.policy.enforce and !self.suppress_enforcement;
    }
    fn applyReloadInner(self: *Coordinator, request: *ReloadRequest) !ReloadOutcome {
        try self.gate.admitMutation();
        if (self.notifier) |notifier| _ = notifier.reloading() catch {};
        defer if (self.notifier) |notifier| {
            notifyReloadReady(self.readinessReport(), notifier);
        };
        const now = self.clock.wallUs();
        const generation = reload_mod.generationId(request.config_digest, now);
        var transitions: [max_jails]durable.Store.PolicyTransition = undefined;
        var digests: [max_jails]durable.Store.ConfigGenerationJail = undefined;
        var count: usize = 0;
        for (request.classification.policySlice()) |change| {
            const jail = self.findJail(change.jail) orelse return error.UnknownJail;
            const current_generation = try self.plannedGeneration(jail, .planned);
            const previous = jail.policy;
            const next_policy = change.next;
            jail.policy = next_policy;
            const next_generation = self.plannedGeneration(jail, .planned) catch |err| {
                jail.policy = previous;
                return err;
            };
            jail.policy = previous;
            const rebinding: ?durable.Store.CursorRebinding = switch (jail.plan) {
                .file => |*plan| blk: {
                    const processing = plan.sessionOptions().processing;
                    break :blk .{ .old = @import("core/durable_file_source.zig").FileSource.framingBinding(processing.encoding, current_generation, processing.max_record_bytes), .new = @import("core/durable_file_source.zig").FileSource.framingBinding(processing.encoding, next_generation, processing.max_record_bytes) };
                },
                else => null,
            };
            transitions[count] = .{ .jail = jail.name, .generation = current_generation, .next_generation = next_generation, .expected = previous, .next = next_policy, .cursor_rebinding = rebinding };
            count += 1;
        }
        for (self.jails, 0..) |*jail, i| {
            var next = jail.policy;
            for (transitions[0..count]) |change| if (std.mem.eql(u8, change.jail, jail.name)) {
                next = change.next;
            };
            digests[i] = .{ .jail = jail.name, .digest = try reload_mod.jailDigest(jail.name, next, try self.plannedGeneration(jail, .planned)), .allowlist_snapshot = if (jail.custom_plan) |assets| assets.initial_ignore.payload else "" };
        }
        var outcome = ReloadOutcome{ .kind = .applied, .generation = generation };
        var refreshed: usize = 0;
        for (self.jails) |*jail| {
            const consumer = jail.consumer orelse continue;
            const path = self.ignoreFilePath(jail.name) orelse continue;
            const result = consumer.refreshAllowlist(path, now) catch |err| {
                if (outcome.reason_count < reload_mod.max_reasons) {
                    var reason: reload_mod.Reason = .{};
                    const written = std.fmt.bufPrint(&reason.bytes, "jails.{s}: allowlist retained: {s}", .{ jail.name, @errorName(err) }) catch reason.bytes[0..0];
                    reason.len = @intCast(written.len);
                    outcome.reasons[outcome.reason_count] = reason;
                    outcome.reason_count += 1;
                }
                continue;
            };
            if (result == .applied) refreshed += 1;
        }
        var next_lists: [max_jails]?*ignore_set.EffectiveIgnore = [_]?*ignore_set.EffectiveIgnore{null} ** max_jails;
        defer for (next_lists) |pending| if (pending) |list| list.deinit(self.allocator);
        var ignore_changes: usize = 0;
        for (self.jails, 0..) |*jail, i| {
            if (ignoreCell(jail) == null) continue;
            for (request.classification.ignoreSlice()) |name| if (std.mem.eql(u8, name, jail.name)) {
                next_lists[i] = try self.effectiveIgnore(request.proposed, jail);
                ignore_changes += 1;
                break;
            };
        }
        if (count == 0 and refreshed == 0 and ignore_changes == 0) {
            outcome.kind = .noop;
            outcome.generation = self.published_generation;
            return outcome;
        }
        for (self.jails, 0..) |*jail, i| if (jail.consumer) |consumer| {
            digests[i].allowlist_snapshot = consumer.ignores.live.payload;
        };
        self.store.commitReloadGeneration(transitions[0..count], .{ .generation = generation, .config_digest = request.config_digest, .config_path = self.config_path, .committed_us = now, .published = true, .mutation_revision = 0 }, digests[0..self.jails.len], .{ .prepared_us = now, .context = self, .read = wallClockEffect }) catch |err| {
            if (refreshed != 0) return ReloadOutcome.single(.partial, "allowlists refreshed but the policy generation was not committed: {s}", .{@errorName(err)});
            return err;
        };
        const committed_revision = self.store.adminRevision();
        self.mutex.lock();
        if (committed_revision) |revision| self.published_revision = revision else |_| {}
        for (transitions[0..count]) |change| if (self.findJail(change.jail)) |jail| {
            jail.policy = change.next;
            jail.rekeyed = !std.mem.eql(u8, &change.generation, &change.next_generation);
            jail.retry_revision = null;
        };
        if (count != 0) self.owner_read_epoch = null;
        if (request.classification.log_level) |level| log_level.set(std.meta.stringToEnum(std.log.Level, @tagName(level)) orelse .info);
        self.replaceLiveConfigLocked(request.arena, request.proposed);
        request.arena = null;
        self.published_generation = generation;
        self.published_config_digest = request.config_digest;
        self.mutex.unlock();
        for (self.jails, 0..) |*jail, i| if (next_lists[i]) |list| {
            next_lists[i] = null;
            self.replaceIgnoreList(jail, list);
        };
        if (count != 0) self.gate.requestRebuild() catch {};
        if (committed_revision) |_| {} else |err| {
            outcome.kind = .partial;
            if (outcome.reason_count < reload_mod.max_reasons) {
                var reason: reload_mod.Reason = .{};
                const written = std.fmt.bufPrint(&reason.bytes, "generation applied but the mutation revision was not read back: {s}; restart fail2zig before changing bans", .{@errorName(err)}) catch reason.bytes[0..0];
                reason.len = @intCast(written.len);
                outcome.reasons[outcome.reason_count] = reason;
                outcome.reason_count += 1;
            }
        }
        return outcome;
    }
    fn hasAllowlistFiles(self: *Coordinator) bool {
        for (self.jails) |*jail| if (jail.custom_plan != null and self.ignoreFilePath(jail.name) != null) return true;
        return false;
    }
    fn inspectPublicationLocked(self: *Coordinator, context: anytype, comptime inspect: anytype) @typeInfo(@TypeOf(inspect)).@"fn".return_type.? {
        self.mutex.lock();
        defer self.mutex.unlock();
        return inspect(self, context);
    }
    const ReloadClassificationInput = struct { proposed: *const config.Config };
    const ReloadClassificationSnapshot = struct {
        generation: [32]u8,
        classification: reload_mod.Classification,
    };
    fn classifyReloadLocked(self: *Coordinator, input: ReloadClassificationInput) ReloadClassificationSnapshot {
        var counts: [max_jails]reload_mod.RuntimeCount = undefined;
        for (self.jails, 0..) |jail, i| counts[i] = .{ .jail = jail.name, .runtime_only = jail.ignore_runtime_only };
        return .{ .generation = self.published_generation, .classification = reload_mod.classifyWithRuntime(self.live_cfg, input.proposed, retry.max_pool_subjects, counts[0..self.jails.len]) };
    }
    fn replaceLiveConfigLocked(self: *Coordinator, arena: ?*std.heap.ArenaAllocator, proposed: *const config.Config) void {
        if (self.live_arena) |old| {
            old.deinit();
            self.allocator.destroy(old);
        }
        self.live_arena = arena;
        self.live_cfg = proposed;
    }
    fn ignoreFilePath(self: *Coordinator, name: []const u8) ?[]const u8 {
        for (self.live_cfg.jails) |*jail| if (std.mem.eql(u8, jail.name, name)) return jail.ignore_file;
        return null;
    }
    fn findJail(self: *Coordinator, name: []const u8) ?*Jail {
        for (self.jails) |*jail| if (std.mem.eql(u8, jail.name, name)) return jail;
        return null;
    }
    const AdminBody = struct {
        schema_version: u32,
        kind: []const u8,
        jail: ?[]const u8 = null,
        address: ?[]const u8 = null,
        prefix: ?u8 = null,
        duration_s: ?u64 = null,
        all: bool = false,
        unban: ?bool = null,
        run_id: ?[]const u8 = null,
        expected_generation: []const u8,
        expected_mutation_revision: u64,
    };
    fn adminResponse(self: *Coordinator, out: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator, frame: shared.Command.Request) !shared.Response {
        const parsed = std.json.parseFromSlice(AdminBody, a, frame.body.slice(), .{ .ignore_unknown_fields = false }) catch {
            return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "malformed admin_v1 request") } };
        };
        defer parsed.deinit();
        const body = parsed.value;
        if (body.schema_version != 1) return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "unsupported schema_version") } };
        const kind = std.meta.stringToEnum(durable.Store.AdminKind, body.kind) orelse return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "unknown admin kind") } };
        if (body.unban != null and kind != .ignore_add) return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "unban is valid only with ignore_add") } };
        if (body.expected_generation.len != 64) return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "expected_generation must be 64 hex characters") } };
        const request = try self.allocator.create(AdminRequest);
        var destroy_on_exit = true;
        defer if (destroy_on_exit) self.freeAdminRequest(request);
        request.* = .{ .request_id = frame.request_id, .kind = kind, .expected_generation = undefined, .expected_revision = body.expected_mutation_revision };
        _ = std.fmt.hexToBytes(&request.expected_generation, body.expected_generation) catch return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "expected_generation is not hex") } };
        if (body.jail) |jail| {
            if (jail.len == 0 or jail.len > 64) return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "jail name length") } };
            @memcpy(request.jail[0..jail.len], jail);
            request.jail_len = @intCast(jail.len);
        }
        if (body.address) |text| request.address = shared.IpAddress.parse(text) catch return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "invalid address") } };
        request.prefix = body.prefix;
        request.duration_s = body.duration_s;
        request.all = body.all;
        request.unban = body.unban orelse false;
        if (body.run_id) |text| {
            if (text.len != 64) return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "run_id must be 64 hex characters") } };
            var run_id: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&run_id, text) catch return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "run_id is not hex") } };
            request.run_id = run_id;
        }
        if ((kind == .migration_activate or kind == .migration_rollback) and request.run_id == null) return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "run_id is required") } };
        const needs_jail = switch (kind) {
            .history_reset => !body.all,
            .setting_batch, .migration_activate, .migration_rollback, .firewall_withdraw => false,
            else => true,
        };
        if (needs_jail and request.jail_len == 0) return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "jail is required") } };
        if ((kind == .ban or kind == .unban or kind == .history_reset or kind == .ignore_add or kind == .ignore_remove) and request.address == null) return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "address is required") } };
        if (request.prefix) |prefix| {
            const address = request.address orelse return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "address is required") } };
            const max: u8 = if (address == .ipv4) 32 else 128;
            const ignore_kind = kind == .ignore_add or kind == .ignore_remove;
            if ((prefix == 0 and !ignore_kind) or prefix > max) return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "invalid prefix") } };
        }
        if (kind == .ignore_add or kind == .ignore_remove) {
            var text: [shared.types.IgnoreEntry.max_text_bytes]u8 = undefined;
            const printed = (if (request.prefix) |prefix|
                std.fmt.bufPrint(&text, "{}/{d}", .{ request.address.?, prefix })
            else
                std.fmt.bufPrint(&text, "{}", .{request.address.?})) catch return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "invalid address") } };
            request.ignore_entry = shared.types.IgnoreEntry.parse(printed) catch |failure| return .{ .err = .{ .code = 400, .message = try a.dupe(u8, if (failure == error.InvalidPrefix) "invalid prefix" else "invalid address") } };
        }
        const wait_ms: u64 = if (kind == .migration_activate or kind == .migration_rollback or kind == .firewall_withdraw) 10_000 else if (request.unban) ignore_unban_wait_ms else 3000;
        const staged = self.stageAdmin(request, wait_ms);
        destroy_on_exit = staged.owned;
        const view = staged.view;
        const w = out.writer(a);
        try w.print("{{\"schema_version\":1,\"kind\":\"{s}\",\"outcome\":\"{s}\",\"generation\":\"{s}\",\"mutation_revision\":{d},\"enforced\":{},\"reasons\":[", .{ @tagName(view.kind), @tagName(view.outcome), &std.fmt.bytesToHex(view.generation, .lower), view.mutation_revision, view.enforced });
        const ignore_state: ?*const IgnoreWork = if (staged.owned) request.ignore else null;
        var wrote_reason = false;
        if (view.reason.len != 0) {
            try std.json.encodeJsonString(view.reason.slice(), .{}, w);
            wrote_reason = true;
        }
        if (ignore_state) |value| if (request.unban) for (value.bans[0..value.ban_count]) |ban| if (ban.lift == .refused) {
            var scope_buffer: [64]u8 = undefined;
            var line_buffer: [240]u8 = undefined;
            const line = std.fmt.bufPrint(&line_buffer, "{s}: {s}", .{ try formatListSubject(ban.canonical.subject, &scope_buffer), ban.reason orelse "not lifted" }) catch line_buffer[0..0];
            if (wrote_reason) try w.writeByte(',');
            try std.json.encodeJsonString(line, .{}, w);
            wrote_reason = true;
        };
        try w.writeAll("]");
        if (kind == .ignore_add or kind == .ignore_remove) try writeIgnoreFields(w, request, ignore_state);
        if (kind == .migration_activate or kind == .migration_rollback) try w.print(",\"observed_protection\":{{\"destination\":\"{s}\",\"source\":\"unknown\"}}", .{view.destination orelse "unknown"});
        try w.writeAll("}");
        return switch (view.outcome) {
            .applied => .{ .ok = .{ .payload = try out.toOwnedSlice(a) } },
            .rejected => .{ .err = .{ .code = 409, .message = try out.toOwnedSlice(a) } },
            .absent => .{ .err = .{ .code = 404, .message = try out.toOwnedSlice(a) } },
            .partial => .{ .err = .{ .code = 507, .message = try out.toOwnedSlice(a) } },
            .uncertain => .{ .err = .{ .code = 508, .message = try out.toOwnedSlice(a) } },
        };
    }
    fn ignoreSourceText(source: ?ignore_set.Source) ?[]const u8 {
        return switch (source orelse return null) {
            .config => "config",
            .runtime => "runtime",
            .both => "config+runtime",
        };
    }
    fn writeIgnoreEntries(w: anytype, entries: []const shared.types.IgnoreEntry) !void {
        try w.writeAll("[");
        for (entries, 0..) |item, i| {
            if (i > 0) try w.writeByte(',');
            var buffer: [64]u8 = undefined;
            try std.json.encodeJsonString(item.canonical(&buffer), .{}, w);
        }
        try w.writeAll("]");
    }
    fn writeIgnoreFields(w: anytype, request: *const AdminRequest, ignore_state: ?*const IgnoreWork) !void {
        const add = request.kind == .ignore_add;
        var buffer: [64]u8 = undefined;
        try w.writeAll(",\"jail\":");
        try std.json.encodeJsonString(request.jailName(), .{}, w);
        try w.writeAll(",\"address\":");
        try std.json.encodeJsonString(request.ignore_entry.?.canonical(&buffer), .{}, w);
        const state: IgnoreEntryState = if (ignore_state) |value| value.entry_state else .not_recorded;
        const reported = if (!add and state == .not_recorded) IgnoreEntryState.not_removed else state;
        try w.print(",\"entry\":\"{s}\",\"source\":", .{@tagName(reported)});
        if (ignoreSourceText(if (ignore_state) |value| value.source else null)) |text| try std.json.encodeJsonString(text, .{}, w) else try w.writeAll("null");
        try w.writeAll(if (add) ",\"covered_by\":" else ",\"still_ignored_by\":");
        try writeIgnoreEntries(w, if (ignore_state) |value| value.configured[0..value.configured_count] else &.{});
        if (!add) return;
        try w.print(",\"unban_requested\":{},\"bans_total\":{d},\"bans\":[", .{ request.unban, if (ignore_state) |value| value.bans_total else 0 });
        if (ignore_state) |value| for (value.bans[0..@min(value.ban_count, max_listed_bans)], 0..) |ban, i| {
            var scope_buffer: [64]u8 = undefined;
            if (i > 0) try w.writeByte(',');
            try w.writeAll("{\"scope\":");
            try std.json.encodeJsonString(try formatListSubject(ban.canonical.subject, &scope_buffer), .{}, w);
            try w.writeAll(",\"deadline_us\":");
            if (ban.deadline_us) |deadline| try w.print("{d}", .{deadline}) else try w.writeAll("null");
            try w.print(",\"permanent\":{},\"confirmed\":{},\"relation\":\"{s}\",\"lift\":\"{s}\",\"lift_reason\":", .{ ban.deadline_us == null, ban.confirmed, @tagName(ban.relation), @tagName(ban.lift) });
            if (ban.reason) |text| try std.json.encodeJsonString(text, .{}, w) else try w.writeAll("null");
            try w.writeAll("}");
        };
        try w.writeAll("]");
    }
    fn ignoreRefusal(self: *Coordinator, request: *AdminRequest, outcome: durable.Store.AdminOutcome, comptime fmt: []const u8, args: anytype) AdminOutcomeView {
        return self.adminDetail(request, (AdminOutcomeView{ .outcome = outcome, .kind = request.kind }).withReason(fmt, args), null);
    }
    fn ignoreUncertain(self: *Coordinator, request: *AdminRequest) AdminOutcomeView {
        return self.ignoreRefusal(request, .uncertain, "the ignore entry may or may not have been recorded; run fail2zig ignore list --jail {s} to see the current list", .{request.jailName()});
    }
    fn recordConfiguredCover(ignore_state: *IgnoreWork, list: *const ignore_set.EffectiveIgnore, entry: shared.types.IgnoreEntry, include_equal: bool) void {
        var found: [ignore_set.max_entries_per_part]*const ignore_set.Item = undefined;
        const covering = list.covering(entry, &found);
        for (found[0..covering], 0..) |item, slot| ignore_state.configured[slot] = item.entry;
        ignore_state.configured_count = covering;
        for (list.entries) |item| {
            if (item.entry.order(entry) != .eq) continue;
            ignore_state.source = item.source;
            if (include_equal and item.source != .runtime and ignore_state.configured_count < ignore_state.configured.len) {
                ignore_state.configured[ignore_state.configured_count] = item.entry;
                ignore_state.configured_count += 1;
            }
        }
        std.sort.pdq(shared.types.IgnoreEntry, ignore_state.configured[0..ignore_state.configured_count], {}, entryLess);
    }
    fn entryLess(_: void, a: shared.types.IgnoreEntry, b: shared.types.IgnoreEntry) bool {
        return a.order(b) == .lt;
    }
    fn subjectEntry(subject: inspection.canonical_scope.Subject) shared.types.IgnoreEntry {
        return .{ .family = switch (subject.family) {
            .v4 => .v4,
            .v6 => .v6,
        }, .address = subject.address, .prefix = subject.prefix };
    }
    fn banRelation(entry: shared.types.IgnoreEntry, ban: shared.types.IgnoreEntry) ?IgnoreRelation {
        if (entry.family != ban.family) return null;
        if (ban.prefix >= entry.prefix) return if (entry.contains(ban.network())) .inside_entry else null;
        return if (ban.contains(entry.network())) .contains_entry else null;
    }
    const RelatedBan = struct { order: shared.types.IgnoreEntry, index: u32, relation: IgnoreRelation };
    fn relatedLess(_: void, a: RelatedBan, b: RelatedBan) bool {
        return a.order.order(b.order) == .lt;
    }
    fn collectRelatedBans(self: *Coordinator, request: *AdminRequest, jail: *Jail) !void {
        const ignore_state = request.ignore.?;
        const entry = request.ignore_entry.?;
        const enforces = self.jailEnforces(jail);
        if (enforces) {
            self.publishOwners() catch |failure| if (failure != error.StaleEffect) return failure;
        } else try self.publishJail(jail);
        const now = self.clock.wallUs();
        const found = try self.allocator.alloc(RelatedBan, if (enforces) self.owner_count else jail.summary.active);
        defer self.allocator.free(found);
        var count: usize = 0;
        var inside: usize = 0;
        if (enforces) {
            for (self.owner_active[0..self.owner_count], 0..) |owner, i| {
                if (!std.mem.eql(u8, owner.jail.slice(), jail.name) or !owner.lease.live(now)) continue;
                const ban = subjectEntry(owner.scope.canonical.subject);
                const relation = banRelation(entry, ban) orelse continue;
                found[count] = .{ .order = ban, .index = @intCast(i), .relation = relation };
                count += 1;
                inside += @intFromBool(relation == .inside_entry);
            }
        } else for (jail.active[0..jail.summary.active], 0..) |decision, i| {
            if (!decision.lease.live(now)) continue;
            const ban = subjectEntry(decisionScope(decision.subject).subject);
            const relation = banRelation(entry, ban) orelse continue;
            found[count] = .{ .order = ban, .index = @intCast(i), .relation = relation };
            count += 1;
            inside += @intFromBool(relation == .inside_entry);
        }
        std.sort.pdq(RelatedBan, found[0..count], {}, relatedLess);
        ignore_state.bans_total = count;
        ignore_state.inside_total = inside;
        ignore_state.ban_count = @min(count, if (request.unban) ignore_state.bans.len else max_listed_bans);
        for (found[0..ignore_state.ban_count], ignore_state.bans[0..ignore_state.ban_count]) |item, *slot| {
            if (enforces) {
                const owner = self.owner_active[item.index];
                slot.* = .{ .canonical = owner.scope.canonical, .key = owner.key, .deadline_us = leaseDeadline(owner.lease), .confirmed = self.owner_confirmed[item.index] and self.confirmationKnown(monotonic(self)), .relation = item.relation };
            } else {
                const decision = jail.active[item.index];
                slot.* = .{ .canonical = decisionScope(decision.subject), .key = [_]u8{0} ** 32, .deadline_us = leaseDeadline(decision.lease), .confirmed = jail.confirmed[item.index] and self.confirmationKnown(monotonic(self)), .relation = item.relation };
            }
        }
    }
    fn leaseDeadline(lease: anytype) ?i64 {
        return switch (lease) {
            .finite => |value| value,
            else => null,
        };
    }
    fn decisionScope(subject: detection.Subject) inspection.CanonicalScope {
        const address: shared.IpAddress = switch (subject) {
            .v4 => |v| .{ .ipv4 = std.mem.readInt(u32, &v, .big) },
            .v6 => |v| .{ .ipv6 = std.mem.readInt(u128, &v, .big) },
        };
        return .{ .subject = inspection.canonical_scope.Subject.host(address) };
    }
    fn liftIgnoredBans(self: *Coordinator, request: *AdminRequest, jail: ?*Jail) void {
        const ignore_state = request.ignore.?;
        const name = request.jailName();
        const budget_end = monotonic(self) + ignore_lift_budget_ms;
        for (ignore_state.bans[0..ignore_state.ban_count], 0..) |*ban, index| {
            if (ban.relation == .contains_entry) {
                ban.lift = .refused;
                ban.reason = "network ban wider than the entry";
                continue;
            }
            const manager_enforces = self.effects != null and jail != null and self.jailEnforces(jail.?);
            if (!manager_enforces) {
                ban.lift = .refused;
                ban.reason = "jail is log-only; manual bans require an enforcing backend";
                continue;
            }
            if (monotonic(self) >= budget_end) {
                ban.lift = .refused;
                ban.reason = "not attempted within the command's time limit; run the command again";
                continue;
            }
            const current = self.store.currentOwner(ban.key, name) catch |failure| {
                ban.lift = .unknown;
                ban.reason = @errorName(failure);
                continue;
            } orelse {
                ban.lift = .refused;
                ban.reason = "no owner for this scope in the jail";
                continue;
            };
            if (current.lease == .absent) {
                ban.lift = .refused;
                ban.reason = "owner already released";
                continue;
            }
            var counter: [4]u8 = undefined;
            std.mem.writeInt(u32, &counter, @intCast(index), .little);
            const transition = effect.hashParts("fail2zig-ignore-unban-v1", &.{ &request.request_id, &counter });
            const prepared = self.clock.wallUs();
            _ = self.store.transitionOwner(.{ .scope = ban.canonical, .jail = name, .current_generation = current.generation, .next_generation = current.generation, .expected_owner_revision = current.revision, .transition_id = transition, .mode = .release, .occurred_us = prepared }, .{ .prepared_us = prepared, .context = self, .read = wallClockEffect }) catch |failure| {
                ban.reason = @errorName(failure);
                ban.lift = switch (failure) {
                    error.StaleEffect, error.EffectGenerationMismatch, error.EffectReconciliationRequired => .refused,
                    else => .unknown,
                };
                continue;
            };
            ban.lift = .pending;
            ignore_state.lifting = true;
            ignore_state.mutated = true;
            request.mutation_committed = true;
        }
    }
    fn settleIgnoreLifts(self: *Coordinator, request: *AdminRequest, ignore_state: *IgnoreWork) void {
        const manager = self.effects.?;
        const readback = adminReadback(manager.status, manager.cached_epoch, self.store.effect_publication_epoch);
        const now = self.clock.wallUs();
        var pending: usize = 0;
        for (ignore_state.bans[0..ignore_state.ban_count]) |*ban| {
            if (ban.lift != .pending) continue;
            switch (readback) {
                .uncertain => {
                    ban.lift = .unknown;
                    ban.reason = "effect outcome uncertain";
                },
                .pending => pending += 1,
                .coherent => {
                    var removed = true;
                    for (manager.live[0..manager.count]) |live| if (std.mem.eql(u8, &live.scope_key, &ban.key)) {
                        removed = live.status == .absent or live.status == .expired or !live.desired.live(now);
                    };
                    if (removed) ban.lift = .confirmed else pending += 1;
                },
            }
        }
        if (pending != 0 and monotonic(self) < request.deadline_ms) return;
        for (ignore_state.bans[0..ignore_state.ban_count]) |*ban| if (ban.lift == .pending) {
            ban.lift = .incomplete;
            ban.reason = "kernel removal not confirmed within the deadline";
        };
        self.completeAdmin(request, self.finishIgnoreAdd(request));
    }
    fn finishIgnoreAdd(self: *Coordinator, request: *AdminRequest) AdminOutcomeView {
        const ignore_state = request.ignore.?;
        var reported: durable.Store.AdminOutcome = .applied;
        var enforced = true;
        for (ignore_state.bans[0..ignore_state.ban_count]) |ban| switch (ban.lift) {
            .unknown => {
                reported = .uncertain;
                enforced = false;
            },
            .incomplete => {
                if (reported != .uncertain) reported = .partial;
                enforced = false;
            },
            .refused => if (reported == .applied) {
                reported = .rejected;
            },
            .kept, .pending, .confirmed => {},
        };
        const recorded: durable.Store.AdminOutcome = if (reported == .rejected and ignore_state.mutated) .partial else reported;
        var finished = self.adminDetail(request, (AdminOutcomeView{ .outcome = recorded, .kind = request.kind, .enforced = enforced }), null);
        if (finished.outcome == recorded) finished.outcome = reported;
        return finished;
    }
    fn executeIgnoreAdd(self: *Coordinator, request: *AdminRequest) !AdminOutcomeView {
        const ignore_state = request.ignore.?;
        const entry = request.ignore_entry.?;
        const name = request.jailName();
        const jail_cfg = findConfigJail(self.live_cfg, name) orelse return self.ignoreRefusal(request, .rejected, "jail '{s}' is not configured", .{name});
        if (jail_cfg.rule_files.len != 0) return self.ignoreRefusal(request, .rejected, "jail '{s}' uses rule_files; manage its exclusions through ignore_file", .{name});
        const jail = self.findJail(name);
        if (jail) |value| if (ignoreCell(value) == null) return self.ignoreRefusal(request, .rejected, "jail '{s}' reads internal events and has no ignore list", .{name});
        var runtime: [ignore_set.max_entries_per_part + 1]shared.types.IgnoreEntry = undefined;
        const runtime_count = try self.store.ignoreEntries(name, runtime[0..ignore_set.max_entries_per_part]);
        const literals = jail_cfg.ignoreip orelse self.live_cfg.defaults.ignoreip;
        const before = try ignore_set.EffectiveIgnore.build(self.allocator, literals, runtime[0..runtime_count]);
        defer before.deinit(self.allocator);
        var existing: ?ignore_set.Source = null;
        for (before.entries) |item| if (item.entry.order(entry) == .eq) {
            existing = item.source;
        };
        const recorded = existing != null and existing.? != .config;
        if (!recorded and before.entries.len + @intFromBool(existing == null) > ignore_set.distinct_bound)
            return self.ignoreRefusal(request, .rejected, "jail {s} already has {d} ignore entries (configuration and runtime combined), the limit. Remove one with fail2zig ignore remove first.", .{ name, before.entries.len });
        runtime[runtime_count] = entry;
        const after = ignore_set.EffectiveIgnore.build(self.allocator, literals, runtime[0 .. runtime_count + @intFromBool(!recorded)]) catch |failure| switch (failure) {
            error.IgnoreCapacityExceeded => return self.ignoreRefusal(request, .rejected, "jail {s} already has {d} ignore entries (configuration and runtime combined), the limit. Remove one with fail2zig ignore remove first.", .{ name, before.entries.len }),
            else => return failure,
        };
        var installed = false;
        defer if (!installed) after.deinit(self.allocator);
        if (jail) |value| try self.collectRelatedBans(request, value);
        var entry_text: [64]u8 = undefined;
        const canonical = entry.canonical(&entry_text);
        if (request.unban and ignore_state.inside_total > max_lifted_bans)
            return self.ignoreRefusal(request, .rejected, "{s} covers {d} bans in {s}; --unban lifts at most {d} per command. Nothing changed. Add the entry without --unban, then lift bans with fail2zig unban.", .{ canonical, ignore_state.inside_total, name, max_lifted_bans });
        ignore_state.entry_state = .present;
        if (!recorded) {
            const result = self.store.addIgnoreEntry(name, entry, self.clock.wallUs()) catch |failure| {
                if (failure == error.IgnoreCapacity)
                    return self.ignoreRefusal(request, .rejected, "jail {s} already has {d} ignore entries (configuration and runtime combined), the limit. Remove one with fail2zig ignore remove first.", .{ name, before.entries.len });
                std.log.err("native admin: ignore entry commit failed: {s}", .{@errorName(failure)});
                return self.ignoreUncertain(request);
            };
            if (result == .added) {
                ignore_state.entry_state = .added;
                ignore_state.mutated = true;
                request.mutation_committed = true;
            }
        }
        recordConfiguredCover(ignore_state, after, entry, false);
        if (jail) |value| {
            self.replaceIgnoreList(value, after);
            installed = true;
        }
        if (ignore_state.entry_state == .added) {
            const lifting = if (request.unban) ignore_state.inside_total else 0;
            if (lifting != 0)
                std.log.info("native: jail={} ignore entry added: {} (runtime); unban requested for {d} {s}", .{ std.zig.fmtEscapes(name), std.zig.fmtEscapes(canonical), lifting, if (lifting == 1) "ban" else "bans" })
            else
                std.log.info("native: jail={} ignore entry added: {} (runtime); existing bans unchanged", .{ std.zig.fmtEscapes(name), std.zig.fmtEscapes(canonical) });
        }
        if (request.unban) self.liftIgnoredBans(request, jail);
        if (ignore_state.lifting) {
            request.expect_absent = true;
            request.scope_key = [_]u8{0} ** 32;
            request.phase = .awaiting;
            request.deadline_ms = monotonic(self) + ignore_lift_settle_ms;
            return .{ .outcome = .applied, .kind = request.kind, .generation = self.published_generation };
        }
        return self.finishIgnoreAdd(request);
    }
    fn executeIgnoreRemove(self: *Coordinator, request: *AdminRequest) !AdminOutcomeView {
        const ignore_state = request.ignore.?;
        const entry = request.ignore_entry.?;
        const name = request.jailName();
        ignore_state.entry_state = .not_removed;
        const jail_cfg = findConfigJail(self.live_cfg, name);
        if (jail_cfg == null) {
            var stored: [128]durable.Store.IgnoreJailCount = undefined;
            const stored_count = try self.store.ignoreEntryJails(&stored);
            var known = false;
            for (stored[0..stored_count]) |item| if (std.mem.eql(u8, item.jail[0..item.jail_len], name)) {
                known = true;
            };
            if (!known) return self.ignoreRefusal(request, .rejected, "jail '{s}' is not configured", .{name});
        }
        const jail = self.findJail(name);
        var runtime: [ignore_set.max_entries_per_part]shared.types.IgnoreEntry = undefined;
        const runtime_count = try self.store.ignoreEntries(name, &runtime);
        const literals: []const []const u8 = if (jail_cfg) |value| (if (value.rule_files.len != 0) &.{} else value.ignoreip orelse self.live_cfg.defaults.ignoreip) else &.{};
        const before = try ignore_set.EffectiveIgnore.build(self.allocator, literals, runtime[0..runtime_count]);
        defer before.deinit(self.allocator);
        var entry_text: [64]u8 = undefined;
        const canonical = entry.canonical(&entry_text);
        var existing: ?ignore_set.Source = null;
        for (before.entries) |item| if (item.entry.order(entry) == .eq) {
            existing = item.source;
        };
        if (existing != null and existing.? == .config) {
            ignore_state.entry_state = .config_only;
            recordConfiguredCover(ignore_state, before, entry, true);
            if (self.config_path.len != 0 and self.config_path.len <= 96)
                return self.ignoreRefusal(request, .rejected, "{s} is set in the configuration file for jail {s} and cannot be removed at runtime. Edit ignoreip in {s} and run fail2zig reload.", .{ canonical, name, self.config_path });
            return self.ignoreRefusal(request, .rejected, "{s} is set in the configuration file for jail {s} and cannot be removed at runtime. Edit ignoreip in the configuration file and run fail2zig reload.", .{ canonical, name });
        }
        if (existing == null) {
            ignore_state.entry_state = .absent;
            recordConfiguredCover(ignore_state, before, entry, false);
            return self.ignoreRefusal(request, .absent, "jail {s} has no runtime ignore entry {s}.", .{ name, canonical });
        }
        var kept: [ignore_set.max_entries_per_part]shared.types.IgnoreEntry = undefined;
        var kept_count: usize = 0;
        for (runtime[0..runtime_count]) |item| if (item.order(entry) != .eq) {
            kept[kept_count] = item;
            kept_count += 1;
        };
        const after = try ignore_set.EffectiveIgnore.build(self.allocator, literals, kept[0..kept_count]);
        var installed = false;
        defer if (!installed) after.deinit(self.allocator);
        const removed = self.store.removeIgnoreEntry(name, entry) catch |failure| {
            std.log.err("native admin: ignore entry removal failed: {s}", .{@errorName(failure)});
            return self.ignoreUncertain(request);
        };
        if (!removed) {
            ignore_state.entry_state = .absent;
            recordConfiguredCover(ignore_state, after, entry, false);
            return self.ignoreRefusal(request, .absent, "jail {s} has no runtime ignore entry {s}.", .{ name, canonical });
        }
        ignore_state.entry_state = .removed;
        ignore_state.mutated = true;
        request.mutation_committed = true;
        recordConfiguredCover(ignore_state, after, entry, true);
        if (jail) |value| if (ignoreCell(value) != null) {
            self.replaceIgnoreList(value, after);
            installed = true;
        };
        std.log.info("native: jail={} ignore entry removed: {} (runtime); configuration still covers it: {s}", .{ std.zig.fmtEscapes(name), std.zig.fmtEscapes(canonical), if (ignore_state.configured_count != 0) "yes" else "no" });
        return self.adminDetail(request, .{ .outcome = .applied, .kind = request.kind, .enforced = true }, null);
    }
    fn reloadResponse(self: *Coordinator, out: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator) !shared.Response {
        var outcome = self.stageReload(2000);
        if (std.mem.allEqual(u8, &outcome.generation, 0)) {
            self.mutex.lock();
            outcome.generation = self.published_generation;
            self.mutex.unlock();
        }
        const w = out.writer(a);
        try w.print("{{\"schema_version\":1,\"outcome\":\"{s}\",\"generation\":\"{s}\",\"reasons\":[", .{ @tagName(outcome.kind), &std.fmt.bytesToHex(outcome.generation, .lower) });
        for (outcome.reasonSlice(), 0..) |reason, i| {
            if (i > 0) try w.writeByte(',');
            try std.json.encodeJsonString(reason.slice(), .{}, w);
        }
        try w.writeAll("]}");
        return switch (outcome.kind) {
            .applied, .noop => .{ .ok = .{ .payload = try out.toOwnedSlice(a) } },
            .rejected => .{ .err = .{ .code = 409, .message = try out.toOwnedSlice(a) } },
            .restart_required => .{ .err = .{ .code = 412, .message = try out.toOwnedSlice(a) } },
            .uncertain => .{ .err = .{ .code = 508, .message = try out.toOwnedSlice(a) } },
            .partial => .{ .err = .{ .code = 507, .message = try out.toOwnedSlice(a) } },
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
    fn plannedGeneration(self: *Coordinator, jail: *Jail, mode: GenerationMode) ![32]u8 {
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
                if (!try self.consumeHistory()) return false;
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
    fn effectBindings(self: *Coordinator, output: *[max_jails]effect_runtime.Binding) void {
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
        const manager = try effect_runtime.Manager.create(self.allocator, &self.store, installation.?);
        manager.wall_context = &self.clock;
        manager.wall = clock_mod.wallRead;
        manager.monotonic_context = &self.clock;
        manager.monotonic = clock_mod.monotonicNsRead;
        manager.last_wall_us = self.clock.wallUs();
        if (comptime build_options.diag) manager.setClockRate(self.clock.rate());
        manager.verify_interval_ns = verify_interval_ns;
        if (self.firewall_observation_cache) |cache| manager.attachObservationCache(cache);
        self.effects = manager;
    }
    fn recoverStorage(ctx: ?*anyopaque) !void {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        if (self.gate.snapshot().has_been_healthy) {
            try self.verifyStateIdentity();
            if (!self.store_open or self.store.reopen_required) {
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
    fn dropRuntimeJail(jail: *Jail) void {
        if (jail.session) |value| value.destroy();
        jail.session = null;
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
                setJailPaused(jail, jail.admin_paused);
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
                    self.rebuild_phase = .done;
                }
            },
            .done => {},
        }
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
        for (self.jails) |*jail| if (jail.plan == .internal) return jail;
        return null;
    }
    fn consumeHistory(self: *Coordinator) !bool {
        const diag_span = if (comptime build_options.diag) diag_mod.enter(.history) else {};
        defer if (comptime build_options.diag) diag_mod.leave(diag_span);
        const owner = if (self.history_consumer) |*value| value else return true;
        var events: [history.max_page]history.Event = undefined;
        const page = try self.store.confirmedEffectPage(owner.installation, owner.live.last_sequence, null, &events);
        if (page.count != 0) {
            const now = self.clock.wallUs();
            const stage = try owner.prepare(page, events[0..page.count], now);
            defer stage.release();
            if (self.recidiveJail()) |jail| {
                for (events[0..page.count]) |event| {
                    _ = try recurrence.consume(&self.store, .{ .jail = jail.name, .generation = jail.session.?.generation(), .policy = jail.policy, .suppress_enforcement = self.suppress_enforcement }, event, now, .{ .prepared_us = now, .context = self, .read = processingClock });
                }
            }
            try self.store.commitConfirmedHistory(owner.manifest(), try stage.batch(.{ .prepared_us = now, .context = self, .read = processingClock }), page.token);
            stage.publish();
            if (self.readiness_progress_started_ns != null and !self.notified_ready) {
                const head = self.readiness_history_head orelse page.token.head_sequence;
                self.readiness_history_head = head;
                if (page.token.last_sequence <= head) self.readiness_history_pages +|= 1;
            }
            self.history_page = null;
            return false;
        }
        try self.store.validateConfirmedEffectPage(page.token);
        self.history_page = page.token;
        return true;
    }
    fn recoverOwnership(ctx: ?*anyopaque) !void {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        self.owner_read_epoch = null;
        for (self.jails) |*jail| {
            jail.retry_revision = null;
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
    fn publishJail(self: *Coordinator, jail: *Jail) !void {
        const diag_span = if (comptime build_options.diag) diag_mod.enter(.publish) else {};
        defer if (comptime build_options.diag) diag_mod.leave(diag_span);
        const now = self.clock.wallUs();
        const retry_revision = try self.store.retryStateRevision();
        const revision = try self.store.revision(jail.name);
        const mark = self.effectMark(self.jailEnforces(jail));
        const expired = if (jail.next_expiry_us) |deadline| now >= deadline else false;
        if (jail.published_once and !expired and jail.retry_revision == retry_revision and std.meta.eql(jail.published_mark, mark) and jail.healthy == jail.session.?.healthy()) {
            if (jail.revision != revision) {
                self.mutex.lock();
                defer self.mutex.unlock();
                jail.revision = revision;
            }
            return;
        }
        var summary: durable.Store.RetrySummary = undefined;
        if (jail.retry_revision == retry_revision) {
            var live: usize = 0;
            for (jail.active[0..jail.summary.active]) |decision| if (decision.lease.live(now)) {
                self.decision_scratch[live] = decision;
                live += 1;
            };
            summary = jail.summary;
            summary.active = live;
        } else summary = try self.store.retrySummary(jail.name, now, self.decision_scratch);
        const keyed_manager = if (self.jailEnforces(jail)) self.effects else null;
        if (keyed_manager) |manager| {
            const trusted = !manager.status.uncertain or (manager.status.cause != null and effect_runtime.transientCause(manager.status.cause.?));
            const prior_keyed = jail.active_keys.len == jail.active.len;
            var prior: usize = 0;
            for (self.decision_scratch[0..summary.active], 0..) |decision, i| {
                while (prior_keyed and prior < jail.active.len and subjectOrder(jail.active[prior].subject, decision.subject) == .lt) prior += 1;
                const carried = prior_keyed and prior < jail.active.len and std.meta.eql(jail.active[prior].subject, decision.subject);
                const key = if (carried) jail.active_keys[prior] else hostEffectKey(manager, decision.subject);
                self.decision_scratch_keys[i] = key;
                self.decision_scratch_confirmed[i] = trusted and if (key) |value| manager.confirmedKey(value, now) else false;
            }
        } else @memset(self.decision_scratch_confirmed[0..summary.active], false);
        const confirmations = try self.confirmedEvents();
        if (jail.published_once and !self.jailEnforces(jail)) for (self.decision_scratch[0..summary.active]) |decision| {
            var already_published = false;
            for (jail.active[0..jail.summary.active]) |prior| {
                if (prior.ordinal == decision.ordinal and std.meta.eql(prior.subject, decision.subject)) {
                    already_published = true;
                    break;
                }
            }
            if (!already_published) {
                const address: shared.IpAddress = switch (decision.subject) {
                    .v4 => |v| .{ .ipv4 = std.mem.readInt(u32, &v, .big) },
                    .v6 => |v| .{ .ipv6 = std.mem.readInt(u128, &v, .big) },
                };
                std.log.info("would-ban: jail='{s}' ip={}", .{ jail.name, address });
            }
        };
        const active = try self.allocator.alloc(durable.Store.ActiveDecision, summary.active);
        errdefer self.allocator.free(active);
        const confirmed = try self.allocator.alloc(bool, summary.active);
        errdefer self.allocator.free(confirmed);
        const keys = try self.allocator.alloc(?[32]u8, if (keyed_manager != null) summary.active else 0);
        errdefer self.allocator.free(keys);
        @memcpy(active, self.decision_scratch[0..summary.active]);
        @memcpy(confirmed, self.decision_scratch_confirmed[0..summary.active]);
        @memcpy(keys, self.decision_scratch_keys[0..keys.len]);
        var next_expiry: ?i64 = null;
        for (active) |decision| if (decision.lease == .finite) {
            next_expiry = if (next_expiry) |prior| @min(prior, decision.lease.finite) else decision.lease.finite;
        };
        self.mutex.lock();
        defer self.mutex.unlock();
        self.allocator.free(jail.active);
        self.allocator.free(jail.confirmed);
        self.allocator.free(jail.active_keys);
        jail.active = active;
        jail.confirmed = confirmed;
        jail.active_keys = keys;
        self.published_confirmations = confirmations;
        jail.summary = summary;
        jail.retry_revision = retry_revision;
        jail.published_once = true;
        jail.next_expiry_us = next_expiry;
        jail.published_mark = mark;
        jail.revision = revision;
        jail.healthy = jail.session.?.healthy();
    }
    fn subjectOrder(a: detection.Subject, b: detection.Subject) std.math.Order {
        const tag = std.math.order(@intFromEnum(std.meta.activeTag(a)), @intFromEnum(std.meta.activeTag(b)));
        if (tag != .eq) return tag;
        return switch (a) {
            .v4 => |left| std.mem.order(u8, &left, &b.v4),
            .v6 => |left| std.mem.order(u8, &left, &b.v6),
        };
    }
    fn hostEffectKey(manager: *const effect_runtime.Manager, subject: detection.Subject) ?[32]u8 {
        const scope = effect.Scope.host(subject) catch return null;
        return scope.key(manager.installation) catch null;
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
    fn publishOwners(self: *Coordinator) !void {
        const diag_span = if (comptime build_options.diag) diag_mod.enter(.owners) else {};
        defer if (comptime build_options.diag) diag_mod.leave(diag_span);
        const manager = self.effects orelse return;
        if (manager.withdrawn) {
            self.mutex.lock();
            defer self.mutex.unlock();
            @memset(self.owner_confirmed[0..self.owner_count], false);
            return;
        }
        const expected_epoch = manager.cached_epoch orelse return error.StaleEffect;
        const fatal = manager.status.uncertain and !(manager.status.cause != null and effect_runtime.transientCause(manager.status.cause.?));
        if (fatal or expected_epoch != self.store.effect_publication_epoch) return error.StaleEffect;
        const mark = self.effectMark(true);
        const reread = self.owner_read_epoch != expected_epoch;
        if (!reread and std.meta.eql(self.published_owners_mark, mark)) return;
        const now = self.clock.wallUs();
        var count: usize = 0;
        if (reread) {
            count = try self.store.operatorOwners(now, self.owner_scratch);
        } else for (self.owner_active[0..self.owner_count]) |owner| if (owner.lease.live(now)) {
            self.owner_scratch[count] = owner;
            count += 1;
        };
        for (self.owner_scratch[0..count], 0..) |owner, i| self.owner_scratch_confirmed[i] = self.ownerConfirmed(owner, now);
        if (expected_epoch != self.store.effect_publication_epoch or manager.cached_epoch == null or manager.cached_epoch.? != expected_epoch) return error.StaleEffect;
        self.mutex.lock();
        defer self.mutex.unlock();
        @memcpy(self.owner_active[0..count], self.owner_scratch[0..count]);
        @memcpy(self.owner_confirmed[0..count], self.owner_scratch_confirmed[0..count]);
        self.owner_count = count;
        if (reread) self.owner_read_epoch = expected_epoch;
        self.published_owners_mark = mark;
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
        return a.built == b.built and a.sources == b.sources and a.loss_sequence == b.loss_sequence and std.mem.eql(?anyerror, &a.causes, &b.causes);
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
    fn jailPaused(jail: *const Jail) bool {
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
            self.tick() catch |failure| {
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
        const now_ms = monotonic(self);
        const committed = self.gate.snapshot().committed_records;
        const quiet = view_idle and !self.effect_backlog and self.history_caught_up and !self.maintenance_progress and committed == self.last_committed_records;
        const slow_due = !quiet or now_ms -| (self.last_slow_tick_ms orelse 0) >= quiet_interval_ms;
        self.last_committed_records = committed;
        if (slow_due) {
            self.last_slow_tick_ms = now_ms;
            if (self.effects) |manager| {
                if (view_idle or manager.last_readback_ns != null) {
                    self.publishOwners() catch |failure| if (failure != error.StaleEffect) return failure;
                    for (self.jails) |*jail| try self.publishJail(jail);
                }
            } else for (self.jails) |*jail| try self.publishJail(jail);
            if (now_ms -| (self.last_history_ms orelse 0) >= quiet_interval_ms) {
                self.last_history_ms = now_ms;
                self.history_caught_up = false;
                var pages: u8 = 0;
                while (pages < history_pages_per_turn) : (pages += 1) {
                    if (try self.consumeHistory()) {
                        self.history_caught_up = true;
                        break;
                    }
                }
            } else self.history_page = null;
        }
        if (self.dns) |resolver| {
            const result = try resolver.pollDns();
            if (result.kind == .ready) {
                const owner = result.source orelse return error.UnboundRequiredConsumer;
                for (self.jails) |*jail| if (jail.consumer) |consumer| {
                    if (!std.mem.eql(u8, consumer.settings.jail, owner.settings.jail)) continue;
                    jail.session.?.resumeConsumer(owner.incarnation) catch |failure| {
                        if (failure == error.SourceRepairPending or failure == error.SourceInterventionRequired) {
                            try self.publishSource(jail);
                            break;
                        }
                        if (pipeline.Pipeline.commitBlocked(failure)) {
                            try self.publishBlocked(jail, failure);
                        } else if (failure != error.ConsumerPending and failure != error.ConsumerExpired and failure != error.EffectExpired) return failure;
                    };
                    try self.publishJail(jail);
                    break;
                };
            }
        }
        for (self.jails) |*jail| {
            const admitted = jail.session.?.poll() catch |failure| {
                if (failure == error.SourceRepairPending or failure == error.SourceInterventionRequired) {
                    try self.publishSource(jail);
                    continue;
                }
                if (pipeline.Pipeline.commitBlocked(failure)) {
                    if (comptime build_options.diag) diag_mod.event(.commit_refused, .{ .subject = jail.name, .cause = @errorName(failure) });
                    try self.publishBlocked(jail, failure);
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
            const session = jail.session orelse continue;
            if (session == .internal) continue;
            const now_us = self.clock.wallUs();
            const fence = durable.Store.CleanupFence{
                .jail = jail.name,
                .source = "@retired",
                .generation = session.generation(),
                .jail_revision = try self.store.revision(jail.name),
                .consumer_revision = try self.store.maintenanceConsumerRevision(),
                .effect_revision = try self.store.maintenanceEffectRevision(),
                .clock = .{ .prepared_us = now_us, .context = self, .read = wallClockEffect },
                .preparations = .released,
            };
            const batch = self.store.retireRetrySubjects(fence, jail.retire_after, now_us, jail.policy.window_us, durable.Store.max_retirement_batch) catch |failure| switch (failure) {
                error.StaleMaintenance, error.MaintenancePinned, error.RetryAdmissionRequired => {
                    self.retire_refused += 1;
                    return;
                },
                else => return failure,
            };
            jail.retire_after = if (batch.exhausted) null else batch.last;
            self.retire_examined += batch.examined;
            self.retire_pinned_state += batch.pinned_state;
            self.retire_pinned_effect += batch.pinned_effect;
            self.retire_batches += @intFromBool(batch.retired != 0);
            self.retired_total += batch.retired;
            if (batch.examined != 0) {
                self.maintenance_progress = true;
                return;
            }
        }
    }
    const quiet_interval_ms: u64 = 1000;
    const maintenance_idle_ms: u64 = 30 * quiet_interval_ms;
    const verify_interval_ns: u64 = 5 * std.time.ns_per_s;
    const stop_history_budget_ns: u64 = 2 * std.time.ns_per_s;
    fn drainHistoryForStop(self: *Coordinator) void {
        if (self.gate.snapshot().phase != .healthy or !self.store_open or self.store.reopen_required) return;
        var timer = std.time.Timer.start() catch |failure| {
            std.log.warn("native: stop left the history consumer behind the head: {s}; the next start resumes it", .{@errorName(failure)});
            return;
        };
        var pages: usize = 0;
        while (timer.read() < stop_history_budget_ns) : (pages += 1) {
            const caught_up = self.consumeHistory() catch |failure| {
                std.log.warn("native: stop left the history consumer behind the head: {s}; the next start resumes it", .{@errorName(failure)});
                return;
            };
            if (caught_up) return;
        }
        std.log.warn("native: stop left the history consumer behind the head after {d} pages in {d} ms; the next start resumes it", .{ pages, timer.read() / std.time.ns_per_ms });
    }
    const history_pages_per_turn: u8 = 4;
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
        const caught_up = if (self.history_page) |page| page.after_sequence == page.head_sequence and page.last_sequence == page.head_sequence else false;
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
        switch (if (step_idle) .idle else try self.store.maintenanceStep(.{ .retention = .{ .age_us = age_us, .max_matches = self.cfg.global.history_max_matches }, .now_us = self.clock.wallUs(), .history_caught_up = caught_up, .spent_scopes = effects_usable })) {
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
            .wait => {
                self.maintenance_progress = true;
                self.gates.step_wait += 1;
                return;
            },
            .idle => record_idle = !step_idle,
        }
        if (!effects_settled) {
            self.gates.unsettled += 1;
            return;
        }
        if (self.effects != null) {
            if (self.history_page == null and self.history_caught_up) _ = try self.consumeHistory();
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
    pub fn destroy(self: *Coordinator) void {
        self.stop_mutex.lock();
        self.stopping = true;
        self.wake.signal();
        self.stop_mutex.unlock();
        if (self.thread) |thread| thread.join();
        if (self.reload_request) |request| self.freeRequest(request);
        if (self.admin_request) |request| self.allocator.destroy(request);
        if (self.history_reader) |*reader| reader.close();
        if (self.live_arena) |arena| {
            arena.deinit();
            self.allocator.destroy(arena);
        }
        if (self.effects) |manager| manager.destroy();
        if (self.firewall_observation_cache) |cache| self.allocator.destroy(cache);
        self.destroyRuntime();
        for (self.jails) |*jail| {
            if (jail.custom_plan) |value| value.destroy();
            jail.plan.deinit(self.allocator);
            destroyZone(self.allocator, jail.zone);
            if (jail.source_status_arena) |*arena| arena.deinit();
            self.allocator.free(jail.active);
            self.allocator.free(jail.confirmed);
            self.allocator.free(jail.active_keys);
        }
        self.allocator.free(self.decision_scratch);
        self.allocator.free(self.decision_scratch_confirmed);
        self.allocator.free(self.decision_scratch_keys);
        if (self.owner_scratch.len != 0) self.allocator.free(self.owner_scratch);
        if (self.owner_active.len != 0) self.allocator.free(self.owner_active);
        if (self.owner_scratch_confirmed.len != 0) self.allocator.free(self.owner_scratch_confirmed);
        if (self.owner_confirmed.len != 0) self.allocator.free(self.owner_confirmed);
        if (self.store_open) self.store.close();
        if (self.authority_lock) |file| file.close();
        if (self.namespace_lock) |file| file.close();
        self.allocator.free(self.jails);
        self.releaseResources();
        self.allocator.destroy(self);
    }
    fn status(ctx: ?*anyopaque, out: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator) !void {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        try self.statusPayload(out, a, true);
    }
    const LossJson = struct { sequence: u64, wall_us: i64, reason: []const u8, inode: u64, committed_offset: u64, observed_size: ?u64 };
    const SourceJson = struct {
        jail: []const u8,
        kind: []const u8,
        path: ?[]const u8,
        on_truncation: ?[]const u8,
        state: []const u8,
        cause: ?[]const u8,
        inode: ?u64,
        committed_offset: ?u64,
        observed_size: ?u64,
        repair: ?[]const u8,
        loss_events: u16,
        last_loss: ?LossJson,
    };
    const redacted_text = "<redacted>";
    fn sourceStatusOrder(_: void, a: *const SourceStatus, b: *const SourceStatus) bool {
        return switch (std.mem.order(u8, a.jail, b.jail)) {
            .lt => true,
            .gt => false,
            .eq => std.mem.lessThan(u8, a.path orelse "", b.path orelse ""),
        };
    }
    fn lossJson(event: files.LossEvent) LossJson {
        return .{ .sequence = event.sequence, .wall_us = event.wall_us, .reason = @tagName(event.reason), .inode = event.inode, .committed_offset = event.committed_offset, .observed_size = event.observed_size };
    }
    fn writeSources(self: *const Coordinator, writer: anytype, redact: bool) !void {
        var ordered: [max_jails * (max_sources_per_jail + 1)]*const SourceStatus = undefined;
        var count: usize = 0;
        for (self.jails) |*jail| for (jail.source_status) |*entry| {
            ordered[count] = entry;
            count += 1;
        };
        std.sort.pdq(*const SourceStatus, ordered[0..count], {}, sourceStatusOrder);
        try writer.writeByte('[');
        for (ordered[0..count], 0..) |entry, index| {
            if (index != 0) try writer.writeByte(',');
            try std.json.stringify(SourceJson{
                .jail = entry.jail,
                .kind = @tagName(entry.kind),
                .path = if (entry.path != null and redact) redacted_text else entry.path,
                .on_truncation = if (entry.on_truncation) |policy| @tagName(policy) else null,
                .state = @tagName(entry.state),
                .cause = entry.cause,
                .inode = entry.inode,
                .committed_offset = entry.committed_offset,
                .observed_size = entry.observed_size,
                .repair = if (entry.repair != null and redact) redacted_text else entry.repair,
                .loss_events = entry.loss_events,
                .last_loss = if (entry.last_loss) |event| lossJson(event) else null,
            }, .{}, writer);
        }
        try writer.writeByte(']');
    }
    fn statusPayload(self: *Coordinator, out: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator, redact: bool) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const gate = self.published_health;
        const sampled_wall = self.observationWall();
        const sampled_ms = observationMs();
        const effect_ms = monotonic(self);
        const observation = self.worker_observation.read(sampled_ms, sampled_wall);
        var healthy = gate.phase == .healthy and observationSound(observation);
        var decisions: u64 = 0;
        var installed: u32 = 0;
        var unhealthy_sources: u32 = 0;
        var paused_sources: u32 = 0;
        var unpaused_unhealthy: u32 = 0;
        var blocked_source: ?[]const u8 = null;
        const now = sampled_wall orelse self.start_us;
        for (self.jails) |jail| {
            healthy = healthy and jail.healthy;
            if (!jail.healthy) unhealthy_sources += 1;
            if (!jail.healthy and !jailPaused(&jail)) unpaused_unhealthy += 1;
            if (!jail.healthy and blocked_source == null) if (jail.source_error) |cause| if (pipeline.Pipeline.commitBlocked(cause)) {
                blocked_source = @errorName(cause);
            };
            for (jail.source_status) |entry| paused_sources += @intFromBool(entry.state == .paused);
            decisions +|= jail.summary.decisions;
            installed +|= self.confirmedCount(jail, now, effect_ms) orelse 0;
        }
        if (self.published_effects) |effects| healthy = healthy and !(effects.uncertain and !self.published_view.transient_uncertain);
        if (self.backend_failure != null) healthy = false;
        const known = self.knowledge(effect_ms);
        const withdrawn = if (self.published_effects) |effects| effects.withdrawn else false;
        const protection: []const u8 = if (!healthy or withdrawn) "degraded" else if (self.published_effects == null) "log-only" else if (known.? == .none) "unknown" else if (known.? == .stale or self.overBlocking()) "degraded" else "active";
        const active_bans: ?u32 = if (known) |k| (if (k == .none) null else self.published_view.installed_live) else installed;
        const knowledge_cause: ?[]const u8 = if (known) |k| switch (k) {
            .stale => "ReadbackStale",
            .none => if (self.published_effects.?.cause == null) "ReadbackPending" else null,
            .fresh => null,
        } else null;
        const generation_hex = std.fmt.bytesToHex(self.published_generation, .lower);
        const effect_diagnostic = if (self.published_effects) |effects| effects.diagnostic else null;
        const none_cause: []const u8 = if (paused_sources != 0 and unpaused_unhealthy == 0) "SourcePaused" else blocked_source orelse "none";
        const payload_start = out.items.len;
        try std.json.stringify(.{ .version = version, .runtime = "native", .generation = &generation_hex, .mutation_revision = self.published_revision, .state = protection, .protection = protection, .protection_cause = if (self.backend_failure) |failure| @as(?[]const u8, @errorName(failure)) else null, .active_bans = active_bans, .total_bans = self.published_confirmations, .knowledge = if (known) |k| @as(?[]const u8, @tagName(k)) else null, .confirmed_at_us = if (known != null and known.? != .none) self.published_view.readback_wall_us else null, .knowledge_age_ms = if (known != null and known.? != .none) self.knowledgeAgeMs(effect_ms) else null, .pending_bans = if (known != null) @as(?u64, self.published_view.pending) else null, .oldest_pending_ms = if (known != null) ageMs(now, self.published_view.oldest_pending_us) else null, .overdue_removals = if (known != null) @as(?u64, self.published_view.overdue_blocking) else null, .oldest_overdue_ms = if (known != null) ageMs(now, self.published_view.oldest_overdue_blocking_us) else null, .overdue_bookkeeping = if (known != null) @as(?u64, self.published_view.overdue -| self.published_view.overdue_blocking) else null, .dump_interrupted = if (known != null) @as(?u64, self.published_view.dump_interrupted) else null, .storage = @tagName(gate.phase), .cause = if (gate.phase == .intervention and gate.last_failure != null) @errorName(gate.last_failure.?.cause) else if (observation.clock_uncertain) "ClockUncertain" else if (observation.stalled) "WorkerStalled" else if (withdrawn) "FirewallWithdrawn" else if (known != null and known.? == .none and knowledge_cause != null) knowledge_cause.? else if (self.overBlocking()) "EffectRemovalOverdue" else if (knowledge_cause) |cause| cause else if (gate.last_failure) |failure| @errorName(failure.cause) else if (self.published_effects) |effects| if (effects.cause) |cause| @errorName(cause) else none_cause else if (self.backend_failure) |failure| @errorName(failure) else none_cause, .sqlite_code = if (gate.last_failure) |failure| failure.diagnostics.sqlite_code else null, .next_retry_ms = gate.next_retry_ms, .committed_records = gate.committed_records, .decisions_total = decisions, .jails_active = self.jails.len, .unhealthy_sources = unhealthy_sources, .backend = self.published_backend, .effect_backend = if (effect_diagnostic) |detail| @as(?[]const u8, @tagName(detail.backend)) else null, .effect_stage = if (effect_diagnostic) |detail| @as(?[]const u8, @tagName(detail.stage)) else null, .effect_cause = if (effect_diagnostic) |detail| @as(?[]const u8, @errorName(detail.cause)) else null, .effect_mutation = if (effect_diagnostic) |detail| @as(?[]const u8, @tagName(detail.mutation)) else null, .effects_uncertain = observation.expiry_uncertain or (if (self.published_effects) |effects| effects.uncertain else false), .overdue_effects = if (self.published_effects) |effects| effects.overdue else 0, .worker_busy = observation.busy, .worker_stalled = observation.stalled, .worker_busy_age_ms = observation.busy_age_ms, .worker_heartbeat_age_ms = observation.heartbeat_age_ms, .clock_uncertain = observation.clock_uncertain, .expiry_overdue = observation.expiry_overdue, .expiry_uncertain = observation.expiry_uncertain, .next_committed_expiry_us = observation.next_committed_expiry_us, .memory_admission_bytes = self.resources.limit_bytes, .uptime_seconds = if (observation.clock_uncertain) @as(?u64, null) else @as(u64, @intCast(@max(0, @divTrunc(now -| self.start_us, 1_000_000)))) }, .{ .emit_null_optional_fields = false }, out.writer(a));
        if (out.items.len == payload_start or out.items[out.items.len - 1] != '}') return error.InvalidStatusPayload;
        out.items.len -= 1;
        const writer = out.writer(a);
        try writer.print(",\"paused_sources\":{d},\"sources\":", .{paused_sources});
        try self.writeSources(writer, redact);
        try writer.writeByte('}');
    }
    fn knowledge(self: *const Coordinator, now_ms: ?u64) ?Knowledge {
        const effects = self.published_effects orelse return null;
        const view = self.published_view;
        if (effects.uncertain and !view.transient_uncertain) return .none;
        const readback = view.readback_ns orelse return if (effects.ready) .fresh else .none;
        const now = now_ms orelse return .stale;
        const age_ns = (now *| std.time.ns_per_ms) -| readback;
        return if (age_ns <= view.verify_interval_ns +| view.wake_interval_ns) .fresh else .stale;
    }
    fn knowledgeAgeMs(self: *const Coordinator, now_ms: ?u64) ?u64 {
        const readback = self.published_view.readback_ns orelse return null;
        const now = now_ms orelse return null;
        return ((now *| std.time.ns_per_ms) -| readback) / std.time.ns_per_ms;
    }
    fn ageMs(now_us: i64, then_us: ?i64) ?u64 {
        const then = then_us orelse return null;
        return @intCast(@max(0, @divTrunc(now_us -| then, 1000)));
    }
    fn enforcementActive(self: *const Coordinator, observation: health.WorkerStatus, now_ms: ?u64) bool {
        if (!observationSound(observation) or self.published_health.phase != .healthy or self.backend_failure != null or self.overBlocking()) return false;
        if (self.published_effects) |effects| if (effects.withdrawn) return false;
        return (self.knowledge(now_ms) orelse return false) == .fresh;
    }
    fn confirmationKnown(self: *const Coordinator, now_ms: ?u64) bool {
        return if (self.knowledge(now_ms)) |known| known != .none else false;
    }
    fn confirmedCount(self: *const Coordinator, jail: Jail, now: i64, now_ms: ?u64) ?u32 {
        if (self.knowledge(now_ms)) |known| if (known == .none) return null;
        var count: u32 = 0;
        if (self.jailEnforces(&jail)) {
            for (self.owner_active[0..self.owner_count], 0..) |owner, i| {
                if (self.owner_confirmed[i] and owner.lease.live(now) and std.mem.eql(u8, owner.jail.slice(), jail.name)) count += 1;
            }
            return count;
        }
        for (jail.active[0..jail.summary.active], 0..) |decision, i| if (jail.confirmed[i] and decision.lease.live(now)) {
            count += 1;
        };
        return count;
    }
    fn bans(ctx: ?*anyopaque, out: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator) !void {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        try self.writeBans(out, a, null);
    }
    fn formatListSubject(subject: inspection.canonical_scope.Subject, buffer: *[64]u8) ![]const u8 {
        const address: shared.IpAddress = switch (subject.family) {
            .v4 => .{ .ipv4 = std.mem.readInt(u32, subject.address[0..4], .big) },
            .v6 => .{ .ipv6 = std.mem.readInt(u128, &subject.address, .big) },
        };
        return switch (subject.kind) {
            .host => std.fmt.bufPrint(buffer, "{}", .{address}),
            .network => std.fmt.bufPrint(buffer, "{}/{d}", .{ address, subject.prefix }),
        };
    }
    fn writeBans(self: *Coordinator, out: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator, selected: ?shared.JailId) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const sampled_wall = self.observationWall();
        const observation = self.worker_observation.read(observationMs(), sampled_wall);
        const w = out.writer(a);
        try w.writeAll("[");
        var first = true;
        for (self.jails) |jail| {
            if (selected) |name| if (!std.mem.eql(u8, name.slice(), jail.name)) continue;
            if (self.jailEnforces(&jail)) {
                for (self.owner_active[0..self.owner_count], 0..) |owner, i| {
                    if (!std.mem.eql(u8, owner.jail.slice(), jail.name)) continue;
                    if (!observation.clock_uncertain and sampled_wall != null and !owner.lease.live(sampled_wall.?)) continue;
                    if (!first) try w.writeByte(',');
                    first = false;
                    var buffer: [64]u8 = undefined;
                    const formatted = try formatListSubject(owner.scope.canonical.subject, &buffer);
                    const confirmed = self.owner_confirmed[i] and self.confirmationKnown(monotonic(self));
                    const expiry_us: ?i64 = switch (owner.lease) {
                        .finite => |value| value,
                        .permanent => null,
                        .absent => return error.InvalidEffect,
                    };
                    try std.json.stringify(.{ .ip = formatted, .jail = owner.jail.slice(), .expiry_us = expiry_us, .ban_expiry = if (expiry_us) |value| @divFloor(value, 1_000_000) else null, .permanent = owner.lease == .permanent, .ban_count = owner.ordinal, .enforced = confirmed, .confirmed = confirmed }, .{}, w);
                }
                continue;
            }
            for (jail.active[0..jail.summary.active], 0..) |decision, i| {
                if (!observation.clock_uncertain and sampled_wall != null and !decision.lease.live(sampled_wall.?)) continue;
                if (!first) try w.writeByte(',');
                first = false;
                const address: shared.IpAddress = switch (decision.subject) {
                    .v4 => |v| .{ .ipv4 = std.mem.readInt(u32, &v, .big) },
                    .v6 => |v| .{ .ipv6 = std.mem.readInt(u128, &v, .big) },
                };
                var buffer: [64]u8 = undefined;
                const formatted = try std.fmt.bufPrint(&buffer, "{}", .{address});
                const confirmed = jail.confirmed[i] and self.confirmationKnown(monotonic(self));
                const expiry_us: ?i64 = switch (decision.lease) {
                    .finite => |value| value,
                    .permanent => null,
                    .absent => return error.InvalidRetryState,
                };
                try std.json.stringify(.{ .ip = formatted, .jail = jail.name, .expiry_us = expiry_us, .ban_expiry = if (expiry_us) |value| @divFloor(value, 1_000_000) else null, .permanent = decision.lease == .permanent, .ban_count = decision.ordinal, .enforced = confirmed, .confirmed = confirmed }, .{}, w);
            }
        }
        try w.writeAll("]");
        if (out.items.len > shared.protocol.max_payload_size - 16) return error.SnapshotLimit;
    }
    fn metrics(ctx: ?*anyopaque, out: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator) !void {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        self.mutex.lock();
        defer self.mutex.unlock();
        const observation = self.observedWorker();
        try out.writer(a).print("fail2zig_up 1\nfail2zig_native_storage_healthy {d}\nfail2zig_native_committed_records {d}\nfail2zig_native_worker_stalled {d}\nfail2zig_native_worker_busy {d}\nfail2zig_native_worker_heartbeat_age_ms {d}\nfail2zig_native_worker_busy_age_ms {d}\nfail2zig_native_clock_uncertain {d}\nfail2zig_native_expiry_overdue {d}\nfail2zig_native_expiry_uncertain {d}\n", .{ @intFromBool(self.published_health.phase == .healthy and observationSound(observation)), self.published_health.committed_records, @intFromBool(observation.stalled), @intFromBool(observation.busy), observation.heartbeat_age_ms, observation.busy_age_ms, @intFromBool(observation.clock_uncertain), @intFromBool(observation.expiry_overdue), @intFromBool(observation.expiry_uncertain) });
        if (comptime build_options.diag) try diag_mod.writeMetrics(out.writer(a));
        if (comptime build_options.diag) {
            const sample = self.clock.snapshot();
            try out.writer(a).print("f2z_diag_clock_rate {d}\nf2z_diag_clock_wall_us {d}\nf2z_diag_clock_regressions {d}\n", .{ sample.rate, sample.wall_us, sample.regressions });
        }
    }
    fn commandAuth(ctx: ?*anyopaque, cmd: shared.Command, peer: ipc.Peer, a: std.mem.Allocator) !shared.Response {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
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
            .admin_serving = if (self.ipc_server) |server| server.isServing() else true,
        };
    }
    fn readinessReport(self: *Coordinator) readiness.Report {
        var jails: [max_jails]readiness.Jail = undefined;
        self.mutex.lock();
        defer self.mutex.unlock();
        return readiness.derive(self.readinessInputs(&jails));
    }
    fn healthView(ctx: ?*anyopaque, out: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator) !void {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        const report = self.readinessReport();
        try readiness.writeJson(report, out.writer(a));
    }
    const StatusQuery = struct { coordinator: *Coordinator, redact: bool };
    fn statusCallback(ctx: ?*anyopaque, a: std.mem.Allocator, out: *std.ArrayList(u8)) anyerror!void {
        const query: *StatusQuery = @ptrCast(@alignCast(ctx.?));
        var unmanaged: std.ArrayListUnmanaged(u8) = .{};
        defer unmanaged.deinit(a);
        try query.coordinator.statusPayload(&unmanaged, a, query.redact);
        try out.appendSlice(unmanaged.items);
    }
    fn healthCallback(ctx: ?*anyopaque, a: std.mem.Allocator, out: *std.ArrayList(u8)) anyerror!void {
        var unmanaged: std.ArrayListUnmanaged(u8) = .{};
        defer unmanaged.deinit(a);
        try healthView(ctx, &unmanaged, a);
        try out.appendSlice(unmanaged.items);
    }
    fn continuityRender(ctx: ?*anyopaque, arena: std.mem.Allocator, cursor: ?u64, limit: u16, redact: bool, out: *query_v1.JsonStream) anyerror!void {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        const reader = if (self.history_reader) |*value| value else return error.HistoryUnavailable;
        const events = try arena.alloc(files.LossEvent, limit);
        const count = try reader.continuityEvents(null, cursor, events, arena);
        try out.objectField("items");
        try out.beginArray();
        for (events[0..count]) |event| {
            try out.beginObject();
            try out.objectField("sequence");
            try out.write(event.sequence);
            try out.objectField("jail");
            try out.write(event.jail);
            try out.objectField("path");
            try out.write(if (redact) redacted_text else event.path);
            try out.objectField("wall_us");
            try out.write(event.wall_us);
            try out.objectField("reason");
            try out.write(@tagName(event.reason));
            try out.objectField("inode");
            try out.write(event.inode);
            try out.objectField("committed_offset");
            try out.write(event.committed_offset);
            try out.objectField("observed_size");
            try out.write(event.observed_size);
            try out.endObject();
        }
        try out.endArray();
        try out.objectField("next_cursor");
        if (count == limit and count != 0) {
            var buffer: [20]u8 = undefined;
            try out.write(try std.fmt.bufPrint(&buffer, "{d}", .{events[count - 1].sequence}));
        } else try out.write(null);
    }
    fn writeIgnoreJail(out: *query_v1.JsonStream, name: []const u8, enabled: bool, ignore_file: ?[]const u8, items: []const ignore_set.Item, hostnames: []const []const u8, redact: bool) !void {
        try out.beginObject();
        try out.objectField("jail");
        try out.write(name);
        try out.objectField("enabled");
        try out.write(enabled);
        try out.objectField("count");
        try out.write(items.len + hostnames.len);
        try out.objectField("ignore_file");
        try out.write(if (ignore_file != null and redact) @as(?[]const u8, redacted_text) else ignore_file);
        try out.objectField("entries");
        try out.beginArray();
        for (items) |item| {
            var buffer: [64]u8 = undefined;
            try out.beginObject();
            try out.objectField("address");
            try out.write(if (redact) redacted_text else item.entry.canonical(&buffer));
            try out.objectField("source");
            try out.write(ignoreSourceText(item.source).?);
            try out.endObject();
        }
        for (hostnames) |literal| {
            try out.beginObject();
            try out.objectField("address");
            try out.write(if (redact) redacted_text else literal);
            try out.objectField("source");
            try out.write("config");
            try out.endObject();
        }
        try out.endArray();
        try out.endObject();
    }
    fn configuredIgnoreItems(arena: std.mem.Allocator, literals: []const []const u8, runtime: []const shared.types.IgnoreEntry, hostnames: *[]const []const u8) ![]const ignore_set.Item {
        const parseable = try arena.alloc([]const u8, literals.len);
        const names = try arena.alloc([]const u8, literals.len);
        var parseable_count: usize = 0;
        var name_count: usize = 0;
        for (literals) |literal| {
            if (shared.types.IgnoreEntry.parse(literal)) |_| {
                parseable[parseable_count] = literal;
                parseable_count += 1;
            } else |_| {
                names[name_count] = literal;
                name_count += 1;
            }
        }
        std.sort.pdq([]const u8, names[0..name_count], {}, hostnameLess);
        hostnames.* = names[0..name_count];
        const list = try ignore_set.EffectiveIgnore.build(arena, parseable[0..parseable_count], runtime);
        return list.entries;
    }
    fn hostnameLess(_: void, a: []const u8, b: []const u8) bool {
        return std.mem.lessThan(u8, a, b);
    }
    fn jailNameLess(self: *const Coordinator, a: usize, b: usize) bool {
        return std.mem.lessThan(u8, self.jails[a].name, self.jails[b].name);
    }
    fn ignoreRender(ctx: ?*anyopaque, arena: std.mem.Allocator, jail_filter: ?[]const u8, redact: bool, out: *query_v1.JsonStream) anyerror!void {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        const reader = if (self.history_reader) |*value| value else return error.HistoryUnavailable;
        var stored: [128]durable.Store.IgnoreJailCount = undefined;
        const stored_count = try reader.ignoreEntryJails(&stored);
        var filtered: [ignore_set.max_entries_per_part]shared.types.IgnoreEntry = undefined;
        var filtered_count: usize = 0;
        if (jail_filter) |name| filtered_count = try reader.ignoreEntries(name, &filtered);
        try out.objectField("limit");
        try out.write(ignore_set.distinct_bound);
        try out.objectField("jails");
        try out.beginArray();
        self.mutex.lock();
        defer self.mutex.unlock();
        var order: [max_jails]usize = undefined;
        var selected: usize = 0;
        for (self.jails, 0..) |jail, index| {
            if (jail_filter) |name| if (!std.mem.eql(u8, name, jail.name)) continue;
            order[selected] = index;
            selected += 1;
        }
        std.sort.pdq(usize, order[0..selected], @as(*const Coordinator, self), jailNameLess);
        for (order[0..selected]) |index| {
            const jail = &self.jails[index];
            const jail_cfg = findConfigJail(self.live_cfg, jail.name);
            var hostnames: []const []const u8 = &.{};
            const items = if (ignoreCell(jail)) |cell| cell.*.entries else blk: {
                const literals = if (jail_cfg) |value| value.ignoreip orelse self.live_cfg.defaults.ignoreip else &[_][]const u8{};
                break :blk try configuredIgnoreItems(arena, literals, &.{}, &hostnames);
            };
            try writeIgnoreJail(out, jail.name, jail.admin_enabled, if (jail_cfg) |value| value.ignore_file else null, items, hostnames, redact);
        }
        if (jail_filter) |name| if (selected == 0) {
            const jail_cfg = findConfigJail(self.live_cfg, name);
            if (jail_cfg == null and filtered_count == 0) return error.UnknownJail;
            var hostnames: []const []const u8 = &.{};
            const literals = if (jail_cfg) |value| (if (value.rule_files.len != 0) &[_][]const u8{} else value.ignoreip orelse self.live_cfg.defaults.ignoreip) else &[_][]const u8{};
            const items = try configuredIgnoreItems(arena, literals, filtered[0..filtered_count], &hostnames);
            try writeIgnoreJail(out, name, false, if (jail_cfg) |value| value.ignore_file else null, items, hostnames, redact);
        };
        try out.endArray();
        try out.objectField("unconfigured");
        try out.beginArray();
        if (jail_filter == null) for (stored[0..stored_count]) |item| {
            const name = item.jail[0..item.jail_len];
            if (findConfigJail(self.live_cfg, name) != null) continue;
            try out.beginObject();
            try out.objectField("jail");
            try out.write(name);
            try out.objectField("runtime_entries");
            try out.write(item.count);
            try out.endObject();
        };
        try out.endArray();
    }
    const history_scan_pages = 16;
    fn historyRead(ctx: ?*anyopaque, jail: ?[]const u8, after_sequence: u64, limit: u16, out: *std.ArrayList(query_v1.HistoryEvent)) anyerror!query_v1.HistoryRead {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        const reader = if (self.history_reader) |*value| value else return error.HistoryUnavailable;
        const installation = try reader.readInstallation() orelse return .{ .more = false, .resume_after = after_sequence };
        var events: [history.max_page]history.Event = undefined;
        var after = after_sequence;
        var appended: usize = 0;
        var pages: usize = 0;
        while (appended < limit and pages < history_scan_pages) : (pages += 1) {
            const page = try reader.confirmedEffectPage(installation, after, null, &events);
            if (page.count == 0) return .{ .more = false, .resume_after = after };
            for (events[0..page.count]) |event| {
                if (appended == limit) return .{ .more = true, .resume_after = after };
                after = event.sequence;
                if (jail) |wanted| if (!std.mem.eql(u8, wanted, event.jail.slice())) continue;
                try out.append(.{ .sequence = event.sequence, .event_id = event.event_id, .jail = try out.allocator.dupe(u8, event.jail.slice()), .decision_id = event.decision_id, .confirmed_us = event.confirmed_us, .scope = try query_v1.projectScope(event.scope.canonical), .native_retry = event.native_retry });
                appended += 1;
            }
            if (!page.more) return .{ .more = false, .resume_after = after };
        }
        return .{ .more = true, .resume_after = after };
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

    fn firewallRead(ctx: ?*anyopaque, request: firewall_observation.PageRequest, out: *firewall_observation.Page) anyerror!void {
        const cache: *firewall_observation.Cache = @ptrCast(@alignCast(ctx.?));
        try cache.readPage(request, out);
    }
    fn queryResponse(self: *Coordinator, a: std.mem.Allocator, body: []const u8, peer_class: query_v1.PeerClass) !shared.Response {
        var arena_state = std.heap.ArenaAllocator.init(a);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var scope_storage: []query_v1.ScopeItem = &.{};
        defer a.free(scope_storage);
        const requested_kind = query_v1.requestedKind(arena, body);
        if (requested_kind == .stats) {
            self.mutex.lock();
            var snapshot = self.published_stats;
            const generation = if (snapshot.available) self.stats_generation else self.published_generation;
            const now_ms = observationMs();
            const now_wall = self.observationWall();
            const observation = self.worker_observation.read(now_ms, now_wall);
            if (snapshot.available) {
                const effect_ms = monotonic(self);
                const known = self.knowledge(effect_ms) orelse .none;
                snapshot.knowledge = @tagName(known);
                snapshot.knowledge_age_ms = if (known == .none) null else self.knowledgeAgeMs(effect_ms);
                if (known == .none) snapshot.last_observed_installed = null;
                if (!observation.clock_uncertain) {
                    if (now_ms) |now| if (self.stats_published_ms) |then| {
                        if (now >= then) snapshot.snapshot_age_ms = now - then;
                    };
                    if (now_wall) |now| snapshot.uptime_seconds = @intCast(@max(0, @divTrunc(now -| self.start_us, 1_000_000)));
                }
            } else {
                snapshot.reason = if (self.backend_failure != null or self.suppress_enforcement) "backend_unavailable" else if (self.startup_backend != null) "not_published" else "log_only";
                snapshot.backend = if (self.startup_backend) |backend| @tagName(backend) else null;
            }
            self.mutex.unlock();
            const result = try query_v1.handle(a, body, peer_class, generation, .{ .stats = snapshot });
            return switch (result) {
                .payload => |bytes| .{ .ok = .{ .payload = bytes } },
                .failure => |failure| .{ .err = .{ .code = failure.code, .message = try a.dupe(u8, failure.message) } },
            };
        }
        const firewall_request = requested_kind != null and requested_kind.? == .firewall;
        var generation: [32]u8 = undefined;
        var config_view: ?query_v1.ConfigView = null;
        var scopes_view: ?query_v1.ScopesView = null;
        var firewall_source: ?query_v1.FirewallSource = null;
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            generation = self.published_generation;
            if (firewall_request) {
                firewall_source = if (self.firewall_observation_cache) |cache|
                    .{ .cache = .{ .ctx = cache, .read = firewallRead } }
                else
                    .{ .unavailable = self.firewall_observation_unavailable };
            } else {
                const cfg = self.live_cfg;
                const jail_configs = try arena.alloc(query_v1.JailConfig, self.jails.len);
                const jail_scopes = try arena.alloc(query_v1.JailScopes, self.jails.len);
                const window: ?query_v1.ScopesWindow = if (requested_kind == .scopes) query_v1.scopesWindow(arena, body) else null;
                var counts: [max_jails]usize = [_]usize{0} ** max_jails;
                var starts: [max_jails]usize = [_]usize{0} ** max_jails;
                var takes: [max_jails]usize = [_]usize{0} ** max_jails;
                var total: usize = 0;
                if (window) |win| {
                    var filter: ?usize = null;
                    if (win.jail) |name| for (self.jails, 0..) |jail, i| {
                        if (std.mem.eql(u8, jail.name, name)) filter = i;
                    };
                    const first: usize = if (win.cursor_jail) |value| value else filter orelse 0;
                    var remaining: usize = win.limit;
                    for (self.jails, 0..) |jail, i| {
                        counts[i] = if (self.jailEnforces(&jail)) blk: {
                            var count: usize = 0;
                            for (self.owner_active[0..self.owner_count]) |owner| if (std.mem.eql(u8, owner.jail.slice(), jail.name)) {
                                count += 1;
                            };
                            break :blk count;
                        } else jail.summary.active;
                        if (i < first or (filter != null and filter.? != i)) continue;
                        starts[i] = if (i == first and win.cursor_jail != null) self.keysetStart(&jail, win.cursor_key.slice()) else 0;
                        takes[i] = @min(remaining, counts[i] - starts[i]);
                        remaining -= takes[i];
                        total += takes[i];
                    }
                }
                scope_storage = try a.alloc(query_v1.ScopeItem, total);
                var scope_offset: usize = 0;
                const now = self.observationWall() orelse self.start_us;
                for (self.jails, 0..) |jail, i| {
                    const source_cfg = findConfigJail(cfg, jail.name);
                    const bantime: u64 = switch (jail.policy.duration) {
                        .finite_us => |value| @intCast(@divTrunc(value, 1_000_000)),
                        .permanent => 0,
                    };
                    jail_configs[i] = .{ .name = jail.name, .enabled = jail.admin_enabled, .filter = if (source_cfg) |c| c.filter else "", .source = @tagName(jail.plan), .logpath = if (source_cfg) |c| c.logpath else &.{}, .maxretry = jail.policy.maxretry, .findtime = @intCast(@divTrunc(jail.policy.window_us, 1_000_000)), .bantime = bantime, .bantime_permanent = jail.policy.duration == .permanent, .banaction = if (self.jailEnforces(&jail)) self.published_backend else "log-only", .ignoreip = if (source_cfg) |c| (c.ignoreip orelse cfg.defaults.ignoreip) else &.{} };
                    const items = scope_storage[scope_offset..][0..takes[i]];
                    scope_offset += takes[i];
                    if (self.jailEnforces(&jail)) {
                        var k: usize = 0;
                        var seen: usize = 0;
                        for (self.owner_active[0..self.owner_count], 0..) |owner, owner_index| {
                            if (!std.mem.eql(u8, owner.jail.slice(), jail.name)) continue;
                            if (seen < starts[i]) {
                                seen += 1;
                                continue;
                            }
                            if (k == items.len) break;
                            items[k] = .{ .scope = try query_v1.projectScope(owner.scope.canonical), .lease = if (owner.lease == .permanent) .permanent else .finite, .deadline_us = if (owner.lease == .finite) owner.lease.finite else null, .decision_id = owner.decision_id, .confirmed = self.owner_confirmed[owner_index] and owner.lease.live(now) and self.confirmationKnown(monotonic(self)), .ban_count = owner.ordinal, .key = query_v1.ItemKey.init(&owner.key) };
                            k += 1;
                        }
                    } else {
                        for (jail.active[starts[i]..][0..items.len], 0..) |decision, k| {
                            var address = [_]u8{0} ** 16;
                            const family: query_v1.Family = switch (decision.subject) {
                                .v4 => |v| blk: {
                                    @memcpy(address[0..4], &v);
                                    break :blk .v4;
                                },
                                .v6 => |v| blk: {
                                    @memcpy(address[0..16], &v);
                                    break :blk .v6;
                                },
                            };
                            items[k] = .{ .scope = .{ .family = family, .address = address, .prefix = if (family == .v4) 32 else 128 }, .lease = if (decision.lease == .permanent) .permanent else .finite, .deadline_us = if (decision.lease == .finite) decision.lease.finite else null, .decision_id = null, .confirmed = jail.confirmed[starts[i] + k] and decision.lease.live(now) and self.confirmationKnown(monotonic(self)), .ban_count = decision.ordinal, .key = decisionKey(decision.subject) };
                        }
                    }
                    jail_scopes[i] = .{ .name = jail.name, .items = items, .count = counts[i], .offset = starts[i] };
                }
                config_view = .{ .jails = jail_configs, .global = .{ .log_level = @tagName(cfg.global.log_level), .firewall = @tagName(cfg.global.firewall), .metrics_enabled = cfg.global.metrics_enabled, .metrics_bind = cfg.global.metrics_bind, .metrics_port = cfg.global.metrics_port, .socket_path = cfg.global.socket_path, .state_file = cfg.global.state_file, .dns_server = cfg.global.dns_server, .timezone_root = cfg.global.timezone_root } };
                if (window != null) scopes_view = .{ .jails = jail_scopes };
            }
        }
        var status_query = StatusQuery{ .coordinator = self, .redact = peer_class == .monitor };
        const result = try query_v1.handle(a, body, peer_class, generation, .{ .status = .{ .ctx = &status_query, .func = statusCallback }, .health = .{ .ctx = self, .func = healthCallback }, .config = config_view, .scopes = scopes_view, .history = .{ .ctx = self, .read = historyRead }, .firewall = firewall_source, .ignore = .{ .ctx = self, .render = ignoreRender }, .continuity = .{ .ctx = self, .render = continuityRender } });
        return switch (result) {
            .payload => |bytes| .{ .ok = .{ .payload = bytes } },
            .failure => |failure| .{ .err = .{ .code = failure.code, .message = try a.dupe(u8, failure.message) } },
        };
    }
    fn decisionKey(subject: detection.Subject) query_v1.ItemKey {
        var bytes: [17]u8 = undefined;
        return switch (subject) {
            .v4 => |v| blk: {
                bytes[0] = 4;
                @memcpy(bytes[1..5], &v);
                break :blk query_v1.ItemKey.init(bytes[0..5]);
            },
            .v6 => |v| blk: {
                bytes[0] = 6;
                @memcpy(bytes[1..17], &v);
                break :blk query_v1.ItemKey.init(bytes[0..17]);
            },
        };
    }
    fn keysetStart(self: *const Coordinator, jail: *const Jail, cursor: []const u8) usize {
        var count: usize = 0;
        if (self.jailEnforces(jail)) {
            for (self.owner_active[0..self.owner_count]) |owner| {
                if (!std.mem.eql(u8, owner.jail.slice(), jail.name)) continue;
                if (std.mem.order(u8, &owner.key, cursor) == .gt) break;
                count += 1;
            }
        } else for (jail.active[0..jail.summary.active]) |decision| {
            const key = decisionKey(decision.subject);
            if (std.mem.order(u8, key.slice(), cursor) == .gt) break;
            count += 1;
        }
        return count;
    }
    fn findConfigJail(cfg: *const config.Config, name: []const u8) ?*const config.JailConfig {
        for (cfg.jails) |*jail| if (std.mem.eql(u8, jail.name, name)) return jail;
        return null;
    }
    fn command(ctx: ?*anyopaque, cmd: shared.Command, a: std.mem.Allocator) !shared.Response {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        var output: std.ArrayListUnmanaged(u8) = .{};
        defer output.deinit(a);
        switch (cmd) {
            .status => try status(self, &output, a),
            .version => try std.json.stringify(.{ .daemon_version = version }, .{}, output.writer(a)),
            .list => |selected| try self.writeBans(&output, a, selected.jail),
            .list_jails => {
                self.mutex.lock();
                defer self.mutex.unlock();
                const sampled_wall = self.observationWall();
                const sampled_ms = observationMs();
                const observation = self.worker_observation.read(sampled_ms, sampled_wall);
                const w = output.writer(a);
                try w.writeAll("[");
                for (self.jails, 0..) |jail, index| {
                    if (index > 0) try w.writeByte(',');
                    const bantime: ?i64 = switch (jail.policy.duration) {
                        .finite_us => |value| @divTrunc(value, 1_000_000),
                        .permanent => null,
                    };
                    try std.json.stringify(.{ .name = jail.name, .healthy = jail.healthy and self.published_health.phase == .healthy and observationSound(observation), .enabled = jail.admin_enabled, .paused = jail.admin_paused, .active_bans = self.confirmedCount(jail, sampled_wall orelse self.start_us, monotonic(self)), .maxretry = jail.policy.maxretry, .findtime = @divTrunc(jail.policy.window_us, 1_000_000), .bantime = bantime, .bantime_permanent = jail.policy.duration == .permanent, .action = if (self.jailEnforces(&jail)) self.published_backend else "log-only", .enforce_configured = jail.policy.enforce, .enforcing = self.jailEnforces(&jail) and self.enforcementActive(observation, monotonic(self)), .log_source = @tagName(jail.plan), .source_healthy = jail.healthy, .source_paused = jailPaused(&jail), .source_missing = jail.source_missing, .source = @tagName(jail.plan), .revision = jail.revision, .decisions = jail.summary.decisions, .cause = if (jail.source_error) |cause| @errorName(cause) else "none", .source_exit_code = if (jail.source_diagnostic) |detail| detail.exit_code else null, .source_signal = if (jail.source_diagnostic) |detail| detail.signal else null, .source_stderr_present = if (jail.source_diagnostic) |detail| @as(?bool, detail.stderr_present) else null }, .{}, w);
                }
                try w.writeAll("]");
            },
            .ban, .unban => return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "legacy ban/unban are retired; use admin_v1") } },
            .reload => return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "legacy reload is retired; use reload_v1") } },
            .reload_v1 => return self.reloadResponse(&output, a),
            .admin_v1 => |request| return self.adminResponse(&output, a, request),
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
fn reloadSignal(_: *const std.os.linux.signalfd_siginfo, ctx: ?*anyopaque) void {
    const coordinator: *Coordinator = @ptrCast(@alignCast(ctx.?));
    const outcome = coordinator.stageReload(2000);
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
    coordinator.ipc_server = &server;
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
        web.?.setBansSource(.{ .ctx = coordinator, .write = Coordinator.bans });
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
    const backend_name = if (coordinator.startup_backend) |selected| @tagName(selected) else "none";
    std.log.info("fail2zig {s} running; backend={s}; native SQLite ingestion; protection admission pending; ipc={s}; http={s}", .{ version, backend_name, cfg.global.socket_path, if (cfg.global.metrics_enabled) cfg.global.metrics_bind else "off" });
    try loop.run();
}
