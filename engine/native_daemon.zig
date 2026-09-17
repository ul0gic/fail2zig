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
const effect_runtime = @import("native_effect_runtime.zig");
const consumer_runtime = @import("native_consumer_runtime.zig");
const consumer_plan = @import("config/native_consumer_plan.zig");
const consumer_bridge = @import("core/native_consumer_coordinator.zig");
const resource = @import("native_resource_budget.zig");
const history = @import("core/native_effect_history.zig");
const recurrence = @import("core/native_recurrence.zig");
const firewall_backend = @import("firewall/backend.zig");
const inspection = @import("firewall/inspection.zig");
const path_guard = @import("config/native_paths.zig");
const durable = @import("core/record_store.zig");
const sessions = @import("core/native_file_session.zig");
const journal_projection = @import("config/native_journal_detection.zig");
const journal_profile = @import("config/native_journal_profile.zig");

// Keep the released query byte-for-byte for existing explicit profiles: it is
// included in persistent source identity. New automatic auth-helper layouts
// get their own query; changing an existing profile still requires admission.
// These static slices remain valid for the lifetime of every journal plan.
const legacy_ssh_matches: []const []const u8 = &.{ "SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session", "+", "_COMM=sshd", "_COMM=sshd-session" };
const auth_ssh_matches: []const []const u8 = &.{ "SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session", "SYSLOG_IDENTIFIER=sshd-auth", "+", "_COMM=sshd", "_COMM=sshd-session", "_COMM=sshd-auth" };
const journal_sessions = @import("core/native_journal_session.zig");
const health = @import("core/storage_health.zig");
const recovery = @import("core/native_recovery.zig");
const loop_mod = @import("core/event_loop.zig");
const ipc = @import("net/ipc.zig");
const http = @import("net/http.zig");
const version = @import("build_options").version;
const reload_mod = @import("native_reload.zig");
const log_level = @import("core/log_level.zig");
const query_v1 = @import("net/query_v1.zig");
const readiness = @import("core/readiness.zig");
const sd_notify = @import("core/sd_notify.zig");
const log_target = @import("core/log_target.zig");
const max_jails = 64;
const max_sources_per_jail = 8;
const max_subjects_total = 4096;

fn notifyReloadReady(report: readiness.Report, notifier: anytype) void {
    if (!report.ready) return;
    _ = notifier.ready() catch |err| std.log.warn("sd_notify READY failed after reload: {s}", .{@errorName(err)});
}

test "native daemon BUG-040: list subject preserves typed network prefix" {
    const testing = std.testing;
    var buffer: [64]u8 = undefined;

    const host = inspection.canonical_scope.Subject.host(try shared.IpAddress.parse("198.51.100.7"));
    try testing.expectEqualStrings("198.51.100.7", try Coordinator.formatListSubject(host, &buffer));

    const network = try inspection.canonical_scope.Subject.network(try shared.IpAddress.parse("192.0.2.0"), 24);
    try testing.expectEqualStrings("192.0.2.0/24", try Coordinator.formatListSubject(network, &buffer));

    const exact_network = try inspection.canonical_scope.Subject.network(try shared.IpAddress.parse("203.0.113.9"), 32);
    try testing.expectEqualStrings("203.0.113.9/32", try Coordinator.formatListSubject(exact_network, &buffer));
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
    fn poll(self: Source) !void {
        switch (self) {
            .file => |source| {
                _ = try source.pollTurn(1);
            },
            .journal => |source| {
                _ = try source.pollTurn(1);
            },
            .internal => {},
        }
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
            .file => |source| source.admission_phase == .ready and source.sources.sources.items.len > 0 and source.repairSnapshot().phase == .healthy,
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
const Jail = struct {
    name: []const u8,
    plan: Plan,
    policy: retry.Policy,
    session: ?Source = null,
    source_snapshot: ?SourceSnapshot = null,
    custom_plan: ?*consumer_plan.Prepared = null,
    consumer: ?*consumer_runtime.JailRuntime = null,
    scratch: []durable.Store.ActiveDecision,
    active: []durable.Store.ActiveDecision,
    scratch_confirmed: []bool,
    confirmed: []bool,
    summary: durable.Store.RetrySummary = .{},
    published_once: bool = false,
    revision: u64 = 0,
    healthy: bool = false,
    source_error: ?anyerror = null,
    zone: ?*timezone.Zone = null,
    maintenance_source: usize = 0,
    retire_next: bool = false,
    retire_after: ?detection.Subject = null,
    rekeyed: bool = false,
    admin_paused: bool = false,
    admin_enabled: bool = true,
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
    var probe = inspection.Inspector.open(a, effect_runtime.transportInstallation(candidate), .{}) catch |cause| return .{ .unavailable = cause };
    defer probe.close();
    var observed = probe.inspect() catch |cause| return .{ .unavailable = cause };
    observed.deinit();
    if (persisted == null) probe.inspectReservedNamespace() catch |cause| return .{ .unavailable = cause };
    return .{ .selected = .{ .installation = candidate, .persisted = persisted != null } };
}

pub const Coordinator = struct {
    allocator: std.mem.Allocator,
    cfg: *const config.Config,
    jails: []Jail,
    store: durable.Store,
    store_open: bool = false,
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
    published_backend: []const u8 = "none",
    startup_backend: ?effect.Backend = null,
    startup_installation: ?effect.Installation = null,
    startup_installation_persisted: bool = false,
    preflight_schema_version: i64 = 0,
    preflight_installation: ?effect.Installation = null,
    backend_failure: ?anyerror = null,
    suppress_enforcement: bool = false,
    published_confirmations: u64 = 0,
    owner_scratch: []durable.Store.OperatorOwner = &.{},
    owner_active: []durable.Store.OperatorOwner = &.{},
    owner_scratch_confirmed: []bool = &.{},
    owner_confirmed: []bool = &.{},
    owner_count: usize = 0,
    timer: std.time.Timer,
    gate: health.Gate,
    published_health: health.Snapshot,
    worker_observation: health.WorkerObservation = .{},
    maintenance_validation: durable.Store.MaintenanceValidation = .{},
    maintenance_validated: bool = false,
    maintenance_jail: usize = 0,
    mutex: std.Thread.Mutex = .{},
    stop_mutex: std.Thread.Mutex = .{},
    wake: std.Thread.Condition = .{},
    stopping: bool = false,
    thread: ?std.Thread = null,
    start_us: i64,
    last_notice: u64 = 0,
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
    config_path: []const u8 = "",
    live_cfg: *const config.Config,
    live_arena: ?*std.heap.ArenaAllocator = null,
    reload_request: ?*ReloadRequest = null,
    admin_request: ?*AdminRequest = null,
    reload_wake: std.Thread.Condition = .{},
    published_revision: u64 = 0,
    notifier: ?*const sd_notify.Notifier = null,
    notified_ready: bool = false,
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
        return self.timer.read() / std.time.ns_per_ms;
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
        fn jailName(self: *const AdminRequest) []const u8 {
            return self.jail[0..self.jail_len];
        }
    };

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
        if (abandoned) self.allocator.destroy(request);
        std.log.info("native admin: kind={s} outcome={s}", .{ @tagName(outcome.kind), @tagName(outcome.outcome) });
    }
    fn adminDetail(self: *Coordinator, request: *AdminRequest, view: AdminOutcomeView, state: ?durable.Store.JailAdminState) AdminOutcomeView {
        var out = view;
        out.generation = self.published_generation;
        const now = std.time.microTimestamp();
        const revision = self.store.finishAdminRequest(.{ .request_id = request.request_id, .kind = request.kind, .subject = request.jailName(), .outcome = view.outcome, .generation = self.published_generation, .committed_us = @max(0, now), .detail = view.reason.slice() }, state) catch |err| {
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
        try self.gate.admitMutation();
        switch (try self.store.admitAdminRequest(request.request_id, request.expected_revision)) {
            .replayed => |prior| return .{ .outcome = prior.outcome, .kind = prior.kind, .generation = self.published_generation, .mutation_revision = prior.mutation_revision },
            .fresh => {},
        }
        if (!std.mem.eql(u8, &request.expected_generation, &self.published_generation)) return self.adminDetail(request, base.withReason("stale generation; reload happened", .{}), null).withOutcome(.rejected);
        const now = std.time.microTimestamp();
        switch (kind) {
            .setting_batch => return self.adminDetail(request, (AdminOutcomeView{ .outcome = .rejected, .kind = kind }).withReason("runtime-only settings are not supported; edit the configuration and reload", .{}), null),
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
                            const released = try self.store.flushJailOwner(jail.name, try self.plannedGeneration(jail), transition, .{ .prepared_us = now, .context = self, .read = wallClockEffect });
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
                const generation = try self.plannedGeneration(jail);
                const current = try self.store.currentOwner(key, jail.name);
                const clock = effect.Clock{ .prepared_us = now, .context = self, .read = wallClockEffect };
                if (kind == .ban) {
                    const duration: @import("core/native_lease.zig").Duration = if (request.duration_s) |seconds| try @import("core/native_lease.zig").Duration.finiteSeconds(seconds) else jail.policy.duration;
                    const lease = try duration.lease(now);
                    _ = try self.store.setOwnerFromCanonical(.{ .scope = canonical, .jail = jail.name, .generation = generation, .decision_id = request.request_id, .expected_revision = if (current) |owner| owner.revision else 0, .lease = lease, .decided_us = now }, clock);
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
            generations[count] = .{ .jail = jail.name, .generation = try self.plannedGeneration(jail) };
            count += 1;
        }
        const seq = try self.store.beginMigrationStep(run_id, .activate_owners, "", now);
        const clock = effect.Clock{ .prepared_us = now, .context = self, .read = wallClockEffect };
        const activated = self.store.activateStagedOwners(run_id, generations[0..count], clock) catch |err| {
            try self.store.finishMigrationStep(run_id, seq, .operational_failure, @errorName(err), null, std.time.microTimestamp());
            return self.adminDetail(request, (AdminOutcomeView{ .outcome = .rejected, .kind = request.kind }).withReason("activation failed: {s}", .{@errorName(err)}), null);
        };
        request.mutation_committed = true;
        request.committed_count = activated;
        try self.store.finishMigrationStep(run_id, seq, .success, "", .activating, std.time.microTimestamp());
        request.verify_seq = try self.store.beginMigrationStep(run_id, .verify_protection, "", std.time.microTimestamp());
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
        const now = std.time.microTimestamp();
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
            const staged_count = self.store.migrationStagedKeys(run_id, keys) catch |err| return (view.withOutcome(.uncertain)).withReason("staged scopes unreadable: {s}", .{@errorName(err)});
            var realized: usize = 0;
            for (keys[0..staged_count]) |key| {
                for (manager.live[0..manager.count]) |entry| if (std.mem.eql(u8, &entry.scope_key, &key) and entry.status == .applied and entry.desired.live(now)) {
                    realized += 1;
                    break;
                };
            }
            const coherent = manager.status.ready and manager.cached_epoch != null and manager.cached_epoch.? == self.store.effect_publication_epoch;
            if (coherent and realized == 0 and report.found == 0) {
                view.outcome = .applied;
                view.destination = "absent";
                return view.withReason("every migrated scope released; {d} staged scopes absent in the kernel", .{staged_count});
            }
            if (monotonic(self) < request.deadline_ms) return null;
            view.destination = "partial";
            return view.withReason("{d} of {d} migrated scopes still realized after the deadline", .{ realized, staged_count });
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
        self.store.finishMigrationStep(run_id, request.verify_seq, outcome, view.reason.slice(), if (outcome == .success) .complete else null, std.time.microTimestamp()) catch |err| {
            std.log.err("native migration: verify outcome {s} could not be recorded: {s}", .{ @tagName(outcome), @errorName(err) });
        };
    }
    fn withdrawRealizedEffects(self: *Coordinator) void {
        const manager = self.effects orelse return;
        var settle: usize = 0;
        while (settle < 64) : (settle += 1) {
            if (manager.status.ready and manager.cached_epoch != null and manager.cached_epoch.? == self.store.effect_publication_epoch) break;
            var bindings: [max_jails]effect_runtime.Binding = undefined;
            self.effectBindings(&bindings);
            _ = manager.turn(bindings[0..self.jails.len]) catch |err| {
                std.log.warn("native: stop left realized rules in place: reconciliation {s}; restart reconciles them", .{@errorName(err)});
                return;
            };
        }
        const epoch = manager.repair_epoch;
        var turns: usize = 0;
        while (turns <= effect.max_effects) : (turns += 1) {
            const done = manager.stopTurn(epoch) catch |err| {
                std.log.warn("native: stop left realized rules in place after {d} turns: {s}; restart reconciles them", .{ turns, @errorName(err) });
                return;
            };
            if (done) {
                std.log.info("native: stop withdrew realized rules in {d} turns; owners and deadlines retained", .{turns});
                return;
            }
        }
        std.log.warn("native: stop withdrawal exceeded its bound; restart reconciles the remainder", .{});
    }
    fn wallClockEffect(_: ?*anyopaque) i64 {
        return std.time.microTimestamp();
    }
    fn settleAdmin(self: *Coordinator, request: *AdminRequest) void {
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
                const now = std.time.microTimestamp();
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
    fn wallClock(_: ?*anyopaque) !i64 {
        return std.time.microTimestamp();
    }
    fn observationMs() ?u64 {
        const sample = std.posix.clock_gettime(.MONOTONIC) catch return null;
        if (sample.sec < 0 or sample.nsec < 0 or sample.nsec >= std.time.ns_per_s) return null;
        return std.math.cast(u64, @as(i128, sample.sec) * 1000 + @divTrunc(sample.nsec, std.time.ns_per_ms));
    }
    fn observationWall() ?i64 {
        const sample = std.posix.clock_gettime(.REALTIME) catch return null;
        if (sample.nsec < 0 or sample.nsec >= std.time.ns_per_s) return null;
        return std.math.cast(i64, @as(i128, sample.sec) * std.time.us_per_s + @divTrunc(sample.nsec, std.time.ns_per_us));
    }
    fn observedWorker(self: *Coordinator) health.WorkerStatus {
        return self.worker_observation.read(observationMs(), observationWall());
    }
    fn observationHealthy(observation: health.WorkerStatus) bool {
        return !observation.stalled and !observation.clock_uncertain and !observation.expiry_uncertain and !observation.expiry_overdue;
    }
    fn resolverGeneration(server: ?std.net.Address) ![32]u8 {
        const selected = server orelse return [_]u8{0} ** 32;
        var bytes: [128]u8 = undefined;
        const canonical = try std.fmt.bufPrint(&bytes, "{}", .{selected});
        return effect.hashParts("fail2zig-native-resolver-udp-v1", &.{canonical});
    }
    fn internalGeneration(jail: []const u8, policy: retry.Policy) ![32]u8 {
        const base = try policy.encode();
        const escalation = try policy.escalationBytes();
        return effect.hashParts("fail2zig-native-recidive-source-v1", &.{ jail, &base, &escalation });
    }
    fn resourceRequirements(cfg: *const config.Config, selected: []config.LogSource) !resource.Requirements {
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
                    // Owned plan paths plus bounded discovery/copy overlap.
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
        try plan.includeDetached(try resource.publicationCost(max_subjects_total, @sizeOf(Coordinator) + selected.len * @sizeOf(Jail)));
        if (enforcing) try plan.includeDetached(.{
            .bytes = try std.math.mul(usize, effect.max_owners, 2 * (@sizeOf(durable.Store.OperatorOwner) + @sizeOf(bool))),
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
        return plan.finish(.{ .zig_bytes = @as(usize, cfg.global.native_memory_ceiling_mb) * resource.mib, .descriptors = cfg.global.native_fd_ceiling }, descriptors);
    }
    fn releaseResources(self: *Coordinator) void {
        if (self.resource_reservation) |reservation| self.resources.release(reservation) catch |failure| {
            std.log.err("native resource reservation release failed: {s}", .{@errorName(failure)});
        };
        self.resource_reservation = null;
    }

    pub fn create(a: std.mem.Allocator, cfg: *const config.Config, config_path: []const u8) !*Coordinator {
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
            std.log.err("native: state authority '{s}': {s}", .{ cfg.global.state_file, @errorName(err) });
            return err;
        };
        errdefer if (authority_lock) |file| file.close();
        const snapshot: durable.Store.InstallationSnapshot = if (authority_lock != null)
            try durable.Store.installationSnapshot(a, cfg.global.state_file)
        else
            .{ .schema_version = 0, .installation = null };
        const backend_admission = preflightBackend(a, cfg, requested_enforcing, snapshot.installation);
        if (backend_admission == .unavailable) {
            const failure = backend_admission.unavailable;
            const forced = cfg.global.firewall != .auto;
            const reason = backendCauseName(failure);
            if (cfg.global.on_no_backend == .@"fail-closed") {
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
        const requirements = try resourceRequirements(cfg, selected_sources[0..count]);
        const per_jail: u32 = @intCast(max_subjects_total / count);
        const self = try a.create(Coordinator);
        errdefer a.destroy(self);
        const timer = try std.time.Timer.start();
        self.* = .{ .allocator = a, .cfg = cfg, .live_cfg = cfg, .config_path = config_path, .jails = &.{}, .store = undefined, .timer = timer, .gate = undefined, .published_health = undefined, .startup_backend = switch (backend_admission) {
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
        }, .preflight_schema_version = snapshot.schema_version, .preflight_installation = snapshot.installation, .suppress_enforcement = requested_enforcing and !runtime_enforcing, .authority_lock = authority_lock, .namespace_lock = namespace_lock, .start_us = std.time.microTimestamp(), .resources = resource.Ledger.init(requirements) };
        authority_lock = null;
        namespace_lock = null;
        errdefer if (self.namespace_lock) |file| file.close();
        errdefer if (self.authority_lock) |file| file.close();
        self.worker_observation = health.WorkerObservation.init(observationMs(), observationWall());
        self.resource_reservation = try self.resources.reserve(.other, requirements.cost);
        errdefer self.releaseResources();
        if (runtime_enforcing) {
            self.owner_scratch = try a.alloc(durable.Store.OperatorOwner, effect.max_owners);
            errdefer a.free(self.owner_scratch);
            self.owner_active = try a.alloc(durable.Store.OperatorOwner, effect.max_owners);
            errdefer a.free(self.owner_active);
            self.owner_scratch_confirmed = try a.alloc(bool, effect.max_owners);
            errdefer a.free(self.owner_scratch_confirmed);
            self.owner_confirmed = try a.alloc(bool, effect.max_owners);
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
            a.free(jail.scratch);
            a.free(jail.active);
            a.free(jail.scratch_confirmed);
            a.free(jail.confirmed);
        };
        for (cfg.jails) |*jail_cfg| {
            if (!jail_cfg.enabled) continue;
            const policy = try retry_config.fromJail(jail_cfg, cfg.defaults, per_jail);
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
                    var settings = projection.Settings{ .timestamp = undefined, .body = if (assets == null and (timestamp == .iso8601 or timestamp == .syslog)) .syslog else .whole, .start = .head, .max_sources = max_sources_per_jail, .ignore_capacity = 128, .custom = assets != null };
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
                .internal => .{ .internal = try internalGeneration(selected.name, policy) },
            };
            errdefer plan.deinit(a);
            const scratch = try a.alloc(durable.Store.ActiveDecision, per_jail);
            errdefer a.free(scratch);
            const active = try a.alloc(durable.Store.ActiveDecision, per_jail);
            errdefer a.free(active);
            const scratch_confirmed = try a.alloc(bool, per_jail);
            errdefer a.free(scratch_confirmed);
            const confirmed = try a.alloc(bool, per_jail);
            self.jails[prepared] = .{ .name = selected.name, .plan = plan, .policy = policy, .scratch = scratch, .active = active, .zone = zone, .scratch_confirmed = scratch_confirmed, .confirmed = confirmed, .custom_plan = assets };
            if (assets != null) self.custom_jails += 1;
            prepared += 1;
        }
        if (self.authority_lock == null) self.authority_lock = path_guard.lockAbsentState(cfg.global.state_file) catch |err| {
            std.log.err("native: state authority '{s}': {s}", .{ cfg.global.state_file, @errorName(err) });
            return err;
        };
        try self.verifyStateIdentity();
        self.store = try durable.Store.openRuntime(a, cfg.global.state_file);
        self.store_open = true;
        errdefer self.store.close();
        try self.verifyStateIdentity();
        try self.validatePreflightInstallation();
        try self.admitStore();
        while (!try self.store.validateMaintenanceTurn(&self.maintenance_validation)) {}
        try self.store.finishMaintenanceValidation(&self.maintenance_validation);
        self.maintenance_validated = true;
        errdefer if (self.effects) |manager| manager.destroy();
        errdefer self.destroyRuntime();
        try self.store.beginStartupAdmission();
        errdefer self.store.abortStartupAdmission();
        try self.validateAdmission();
        var recovery_driver = self.driver();
        _ = try recovery_driver.poll();
        for (0..max_jails * (max_sources_per_jail + 7) + 160) |_| {
            const startup_state = self.gate.snapshot();
            if (startup_state.phase != .recovering or startup_state.recovery_step != .state) break;
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

    fn admitStore(self: *Coordinator) !void {
        self.store.runtime_path = self.cfg.global.state_file;
        try self.store.configureRuntimeLimits();
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
        const now = std.time.microTimestamp();
        const generation = reload_mod.generationId(digest, now);
        var jails: [max_jails]durable.Store.ConfigGenerationJail = undefined;
        for (self.jails, 0..) |*jail, i| jails[i] = .{ .jail = jail.name, .digest = try reload_mod.jailDigest(jail.name, jail.policy, try self.plannedGeneration(jail)), .allowlist_snapshot = if (jail.custom_plan) |assets| assets.initial_ignore.payload else "" };
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
        config.validate(proposed) catch |err| return ReloadOutcome.single(.rejected, "config: validation failed: {s}", .{@errorName(err)});
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
        const now = std.time.microTimestamp();
        const generation = reload_mod.generationId(request.config_digest, now);
        var transitions: [max_jails]durable.Store.PolicyTransition = undefined;
        var digests: [max_jails]durable.Store.ConfigGenerationJail = undefined;
        var count: usize = 0;
        for (request.classification.policySlice()) |change| {
            const jail = self.findJail(change.jail) orelse return error.UnknownJail;
            const current_generation = try self.plannedGeneration(jail);
            const previous = jail.policy;
            const next_policy = change.next;
            jail.policy = next_policy;
            const next_generation = self.plannedGeneration(jail) catch |err| {
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
            digests[i] = .{ .jail = jail.name, .digest = try reload_mod.jailDigest(jail.name, next, try self.plannedGeneration(jail)), .allowlist_snapshot = if (jail.custom_plan) |assets| assets.initial_ignore.payload else "" };
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
        if (count == 0 and refreshed == 0) {
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
        self.mutex.lock();
        for (transitions[0..count]) |change| if (self.findJail(change.jail)) |jail| {
            jail.policy = change.next;
            jail.rekeyed = !std.mem.eql(u8, &change.generation, &change.next_generation);
        };
        if (request.classification.log_level) |level| log_level.set(std.meta.stringToEnum(std.log.Level, @tagName(level)) orelse .info);
        self.replaceLiveConfigLocked(request.arena, request.proposed);
        request.arena = null;
        self.published_generation = generation;
        self.published_config_digest = request.config_digest;
        self.mutex.unlock();
        if (count != 0) self.gate.requestRebuild() catch {};
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
        const per_jail: u32 = @intCast(max_subjects_total / @max(1, self.jails.len));
        return .{ .generation = self.published_generation, .classification = reload_mod.classify(self.live_cfg, input.proposed, per_jail) };
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
        if (body.expected_generation.len != 64) return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "expected_generation must be 64 hex characters") } };
        const request = try self.allocator.create(AdminRequest);
        var destroy_on_exit = true;
        defer if (destroy_on_exit) self.allocator.destroy(request);
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
        if (body.run_id) |text| {
            if (text.len != 64) return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "run_id must be 64 hex characters") } };
            var run_id: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&run_id, text) catch return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "run_id is not hex") } };
            request.run_id = run_id;
        }
        if ((kind == .migration_activate or kind == .migration_rollback) and request.run_id == null) return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "run_id is required") } };
        const needs_jail = switch (kind) {
            .history_reset => !body.all,
            .setting_batch, .migration_activate, .migration_rollback => false,
            else => true,
        };
        if (needs_jail and request.jail_len == 0) return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "jail is required") } };
        if ((kind == .ban or kind == .unban or kind == .history_reset) and request.address == null) return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "address is required") } };
        if (request.prefix) |prefix| {
            const address = request.address orelse return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "address is required") } };
            const max: u8 = if (address == .ipv4) 32 else 128;
            if (prefix == 0 or prefix > max) return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "invalid prefix") } };
        }
        const staged = self.stageAdmin(request, if (kind == .migration_activate or kind == .migration_rollback) 10_000 else 3000);
        destroy_on_exit = staged.owned;
        const view = staged.view;
        const w = out.writer(a);
        try w.print("{{\"schema_version\":1,\"kind\":\"{s}\",\"outcome\":\"{s}\",\"generation\":\"{s}\",\"mutation_revision\":{d},\"enforced\":{},\"reasons\":[", .{ @tagName(view.kind), @tagName(view.outcome), &std.fmt.bytesToHex(view.generation, .lower), view.mutation_revision, view.enforced });
        if (view.reason.len != 0) try std.json.encodeJsonString(view.reason.slice(), .{}, w);
        try w.writeAll("]");
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
            .generation = try self.plannedGeneration(jail),
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
    fn plannedGeneration(self: *Coordinator, jail: *Jail) ![32]u8 {
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
                var options = plan.sessionOptions();
                options.retry = jail.policy;
                options.suppress_retry_enforcement = self.suppress_enforcement;
                if (jail.custom_plan != null) {
                    options.staged_detection = registry.consumer();
                    options.consumer_sources = .{ .context = null, .admit = preflightSource };
                }
                const processor = try sessions.Session.prepareProcessor(self.allocator, options, plan.specs, &scratch, .{ .us = 0 });
                break :blk processor.generation;
            },
            .journal => |plan| blk: {
                var options = plan.sessionOptions();
                options.retry = jail.policy;
                options.suppress_retry_enforcement = self.suppress_enforcement;
                if (jail.custom_plan != null) {
                    options.staged_detection = registry.consumer();
                    options.consumer_sources = .{ .context = null, .admit = preflightSource };
                }
                const processor = try journal_sessions.Session.prepareProcessor(self.allocator, options, &scratch, .{ .us = 0 });
                break :blk processor.generation;
            },
            .internal => |generation| generation,
        };
    }
    fn driver(self: *Coordinator) recovery.Driver {
        return .{ .store = &self.store, .gate = &self.gate, .clock = .{ .generation = [_]u8{0} ** 32 }, .hooks = .{ .context = self, .storage = recoverStorage, .state = recoverState, .ownership = recoverOwnership, .sources = recoverSources, .turn = recoverTurn } };
    }
    fn recoverTurn(stage: health.RecoveryStep, ctx: ?*anyopaque) !bool {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        const generation = self.gate.snapshot().generation;
        if (self.recovery_generation == null or self.recovery_generation.? != generation) {
            self.recovery_generation = generation;
            self.restore_jail = 0;
            self.verify_jail = 0;
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
                try self.store.finishMaintenanceValidation(&self.maintenance_validation);
                try self.ensureEffects();
                if (self.effects) |manager| {
                    var bindings: [max_jails]effect_runtime.Binding = undefined;
                    self.effectBindings(&bindings);
                    if (!try manager.turn(bindings[0..self.jails.len])) return false;
                }
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
        const held = try std.posix.fstat((self.authority_lock orelse return error.NativeAuthorityLockRequired).handle);
        const selected = try std.posix.fstatat(std.posix.AT.FDCWD, self.cfg.global.state_file, std.posix.AT.SYMLINK_NOFOLLOW);
        if (held.dev != selected.dev or held.ino != selected.ino or !std.posix.S.ISREG(selected.mode)) return error.NativeStateReplaced;
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
        self.effects = try effect_runtime.Manager.create(self.allocator, &self.store, installation.?);
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
                self.store = try durable.Store.openRuntime(self.allocator, self.cfg.global.state_file);
                self.store_open = true;
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
    fn recoverState(ctx: ?*anyopaque) !void {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        switch (self.rebuild_phase) {
            .maintenance => {
                if (!self.maintenance_validated) {
                    if (!try self.store.validateMaintenanceTurn(&self.maintenance_validation)) return;
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
                        options.suppress_retry_enforcement = self.suppress_enforcement;
                        options.gate = &self.gate;
                        options.monotonic_clock = .{ .context = self, .read = monotonic };
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
    fn processingClock(_: ?*anyopaque) i64 {
        return std.time.microTimestamp();
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
            try self.store.bootstrapConfirmedHistory(manifest, try stage.batch(.{ .prepared_us = std.time.microTimestamp(), .read = processingClock }), installation);
            stage.publish();
        }
    }
    fn recidiveJail(self: *Coordinator) ?*Jail {
        for (self.jails) |*jail| if (jail.plan == .internal) return jail;
        return null;
    }
    fn consumeHistory(self: *Coordinator) !bool {
        const owner = if (self.history_consumer) |*value| value else return true;
        var events: [history.max_page]history.Event = undefined;
        const page = try self.store.confirmedEffectPage(owner.installation, owner.live.last_sequence, null, &events);
        if (page.count != 0) {
            const now = std.time.microTimestamp();
            const stage = try owner.prepare(page, events[0..page.count], now);
            defer stage.release();
            if (self.recidiveJail()) |jail| {
                for (events[0..page.count]) |event| {
                    _ = try recurrence.consume(&self.store, .{ .jail = jail.name, .generation = jail.session.?.generation(), .policy = jail.policy, .suppress_enforcement = self.suppress_enforcement }, event, now, .{ .prepared_us = now, .read = processingClock });
                }
            }
            try self.store.commitConfirmedHistory(owner.manifest(), try stage.batch(.{ .prepared_us = now, .read = processingClock }), page.token);
            stage.publish();
            self.history_page = null;
            return false;
        }
        try self.store.validateConfirmedEffectPage(page.token);
        self.history_page = page.token;
        return true;
    }
    fn recoverOwnership(ctx: ?*anyopaque) !void {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
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
                    self.publishSource(jail);
                    return failure;
                };
                if (!verified) return;
                self.mutex.lock();
                jail.source_error = null;
                self.mutex.unlock();
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
                    if (!try self.store.validateMaintenanceTurn(&self.maintenance_validation)) return;
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
        const now = std.time.microTimestamp();
        const summary = try self.store.retrySummary(jail.name, now, jail.scratch);
        for (jail.scratch[0..summary.active], 0..) |decision, i| jail.scratch_confirmed[i] = self.jailEnforces(jail) and if (self.effects) |manager| manager.confirmedSubject(decision.subject, now) else false;
        const confirmations = if (self.effects != null) try self.store.confirmedEffectEvents() else 0;
        const revision = try self.store.revision(jail.name);
        if (jail.published_once and !self.jailEnforces(jail)) for (jail.scratch[0..summary.active]) |decision| {
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
        self.mutex.lock();
        defer self.mutex.unlock();
        @memcpy(jail.active[0..summary.active], jail.scratch[0..summary.active]);
        @memcpy(jail.confirmed[0..summary.active], jail.scratch_confirmed[0..summary.active]);
        self.published_confirmations = confirmations;
        jail.summary = summary;
        jail.published_once = true;
        jail.revision = revision;
        jail.healthy = jail.session.?.healthy();
    }
    fn ownerConfirmed(self: *const Coordinator, owner: durable.Store.OperatorOwner, now: i64) bool {
        const manager = self.effects orelse return false;
        if (!manager.status.ready or manager.status.uncertain or manager.cached_epoch == null or manager.cached_epoch.? != self.store.effect_publication_epoch) return false;
        for (manager.live[0..manager.count]) |entry| {
            if (!std.meta.eql(entry.scope, owner.scope)) continue;
            return entry.status == .applied and entry.desired.live(now) and owner.lease.live(now);
        }
        return false;
    }
    fn publishOwners(self: *Coordinator) !void {
        const manager = self.effects orelse return;
        const expected_epoch = manager.cached_epoch orelse return error.StaleEffect;
        if (!manager.status.ready or manager.status.uncertain or expected_epoch != self.store.effect_publication_epoch) return error.StaleEffect;
        const now = std.time.microTimestamp();
        const count = try self.store.operatorOwners(now, self.owner_scratch);
        for (self.owner_scratch[0..count], 0..) |owner, i| self.owner_scratch_confirmed[i] = self.ownerConfirmed(owner, now);
        if (expected_epoch != self.store.effect_publication_epoch or manager.cached_epoch == null or manager.cached_epoch.? != expected_epoch) return error.StaleEffect;
        self.mutex.lock();
        defer self.mutex.unlock();
        @memcpy(self.owner_active[0..count], self.owner_scratch[0..count]);
        @memcpy(self.owner_confirmed[0..count], self.owner_scratch_confirmed[0..count]);
        self.owner_count = count;
    }
    fn publishSource(self: *Coordinator, jail: *Jail) void {
        const source = jail.session.?;
        const cause: ?anyerror = switch (source) {
            .file => |value| value.repairSnapshot().last_cause,
            .journal => |value| value.repairSnapshot().last_cause,
            .internal => null,
        };
        self.mutex.lock();
        defer self.mutex.unlock();
        jail.healthy = source.healthy();
        jail.source_error = cause;
    }
    fn publishHealth(self: *Coordinator) void {
        const snapshot = self.gate.snapshot();
        var next_expiry: ?i64 = null;
        var expiry_current = self.effects == null;
        if (self.effects) |manager| {
            expiry_current = manager.status.ready and manager.cached_epoch != null and manager.cached_epoch.? == self.store.effect_publication_epoch;
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
        self.worker_observation.publication(observationMs(), observationWall(), next_expiry, expiry_current);
        self.published_health = snapshot;
        if (self.effects) |manager| {
            self.published_effects = manager.status;
            if (manager.cached_epoch == null or manager.cached_epoch.? != self.store.effect_publication_epoch) self.published_effects.?.ready = false;
            self.published_backend = @tagName(manager.installation.backend);
        }
        self.mutex.unlock();
        if (snapshot.notice_sequence != self.last_notice) {
            self.last_notice = snapshot.notice_sequence;
            std.log.info("native ingestion: {s}; cause={s}; committed={d}", .{ @tagName(snapshot.phase), if (snapshot.last_failure) |failure| @errorName(failure.cause) else "none", snapshot.committed_records });
        }
        if (!self.notified_ready) {
            const report = self.readinessReport();
            if (report.ready) {
                self.notified_ready = true;
                if (self.notifier) |notifier| _ = notifier.ready() catch |err| std.log.warn("sd_notify READY failed: {s}", .{@errorName(err)});
                std.log.info("native: ready; all readiness components verified", .{});
            }
        }
    }
    pub fn start(self: *Coordinator) !void {
        self.thread = try std.Thread.spawn(.{ .stack_size = 16 * resource.mib }, work, .{self});
    }
    fn work(self: *Coordinator) void {
        while (true) {
            self.stop_mutex.lock();
            if (self.stopping) {
                self.stop_mutex.unlock();
                self.withdrawRealizedEffects();
                return;
            }
            self.stop_mutex.unlock();
            self.mutex.lock();
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
            self.worker_observation.begin(observationMs(), observationWall());
            if (self.effects != null) self.worker_observation.publication(observationMs(), observationWall(), null, false);
            self.mutex.unlock();
            self.tick() catch |failure| {
                if (!self.gate.snapshot().has_been_healthy and failure != error.ReceiptClockReversed) {
                    for (self.jails) |jail| if (jail.source_error) |cause| {
                        std.log.err("native: jail={s} source={s} continuity failure: {s}", .{ jail.name, @tagName(jail.plan), @errorName(cause) });
                    };
                    std.log.err("native: startup recovery failed: {s}; refusing to start", .{@errorName(failure)});
                    std.process.exit(1);
                }
                if (self.gate.snapshot().phase == .healthy) self.gate.failed(failure, .{ .sqlite_code = if (self.store_open) self.store.last_error_code else null, .reopen_required = !self.store_open or self.store.reopen_required });
            };
            self.publishHealth();
            self.mutex.lock();
            self.worker_observation.complete(observationMs(), observationWall());
            self.mutex.unlock();
            self.stop_mutex.lock();
            if (!self.stopping) self.wake.timedWait(&self.stop_mutex, 100 * std.time.ns_per_ms) catch {};
            const stopped = self.stopping;
            self.stop_mutex.unlock();
            if (stopped) {
                self.withdrawRealizedEffects();
                return;
            }
        }
    }
    fn tick(self: *Coordinator) !void {
        if (self.gate.snapshot().phase != .healthy) {
            if (self.effects) |manager| manager.expireDuringOutage() catch |failure| {
                manager.status.cause = failure;
            };
            var recovery_driver = self.driver();
            _ = try recovery_driver.poll();
            return;
        }
        if (self.effects) |manager| {
            var bindings: [max_jails]effect_runtime.Binding = undefined;
            self.effectBindings(&bindings);
            if (!try manager.turn(bindings[0..self.jails.len])) return;
            try self.publishOwners();
            for (self.jails) |*jail| try self.publishJail(jail);
        }
        _ = try self.consumeHistory();
        if (self.dns) |resolver| {
            const result = try resolver.pollDns();
            if (result.kind == .ready) {
                const owner = result.source orelse return error.UnboundRequiredConsumer;
                for (self.jails) |*jail| if (jail.consumer) |consumer| {
                    if (!std.mem.eql(u8, consumer.settings.jail, owner.settings.jail)) continue;
                    jail.session.?.resumeConsumer(owner.incarnation) catch |failure| {
                        if (failure == error.SourceRepairPending or failure == error.SourceInterventionRequired) {
                            self.publishSource(jail);
                            break;
                        }
                        if (failure != error.ConsumerPending and failure != error.ConsumerExpired and failure != error.EffectExpired) return failure;
                    };
                    try self.publishJail(jail);
                    break;
                };
            }
        }
        for (self.jails) |*jail| {
            jail.session.?.poll() catch |failure| {
                if (failure == error.SourceRepairPending or failure == error.SourceInterventionRequired) {
                    self.publishSource(jail);
                    continue;
                }
                if (failure == error.EffectExpired or failure == error.ConsumerExpired or failure == error.ConsumerPending) continue;
                if (self.gate.snapshot().phase != .healthy) return failure;
                self.mutex.lock();
                const changed = jail.source_error == null or jail.source_error.? != failure;
                jail.source_error = failure;
                jail.healthy = false;
                self.mutex.unlock();
                if (changed) std.log.err("native jail {s}: {s}; source paused pending repair", .{ jail.name, @errorName(failure) });
                continue;
            };
            self.publishSource(jail);
            try self.publishJail(jail);
        }
        self.maintenanceTurn() catch |failure| switch (failure) {
            error.MaintenancePinned, error.StaleMaintenance => {},
            else => return failure,
        };
        if (try self.store.admissionClock()) |floor| {
            self.mutex.lock();
            self.worker_observation.wall_floor_us = if (self.worker_observation.wall_floor_us) |prior| @max(prior, floor.us) else floor.us;
            self.mutex.unlock();
        }
    }
    fn maintenanceTurn(self: *Coordinator) !void {
        if (self.gate.snapshot().phase != .healthy or self.jails.len == 0) return;
        if (self.effects) |manager| if (!manager.status.ready or manager.status.uncertain) return;
        if (self.history_page) |page| {
            if (page.after_sequence == page.head_sequence and page.last_sequence == page.head_sequence) {
                const age_us = std.math.mul(i64, std.math.cast(i64, self.cfg.global.history_retention) orelse return error.InvalidApplicationHistoryQuery, 1_000_000) catch return error.InvalidApplicationHistoryQuery;
                if (try self.store.cleanupConfirmedHistoryOne(.{ .age_us = age_us, .max_matches = self.cfg.global.history_max_matches }, std.time.microTimestamp())) {
                    self.history_page = null;
                    return;
                }
            }
        }
        const jail = &self.jails[self.maintenance_jail % self.jails.len];
        self.maintenance_jail = (self.maintenance_jail + 1) % self.jails.len;
        const session = jail.session orelse return;
        if (!session.healthy()) return;
        switch (session) {
            .file => |value| if (value.pipe.candidate_receipt != null) return,
            .journal => |value| if (value.pipe.candidate_receipt != null) return,
            .internal => return,
        }
        if (jail.consumer) |owner| {
            if (owner.ignores.in_flight) return;
            for (owner.registry.sources[0..owner.registry.count]) |source| {
                if (source.busy or source.pending != null or source.waiting_occurrence != null or source.dns_stage != null) return;
            }
        }
        const source_count: usize = switch (session) {
            .file => |value| blk: {
                if (value.candidate_source != null) return;
                break :blk value.sources.sources.items.len;
            },
            .journal => 1,
            .internal => return,
        };
        if (source_count == 0) return;
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
        if (self.effects != null) {
            const page = self.history_page orelse return;
            if (page.after_sequence != page.head_sequence or page.last_sequence != page.head_sequence) return;
        }
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
            .clock = .{ .prepared_us = std.time.microTimestamp() },
            .preparations = .released,
        };
        const retire = jail.retire_next;
        jail.retire_next = !retire;
        if (retire) {
            const candidate = (try self.store.retryRetirementCandidate(jail.name, jail.retire_after)) orelse {
                jail.retire_after = null;
                return;
            };
            jail.retire_after = candidate.subject;
            _ = try self.store.retireRetrySubject(fence, candidate);
            return;
        }
        jail.maintenance_source = (source_index + 1) % source_count;
        if (try self.store.cleanupResume(jail.name, source_id, generation)) |token| {
            _ = try self.store.cleanupDelete(fence, token);
        } else if (try self.store.sourceMaintenance(jail.name, source_id, generation)) |state| {
            _ = try self.store.cleanupAdvance(fence, state, state.head_sequence);
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
        self.destroyRuntime();
        for (self.jails) |*jail| {
            if (jail.custom_plan) |value| value.destroy();
            jail.plan.deinit(self.allocator);
            destroyZone(self.allocator, jail.zone);
            self.allocator.free(jail.scratch);
            self.allocator.free(jail.active);
            self.allocator.free(jail.scratch_confirmed);
            self.allocator.free(jail.confirmed);
        }
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
        self.mutex.lock();
        defer self.mutex.unlock();
        const gate = self.published_health;
        const sampled_wall = observationWall();
        const observation = self.worker_observation.read(observationMs(), sampled_wall);
        var healthy = gate.phase == .healthy and observationHealthy(observation);
        var decisions: u64 = 0;
        var installed: u32 = 0;
        const now = sampled_wall orelse self.start_us;
        for (self.jails) |jail| {
            healthy = healthy and jail.healthy;
            decisions +|= jail.summary.decisions;
            installed +|= self.confirmedCount(jail, now, observation);
        }
        if (self.published_effects) |effects| healthy = healthy and effects.ready;
        if (self.backend_failure != null) healthy = false;
        const protection: []const u8 = if (!healthy) "degraded" else if (self.published_effects != null) "active" else "log-only";
        const generation_hex = std.fmt.bytesToHex(self.published_generation, .lower);
        try std.json.stringify(.{ .version = version, .runtime = "native", .generation = &generation_hex, .mutation_revision = self.published_revision, .state = protection, .protection = protection, .protection_cause = if (self.backend_failure) |failure| @as(?[]const u8, @errorName(failure)) else null, .active_bans = installed, .total_bans = self.published_confirmations, .storage = @tagName(gate.phase), .cause = if (gate.phase == .intervention and gate.last_failure != null) @errorName(gate.last_failure.?.cause) else if (observation.clock_uncertain) "ClockUncertain" else if (observation.stalled) "WorkerStalled" else if (observation.expiry_overdue) "EffectExpiryOverdue" else if (observation.expiry_uncertain) "EffectViewUncertain" else if (gate.last_failure) |failure| @errorName(failure.cause) else if (self.published_effects) |effects| if (effects.cause) |cause| @errorName(cause) else "none" else if (self.backend_failure) |failure| @errorName(failure) else "none", .sqlite_code = if (gate.last_failure) |failure| failure.diagnostics.sqlite_code else null, .next_retry_ms = gate.next_retry_ms, .committed_records = gate.committed_records, .decisions_total = decisions, .jails_active = self.jails.len, .backend = self.published_backend, .effects_uncertain = observation.expiry_uncertain or (if (self.published_effects) |effects| effects.uncertain else false), .overdue_effects = if (self.published_effects) |effects| effects.overdue else 0, .worker_busy = observation.busy, .worker_stalled = observation.stalled, .worker_busy_age_ms = observation.busy_age_ms, .worker_heartbeat_age_ms = observation.heartbeat_age_ms, .clock_uncertain = observation.clock_uncertain, .expiry_overdue = observation.expiry_overdue, .expiry_uncertain = observation.expiry_uncertain, .next_committed_expiry_us = observation.next_committed_expiry_us, .uptime_seconds = if (observation.clock_uncertain) @as(?u64, null) else @as(u64, @intCast(@max(0, @divTrunc(now -| self.start_us, 1_000_000)))) }, .{ .emit_null_optional_fields = false }, out.writer(a));
    }
    fn confirmationReady(self: *const Coordinator, observation: health.WorkerStatus) bool {
        return observationHealthy(observation) and self.published_health.phase == .healthy and if (self.published_effects) |effects| effects.ready and !effects.uncertain else false;
    }
    fn confirmedCount(self: *const Coordinator, jail: Jail, now: i64, observation: health.WorkerStatus) u32 {
        if (!self.confirmationReady(observation)) return 0;
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
        const sampled_wall = observationWall();
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
                    const confirmed = self.owner_confirmed[i] and self.confirmationReady(observation);
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
                const confirmed = jail.confirmed[i] and self.confirmationReady(observation);
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
        try out.writer(a).print("fail2zig_up 1\nfail2zig_native_storage_healthy {d}\nfail2zig_native_committed_records {d}\nfail2zig_native_worker_stalled {d}\nfail2zig_native_worker_busy {d}\nfail2zig_native_worker_heartbeat_age_ms {d}\nfail2zig_native_worker_busy_age_ms {d}\nfail2zig_native_clock_uncertain {d}\nfail2zig_native_expiry_overdue {d}\nfail2zig_native_expiry_uncertain {d}\n", .{ @intFromBool(self.published_health.phase == .healthy and observationHealthy(observation)), self.published_health.committed_records, @intFromBool(observation.stalled), @intFromBool(observation.busy), observation.heartbeat_age_ms, observation.busy_age_ms, @intFromBool(observation.clock_uncertain), @intFromBool(observation.expiry_overdue), @intFromBool(observation.expiry_uncertain) });
    }
    fn commandAuth(ctx: ?*anyopaque, cmd: shared.Command, peer: ipc.Peer, a: std.mem.Allocator) !shared.Response {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        if (cmd == .query_v1) return self.queryResponse(a, cmd.query_v1.slice(), switch (peer.class) {
            .admin => .admin,
            .monitor => .monitor,
        });
        return command(ctx, cmd, a);
    }
    fn readinessInputs(self: *Coordinator, jails: *[max_jails]readiness.Jail) readiness.Inputs {
        const observation = self.observedWorker();
        for (self.jails, 0..) |jail, i| jails[i] = .{ .healthy = jail.healthy, .source_error = jail.source_error != null, .enforce = self.jailEnforces(&jail) };
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
    fn statusCallback(ctx: ?*anyopaque, a: std.mem.Allocator, out: *std.ArrayList(u8)) anyerror!void {
        var unmanaged: std.ArrayListUnmanaged(u8) = .{};
        defer unmanaged.deinit(a);
        try status(ctx, &unmanaged, a);
        try out.appendSlice(unmanaged.items);
    }
    fn healthCallback(ctx: ?*anyopaque, a: std.mem.Allocator, out: *std.ArrayList(u8)) anyerror!void {
        var unmanaged: std.ArrayListUnmanaged(u8) = .{};
        defer unmanaged.deinit(a);
        try healthView(ctx, &unmanaged, a);
        try out.appendSlice(unmanaged.items);
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
                try out.append(.{ .sequence = event.sequence, .event_id = event.event_id, .jail = try out.allocator.dupe(u8, event.jail.slice()), .decision_id = event.decision_id, .confirmed_us = event.confirmed_us, .scope = scopeFields(event.scope), .native_retry = event.native_retry });
                appended += 1;
            }
            if (!page.more) return .{ .more = false, .resume_after = after };
        }
        return .{ .more = true, .resume_after = after };
    }
    fn scopeFields(scope: effect.Scope) query_v1.ScopeFields {
        const subject = scope.canonical.subject;
        const family: query_v1.Family = switch (subject.family) {
            .v4 => .v4,
            .v6 => .v6,
        };
        return .{ .family = family, .address = subject.address, .prefix = subject.prefix, .protocol = if (scope.canonical.protocols.isAll()) null else "tcp", .port = null, .direction = "input", .target = "drop" };
    }
    fn queryResponse(self: *Coordinator, a: std.mem.Allocator, body: []const u8, peer_class: query_v1.PeerClass) !shared.Response {
        var arena_state = std.heap.ArenaAllocator.init(a);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var generation: [32]u8 = undefined;
        var config_view: ?query_v1.ConfigView = null;
        var scopes_view: ?query_v1.ScopesView = null;
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            generation = self.published_generation;
            const cfg = self.live_cfg;
            var jail_configs = try arena.alloc(query_v1.JailConfig, self.jails.len);
            var jail_scopes = try arena.alloc(query_v1.JailScopes, self.jails.len);
            const now = observationWall() orelse self.start_us;
            const observation = self.observedWorker();
            for (self.jails, 0..) |jail, i| {
                const source_cfg = findConfigJail(cfg, jail.name);
                const bantime: u64 = switch (jail.policy.duration) {
                    .finite_us => |value| @intCast(@divTrunc(value, 1_000_000)),
                    .permanent => 0,
                };
                jail_configs[i] = .{ .name = jail.name, .enabled = jail.admin_enabled, .filter = if (source_cfg) |c| c.filter else "", .source = @tagName(jail.plan), .logpath = if (source_cfg) |c| c.logpath else &.{}, .maxretry = jail.policy.maxretry, .findtime = @intCast(@divTrunc(jail.policy.window_us, 1_000_000)), .bantime = bantime, .bantime_permanent = jail.policy.duration == .permanent, .banaction = if (self.jailEnforces(&jail)) self.published_backend else "log-only", .ignoreip = if (source_cfg) |c| (c.ignoreip orelse cfg.defaults.ignoreip) else &.{} };
                const item_count = if (self.jailEnforces(&jail)) blk: {
                    var count: usize = 0;
                    for (self.owner_active[0..self.owner_count]) |owner| if (std.mem.eql(u8, owner.jail.slice(), jail.name)) {
                        count += 1;
                    };
                    break :blk count;
                } else jail.summary.active;
                var items = try arena.alloc(query_v1.ScopeItem, item_count);
                if (self.jailEnforces(&jail)) {
                    var k: usize = 0;
                    for (self.owner_active[0..self.owner_count], 0..) |owner, owner_index| {
                        if (!std.mem.eql(u8, owner.jail.slice(), jail.name)) continue;
                        items[k] = .{ .scope = scopeFields(owner.scope), .lease = if (owner.lease == .permanent) .permanent else .finite, .deadline_us = if (owner.lease == .finite) owner.lease.finite else null, .decision_id = owner.decision_id, .confirmed = self.owner_confirmed[owner_index] and owner.lease.live(now) and self.confirmationReady(observation) };
                        k += 1;
                    }
                } else {
                    for (jail.active[0..jail.summary.active], 0..) |decision, k| {
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
                        items[k] = .{ .scope = .{ .family = family, .address = address, .prefix = if (family == .v4) 32 else 128 }, .lease = if (decision.lease == .permanent) .permanent else .finite, .deadline_us = if (decision.lease == .finite) decision.lease.finite else null, .decision_id = null, .confirmed = jail.confirmed[k] and decision.lease.live(now) and self.confirmationReady(observation) };
                    }
                }
                jail_scopes[i] = .{ .name = jail.name, .items = items };
            }
            config_view = .{ .jails = jail_configs, .global = .{ .log_level = @tagName(cfg.global.log_level), .firewall = @tagName(cfg.global.firewall), .metrics_enabled = cfg.global.metrics_enabled, .metrics_bind = cfg.global.metrics_bind, .metrics_port = cfg.global.metrics_port, .socket_path = cfg.global.socket_path, .state_file = cfg.global.state_file, .dns_server = cfg.global.dns_server, .timezone_root = cfg.global.timezone_root } };
            scopes_view = .{ .jails = jail_scopes };
        }
        const result = try query_v1.handle(a, body, peer_class, generation, .{ .status = .{ .ctx = self, .func = statusCallback }, .health = .{ .ctx = self, .func = healthCallback }, .config = config_view, .scopes = scopes_view, .history = .{ .ctx = self, .read = historyRead } });
        return switch (result) {
            .payload => |bytes| .{ .ok = .{ .payload = bytes } },
            .failure => |failure| .{ .err = .{ .code = failure.code, .message = try a.dupe(u8, failure.message) } },
        };
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
                const sampled_wall = observationWall();
                const observation = self.worker_observation.read(observationMs(), sampled_wall);
                const w = output.writer(a);
                try w.writeAll("[");
                for (self.jails, 0..) |jail, index| {
                    if (index > 0) try w.writeByte(',');
                    const bantime: ?i64 = switch (jail.policy.duration) {
                        .finite_us => |value| @divTrunc(value, 1_000_000),
                        .permanent => null,
                    };
                    try std.json.stringify(.{ .name = jail.name, .healthy = jail.healthy and self.published_health.phase == .healthy and observationHealthy(observation), .enabled = jail.admin_enabled, .paused = jail.admin_paused, .active_bans = self.confirmedCount(jail, sampled_wall orelse self.start_us, observation), .maxretry = jail.policy.maxretry, .findtime = @divTrunc(jail.policy.window_us, 1_000_000), .bantime = bantime, .bantime_permanent = jail.policy.duration == .permanent, .action = if (self.jailEnforces(&jail)) self.published_backend else "log-only", .enforcing = self.jailEnforces(&jail) and self.confirmationReady(observation), .log_source = @tagName(jail.plan), .source_healthy = jail.healthy and self.published_health.phase == .healthy and observationHealthy(observation), .source = @tagName(jail.plan), .revision = jail.revision, .decisions = jail.summary.decisions, .cause = if (jail.source_error) |cause| @errorName(cause) else "none" }, .{}, w);
                }
                try w.writeAll("]");
            },
            .ban, .unban => return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "legacy ban/unban are retired; use admin_v1") } },
            .reload => return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "legacy reload is retired; use reload_v1") } },
            .reload_v1 => return self.reloadResponse(&output, a),
            .admin_v1 => |request| return self.adminResponse(&output, a, request),
            .query_v1 => |body| return self.queryResponse(a, body.slice(), .monitor),
        }
        return .{ .ok = .{ .payload = try output.toOwnedSlice(a) } };
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
    const coordinator = try Coordinator.create(a, cfg, config_path);
    defer coordinator.destroy();
    var loop = try loop_mod.EventLoop.init(a);
    defer loop.deinit();
    var notifier: ?sd_notify.Notifier = sd_notify.Notifier.fromEnvironment() catch |err| blk: {
        std.log.warn("sd_notify disabled: {s}", .{@errorName(err)});
        break :blk null;
    };
    defer if (notifier) |*value| value.deinit();
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
    coordinator.history_reader = durable.Store.openReadOnly(a, cfg.global.state_file) catch |err| blk: {
        std.log.warn("native: history reader unavailable: {s}", .{@errorName(err)});
        break :blk null;
    };
    try coordinator.start();
    const backend_name = if (coordinator.startup_backend) |selected| @tagName(selected) else "none";
    std.log.info("fail2zig {s} running; backend={s}; native SQLite ingestion; protection admission pending; ipc={s}; http={s}", .{ version, backend_name, cfg.global.socket_path, if (cfg.global.metrics_enabled) cfg.global.metrics_bind else "off" });
    try loop.run();
}

const TestCountingAllocator = struct {
    parent: std.mem.Allocator,
    allocations: usize = 0,
    frees: usize = 0,

    fn allocator(self: *TestCountingAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(context: *anyopaque, len: usize, alignment: std.mem.Alignment, return_address: usize) ?[*]u8 {
        const self: *TestCountingAllocator = @ptrCast(@alignCast(context));
        const memory = self.parent.rawAlloc(len, alignment, return_address) orelse return null;
        self.allocations += 1;
        return memory;
    }
    fn resize(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, return_address: usize) bool {
        const self: *TestCountingAllocator = @ptrCast(@alignCast(context));
        return self.parent.rawResize(memory, alignment, new_len, return_address);
    }
    fn remap(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, return_address: usize) ?[*]u8 {
        const self: *TestCountingAllocator = @ptrCast(@alignCast(context));
        return self.parent.rawRemap(memory, alignment, new_len, return_address);
    }
    fn free(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, return_address: usize) void {
        const self: *TestCountingAllocator = @ptrCast(@alignCast(context));
        self.parent.rawFree(memory, alignment, return_address);
        self.frees += 1;
    }
};

const ReloadNotifyProbe = struct {
    ready_calls: *usize,

    fn ready(self: *const ReloadNotifyProbe) sd_notify.Error!sd_notify.Result {
        self.ready_calls.* += 1;
        return .sent;
    }
};

test "native daemon BUG-034: reload completion notifies READY only for a ready report" {
    const testing = std.testing;
    var calls: usize = 0;
    const probe = ReloadNotifyProbe{ .ready_calls = &calls };
    const states = [_]readiness.State{.ok} ** readiness.Component.count;

    notifyReloadReady(.{ .components = states, .ready = false, .cause = "source not yet admitted" }, &probe);
    try testing.expectEqual(@as(usize, 0), calls);
    notifyReloadReady(.{ .components = states, .ready = true, .cause = null }, &probe);
    try testing.expectEqual(@as(usize, 1), calls);
}

test "native daemon BUG-035: admin settlement requires coherent effect readback" {
    const testing = std.testing;
    try testing.expectEqual(AdminReadback.pending, adminReadback(.{ .ready = false }, null, 8));
    try testing.expectEqual(AdminReadback.pending, adminReadback(.{ .ready = true }, 7, 8));
    try testing.expectEqual(AdminReadback.uncertain, adminReadback(.{ .ready = true, .uncertain = true }, 8, 8));
    try testing.expectEqual(AdminReadback.coherent, adminReadback(.{ .ready = true }, 8, 8));
}

const AdminOwnershipProbe = struct {
    coordinator: *Coordinator,
    request: *Coordinator.AdminRequest,
    mutex: std.Thread.Mutex = .{},
    wake: std.Thread.Condition = .{},
    worker_arrived: bool = false,
    taken: bool = false,
    release: bool = false,
    completions: usize = 0,

    fn worker(self: *AdminOwnershipProbe) void {
        self.coordinator.mutex.lock();
        const work_item = self.coordinator.adminWorkLocked().?;
        self.coordinator.mutex.unlock();

        self.mutex.lock();
        self.worker_arrived = true;
        self.taken = work_item.request == self.request and work_item.phase == .executing;
        self.wake.broadcast();
        while (!self.release) self.wake.wait(&self.mutex);
        self.mutex.unlock();

        self.coordinator.completeAdmin(work_item.request, .{ .outcome = .applied, .kind = work_item.request.kind });
        self.mutex.lock();
        self.completions += 1;
        self.wake.broadcast();
        self.mutex.unlock();
    }
};

test "native daemon BUG-021: an expired wait abandons executing admin ownership exactly once" {
    const testing = std.testing;
    var counted = TestCountingAllocator{ .parent = testing.allocator };
    const allocator = counted.allocator();
    var coordinator: Coordinator = undefined;
    coordinator.allocator = allocator;
    coordinator.mutex = .{};
    coordinator.reload_wake = .{};
    coordinator.admin_request = null;
    coordinator.published_generation = [_]u8{0x21} ** 32;

    const request = try allocator.create(Coordinator.AdminRequest);
    request.* = .{ .request_id = [_]u8{0x21} ** 32, .kind = .group_pause, .expected_generation = coordinator.published_generation, .expected_revision = 0 };
    coordinator.mutex.lock();
    const rejected = coordinator.enqueueAdminLocked(request);
    coordinator.mutex.unlock();
    try testing.expect(rejected == null);

    var probe = AdminOwnershipProbe{ .coordinator = &coordinator, .request = request };
    const thread = try std.Thread.spawn(.{}, AdminOwnershipProbe.worker, .{&probe});
    var joined = false;
    defer if (!joined) {
        probe.mutex.lock();
        probe.release = true;
        probe.wake.broadcast();
        probe.mutex.unlock();
        thread.join();
    };

    probe.mutex.lock();
    while (!probe.worker_arrived) probe.wake.wait(&probe.mutex);
    const taken = probe.taken;
    probe.mutex.unlock();
    try testing.expect(taken);
    coordinator.mutex.lock();
    const expired = coordinator.expireAdminWaitLocked(request, 0);
    const abandoned = request.abandoned;
    coordinator.mutex.unlock();

    try testing.expect(!expired.owned);
    try testing.expectEqual(durable.Store.AdminOutcome.uncertain, expired.view.outcome);
    try testing.expect(abandoned);
    try testing.expect(std.mem.indexOf(u8, expired.view.reason.slice(), "still executing") != null);

    probe.mutex.lock();
    probe.release = true;
    probe.wake.broadcast();
    probe.mutex.unlock();
    thread.join();
    joined = true;

    probe.mutex.lock();
    const completions = probe.completions;
    probe.mutex.unlock();
    coordinator.mutex.lock();
    const empty = coordinator.admin_request == null;
    coordinator.mutex.unlock();
    try testing.expectEqual(@as(usize, 1), completions);
    try testing.expect(empty);
    try testing.expectEqual(@as(usize, 1), counted.allocations);
    try testing.expectEqual(@as(usize, 1), counted.frees);
}

const ReloadPublicationProbe = struct {
    coordinator: *Coordinator,
    proposed: *const config.Config,
    mutex: std.Thread.Mutex = .{},
    wake: std.Thread.Condition = .{},
    classified: bool = false,
    release_classification: bool = false,
    first_kind: reload_mod.Kind = .rejected,
    swap_started: bool = false,
    swap_done: bool = false,

    fn classifyAndHold(coordinator: *Coordinator, self: *ReloadPublicationProbe) Coordinator.ReloadClassificationSnapshot {
        const result = coordinator.classifyReloadLocked(.{ .proposed = self.proposed });
        self.mutex.lock();
        self.classified = true;
        self.first_kind = result.classification.kind;
        self.wake.broadcast();
        while (!self.release_classification) self.wake.wait(&self.mutex);
        self.mutex.unlock();
        return result;
    }
    fn classify(self: *ReloadPublicationProbe) void {
        _ = self.coordinator.inspectPublicationLocked(self, classifyAndHold);
    }
    fn swap(self: *ReloadPublicationProbe) void {
        self.mutex.lock();
        self.swap_started = true;
        self.wake.broadcast();
        self.mutex.unlock();

        self.coordinator.mutex.lock();
        self.coordinator.replaceLiveConfigLocked(null, self.proposed);
        self.coordinator.mutex.unlock();

        self.mutex.lock();
        self.swap_done = true;
        self.wake.broadcast();
        self.mutex.unlock();
    }
};

test "native daemon BUG-022: live config classification excludes arena replacement" {
    const testing = std.testing;
    const old_arena = try testing.allocator.create(std.heap.ArenaAllocator);
    old_arena.* = std.heap.ArenaAllocator.init(testing.allocator);
    const old_config = try old_arena.allocator().create(config.Config);
    old_config.* = .{};
    var proposed = config.Config{};
    proposed.global.log_level = .warn;

    var coordinator: Coordinator = undefined;
    coordinator.allocator = testing.allocator;
    coordinator.mutex = .{};
    coordinator.jails = &.{};
    coordinator.live_arena = old_arena;
    coordinator.live_cfg = old_config;
    coordinator.published_generation = [_]u8{0x22} ** 32;
    defer if (coordinator.live_arena) |arena| {
        arena.deinit();
        testing.allocator.destroy(arena);
    };

    var probe = ReloadPublicationProbe{ .coordinator = &coordinator, .proposed = &proposed };
    const classifier = try std.Thread.spawn(.{}, ReloadPublicationProbe.classify, .{&probe});
    var classifier_joined = false;
    defer if (!classifier_joined) {
        probe.mutex.lock();
        probe.release_classification = true;
        probe.wake.broadcast();
        probe.mutex.unlock();
        classifier.join();
    };
    probe.mutex.lock();
    while (!probe.classified) probe.wake.wait(&probe.mutex);
    probe.mutex.unlock();

    const swapper = try std.Thread.spawn(.{}, ReloadPublicationProbe.swap, .{&probe});
    var swapper_joined = false;
    defer if (!swapper_joined) swapper.join();
    probe.mutex.lock();
    while (!probe.swap_started) probe.wake.wait(&probe.mutex);
    const swapped_while_classifying = probe.swap_done;
    probe.release_classification = true;
    probe.wake.broadcast();
    probe.mutex.unlock();

    classifier.join();
    classifier_joined = true;
    swapper.join();
    swapper_joined = true;
    const second = coordinator.inspectPublicationLocked(Coordinator.ReloadClassificationInput{ .proposed = &proposed }, Coordinator.classifyReloadLocked);

    try testing.expect(!swapped_while_classifying);
    try testing.expectEqual(reload_mod.Kind.live, probe.first_kind);
    try testing.expect(probe.swap_done);
    try testing.expectEqual(reload_mod.Kind.noop, second.classification.kind);
    try testing.expect(coordinator.live_arena == null);
    try testing.expect(coordinator.live_cfg == &proposed);
}
