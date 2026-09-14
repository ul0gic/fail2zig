// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Native daemon authority for constant-duration file and qualified SSH journal
//! policies, with typed enforcement. Unsupported protection refuses at admission.
//! A single worker owns SQLite and sources; IPC/HTTP read detached snapshots.
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
const inspection = @import("firewall/inspection.zig");
const path_guard = @import("config/native_paths.zig");
const durable = @import("core/record_store.zig");
const sessions = @import("core/native_file_session.zig");
const journal_projection = @import("config/native_journal_detection.zig");
const journal_sessions = @import("core/native_journal_session.zig");
const pipeline = @import("core/record_pipeline.zig");
const health = @import("core/storage_health.zig");
const recovery = @import("core/native_recovery.zig");
const loop_mod = @import("core/event_loop.zig");
const ipc = @import("net/ipc.zig");
const http = @import("net/http.zig");
const version = @import("build_options").version;
const max_jails = 64;
const max_sources_per_jail = 8;
const max_subjects_total = 4096;

const Plan = union(enum) {
    file: projection.Plan,
    journal: *journal_projection.Plan,
    fn deinit(self: *Plan, a: std.mem.Allocator) void {
        switch (self.*) {
            .file => |*plan| plan.deinit(a),
            .journal => |plan| plan.destroy(),
        }
    }
};
const Source = union(enum) {
    file: *sessions.Session,
    journal: *journal_sessions.Session,
    fn destroy(self: Source) void {
        switch (self) {
            .file => |source| source.destroy(),
            .journal => |source| source.destroy(),
        }
    }
    fn pipe(self: Source) *pipeline.Pipeline {
        return switch (self) {
            .file => |source| &source.pipe,
            .journal => |source| &source.pipe,
        };
    }
    fn generation(self: Source) [32]u8 {
        return switch (self) {
            .file => |source| source.processor.generation,
            .journal => |source| source.processor.generation,
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
        }
    }
    fn verify(self: Source) !bool {
        return switch (self) {
            .file => |source| try source.verifyRecoverySourcesTurn(),
            .journal => |source| try source.verifyRecoverySourcesTurn(),
        };
    }
    fn healthy(self: Source) bool {
        return switch (self) {
            .file => |source| source.admission_phase == .ready and source.sources.sources.items.len > 0 and source.repairSnapshot().phase == .healthy,
            .journal => |source| source.admission_phase == .ready and source.source_health == .healthy and source.repairSnapshot().phase == .healthy,
        };
    }
    fn exportRecovery(self: Source) !SourceSnapshot {
        return switch (self) {
            .file => |value| .{ .file = try value.exportRecovery() },
            .journal => |value| .{ .journal = try value.exportRecovery() },
        };
    }
    fn importRecovery(self: Source, snapshot: SourceSnapshot) !void {
        switch (self) {
            .file => |value| if (snapshot == .file) try value.importRecovery(snapshot.file) else return error.SourceGenerationMismatch,
            .journal => |value| if (snapshot == .journal) try value.importRecovery(snapshot.journal) else return error.SourceGenerationMismatch,
        }
    }
    fn resumeConsumer(self: Source, identity: []const u8) !void {
        switch (self) {
            .file => |value| _ = try value.resumeConsumerSource(identity),
            .journal => |value| _ = try value.resumeConsumerSource(identity),
        }
    }
};
const SourceSnapshot = union(enum) {
    file: *sessions.RecoverySnapshot,
    journal: *journal_sessions.RecoverySnapshot,
    fn destroy(self: SourceSnapshot) void {
        switch (self) {
            .file => |value| value.destroy(),
            .journal => |value| value.destroy(),
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
    /// Worker builds a full detached snapshot before locking its published copy.
    scratch: []durable.Store.ActiveDecision,
    active: []durable.Store.ActiveDecision,
    scratch_confirmed: []bool,
    confirmed: []bool,
    summary: durable.Store.RetrySummary = .{},
    revision: u64 = 0,
    healthy: bool = false,
    source_error: ?anyerror = null,
    zone: ?*timezone.Zone = null,
    maintenance_source: usize = 0,
    retire_next: bool = false,
    retire_after: ?detection.Subject = null,
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
    published_confirmations: u64 = 0,
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

    fn monotonic(ctx: ?*anyopaque) u64 {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        return self.timer.read() / std.time.ns_per_ms;
    }
    fn wallClock(_: ?*anyopaque) !i64 {
        return std.time.microTimestamp();
    }
    // Separate samples avoid sharing Timer.read's mutable state across threads.
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
    /// Caller holds the publication mutex; this never reads the live Store.
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
    fn resourceRequirements(cfg: *const config.Config, selected: []config.LogSource) !resource.Requirements {
        const environment = try resource.currentEnvironment();
        const descriptors = try resource.FdContext.observe(cfg.global.native_fd_ceiling, 32);
        var plan: resource.Plan = .{};
        try plan.include(resource.storeWorkspace());
        try plan.include(try resource.controlCost(cfg.global.metrics_enabled, 2 * shared.protocol.max_payload_size));
        try plan.includeDetached(try resource.publicationCost(max_subjects_total, @sizeOf(Coordinator) + selected.len * @sizeOf(Jail)));
        // The worker's explicitly configured stack and original parser arena
        // remain live alongside record preparation and detached IPC responses.
        try plan.include(.{ .live = .{ .bytes = try std.math.add(usize, cfg.retained_capacity, 16 * resource.mib), .allocations = 2, .fds = 2 } });
        var custom: usize = 0;
        var enforcing = false;
        var index: usize = 0;
        for (cfg.jails) |jail| {
            if (!jail.enabled) continue;
            var source = if (jail.source == .auto) cfg.defaults.source else jail.source;
            if (source == .auto) source = if (config.anyLogpathExists(jail.logpath)) .file else if (config.filterSupportsJournald(jail.filter) and config.journalctlPresent()) .journald else .file;
            selected[index] = source;
            index += 1;
            const capacity: usize = if (source == .journald) 1 else max_sources_per_jail;
            switch (source) {
                .file => try plan.include(try resource.fileCost(.{ .source_capacity = capacity, .spec_count = jail.logpath.len, .max_record_bytes = 2048, .max_decoded_bytes = 2048 })),
                .journald => try plan.include(try resource.journalCost(.{ .max_record_bytes = 2048, .max_decoded_bytes = 2048, .batch_records = 1, .environment = environment })),
                else => return error.NativeInternalEventsRequired,
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

    /// Immutable config must outlive this stable owner. All plans and aggregate
    /// allowances are validated before the database is opened or upgraded.
    pub fn create(a: std.mem.Allocator, cfg: *const config.Config) !*Coordinator {
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
        for (cfg.jails) |jail| if (jail.enabled) {
            count += 1;
        };
        if (count == 0 or count > max_jails) return error.NativeJailLimit;
        var selected_sources: [max_jails]config.LogSource = undefined;
        const requirements = try resourceRequirements(cfg, selected_sources[0..count]);
        const per_jail: u32 = @intCast(max_subjects_total / count);
        const self = try a.create(Coordinator);
        errdefer a.destroy(self);
        const timer = try std.time.Timer.start();
        self.* = .{ .allocator = a, .cfg = cfg, .jails = &.{}, .store = undefined, .timer = timer, .gate = undefined, .published_health = undefined, .start_us = std.time.microTimestamp(), .resources = resource.Ledger.init(requirements) };
        self.worker_observation = health.WorkerObservation.init(observationMs(), observationWall());
        // Immutable configuration fixes all owner capacities. Hold its complete
        // envelope, including recovery overlap, until the coordinator is destroyed.
        self.resource_reservation = try self.resources.reserve(.other, requirements.cost);
        errdefer self.releaseResources();
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
        var enforcing = false;
        for (cfg.jails) |jail| enforcing = enforcing or (jail.enabled and jail.effectiveBanaction(cfg.defaults) != .@"log-only");
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
                    if (selected.journal_executables.len == 0 or selected.journal_executables.len > 8) return error.InvalidJournalExecutables;
                    for (selected.journal_executables) |executable| {
                        var file = try std.fs.openFileAbsolute(executable, .{});
                        defer file.close();
                        const stat = try std.posix.fstat(file.handle);
                        if (!std.posix.S.ISREG(stat.mode) or stat.uid != 0 or stat.mode & 0o022 != 0 or stat.mode & 0o111 == 0) return error.UnqualifiedJournalExecutable;
                    }
                    const machine = try std.fs.cwd().readFileAlloc(a, "/etc/machine-id", 33);
                    defer a.free(machine);
                    break :blk .{ .journal = try journal_projection.Plan.create(a, &selected_cfg, 0, parent_generation, .{ .machine_id = std.mem.trim(u8, machine, "\n"), .executables = selected.journal_executables, .ignore_capacity = 128, .custom = assets != null, .journal = .{ .batch_records = 1, .matches = &.{ "SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session", "+", "_COMM=sshd", "_COMM=sshd-session" } } }) };
                },
                .auto => unreachable,
                .internal => return error.NativeInternalEventsRequired,
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
        if (enforcing) {
            self.namespace_lock = try std.fs.openFileAbsolute(cfg.global.firewall_namespace, .{});
            errdefer self.namespace_lock.?.close();
            try self.verifyNamespace();
            if (!try self.namespace_lock.?.tryLock(.exclusive)) return error.NativeNamespaceAlreadyRunning;
        }
        errdefer if (self.namespace_lock) |file| file.close();
        self.authority_lock = path_guard.lockState(cfg.global.state_file) catch |err| {
            std.log.err("native: state authority '{s}': {s}", .{ cfg.global.state_file, @errorName(err) });
            return err;
        };
        errdefer self.authority_lock.?.close();
        try self.verifyStateIdentity();
        self.store = try durable.Store.openRuntime(a, cfg.global.state_file);
        self.store_open = true;
        errdefer self.store.close();
        try self.verifyStateIdentity();
        try self.admitStore();
        // Validate durable cleanup state before any provisional first-use STATE
        // registration. Each read advances a typed keyset, bounded by the admitted
        // SQLite page ceiling; concurrent changes refuse instead of restarting it.
        while (!try self.store.validateMaintenanceTurn(&self.maintenance_validation)) {}
        try self.store.finishMaintenanceValidation(&self.maintenance_validation);
        self.maintenance_validated = true;
        errdefer if (self.effects) |manager| manager.destroy();
        errdefer self.destroyRuntime();
        // The initial STATE pass performs only private restore/registration.
        // One outer transaction makes first-use admission crash-atomic across
        // every jail; ownership/source work begins only after this commit.
        try self.store.beginStartupAdmission();
        errdefer self.store.abortStartupAdmission();
        try self.validateAdmission();
        var recovery_driver = self.driver();
        _ = try recovery_driver.poll();
        // Validate every persisted consumer generation before publishing IPC.
        // Runtime recovery remains sliced; startup has at most max_jails owners.
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
        try self.validateAdmission();
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
        try self.store.validateRuntimeAdmissions(admissions[0..self.jails.len], if (self.custom_jails != 0 and self.dns_server != null) self.dns_generation else null);
        if (try self.store.readInstallation()) |saved| {
            if (!std.mem.eql(u8, saved.selector(), self.cfg.global.firewall_namespace)) return error.InstallationMismatch;
            if (self.cfg.global.firewall != .auto and !std.mem.eql(u8, @tagName(saved.backend), @tagName(self.cfg.global.firewall))) return error.InstallationMismatch;
        }
    }
    fn preflightSource(_: []const u8, _: [32]u8, _: ?*anyopaque) anyerror!void {
        return error.ConsumerRuntimeNotReady;
    }
    /// Derive exactly the constructor identity without opening sources, consulting
    /// clocks, creating resolver state or admitting any first-use durable owner.
    fn plannedGeneration(self: *Coordinator, jail: *Jail) ![32]u8 {
        var registry = consumer_bridge.Registry.init([_]u8{0} ** 32);
        if (jail.custom_plan) |assets| {
            var settings = assets.settings;
            settings.journal_origin = switch (jail.plan) {
                .file => null,
                .journal => |value| &value.profile,
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
                if (jail.custom_plan != null) {
                    options.staged_detection = registry.consumer();
                    options.consumer_sources = .{ .context = null, .admit = preflightSource };
                }
                const processor = try journal_sessions.Session.prepareProcessor(self.allocator, options, &scratch, .{ .us = 0 });
                break :blk processor.generation;
            },
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
        for (self.jails, 0..) |jail, i| output[i] = .{ .jail = jail.name, .generation = switch (jail.session.?) {
            .file => |source| source.processor.generation,
            .journal => |source| source.processor.generation,
        } };
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
        for (self.jails) |jail| enforcing = enforcing or jail.policy.enforce;
        if (!enforcing) return;
        try self.verifyNamespace();
        var installation = try self.store.readInstallation();
        if (installation) |saved| {
            if (!std.mem.eql(u8, saved.selector(), self.cfg.global.firewall_namespace)) return error.InstallationMismatch;
            if (self.cfg.global.firewall != .auto and !std.mem.eql(u8, @tagName(saved.backend), @tagName(self.cfg.global.firewall))) return error.InstallationMismatch;
        } else {
            var id: [16]u8 = undefined;
            std.crypto.random.bytes(&id);
            var last_failure: anyerror = error.NoFirewallBackend;
            for ([_]effect.Backend{ .nftables, .ipset, .iptables }) |backend| {
                if (self.cfg.global.firewall != .auto and !std.mem.eql(u8, @tagName(backend), @tagName(self.cfg.global.firewall))) continue;
                const candidate = try effect.Installation.init(id, backend, self.cfg.global.firewall_namespace);
                var probe = try inspection.Inspector.open(self.allocator, effect_runtime.transportInstallation(candidate), .{});
                defer probe.close();
                var observed = probe.inspect() catch |failure| {
                    last_failure = failure;
                    continue;
                };
                defer observed.deinit();
                try probe.inspectReservedNamespace();
                try self.store.admitInstallation(candidate, .{ .selector = candidate.selector(), .disposition = .verified_absent });
                installation = candidate;
                break;
            }
            if (installation == null) return last_failure;
        }
        self.effects = try effect_runtime.Manager.create(self.allocator, &self.store, installation.?);
    }
    fn recoverStorage(ctx: ?*anyopaque) !void {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        if (self.gate.snapshot().has_been_healthy) {
            try self.verifyStateIdentity();
            // A rolled-back Busy/full/read-only transaction does not poison the
            // connection. Retaining it also preserves coherent finite-expiry
            // authority while writer admission remains unavailable. A genuinely
            // uncertain connection must discard its cache before reopening.
            if (!self.store_open or self.store.reopen_required) {
                if (self.effects) |manager| manager.storageReopened();
                if (self.store_open) {
                    self.store.close();
                    self.store_open = false;
                    // The recovery driver reads diagnostics even if reopen fails.
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
                    if (jail.session) |source| {
                        // Capture must succeed before releasing any original evidence.
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
                        options.gate = &self.gate;
                        options.monotonic_clock = .{ .context = self, .read = monotonic };
                        if (jail.consumer) |value| {
                            options.staged_detection = value.stagedConsumer();
                            options.consumer_sources = value.consumerSources();
                        }
                        break :blk .{ .journal = try journal_sessions.Session.createDeferred(self.allocator, &self.store, options) };
                    },
                };
                errdefer next.destroy();
                if (jail.source_snapshot) |snapshot| try next.importRecovery(snapshot);
                jail.session = next;
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
                    // Restore every durable owner before effect reconciliation or
                    // IPC publication, including temporarily unavailable sources.
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
                // Validate the complete persisted consumer set before touching
                // effects. Discovery may bootstrap new owners later, so repeat
                // this fence after source continuity has been established.
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
    fn consumeHistory(self: *Coordinator) !bool {
        const owner = if (self.history_consumer) |*value| value else return true;
        var events: [history.max_page]history.Event = undefined;
        const page = try self.store.confirmedEffectPage(owner.installation, owner.live.last_sequence, null, &events);
        if (page.count != 0) {
            const now = std.time.microTimestamp();
            const stage = try owner.prepare(page, events[0..page.count], now);
            defer stage.release();
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
                    // First-use source admission may commit a baseline and new
                    // ordering header. Validate that complete post-source view;
                    // never retag the earlier cleanup snapshot as current.
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
        for (jail.scratch[0..summary.active], 0..) |decision, i| jail.scratch_confirmed[i] = jail.policy.enforce and if (self.effects) |manager| manager.confirmedSubject(decision.subject, now) else false;
        const confirmations = if (self.effects != null) try self.store.confirmedEffectEvents() else 0;
        const session = jail.session.?;
        self.mutex.lock();
        defer self.mutex.unlock();
        @memcpy(jail.active[0..summary.active], jail.scratch[0..summary.active]);
        @memcpy(jail.confirmed[0..summary.active], jail.scratch_confirmed[0..summary.active]);
        self.published_confirmations = confirmations;
        jail.summary = summary;
        jail.revision = session.pipe().revision;
        jail.healthy = session.healthy();
    }
    fn publishSource(self: *Coordinator, jail: *Jail) void {
        const source = jail.session.?;
        const snapshot = switch (source) {
            .file => |value| value.repairSnapshot(),
            .journal => |value| value.repairSnapshot(),
        };
        self.mutex.lock();
        defer self.mutex.unlock();
        jail.healthy = source.healthy();
        jail.source_error = snapshot.last_cause;
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
        // Bind diagnostics to clocks already checked by the worker. A fresh
        // sample below this floor must remain uncertain, never be clamped up.
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
    }
    pub fn start(self: *Coordinator) !void {
        self.thread = try std.Thread.spawn(.{ .stack_size = 16 * resource.mib }, work, .{self});
    }
    fn work(self: *Coordinator) void {
        while (true) {
            self.stop_mutex.lock();
            if (self.stopping) {
                self.stop_mutex.unlock();
                return;
            }
            self.stop_mutex.unlock();
            self.mutex.lock();
            self.worker_observation.begin(observationMs(), observationWall());
            // Source/effect work can change committed owners before the next
            // coherent publication. Keep the previous absolute deadline visible.
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
            if (stopped) return;
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
            for (self.jails) |*jail| try self.publishJail(jail);
        }
        _ = try self.consumeHistory();
        if (self.dns) |resolver| {
            const result = try resolver.pollDns();
            if (result.kind == .ready) {
                const owner = result.source orelse return error.UnboundRequiredConsumer;
                for (self.jails) |*jail| if (jail.consumer) |consumer| {
                    if (!std.mem.eql(u8, consumer.settings.jail, owner.settings.jail)) continue;
                    // A zero-TTL subject belongs to this exact scheduler turn.
                    // Resume its original pending receipt before any other poll.
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
                // SQL failures have already closed the shared gate. Decode or
                // continuity failures belong to this jail and must not stop
                // independent owners of the same healthy store.
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
            // Pins and stale optional work are normal scheduling outcomes. No
            // authoritative state was changed; select fresh fences next turn.
            error.MaintenancePinned, error.StaleMaintenance => {},
            else => return failure,
        };
        if (try self.store.admissionClock()) |floor| {
            self.mutex.lock();
            self.worker_observation.wall_floor_us = if (self.worker_observation.wall_floor_us) |prior| @max(prior, floor.us) else floor.us;
            self.mutex.unlock();
        }
    }
    /// One optional writer slice after ordinary work. Source selection and subject
    /// iteration are bounded independently; no mark and delete share a turn.
    fn maintenanceTurn(self: *Coordinator) !void {
        if (self.gate.snapshot().phase != .healthy or self.jails.len == 0) return;
        if (self.effects) |manager| if (!manager.status.ready or manager.status.uncertain) return;
        const jail = &self.jails[self.maintenance_jail % self.jails.len];
        self.maintenance_jail = (self.maintenance_jail + 1) % self.jails.len;
        const session = jail.session orelse return;
        if (!session.healthy() or session.pipe().candidate_receipt != null) return;
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
        };
        if (source_count == 0) return;
        const source_index = jail.maintenance_source % source_count;
        const source_id = switch (session) {
            .file => |value| value.sources.sources.items[source_index].source_id,
            .journal => |value| value.options.source_id,
        };
        const generation = switch (session) {
            .file => |value| value.processor.generation,
            .journal => |value| value.processor.generation,
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
            .jail_revision = session.pipe().revision,
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
        // Rotate only on detail turns; alternating retirement must not starve
        // every second physical source in a jail with an even source count.
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
        const protection: []const u8 = if (!healthy) "degraded" else if (self.published_effects != null) "enforcing" else "log-only";
        try std.json.stringify(.{ .version = version, .runtime = "native", .state = protection, .protection = protection, .active_bans = installed, .total_bans = self.published_confirmations, .storage = @tagName(gate.phase), .cause = if (gate.phase == .intervention and gate.last_failure != null) @errorName(gate.last_failure.?.cause) else if (observation.clock_uncertain) "ClockUncertain" else if (observation.stalled) "WorkerStalled" else if (observation.expiry_overdue) "EffectExpiryOverdue" else if (observation.expiry_uncertain) "EffectViewUncertain" else if (gate.last_failure) |failure| @errorName(failure.cause) else if (self.published_effects) |effects| if (effects.cause) |cause| @errorName(cause) else "none" else "none", .sqlite_code = if (gate.last_failure) |failure| failure.diagnostics.sqlite_code else null, .next_retry_ms = gate.next_retry_ms, .committed_records = gate.committed_records, .decisions_total = decisions, .jails_active = self.jails.len, .backend = self.published_backend, .effects_uncertain = observation.expiry_uncertain or (if (self.published_effects) |effects| effects.uncertain else false), .overdue_effects = if (self.published_effects) |effects| effects.overdue else 0, .worker_busy = observation.busy, .worker_stalled = observation.stalled, .worker_busy_age_ms = observation.busy_age_ms, .worker_heartbeat_age_ms = observation.heartbeat_age_ms, .clock_uncertain = observation.clock_uncertain, .expiry_overdue = observation.expiry_overdue, .expiry_uncertain = observation.expiry_uncertain, .next_committed_expiry_us = observation.next_committed_expiry_us, .uptime_seconds = if (observation.clock_uncertain) @as(?u64, null) else @as(u64, @intCast(@max(0, @divTrunc(now -| self.start_us, 1_000_000)))) }, .{}, out.writer(a));
    }
    fn confirmationReady(self: *const Coordinator, observation: health.WorkerStatus) bool {
        return observationHealthy(observation) and self.published_health.phase == .healthy and if (self.published_effects) |effects| effects.ready and !effects.uncertain else false;
    }
    fn confirmedCount(self: *const Coordinator, jail: Jail, now: i64, observation: health.WorkerStatus) u32 {
        if (!self.confirmationReady(observation)) return 0;
        var count: u32 = 0;
        for (jail.active[0..jail.summary.active], 0..) |decision, i| if (jail.confirmed[i] and decision.expiry_us > now) {
            count += 1;
        };
        return count;
    }
    fn bans(ctx: ?*anyopaque, out: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator) !void {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        try self.writeBans(out, a, null);
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
            for (jail.active[0..jail.summary.active], 0..) |decision, i| {
                if (!observation.clock_uncertain and sampled_wall != null and decision.expiry_us <= sampled_wall.?) continue;
                if (!first) try w.writeByte(',');
                first = false;
                const address: shared.IpAddress = switch (decision.subject) {
                    .v4 => |v| .{ .ipv4 = std.mem.readInt(u32, &v, .big) },
                    .v6 => |v| .{ .ipv6 = std.mem.readInt(u128, &v, .big) },
                };
                var buffer: [64]u8 = undefined;
                const formatted = try std.fmt.bufPrint(&buffer, "{}", .{address});
                const confirmed = jail.confirmed[i] and self.confirmationReady(observation);
                try std.json.stringify(.{ .ip = formatted, .jail = jail.name, .expiry_us = decision.expiry_us, .ban_expiry = @divFloor(decision.expiry_us, 1_000_000), .ban_count = decision.ordinal, .enforced = confirmed, .confirmed = confirmed }, .{}, w);
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
                    try std.json.stringify(.{ .name = jail.name, .healthy = jail.healthy and self.published_health.phase == .healthy and observationHealthy(observation), .enabled = true, .active_bans = self.confirmedCount(jail, sampled_wall orelse self.start_us, observation), .maxretry = jail.policy.maxretry, .findtime = @divTrunc(jail.policy.window_us, 1_000_000), .bantime = @divTrunc(jail.policy.bantime_us, 1_000_000), .action = if (jail.policy.enforce) self.published_backend else "log-only", .enforcing = jail.policy.enforce and self.confirmationReady(observation), .log_source = @tagName(jail.plan), .source_healthy = jail.healthy and self.published_health.phase == .healthy and observationHealthy(observation), .source = @tagName(jail.plan), .revision = jail.revision, .decisions = jail.summary.decisions, .cause = if (jail.source_error) |cause| @errorName(cause) else "none" }, .{}, w);
                }
                try w.writeAll("]");
            },
            .ban, .unban, .reload => return .{ .err = .{ .code = 503, .message = try a.dupe(u8, "Native administrative mutation is not integrated; no state was changed") } },
        }
        return .{ .ok = .{ .payload = try output.toOwnedSlice(a) } };
    }
};

fn terminate(_: *const std.os.linux.signalfd_siginfo, ctx: ?*anyopaque) void {
    const loop: *loop_mod.EventLoop = @ptrCast(@alignCast(ctx.?));
    loop.stop();
}
fn reload(_: *const std.os.linux.signalfd_siginfo, _: ?*anyopaque) void {
    std.log.warn("native reload is not integrated; current configuration retained", .{});
}
pub fn run(a: std.mem.Allocator, cfg: *const config.Config) !void {
    const coordinator = try Coordinator.create(a, cfg);
    defer coordinator.destroy();
    var loop = try loop_mod.EventLoop.init(a);
    defer loop.deinit();
    // Block signals before starting the worker so it inherits the signal mask.
    try loop.addSignalHandler(std.os.linux.SIG.TERM, terminate, &loop);
    try loop.addSignalHandler(std.os.linux.SIG.INT, terminate, &loop);
    try loop.addSignalHandler(std.os.linux.SIG.HUP, reload, &loop);
    try path_guard.validate(a, cfg);
    try coordinator.verifyStateIdentity();
    var server = try ipc.IpcServer.init(a, &loop, cfg.global.socket_path);
    defer server.deinit();
    server.setCommandHandler(.{ .ctx = coordinator, .dispatch = Coordinator.command });
    try server.start();
    var web: ?http.HttpServer = null;
    defer if (web) |*value| value.deinit();
    if (cfg.global.metrics_enabled) {
        web = http.HttpServer.init(a, &loop, cfg.global.metrics_port, cfg.global.metrics_bind) catch |err| {
            std.log.err("native: HTTP listener {s}:{d}: {s}", .{ cfg.global.metrics_bind, cfg.global.metrics_port, @errorName(err) });
            return err;
        };
        web.?.setStatusSource(.{ .ctx = coordinator, .write = Coordinator.status });
        web.?.setBansSource(.{ .ctx = coordinator, .write = Coordinator.bans });
        web.?.setMetricsSource(.{ .ctx = coordinator, .write = Coordinator.metrics });
        try web.?.start();
    }
    try coordinator.start();
    std.log.info("fail2zig {s} running; native SQLite ingestion; protection admission pending; ipc={s}", .{ version, cfg.global.socket_path });
    try loop.run();
}
