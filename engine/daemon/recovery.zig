// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Recovers storage, effects, ownership, history and sources into runtime state at startup and after a storage failure.
// Holds: The state path must still name, without following a symlink, the regular file whose lock is held; anything else refuses.

const std = @import("std");
const effect = @import("../effect/effect.zig");
const effect_runtime = @import("../runtime/effect_runtime.zig");
const consumer_runtime = @import("../runtime/consumer_runtime.zig");
const resource = @import("../runtime/resource_budget.zig");
const history = @import("../effect/effect_history.zig");
const recurrence = @import("../detect/recurrence.zig");
const durable = @import("../store/store.zig");
const sessions = @import("../source/file_session.zig");
const pipeline = @import("../source/record_pipeline.zig");
const journal_sessions = @import("../source/journal_session.zig");
const health = @import("../platform/storage_health.zig");
const recovery = @import("../source/recovery.zig");
const build_options = @import("build_options");
const diag_mod = @import("../diag/diag.zig");
const clock_mod = @import("../time/clock.zig");
const daemon = @import("daemon.zig");
const max_jails = daemon.max_jails;
const max_sources_per_jail = daemon.max_sources_per_jail;
const recovery_validation_budget_ns = daemon.recovery_validation_budget_ns;
const Source = daemon.Source;
const Jail = daemon.Jail;
const logStateOpenFailure = daemon.logStateOpenFailure;
const lockFirewallNamespace = daemon.lockFirewallNamespace;
const preflightBackend = daemon.preflightBackend;

pub fn Methods(comptime Coordinator: type) type {
    return struct {
        const monotonic = Coordinator.monotonic;
        const bindDecay = Coordinator.bindDecay;
        const setJailPaused = Coordinator.setJailPaused;
        const wallClock = Coordinator.wallClock;
        const sessionProcessor = Coordinator.sessionProcessor;
        const HistoryStep = Coordinator.HistoryStep;
        const journalFailureDetail = Coordinator.journalFailureDetail;
        const logJournalFailure = Coordinator.logJournalFailure;
        const verify_interval_ns = Coordinator.verify_interval_ns;
        const audit_interval_ns = Coordinator.audit_interval_ns;

        pub fn driver(self: *Coordinator) recovery.Driver {
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
                    const step = self.consumeHistory() catch |failure| {
                        if (failure == error.RetryEligibilityPending) {
                            self.retryPublicationPending(null);
                            return false;
                        }
                        return failure;
                    };
                    if (step == .behind) return false;
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

        // Holds: The state path must still name, without following a symlink, the regular file whose lock is held; anything else refuses.
        pub fn verifyStateIdentity(self: *Coordinator) !void {
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

        // Holds: A saved installation must equal the startup one; a new one is recorded only when none was persisted before the probe.
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

        pub fn destroyEffects(self: *Coordinator) void {
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

        pub fn ensureRetirementEffects(self: *Coordinator) !void {
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

        pub fn dropRuntimeJail(jail: *Jail) void {
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

        pub fn destroyRuntime(self: *Coordinator) void {
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

        pub fn prepareRetryProjection(self: *Coordinator) !void {
            var names: [max_jails][]const u8 = undefined;
            for (self.jails, 0..) |jail, i| names[i] = jail.name;
            try self.store.prepareRetryAdmissionView(names[0..self.jails.len], self.clock.wallUs());
        }

        pub fn clearRetryPublication(self: *Coordinator) void {
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

        fn historyWaits(cause: anyerror) bool {
            return pipeline.Pipeline.commitBlocked(cause) and cause != error.RetryEligibilityPending;
        }

        pub fn consumeHistory(self: *Coordinator) !HistoryStep {
            const diag_span = if (comptime build_options.diag) diag_mod.enter(.history) else {};
            defer if (comptime build_options.diag) diag_mod.leave(diag_span);
            const owner = if (self.history_consumer) |*value| value else return .caught_up;
            var prepared: [durable.Store.max_history_commit_pages]history.Consumer = undefined;
            var commits: [durable.Store.max_history_commit_pages]durable.Store.HistoryCommit = undefined;
            var events: [history.max_page]history.Event = undefined;
            var count: usize = 0;
            var wait: ?anyerror = null;
            while (count < self.history_commit_pages) {
                prepared[count] = if (count == 0) owner.* else prepared[count - 1];
                const next = &prepared[count];
                var page = try self.store.confirmedEffectPage(owner.installation, next.live.last_sequence, null, &events);
                if (page.count == 0) {
                    if (count != 0) break;
                    try self.store.validateConfirmedEffectPage(page.token);
                    self.history_page = page.token;
                    self.history_wait = null;
                    return .caught_up;
                }
                const now = self.clock.wallUs();
                var stage = try next.prepare(page, events[0..page.count], now);
                defer stage.release();
                if (self.recidiveJail()) |jail| {
                    const processed = for (events[0..page.count], 0..) |event, index| {
                        _ = recurrence.consume(&self.store, .{ .jail = jail.name, .generation = jail.session.?.generation(), .policy = jail.policy, .suppress_enforcement = self.suppress_enforcement, .decay = jail.decay }, event, now, .{ .prepared_us = now, .context = self, .read = processingClock }) catch |failure| {
                            if (!historyWaits(failure)) return failure;
                            wait = failure;
                            break index;
                        };
                    } else page.count;
                    if (wait != null) {
                        stage.release();
                        if (processed == 0) break;
                        page = try self.store.confirmedEffectPage(owner.installation, next.live.last_sequence, null, events[0..processed]);
                        if (page.count != processed) return error.InvalidHistoryPage;
                        stage = try next.prepare(page, events[0..page.count], now);
                    }
                }
                commits[count] = .{ .batch = try stage.batch(.{ .prepared_us = now, .context = self, .read = processingClock }), .token = page.token };
                // Why: Only the prepared copy advances here; owner.live takes it after commitConfirmedHistoryGroup succeeds.
                stage.publish();
                count += 1;
                if (wait != null or !page.more) break;
            }
            if (wait) |cause| if (self.history_wait == null) std.log.warn("native: recidive history consumption waits: {s}; processed events keep their checkpoint and the rest resume when room returns", .{@errorName(cause)});
            self.history_wait = wait;
            if (count == 0) {
                self.history_page = null;
                return .waiting;
            }
            const internal: ?durable.Store.InternalSource = if (self.recidiveJail()) |jail| .{ .jail = jail.name, .generation = jail.session.?.generation() } else null;
            if (!try self.store.commitConfirmedHistoryGroup(owner.manifest(), commits[0..count], internal)) {
                self.history_commit_pages = @intCast(@max(@as(usize, 1), count / 2));
                self.history_page = null;
                return .behind;
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
            return if (wait != null) .waiting else .behind;
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
    };
}
