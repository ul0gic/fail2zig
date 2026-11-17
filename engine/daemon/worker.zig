// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Runs the worker thread: each tick takes staged work, polls sources, steps effects and maintenance, and publishes health.
// Holds: Before the gate has ever been healthy, a tick failure other than the named pending or clock causes drains the log and exits.

const std = @import("std");
const effect_runtime = @import("../runtime/effect_runtime.zig");
const resource = @import("../runtime/resource_budget.zig");
const pipeline = @import("../source/record_pipeline.zig");
const native_banip = @import("../config/banip.zig");
const health = @import("../platform/storage_health.zig");
const build_options = @import("build_options");
const diag_mod = @import("../diag/diag.zig");
const ban_origin = @import("../effect/ban_origin.zig");
const daemon = @import("daemon.zig");
const tick_wait_ns = daemon.tick_wait_ns;
const MaintenanceMark = daemon.MaintenanceMark;
const MaintenanceGates = daemon.MaintenanceGates;

pub fn Methods(comptime Coordinator: type) type {
    return struct {
        const monotonic = Coordinator.monotonic;
        const stopRequested = Coordinator.stopRequested;
        const wallClockEffect = Coordinator.wallClockEffect;
        const observationMs = Coordinator.observationMs;
        const journalFailureDetail = Coordinator.journalFailureDetail;
        const logJournalFailure = Coordinator.logJournalFailure;
        const quiet_interval_ms = Coordinator.quiet_interval_ms;
        const maintenance_idle_ms = Coordinator.maintenance_idle_ms;
        const stop_history_budget_ns = Coordinator.stop_history_budget_ns;
        const shed_notice_interval_ms = Coordinator.shed_notice_interval_ms;
        const findConfigJail = Coordinator.findConfigJail;

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
                        // Why: process.exit skips the event loop's periodic drain, so a file log target would lose the refusal cause.
                        if (daemon.log_sink) |sink| sink.drain();
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
                if (self.fullStateFile()) try self.reclaimUnderPressure();
                return;
            }
            if (self.store.intake_closed) try self.reclaimUnderPressure();
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
                    self.history_caught_up = try self.consumeHistory() != .behind;
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
                        if (jail.session.? == .journal) logJournalFailure(jail, failure, diagnostic) else std.log.err("native jail {s}: {s}; source stuck, retried on every poll; see fail2zig status", .{ jail.name, @errorName(failure) });
                        try self.refreshSourceStatus(jail);
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

        fn applyBanLists(self: *Coordinator) !void {
            for (self.jails) |*jail| {
                if (!jail.banlist_pending or jail.retiring or !jail.admin_enabled) continue;
                if (jail.banlist_waiting != 0 and monotonic(self) -| jail.banlist_retry_ms < quiet_interval_ms) continue;
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
                jail.banlist_pending = change.pending != 0;
                jail.banlist_retry_ms = monotonic(self);
                jail.config_bans +|= change.added;
                if (change.added != 0 or change.lifted != 0 or change.expired != 0 or change.pending != jail.banlist_waiting)
                    std.log.info("native: jail={} banip applied: {d} added, {d} lifted, {d} unchanged, {d} expired, {d} waiting for state-file capacity", .{ std.zig.fmtEscapes(jail.name), change.added, change.lifted, change.unchanged, change.expired, change.pending });
                jail.banlist_waiting = change.pending;
            }
        }

        fn reportMaintenanceGates(self: *Coordinator, now_ms: u64) void {
            if (self.last_gate_report_ms) |last| if (now_ms -| last < 10_000) return;
            const g = self.gates;
            if (std.meta.eql(g, MaintenanceGates{})) return;
            std.log.debug("native: maintenance gates: slow={d} due={d} turns={d} unhealthy_gate={d} step={d}/{d}/{d} record_passes={d} record_deletes={d} records_parked={d}", .{ g.slow, g.due, g.turns, g.unhealthy_gate, g.step_progress, g.step_returned, g.step_wait, g.record_passes, g.record_deletes, g.records_parked });
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

        fn drainHistoryForStop(self: *Coordinator) void {
            if (self.gate.snapshot().phase != .healthy or !self.store_open or self.store.reopen_required) return;
            var timer = std.time.Timer.start() catch |failure| {
                std.log.warn("native: stop left the history consumer behind the head: {s}; the next start resumes it", .{@errorName(failure)});
                return;
            };
            var groups: usize = 0;
            while (timer.read() < stop_history_budget_ns) : (groups += 1) {
                const step = self.consumeHistory() catch |failure| {
                    std.log.warn("native: stop left the history consumer behind the head: {s}; the next start resumes it", .{@errorName(failure)});
                    return;
                };
                if (step != .behind) return;
            }
            std.log.warn("native: stop left the history consumer behind the head after {d} groups in {d} ms; the next start resumes it", .{ groups, timer.read() / std.time.ns_per_ms });
        }

        fn maintenanceMark(self: *Coordinator) !MaintenanceMark {
            return .{ .committed = self.gate.snapshot().committed_records, .epoch = self.store.effect_publication_epoch, .retry_revision = try self.store.retryStateRevision() };
        }

        fn cleanupRecords(self: *Coordinator) !void {
            const now_ms = monotonic(self);
            if (std.meta.eql(self.records_idle, try self.maintenanceMark()) and now_ms -| self.records_idle_since_ms < maintenance_idle_ms) {
                self.gates.records_parked += 1;
                return;
            }
            self.records_idle = null;
            self.gates.record_passes += 1;
            switch (try self.store.cleanupRecords(.{ .prepared_us = self.clock.wallUs(), .context = self, .read = wallClockEffect })) {
                .deleted => {
                    self.gates.record_deletes += 1;
                    self.maintenance_progress = true;
                },
                .scanned => self.maintenance_progress = true,
                .idle => {
                    self.records_idle = try self.maintenanceMark();
                    self.records_idle_since_ms = now_ms;
                },
            }
        }

        fn fullStateFile(self: *Coordinator) bool {
            const gate = self.gate.snapshot();
            if (gate.phase != .paused or !gate.has_been_healthy or !self.store_open or self.store.reopen_required or self.store.api.get_autocommit(self.store.db) == 0) return false;
            const failure = gate.last_failure orelse return false;
            return failure.cause == error.StorageFull or failure.cause == error.StorageCapacity;
        }

        fn reclaimUnderPressure(self: *Coordinator) !void {
            const now_ms = monotonic(self);
            if (self.reclaim_ms) |last| if (now_ms -| last < health.Fairness.maintenance_interval_ms) return;
            self.reclaim_ms = now_ms;
            const effects_usable = if (self.effects) |manager| !manager.status.uncertain else true;
            defer self.store.maintenance_operation = null;
            const cleanup = self.store.cleanupRecords(.{ .prepared_us = self.clock.wallUs(), .context = self, .read = wallClockEffect }) catch |failure| switch (failure) {
                error.MaintenancePinned, error.StaleMaintenance => .idle,
                else => return failure,
            };
            if (cleanup == .idle) _ = try self.store.shedStep(self.clock.wallUs(), effects_usable, &self.shed);
            self.noteShedding(now_ms);
        }

        fn noteShedding(self: *Coordinator, now_ms: u64) void {
            if (std.meta.eql(self.shed, self.shed_logged)) return;
            if (self.shed_notice_ms) |last| if (now_ms -| last < shed_notice_interval_ms) return;
            self.shed_notice_ms = now_ms;
            const shed = self.shed;
            const logged = self.shed_logged;
            self.shed_logged = shed;
            std.log.warn("native: state file under capacity pressure; shed {d} spent bookkeeping pages, {d} detail rows, {d} consumed events, {d} memory rows ({d}, {d}, {d}, {d} since start)", .{ shed.spent_pages - logged.spent_pages, shed.detail_rows - logged.detail_rows, shed.consumed_events - logged.consumed_events, shed.memory_rows - logged.memory_rows, shed.spent_pages, shed.detail_rows, shed.consumed_events, shed.memory_rows });
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
            if (self.history_page == null and self.history_caught_up and self.history_wait == null) _ = try self.consumeHistory();
            try self.cleanupRecords();
            const caught_up = if (self.history_page) |page| page.after_sequence == page.head_sequence and page.last_sequence == page.head_sequence else self.history_consumer == null;
            const effects_usable = if (self.effects) |manager| !manager.status.uncertain and !self.store.reopen_required else true;
            const now_ms = monotonic(self);
            const step_idle = !self.store.intake_closed and std.meta.eql(self.maintenance_idle, try self.maintenanceMark()) and now_ms -| self.maintenance_idle_since_ms < maintenance_idle_ms;
            var record_idle = false;
            // Why: The mark is taken after this turn's own writes, so only changes made elsewhere end the idle period.
            defer if (record_idle or step_idle) {
                self.maintenance_idle = self.maintenanceMark() catch null;
                if (record_idle) self.maintenance_idle_since_ms = now_ms;
            };
            if (!step_idle) self.maintenance_idle = null;
            switch (if (step_idle) .idle else try self.store.maintenanceStep(.{ .retention = .{ .age_us = age_us, .max_matches = self.live_cfg.global.history_max_matches }, .now_us = self.clock.wallUs(), .history_caught_up = caught_up, .spent_scopes = effects_usable, .shed = &self.shed })) {
                .progress => |operation| {
                    self.maintenance_progress = true;
                    self.confirmations_epoch = null;
                    self.gates.step_progress += 1;
                    if (operation == .history_rebuild or operation == .history_details or operation == .history_prefix) {
                        self.history_page = null;
                        self.gates.step_returned += 1;
                    }
                },
                .wait => {
                    self.maintenance_progress = true;
                    self.gates.step_wait += 1;
                },
                .idle => record_idle = !step_idle and caught_up,
            }
            self.noteShedding(now_ms);
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
    };
}
