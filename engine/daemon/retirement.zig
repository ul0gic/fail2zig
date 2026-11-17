// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Retires removed and unconfigured jails and old retry subjects in bounded steps.
// Holds: A retry-retirement batch that yields halves the next batch size and never drops it below one row.

const std = @import("std");
const effect = @import("../effect/effect.zig");
const effect_runtime = @import("../runtime/effect_runtime.zig");
const durable = @import("../store/store.zig");
const daemon = @import("daemon.zig");
const max_jails = daemon.max_jails;
const tick_wait_ns = daemon.tick_wait_ns;
const Jail = daemon.Jail;
const destroyZone = daemon.destroyZone;

pub fn Methods(comptime Coordinator: type) type {
    return struct {
        const stopRequested = Coordinator.stopRequested;
        const wallClockEffect = Coordinator.wallClockEffect;
        const dropRuntimeJail = Coordinator.dropRuntimeJail;
        const findConfigJail = Coordinator.findConfigJail;

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
                self.reportStartup(
                    .maintenance,
                    std.fmt.bufPrint(&label, "jail retirement: {d} releases, {d} deleted", .{ owners_released, deleted_rows }) catch "jail retirement",
                    self.startup_retirement_progress,
                    0,
                );
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
            std.log.info(
                "native: jail={} retirement completed this start: {d} owner releases, {d} bans lifted, {d} operational rows deleted",
                .{ std.zig.fmtEscapes(intent.jail.slice()), owners_released, bans_lifted, deleted_rows },
            );
            if (self.findJail(intent.jail.slice())) |jail| if (jail.retiring) {
                const index = (@intFromPtr(jail) - @intFromPtr(self.jails.ptr)) / @sizeOf(Jail);
                try self.removeJail(index);
            };
        }

        pub fn retireUnconfiguredJails(self: *Coordinator) !void {
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

        pub fn retireUnusedSharedDns(self: *Coordinator) !void {
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

        fn logJailRemoved(name: []const u8, bans_lifted: u32) void {
            std.log.info("native: jail={} removed: {d} bans lifted", .{ std.zig.fmtEscapes(name), bans_lifted });
        }

        pub fn retireRemovedJail(self: *Coordinator) !bool {
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

        pub fn retirementStep(self: *Coordinator) !void {
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
                };
                const batch = self.store.retireRetrySubjects(fence, pass.after, now_us, jail.policy.window_us, pass.max) catch |failure| switch (failure) {
                    error.StaleMaintenance, error.MaintenancePinned, error.RetryAdmissionRequired => {
                        self.retire_refused += 1;
                        return;
                    },
                    else => return failure,
                };
                if (batch.yielded) {
                    // Why: A yielded batch rolled back cleanly, so jail.retirement keeps its marks and cursor; only the batch size halves.
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
                        // Why: Restarting from the first subject revisits those behind the cursor after outside changes or a due recheck.
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
    };
}
