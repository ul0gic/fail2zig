// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const shared = @import("shared");
const config = @import("config/native.zig");
const detection = @import("core/native_detection_record.zig");
const effect = @import("core/native_effect.zig");
const effect_runtime = @import("runtime/native_effect_runtime.zig");
const inspection = @import("firewall/inspection.zig");
const durable = @import("core/record_store.zig");
const ignore_set = @import("core/native_ignore_set.zig");
const RuntimeIgnoreEntry = @import("store/ignore_entries.zig").RuntimeIgnoreEntry;
const audit = @import("core/audit.zig");
const ban_origin = @import("core/ban_origin.zig");
const source_repair = @import("store/source_repair.zig");
const daemon = @import("native_daemon.zig");
const max_jails = daemon.max_jails;
const Jail = daemon.Jail;
const AdminReadback = enum { pending, uncertain, coherent };

fn adminReadback(effect_health: effect_runtime.Health, cached_epoch: ?u64, store_epoch: u64) AdminReadback {
    if (effect_health.uncertain) return .uncertain;
    if (effect_health.ready and cached_epoch != null and cached_epoch.? == store_epoch) return .coherent;
    return .pending;
}

pub fn Methods(comptime Coordinator: type) type {
    return struct {
        const AdminOutcomeView = Coordinator.AdminOutcomeView;
        const AdminPhase = Coordinator.AdminPhase;
        const AdminRequest = Coordinator.AdminRequest;
        const IgnoreEntryState = Coordinator.IgnoreEntryState;
        const IgnoreRelation = Coordinator.IgnoreRelation;
        const IgnoreWork = Coordinator.IgnoreWork;
        const configuredIgnoreDeadlines = Coordinator.configuredIgnoreDeadlines;
        const findConfigJail = Coordinator.findConfigJail;
        const formatListSubject = Coordinator.formatListSubject;
        const ignoreCell = Coordinator.ignoreCell;
        const ignoreSourceText = Coordinator.ignoreSourceText;
        const max_lifted_bans = Coordinator.max_lifted_bans;
        const monotonic = Coordinator.monotonic;
        const setJailPaused = Coordinator.setJailPaused;
        const stopRequested = Coordinator.stopRequested;
        const wallClockEffect = Coordinator.wallClockEffect;
        const max_listed_bans = 256;
        const ignore_lift_budget_ms: u64 = 1000;
        const ignore_lift_settle_ms: u64 = 2000;
        const ignore_unban_wait_ms: u64 = 4000;
        pub fn freeAdminRequest(self: *Coordinator, request: *AdminRequest) void {
            if (request.ignore) |ignore_state| self.allocator.destroy(ignore_state);
            self.allocator.destroy(request);
        }
        pub const Staged = struct { view: AdminOutcomeView, owned: bool };
        pub fn enqueueAdminLocked(self: *Coordinator, request: *AdminRequest) ?Staged {
            if (self.admin_request != null) return .{ .view = (AdminOutcomeView{ .outcome = .rejected, .kind = request.kind }).withReason("administration already in progress", .{}), .owned = true };
            self.admin_request = request;
            return null;
        }
        pub fn expireAdminWaitLocked(self: *Coordinator, request: *AdminRequest, wait_ms: u64) Staged {
            if (request.phase == .staged) {
                self.admin_request = null;
                return .{ .view = (AdminOutcomeView{ .outcome = .rejected, .kind = request.kind }).withReason("worker did not accept the request within {d} ms; no state was changed", .{wait_ms}), .owned = true };
            }
            request.abandoned = true;
            return .{ .view = (AdminOutcomeView{ .outcome = .uncertain, .kind = request.kind, .generation = self.published_generation }).withReason("worker is still executing the request; inspect status and the recorded outcome", .{}), .owned = false };
        }
        pub fn adminWorkLocked(self: *Coordinator) ?struct { request: *AdminRequest, phase: AdminPhase } {
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
        pub fn completeAdmin(self: *Coordinator, request: *AdminRequest, outcome: AdminOutcomeView) void {
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
        pub fn adminDetail(self: *Coordinator, request: *AdminRequest, view: AdminOutcomeView, state: ?durable.Store.JailAdminState) AdminOutcomeView {
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
        pub fn adminScope(self: *Coordinator, request: *AdminRequest) !@import("firewall/scope.zig").Scope {
            const address = request.address orelse return error.AdminAddressRequired;
            const canonical = @import("firewall/scope.zig");
            const subject = if (request.prefix) |prefix| blk: {
                const manager = self.effects orelse return error.AdminEnforcementRequired;
                if (manager.installation.backend == .iptables) return error.AdminNetworkScopeUnsupported;
                break :blk try canonical.Subject.network(address, prefix);
            } else canonical.Subject.host(address);
            return .{ .subject = subject };
        }
        pub fn executeAdmin(self: *Coordinator, request: *AdminRequest) void {
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
        pub fn executeAdminInner(self: *Coordinator, request: *AdminRequest) !AdminOutcomeView {
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
                .repair_source => return self.executeRepairSource(request, base, now),
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
                    const origin = try self.store.originForScope(key, jail.name);
                    const clock = effect.Clock{ .prepared_us = now, .context = self, .read = wallClockEffect };
                    if (kind == .ban) {
                        switch (ban_origin.manualOutcome(origin)) {
                            .refuse_config => return self.adminDetail(request, (AdminOutcomeView{ .outcome = .rejected, .kind = kind }).withReason("{s}", .{ban_origin.refused_config_text}), null),
                            .set_manual, .extend_as_manual => {},
                        }
                        const duration: @import("core/native_lease.zig").Duration = if (request.duration_s) |seconds| try @import("core/native_lease.zig").Duration.finiteSeconds(seconds) else jail.policy.duration;
                        const lease = try duration.lease(now);
                        noteIgnoredTarget(request, jail);
                        _ = try self.store.setOwnerFromCanonical(.{ .scope = canonical, .jail = jail.name, .generation = generation, .decision_id = durable.Store.adminDecisionId(request.request_id, request.expected_revision), .expected_revision = if (current) |owner| owner.revision else 0, .lease = lease, .decided_us = now, .origin = .manual }, clock);
                        jail.manual_bans +|= 1;
                        request.expect_absent = false;
                    } else {
                        if (origin) |held| if (held.origin == .config) return self.adminDetail(request, (AdminOutcomeView{ .outcome = .rejected, .kind = kind }).withReason("{s}", .{ban_origin.refused_config_text}), null);
                        const owner = current orelse return self.adminDetail(request, (AdminOutcomeView{ .outcome = .absent, .kind = kind }).withReason("no owner for this scope in the jail", .{}), null);
                        if (owner.lease == .absent) return self.adminDetail(request, (AdminOutcomeView{ .outcome = .absent, .kind = kind }).withReason("owner already released", .{}), null);
                        _ = try self.store.transitionOwner(.{ .scope = canonical, .jail = jail.name, .current_generation = owner.generation, .next_generation = owner.generation, .expected_owner_revision = owner.revision, .transition_id = request.request_id, .mode = .release, .occurred_us = now }, clock);
                        request.mutation_committed = true;
                        if (request.prefix == null) _ = try self.store.releaseRetryDecision(jail.name, hostSubject(request.address.?), now);
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
                    const subject = hostSubject(address);
                    const scope: durable.HistoryResetScope = if (request.all) .overall else .{ .jail = request.jailName() };
                    if (!request.all and self.findJail(request.jailName()) == null) return self.adminDetail(request, (AdminOutcomeView{ .outcome = .absent, .kind = kind }).withReason("unknown jail", .{}), null);
                    const expected = try self.store.historyResetRevision(scope, subject);
                    _ = try self.store.resetHistory(.{ .scope = scope, .subject = subject, .expected_revision = expected, .intent_id = request.request_id }, .{ .prepared_us = now, .context = self, .read = wallClockEffect });
                    return self.adminDetail(request, base, null);
                },
            }
        }
        pub fn executeRepairSource(self: *Coordinator, request: *AdminRequest, base: AdminOutcomeView, now: i64) !AdminOutcomeView {
            const name = request.jailName();
            const jail = self.findJail(name) orelse return self.adminDetail(request, (AdminOutcomeView{ .outcome = .absent, .kind = request.kind }).withReason("unknown jail", .{}), null);
            var diagnostic: source_repair.Diagnostic = .{};
            const outcome = self.store.repairSourceOnline(.{ .jail = name, .path = request.repair_path[0..request.repair_path_len], .token = request.repair_token[0..request.repair_token_len] }, now, &diagnostic) catch |failure| {
                request.repair_shape = diagnostic.shape;
                if (failure == error.LossAlreadyRecorded) return self.adminDetail(request, base.withReason("{s}", .{source_repair.Headline.loss_recorded}), null);
                return self.adminDetail(request, (AdminOutcomeView{ .outcome = .rejected, .kind = request.kind }).withReason("{s}", .{@errorName(failure)}), null);
            };
            defer outcome.deinit(self.store.allocator);
            request.repair_shape = diagnostic.shape;
            request.resumed_offset = if (outcome.removed) |removed| removed.current_offset orelse 0 else 0;
            if (!outcome.replayed) {
                request.mutation_committed = true;
                jail.rekeyed = true;
                self.gate.requestRebuild() catch |failure| std.log.warn("native: jail={} source repaired; reading resumes with the next recovery: {s}", .{ std.zig.fmtEscapes(name), @errorName(failure) });
            }
            return self.adminDetail(request, base.withReason("{s}", .{source_repair.headline(outcome)}), null);
        }
        pub fn hostSubject(address: shared.IpAddress) detection.Subject {
            return switch (address) {
                .ipv4 => |v| .{ .v4 = @bitCast(std.mem.nativeToBig(u32, v)) },
                .ipv6 => |v| .{ .v6 = @bitCast(std.mem.nativeToBig(u128, v)) },
            };
        }
        pub fn noteIgnoredTarget(request: *AdminRequest, jail: *const Jail) void {
            const cell = ignoreCell(jail) orelse return;
            const item = cell.*.check(request.address.?) orelse return;
            var text: [64]u8 = undefined;
            const written = std.fmt.bufPrint(&request.warning.bytes, "{s} is on the ignore list ({s})", .{ formatAdminTarget(request, &text), ignoreSourceText(item.source).? }) catch request.warning.bytes[0..0];
            request.warning.len = @intCast(written.len);
        }
        pub fn formatAdminTarget(request: *const AdminRequest, buffer: *[64]u8) []const u8 {
            const address = request.address orelse return "-";
            return (if (request.prefix) |prefix| std.fmt.bufPrint(buffer, "{}/{d}", .{ address, prefix }) else std.fmt.bufPrint(buffer, "{}", .{address})) catch "-";
        }
        pub fn activateMigration(self: *Coordinator, request: *AdminRequest, base: AdminOutcomeView, now: i64) !AdminOutcomeView {
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
        pub fn rollbackMigration(self: *Coordinator, request: *AdminRequest, base: AdminOutcomeView, now: i64) !AdminOutcomeView {
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
        pub fn closeInterruptedMigrationStep(self: *Coordinator, run_id: [32]u8, now: i64) !void {
            if (try self.store.pendingMigrationStep(run_id)) |open| {
                if (open.step == .rollback) return error.MigrationRollbackOpen;
                try self.store.finishMigrationStep(run_id, open.seq, .uncertain, "interrupted before its outcome was recorded", null, now);
            }
        }
        pub fn settleMigration(self: *Coordinator, request: *AdminRequest, manager: *effect_runtime.Manager) ?AdminOutcomeView {
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
        pub fn finishMigrationVerify(self: *Coordinator, request: *AdminRequest, view: AdminOutcomeView) void {
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
        pub fn withdrawFirewall(self: *Coordinator, request: *AdminRequest) AdminOutcomeView {
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
        pub fn settleAdmin(self: *Coordinator, request: *AdminRequest) void {
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
            source: ?[]const u8 = null,
            token: ?[]const u8 = null,
            origin: ?[]const u8 = null,
            expected_generation: []const u8,
            expected_mutation_revision: u64,
        };
        pub fn auditCommand(kind: durable.Store.AdminKind) ?[]const u8 {
            return switch (kind) {
                .ban => "ban",
                .unban => "unban",
                .ignore_add => "ignore add",
                .ignore_remove => "ignore remove",
                .group_pause => "jail pause",
                .group_resume => "jail resume",
                .group_enable => "jail enable",
                .group_disable => "jail disable",
                .history_reset => "history reset",
                .repair_source => "repair-source",
                .setting_batch, .migration_activate, .migration_rollback, .firewall_withdraw => null,
            };
        }
        pub fn auditAdmin(kind: durable.Store.AdminKind, body: AdminBody, outcome: durable.Store.AdminOutcome, peer_uid: u32) void {
            const command_name = auditCommand(kind) orelse return;
            var buffer: [96]u8 = undefined;
            const target: []const u8 = switch (kind) {
                .group_pause, .group_resume, .group_enable, .group_disable => body.jail orelse "-",
                .repair_source => body.source orelse "-",
                else => if (body.address) |address| (if (body.prefix) |prefix| std.fmt.bufPrint(&buffer, "{s}/{d}", .{ address, prefix }) catch address else address) else "-",
            };
            audit.write(.{ .command = command_name, .target = target, .jail = body.jail, .peer_uid = peer_uid, .outcome = @tagName(outcome) });
        }
        pub fn adminResponse(self: *Coordinator, out: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator, frame: shared.Command.Request, peer_uid: u32) !shared.Response {
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
            if (kind == .repair_source) {
                const path = body.source orelse return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "source is required") } };
                const token = body.token orelse return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "token is required") } };
                if (path.len == 0 or path.len > request.repair_path.len) return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "source path length") } };
                if (token.len == 0 or token.len > request.repair_token.len) return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "token length") } };
                @memcpy(request.repair_path[0..path.len], path);
                request.repair_path_len = path.len;
                @memcpy(request.repair_token[0..token.len], token);
                request.repair_token_len = token.len;
            }
            if (kind == .ignore_add) if (request.duration_s) |seconds| if (seconds == 0 or seconds > shared.types.TimedEntry.max_duration_s)
                return .{ .err = .{ .code = 400, .message = try a.dupe(u8, "invalid duration") } };
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
            auditAdmin(kind, body, view.outcome, peer_uid);
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
            if (staged.owned and kind == .ban and request.warning.len != 0) {
                try w.writeAll(",\"warning\":");
                try std.json.encodeJsonString(request.warning.slice(), .{}, w);
            }
            if (staged.owned and kind == .repair_source) {
                if (request.repair_shape) |shape| try w.print(",\"shape\":\"{s}\"", .{@tagName(shape)});
                if (view.outcome == .applied) if (request.resumed_offset) |offset| try w.print(",\"resumed_offset\":{d}", .{offset});
            }
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
        pub fn writeIgnoreEntries(w: anytype, entries: []const shared.types.IgnoreEntry) !void {
            try w.writeAll("[");
            for (entries, 0..) |item, i| {
                if (i > 0) try w.writeByte(',');
                var buffer: [64]u8 = undefined;
                try std.json.encodeJsonString(item.canonical(&buffer), .{}, w);
            }
            try w.writeAll("]");
        }
        pub fn writeIgnoreFields(w: anytype, request: *const AdminRequest, ignore_state: ?*const IgnoreWork) !void {
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
            if (request.duration_s != null) if (ignore_state) |value| if (value.expires_us) |deadline| try w.print(",\"expires_us\":{d}", .{deadline});
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
        pub fn ignoreRefusal(self: *Coordinator, request: *AdminRequest, outcome: durable.Store.AdminOutcome, comptime fmt: []const u8, args: anytype) AdminOutcomeView {
            return self.adminDetail(request, (AdminOutcomeView{ .outcome = outcome, .kind = request.kind }).withReason(fmt, args), null);
        }
        pub fn ignoreUncertain(self: *Coordinator, request: *AdminRequest) AdminOutcomeView {
            return self.ignoreRefusal(request, .uncertain, "the ignore entry may or may not have been recorded; run fail2zig ignore list --jail {s} to see the current list", .{request.jailName()});
        }
        pub fn recordConfiguredCover(ignore_state: *IgnoreWork, list: *const ignore_set.EffectiveIgnore, entry: shared.types.IgnoreEntry, include_equal: bool) void {
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
        pub fn entryLess(_: void, a: shared.types.IgnoreEntry, b: shared.types.IgnoreEntry) bool {
            return a.order(b) == .lt;
        }
        pub fn subjectEntry(subject: inspection.canonical_scope.Subject) shared.types.IgnoreEntry {
            return .{ .family = switch (subject.family) {
                .v4 => .v4,
                .v6 => .v6,
            }, .address = subject.address, .prefix = subject.prefix };
        }
        pub fn banRelation(entry: shared.types.IgnoreEntry, ban: shared.types.IgnoreEntry) ?IgnoreRelation {
            if (entry.family != ban.family) return null;
            if (ban.prefix >= entry.prefix) return if (entry.contains(ban.network())) .inside_entry else null;
            return if (ban.contains(entry.network())) .contains_entry else null;
        }
        const RelatedBan = struct { order: shared.types.IgnoreEntry, index: u32, relation: IgnoreRelation };
        pub fn relatedLess(_: void, a: RelatedBan, b: RelatedBan) bool {
            return a.order.order(b.order) == .lt;
        }
        pub fn collectRelatedBans(self: *Coordinator, request: *AdminRequest, jail: *Jail) !void {
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
        pub fn leaseDeadline(lease: anytype) ?i64 {
            return switch (lease) {
                .finite => |value| value,
                else => null,
            };
        }
        pub fn decisionScope(subject: detection.Subject) inspection.CanonicalScope {
            const address: shared.IpAddress = switch (subject) {
                .v4 => |v| .{ .ipv4 = std.mem.readInt(u32, &v, .big) },
                .v6 => |v| .{ .ipv6 = std.mem.readInt(u128, &v, .big) },
            };
            return .{ .subject = inspection.canonical_scope.Subject.host(address) };
        }
        pub fn liftIgnoredBans(self: *Coordinator, request: *AdminRequest, jail: ?*Jail) void {
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
        pub fn settleIgnoreLifts(self: *Coordinator, request: *AdminRequest, ignore_state: *IgnoreWork) void {
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
        pub fn finishIgnoreAdd(self: *Coordinator, request: *AdminRequest) AdminOutcomeView {
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
        pub fn executeIgnoreAdd(self: *Coordinator, request: *AdminRequest) !AdminOutcomeView {
            const ignore_state = request.ignore.?;
            const entry = request.ignore_entry.?;
            const name = request.jailName();
            const jail_cfg = findConfigJail(self.live_cfg, name) orelse return self.ignoreRefusal(request, .rejected, "jail '{s}' is not configured", .{name});
            if (jail_cfg.rule_files.len != 0) return self.ignoreRefusal(request, .rejected, "jail '{s}' uses rule_files; manage its exclusions through ignore_file", .{name});
            const jail = self.findJail(name);
            if (jail) |value| if (ignoreCell(value) == null) return self.ignoreRefusal(request, .rejected, "jail '{s}' reads internal events and has no ignore list", .{name});
            var runtime: [ignore_set.max_entries_per_part + 1]RuntimeIgnoreEntry = undefined;
            const runtime_count = try self.store.ignoreEntries(name, runtime[0..ignore_set.max_entries_per_part]);
            const literals = jail_cfg.ignoreip orelse self.live_cfg.defaults.ignoreip;
            const resolved = config.resolveJailFromConfig(jail_cfg, self.live_cfg.defaults);
            const now = self.clock.wallUs();
            const deadlines = try configuredIgnoreDeadlines(self.allocator, &self.store, name, literals, resolved.ignoretime_s, .read, now);
            defer self.allocator.free(deadlines);
            const own: []const shared.IpAddress = if (resolved.ignoreself) self.selfAddressList() else &.{};
            const before = try ignore_set.EffectiveIgnore.build(self.allocator, literals, deadlines, runtime[0..runtime_count], own, now);
            defer before.deinit(self.allocator);
            var existing: ?ignore_set.Source = null;
            for (before.entries) |item| if (item.entry.order(entry) == .eq and item.source != .self and !item.expired) {
                existing = item.source;
            };
            var entry_text: [64]u8 = undefined;
            const canonical = entry.canonical(&entry_text);
            if (request.duration_s != null and existing != null and existing.? == .config)
                return self.ignoreRefusal(request, .rejected, "--for applies to runtime entries only; {s} is configured in ignoreip", .{canonical});
            const expires_us: ?i64 = if (request.duration_s orelse resolved.ignoretime_s) |seconds| now + @as(i64, @intCast(seconds)) * std.time.us_per_s else null;
            ignore_state.expires_us = expires_us;
            const recorded = existing != null and existing.? != .config;
            if (!recorded and before.entries.len + @intFromBool(existing == null) > ignore_set.distinct_bound)
                return self.ignoreRefusal(request, .rejected, "jail {s} already has {d} ignore entries (configuration and runtime combined), the limit. Remove one with fail2zig ignore remove first.", .{ name, before.entries.len });
            runtime[runtime_count] = .{ .entry = entry, .expires_us = expires_us };
            if (recorded) for (runtime[0..runtime_count]) |*item| if (item.entry.order(entry) == .eq) {
                if (item.expires_us) |held| if (expires_us == null or expires_us.? > held) {
                    item.expires_us = expires_us;
                };
            };
            const after = ignore_set.EffectiveIgnore.build(self.allocator, literals, deadlines, runtime[0 .. runtime_count + @intFromBool(!recorded)], own, now) catch |failure| switch (failure) {
                error.IgnoreCapacityExceeded => return self.ignoreRefusal(request, .rejected, "jail {s} already has {d} ignore entries (configuration and runtime combined), the limit. Remove one with fail2zig ignore remove first.", .{ name, before.entries.len }),
                else => return failure,
            };
            var installed = false;
            defer if (!installed) after.deinit(self.allocator);
            if (jail) |value| try self.collectRelatedBans(request, value);
            if (request.unban and ignore_state.inside_total > max_lifted_bans)
                return self.ignoreRefusal(request, .rejected, "{s} covers {d} bans in {s}; --unban lifts at most {d} per command. Nothing changed. Add the entry without --unban, then lift bans with fail2zig unban.", .{ canonical, ignore_state.inside_total, name, max_lifted_bans });
            ignore_state.entry_state = .present;
            const result = self.store.addIgnoreEntry(name, entry, now, expires_us) catch |failure| {
                if (failure == error.IgnoreCapacity)
                    return self.ignoreRefusal(request, .rejected, "jail {s} already has {d} ignore entries (configuration and runtime combined), the limit. Remove one with fail2zig ignore remove first.", .{ name, before.entries.len });
                std.log.err("native admin: ignore entry commit failed: {s}", .{@errorName(failure)});
                return self.ignoreUncertain(request);
            };
            if (result != .present) {
                ignore_state.entry_state = .added;
                ignore_state.mutated = true;
                request.mutation_committed = true;
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
        pub fn executeIgnoreRemove(self: *Coordinator, request: *AdminRequest) !AdminOutcomeView {
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
            var runtime: [ignore_set.max_entries_per_part]RuntimeIgnoreEntry = undefined;
            const runtime_count = try self.store.ignoreEntries(name, &runtime);
            const literals: []const []const u8 = if (jail_cfg) |value| (if (value.rule_files.len != 0) &.{} else value.ignoreip orelse self.live_cfg.defaults.ignoreip) else &.{};
            const resolved: ?config.ResolvedJailConfig = if (jail_cfg) |value| config.resolveJailFromConfig(value, self.live_cfg.defaults) else null;
            const now = self.clock.wallUs();
            const deadlines = try configuredIgnoreDeadlines(self.allocator, &self.store, name, literals, if (resolved) |value| value.ignoretime_s else null, .read, now);
            defer self.allocator.free(deadlines);
            const own: []const shared.IpAddress = if (resolved != null and resolved.?.ignoreself) self.selfAddressList() else &.{};
            const before = try ignore_set.EffectiveIgnore.build(self.allocator, literals, deadlines, runtime[0..runtime_count], own, now);
            defer before.deinit(self.allocator);
            var entry_text: [64]u8 = undefined;
            const canonical = entry.canonical(&entry_text);
            var existing: ?ignore_set.Source = null;
            for (before.entries) |item| if (item.entry.order(entry) == .eq and item.source != .self and !item.expired) {
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
            var kept: [ignore_set.max_entries_per_part]RuntimeIgnoreEntry = undefined;
            var kept_count: usize = 0;
            for (runtime[0..runtime_count]) |item| if (item.entry.order(entry) != .eq) {
                kept[kept_count] = item;
                kept_count += 1;
            };
            const after = try ignore_set.EffectiveIgnore.build(self.allocator, literals, deadlines, kept[0..kept_count], own, now);
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
    };
}
