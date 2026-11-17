// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Activates and rolls back migrated owners and settles each run against kernel readback.
// Holds: Activation needs a recorded success for every earlier step and reports applied only when every activated owner is in the kernel.

const std = @import("std");
const effect = @import("../effect/effect.zig");
const effect_runtime = @import("../runtime/effect_runtime.zig");
const durable = @import("../store/store.zig");

pub fn Methods(comptime Coordinator: type) type {
    return struct {
        const AdminOutcomeView = Coordinator.AdminOutcomeView;
        const AdminRequest = Coordinator.AdminRequest;
        const monotonic = Coordinator.monotonic;
        const wallClockEffect = Coordinator.wallClockEffect;

        pub fn activateMigration(self: *Coordinator, request: *AdminRequest, base: AdminOutcomeView, now: i64) !AdminOutcomeView {
            const run_id = request.run_id orelse return error.AdminRunIdRequired;
            if (self.effects == null) return self.adminDetail(
                request,
                (AdminOutcomeView{ .outcome = .rejected, .kind = request.kind }).withReason("destination is log-only; migrated owners need an enforcing backend", .{}),
                null,
            );
            const migration_run = (try self.store.migrationRun(self.allocator, run_id)) orelse return self.adminDetail(
                request,
                (AdminOutcomeView{ .outcome = .absent, .kind = request.kind }).withReason("unknown migration run", .{}),
                null,
            );
            self.allocator.free(migration_run.recovery_point);
            if (migration_run.state == .complete) return self.adminDetail(request, base.withReason("migration run already complete", .{}), null);
            if (migration_run.state != .staged and migration_run.state != .activating) return self.adminDetail(
                request,
                (AdminOutcomeView{ .outcome = .rejected, .kind = request.kind }).withReason("migration run is {s}, not staged", .{@tagName(migration_run.state)}),
                null,
            );
            try self.closeInterruptedMigrationStep(run_id, now);
            inline for (.{ durable.Store.MigrationStep.validate_plan, .check_drift, .capture_recovery_point, .quiesce_source, .stage_destination }) |required| {
                if (!try self.store.migrationStepSucceeded(run_id, required)) return self.adminDetail(
                    request,
                    (AdminOutcomeView{ .outcome = .rejected, .kind = request.kind }).withReason("validation_failed: step {s} has no recorded success", .{@tagName(required)}),
                    null,
                );
            }
            var generations: [64]durable.Store.JailGeneration = undefined;
            var count: usize = 0;
            for (self.jails) |*jail| {
                if (jail.retiring or !jail.admin_enabled) continue;
                if (count == generations.len) return error.AdminJailCapacity;
                generations[count] = .{ .jail = jail.name, .generation = try self.plannedGeneration(jail, .planned) };
                count += 1;
            }
            const seq = try self.store.beginMigrationStep(run_id, .activate_owners, "", now);
            const clock = effect.Clock{ .prepared_us = now, .context = self, .read = wallClockEffect };
            const activated = self.store.activateStagedOwners(run_id, generations[0..count], clock) catch |err| {
                try self.store.finishMigrationStep(run_id, seq, .operational_failure, @errorName(err), null, self.clock.wallUs());
                if (err == error.MigrationJailUnknown) return self.adminDetail(
                    request,
                    base.withOutcome(.rejected).withReason("destination jail is disabled or unconfigured; enable/configure it before activation", .{}),
                    null,
                );
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
            if (self.effects == null) return self.adminDetail(
                request,
                (AdminOutcomeView{ .outcome = .rejected, .kind = request.kind }).withReason("destination is log-only; nothing is realized to release", .{}),
                null,
            );
            const migration_run = (try self.store.migrationRun(self.allocator, run_id)) orelse return self.adminDetail(
                request,
                (AdminOutcomeView{ .outcome = .absent, .kind = request.kind }).withReason("unknown migration run", .{}),
                null,
            );
            self.allocator.free(migration_run.recovery_point);
            if (migration_run.state != .complete and migration_run.state != .activating and migration_run.state != .rolled_back) return self.adminDetail(
                request,
                (AdminOutcomeView{ .outcome = .rejected, .kind = request.kind }).withReason("migration run is {s}; only an activated run can be rolled back", .{@tagName(migration_run.state)}),
                null,
            );
            const open = try self.store.pendingMigrationStep(run_id);
            if (open == null or open.?.step != .rollback) return self.adminDetail(
                request,
                (AdminOutcomeView{ .outcome = .rejected, .kind = request.kind }).withReason("no rollback in progress for this run; restore the source with `migrate rollback` first", .{}),
                null,
            );
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
            for (keys[0..report.found]) |key| applied += @intFromBool(manager.appliedKey(key, now));
            if (manager.status.uncertain) {
                view.destination = "uncertain";
                return (view.withOutcome(.uncertain)).withReason("effect outcome uncertain: {s}", .{if (manager.status.cause) |cause| @errorName(cause) else "unknown"});
            }
            if (request.kind == .migration_rollback) {
                const remaining = self.store.migrationOwnersRemaining(run_id) catch |err| return (view.withOutcome(.uncertain)).withReason("migration owners unreadable: {s}", .{@errorName(err)});
                const staged_count = self.store.migrationStagedKeys(run_id, keys) catch |err| return (view.withOutcome(.uncertain)).withReason("staged scopes unreadable: {s}", .{@errorName(err)});
                var realized: usize = 0;
                for (keys[0..staged_count]) |key| realized += @intFromBool(manager.appliedKey(key, now));
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
    };
}
