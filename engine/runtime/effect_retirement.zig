// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Withdraws and settles a retiring jail's effects page by page and proves the kernel set clean before retirement finishes.
// Holds: A retirement walk restarts from its first key whenever the inventory loses continuity.

const std = @import("std");
const durable = @import("../store/store.zig");
const effect = @import("../effect/effect.zig");
const firewall = @import("../firewall/inspection.zig");
const Step = @import("effect_runtime.zig").Step;
const transientReadback = @import("effect_runtime.zig").transientReadback;
const audit_lead_ns = @import("effect_runtime.zig").audit_lead_ns;
const JailRetirementWithdrawalCursor = @import("effect_runtime.zig").JailRetirementWithdrawalCursor;
const JailRetirementWithdrawalResult = @import("effect_runtime.zig").JailRetirementWithdrawalResult;

pub fn Methods(comptime Manager: type) type {
    return struct {
        // Holds: Settles an already issued operation from readback; it never dispatches or withdraws an effect.
        pub fn reconcileJailRetirement(self: *Manager, request: durable.Store.JailRetirementReconciliation) Step {
            return self.reconcileJailRetirementInner(request) catch |failure| {
                self.dropInventory();
                self.status.ready = false;
                self.status.uncertain = true;
                self.status.cause = failure;
                return .{ .fatal = failure };
            };
        }
        pub fn retirementObservationTurn(self: *Manager, preserve_runtime: bool) !?Step {
            self.status.ready = false;
            if (self.stopping) return .stop;
            const runtime = preserve_runtime and (self.view_authority == .runtime or self.staged_authority == .runtime);
            if (!runtime and (self.view_authority == .runtime or self.staged_authority == .runtime)) self.discardViewAuthority();
            if (self.readback_wait != 0) {
                self.readback_wait -= 1;
                return .{ .wait = self.waitDue() };
            }
            if (!self.admitted) {
                self.admit() catch |failure| {
                    if (transientReadback(failure)) return self.deferReadback();
                    return failure;
                };
                return .progress;
            }
            if (self.cached_epoch == null or self.cached_epoch.? != self.store.effect_publication_epoch) {
                if (runtime) return .progress;
                if (self.view_authority == .retirement_observation and self.staged_revision == null) if (try self.catchUp(&.{})) |_| return .progress;
                _ = try self.refreshTurn(&.{}, .retirement_observation);
                return .progress;
            }
            self.drainEvents();
            const sampled = try self.clock();
            if (self.inventory != null and self.verify_interval_ns != 0) if (self.last_readback_ns) |last| if (self.monotonic(self.monotonic_context)) |now| {
                const interval = if (self.events_subscribed) self.verify_interval_ns -| audit_lead_ns else self.verify_interval_ns;
                if (now -| last >= interval) return try self.readback(sampled);
            };
            if (!self.inventoryCurrent()) return try self.readback(sampled);
            return null;
        }
        pub fn reconcileJailRetirementInner(self: *Manager, request: durable.Store.JailRetirementReconciliation) !Step {
            self.status.ready = false;
            if (!try self.store.validateJailRetirementReconciliation(request)) return .idle;
            if (!std.mem.eql(u8, &request.token.installation, &self.installation.id)) return error.InstallationMismatch;
            if (try self.retirementObservationTurn(false)) |outcome| return outcome;
            const index = self.findLive(request.token.scope_key) orelse return error.StaleEffect;
            const entry = self.live[index];
            if (!std.meta.eql(entry.token(), request.token) or entry.status != .dispatched) {
                self.cached_epoch = null;
                return .progress;
            }
            try self.refreshMatch(index);
            const held = self.inventory orelse return self.deferReadback();
            const pre = self.store.effect_publication_epoch;
            {
                errdefer self.writeFailed(pre);
                _ = self.store.settleJailRetirementReconciliation(request, held.start_us, .{ .installation = entry.installation.id, .scope_key = entry.scope_key, .fingerprint = held.snapshot.fingerprint, .observed_us = held.end_us, .qualification = .complete_owned, .state = if (self.matched[index]) entry.desired else null }, try self.clock()) catch |failure| {
                    if (failure == error.EffectExpired) {
                        self.dropInventory();
                        return .progress;
                    }
                    return failure;
                };
            }
            if (self.store.effect_publication_epoch != pre) _ = try self.attributeCommit(&.{}, index, pre);
            self.status.ready = false;
            return .idle;
        }
        const RetirementSelector = union(enum) {
            generation: struct { jail: []const u8, generation: effect.Hash },
            accepted: durable.Store.JailRetirementIntent,
            fn matches(self: RetirementSelector, owner: effect.Owner) bool {
                return switch (self) {
                    .generation => |selected| std.mem.eql(u8, owner.jail.slice(), selected.jail) and std.mem.eql(u8, &owner.generation, &selected.generation),
                    .accepted => |intent| std.mem.eql(u8, owner.jail.slice(), intent.jail.slice()),
                };
            }
        };
        const RetirementScope = struct { index: usize, entry: effect.Entry };
        pub fn retirementScope(self: *Manager, intent: durable.Store.JailRetirementIntent, key: effect.Hash) !?RetirementScope {
            try self.store.beginRead();
            errdefer self.store.rollback();
            var owners: [effect.max_page]effect.Owner = undefined;
            const count = try self.store.readOwners(key, &owners);
            const selector: RetirementSelector = .{ .accepted = intent };
            for (owners[0..count]) |owner| {
                if (!selector.matches(owner)) continue;
                if (owner.lease != .absent) return error.StaleEffect;
                const entry = try self.store.readEffect(key, self.installation) orelse return error.InvalidEffect;
                const index = self.findLive(key) orelse return error.StaleEffect;
                if (!std.meta.eql(entry.token(), self.live[index].token())) return error.StaleEffect;
                try self.store.commitTransaction();
                return .{ .index = index, .entry = entry };
            }
            try self.store.commitTransaction();
            return null;
        }
        pub fn processRetirementKeys(self: *Manager, intent: durable.Store.JailRetirementIntent, keys: []const effect.Hash) !?Step {
            var withdrawals: [firewall.max_withdraw_messages]firewall.DispatchToken = undefined;
            var withdraw_count: usize = 0;
            var budget: usize = 0;
            var settlements: [durable.Store.max_expiry_batch]effect.Token = undefined;
            var settle_count: usize = 0;
            for (keys) |key| {
                const scope = try self.retirementScope(intent, key) orelse continue;
                const entry = scope.entry;
                if (entry.desired != .absent) continue;
                try self.refreshMatch(scope.index);
                if (self.inventory == null) return self.deferReadback();
                const absent = self.matched[scope.index];
                if (entry.status == .dispatched or (absent and (entry.status != .absent or self.markers[scope.index] != null))) {
                    if (try self.settlementReadback(entry, try self.clock())) |outcome| return outcome;
                }
                if (entry.status == .dispatched) {
                    if (!absent) {
                        const held = self.inventory.?;
                        const pre = self.store.effect_publication_epoch;
                        errdefer self.writeFailed(pre);
                        _ = try self.store.settleOutcome(entry.token(), held.start_us, .{ .installation = entry.installation.id, .scope_key = entry.scope_key, .fingerprint = held.snapshot.fingerprint, .observed_us = held.end_us, .qualification = .complete_owned, .state = null }, try self.clock());
                        if (std.meta.eql(entry.token(), self.live[scope.index].token())) self.markers[scope.index] = null;
                        return .progress;
                    }
                }
                if (!absent) {
                    const cost = try firewall.withdrawCost(entry.scope.canonical);
                    if (withdraw_count != 0 and budget + cost > firewall.max_withdraw_messages) break;
                    withdrawals[withdraw_count] = self.token(entry, .absent);
                    withdraw_count += 1;
                    budget += cost;
                    if (withdraw_count == withdrawals.len) break;
                } else if (entry.status != .absent or self.markers[scope.index] != null) {
                    settlements[settle_count] = entry.token();
                    settle_count += 1;
                    if (settle_count == settlements.len) break;
                }
            }
            if (settle_count != 0) {
                const held = self.inventory.?;
                const pre = self.store.effect_publication_epoch;
                errdefer self.writeFailed(pre);
                _ = try self.store.settleExpired(settlements[0..settle_count], held.snapshot.fingerprint, held.end_us, try self.clock());
                for (settlements[0..settle_count]) |token_value| if (self.findLive(token_value.scope_key)) |index| {
                    if (std.meta.eql(self.live[index].token(), token_value)) self.markers[index] = null;
                };
                return .progress;
            }
            if (withdraw_count != 0) return try self.withdrawTokens(withdrawals[0..withdraw_count], try self.clock());
            return null;
        }
        pub fn withdrawJailRetirement(self: *Manager, intent: durable.Store.JailRetirementIntent, cursor: *JailRetirementWithdrawalCursor) JailRetirementWithdrawalResult {
            const before = cursor.*;
            return self.withdrawJailRetirementInner(intent, cursor) catch |failure| {
                cursor.* = before;
                self.dropInventory();
                self.status.ready = false;
                self.status.uncertain = true;
                self.status.cause = failure;
                return .{ .step = .{ .fatal = failure } };
            };
        }
        pub fn withdrawJailRetirementInner(self: *Manager, intent: durable.Store.JailRetirementIntent, cursor: *JailRetirementWithdrawalCursor) !JailRetirementWithdrawalResult {
            const current = try self.store.jailRetirement(intent.jail.slice()) orelse return error.StaleEffect;
            if (current.keep_ignore_deadlines != intent.keep_ignore_deadlines) return error.StaleEffect;
            if (try self.retirementObservationTurn(true)) |outcome| return .{ .step = outcome };
            // Why: inventory_discontinuity saturates, so at its maximum a later loss could no longer reset the walk.
            if (self.inventory_discontinuity == std.math.maxInt(u64)) return error.EffectCapacity;
            const epoch = self.store.effect_publication_epoch;
            if (epoch == std.math.maxInt(u64)) return error.EffectCapacity;
            if (cursor.inventory_epoch == null or cursor.inventory_epoch.? != self.inventory_discontinuity) {
                cursor.* = .{ .inventory_epoch = self.inventory_discontinuity };
            }
            if (cursor.revisit) |key| {
                cursor.after = try self.store.jailRetirementOwnerBefore(intent, key);
                cursor.revisit = null;
            }
            var keys: [64]effect.Hash = undefined;
            const count = try self.store.jailRetirementOwnerKeys(intent, cursor.after, &keys);
            if (try self.processRetirementKeys(intent, keys[0..count])) |outcome| return .{ .step = outcome };
            if (count != 0) cursor.after = keys[count - 1];
            if (count == keys.len) return .{ .step = .progress };
            if (cursor.revisit != null or !self.inventoryCurrent() or cursor.inventory_epoch.? != self.inventory_discontinuity or self.store.effect_publication_epoch != epoch) return .{ .step = .progress };
            try self.store.beginRead();
            errdefer self.store.rollback();
            const revision = try self.store.integer("SELECT revision FROM effect_clock WHERE singleton=1;");
            if (revision < 0) return error.InvalidEffect;
            try self.store.commitTransaction();
            const held = self.inventory.?;
            return .{ .verified = .{ .intent = intent, .verification = .{ .observed = .{ .installation = self.installation.id, .effect_revision = @intCast(revision), .publication_epoch = epoch, .fingerprint = held.snapshot.fingerprint, .observed_us = held.end_us } } } };
        }
    };
}
