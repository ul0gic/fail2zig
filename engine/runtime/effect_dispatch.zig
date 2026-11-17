// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Sends effects to the kernel singly or in batches and withdraws pending removals, marking each before it is sent.
// Holds: The mutation time is recorded before each send and restored when the send provably did not start.

const std = @import("std");
const build_options = @import("build_options");
const diag_mod = @import("../diag/diag.zig");
const effect = @import("../effect/effect.zig");
const firewall = @import("../firewall/inspection.zig");
const Binding = @import("effect_runtime.zig").Binding;
const Step = @import("effect_runtime.zig").Step;
const expiryClass = @import("effect_runtime.zig").expiryClass;
const transientReadback = @import("effect_runtime.zig").transientReadback;
const presentIn = @import("effect_runtime.zig").Manager.presentIn;

pub fn Methods(comptime Manager: type) type {
    return struct {
        pub fn installPending(self: *Manager, bindings: []const Binding, sampled: effect.Clock, indices: []usize, stale: []const usize) !?Step {
            var tokens: [firewall.max_install_messages]firewall.DispatchToken = undefined;
            var n = indices.len;
            if (n < 2) return null;
            if (stale.len != 0) {
                const held = &self.inventory.?;
                self.counters.redispatched += stale.len;
                const dispatched = if (self.events_subscribed) sampled.prepared_us else held.start_us;
                const observed = if (self.events_subscribed) sampled.prepared_us else held.end_us;
                try self.settleBatch(bindings, stale, dispatched, observed, .mismatch, held.snapshot.fingerprint);
                if (self.cached_epoch == null) return .progress;
            }
            const dispatch_clock = try self.clock();
            var pending: usize = 0;
            for (indices[0..n]) |index| {
                const entry = self.live[index];
                if (entry.status != .pending) continue;
                if (entry.desired == .finite and !entry.desired.live(dispatch_clock.prepared_us)) continue;
                tokens[pending] = self.token(entry, entry.desired);
                indices[pending] = index;
                pending += 1;
            }
            if (pending == 0) return .progress;
            n = pending;
            const diag_span = if (comptime build_options.diag) diag_mod.enter(.dispatch) else {};
            defer if (comptime build_options.diag) diag_mod.leave(diag_span);
            const sent_ns = self.monotonic(self.monotonic_context);
            const prior_mutation_ns = self.last_mutation_ns;
            const prior_mutation_wall_us = self.last_mutation_wall_us;
            for (indices[0..n]) |index| self.markers[index] = .{ .sent_ns = sent_ns, .sent_wall_us = dispatch_clock.prepared_us };
            // Why: The mutation time is recorded before sending, so no inventory read that began earlier counts as current afterwards.
            self.last_mutation_ns = sent_ns;
            self.last_mutation_wall_us = dispatch_clock.prepared_us;
            const outcome = self.inspector.installBatch(tokens[0..n], .{ .wall_us = dispatch_clock.prepared_us }, &self.inventory.?.snapshot) catch |failure| {
                self.recordFirewallDirect(.effect_dispatch, failure);
                if (!transientReadback(failure)) {
                    std.log.warn("native: batch install of {d} effects refused: {s}", .{ n, @errorName(failure) });
                    return error.EffectBackendUncertain;
                }
                for (indices[0..n]) |index| self.markers[index] = null;
                self.last_mutation_ns = prior_mutation_ns;
                self.last_mutation_wall_us = prior_mutation_wall_us;
                return self.deferReadback();
            };
            const consumed = outcome.consumed;
            for (indices[consumed..n]) |index| self.markers[index] = null;
            switch (outcome.result) {
                .uncertain => |failure| {
                    self.recordFirewallFailure(failure);
                    if (failure.mutation == .not_started) {
                        for (indices[0..consumed]) |index| self.markers[index] = null;
                        self.last_mutation_ns = prior_mutation_ns;
                        self.last_mutation_wall_us = prior_mutation_wall_us;
                    }
                    if (!transientReadback(failure.cause)) {
                        std.log.warn("native: batch install of {d} effects uncertain at {s}: {s}", .{ consumed, @tagName(failure.stage), @errorName(failure.cause) });
                        return error.EffectBackendUncertain;
                    }
                    return self.deferReadback();
                },
                .acknowledged => |acked| {
                    for (indices[0..consumed]) |index| self.markers[index] = null;
                    self.rememberOwnPort(acked.port_id);
                    self.applyAcknowledged(indices[0..consumed]) catch |failure| {
                        std.log.warn("native: acknowledged batch of {d} effects could not enter the view: {s}", .{ consumed, @errorName(failure) });
                        return failure;
                    };
                    self.settleBatch(bindings, indices[0..consumed], dispatch_clock.prepared_us, acked.acked_wall_us, .desired, self.tokenFingerprint(indices[0..consumed])) catch |failure| {
                        std.log.warn("native: acknowledged batch of {d} effects could not be settled: {s}", .{ consumed, @errorName(failure) });
                        return failure;
                    };
                    self.refreshSettled(bindings, indices[0..consumed]) catch |failure| {
                        std.log.warn("native: settled batch of {d} effects could not be re-read: {s}", .{ consumed, @errorName(failure) });
                        return failure;
                    };
                    for (indices[0..consumed]) |index| if (self.live[index].status == .applied and self.confirmed[index]) {
                        self.status.confirmed += 1;
                    };
                    self.counters.install_batches += 1;
                    self.counters.acknowledged_batches += 1;
                    if (comptime build_options.diag) diag_mod.count(.acknowledged_batches, 1);
                    return .progress;
                },
                .verified => |verified| {
                    var snapshot = verified.snapshot;
                    const after_ns = self.monotonic(self.monotonic_context);
                    for (indices[0..consumed]) |index| self.markers[index] = null;
                    {
                        errdefer snapshot.deinit();
                        try self.validateAndCaptureObservation(&snapshot, .effect, verified.observed_wall_us, .effect_verify);
                    }
                    self.keepInventory(snapshot, verified.observed_start_wall_us, verified.observed_wall_us, after_ns);
                    try self.settleBatch(bindings, indices[0..consumed], dispatch_clock.prepared_us, verified.observed_wall_us, .desired, verified.snapshot.fingerprint);
                    self.counters.install_batches += 1;
                    if (!try self.evaluateInventory()) return self.deferReadback();
                    return .progress;
                },
            }
        }
        pub fn applyAcknowledged(self: *Manager, indices: []const usize) !void {
            const held = &self.inventory.?;
            var entries: [firewall.max_install_messages]firewall.HostBatchEntry = undefined;
            var added: [firewall.max_install_messages]bool = undefined;
            if (indices.len > entries.len) return error.InvalidEffect;
            for (indices, 0..) |index, position| {
                const entry = self.live[index];
                const host = firewall.legacyAddress(entry.scope.canonical) catch return error.InvalidEffect;
                const remaining: ?u64 = switch (entry.desired) {
                    .finite => |until| if (until > held.end_us) self.inspector.toKernelUs(@intCast(until - held.end_us)) / 1000 else 0,
                    .permanent => null,
                    .absent => return error.InvalidEffect,
                };
                entries[position] = .{ .entry = .{ .address = host, .remaining_ms = remaining }, .original = position };
            }
            try held.snapshot.upsertHosts(entries[0..indices.len], added[0..indices.len]);
            for (indices, 0..) |index, position| {
                const entry = self.live[index];
                if (added[position] and entry.desired.live(held.end_us)) self.installed_live += 1;
                if (!self.confirmed[index] or !self.matched[index]) self.view_revision +%= 1;
                self.matched[index] = true;
                self.confirmed[index] = true;
            }
            self.inspector.retained_bytes = held.snapshot.entries.len * @sizeOf(firewall.Entry);
        }
        pub fn tokenFingerprint(self: *Manager, indices: []const usize) effect.Hash {
            var digest = std.crypto.hash.sha2.Sha256.init(.{});
            digest.update(&self.installation.id);
            for (indices) |index| digest.update(&self.live[index].scope_key);
            var out: effect.Hash = undefined;
            digest.final(&out);
            return out;
        }
        pub fn dispatch(self: *Manager, bindings: []const Binding, index: usize, sampled: effect.Clock) !Step {
            const diag_span = if (comptime build_options.diag) diag_mod.enter(.dispatch) else {};
            defer if (comptime build_options.diag) diag_mod.leave(diag_span);
            self.status.ready = false;
            var entry = self.live[index];
            if (entry.status != .pending) {
                if (try self.settlementReadback(entry, sampled)) |outcome| return outcome;
                const held = &(self.inventory orelse return self.readback(sampled));
                try self.settle(
                    bindings,
                    index,
                    entry,
                    held.start_us,
                    .{
                        .installation = entry.installation.id,
                        .scope_key = entry.scope_key,
                        .fingerprint = held.snapshot.fingerprint,
                        .observed_us = held.end_us,
                        .qualification = .complete_owned,
                        .state = null,
                    },
                );
                if (self.cached_epoch == null) return .progress;
                entry = self.live[index];
                if (entry.status != .pending) return .progress;
            }
            const dispatch_clock = try self.clock();
            if (entry.desired == .finite and !entry.desired.live(dispatch_clock.prepared_us)) return .progress;
            if (entry.desired == .absent) if (try self.withdrawPending(index, dispatch_clock)) |outcome| return outcome;
            const sent_ns = self.monotonic(self.monotonic_context);
            const prior_mutation_ns = self.last_mutation_ns;
            const prior_mutation_wall_us = self.last_mutation_wall_us;
            self.markers[index] = .{ .sent_ns = sent_ns, .sent_wall_us = dispatch_clock.prepared_us };
            self.last_mutation_ns = sent_ns;
            self.last_mutation_wall_us = dispatch_clock.prepared_us;
            const target = self.token(entry, entry.desired);
            const clock_sample = firewall.ClockSample{ .wall_us = dispatch_clock.prepared_us };
            const result = (if (self.inspector.installation.transport == .nftables and self.inventory != null)
                self.inspector.applyFromBaseline(target, clock_sample, &self.inventory.?.snapshot)
            else
                self.inspector.applyExact(target, clock_sample)) catch |failure| {
                if (failure == error.ExpiredIntent) {
                    self.markers[index] = null;
                    self.last_mutation_ns = prior_mutation_ns;
                    self.last_mutation_wall_us = prior_mutation_wall_us;
                    return .progress;
                }
                self.recordFirewallDirect(.effect_dispatch, failure);
                if (!transientReadback(failure)) return error.EffectBackendUncertain;
                self.markers[index] = null;
                self.last_mutation_ns = prior_mutation_ns;
                self.last_mutation_wall_us = prior_mutation_wall_us;
                return self.deferReadback();
            };
            switch (result) {
                .uncertain => |failure| {
                    if (failure.cause == error.ExpiredIntent and failure.mutation == .not_started) {
                        self.markers[index] = null;
                        self.last_mutation_ns = prior_mutation_ns;
                        self.last_mutation_wall_us = prior_mutation_wall_us;
                        return .progress;
                    }
                    self.recordFirewallFailure(failure);
                    if (failure.mutation == .not_started) {
                        self.markers[index] = null;
                        self.last_mutation_ns = prior_mutation_ns;
                        self.last_mutation_wall_us = prior_mutation_wall_us;
                    }
                    if (!transientReadback(failure.cause)) return error.EffectBackendUncertain;
                    return self.deferReadback();
                },
                .verified => |verified| {
                    var snapshot = verified.snapshot;
                    const after_ns = self.monotonic(self.monotonic_context);
                    self.markers[index] = null;
                    if (!verified.changed) {
                        self.last_mutation_ns = prior_mutation_ns;
                        self.last_mutation_wall_us = prior_mutation_wall_us;
                        // Why: An unchanged result from a baseline read before the intent cannot settle it, so the baseline is re-read.
                        if (self.inspector.installation.transport == .nftables) {
                            if (self.inventory) |held| if (held.start_us < entry.intent_us) {
                                snapshot.deinit();
                                self.dropInventory();
                                return .progress;
                            };
                        }
                        // Why: applyExact read a fresh baseline that may show an element expired since the held inventory, so it is kept.
                        if (self.inventory == null or self.inspector.installation.transport != .nftables) {
                            {
                                errdefer snapshot.deinit();
                                try self.validateAndCaptureObservation(&snapshot, .effect, verified.observed_wall_us, .effect_verify);
                            }
                            self.keepInventory(snapshot, verified.observed_start_wall_us, verified.observed_wall_us, sent_ns);
                            if (!try self.evaluateInventory()) return self.deferReadback();
                        } else snapshot.deinit();
                        const held = &self.inventory.?;
                        try self.settle(
                            bindings,
                            index,
                            entry,
                            held.start_us,
                            .{
                                .installation = entry.installation.id,
                                .scope_key = entry.scope_key,
                                .fingerprint = held.snapshot.fingerprint,
                                .observed_us = held.end_us,
                                .qualification = .complete_owned,
                                .state = entry.desired,
                            },
                        );
                        return .progress;
                    }
                    {
                        errdefer snapshot.deinit();
                        try self.validateAndCaptureObservation(&snapshot, .effect, verified.observed_wall_us, .effect_verify);
                    }
                    self.keepInventory(snapshot, verified.observed_start_wall_us, verified.observed_wall_us, after_ns);
                    try self.settle(
                        bindings,
                        index,
                        entry,
                        dispatch_clock.prepared_us,
                        .{
                            .installation = entry.installation.id,
                            .scope_key = entry.scope_key,
                            .fingerprint = self.inventory.?.snapshot.fingerprint,
                            .observed_us = verified.observed_wall_us,
                            .qualification = .complete_owned,
                            .state = entry.desired,
                        },
                    );
                    if (!try self.evaluateInventory()) return self.deferReadback();
                    return .progress;
                },
            }
        }
        pub fn withdrawPending(self: *Manager, selected: usize, sampled: effect.Clock) !?Step {
            if (self.view_authority != .runtime or self.staged_revision != null or self.cached_epoch == null or self.cached_epoch.? != self.store.effect_publication_epoch) return .progress;
            if (!self.inventoryCurrent()) return try self.readback(sampled);
            const held = &self.inventory.?;
            const entry = self.live[selected];
            if (entry.status != .pending or entry.desired != .absent or self.markers[selected] != null or self.matched[selected] or !try presentIn(held, entry)) return null;
            const transport = self.inspector.installation.transport;
            if (expiryClass(transport, entry.scope) == .kernel_expiring and held.start_us < entry.intent_us) return null;
            var tokens: [firewall.max_withdraw_messages]firewall.DispatchToken = undefined;
            var budget = try firewall.withdrawCost(entry.scope.canonical);
            if (budget > firewall.max_withdraw_messages) return error.LimitExceeded;
            tokens[0] = self.token(entry, .absent);
            var count: usize = 1;
            for (self.live[0..self.count], 0..) |other, index| {
                if (count == tokens.len or budget == firewall.max_withdraw_messages) break;
                if (index == selected or other.status != .pending or other.desired != .absent or self.markers[index] != null or self.matched[index]) continue;
                if (expiryClass(transport, other.scope) == .kernel_expiring and held.start_us < other.intent_us) continue;
                if (!try presentIn(held, other)) continue;
                const cost = try firewall.withdrawCost(other.scope.canonical);
                if (budget + cost > firewall.max_withdraw_messages) break;
                tokens[count] = self.token(other, .absent);
                count += 1;
                budget += cost;
            }
            return try self.withdrawTokens(tokens[0..count], sampled);
        }
        pub fn withdrawTokens(self: *Manager, tokens: []const firewall.DispatchToken, sampled: effect.Clock) !Step {
            self.status.ready = false;
            const sent_ns = self.monotonic(self.monotonic_context);
            const prior_mutation_ns = self.last_mutation_ns;
            const prior_mutation_wall_us = self.last_mutation_wall_us;
            self.last_mutation_ns = sent_ns;
            self.last_mutation_wall_us = sampled.prepared_us;
            const result = self.inspector.withdrawBatch(tokens, .{ .wall_us = sampled.prepared_us }, &self.inventory.?.snapshot) catch |failure| {
                self.recordFirewallDirect(.effect_dispatch, failure);
                self.last_mutation_ns = prior_mutation_ns;
                self.last_mutation_wall_us = prior_mutation_wall_us;
                if (!transientReadback(failure)) return error.EffectBackendUncertain;
                return self.deferReadback();
            };
            switch (result) {
                .uncertain => |failure| {
                    self.recordFirewallFailure(failure);
                    if (failure.mutation == .not_started) {
                        self.last_mutation_ns = prior_mutation_ns;
                        self.last_mutation_wall_us = prior_mutation_wall_us;
                    }
                    if (!transientReadback(failure.cause)) return error.EffectBackendUncertain;
                    return self.deferReadback();
                },
                .verified => |verified| {
                    var snapshot = verified.snapshot;
                    const after_ns = self.monotonic(self.monotonic_context);
                    {
                        errdefer snapshot.deinit();
                        try self.validateAndCaptureObservation(&snapshot, .effect, verified.observed_wall_us, .effect_verify);
                    }
                    self.keepInventory(snapshot, verified.observed_start_wall_us, verified.observed_wall_us, after_ns);
                    if (!try self.evaluateInventory()) return self.deferReadback();
                    return .progress;
                },
            }
        }
    };
}
