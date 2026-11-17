// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Withdraws every installed effect at stop in bounded batches, then reads back the withdrawn kernel set.
// Holds: Stop finishes only when a final readback shows the owned set empty; any element left is refused as unowned.

const std = @import("std");
const firewall = @import("../firewall/inspection.zig");
const Step = @import("effect_runtime.zig").Step;
const transientReadback = @import("effect_runtime.zig").transientReadback;
const transientCause = @import("effect_runtime.zig").transientCause;
const propagateFirewall = @import("effect_runtime.zig").propagateFirewall;

pub fn Methods(comptime Manager: type) type {
    return struct {
        pub fn withdrawStep(self: *Manager, expected_repair_epoch: u64) Step {
            const result = self.stopStepInner(expected_repair_epoch, false) catch |failure| Step{ .fatal = failure };
            if (self.stopping or result == .idle) {
                self.withdrawn = true;
                self.status.ready = false;
                self.status.withdrawn = true;
                self.last_readback_ns = null;
                @memset(self.confirmed[0..self.count], false);
                self.view_revision +%= 1;
            }
            return result;
        }
        const max_stop_retries: u8 = 32;
        pub fn stopFailure(self: *Manager, cause: anyerror, fatal: anyerror) !Step {
            if (!transientCause(cause) or self.stop_retries >= max_stop_retries) return fatal;
            self.stop_retries += 1;
            self.dropInventory();
            return .{ .wait = self.waitDue() };
        }
        pub fn stopStepInner(self: *Manager, expected_repair_epoch: u64, require_ready: bool) !Step {
            if (expected_repair_epoch == 0 or expected_repair_epoch != self.repair_epoch) return error.StaleRepairEpoch;
            if (self.store.reopen_required) return error.ReopenRequired;
            if (!self.stopping) {
                if (!self.admitted or (require_ready and !self.status.ready) or self.cached_epoch == null or self.cached_epoch.? != self.store.effect_publication_epoch) return error.EffectReconciliationRequired;
                self.dropInventory();
                self.stopping = true;
                self.stop_cursor = 0;
                self.stop_retries = 0;
                self.status.ready = false;
            }
            errdefer |failure| {
                self.status.uncertain = true;
                self.status.cause = failure;
            }
            const sampled = try self.clock();
            while (self.stop_cursor < self.count) {
                var tokens: [firewall.max_withdraw_messages]firewall.DispatchToken = undefined;
                var batched: usize = 0;
                var budget: usize = 0;
                var next = self.stop_cursor;
                while (next < self.count and batched < tokens.len) : (next += 1) {
                    const entry = self.live[next];
                    if (entry.desired == .absent) continue;
                    const cost = try firewall.withdrawCost(entry.scope.canonical);
                    if (batched != 0 and budget + cost > firewall.max_withdraw_messages) break;
                    tokens[batched] = self.token(entry, .absent);
                    batched += 1;
                    budget += cost;
                }
                if (batched == 0) {
                    self.stop_cursor = next;
                    continue;
                }
                if (self.inventory == null) {
                    const start_ns = self.monotonic(self.monotonic_context);
                    var snapshot = self.inspector.inspect() catch |failure| {
                        self.recordFirewallDirect(.readback, failure);
                        return self.stopFailure(failure, failure);
                    };
                    {
                        errdefer snapshot.deinit();
                        try self.validateAndCaptureObservation(&snapshot, .stop, sampled.prepared_us, .readback);
                    }
                    self.keepInventory(snapshot, sampled.prepared_us, (try self.clock()).prepared_us, start_ns);
                }
                const result = self.inspector.withdrawBatch(tokens[0..batched], .{ .wall_us = sampled.prepared_us }, &self.inventory.?.snapshot) catch |failure| {
                    self.recordFirewallDirect(.effect_dispatch, failure);
                    return self.stopFailure(failure, failure);
                };
                switch (result) {
                    .uncertain => |failure| {
                        self.recordFirewallFailure(failure);
                        return self.stopFailure(failure.cause, error.EffectBackendUncertain);
                    },
                    .verified => |verified| {
                        var snapshot = verified.snapshot;
                        {
                            errdefer snapshot.deinit();
                            try self.validateAndCaptureObservation(&snapshot, .stop, verified.observed_wall_us, .effect_verify);
                        }
                        self.keepInventory(snapshot, verified.observed_start_wall_us, verified.observed_wall_us, self.monotonic(self.monotonic_context));
                    },
                }
                self.stop_cursor = next;
                return .progress;
            }
            var final = self.inspector.inspect() catch |failure| {
                self.recordFirewallDirect(.readback, failure);
                return self.stopFailure(failure, failure);
            };
            defer final.deinit();
            try self.validateAndCaptureObservation(&final, .stop, sampled.prepared_us, .readback);
            if (final.entries.len != 0) {
                self.recordObservationFailure(.readback, error.UnownedInstalledEffect);
                return error.UnownedInstalledEffect;
            }
            self.dropInventory();
            self.stopping = false;
            self.stop_cursor = 0;
            self.stop_retries = 0;
            self.admitted = false;
            self.cached_epoch = null;
            self.count = 0;
            self.view_revision +%= 1;
            self.status = .{};
            return .idle;
        }
        pub fn withdrawnReadback(self: *Manager) !Step {
            const start_ns = self.monotonic(self.monotonic_context);
            if (self.last_readback_ns) |last| if (start_ns) |now| if (now -| last < self.verify_interval_ns) return .idle;
            const sampled = try self.clock();
            var snapshot = self.inspector.inspect() catch |failure| {
                self.recordFirewallDirect(.readback, failure);
                if (transientReadback(failure)) return self.deferReadback();
                return propagateFirewall(Step, failure);
            };
            defer snapshot.deinit();
            if (snapshot.state != .owned) return error.InstallationMismatch;
            self.captureObservation(&snapshot, .readback, sampled.prepared_us, .not_checked);
            self.readback_failures = 0;
            self.counters.full_readbacks += 1;
            self.last_readback_ns = start_ns;
            self.last_readback_wall_us = (try self.clock()).prepared_us;
            self.installed_live = std.math.cast(u32, snapshot.entries.len) orelse return error.LimitExceeded;
            self.status.ready = false;
            self.status.withdrawn = true;
            if (self.status.diagnostic) |diagnostic| if (transientReadback(diagnostic.cause)) {
                self.status.diagnostic = null;
                self.status.cause = null;
                self.status.uncertain = false;
            };
            return .idle;
        }
        pub const Residual = struct {
            installed: ?usize,
            cause: ?anyerror = null,
        };
        pub fn residualInstalled(self: *Manager) Residual {
            var snapshot = self.inspector.inspect() catch |failure| {
                self.recordFirewallDirect(.readback, failure);
                return .{ .installed = null, .cause = failure };
            };
            defer snapshot.deinit();
            if (snapshot.state != .owned) return .{ .installed = null, .cause = error.InstallationMismatch };
            return .{ .installed = snapshot.entries.len };
        }
    };
}
