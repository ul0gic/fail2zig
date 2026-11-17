// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Reads the kernel set, keeps it as the held inventory and matches each live effect against it.
// Holds: A held inventory counts as current only if read after the last mutation was sent, or while subscribed events stay healthy.

const std = @import("std");
const build_options = @import("build_options");
const diag_mod = @import("../diag/diag.zig");
const effect = @import("../effect/effect.zig");
const firewall = @import("../firewall/inspection.zig");
const Step = @import("effect_runtime.zig").Step;
const transientReadback = @import("effect_runtime.zig").transientReadback;
const propagateFirewall = @import("effect_runtime.zig").propagateFirewall;
const audit_lead_ns = @import("effect_runtime.zig").audit_lead_ns;

pub fn Methods(comptime Manager: type) type {
    return struct {
        // Holds: Refuses the inventory if any kernel element is not claimed by a live effect with the same scope and effect id.
        pub fn validateInventory(self: *Manager, snapshot: *const firewall.Snapshot) !void {
            if (snapshot.state != .owned) return error.InstallationMismatch;
            const installed = snapshot.entries;
            if (installed.len > self.owned_marks.capacity()) return error.LimitExceeded;
            self.owned_marks.setRangeValue(.{ .start = 0, .end = installed.len }, false);
            for (self.live[0..self.count]) |entry| {
                const index = try snapshot.find(entry.scope.canonical) orelse continue;
                const found = installed[index];
                if (found.scope != null and (found.effect_id == null or !std.mem.eql(u8, &found.effect_id.?, &entry.scope_key))) continue;
                self.owned_marks.set(index);
            }
            for (0..installed.len) |index| if (!self.owned_marks.isSet(index)) return error.UnownedInstalledEffect;
        }
        pub fn keepInventory(self: *Manager, snapshot: firewall.Snapshot, start_us: i64, end_us: i64, start_ns: ?u64) void {
            if (self.inventory) |*held| held.snapshot.deinit();
            self.inventory = null;
            self.inventory = .{ .snapshot = snapshot, .start_us = start_us, .end_us = end_us, .start_ns = start_ns };
            self.inspector.retained_bytes = snapshot.entries.len * @sizeOf(firewall.Entry);
            self.legacy_targets_attempted = null;
        }
        pub fn dropInventory(self: *Manager) void {
            self.inventory_discontinuity +|= 1;
            if (self.inventory) |*held| held.snapshot.deinit();
            self.inventory = null;
            self.inspector.retained_bytes = 0;
        }
        pub fn inventoryFreshForRetirement(self: *const Manager) bool {
            if (!self.inventoryCurrent()) return false;
            if (self.verify_interval_ns != 0) if (self.last_readback_ns) |last| if (self.monotonic(self.monotonic_context)) |now| {
                const interval = if (self.events_subscribed) self.verify_interval_ns -| audit_lead_ns else self.verify_interval_ns;
                if (now -| last >= interval) return false;
            };
            return true;
        }
        // Does:  Reports whether the held inventory stands: read after the last mutation was sent or, with events subscribed, healthy.
        pub fn inventoryCurrent(self: *const Manager) bool {
            const held = self.inventory orelse return false;
            if (self.events_subscribed) return self.events_healthy;
            const sent_wall = self.last_mutation_wall_us orelse return true;
            if (held.start_ns) |start| if (self.last_mutation_ns) |sent| return start > sent;
            return held.start_us > sent_wall;
        }
        pub fn refreshMatch(self: *Manager, index: usize) !void {
            const held = &(self.inventory orelse {
                self.matched[index] = false;
                return;
            });
            const entry = self.live[index];
            const matched = self.inspector.matchesSnapshot(&held.snapshot, self.token(entry, entry.desired), held.start_us, held.end_us) catch |failure| {
                if (transientReadback(failure)) {
                    self.recordFirewallDirect(.readback, failure);
                    self.dropInventory();
                    self.matched[index] = false;
                    return;
                }
                self.recordObservationFailure(.readback, failure);
                return propagateFirewall(void, failure);
            };
            // Why: An absence that stops matching voids a retirement walk in progress, which restarts when inventory_discontinuity moves.
            if (entry.desired == .absent and self.matched[index] and !matched) self.inventory_discontinuity +|= 1;
            self.matched[index] = matched;
            if (self.confirmed[index] != matched) self.view_revision +%= 1;
            self.confirmed[index] = matched;
        }
        pub fn recount(self: *Manager) !bool {
            var confirmed_count: usize = 0;
            var installed: u32 = 0;
            for (self.live[0..self.count], 0..) |entry, index| {
                try self.refreshMatch(index);
                const held = &(self.inventory orelse return false);
                if (entry.status == .applied and entry.desired.live(held.end_us) and self.confirmed[index]) confirmed_count += 1;
                if (entry.desired.live(held.end_us)) if (try held.snapshot.find(entry.scope.canonical)) |found| {
                    const installed_entry = held.snapshot.entries[found];
                    if (installed_entry.scope == null or (installed_entry.effect_id != null and std.mem.eql(u8, &installed_entry.effect_id.?, &entry.scope_key))) installed += 1;
                };
            }
            if (self.inventory == null) return false;
            self.installed_live = installed;
            self.status.confirmed = confirmed_count;
            return true;
        }
        pub fn evaluateInventory(self: *Manager) !bool {
            if (!try self.recount()) return false;
            const held = &(self.inventory orelse return false);
            self.readback_failures = 0;
            self.counters.full_readbacks += 1;
            self.counters.dump_interrupted = self.inspector.dump_interruptions;
            self.last_readback_ns = held.start_ns;
            self.last_readback_wall_us = held.end_us;
            self.events_healthy = self.events_subscribed;
            self.last_generation = null;
            if (self.status.diagnostic) |diagnostic| if (transientReadback(diagnostic.cause) or diagnostic.cause == error.UnownedInstalledEffect) {
                if (diagnostic.cause == error.UnownedInstalledEffect) std.log.info("native: the kernel set holds only owned elements again; protection restored", .{});
                self.status.diagnostic = null;
                self.status.cause = null;
                self.status.uncertain = false;
            };
            return true;
        }
        pub fn readback(self: *Manager, sampled: effect.Clock) !Step {
            const diag_span = if (comptime build_options.diag) diag_mod.enter(.readback) else {};
            defer if (comptime build_options.diag) diag_mod.leave(diag_span);
            const start_ns = self.monotonic(self.monotonic_context);
            if (comptime build_options.diag) diag_mod.readback(start_ns, self.last_verified_ns, self.verify_interval_ns, self.wake_interval_ns);
            self.discardEvents();
            var snapshot = self.inspector.inspect() catch |failure| {
                self.recordFirewallDirect(.readback, failure);
                if (transientReadback(failure)) return self.deferReadback();
                return propagateFirewall(Step, failure);
            };
            if (comptime build_options.diag) diag_mod.limit(.kernel_elements, snapshot.entries.len, firewall.max_inventory_entries);
            {
                const diag_compare = if (comptime build_options.diag) diag_mod.enter(.compare) else {};
                defer if (comptime build_options.diag) diag_mod.leave(diag_compare);
                errdefer snapshot.deinit();
                self.validateAndCaptureObservation(&snapshot, .readback, sampled.prepared_us, .readback) catch |failure| {
                    if (failure != error.UnownedInstalledEffect) return failure;
                    return self.unownedElementSeen(&snapshot, failure);
                };
            }
            self.keepInventory(snapshot, sampled.prepared_us, (try self.clock()).prepared_us, start_ns);
            const evaluated = evaluated_blk: {
                const diag_compare = if (comptime build_options.diag) diag_mod.enterContinued(.compare) else {};
                defer if (comptime build_options.diag) diag_mod.leave(diag_compare);
                break :evaluated_blk try self.evaluateInventory();
            };
            if (!evaluated) return self.deferReadback();
            if (self.counters.redispatched != 0) {
                std.log.info("native: {d} applied effects were missing from the kernel since the last audit and were dispatched again", .{self.counters.redispatched});
                self.counters.redispatched = 0;
            }
            self.status.ready = false;
            return .progress;
        }
        pub fn unownedElementSeen(self: *Manager, snapshot: *firewall.Snapshot, failure: anyerror) Step {
            snapshot.deinit();
            if (self.readback_failures == 0) std.log.warn("native: an element the daemon does not own is in its kernel set; protection degraded until an audit finds the set clean", .{});
            self.dropInventory();
            self.events_healthy = false;
            self.status.ready = false;
            self.status.uncertain = true;
            self.status.cause = failure;
            self.backOff();
            return .{ .wait = self.waitDue() };
        }
    };
}
