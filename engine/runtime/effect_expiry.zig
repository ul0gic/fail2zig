// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Prepares due expiries in batches, settles expired removals from readback, and removes lapsed effects during an outage.
// Holds: An effect with a dispatch in flight or an unsettled marker is never counted due for expiry.

const std = @import("std");
const build_options = @import("build_options");
const diag_mod = @import("../diag/diag.zig");
const durable = @import("../store/store.zig");
const effect = @import("../effect/effect.zig");
const firewall = @import("../firewall/inspection.zig");
const Binding = @import("effect_runtime.zig").Binding;
const Step = @import("effect_runtime.zig").Step;
const propagateFirewall = @import("effect_runtime.zig").propagateFirewall;

pub fn Methods(comptime Manager: type) type {
    return struct {
        pub fn expiryDeadline(self: *const Manager, index: usize, entry: effect.Entry) ?i64 {
            const owner = self.owner_deadline_us[index];
            return switch (entry.desired) {
                .finite => |deadline| if (owner) |at| @min(at, deadline) else deadline,
                .absent, .permanent => owner,
            };
        }
        pub fn expiryDue(self: *const Manager, index: usize, entry: effect.Entry, now_us: i64) bool {
            if (entry.status == .dispatched or self.markers[index] != null) return false;
            if (self.expiryDeadline(index, entry)) |deadline| return deadline <= now_us;
            return false;
        }
        pub fn settleExpiredBatch(self: *Manager, tokens: []const effect.Token) !Step {
            const diag_span = if (comptime build_options.diag) diag_mod.enter(.expiry) else {};
            defer if (comptime build_options.diag) diag_mod.leave(diag_span);
            const sampled = try self.clock();
            for (tokens) |token_value| {
                const index = self.findLive(token_value.scope_key) orelse return error.StaleEffect;
                const entry = self.live[index];
                if (!std.meta.eql(entry.token(), token_value)) return error.StaleEffect;
                if (try self.settlementReadback(entry, sampled)) |outcome| return outcome;
            }
            const held = &self.inventory.?;
            const pre = self.store.effect_publication_epoch;
            {
                errdefer self.writeFailed(pre);
                _ = try self.store.settleExpired(tokens, held.snapshot.fingerprint, held.end_us, try self.clock());
            }
            if (self.store.effect_publication_epoch == pre) {
                std.log.warn("native: expiry settlement of {d} effects changed no row at epoch {d}", .{ tokens.len, pre });
                return error.InvalidEffect;
            }
            if (self.events_subscribed) try self.forgetExpired(tokens);
            if (comptime build_options.diag) diag_mod.count(.expiries_settled, tokens.len);
            return .progress;
        }
        pub fn forgetExpired(self: *Manager, tokens: []const effect.Token) !void {
            const held = &self.inventory.?;
            for (self.live[0..self.count]) |entry| {
                if (entry.scope.canonical.subject.kind != .host) continue;
                for (tokens) |expired| if (std.mem.eql(u8, &expired.scope_key, &entry.scope_key)) {
                    const host = firewall.legacyAddress(entry.scope.canonical) catch continue;
                    _ = try held.snapshot.removeHost(.{ .address = host });
                    break;
                };
            }
            self.inspector.retained_bytes = held.snapshot.entries.len * @sizeOf(firewall.Entry);
            _ = try self.recount();
        }
        pub fn expire(self: *Manager, bindings: []const Binding, index: usize, sampled: effect.Clock) !Step {
            const diag_span = if (comptime build_options.diag) diag_mod.enter(.expiry) else {};
            defer if (comptime build_options.diag) diag_mod.leave(diag_span);
            self.status.ready = false;
            const entry = self.live[index];
            const pre = self.store.effect_publication_epoch;
            var items: [durable.Store.max_expiry_batch]durable.Store.ExpiryItem = undefined;
            items[0] = .{ .key = entry.scope_key, .revision = entry.revision };
            var count: usize = 1;
            for (self.live[0..self.count], 0..) |other, i| {
                if (count == items.len) break;
                if (i == index or !self.expiryDue(i, other, sampled.prepared_us)) continue;
                items[count] = .{ .key = other.scope_key, .revision = other.revision };
                count += 1;
            }
            if (count == 1) {
                const prepared = blk: {
                    errdefer self.writeFailed(pre);
                    break :blk try self.store.prepareExpiry(entry.scope_key, entry.revision, sampled);
                };
                if (prepared.desired != .absent) self.live_selections = 0;
                self.counters.expiry_batches += 1;
                self.counters.expiries_prepared += 1;
                if (comptime build_options.diag) diag_mod.count(.expiries_prepared, 1);
                return switch (try self.attributeCommit(bindings, index, pre)) {
                    .changed => .progress,
                    .unchanged => .{ .wait = self.waitDue() },
                };
            }
            const expired = blk: {
                errdefer self.writeFailed(pre);
                break :blk try self.store.prepareExpiries(items[0..count], sampled);
            };
            self.counters.expiry_batches += 1;
            self.counters.expiries_prepared += count;
            if (comptime build_options.diag) diag_mod.count(.expiries_prepared, expired);
            if (expired == 0 or self.store.effect_publication_epoch == pre) {
                self.live_selections = 0;
                return .{ .wait = self.waitDue() };
            }
            return .progress;
        }
        pub fn expireDuringOutage(self: *Manager) !void {
            self.status.ready = false;
            errdefer |failure| {
                self.status.uncertain = true;
                self.status.cause = failure;
            }
            const clock_sample = try self.clock();
            self.status.overdue = 0;
            for (self.live[0..self.count]) |entry| if (entry.desired == .finite and !entry.desired.live(clock_sample.prepared_us)) {
                self.status.overdue += 1;
            };
            if (self.store.reopen_required or !self.admitted or self.cached_epoch == null or self.cached_epoch.? != self.store.effect_publication_epoch or self.store.effect_publication_epoch == std.math.maxInt(u64)) return;
            for (self.live[0..self.count], 0..) |entry, i| {
                if (entry.desired != .finite or entry.desired.live(clock_sample.prepared_us) or self.outage_attempted[i]) continue;
                self.outage_attempted[i] = true;
                self.status.uncertain = true;
                self.dropInventory();
                var result = self.inspector.applyExact(self.token(entry, .absent), .{ .wall_us = clock_sample.prepared_us }) catch |failure| {
                    self.recordFirewallDirect(.effect_dispatch, failure);
                    return propagateFirewall(void, failure);
                };
                defer result.deinit();
                switch (result) {
                    .uncertain => |failure| self.recordFirewallFailure(failure),
                    .verified => |*observed| self.captureObservation(&observed.snapshot, .outage, observed.observed_wall_us, .not_checked),
                }
                return;
            }
        }
    };
}
