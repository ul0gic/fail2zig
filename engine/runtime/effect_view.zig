// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Rebuilds and patches the Manager's view of stored effects page by page, checking each owner's binding and lease.
// Holds: A rebuild is discarded and restarted when the store's publication epoch moves while its pages are read.

const std = @import("std");
const durable = @import("../store/store.zig");
const effect = @import("../effect/effect.zig");
const Binding = @import("effect_runtime.zig").Binding;
const Step = @import("effect_runtime.zig").Step;
const ViewAuthority = @import("effect_runtime.zig").ViewAuthority;
const Marker = @import("effect_runtime.zig").Marker;

pub fn Methods(comptime Manager: type) type {
    return struct {
        pub fn refreshTurn(self: *Manager, bindings: []const Binding, authority: ViewAuthority) !bool {
            if (self.staged_revision == null) {
                self.staged_authority = authority;
                self.staged_count = 0;
                self.staged_epoch = self.store.effect_publication_epoch;
            }
            if (self.staged_authority != authority or self.staged_epoch != self.store.effect_publication_epoch) {
                self.staged_revision = null;
                self.counters.rebuild_restarts += 1;
                return false;
            }
            var rows: [effect.max_page]effect.Entry = undefined;
            const after = if (self.staged_count == 0) null else self.staged[self.staged_count - 1].scope_key;
            const page = try self.store.effectPage(after, self.staged_revision, &rows);
            if (page.count > self.staged.len - self.staged_count) return error.EffectCapacity;
            for (rows[0..page.count], 0..) |entry, offset| self.staged_owner_deadline_us[self.staged_count + offset] = try self.validateViewOwners(bindings, entry, authority);
            @memcpy(self.staged[self.staged_count..][0..page.count], rows[0..page.count]);
            self.staged_count += page.count;
            self.staged_revision = page.revision;
            if (page.more) return false;
            if (self.staged_epoch != self.store.effect_publication_epoch) {
                self.staged_revision = null;
                self.counters.rebuild_restarts += 1;
                return false;
            }
            self.counters.rebuilds_completed += 1;
            const keep_inventory = self.view_authority == authority and self.inventoryFreshForRetirement();
            for (self.staged[0..self.staged_count], 0..) |entry, index| {
                const carried = self.findLive(entry.scope_key);
                const same = carried != null and std.mem.eql(u8, &self.live[carried.?].intent_id, &entry.intent_id);
                self.staged_markers[index] = if (same) self.markers[carried.?] else null;
                self.staged_confirmed[index] = same and self.confirmed[carried.?];
                self.staged_matched[index] = keep_inventory and same and self.matched[carried.?];
            }
            if (!keep_inventory) self.dropInventory();
            std.mem.swap([]effect.Entry, &self.live, &self.staged);
            std.mem.swap([]?Marker, &self.markers, &self.staged_markers);
            std.mem.swap([]bool, &self.confirmed, &self.staged_confirmed);
            std.mem.swap([]bool, &self.matched, &self.staged_matched);
            std.mem.swap([]?i64, &self.owner_deadline_us, &self.staged_owner_deadline_us);
            self.count = self.staged_count;
            self.cached_epoch = self.staged_epoch;
            self.view_authority = authority;
            self.staged_authority = .none;
            self.view_revision +%= 1;
            self.staged_revision = null;
            self.cursor = self.count;
            self.legacy_targets_attempted = null;
            @memset(self.outage_attempted, false);
            self.status.ready = false;
            if (keep_inventory) {
                errdefer self.dropInventory();
                try self.validateInventory(&self.inventory.?.snapshot);
                if (!try self.recount()) self.dropInventory();
            }
            return true;
        }
        pub fn catchUp(self: *Manager, bindings: []const Binding) !?Step {
            const cached = self.cached_epoch orelse return null;
            const current = self.store.effect_publication_epoch;
            // Why: The store keeps attributions only for its last attribution_ring epochs; a gap it cannot replay falls back to a rebuild.
            if (current == std.math.maxInt(u64) or current <= cached or current - cached > durable.Store.attribution_ring) return null;
            var epoch = cached + 1;
            while (epoch <= current) : (epoch += 1) if (self.store.attributedChange(epoch) == null) return null;
            var spent_only = true;
            epoch = cached + 1;
            while (epoch <= current) : (epoch += 1) for (self.store.attributedChange(epoch).?.slice()) |key| {
                const found = self.findLive(key);
                if (try self.readScope(key)) |entry| {
                    const owner_deadline = try self.validateViewOwners(bindings, entry, self.view_authority);
                    spent_only = false;
                    if (found) |index| {
                        try self.replaceAt(index, entry, owner_deadline);
                    } else {
                        if (self.count == self.live.len) return error.EffectCapacity;
                        try self.insertAt(self.insertionPoint(key), entry, owner_deadline);
                    }
                } else if (found) |index| {
                    const removed = self.live[index];
                    if (removed.desired != .absent or removed.status != .absent) spent_only = false;
                    self.removeAt(index);
                }
            };
            if (self.store.effect_publication_epoch != current) return null;
            self.cached_epoch = current;
            self.counters.incremental_updates += 1;
            if (spent_only and self.status.ready) {
                self.cursor = self.count;
                return .idle;
            }
            self.status.ready = false;
            self.cursor = self.count;
            return .progress;
        }
        pub fn replaceAt(self: *Manager, index: usize, entry: effect.Entry, owner_deadline: ?i64) !void {
            const previous = self.live[index];
            self.live[index] = entry;
            self.view_revision +%= 1;
            self.outage_attempted[index] = false;
            self.owner_deadline_us[index] = owner_deadline;
            if (!std.mem.eql(u8, &previous.intent_id, &entry.intent_id)) {
                self.markers[index] = null;
                self.confirmed[index] = false;
                self.matched[index] = false;
            }
            try self.refreshMatch(index);
        }
        pub fn insertAt(self: *Manager, at: usize, entry: effect.Entry, owner_deadline: ?i64) !void {
            const n = self.count;
            std.mem.copyBackwards(effect.Entry, self.live[at + 1 .. n + 1], self.live[at..n]);
            std.mem.copyBackwards(bool, self.outage_attempted[at + 1 .. n + 1], self.outage_attempted[at..n]);
            std.mem.copyBackwards(?Marker, self.markers[at + 1 .. n + 1], self.markers[at..n]);
            std.mem.copyBackwards(bool, self.confirmed[at + 1 .. n + 1], self.confirmed[at..n]);
            std.mem.copyBackwards(bool, self.matched[at + 1 .. n + 1], self.matched[at..n]);
            std.mem.copyBackwards(?i64, self.owner_deadline_us[at + 1 .. n + 1], self.owner_deadline_us[at..n]);
            self.live[at] = entry;
            self.view_revision +%= 1;
            self.outage_attempted[at] = false;
            self.markers[at] = null;
            self.confirmed[at] = false;
            self.matched[at] = false;
            self.owner_deadline_us[at] = owner_deadline;
            self.count += 1;
            try self.refreshMatch(at);
        }
        pub fn removeAt(self: *Manager, index: usize) void {
            const n = self.count;
            std.mem.copyForwards(effect.Entry, self.live[index .. n - 1], self.live[index + 1 .. n]);
            std.mem.copyForwards(bool, self.outage_attempted[index .. n - 1], self.outage_attempted[index + 1 .. n]);
            std.mem.copyForwards(?Marker, self.markers[index .. n - 1], self.markers[index + 1 .. n]);
            std.mem.copyForwards(bool, self.confirmed[index .. n - 1], self.confirmed[index + 1 .. n]);
            std.mem.copyForwards(bool, self.matched[index .. n - 1], self.matched[index + 1 .. n]);
            std.mem.copyForwards(?i64, self.owner_deadline_us[index .. n - 1], self.owner_deadline_us[index + 1 .. n]);
            self.count -= 1;
            self.view_revision +%= 1;
        }
        pub fn findLive(self: *const Manager, key: [32]u8) ?usize {
            const at = self.insertionPoint(key);
            return if (at < self.count and std.mem.eql(u8, &self.live[at].scope_key, &key)) at else null;
        }
        pub fn insertionPoint(self: *const Manager, key: [32]u8) usize {
            var low: usize = 0;
            var high: usize = self.count;
            while (low < high) {
                const mid = low + (high - low) / 2;
                if (std.mem.order(u8, &self.live[mid].scope_key, &key) == .lt) low = mid + 1 else high = mid;
            }
            return low;
        }
        pub fn validateViewOwners(self: *Manager, bindings: []const Binding, entry: effect.Entry, authority: ViewAuthority) !?i64 {
            switch (authority) {
                .runtime => return self.validateOwners(bindings, entry),
                .retirement_observation => {
                    var owners: [effect.max_page]effect.Owner = undefined;
                    _ = try self.store.effectOwners(entry.scope_key, entry.revision, &owners);
                    return null;
                },
                .none => return error.EffectReconciliationRequired,
            }
        }
        // Does:  Discards a runtime view and clears ready at once, for startup retirement that cannot wait for a runtime slice.
        pub fn beginJailRetirementObservation(self: *Manager) void {
            if (self.view_authority == .runtime or self.staged_authority == .runtime) self.discardViewAuthority();
            self.status.ready = false;
        }
        pub fn discardViewAuthority(self: *Manager) void {
            self.forgetKernel();
            self.cached_epoch = null;
            self.staged_revision = null;
            self.staged_count = 0;
            self.view_authority = .none;
            self.staged_authority = .none;
            self.count = 0;
            self.cursor = 0;
            self.readback_failures = 0;
            self.readback_wait = 0;
            self.last_verified_ns = null;
            self.legacy_targets_attempted = null;
            @memset(self.outage_attempted, false);
            self.status.ready = false;
        }
        pub fn validateOwners(self: *Manager, bindings: []const Binding, entry: effect.Entry) !?i64 {
            var owners: [effect.max_page]effect.Owner = undefined;
            const count = try self.store.effectOwners(entry.scope_key, entry.revision, &owners);
            return self.ownerDeadline(bindings, owners[0..count]);
        }
        pub fn ownerDeadline(self: *Manager, bindings: []const Binding, owners: []const effect.Owner) !?i64 {
            _ = self;
            var deadline: ?i64 = null;
            for (owners) |owner| {
                if (owner.lease == .absent) continue;
                for (bindings) |binding| {
                    if (!std.mem.eql(u8, binding.jail, owner.jail.slice())) continue;
                    if (!std.mem.eql(u8, &binding.generation, &owner.generation)) return error.EffectGenerationMismatch;
                    break;
                } else return error.UnconfiguredStateOwner;
                if (owner.lease == .finite) deadline = if (deadline) |prior| @min(prior, owner.lease.finite) else owner.lease.finite;
            }
            return deadline;
        }
        pub fn readScope(self: *Manager, key: [32]u8) !?effect.Entry {
            try self.store.beginRead();
            errdefer self.store.rollback();
            const installation = try self.store.readInstallation() orelse return error.InstallationRequired;
            const entry = try self.store.readEffect(key, installation);
            try self.store.commitTransaction();
            return entry;
        }
        const Commit = enum { unchanged, changed };
        pub fn attributeCommit(self: *Manager, bindings: []const Binding, index: usize, pre: u64) !Commit {
            const post = self.store.effect_publication_epoch;
            if (post == std.math.maxInt(u64)) {
                self.cached_epoch = null;
                return .changed;
            }
            if (post == pre) {
                self.cached_epoch = null;
                return .unchanged;
            }
            const current = self.cached_epoch != null and self.cached_epoch.? == pre;
            if (!current or post < pre or post - pre != 1 or self.staged_revision != null) {
                self.cached_epoch = null;
                return .changed;
            }
            self.cached_epoch = null;
            const entry = try self.readScope(self.live[index].scope_key) orelse return .changed;
            const owner_deadline = try self.validateViewOwners(bindings, entry, self.view_authority);
            if (self.store.effect_publication_epoch != post) return .changed;
            try self.replaceAt(index, entry, owner_deadline);
            self.cached_epoch = post;
            return .changed;
        }
        pub fn writeFailed(self: *Manager, pre: u64) void {
            if (self.store.reopen_required or self.store.effect_publication_epoch != pre) self.cached_epoch = null;
        }
    };
}
