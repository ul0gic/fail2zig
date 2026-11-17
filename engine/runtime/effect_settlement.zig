// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Records dispatch outcomes in the store from readback or acknowledgement and patches the view with the committed rows.
// Holds: A settlement that changes no stored row is refused as an invalid effect rather than taken as done.

const std = @import("std");
const durable = @import("../store/store.zig");
const effect = @import("../effect/effect.zig");
const firewall = @import("../firewall/inspection.zig");
const Binding = @import("effect_runtime.zig").Binding;
const Step = @import("effect_runtime.zig").Step;

pub fn Methods(comptime Manager: type) type {
    return struct {
        const BatchState = enum { desired, mismatch };
        pub fn settleBatch(self: *Manager, bindings: []const Binding, indices: []const usize, dispatch_us: i64, observed_us: i64, state: BatchState, fingerprint: effect.Hash) !void {
            var items: [firewall.max_install_messages]durable.Store.InstallItem = undefined;
            for (indices, 0..) |index, k| {
                const entry = self.live[index];
                items[k] = .{ .token = entry.token(), .state = if (state == .desired) entry.desired else null };
            }
            const pre = self.store.effect_publication_epoch;
            {
                errdefer self.writeFailed(pre);
                _ = try self.store.settleInstalled(items[0..indices.len], dispatch_us, fingerprint, observed_us, try self.clock());
            }
            try self.attributeBatch(bindings, indices, pre);
        }
        pub fn attributeBatch(self: *Manager, bindings: []const Binding, indices: []const usize, pre: u64) !void {
            const post = self.store.effect_publication_epoch;
            const current = self.cached_epoch != null and self.cached_epoch.? == pre;
            self.cached_epoch = null;
            if (post == std.math.maxInt(u64)) return;
            if (post == pre) {
                std.log.warn("native: settlement of {d} effects changed no row at epoch {d}", .{ indices.len, pre });
                return error.InvalidEffect;
            }
            if (!current or post < pre or post - pre != 1 or self.staged_revision != null) return;
            try self.store.beginRead();
            errdefer self.store.rollback();
            const installation = try self.store.readInstallation() orelse return error.InstallationRequired;
            for (indices) |index| {
                const entry = try self.store.readEffect(self.live[index].scope_key, installation) orelse break;
                var owners: [effect.max_page]effect.Owner = undefined;
                const count = try self.store.readOwners(entry.scope_key, &owners);
                const owner_deadline = try self.ownerDeadline(bindings, owners[0..count]);
                try self.replaceAt(index, entry, owner_deadline);
            } else {
                try self.store.commitTransaction();
                if (self.store.effect_publication_epoch == post) self.cached_epoch = post;
                return;
            }
            try self.store.commitTransaction();
        }
        pub fn settleMarker(self: *Manager, bindings: []const Binding, index: usize) !Step {
            const marker = self.markers[index].?;
            self.markers[index] = null;
            if (!self.matched[index]) return .progress;
            const held = &self.inventory.?;
            const entry = self.live[index];
            try self.settle(bindings, index, entry, marker.sent_wall_us, .{ .installation = entry.installation.id, .scope_key = entry.scope_key, .fingerprint = held.snapshot.fingerprint, .observed_us = held.end_us, .qualification = .complete_owned, .state = entry.desired });
            return .progress;
        }
        pub fn settleLegacy(self: *Manager, bindings: []const Binding, index: usize, sampled: effect.Clock) !Step {
            const entry = self.live[index];
            if (try self.settlementReadback(entry, sampled)) |outcome| return outcome;
            const held = &self.inventory.?;
            try self.settle(bindings, index, entry, held.start_us, .{ .installation = entry.installation.id, .scope_key = entry.scope_key, .fingerprint = held.snapshot.fingerprint, .observed_us = held.end_us, .qualification = .complete_owned, .state = if (self.matched[index]) entry.desired else null });
            return .progress;
        }
        pub fn settlementReadback(self: *Manager, entry: effect.Entry, sampled: effect.Clock) !?Step {
            const held = &(self.inventory orelse return self.deferReadback());
            const proof = blk: {
                try self.store.beginRead();
                errdefer self.store.rollback();
                var row = try self.store.statement("SELECT dispatch_us,observed_us,fingerprint FROM effect_intents WHERE intent_id=?1;");
                defer row.deinit();
                try row.blob(1, &entry.intent_id);
                if (!try row.row()) return error.InvalidEffect;
                const dispatched = try row.optionalSigned(0);
                const observed = try row.optionalSigned(1);
                if (entry.status != .pending and dispatched == null) return error.InvalidEffect;
                if ((entry.status == .applied or entry.status == .absent or entry.status == .expired) and observed == null) return error.InvalidEffect;
                const start_floor = @max(entry.intent_us, dispatched orelse entry.intent_us);
                var next_us = start_floor;
                var current = held.start_us >= start_floor;
                if (observed) |previous| {
                    const fingerprint = try durable.Store.effectBlob(&row, 2, 32);
                    const conflict = held.end_us == previous and !std.mem.eql(u8, &held.snapshot.fingerprint, &fingerprint);
                    current = current and held.end_us >= previous and !conflict;
                    next_us = @max(next_us, if (conflict) std.math.add(i64, previous, 1) catch return error.InvalidEffect else previous);
                }
                if (!current) _ = try self.store.effectClock(sampled);
                try self.store.commitTransaction();
                break :blk .{ .current = current, .next_us = next_us };
            };
            if (proof.current) return null;
            self.status.ready = false;
            if (sampled.prepared_us < proof.next_us) {
                self.readback_wait = @max(self.readback_wait, 1);
                return .{ .wait = self.waitDue() };
            }
            return try self.readback(sampled);
        }
        pub fn settleLegacyTargets(self: *Manager, bindings: []const Binding, sampled: effect.Clock) !?Step {
            if (self.store.schema_version < 21) return null;
            const key = try self.store.unsettledActionScope() orelse return null;
            if (self.legacy_targets_attempted) |prior| if (std.mem.eql(u8, &prior, &key)) return null;
            const index = self.findLive(key) orelse return null;
            const entry = self.live[index];
            if ((entry.status != .applied and entry.status != .absent) or !self.matched[index]) return null;
            if (try self.settlementReadback(entry, sampled)) |outcome| return outcome;
            const held = &self.inventory.?;
            try self.settle(bindings, index, entry, held.start_us, .{ .installation = entry.installation.id, .scope_key = entry.scope_key, .fingerprint = held.snapshot.fingerprint, .observed_us = held.end_us, .qualification = .complete_owned, .state = entry.desired });
            self.legacy_targets_attempted = key;
            return .progress;
        }
        pub fn refreshSettled(self: *Manager, bindings: []const Binding, indices: []const usize) !void {
            var stale = false;
            for (indices) |index| stale = stale or self.live[index].status == .pending;
            if (!stale) return;
            try self.store.beginRead();
            errdefer self.store.rollback();
            const installation = try self.store.readInstallation() orelse return error.InstallationRequired;
            for (indices) |index| {
                if (self.live[index].status != .pending) continue;
                const entry = try self.store.readEffect(self.live[index].scope_key, installation) orelse continue;
                var owners: [effect.max_page]effect.Owner = undefined;
                const count = try self.store.readOwners(entry.scope_key, &owners);
                try self.replaceAt(index, entry, try self.ownerDeadline(bindings, owners[0..count]));
            }
            try self.store.commitTransaction();
        }
        pub fn settle(self: *Manager, bindings: []const Binding, index: usize, entry: effect.Entry, dispatch_us: i64, observed: effect.Observation) !void {
            const pre = self.store.effect_publication_epoch;
            {
                errdefer self.writeFailed(pre);
                _ = try self.store.settleOutcome(entry.token(), dispatch_us, observed, try self.clock());
            }
            if (try self.attributeCommit(bindings, index, pre) == .unchanged) {
                std.log.warn("native: settlement of view index {d} changed no row at epoch {d}", .{ index, pre });
                return error.InvalidEffect;
            }
        }
    };
}
