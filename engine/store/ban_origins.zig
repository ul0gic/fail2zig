// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Applies a jail's configured banip list as config-owned bans and lists live owners by origin.
// Holds: A config owner whose decision is missing from the applied list is released; an entry over storage capacity is counted pending.

const std = @import("std");
const shared = @import("shared");
const store = @import("store.zig");
const effects = @import("../effect/effect.zig");
const detection = @import("../detect/detection_record.zig");
const ban_origin = @import("../effect/ban_origin.zig");
const canonical_scope = @import("../firewall/scope.zig");
const origin_schema = @import("effects.zig").origin_schema;
const budget = @import("budget.zig");
const Error = store.Error;

pub const Origin = shared.types.Origin;
pub const BanListError = Error || error{InvalidBanListEntry};

pub const BanListChange = struct {
    added: u32 = 0,
    lifted: u32 = 0,
    unchanged: u32 = 0,
    expired: u32 = 0,
    pending: u32 = 0,
};

pub const OwnerOrigin = struct {
    origin: Origin,
    revision: u64,
    decision_id: [32]u8,
};

const ConfigOwner = struct {
    scope: canonical_scope.Scope,
    generation: effects.Hash,
    revision: u64,
};

const StaleOwner = struct { owner: ConfigOwner, decision_id: effects.Hash };

const IndexedId = struct { id: effects.Hash, index: usize };

fn indexedLess(_: void, a: IndexedId, b: IndexedId) bool {
    return switch (std.mem.order(u8, &a.id, &b.id)) {
        .lt => true,
        .gt => false,
        .eq => a.index < b.index,
    };
}

fn idOrder(target: effects.Hash, item: IndexedId) std.math.Order {
    return std.mem.order(u8, &target, &item.id);
}

fn entryScope(entry: shared.types.IgnoreEntry) error{InvalidBanListEntry}!effects.Scope {
    const width: u8 = if (entry.family == .v4) 32 else 128;
    const subject = if (entry.prefix == width)
        canonical_scope.Subject.host(entry.network())
    else
        canonical_scope.Subject.network(entry.network(), entry.prefix) catch return error.InvalidBanListEntry;
    const scope = effects.Scope.exact(.{ .subject = subject }) catch return error.InvalidBanListEntry;
    scope.validate() catch return error.InvalidBanListEntry;
    return scope;
}

pub fn Methods(comptime Store: type) type {
    return struct {
        pub fn applyBanList(self: *Store, jail: []const u8, generation: [32]u8, entries: []const ban_origin.BanListEntry, now_us: i64, clock: effects.Clock) BanListError!BanListChange {
            _ = detection.Name.init(jail) catch return error.InvalidBanListEntry;
            const timed = try self.allocator.alloc(shared.types.TimedEntry, entries.len);
            defer self.allocator.free(timed);
            const deadlines = try self.allocator.alloc(?i64, entries.len);
            defer self.allocator.free(deadlines);
            const ids = try self.allocator.alloc(IndexedId, entries.len);
            defer self.allocator.free(ids);
            for (entries, 0..) |item, index| {
                if (!std.mem.eql(u8, item.jail, jail)) return error.InvalidBanListEntry;
                if (item.duration_s) |seconds| if (seconds < 1 or seconds > shared.types.TimedEntry.max_duration_s) return error.InvalidBanListEntry;
                timed[index] = .{ .entry = item.entry, .duration_s = item.duration_s };
                ids[index] = .{ .id = item.decisionId(), .index = index };
            }
            std.mem.sort(IndexedId, ids, {}, indexedLess);

            try self.beginWrite();
            errdefer self.rollback();
            try self.effectSchema();
            if (self.schema_version < origin_schema) return error.EffectStorageRequired;
            const installation = try self.readInstallation() orelse return error.InstallationRequired;
            const now = try self.effectClock(clock);
            const prior_revision = try self.integer("SELECT revision FROM effect_clock WHERE singleton=1;");
            try self.applyConfigDeadlines(.banip, jail, timed, now_us, deadlines);
            const current_us = @max(now_us, now);
            var change = BanListChange{};
            var earliest_deadline: ?i64 = null;
            for (entries, 0..) |item, index| {
                const decision_id = item.decisionId();
                const first = std.sort.binarySearch(IndexedId, ids, decision_id, idOrder) orelse return error.InvalidBanListEntry;
                var lowest = first;
                while (lowest > 0 and std.mem.eql(u8, &ids[lowest - 1].id, &decision_id)) lowest -= 1;
                // Why: Only the first entry carrying a decision id is applied; later entries with the same id are skipped.
                if (ids[lowest].index != index) continue;
                const scope = try entryScope(item.entry);
                const key = try scope.key(installation);
                const current = try self.jailOwner(key, jail);
                const desired: effects.Lease = if (deadlines[index]) |deadline| .{ .finite = deadline } else .permanent;
                const held = if (current) |owner| owner.origin == .config and std.mem.eql(u8, &owner.decision_id, &decision_id) else false;
                if (desired == .finite and desired.finite <= current_us) {
                    change.expired += 1;
                    if (held and current.?.lease != .absent)
                        try self.releaseConfigOwnerTx(jail, .{ .scope = scope.canonical, .generation = current.?.generation, .revision = current.?.revision }, decision_id, now);
                    continue;
                }
                if (held and effects.Lease.eql(current.?.lease, desired)) {
                    change.unchanged += 1;
                    continue;
                }
                self.admitIntake(budget.ban_pages) catch |failure| switch (failure) {
                    error.StorageCapacity => {
                        change.pending += 1;
                        continue;
                    },
                    else => return failure,
                };
                _ = try self.setOwnerTx(.{
                    .scope = scope,
                    .jail = jail,
                    .generation = generation,
                    .decision_id = decision_id,
                    .expected_revision = if (current) |owner| owner.revision else 0,
                    .lease = desired,
                    .decided_us = now,
                    .origin = .config,
                }, now);
                change.added += 1;
                if (desired == .finite) earliest_deadline = @min(earliest_deadline orelse desired.finite, desired.finite);
            }
            var stale = std.ArrayListUnmanaged(StaleOwner){};
            defer stale.deinit(self.allocator);
            {
                var row = try self.statement("SELECT n.canonical_scope,o.decision_id,o.revision,o.generation FROM effect_owners o JOIN native_effects n USING(scope_key) WHERE o.jail=?1 AND o.origin=3 AND o.lease_kind<>0 ORDER BY o.scope_key;");
                defer row.deinit();
                try row.text(1, jail);
                while (try row.row()) {
                    const decision_id = try Store.effectBlob(&row, 1, 32);
                    if (std.sort.binarySearch(IndexedId, ids, decision_id, idOrder) != null) continue;
                    const scope = try self.decodeStoredScope(&row, 0);
                    const revision = try row.signed(2);
                    if (revision <= 0) return error.InvalidEffect;
                    try stale.append(
                        self.allocator,
                        .{ .owner = .{ .scope = scope.canonical, .generation = try Store.effectBlob(&row, 3, 32), .revision = @intCast(revision) }, .decision_id = decision_id },
                    );
                }
            }
            for (stale.items) |item| {
                try self.releaseConfigOwnerTx(jail, item.owner, item.decision_id, now);
                change.lifted += 1;
            }
            const changed = prior_revision != try self.integer("SELECT revision FROM effect_clock WHERE singleton=1;");
            const final = try self.commitEffectClock(clock);
            if (earliest_deadline) |deadline| if (deadline <= final) return error.EffectExpired;
            try self.commitEffectTransaction(changed);
            return change;
        }

        fn jailOwner(self: *Store, key: effects.Hash, jail: []const u8) Error!?effects.Owner {
            var owners: [effects.max_page]effects.Owner = undefined;
            const count = try self.readOwners(key, &owners);
            for (owners[0..count]) |owner| if (std.mem.eql(u8, owner.jail.slice(), jail)) return owner;
            return null;
        }

        fn releaseConfigOwnerTx(self: *Store, jail: []const u8, owner: ConfigOwner, decision_id: effects.Hash, now: i64) Error!void {
            var revision: [8]u8 = undefined;
            std.mem.writeInt(u64, &revision, owner.revision, .little);
            _ = try self.transitionOwnerTx(.{
                .scope = owner.scope,
                .jail = jail,
                .current_generation = owner.generation,
                .next_generation = owner.generation,
                .expected_owner_revision = owner.revision,
                .transition_id = effects.hashParts("fail2zig-banip-release-v1", &.{ jail, &decision_id, &revision }),
                .mode = .release,
                .occurred_us = now,
            }, now);
        }

        pub fn originForScope(self: *Store, key: [32]u8, jail: []const u8) Error!?OwnerOrigin {
            try self.beginRead();
            errdefer self.rollback();
            var row = try self.statement(self.originSql("SELECT ", "origin", ",revision,decision_id FROM effect_owners WHERE scope_key=?1 AND jail=?2 AND lease_kind<>0;"));
            defer row.deinit();
            try row.blob(1, &key);
            try row.text(2, jail);
            if (!try row.row()) {
                try self.commitTransaction();
                return null;
            }
            const revision = try row.signed(1);
            if (revision <= 0) return error.InvalidEffect;
            const result = OwnerOrigin{ .origin = try Store.storedOrigin(&row, 0), .revision = @intCast(revision), .decision_id = try Store.effectBlob(&row, 2, 32) };
            try self.commitTransaction();
            return result;
        }
    };
}
