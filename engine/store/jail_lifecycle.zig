// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const effects = @import("../core/native_effect.zig");
const store = @import("store.zig");
const Error = store.Error;

const retirement_deletes = [_][:0]const u8{
    "DELETE FROM retry_retired WHERE jail=?1;",
    "DELETE FROM retry_retired_totals WHERE jail=?1;",
    "DELETE FROM retry_states WHERE jail=?1;",
    "DELETE FROM retry_escalation_policies WHERE jail=?1;",
    "DELETE FROM confirmed_policy_summaries WHERE jail=?1;",
    "DELETE FROM retry_policies WHERE jail=?1;",
    "DELETE FROM checkpoints WHERE jail=?1;",
    "DELETE FROM source_cursors WHERE jail=?1;",
    "DELETE FROM pending_receipts WHERE jail=?1;",
    "DELETE FROM config_timed_entries WHERE jail=?1;",
};

const manifest_deletes = [_][:0]const u8{
    "DELETE FROM consumer_requirements WHERE manifest_jail=?1;",
    "DELETE FROM consumer_manifests WHERE jail=?1;",
    "DELETE FROM consumer_checkpoints WHERE jail=?1 AND NOT EXISTS(SELECT 1 FROM consumer_requirements r WHERE r.kind=consumer_checkpoints.kind AND r.jail=consumer_checkpoints.jail AND r.source=consumer_checkpoints.source AND r.rule=consumer_checkpoints.rule AND r.generation=consumer_checkpoints.generation AND r.format=consumer_checkpoints.format);",
};

pub const JailRetirement = struct {
    bans_lifted: u32,
    owners_released: u32,
};

pub fn Methods(comptime Store: type) type {
    return struct {
        pub fn retireJail(self: *Store, jail: []const u8, now_us: i64, clock: effects.Clock) Error!JailRetirement {
            if (jail.len == 0 or jail.len > 64 or std.mem.indexOfScalar(u8, jail, 0) != null) return error.InvalidEffect;
            try self.beginWrite();
            errdefer self.rollback();
            try self.effectSchema();
            const now = try self.effectClock(clock);
            if (now_us > now) return error.InvalidEffect;
            var outcome: JailRetirement = .{ .bans_lifted = 0, .owners_released = 0 };
            while (try self.releaseNextJailOwner(jail, now_us, now)) |entry| {
                outcome.owners_released = std.math.add(u32, outcome.owners_released, 1) catch return error.EffectCapacity;
                if (entry.desired == .absent) outcome.bans_lifted = std.math.add(u32, outcome.bans_lifted, 1) catch return error.EffectCapacity;
            }
            for (retirement_deletes) |sql| try self.deleteJailRows(sql, jail);
            self.deletedRows(.retry_states);
            var manifests_removed: c_int = 0;
            for (manifest_deletes, 0..) |sql, index| {
                try self.deleteJailRows(sql, jail);
                if (index == 1) manifests_removed = self.api.changes(self.db);
            }
            if (manifests_removed != 0) {
                if (try self.consumerRevision() == std.math.maxInt(i64)) return error.ConsumerCapacity;
                try self.exec("UPDATE consumer_revision SET revision=revision+1 WHERE id=1;");
                if (self.api.changes(self.db) != 1) return error.InvalidConsumer;
            }
            _ = try self.commitEffectClock(clock);
            try self.commitEffectTransaction(outcome.owners_released != 0);
            return outcome;
        }
        fn releaseNextJailOwner(self: *Store, jail: []const u8, occurred_us: i64, now: i64) Error!?effects.Entry {
            var scope: effects.Scope = undefined;
            var scope_key: effects.Hash = undefined;
            var generation: effects.Hash = undefined;
            var owner_revision: u64 = undefined;
            {
                var row = try self.statement("SELECT n.canonical_scope,o.revision,o.generation,o.scope_key FROM effect_owners o JOIN native_effects n USING(scope_key) WHERE o.jail=?1 AND o.lease_kind<>0 ORDER BY o.scope_key LIMIT 1;");
                defer row.deinit();
                try row.text(1, jail);
                if (!try row.row()) return null;
                scope = try effects.Scope.decodeCanonical(&try Store.effectBlob(&row, 0, effects.Scope.canonical_encoded_bytes));
                const revision_value = try row.signed(1);
                if (revision_value <= 0) return error.InvalidEffect;
                owner_revision = @intCast(revision_value);
                generation = try Store.effectBlob(&row, 2, 32);
                scope_key = try Store.effectBlob(&row, 3, 32);
            }
            var revision_bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &revision_bytes, owner_revision, .little);
            const transition_id = effects.hashParts("fail2zig-jail-retire-v1", &.{ jail, &scope_key, &revision_bytes });
            const result = try self.transitionOwnerTx(.{ .scope = scope.canonical, .jail = jail, .current_generation = generation, .next_generation = generation, .expected_owner_revision = owner_revision, .transition_id = transition_id, .mode = .release, .occurred_us = occurred_us }, now);
            if (!result.changed) return error.InvalidEffect;
            return result.entry;
        }
        fn deleteJailRows(self: *Store, sql: [:0]const u8, jail: []const u8) Error!void {
            var row = try self.statement(sql);
            defer row.deinit();
            try row.text(1, jail);
            try row.done();
        }
        pub fn unconfiguredJails(self: *Store, configured: []const []const u8, out: [][64]u8) Error!usize {
            try self.beginRead();
            errdefer self.rollback();
            var count: usize = 0;
            {
                var row = try self.statement("SELECT jail FROM retry_policies UNION SELECT jail FROM effect_owners WHERE lease_kind<>0 ORDER BY jail;");
                defer row.deinit();
                while (try row.row()) {
                    const jail = try row.boundedBytes(0, 64);
                    for (configured) |name| {
                        if (std.mem.eql(u8, name, jail)) break;
                    } else {
                        if (count == out.len) return error.StorageLimit;
                        out[count] = [_]u8{0} ** 64;
                        @memcpy(out[count][0..jail.len], jail);
                        count += 1;
                    }
                }
            }
            try self.commitTransaction();
            return count;
        }
    };
}
