// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Pages through native effects to find, and optionally repair, intents marked absent by evidence dispatched before them.
// Holds: A repair commits only if each update and delete touches exactly one row and the effect then reads back equal to its entry.

const std = @import("std");
const store = @import("store.zig");
const effects = @import("../effect/effect.zig");
const Error = store.Error;
const observation_limit: usize = @intCast(store.load_repair.observations_per_intent);

pub fn Methods(comptime Store: type) type {
    return struct {
        pub const EffectEvidencePage = struct {
            after: ?effects.Hash = null,
            done: bool = false,
            examined: u16 = 0,
            eligible: u16 = 0,
            repaired: u16 = 0,
        };
        const Candidate = struct {
            entry: effects.Entry,
            stamp: i64,
            fingerprint: effects.Hash,
            observations: [observation_limit]effects.Hash = undefined,
            count: usize = 0,
        };

        fn effectEvidenceCandidate(self: *Store, key: effects.Hash, installation: effects.Installation) Error!?Candidate {
            if (self.readEffect(key, installation)) |entry| {
                if (entry == null) return error.StaleEffect;
                return null;
            } else |failure| if (failure != error.InvalidEffect) return failure;
            var candidate: Candidate = undefined;
            const floor = blk: {
                var row = try self.statement("SELECT i.status,i.created_us,i.dispatch_us,i.observed_us,i.fingerprint,c.floor_us FROM native_effects n JOIN effect_intents i ON i.intent_id=n.intent_id CROSS JOIN effect_clock c WHERE n.scope_key=?1 AND c.singleton=1;");
                defer row.deinit();
                try row.blob(1, &key);
                if (!try row.row() or try row.signed(0) != @intFromEnum(effects.Status.absent)) return error.InvalidEffect;
                const created = try row.signed(1);
                candidate.stamp = try row.signed(2);
                if (try row.signed(3) != candidate.stamp or candidate.stamp >= created) return error.InvalidEffect;
                candidate.fingerprint = try Store.effectBlob(&row, 4, 32);
                break :blk try row.signed(5);
            };
            {
                var row = try self.statement("SELECT n.scope_key,n.canonical_scope,n.revision,n.lease_kind,n.deadline_us,n.intent_id,1,i.decision_id,i.revision,i.lease_kind,i.deadline_us,i.created_us,NULL,NULL,NULL FROM native_effects n JOIN effect_intents i ON i.intent_id=n.intent_id WHERE n.scope_key=?1;");
                defer row.deinit();
                try row.blob(1, &key);
                if (!try row.row()) return error.StaleEffect;
                candidate.entry = try self.decodeEffect(&row, installation);
                if (candidate.entry.desired != .absent) return error.InvalidEffect;
            }
            candidate.count = 0;
            var matched = false;
            var rows = try self.statement("SELECT observation_id,dispatch_us,observed_us,fingerprint,state_kind,deadline_us,outcome FROM effect_observations INDEXED BY effect_observations_intent WHERE intent_id=?1 ORDER BY rowid LIMIT ?2;");
            defer rows.deinit();
            try rows.blob(1, &candidate.entry.intent_id);
            try rows.int(2, observation_limit + 1);
            var examined: usize = 0;
            while (try rows.row()) {
                examined += 1;
                if (examined > observation_limit) return error.InvalidEffect;
                const id = try Store.effectBlob(&rows, 0, 32);
                const dispatched = try rows.signed(1);
                const observed = try rows.signed(2);
                const fingerprint = try Store.effectBlob(&rows, 3, 32);
                const state: ?effects.Lease = if (try rows.signed(4) == 3) blk: {
                    if (self.api.column_type(rows.ptr, 5) != 5) return error.InvalidEffect;
                    break :blk null;
                } else try Store.effectLease(&rows, 4, 5);
                const status = std.meta.intToEnum(effects.Status, try rows.signed(6)) catch return error.InvalidEffect;
                const expected: effects.Status = if (state != null and state.? == .absent) .absent else .pending;
                if (status != expected or observed < dispatched or observed > floor) return error.InvalidEffect;
                const expected_id = Store.effectObservationId(candidate.entry.intent_id, dispatched, observed, fingerprint, state, status);
                if (!std.mem.eql(u8, &id, &expected_id)) return error.InvalidEffect;
                if (dispatched >= candidate.entry.intent_us) continue;
                if (dispatched != observed or status != .absent) return error.InvalidEffect;
                candidate.observations[candidate.count] = id;
                candidate.count += 1;
                if (observed == candidate.stamp and std.mem.eql(u8, &fingerprint, &candidate.fingerprint)) matched = true;
            }
            if (!matched) return error.InvalidEffect;
            return candidate;
        }

        pub fn effectEvidencePage(self: *Store, after: ?effects.Hash, repair: bool, clock: effects.Clock) Error!EffectEvidencePage {
            if (self.schema_version != store.latest_schema) return error.UnsupportedSchema;
            if (repair) try self.beginWrite() else try self.beginRead();
            errdefer self.rollback();
            if (repair) _ = try self.effectClock(clock);
            var keys: [Store.attribution_batch]effects.Hash = undefined;
            var count: usize = 0;
            {
                var rows = try self.statement(if (after != null)
                    "SELECT scope_key FROM native_effects WHERE scope_key>?1 ORDER BY scope_key LIMIT ?2;"
                else
                    "SELECT scope_key FROM native_effects ORDER BY scope_key LIMIT ?2;");
                defer rows.deinit();
                if (after) |*key| try rows.blob(1, key);
                try rows.int(2, keys.len);
                while (try rows.row()) {
                    keys[count] = try Store.effectBlob(&rows, 0, 32);
                    count += 1;
                }
            }
            var result = EffectEvidencePage{ .after = if (count == 0) after else keys[count - 1], .done = count < keys.len, .examined = @intCast(count) };
            if (count != 0) {
                const installation = try self.readInstallation() orelse return error.InstallationRequired;
                for (keys[0..count]) |key| {
                    const candidate = try self.effectEvidenceCandidate(key, installation) orelse continue;
                    result.eligible += 1;
                    if (!repair) continue;
                    {
                        var row = try self.statement("UPDATE effect_intents SET status=1,dispatch_us=NULL,observed_us=NULL,fingerprint=NULL WHERE intent_id=?1 AND status=4 AND dispatch_us=?2 AND observed_us=?2 AND fingerprint=?3 AND created_us>?2;");
                        defer row.deinit();
                        try row.blob(1, &candidate.entry.intent_id);
                        try row.int(2, candidate.stamp);
                        try row.blob(3, &candidate.fingerprint);
                        try row.done();
                        if (self.api.changes(self.db) != 1) return error.StaleEffect;
                    }
                    for (candidate.observations[0..candidate.count]) |id| {
                        var row = try self.statement("DELETE FROM effect_observations WHERE observation_id=?1 AND intent_id=?2;");
                        defer row.deinit();
                        try row.blob(1, &id);
                        try row.blob(2, &candidate.entry.intent_id);
                        try row.done();
                        if (self.api.changes(self.db) != 1) return error.StaleEffect;
                        self.removedRows(.effect_observations, 1);
                    }
                    const repaired = try self.readEffect(key, installation) orelse return error.InvalidEffect;
                    if (!std.meta.eql(repaired, candidate.entry)) return error.InvalidEffect;
                    self.noteEffectChange(key);
                    result.repaired += 1;
                }
            }
            if (result.repaired != 0) {
                try self.advanceEffectSnapshot();
                try self.fault(.before_effect_receipt_commit);
                _ = try self.commitEffectClock(clock);
                try self.commitEffectTransaction(true);
            } else try self.commitTransaction();
            return result;
        }
    };
}
