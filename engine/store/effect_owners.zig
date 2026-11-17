// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Changes effect ownership: replaces a scope's intent, sets and transitions jail owners and releases a disabled jail's scopes.
// Holds: An owner change on a scope whose intent is still awaiting dispatch reconciliation is refused before anything is written.

const std = @import("std");
const effects = @import("../effect/effect.zig");
const detection = @import("../detect/detection_record.zig");
const store = @import("store.zig");
const budget = @import("budget.zig");
const Error = store.Error;
const origin_schema = @import("effects.zig").origin_schema;

pub fn Methods(comptime Store: type) type {
    return struct {
        const effectBlob = Store.effectBlob;
        const bindEffectLease = Store.bindEffectLease;
        const observations_per_intent = Store.observations_per_intent;
        pub fn retireOwnerDecisionTx(self: *Store, key: effects.Hash, jail: []const u8, replaced: ?effects.Hash, now: i64) Error!void {
            if (self.schema_version < store.load_repair_schema) return;
            var marker = try self.statement("DELETE FROM confirmation_markers WHERE scope_key=?1 AND jail=?2;");
            defer marker.deinit();
            try marker.blob(1, &key);
            try marker.text(2, jail);
            try marker.done();
            const decision = replaced orelse return;
            var targets = try self.statement("UPDATE action_targets SET status=7,settled_us=max(coalesce(dispatch_us,intent_us),?4) WHERE action_id=?1 AND scope_key=?2 AND jail=?3 AND status IN(1,2,5);");
            defer targets.deinit();
            try targets.blob(1, &decision);
            try targets.blob(2, &key);
            try targets.text(3, jail);
            try targets.int(4, now);
            try targets.done();
        }
        pub fn replaceEffectIntent(self: *Store, installation: effects.Installation, scope: effects.Scope, key: effects.Hash, effect_revision: u64, decision_id: effects.Hash, now: i64) Error!effects.Entry {
            var owners: [effects.max_page]effects.Owner = undefined;
            const count = try self.readOwners(key, &owners);
            var lease: effects.Lease = .absent;
            for (owners[0..count]) |owner| switch (owner.lease) {
                .absent => {},
                .permanent => lease = .permanent,
                .finite => |deadline| if (deadline > now and lease != .permanent and (lease == .absent or deadline > lease.finite)) {
                    lease = .{ .finite = deadline };
                },
            };
            const id = effects.intentId(installation.id, key, decision_id, effect_revision, lease);
            if (try self.tableRows(.effect_intents) >= effects.max_intents) return error.EffectCapacity;
            {
                var old = try self.statement("UPDATE effect_intents SET status=CASE WHEN lease_kind=1 AND deadline_us<=?2 THEN 6 ELSE 5 END WHERE scope_key=?1 AND status=1;");
                defer old.deinit();
                try old.blob(1, &key);
                try old.int(2, now);
                try old.done();
                var intent = try self.statement("INSERT INTO effect_intents(intent_id,scope_key,revision,decision_id,lease_kind,deadline_us,status,created_us) VALUES(?1,?2,?3,?4,?5,?6,1,?7);");
                defer intent.deinit();
                try intent.blob(1, &id);
                try intent.blob(2, &key);
                try intent.int(3, @intCast(effect_revision));
                try intent.blob(4, &decision_id);
                try bindEffectLease(&intent, 5, lease);
                try intent.int(7, now);
                try intent.done();
                self.insertedRows(.effect_intents, 1);
                var aggregate = try self.statement("UPDATE native_effects SET revision=?2,lease_kind=?3,deadline_us=?4,intent_id=?5 WHERE scope_key=?1;");
                defer aggregate.deinit();
                try aggregate.blob(1, &key);
                try aggregate.int(2, @intCast(effect_revision));
                try bindEffectLease(&aggregate, 3, lease);
                try aggregate.blob(5, &id);
                try aggregate.done();
                if (self.api.changes(self.db) != 1) return error.InvalidEffect;
            }
            try self.advanceEffectSnapshot();
            try self.fault(.after_effect_intent);
            self.noteEffectChange(key);
            if (self.effect_invalidation) |hook| if (hook.retirement_pending) |notify| notify(hook.context, key, owners[0..count], lease);
            return .{ .installation = installation, .scope = scope, .scope_key = key, .revision = effect_revision, .desired = lease, .intent_id = id, .status = .pending, .intent_us = now };
        }
        pub fn setOwnerTx(self: *Store, change: effects.OwnerChange, now: i64) Error!effects.Entry {
            return self.setOwnerReservedTx(change, now, 0);
        }
        pub fn setOwnerReservedTx(self: *Store, change: effects.OwnerChange, now: i64, targets: i64) Error!effects.Entry {
            const jail = detection.Name.init(change.jail) catch return error.InvalidEffect;
            if (change.expected_revision >= std.math.maxInt(i64) or change.decided_us > now or (change.lease == .finite and change.lease.finite <= change.decided_us)) return error.InvalidEffect;
            if (change.lease != .absent and !change.lease.live(now)) return error.EffectExpired;
            const installation = try self.readInstallation() orelse return error.InstallationRequired;
            if (self.schema_version < 19) _ = try change.scope.encode();
            const key = try change.scope.key(installation);
            const previous = try self.readEffect(key, installation);
            if (previous) |entry| if (entry.status == .dispatched) return error.EffectReconciliationRequired;
            var owners: [effects.max_page]effects.Owner = undefined;
            const count = try self.readOwners(key, &owners);
            var owner_revision: u64 = 0;
            var replaced: ?effects.Owner = null;
            for (owners[0..count]) |owner| if (std.mem.eql(u8, owner.jail.slice(), jail.slice())) {
                owner_revision = owner.revision;
                if (!std.mem.eql(u8, &owner.generation, &change.generation)) {
                    if (owner.lease != .absent or change.lease == .absent) return error.EffectGenerationMismatch;
                    const admission = try self.readRetryPolicy(change.jail) orelse return error.EffectGenerationMismatch;
                    if (!std.mem.eql(u8, &admission.generation, &change.generation)) return error.EffectGenerationMismatch;
                    if (self.schema_version >= 28 and try self.jailRetirement(change.jail) != null) return error.EffectGenerationMismatch;
                }
                if (std.mem.eql(u8, &owner.decision_id, &change.decision_id)) {
                    const replay = effects.Lease.eql(owner.lease, change.lease) and owner.decided_us == change.decided_us and owner.origin == change.origin;
                    if (replay) return previous orelse error.InvalidEffect;
                    if (change.origin != .config or owner.origin != .config) return error.InvalidEffect;
                }
                replaced = owner;
            };
            if (owner_revision != change.expected_revision) return error.StaleEffect;
            const was_live = if (replaced) |owner| owner.lease != .absent else false;
            const is_live = change.lease != .absent;
            const retired_markers: i64 = if (replaced != null and self.schema_version >= store.load_repair_schema) blk: {
                var marker = try self.statement("SELECT count(*) FROM confirmation_markers WHERE scope_key=?1 AND jail=?2;");
                defer marker.deinit();
                try marker.blob(1, &key);
                try marker.text(2, change.jail);
                if (!try marker.row()) return error.InvalidEffect;
                break :blk try marker.signed(0);
            } else 0;
            try self.reserveEffectRows(.{
                .owners = @intFromBool(replaced == null),
                .effects = @intFromBool(previous == null),
                .revisions = 1,
                .intents = 1,
                .observations = observations_per_intent,
                .targets = targets,
                .live_owners = @as(i64, @intFromBool(is_live)) - @intFromBool(was_live),
                .retired_markers = retired_markers,
            });
            if (try self.tableRows(.effect_owner_revisions) >= effects.max_owner_revisions) return error.EffectCapacity;
            if (owner_revision == 0) {
                if (count == effects.max_page or try self.tableRows(.effect_owners) >= effects.max_owners) return error.EffectCapacity;
            }
            const effect_revision = if (previous) |entry| std.math.add(u64, entry.revision, 1) catch return error.EffectCapacity else 1;
            if (effect_revision > std.math.maxInt(i64)) return error.EffectCapacity;
            if (previous == null) {
                if (try self.tableRows(.native_effects) >= effects.max_effects) return error.EffectCapacity;
                const legacy_wire = change.scope.encode() catch [_]u8{0} ** effects.Scope.encoded_bytes;
                const canonical_wire = try change.scope.encodeCanonical();
                var row = try self.statement(if (self.schema_version >= 19)
                    "INSERT INTO native_effects(scope_key,scope,revision,lease_kind,canonical_scope) VALUES(?1,?2,0,0,?3);"
                else
                    "INSERT INTO native_effects(scope_key,scope,revision,lease_kind) VALUES(?1,?2,0,0);");
                defer row.deinit();
                try row.blob(1, &key);
                try row.blob(2, &legacy_wire);
                if (self.schema_version >= 19) try row.blob(3, &canonical_wire);
                try row.done();
                self.insertedRows(.native_effects, 1);
            }
            if (replaced) |owner| try self.retireOwnerDecisionTx(key, change.jail, owner.decision_id, now);
            {
                var owner = try self.statement(if (self.schema_version >= origin_schema)
                    "INSERT INTO effect_owners(scope_key,jail,generation,decision_id,revision,lease_kind,deadline_us,decided_us,origin) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT(scope_key,jail) DO UPDATE SET generation=excluded.generation,decision_id=excluded.decision_id,revision=excluded.revision,lease_kind=excluded.lease_kind,deadline_us=excluded.deadline_us,decided_us=excluded.decided_us,origin=excluded.origin;"
                else
                    "INSERT INTO effect_owners(scope_key,jail,generation,decision_id,revision,lease_kind,deadline_us,decided_us) VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(scope_key,jail) DO UPDATE SET generation=excluded.generation,decision_id=excluded.decision_id,revision=excluded.revision,lease_kind=excluded.lease_kind,deadline_us=excluded.deadline_us,decided_us=excluded.decided_us;");
                defer owner.deinit();
                try owner.blob(1, &key);
                try owner.text(2, change.jail);
                try owner.blob(3, &change.generation);
                try owner.blob(4, &change.decision_id);
                try owner.int(5, @intCast(owner_revision + 1));
                try bindEffectLease(&owner, 6, change.lease);
                try owner.int(8, change.decided_us);
                if (self.schema_version >= origin_schema) {
                    try owner.int(9, @intFromEnum(change.origin));
                } else if (change.origin != .detection) return error.EffectStorageRequired;
                try owner.done();
                if (replaced == null) self.insertedRows(.effect_owners, 1);
                // Why: The effect_owner_insert and effect_owner_update triggers each add one revision row, on insert and on update alike.
                self.insertedRows(.effect_owner_revisions, 1);
            }
            try self.fault(.after_effect_owner);
            return self.replaceEffectIntent(installation, change.scope, key, effect_revision, change.decision_id, now);
        }
        pub fn setOwner(self: *Store, change: effects.OwnerChange, clock: effects.Clock) Error!effects.Entry {
            try self.beginIntakeWrite(budget.ban_pages);
            errdefer self.rollback();
            try self.effectSchema();
            const now = try self.effectClock(clock);
            const prior_revision = try self.integer("SELECT revision FROM effect_clock WHERE singleton=1;");
            const entry = try self.setOwnerTx(change, now);
            const changed = prior_revision != try self.integer("SELECT revision FROM effect_clock WHERE singleton=1;");
            const final = try self.commitEffectClock(clock);
            if (change.lease == .finite and !change.lease.live(final)) return error.EffectExpired;
            if (entry.desired == .finite and !entry.desired.live(final)) return error.EffectExpired;
            try self.commitEffectTransaction(changed);
            return entry;
        }
        pub fn setOwnerFromCanonical(self: *Store, change: effects.CanonicalOwnerChange, clock: effects.Clock) Error!effects.Entry {
            change.scope.validate() catch return error.InvalidEffect;
            const projected = if (self.schema_version >= 19) try change.exact() else try change.legacy();
            return self.setOwner(projected, clock);
        }
        const OwnerTransitionTx = struct { entry: effects.Entry, changed: bool };
        pub fn transitionOwnerTx(self: *Store, change: effects.OwnerTransition, now: i64) Error!OwnerTransitionTx {
            return self.transitionOwnerReservedTx(change, now, true);
        }
        pub fn transitionOwnerReservedTx(self: *Store, change: effects.OwnerTransition, now: i64, reserve: bool) Error!OwnerTransitionTx {
            change.scope.validate() catch return error.InvalidEffect;
            _ = detection.Name.init(change.jail) catch return error.InvalidEffect;
            if (change.expected_owner_revision == 0 or change.expected_owner_revision >= std.math.maxInt(i64) or change.occurred_us > now or std.mem.allEqual(
                u8,
                &change.transition_id,
                0,
            )) return error.InvalidEffect;
            if (change.mode == .retain and std.mem.eql(u8, &change.current_generation, &change.next_generation)) return error.InvalidEffect;
            const installation = try self.readInstallation() orelse return error.InstallationRequired;
            const scope = try effects.Scope.exact(change.scope);
            const key = try scope.key(installation);
            const prior = try self.readEffect(key, installation) orelse return error.StaleEffect;
            if (prior.status == .dispatched) return error.EffectReconciliationRequired;
            var owners: [effects.max_page]effects.Owner = undefined;
            const count = try self.readOwners(key, &owners);
            var selected: ?effects.Owner = null;
            for (owners[0..count]) |owner| if (std.mem.eql(u8, owner.jail.slice(), change.jail)) {
                if (selected != null) return error.InvalidEffect;
                selected = owner;
            };
            const owner = selected orelse return error.StaleEffect;
            if (owner.revision == change.expected_owner_revision + 1 and std.mem.eql(u8, &owner.generation, &change.next_generation)) {
                const wanted_lease: effects.Lease = if (change.mode == .release) .absent else owner.lease;
                const replay_id = effects.intentId(installation.id, key, change.transition_id, prior.revision, prior.desired);
                if (effects.Lease.eql(owner.lease, wanted_lease) and std.mem.eql(u8, &prior.intent_id, &replay_id)) return .{ .entry = prior, .changed = false };
            }
            if (owner.revision != change.expected_owner_revision) return error.StaleEffect;
            if (!std.mem.eql(u8, &owner.generation, &change.current_generation)) return error.EffectGenerationMismatch;
            if (owner.lease == .absent) return error.StaleEffect;
            switch (change.mode) {
                .retain => if (reserve) try self.reserveEffectRows(.{ .revisions = 1, .intents = 1, .observations = observations_per_intent }),
                .release => {
                    try self.retireOwnerDecisionTx(key, change.jail, null, now);
                    try self.closeRetryDecisionsTx(change.jail, change.scope, now);
                },
            }
            if (try self.tableRows(.effect_owner_revisions) >= effects.max_owner_revisions) return error.EffectCapacity;
            const effect_revision = std.math.add(u64, prior.revision, 1) catch return error.EffectCapacity;
            if (effect_revision > std.math.maxInt(i64)) return error.EffectCapacity;
            {
                var update = try self.statement("UPDATE effect_owners SET generation=?4,revision=?5,lease_kind=?6,deadline_us=?7 WHERE scope_key=?1 AND jail=?2 AND revision=?3;");
                defer update.deinit();
                try update.blob(1, &key);
                try update.text(2, change.jail);
                try update.int(3, @intCast(owner.revision));
                try update.blob(4, &change.next_generation);
                try update.int(5, @intCast(owner.revision + 1));
                try bindEffectLease(&update, 6, if (change.mode == .release) .absent else owner.lease);
                try update.done();
                if (self.api.changes(self.db) != 1) return error.StaleEffect;
                self.insertedRows(.effect_owner_revisions, 1);
            }
            try self.fault(.after_effect_owner);
            return .{ .entry = try self.replaceEffectIntent(installation, scope, key, effect_revision, change.transition_id, now), .changed = true };
        }
        pub fn transitionOwner(self: *Store, change: effects.OwnerTransition, clock: effects.Clock) Error!effects.Entry {
            try self.beginWrite();
            errdefer self.rollback();
            try self.effectSchema();
            if (self.schema_version < 19) return error.EffectStorageRequired;
            const now = try self.effectClock(clock);
            const result = try self.transitionOwnerTx(change, now);
            _ = try self.commitEffectClock(clock);
            try self.commitEffectTransaction(result.changed);
            return result.entry;
        }
        pub const jail_disable_page_rows: usize = 64;
        pub const JailDisablePage = struct { after: ?effects.Hash, examined: u8, released: u8, done: bool };

        pub fn releaseDisabledJailPage(self: *Store, jail: []const u8, request_id: effects.Hash, after: ?effects.Hash, clock: effects.Clock) Error!JailDisablePage {
            _ = detection.Name.init(jail) catch return error.InvalidEffect;
            if (std.mem.allEqual(u8, &request_id, 0)) return error.InvalidAdminRequest;
            try self.beginWrite();
            errdefer self.rollback();
            try self.effectSchema();
            if (self.schema_version < 22) return error.AdminStorageRequired;
            var state: Store.JailAdminState = undefined;
            if (!try self.jailAdminState(jail, &state) or state.enabled or !std.mem.eql(u8, &state.request_id, &request_id)) return error.StaleAdminRevision;
            const now = try self.effectClock(clock);
            const Held = struct { key: effects.Hash, generation: effects.Hash, revision: u64, absent: bool };
            var held: [jail_disable_page_rows]Held = undefined;
            var count: usize = 0;
            {
                // Why: Absent owners and every generation are selected so LIMIT 64 bounds the rows examined, not only the rows released.
                var rows = try self.statement(if (after != null)
                    "SELECT scope_key,generation,revision,lease_kind,deadline_us FROM effect_owners INDEXED BY effect_owners_jail WHERE jail=?1 AND scope_key>?2 ORDER BY scope_key LIMIT 64;"
                else
                    "SELECT scope_key,generation,revision,lease_kind,deadline_us FROM effect_owners INDEXED BY effect_owners_jail WHERE jail=?1 ORDER BY scope_key LIMIT 64;");
                defer rows.deinit();
                try rows.text(1, jail);
                if (after) |*key| try rows.blob(2, key);
                while (try rows.row()) {
                    const revision = try rows.signed(2);
                    if (revision <= 0) return error.InvalidEffect;
                    held[count] = .{
                        .key = try effectBlob(&rows, 0, 32),
                        .generation = try effectBlob(&rows, 1, 32),
                        .revision = @intCast(revision),
                        .absent = (try Store.effectLease(&rows, 3, 4)) == .absent,
                    };
                    count += 1;
                }
            }
            var released: u8 = 0;
            for (held[0..count]) |owner| {
                if (owner.absent) continue;
                const scope = blk: {
                    var row = try self.statement("SELECT canonical_scope FROM native_effects WHERE scope_key=?1;");
                    defer row.deinit();
                    try row.blob(1, &owner.key);
                    if (!try row.row()) return error.InvalidEffect;
                    break :blk try effects.Scope.decodeCanonical(&try effectBlob(&row, 0, effects.Scope.canonical_encoded_bytes));
                };
                const result = try self.transitionOwnerTx(
                    .{
                        .scope = scope.canonical,
                        .jail = jail,
                        .current_generation = owner.generation,
                        .next_generation = owner.generation,
                        .expected_owner_revision = owner.revision,
                        .transition_id = request_id,
                        .mode = .release,
                        .occurred_us = now,
                    },
                    now,
                );
                if (!result.changed) return error.StaleEffect;
                released += 1;
            }
            _ = try self.commitEffectClock(clock);
            try self.commitEffectTransaction(released != 0);
            return .{ .after = if (count == 0) after else held[count - 1].key, .examined = @intCast(count), .released = released, .done = count < jail_disable_page_rows };
        }
    };
}
