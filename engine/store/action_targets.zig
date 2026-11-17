// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Prepares, dispatches and settles the enforcement and notification targets recorded for each action.
// Holds: Preparing targets for an action that already has them writes nothing and refuses any target that differs from the intent.

const std = @import("std");
const detection = @import("../detect/detection_record.zig");
const effects = @import("../effect/effect.zig");
const action_outcome = @import("../effect/action_outcome.zig");
const store = @import("store.zig");
const Error = store.Error;

pub fn Methods(comptime Store: type) type {
    return struct {
        fn readActionTargetsTx(self: *Store, action_id: [32]u8, output: *[action_outcome.max_targets_per_action]action_outcome.Target) Error!usize {
            var row = try self.statement("SELECT scope_key,jail,kind,required,restored,status,intent_us,dispatch_us,settled_us,metadata FROM action_targets WHERE action_id=?1 ORDER BY kind;");
            defer row.deinit();
            try row.blob(1, &action_id);
            var count: usize = 0;
            while (try row.row()) {
                if (count == output.len) return error.InvalidActionTarget;
                const kind_value = try row.signed(2);
                const required = try row.signed(3);
                const restored = try row.signed(4);
                const status_value = try row.signed(5);
                const intent_us = try row.signed(6);
                const dispatch_us = try row.optionalSigned(7);
                const settled_us = try row.optionalSigned(8);
                if (required < 0 or required > 1 or restored < 0 or restored > 1) return error.InvalidActionTarget;
                const kind = std.meta.intToEnum(action_outcome.Kind, kind_value) catch return error.InvalidActionTarget;
                const status = std.meta.intToEnum(action_outcome.Status, status_value) catch return error.InvalidActionTarget;
                const jail = detection.Name.init(try row.boundedBytes(1, 64)) catch return error.InvalidActionTarget;
                var target = action_outcome.Target{
                    .action_id = action_id,
                    .scope_key = try Store.effectBlob(&row, 0, 32),
                    .jail = jail,
                    .kind = kind,
                    .required = required == 1,
                    .restored = restored == 1,
                    .status = status,
                    .intent_us = intent_us,
                    .dispatch_us = dispatch_us,
                    .settled_us = settled_us,
                    .metadata_len = 0,
                };
                if (self.api.column_type(row.ptr, 9) != 5) {
                    const metadata = try row.boundedBytes(9, action_outcome.max_metadata_bytes);
                    if (metadata.len == 0 or !std.unicode.utf8ValidateSlice(metadata)) return error.InvalidActionTarget;
                    target.metadata_len = @intCast(metadata.len);
                    @memcpy(target.metadata_bytes[0..metadata.len], metadata);
                }
                output[count] = target;
                count += 1;
            }
            return count;
        }

        pub fn prepareActionTargetsTx(self: *Store, intent: action_outcome.Intent, now: i64) Error!void {
            try intent.validate();
            var existing: [action_outcome.max_targets_per_action]action_outcome.Target = undefined;
            const existing_count = try self.readActionTargetsTx(intent.action_id, &existing);
            if (existing_count != 0) {
                if (existing_count != action_outcome.max_targets_per_action) return error.InvalidActionTarget;
                for (existing, 0..) |target, index| {
                    if (target.kind != @as(action_outcome.Kind, if (index == 0) .enforcement else .notification) or
                        !std.mem.eql(u8, &target.scope_key, &intent.scope_key) or !std.mem.eql(u8, target.jail.slice(), intent.jail) or
                        target.restored != intent.restored or !std.mem.eql(u8, target.metadata(), intent.metadata orelse "")) return error.InvalidActionTarget;
                }
                return;
            }
            if (try self.tableRows(.action_targets) > action_outcome.max_rows - action_outcome.max_targets_per_action) return error.ActionTargetCapacity;
            for ([_]action_outcome.Kind{ .enforcement, .notification }) |kind| {
                const suppressed = kind == .notification and intent.restored;
                var insert = try self.statement("INSERT INTO action_targets VALUES(?1,?2,?3,?4,?5,?6,?7,?8,NULL,?9,?10);");
                defer insert.deinit();
                try insert.blob(1, &intent.action_id);
                try insert.int(2, @intFromEnum(kind));
                try insert.blob(3, &intent.scope_key);
                try insert.text(4, intent.jail);
                try insert.int(5, if (kind == .enforcement) 1 else 0);
                try insert.int(6, @intFromBool(intent.restored));
                try insert.int(7, @intFromEnum(if (suppressed) action_outcome.Status.suppressed_restored else .pending));
                try insert.int(8, now);
                if (suppressed) try insert.int(9, now);
                if (intent.metadata) |metadata| try insert.text(10, metadata);
                try insert.done();
                self.insertedRows(.action_targets, 1);
            }
            try self.fault(.after_action_target_intent);
        }

        pub fn actionTargets(self: *Store, action_id: [32]u8, output: *[action_outcome.max_targets_per_action]action_outcome.Target) Error!usize {
            if (std.mem.allEqual(u8, &action_id, 0) or self.schema_version < 21) return error.InvalidActionTarget;
            try self.beginRead();
            errdefer self.rollback();
            const count = try self.readActionTargetsTx(action_id, output);
            try self.commitTransaction();
            return count;
        }

        pub fn markActionTargetDispatched(self: *Store, action_id: [32]u8, kind: action_outcome.Kind, clock: effects.Clock) Error!void {
            try self.beginWrite();
            errdefer self.rollback();
            if (self.schema_version < 21) return error.ActionTargetStorageRequired;
            const now = try self.effectClock(clock);
            var row = try self.statement("SELECT status FROM action_targets WHERE action_id=?1 AND kind=?2;");
            defer row.deinit();
            try row.blob(1, &action_id);
            try row.int(2, @intFromEnum(kind));
            if (!try row.row()) return error.StaleActionTarget;
            const status = std.meta.intToEnum(action_outcome.Status, try row.signed(0)) catch return error.InvalidActionTarget;
            if (try row.row()) return error.InvalidActionTarget;
            if (status == .dispatched or status == .confirmed) {
                try self.commitTransaction();
                return;
            }
            if (status != .pending and status != .uncertain) return error.StaleActionTarget;
            var update = try self.statement("UPDATE action_targets SET status=2,dispatch_us=?3,settled_us=NULL WHERE action_id=?1 AND kind=?2 AND status IN(1,5);");
            defer update.deinit();
            try update.blob(1, &action_id);
            try update.int(2, @intFromEnum(kind));
            try update.int(3, now);
            try update.done();
            if (self.api.changes(self.db) != 1) return error.StaleActionTarget;
            try self.fault(.before_action_target_dispatch_commit);
            _ = try self.commitEffectClock(clock);
            try self.commitTransaction();
        }

        pub fn settleActionTargetsTx(self: *Store, scope_key: effects.Hash, now: i64) Error!usize {
            if (self.schema_version < 21) return 0;
            var retired: usize = 0;
            if (self.schema_version >= store.load_repair_schema) {
                var retire = try self.statement("UPDATE action_targets SET status=7,settled_us=max(coalesce(dispatch_us,intent_us),?2) WHERE rowid IN (SELECT a.rowid FROM effect_owners o CROSS JOIN action_targets a ON a.action_id=o.decision_id AND a.scope_key=o.scope_key AND a.jail=o.jail WHERE o.scope_key=?1 AND o.lease_kind=0 AND a.status IN(1,2,5));");
                defer retire.deinit();
                try retire.blob(1, &scope_key);
                try retire.int(2, now);
                try retire.done();
                retired = @intCast(@max(0, self.api.changes(self.db)));
            }
            var update = try self.statement(if (self.schema_version >= store.load_repair_schema)
                "UPDATE action_targets SET status=3,settled_us=?2 WHERE scope_key=?1 AND status=2 AND action_id IN (SELECT decision_id FROM effect_owners WHERE scope_key=?1 AND lease_kind<>0) AND (kind<>1 OR EXISTS(SELECT 1 FROM confirmation_markers m WHERE m.scope_key=action_targets.scope_key AND m.jail=action_targets.jail AND m.decision_id=action_targets.action_id) OR EXISTS(SELECT 1 FROM confirmed_effect_events e WHERE e.scope_key=action_targets.scope_key AND e.jail=action_targets.jail AND e.decision_id=action_targets.action_id));"
            else
                "UPDATE action_targets SET status=3,settled_us=?2 WHERE scope_key=?1 AND status=2 AND action_id IN (SELECT decision_id FROM effect_owners WHERE scope_key=?1 AND lease_kind<>0) AND (kind<>1 OR EXISTS(SELECT 1 FROM confirmed_effect_events e WHERE e.scope_key=action_targets.scope_key AND e.jail=action_targets.jail AND e.decision_id=action_targets.action_id));");
            defer update.deinit();
            try update.blob(1, &scope_key);
            try update.int(2, now);
            try update.done();
            return retired + @as(usize, @intCast(@max(0, self.api.changes(self.db))));
        }
        pub fn settleActionTarget(self: *Store, action_id: [32]u8, kind: action_outcome.Kind, settlement: action_outcome.Settlement, clock: effects.Clock) Error!void {
            try self.beginWrite();
            errdefer self.rollback();
            if (self.schema_version < 21) return error.ActionTargetStorageRequired;
            var targets: [action_outcome.max_targets_per_action]action_outcome.Target = undefined;
            const count = try self.readActionTargetsTx(action_id, &targets);
            var selected: ?action_outcome.Target = null;
            for (targets[0..count]) |target| {
                if (target.kind == kind) selected = target;
            }
            const target = selected orelse return error.StaleActionTarget;
            const wanted: action_outcome.Status = switch (settlement) {
                .confirmed => .confirmed,
                .failed => .failed,
                .uncertain => .uncertain,
            };
            if (target.status == wanted) {
                try self.commitTransaction();
                return;
            }
            if (target.status != .dispatched) return error.StaleActionTarget;
            if (kind == .enforcement and settlement == .confirmed) {
                var proof = try self.statement(if (self.schema_version >= store.load_repair_schema)
                    "SELECT (SELECT count(*) FROM confirmation_markers WHERE scope_key=?1 AND jail=?2 AND decision_id=?3)+(SELECT count(*) FROM confirmed_effect_events WHERE scope_key=?1 AND jail=?2 AND decision_id=?3)>0;"
                else
                    "SELECT count(*) FROM confirmed_effect_events WHERE scope_key=?1 AND jail=?2 AND decision_id=?3;");
                defer proof.deinit();
                try proof.blob(1, &target.scope_key);
                try proof.text(2, target.jail.slice());
                try proof.blob(3, &action_id);
                if (!try proof.row() or try proof.signed(0) != 1 or try proof.row()) return error.ActionTargetProofRequired;
            }
            const now = try self.effectClock(clock);
            var update = try self.statement("UPDATE action_targets SET status=?3,settled_us=?4 WHERE action_id=?1 AND kind=?2 AND status=2;");
            defer update.deinit();
            try update.blob(1, &action_id);
            try update.int(2, @intFromEnum(kind));
            try update.int(3, @intFromEnum(wanted));
            try update.int(4, now);
            try update.done();
            if (self.api.changes(self.db) != 1) return error.StaleActionTarget;
            try self.fault(.before_action_target_settlement_commit);
            _ = try self.commitEffectClock(clock);
            try self.commitTransaction();
        }

        pub fn unsettledActionScope(self: *Store) Error!?effects.Hash {
            if (self.schema_version < 21) return null;
            var row = try self.statement("SELECT a.scope_key FROM action_targets a JOIN effect_owners o ON o.scope_key=a.scope_key AND o.decision_id=a.action_id WHERE a.status IN(1,2,5) LIMIT 1;");
            defer row.deinit();
            if (!try row.row()) return null;
            return try Store.effectBlob(&row, 0, 32);
        }
    };
}
