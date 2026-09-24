// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const effects = @import("../core/native_effect.zig");
const Error = @import("store.zig").Error;

pub fn Methods(comptime Store: type) type {
    return struct {
        const effectBlob = Store.effectBlob;
        pub const MigrationState = enum(u8) { planned = 1, validated, recovery_point, quiesced, staged, activating, complete, rolled_back, failed };
        pub const MigrationStep = enum(u8) { validate_plan = 1, check_drift, capture_recovery_point, quiesce_source, stage_destination, activate_owners, verify_protection, complete, rollback };
        pub const MigrationOutcome = enum(u8) { pending = 0, success, incompatible, validation_failed, operational_failure, uncertain, rollback_failed, partial };
        pub const MigrationRun = struct {
            run_id: [32]u8,
            host_id: [32]u8,
            source_db_fp: [32]u8,
            source_cfg_fp: [32]u8,
            plan_fp: [32]u8,
            recovery_point: []const u8,
            generation: [32]u8,
            state: MigrationState,
            created_us: i64,
            updated_us: i64,
        };
        pub const MigrationStepRow = struct { seq: u64, step: MigrationStep, outcome: MigrationOutcome, started_us: i64, finished_us: ?i64 };

        pub fn createMigrationRun(self: *Store, run: MigrationRun) Error!void {
            if (run.recovery_point.len > 4096 or run.created_us < 0 or run.updated_us < run.created_us) return error.InvalidMigrationRow;
            try self.beginWrite();
            errdefer self.rollback();
            if (self.schema_version < 23) return error.MigrationStorageRequired;
            {
                var exists = try self.statement("SELECT 1 FROM migration_runs WHERE run_id=?1;");
                defer exists.deinit();
                try exists.blob(1, &run.run_id);
                if (try exists.row()) return error.MigrationRunExists;
            }
            var insert = try self.statement("INSERT INTO migration_runs VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10);");
            defer insert.deinit();
            try insert.blob(1, &run.run_id);
            try insert.blob(2, &run.host_id);
            try insert.blob(3, &run.source_db_fp);
            try insert.blob(4, &run.source_cfg_fp);
            try insert.blob(5, &run.plan_fp);
            try insert.text(6, run.recovery_point);
            try insert.blob(7, &run.generation);
            try insert.int(8, @intFromEnum(run.state));
            try insert.int(9, run.created_us);
            try insert.int(10, run.updated_us);
            try insert.done();
            try self.commitTransaction();
        }

        pub fn migrationRun(self: *Store, allocator: std.mem.Allocator, run_id: [32]u8) Error!?MigrationRun {
            if (self.schema_version < 23) return error.MigrationStorageRequired;
            try self.beginRead();
            errdefer self.rollback();
            var row = try self.statement("SELECT host_id,source_db_fp,source_cfg_fp,plan_fp,recovery_point,generation,state,created_us,updated_us FROM migration_runs WHERE run_id=?1;");
            defer row.deinit();
            try row.blob(1, &run_id);
            if (!try row.row()) {
                try self.commitTransaction();
                return null;
            }
            const recovery = try allocator.dupe(u8, try row.boundedBytes(4, 4096));
            errdefer allocator.free(recovery);
            const state = std.meta.intToEnum(MigrationState, try row.signed(6)) catch return error.InvalidMigrationRow;
            const run = MigrationRun{ .run_id = run_id, .host_id = try effectBlob(&row, 0, 32), .source_db_fp = try effectBlob(&row, 1, 32), .source_cfg_fp = try effectBlob(&row, 2, 32), .plan_fp = try effectBlob(&row, 3, 32), .recovery_point = recovery, .generation = try effectBlob(&row, 5, 32), .state = state, .created_us = try row.signed(7), .updated_us = try row.signed(8) };
            try self.commitTransaction();
            return run;
        }

        pub fn beginMigrationStep(self: *Store, run_id: [32]u8, step: MigrationStep, intent: []const u8, now_us: i64) Error!u64 {
            if (intent.len > 4096 or now_us < 0) return error.InvalidMigrationRow;
            try self.beginWrite();
            errdefer self.rollback();
            if (self.schema_version < 23) return error.MigrationStorageRequired;
            {
                var exists = try self.statement("SELECT 1 FROM migration_runs WHERE run_id=?1;");
                defer exists.deinit();
                try exists.blob(1, &run_id);
                if (!try exists.row()) return error.MigrationRunMissing;
            }
            var pending_step = try self.statement("SELECT seq FROM migration_steps WHERE run_id=?1 AND outcome=0;");
            defer pending_step.deinit();
            try pending_step.blob(1, &run_id);
            if (try pending_step.row()) return error.MigrationStepOpen;
            var last = try self.statement("SELECT coalesce(max(seq),0) FROM migration_steps WHERE run_id=?1;");
            defer last.deinit();
            try last.blob(1, &run_id);
            if (!try last.row()) return error.DatabaseFailure;
            const next_seq = std.math.add(i64, try last.signed(0), 1) catch return error.InvalidMigrationRow;
            const seq = std.math.cast(u64, next_seq) orelse return error.InvalidMigrationRow;
            {
                var insert = try self.statement("INSERT INTO migration_steps VALUES(?1,?2,?3,?4,0,zeroblob(0),?5,NULL);");
                defer insert.deinit();
                try insert.blob(1, &run_id);
                try insert.int(2, @intCast(seq));
                try insert.int(3, @intFromEnum(step));
                try insert.blob(4, intent);
                try insert.int(5, now_us);
                try insert.done();
            }
            try self.touchMigrationRunTx(run_id, null, now_us);
            try self.fault(.after_migration_step_intent);
            try self.commitTransaction();
            return seq;
        }

        pub fn finishMigrationStep(self: *Store, run_id: [32]u8, seq: u64, outcome: MigrationOutcome, detail: []const u8, state: ?MigrationState, now_us: i64) Error!void {
            if (outcome == .pending or detail.len > 4096 or now_us < 0 or seq == 0 or seq > std.math.maxInt(i64)) return error.InvalidMigrationRow;
            try self.beginWrite();
            errdefer self.rollback();
            if (self.schema_version < 23) return error.MigrationStorageRequired;
            var update = try self.statement("UPDATE migration_steps SET outcome=?3,detail=?4,finished_us=?5 WHERE run_id=?1 AND seq=?2 AND outcome=0 AND started_us<=?5;");
            defer update.deinit();
            try update.blob(1, &run_id);
            try update.int(2, @intCast(seq));
            try update.int(3, @intFromEnum(outcome));
            try update.blob(4, detail);
            try update.int(5, now_us);
            try update.done();
            if (self.api.changes(self.db) != 1) return error.MigrationStepMissing;
            try self.touchMigrationRunTx(run_id, state, now_us);
            try self.fault(.after_migration_step_outcome);
            try self.commitTransaction();
        }

        fn touchMigrationRunTx(self: *Store, run_id: [32]u8, state: ?MigrationState, now_us: i64) Error!void {
            var update = try self.statement(if (state != null) "UPDATE migration_runs SET state=?2,updated_us=max(updated_us,?3) WHERE run_id=?1;" else "UPDATE migration_runs SET updated_us=max(updated_us,?3) WHERE run_id=?1;");
            defer update.deinit();
            try update.blob(1, &run_id);
            if (state) |value| try update.int(2, @intFromEnum(value));
            try update.int(3, now_us);
            try update.done();
            if (self.api.changes(self.db) != 1) return error.MigrationRunMissing;
        }

        pub fn migrationSteps(self: *Store, run_id: [32]u8, output: []MigrationStepRow) Error!usize {
            if (self.schema_version < 23) return error.MigrationStorageRequired;
            try self.beginRead();
            errdefer self.rollback();
            var row = try self.statement("SELECT seq,step,outcome,started_us,finished_us FROM migration_steps WHERE run_id=?1 ORDER BY seq LIMIT ?2;");
            defer row.deinit();
            try row.blob(1, &run_id);
            try row.int(2, @intCast(output.len));
            var count: usize = 0;
            while (try row.row()) {
                output[count] = .{ .seq = std.math.cast(u64, try row.signed(0)) orelse return error.InvalidMigrationRow, .step = std.meta.intToEnum(MigrationStep, try row.signed(1)) catch return error.InvalidMigrationRow, .outcome = std.meta.intToEnum(MigrationOutcome, try row.signed(2)) catch return error.InvalidMigrationRow, .started_us = try row.signed(3), .finished_us = try row.optionalSigned(4) };
                count += 1;
            }
            try self.commitTransaction();
            return count;
        }

        pub const StagedOwnerRow = struct { jail: []const u8, scope: [canonical_scope_bytes]u8, lease_kind: u8, deadline_us: ?i64, source_event_us: i64, source_row: u64 };
        pub const StagedHistoryRow = struct { jail: []const u8, scope: [canonical_scope_bytes]u8, event_kind: u8, event_us: i64, bancount: i64, source_row: u64 };
        pub const canonical_scope_bytes = 92;

        pub fn stageMigrationRows(self: *Store, run_id: [32]u8, owners: []const StagedOwnerRow, history: []const StagedHistoryRow) Error!void {
            if (owners.len > 200_000 or history.len > 200_000) return error.InvalidMigrationRow;
            try self.beginWrite();
            errdefer self.rollback();
            if (self.schema_version < 23) return error.MigrationStorageRequired;
            for ([_][:0]const u8{ "DELETE FROM migration_staged_owners WHERE run_id=?1;", "DELETE FROM migration_staged_history WHERE run_id=?1;" }) |sql| {
                var delete = try self.statement(sql);
                defer delete.deinit();
                try delete.blob(1, &run_id);
                try delete.done();
            }
            for (owners, 1..) |owner, seq| {
                if (owner.jail.len == 0 or owner.jail.len > 64 or owner.lease_kind < 1 or owner.lease_kind > 2 or (owner.lease_kind == 1) != (owner.deadline_us != null)) return error.InvalidMigrationRow;
                var insert = try self.statement("INSERT INTO migration_staged_owners VALUES(?1,?2,?3,?4,?5,?6,?7,?8);");
                defer insert.deinit();
                try insert.blob(1, &run_id);
                try insert.int(2, @intCast(seq));
                try insert.text(3, owner.jail);
                try insert.blob(4, &owner.scope);
                try insert.int(5, owner.lease_kind);
                if (owner.deadline_us) |deadline| try insert.int(6, deadline);
                try insert.int(7, owner.source_event_us);
                try insert.int(8, @intCast(owner.source_row));
                try insert.done();
            }
            for (history, 1..) |event, seq| {
                if (event.jail.len == 0 or event.jail.len > 64 or event.event_kind < 1 or event.event_kind > 3 or event.bancount < 0) return error.InvalidMigrationRow;
                var insert = try self.statement("INSERT INTO migration_staged_history VALUES(?1,?2,?3,?4,?5,?6,?7,?8);");
                defer insert.deinit();
                try insert.blob(1, &run_id);
                try insert.int(2, @intCast(seq));
                try insert.text(3, event.jail);
                try insert.blob(4, &event.scope);
                try insert.int(5, event.event_kind);
                try insert.int(6, event.event_us);
                try insert.int(7, event.bancount);
                try insert.int(8, @intCast(event.source_row));
                try insert.done();
            }
            try self.commitTransaction();
        }

        pub const StagedCounts = struct { owners: u64, history: u64 };
        pub fn stagedMigrationCounts(self: *Store, run_id: [32]u8) Error!StagedCounts {
            if (self.schema_version < 23) return error.MigrationStorageRequired;
            try self.beginRead();
            errdefer self.rollback();
            var owners = try self.statement("SELECT count(*) FROM migration_staged_owners WHERE run_id=?1;");
            defer owners.deinit();
            try owners.blob(1, &run_id);
            if (!try owners.row()) return error.DatabaseFailure;
            const owner_count: u64 = @intCast(try owners.signed(0));
            var history = try self.statement("SELECT count(*) FROM migration_staged_history WHERE run_id=?1;");
            defer history.deinit();
            try history.blob(1, &run_id);
            if (!try history.row()) return error.DatabaseFailure;
            const history_count: u64 = @intCast(try history.signed(0));
            try self.commitTransaction();
            return .{ .owners = owner_count, .history = history_count };
        }

        pub const JailGeneration = struct { jail: []const u8, generation: [32]u8 };
        pub fn activateStagedOwners(self: *Store, run_id: [32]u8, generations: []const JailGeneration, clock: effects.Clock) Error!u64 {
            try self.beginWrite();
            errdefer self.rollback();
            if (self.schema_version < 23) return error.MigrationStorageRequired;
            try self.effectSchema();
            const now = try self.effectClock(clock);
            {
                var state = try self.statement("SELECT state FROM migration_runs WHERE run_id=?1;");
                defer state.deinit();
                try state.blob(1, &run_id);
                if (!try state.row()) return error.MigrationRunMissing;
                const current = try state.signed(0);
                if (current != @intFromEnum(MigrationState.staged) and current != @intFromEnum(MigrationState.activating)) return error.InvalidMigrationState;
            }
            {
                var mark = try self.statement("UPDATE migration_runs SET state=?2,updated_us=max(updated_us,?3) WHERE run_id=?1;");
                defer mark.deinit();
                try mark.blob(1, &run_id);
                try mark.int(2, @intFromEnum(MigrationState.activating));
                try mark.int(3, @max(0, now));
                try mark.done();
            }
            const Staged = struct { seq: u64, jail: [64]u8, jail_len: u8, scope: [canonical_scope_bytes]u8, lease_kind: u8, deadline_us: ?i64, decided_us: i64 };
            var held = std.ArrayListUnmanaged(Staged){};
            defer held.deinit(self.allocator);
            {
                var rows = try self.statement("SELECT seq,jail,scope,lease_kind,deadline_us,source_event_us FROM migration_staged_owners WHERE run_id=?1 ORDER BY seq;");
                defer rows.deinit();
                try rows.blob(1, &run_id);
                while (try rows.row()) {
                    if (held.items.len == effects.max_effects) return error.EffectCapacity;
                    var item = Staged{ .seq = std.math.cast(u64, try rows.signed(0)) orelse return error.InvalidMigrationRow, .jail = undefined, .jail_len = 0, .scope = try effectBlob(&rows, 2, canonical_scope_bytes), .lease_kind = std.math.cast(u8, try rows.signed(3)) orelse return error.InvalidMigrationRow, .deadline_us = try rows.optionalSigned(4), .decided_us = try rows.signed(5) };
                    const jail = try rows.boundedBytes(1, 64);
                    @memcpy(item.jail[0..jail.len], jail);
                    item.jail_len = @intCast(jail.len);
                    try held.append(self.allocator, item);
                }
            }
            const canonical_scope = @import("../firewall/scope.zig");
            const installation = try self.readInstallation() orelse return error.InstallationRequired;
            var activated: u64 = 0;
            var effect_changed = false;
            for (held.items) |item| {
                const scope = canonical_scope.Scope.decode(&item.scope) catch return error.InvalidMigrationRow;
                const lease: effects.Lease = if (item.lease_kind == 2) .permanent else .{ .finite = item.deadline_us orelse return error.InvalidMigrationRow };
                if (lease == .finite and lease.finite <= now) continue;
                var counter: [8]u8 = undefined;
                std.mem.writeInt(u64, &counter, item.seq, .little);
                const decision_id = effects.hashParts("fail2zig-migration-owner-v1", &.{ &run_id, &counter });
                const key = try (try effects.Scope.exact(scope)).key(installation);
                const jail = item.jail[0..item.jail_len];
                const generation = for (generations) |candidate| {
                    if (std.mem.eql(u8, candidate.jail, jail)) break candidate.generation;
                } else return error.MigrationJailUnknown;
                var existing_revision: u64 = 0;
                var replay = false;
                var native: ?struct { decision_id: [32]u8, permanent: bool, deadline_us: ?i64, decided_us: i64 } = null;
                {
                    var row = try self.statement("SELECT decision_id,revision,lease_kind,deadline_us,decided_us FROM effect_owners WHERE scope_key=?1 AND jail=?2;");
                    defer row.deinit();
                    try row.blob(1, &key);
                    try row.text(2, jail);
                    if (try row.row()) {
                        const saved = try effectBlob(&row, 0, 32);
                        existing_revision = std.math.cast(u64, try row.signed(1)) orelse return error.InvalidMigrationRow;
                        const kind = try row.signed(2);
                        replay = std.mem.eql(u8, &saved, &decision_id) and kind != 0;
                        if (!replay and kind != 0) native = .{ .decision_id = saved, .permanent = kind == 2, .deadline_us = try row.optionalSigned(3), .decided_us = try row.signed(4) };
                    }
                }
                if (replay) {
                    activated += 1;
                    continue;
                }
                if (native) |owner| {
                    const native_live = owner.permanent or (owner.deadline_us orelse 0) > now;
                    if (native_live) {
                        try self.recordMigrationConflictTx(run_id, item.seq, &item.scope, jail, item.lease_kind, item.deadline_us, now);
                        const extend = !owner.permanent and lease == .finite and (owner.deadline_us orelse 0) < lease.finite;
                        if (extend) {
                            _ = try self.setOwnerTx(try (effects.CanonicalOwnerChange{ .scope = scope, .jail = jail, .generation = generation, .decision_id = effects.hashParts("fail2zig-migration-extend-v1", &.{ &run_id, &counter }), .expected_revision = existing_revision, .lease = lease, .decided_us = @min(owner.decided_us, now) }).exact(), now);
                            effect_changed = true;
                        }
                        continue;
                    }
                }
                _ = try self.setOwnerTx(try (effects.CanonicalOwnerChange{ .scope = scope, .jail = jail, .generation = generation, .decision_id = decision_id, .expected_revision = existing_revision, .lease = lease, .decided_us = @min(item.decided_us, now) }).exact(), now);
                effect_changed = true;
                activated += 1;
            }
            _ = try self.commitEffectClock(clock);
            try self.fault(.before_migration_activation_commit);
            try self.commitEffectTransaction(effect_changed);
            return activated;
        }

        fn recordMigrationConflictTx(self: *Store, run_id: [32]u8, seq: u64, scope: *const [canonical_scope_bytes]u8, jail: []const u8, lease_kind: u8, deadline_us: ?i64, now: i64) Error!void {
            {
                var exists = try self.statement("SELECT 1 FROM migration_deltas WHERE run_id=?1 AND seq=?2;");
                defer exists.deinit();
                try exists.blob(1, &run_id);
                try exists.int(2, @intCast(seq));
                if (try exists.row()) return;
            }
            var insert = try self.statement("INSERT INTO migration_deltas VALUES(?1,?2,3,?3,?4,?5,?6,1,0,?7);");
            defer insert.deinit();
            try insert.blob(1, &run_id);
            try insert.int(2, @intCast(seq));
            try insert.blob(3, scope);
            try insert.text(4, jail);
            try insert.int(5, lease_kind);
            if (deadline_us) |deadline| try insert.int(6, deadline) else try self.check(self.api.bind_null(insert.ptr, 6));
            try insert.int(7, @max(0, now));
            try insert.done();
        }

        pub const MigrationDeltaKind = enum(u8) { ban = 1, unban = 2, conflict = 3 };
        pub const MigrationCarryBack = enum(u8) { mapped = 1, unsupported = 2, expired = 3 };
        pub const MigrationDelta = struct {
            kind: MigrationDeltaKind,
            jail: [64]u8,
            jail_len: u8,
            scope: [canonical_scope_bytes]u8,
            lease_kind: u8,
            deadline_us: ?i64,
            decided_us: i64,
            carry_back: MigrationCarryBack,
            pub fn jailName(self: *const MigrationDelta) []const u8 {
                return self.jail[0..self.jail_len];
            }
        };
        pub fn planMigrationDeltas(self: *Store, run_id: [32]u8, jails: []const []const u8, now_us: i64, output: []MigrationDelta) Error!usize {
            if (self.schema_version < 23) return error.MigrationStorageRequired;
            const installation = try self.readInstallation() orelse return error.InstallationRequired;
            const canonical_scope = @import("../firewall/scope.zig");
            var count: usize = 0;
            var staged = try self.statement("SELECT jail,scope,lease_kind,deadline_us,seq FROM migration_staged_owners WHERE run_id=?1 ORDER BY seq;");
            defer staged.deinit();
            try staged.blob(1, &run_id);
            while (try staged.row()) {
                const jail = try staged.boundedBytes(0, 64);
                const scope_bytes = try effectBlob(&staged, 1, canonical_scope_bytes);
                const scope = canonical_scope.Scope.decode(&scope_bytes) catch return error.InvalidMigrationRow;
                const key = try (try effects.Scope.exact(scope)).key(installation);
                var live = false;
                var native_decision = false;
                var live_kind: u8 = 0;
                var live_deadline: ?i64 = null;
                var live_decided: i64 = now_us;
                {
                    var owner = try self.statement("SELECT lease_kind,deadline_us,decided_us,decision_id FROM effect_owners WHERE scope_key=?1 AND jail=?2 AND lease_kind!=0 AND (lease_kind=2 OR deadline_us>?3);");
                    defer owner.deinit();
                    try owner.blob(1, &key);
                    try owner.text(2, jail);
                    try owner.int(3, now_us);
                    if (try owner.row()) {
                        live = true;
                        live_kind = std.math.cast(u8, try owner.signed(0)) orelse return error.InvalidMigrationRow;
                        live_deadline = try owner.optionalSigned(1);
                        live_decided = try owner.signed(2);
                        var seq_counter: [8]u8 = undefined;
                        std.mem.writeInt(u64, &seq_counter, std.math.cast(u64, try staged.signed(4)) orelse return error.InvalidMigrationRow, .little);
                        const migration_decision = effects.hashParts("fail2zig-migration-owner-v1", &.{ &run_id, &seq_counter });
                        const extension_decision = effects.hashParts("fail2zig-migration-extend-v1", &.{ &run_id, &seq_counter });
                        const decision = try effectBlob(&owner, 3, 32);
                        native_decision = !std.mem.eql(u8, &decision, &migration_decision) and !std.mem.eql(u8, &decision, &extension_decision);
                    }
                }
                if (live and !native_decision) continue;
                if (count == output.len) return error.EffectCapacity;
                if (live) {
                    var delta = MigrationDelta{ .kind = .ban, .jail = undefined, .jail_len = @intCast(jail.len), .scope = scope_bytes, .lease_kind = live_kind, .deadline_us = live_deadline, .decided_us = live_decided, .carry_back = if (scope.protocols.isAll() and scope.ports.isAll()) .mapped else .unsupported };
                    @memcpy(delta.jail[0..jail.len], jail);
                    output[count] = delta;
                    count += 1;
                    continue;
                }
                const staged_kind = std.math.cast(u8, try staged.signed(2)) orelse return error.InvalidMigrationRow;
                const staged_deadline = try staged.optionalSigned(3);
                const expired = staged_kind == 1 and (staged_deadline orelse 0) <= now_us;
                var delta = MigrationDelta{ .kind = .unban, .jail = undefined, .jail_len = @intCast(jail.len), .scope = scope_bytes, .lease_kind = 0, .deadline_us = null, .decided_us = now_us, .carry_back = if (expired) .expired else .mapped };
                @memcpy(delta.jail[0..jail.len], jail);
                output[count] = delta;
                count += 1;
            }
            for (jails) |jail| {
                var owners = try self.statement("SELECT n.canonical_scope,o.lease_kind,o.deadline_us,o.decided_us FROM effect_owners o JOIN native_effects n USING(scope_key) WHERE o.jail=?1 AND o.lease_kind!=0 AND (o.lease_kind=2 OR o.deadline_us>?2) AND NOT EXISTS (SELECT 1 FROM migration_staged_owners s WHERE s.run_id=?3 AND s.jail=o.jail AND s.scope=n.canonical_scope) ORDER BY o.decided_us;");
                defer owners.deinit();
                try owners.text(1, jail);
                try owners.int(2, now_us);
                try owners.blob(3, &run_id);
                while (try owners.row()) {
                    if (count == output.len) return error.EffectCapacity;
                    const scope_bytes = try effectBlob(&owners, 0, canonical_scope_bytes);
                    const scope = canonical_scope.Scope.decode(&scope_bytes) catch return error.InvalidMigrationRow;
                    const mapped = scope.protocols.isAll() and scope.ports.isAll();
                    var delta = MigrationDelta{ .kind = .ban, .jail = undefined, .jail_len = @intCast(jail.len), .scope = scope_bytes, .lease_kind = std.math.cast(u8, try owners.signed(1)) orelse return error.InvalidMigrationRow, .deadline_us = try owners.optionalSigned(2), .decided_us = try owners.signed(3), .carry_back = if (mapped) .mapped else .unsupported };
                    @memcpy(delta.jail[0..jail.len], jail);
                    output[count] = delta;
                    count += 1;
                }
            }
            return count;
        }
        pub fn recordMigrationDeltas(self: *Store, run_id: [32]u8, deltas: []const MigrationDelta, applied: bool, now_us: i64) Error!void {
            try self.beginWrite();
            errdefer self.rollback();
            if (self.schema_version < 23) return error.MigrationStorageRequired;
            {
                var stale = try self.statement("DELETE FROM migration_deltas WHERE run_id=?1 AND kind IN (1,2) AND applied=0;");
                defer stale.deinit();
                try stale.blob(1, &run_id);
                try stale.done();
            }
            var last = try self.statement("SELECT coalesce(max(seq),0) FROM migration_deltas WHERE run_id=?1;");
            defer last.deinit();
            try last.blob(1, &run_id);
            if (!try last.row()) return error.DatabaseFailure;
            var seq: i64 = try last.signed(0);
            for (deltas) |delta| {
                seq += 1;
                var insert = try self.statement("INSERT INTO migration_deltas VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10);");
                defer insert.deinit();
                try insert.blob(1, &run_id);
                try insert.int(2, seq);
                try insert.int(3, @intFromEnum(delta.kind));
                try insert.blob(4, &delta.scope);
                try insert.text(5, delta.jailName());
                try insert.int(6, delta.lease_kind);
                if (delta.lease_kind == 1) try insert.int(7, delta.deadline_us orelse return error.InvalidMigrationRow) else try self.check(self.api.bind_null(insert.ptr, 7));
                try insert.int(8, @intFromEnum(delta.carry_back));
                try insert.int(9, @intFromBool(applied));
                try insert.int(10, @max(0, now_us));
                try insert.done();
            }
            try self.commitTransaction();
        }
        pub fn releaseMigrationOwners(self: *Store, run_id: [32]u8, clock: effects.Clock) Error!u64 {
            if (self.schema_version < 23) return error.MigrationStorageRequired;
            const installation = try self.readInstallation() orelse return error.InstallationRequired;
            const canonical_scope = @import("../firewall/scope.zig");
            var released: u64 = 0;
            var seq_index: u64 = 0;
            var staged = try self.statement("SELECT seq,jail,scope FROM migration_staged_owners WHERE run_id=?1 ORDER BY seq;");
            defer staged.deinit();
            try staged.blob(1, &run_id);
            var pending = std.ArrayListUnmanaged(struct { seq: u64, jail: [64]u8, jail_len: u8, scope: [canonical_scope_bytes]u8 }){};
            defer pending.deinit(self.allocator);
            while (try staged.row()) {
                if (pending.items.len == effects.max_effects) return error.EffectCapacity;
                const jail = try staged.boundedBytes(1, 64);
                var item: @TypeOf(pending.items[0]) = .{ .seq = std.math.cast(u64, try staged.signed(0)) orelse return error.InvalidMigrationRow, .jail = undefined, .jail_len = @intCast(jail.len), .scope = try effectBlob(&staged, 2, canonical_scope_bytes) };
                @memcpy(item.jail[0..jail.len], jail);
                try pending.append(self.allocator, item);
            }
            for (pending.items) |item| {
                seq_index += 1;
                const scope = canonical_scope.Scope.decode(&item.scope) catch return error.InvalidMigrationRow;
                const key = try (try effects.Scope.exact(scope)).key(installation);
                const jail = item.jail[0..item.jail_len];
                const owner = (try self.currentOwner(key, jail)) orelse continue;
                if (owner.lease == .absent) continue;
                var counter: [8]u8 = undefined;
                std.mem.writeInt(u64, &counter, item.seq, .little);
                _ = try self.transitionOwner(.{ .scope = scope, .jail = jail, .current_generation = owner.generation, .next_generation = owner.generation, .expected_owner_revision = owner.revision, .transition_id = effects.hashParts("fail2zig-migration-release-v1", &.{ &run_id, &counter }), .mode = .release, .occurred_us = clock.prepared_us }, clock);
                released += 1;
            }
            return released;
        }

        pub const PendingStep = struct { seq: u64, step: MigrationStep };
        pub fn pendingMigrationStep(self: *Store, run_id: [32]u8) Error!?PendingStep {
            if (self.schema_version < 23) return error.MigrationStorageRequired;
            var row = try self.statement("SELECT seq,step FROM migration_steps WHERE run_id=?1 AND outcome=0;");
            defer row.deinit();
            try row.blob(1, &run_id);
            if (!try row.row()) return null;
            const step = std.meta.intToEnum(MigrationStep, try row.signed(1)) catch return error.InvalidMigrationRow;
            return .{ .seq = std.math.cast(u64, try row.signed(0)) orelse return error.InvalidMigrationRow, .step = step };
        }
        pub fn migrationStagedKeys(self: *Store, run_id: [32]u8, output: [][32]u8) Error!usize {
            if (self.schema_version < 23) return error.MigrationStorageRequired;
            const installation = try self.readInstallation() orelse return error.InstallationRequired;
            const canonical_scope = @import("../firewall/scope.zig");
            var count: usize = 0;
            var staged = try self.statement("SELECT scope FROM migration_staged_owners WHERE run_id=?1 ORDER BY seq;");
            defer staged.deinit();
            try staged.blob(1, &run_id);
            while (try staged.row()) {
                if (count == output.len) return error.EffectCapacity;
                const scope = canonical_scope.Scope.decode(&try effectBlob(&staged, 0, canonical_scope_bytes)) catch return error.InvalidMigrationRow;
                output[count] = try (try effects.Scope.exact(scope)).key(installation);
                count += 1;
            }
            return count;
        }
        pub fn markMigrationDeltasApplied(self: *Store, run_id: [32]u8) Error!void {
            try self.beginWrite();
            errdefer self.rollback();
            if (self.schema_version < 23) return error.MigrationStorageRequired;
            var update = try self.statement("UPDATE migration_deltas SET applied=1 WHERE run_id=?1 AND kind IN (1,2);");
            defer update.deinit();
            try update.blob(1, &run_id);
            try update.done();
            try self.commitTransaction();
        }
        pub fn migrationStepSucceeded(self: *Store, run_id: [32]u8, step: MigrationStep) Error!bool {
            if (self.schema_version < 23) return error.MigrationStorageRequired;
            var row = try self.statement("SELECT 1 FROM migration_steps WHERE run_id=?1 AND step=?2 AND outcome=?3;");
            defer row.deinit();
            try row.blob(1, &run_id);
            try row.int(2, @intFromEnum(step));
            try row.int(3, @intFromEnum(MigrationOutcome.success));
            return try row.row();
        }

        pub fn migrationActivatedKeys(self: *Store, run_id: [32]u8, now_us: i64, output: [][32]u8) Error!struct { expected: u64, found: usize } {
            if (self.schema_version < 23) return error.MigrationStorageRequired;
            const installation = try self.readInstallation() orelse return error.InstallationRequired;
            const canonical_scope = @import("../firewall/scope.zig");
            var expected: u64 = 0;
            var found: usize = 0;
            var staged = try self.statement("SELECT jail,scope FROM migration_staged_owners WHERE run_id=?1 AND (lease_kind=2 OR deadline_us>?2) ORDER BY seq;");
            defer staged.deinit();
            try staged.blob(1, &run_id);
            try staged.int(2, now_us);
            while (try staged.row()) {
                expected += 1;
                const jail = try staged.boundedBytes(0, 64);
                const scope = canonical_scope.Scope.decode(&try effectBlob(&staged, 1, canonical_scope_bytes)) catch return error.InvalidMigrationRow;
                const key = try (try effects.Scope.exact(scope)).key(installation);
                var owner = try self.statement("SELECT scope_key FROM effect_owners WHERE scope_key=?1 AND jail=?2 AND lease_kind!=0 AND (lease_kind=2 OR deadline_us>?3);");
                defer owner.deinit();
                try owner.blob(1, &key);
                try owner.text(2, jail);
                try owner.int(3, now_us);
                if (try owner.row()) {
                    if (found == output.len) return error.EffectCapacity;
                    output[found] = try effectBlob(&owner, 0, 32);
                    found += 1;
                }
            }
            return .{ .expected = expected, .found = found };
        }
    };
}
