// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Reclaims obsolete effect rows in rowid windows and prunes spent effect scopes in bounded, yielding batches.
// Holds: A spent scope counts as pruned only when its native_effects delete removes exactly one row.

const build_options = @import("build_options");
const diag_mod = @import("../diag/diag.zig");
const effects = @import("../effect/effect.zig");
const store = @import("store.zig");
const Error = store.Error;

pub fn Methods(comptime Store: type) type {
    return struct {
        const reclaim_window: i64 = 1024;
        const obsolete_intent = "i.intent_id IS NOT n.intent_id AND i.status NOT IN(1,2) AND NOT EXISTS(SELECT 1 FROM action_targets a WHERE a.action_id=i.decision_id AND a.scope_key=i.scope_key AND a.status IN(1,2,5))";
        const reclaim_phases = [_]struct { max_sql: [:0]const u8, seek_sql: [:0]const u8, tables: []const store.TalliedTable, statements: []const [:0]const u8 }{
            .{ .max_sql = "SELECT coalesce(max(rowid),0) FROM action_targets;", .seek_sql = "SELECT rowid FROM action_targets WHERE rowid>?1 ORDER BY rowid LIMIT 1 OFFSET ?2;", .tables = &.{.action_targets}, .statements = &.{"DELETE FROM action_targets WHERE rowid IN (SELECT a.rowid FROM action_targets a WHERE a.rowid>?1 AND a.rowid<=?2 AND a.status NOT IN(1,2,5) AND NOT EXISTS(SELECT 1 FROM effect_owners o INDEXED BY effect_owners_decision WHERE o.jail=a.jail AND o.decision_id=a.action_id));"} },
            .{ .max_sql = "SELECT coalesce(max(rowid),0) FROM effect_intents;", .seek_sql = "SELECT rowid FROM effect_intents WHERE rowid>?1 ORDER BY rowid LIMIT 1 OFFSET ?2;", .tables = &.{ .effect_observations, .effect_intents }, .statements = &.{
                "DELETE FROM effect_observations WHERE intent_id IN (SELECT i.intent_id FROM effect_intents i JOIN native_effects n ON n.scope_key=i.scope_key WHERE i.rowid>?1 AND i.rowid<=?2 AND " ++ obsolete_intent ++ ");",
                "DELETE FROM effect_intents WHERE rowid IN (SELECT i.rowid FROM effect_intents i JOIN native_effects n ON n.scope_key=i.scope_key WHERE i.rowid>?1 AND i.rowid<=?2 AND " ++ obsolete_intent ++ ");",
            } },
            .{ .max_sql = "SELECT coalesce(max(rowid),0) FROM effect_owner_revisions;", .seek_sql = "SELECT rowid FROM effect_owner_revisions WHERE rowid>?1 ORDER BY rowid LIMIT 1 OFFSET ?2;", .tables = &.{.effect_owner_revisions}, .statements = &.{"DELETE FROM effect_owner_revisions WHERE rowid IN (SELECT h.rowid FROM effect_owner_revisions h WHERE h.rowid>?1 AND h.rowid<=?2 AND NOT EXISTS(SELECT 1 FROM effect_owners o WHERE o.scope_key=h.scope_key AND o.jail=h.jail AND o.revision=h.revision) AND NOT EXISTS(SELECT 1 FROM action_targets a WHERE a.action_id=h.decision_id AND a.scope_key=h.scope_key AND a.status IN(1,2,5)));"} },
        };

        pub const ReclaimOutcome = enum { deleted, scanned, idle };
        const ReclaimPage = struct { high: i64, maximum: i64, deleted: bool };
        fn reclaimPageTx(self: *Store, phase_index: u2, cursor: i64, window: i64) Error!ReclaimPage {
            const phase = reclaim_phases[phase_index];
            const maximum = try self.integer(phase.max_sql);
            const high = blk: {
                var seek = try self.statement(phase.seek_sql);
                defer seek.deinit();
                try seek.int(1, cursor);
                try seek.int(2, window - 1);
                break :blk if (try seek.row()) try seek.signed(0) else maximum;
            };
            for (phase.tables) |table| self.deletedRows(table);
            var deleted = false;
            if (cursor < maximum) for (phase.statements) |sql| {
                var row = try self.statement(sql);
                defer row.deinit();
                try row.int(1, cursor);
                try row.int(2, high);
                try row.done();
                if (self.api.changes(self.db) != 0) deleted = true;
            };
            return .{ .high = high, .maximum = maximum, .deleted = deleted };
        }
        pub fn reclaimObsoleteOne(self: *Store) Error!ReclaimOutcome {
            const diag_span = if (comptime build_options.diag) diag_mod.enter(.obsolete_reclaim) else {};
            defer if (comptime build_options.diag) diag_mod.leave(diag_span);
            if (self.schema_version < store.load_repair_schema) return .idle;
            if (self.reclaim.rest != 0) {
                self.reclaim.rest -= 1;
                return .idle;
            }
            try self.beginWrite();
            errdefer self.rollback();
            var next = self.reclaim;
            const page = try self.reclaimPageTx(next.phase, next.cursor, reclaim_window);
            next.found = next.found or page.deleted;
            var idle = false;
            if (page.high >= page.maximum) {
                next.cursor = 0;
                next.phase += 1;
                if (next.phase == reclaim_phases.len) {
                    next.phase = 0;
                    idle = !next.found;
                    next.found = false;
                }
            } else next.cursor = page.high;
            if (idle) next.rest = 63;
            try self.commitTransaction();
            if (comptime build_options.diag) {
                diag_mod.count(.reclaim_pages, 1);
                if (page.high >= page.maximum and next.phase == 0) diag_mod.count(.reclaim_passes, 1);
            }
            self.reclaim = next;
            return if (page.deleted) .deleted else if (idle) .idle else .scanned;
        }

        fn reclaimCustomCompatibilityAttempt(self: *Store, cursor: store.ReclaimCursor, window: u16) Error!ReclaimPage {
            errdefer self.rollback();
            try self.beginAdmissionWrite();
            const page = try self.reclaimPageTx(cursor.phase, cursor.cursor, window);
            try self.commitTransaction();
            return page;
        }

        // Holds: Each page is one savepoint of the open startup admission and moves only the caller's cursor and window, not self.reclaim.
        pub fn reclaimCustomCompatibilityPage(self: *Store, cursor: *store.ReclaimCursor, window: *u16) Error!void {
            if (!self.startupAdmissionActive()) return error.DatabaseFailure;
            if (cursor.phase < 1 or cursor.phase > 2 or window.* == 0 or window.* > reclaim_window) return error.InvalidMaintenanceState;
            while (true) {
                const prior_rollback = self.rollback_error_code;
                self.rollback_error_code = null;
                const page = self.reclaimCustomCompatibilityAttempt(cursor.*, window.*) catch |failure| {
                    const clean = self.rollback_error_code == null and self.startupAdmissionActive();
                    if (self.rollback_error_code == null) self.rollback_error_code = prior_rollback;
                    if (failure != error.Interrupted or !clean) return failure;
                    if (window.* == 1) return error.MaintenanceWorkExhausted;
                    window.* /= 2;
                    continue;
                };
                self.rollback_error_code = prior_rollback;
                if (page.high >= page.maximum) {
                    cursor.cursor = 0;
                    cursor.phase += 1;
                } else cursor.cursor = page.high;
                return;
            }
        }

        pub const PruneResult = enum { idle, pruned, scanned, yielded };
        pub const max_prune_batch = Store.attribution_batch;
        pub fn pruneSpentEffects(self: *Store, max_scopes: usize) Error!PruneResult {
            const diag_span = if (comptime build_options.diag) diag_mod.enter(.spent_prune) else {};
            defer if (comptime build_options.diag) diag_mod.leave(diag_span);
            if (self.schema_version < 13) return .idle;
            if (max_scopes == 0 or max_scopes > max_prune_batch) return error.InvalidEffect;
            try self.beginWrite();
            errdefer self.rollback();
            var deleted: i64 = 0;
            var scopes: usize = 0;
            var after = self.prune_after;
            while (scopes < max_scopes) {
                const outcome = self.pruneSpentScopeTx(&deleted, &after) catch |failure| {
                    if (failure != error.Interrupted) return failure;
                    return self.yieldPrune(max_scopes);
                };
                if (outcome == .none) break;
                scopes += 1;
                if (outcome == .budget) break;
            }
            if (deleted == 0) {
                try self.commitTransaction();
            } else try self.commitEffectTransaction(true);
            self.prune_after = after;
            self.prune_batch = @min(max_prune_batch, self.prune_batch *| 2);
            if (comptime build_options.diag) diag_mod.gauge(.prune_batch, self.prune_batch);
            return if (deleted != 0) .pruned else if (after != null) .scanned else .idle;
        }
        fn yieldPrune(self: *Store, max_scopes: usize) Error!PruneResult {
            const prior_rollback = self.rollback_error_code;
            self.rollback_error_code = null;
            self.rollback();
            const clean = !self.reopen_required and self.rollback_error_code == null and self.api.get_autocommit(self.db) != 0;
            if (self.rollback_error_code == null) self.rollback_error_code = prior_rollback;
            if (!clean) return error.Interrupted;
            if (max_scopes <= 1) return error.MaintenanceWorkExhausted;
            self.prune_batch = @intCast(max_scopes / 2);
            if (comptime build_options.diag) {
                diag_mod.count(.prune_yields, 1);
                diag_mod.gauge(.prune_batch, self.prune_batch);
            }
            return .yielded;
        }
        const PruneOutcome = enum { none, skipped, removed, budget };
        fn pruneSpentScopeTx(self: *Store, deleted: *i64, after: *?effects.Hash) Error!PruneOutcome {
            // Why: Eligibility is a column, not a WHERE filter, so LIMIT 1 bounds the search even when every spent scope is still pending.
            var candidate = try self.statement(if (self.schema_version >= store.load_repair_schema)
                "SELECT n.scope_key,n.intent_id,i.status=4 AND NOT EXISTS(SELECT 1 FROM effect_owners o WHERE o.scope_key=n.scope_key AND o.lease_kind<>0) AND NOT EXISTS(SELECT 1 FROM action_targets a INDEXED BY action_targets_unsettled WHERE a.scope_key=n.scope_key AND a.status IN(1,2,5)) AND NOT EXISTS(SELECT 1 FROM effect_intents p INDEXED BY effect_intents_pending WHERE p.scope_key=n.scope_key AND p.status IN(1,2)) AND NOT EXISTS(SELECT 1 FROM confirmation_markers m WHERE m.scope_key=n.scope_key) FROM native_effects n INDEXED BY native_effects_spent JOIN effect_intents i ON i.intent_id=n.intent_id WHERE n.lease_kind=0 AND n.scope_key>?1 ORDER BY n.scope_key LIMIT 1;"
            else if (self.schema_version >= 21)
                "SELECT n.scope_key,n.intent_id,i.status=4 AND NOT EXISTS(SELECT 1 FROM effect_owners o WHERE o.scope_key=n.scope_key AND o.lease_kind<>0) AND NOT EXISTS(SELECT 1 FROM confirmed_effect_events e WHERE e.scope_key=n.scope_key) AND NOT EXISTS(SELECT 1 FROM action_targets a WHERE a.scope_key=n.scope_key AND a.status IN(1,2,5)) AND NOT EXISTS(SELECT 1 FROM effect_intents p WHERE p.scope_key=n.scope_key AND p.status IN(1,2)) FROM native_effects n JOIN effect_intents i ON i.intent_id=n.intent_id WHERE n.lease_kind=0 AND n.scope_key>?1 ORDER BY n.scope_key LIMIT 1;"
            else
                "SELECT n.scope_key,n.intent_id,i.status=4 AND NOT EXISTS(SELECT 1 FROM effect_owners o WHERE o.scope_key=n.scope_key AND o.lease_kind<>0) AND NOT EXISTS(SELECT 1 FROM confirmed_effect_events e WHERE e.scope_key=n.scope_key) AND NOT EXISTS(SELECT 1 FROM effect_intents p WHERE p.scope_key=n.scope_key AND p.status IN(1,2)) FROM native_effects n JOIN effect_intents i ON i.intent_id=n.intent_id WHERE n.lease_kind=0 AND n.scope_key>?1 ORDER BY n.scope_key LIMIT 1;");
            defer candidate.deinit();
            // Why: An empty blob compares lower than every 32-byte key, so a pass with no cursor starts at the lowest scope.
            try candidate.blob(1, if (after.*) |*key| key else &.{});
            if (!try candidate.row()) {
                after.* = null;
                return .none;
            }
            const scope_key = try Store.effectBlob(&candidate, 0, 32);
            const current = try Store.effectBlob(&candidate, 1, 32);
            if (try candidate.signed(2) == 0) {
                after.* = scope_key;
                return .skipped;
            }
            const chunks = [_][:0]const u8{
                if (self.schema_version >= store.load_repair_schema)
                    "DELETE FROM effect_observations WHERE rowid IN (SELECT o.rowid FROM effect_intents i JOIN effect_observations o INDEXED BY effect_observations_intent ON o.intent_id=i.intent_id WHERE i.scope_key=?1 LIMIT 256);"
                else
                    "DELETE FROM effect_observations WHERE rowid IN (SELECT o.rowid FROM effect_intents i JOIN effect_observations o ON o.intent_id=i.intent_id WHERE i.scope_key=?1 LIMIT 256);",
                "DELETE FROM effect_intents WHERE rowid IN (SELECT rowid FROM effect_intents WHERE scope_key=?1 AND intent_id<>?2 LIMIT 256);",
                "DELETE FROM effect_owner_revisions WHERE rowid IN (SELECT h.rowid FROM effect_owner_revisions h WHERE h.scope_key=?1 AND NOT EXISTS(SELECT 1 FROM effect_owners o WHERE o.scope_key=h.scope_key AND o.jail=h.jail AND o.revision=h.revision) LIMIT 256);",
                "DELETE FROM action_targets WHERE rowid IN (SELECT a.rowid FROM effect_owners o CROSS JOIN action_targets a ON a.action_id=o.decision_id AND a.scope_key=o.scope_key AND a.jail=o.jail WHERE o.scope_key=?1 LIMIT 256);",
            };
            for ([_]store.TalliedTable{ .effect_observations, .effect_intents, .effect_owner_revisions, .action_targets, .effect_owners, .native_effects }) |table| self.deletedRows(table);
            while (true) {
                var pass: i64 = 0;
                for (chunks, 0..) |sql, index| {
                    if (index == 3 and self.schema_version < 21) break;
                    var chunk = try self.statement(sql);
                    defer chunk.deinit();
                    try chunk.blob(1, &scope_key);
                    if (index == 1) try chunk.blob(2, &current);
                    try chunk.done();
                    const changed = self.api.changes(self.db);
                    pass += changed;
                    deleted.* += changed;
                    if (deleted.* >= 256) return .budget;
                }
                if (pass == 0) break;
            }
            for ([_][:0]const u8{
                "DELETE FROM effect_owner_revisions WHERE scope_key=?1;",
                "DELETE FROM effect_owners WHERE scope_key=?1;",
                "DELETE FROM effect_intents WHERE scope_key=?1;",
                "DELETE FROM native_effects WHERE scope_key=?1;",
            }) |sql| {
                var final = try self.statement(sql);
                defer final.deinit();
                try final.blob(1, &scope_key);
                try final.done();
            }
            // Why: changes() reports only the last statement, the native_effects delete, which must remove the scope's one row.
            if (self.api.changes(self.db) != 1) return error.InvalidEffect;
            deleted.* += 1;
            try self.advanceEffectSnapshot();
            self.noteEffectChange(scope_key);
            after.* = scope_key;
            return if (deleted.* >= 256) .budget else .removed;
        }
    };
}
