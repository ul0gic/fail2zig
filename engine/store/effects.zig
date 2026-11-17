// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Stores firewall effect ownership: each jail's owner of a ban scope, the scope's desired intent and the observed outcomes.
// Holds: A stored effect is used only once its key, intent id and owner aggregate recompute equal and no timestamp passes the effect clock.

const std = @import("std");
const build_options = @import("build_options");
const diag = @import("../diag/diag.zig");
const effects = @import("../effect/effect.zig");
const detection = @import("../detect/detection_record.zig");
const action_outcome = @import("../effect/action_outcome.zig");
const application_history = @import("../effect/application_history.zig");
const store = @import("store.zig");
const budget = @import("budget.zig");
const Error = store.Error;
const Stmt = store.Stmt;
const latest_schema = store.latest_schema;
pub const origin_schema: i64 = 26;

pub fn Methods(comptime Store: type) type {
    return struct {
        pub usingnamespace @import("memory_caps.zig").Methods(Store);
        pub fn enableEffects(self: *Store) Error!void {
            try self.beginWrite();
            errdefer self.rollback();
            const schema = try self.chainSchema();
            if (schema < 10 or schema > latest_schema) return error.UnsupportedSchema;
            if (schema == 10) try self.exec(
                \\CREATE TABLE effect_installation(singleton INTEGER PRIMARY KEY CHECK(singleton=1),identity BLOB NOT NULL CHECK(typeof(identity)='blob' AND length(identity)=16),backend INTEGER NOT NULL CHECK(typeof(backend)='integer' AND backend BETWEEN 1 AND 3),selector TEXT NOT NULL CHECK(typeof(selector)='text' AND length(selector) BETWEEN 1 AND 256));
                \\CREATE TABLE effect_clock(singleton INTEGER PRIMARY KEY CHECK(singleton=1),floor_us INTEGER CHECK(floor_us IS NULL OR typeof(floor_us)='integer'),revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision>=0));
                \\INSERT INTO effect_clock VALUES(1,NULL,0);
                \\CREATE TABLE native_effects(scope_key BLOB PRIMARY KEY NOT NULL CHECK(typeof(scope_key)='blob' AND length(scope_key)=32),scope BLOB NOT NULL CHECK(typeof(scope)='blob' AND length(scope)=24),revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision>=0),lease_kind INTEGER NOT NULL CHECK(typeof(lease_kind)='integer' AND lease_kind BETWEEN 0 AND 2),deadline_us INTEGER CHECK(deadline_us IS NULL OR typeof(deadline_us)='integer'),intent_id BLOB CHECK(intent_id IS NULL OR (typeof(intent_id)='blob' AND length(intent_id)=32)),CHECK((lease_kind=1)=(deadline_us IS NOT NULL)));
                \\CREATE TABLE effect_owners(scope_key BLOB NOT NULL,jail TEXT NOT NULL CHECK(length(jail) BETWEEN 1 AND 64),generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=32),decision_id BLOB NOT NULL CHECK(typeof(decision_id)='blob' AND length(decision_id)=32),revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision>0),lease_kind INTEGER NOT NULL CHECK(typeof(lease_kind)='integer' AND lease_kind BETWEEN 0 AND 2),deadline_us INTEGER CHECK(deadline_us IS NULL OR typeof(deadline_us)='integer'),decided_us INTEGER NOT NULL CHECK(typeof(decided_us)='integer'),PRIMARY KEY(scope_key,jail),FOREIGN KEY(scope_key) REFERENCES native_effects(scope_key),CHECK((lease_kind=1)=(deadline_us IS NOT NULL)),CHECK(deadline_us IS NULL OR deadline_us>decided_us));
                \\CREATE TABLE effect_owner_revisions(scope_key BLOB NOT NULL,jail TEXT NOT NULL,generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=32),decision_id BLOB NOT NULL CHECK(typeof(decision_id)='blob' AND length(decision_id)=32),revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision>0),lease_kind INTEGER NOT NULL CHECK(typeof(lease_kind)='integer' AND lease_kind BETWEEN 0 AND 2),deadline_us INTEGER CHECK(deadline_us IS NULL OR typeof(deadline_us)='integer'),decided_us INTEGER NOT NULL CHECK(typeof(decided_us)='integer'),PRIMARY KEY(scope_key,jail,revision),FOREIGN KEY(scope_key) REFERENCES native_effects(scope_key),CHECK((lease_kind=1)=(deadline_us IS NOT NULL)));
                \\CREATE TRIGGER effect_owner_insert AFTER INSERT ON effect_owners BEGIN INSERT INTO effect_owner_revisions VALUES(NEW.scope_key,NEW.jail,NEW.generation,NEW.decision_id,NEW.revision,NEW.lease_kind,NEW.deadline_us,NEW.decided_us); END;
                \\CREATE TRIGGER effect_owner_update AFTER UPDATE ON effect_owners BEGIN INSERT INTO effect_owner_revisions VALUES(NEW.scope_key,NEW.jail,NEW.generation,NEW.decision_id,NEW.revision,NEW.lease_kind,NEW.deadline_us,NEW.decided_us); END;
                \\CREATE TABLE effect_intents(intent_id BLOB PRIMARY KEY NOT NULL CHECK(typeof(intent_id)='blob' AND length(intent_id)=32),scope_key BLOB NOT NULL,revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision>0),decision_id BLOB NOT NULL CHECK(typeof(decision_id)='blob' AND length(decision_id)=32),lease_kind INTEGER NOT NULL CHECK(typeof(lease_kind)='integer' AND lease_kind BETWEEN 0 AND 2),deadline_us INTEGER CHECK(deadline_us IS NULL OR typeof(deadline_us)='integer'),status INTEGER NOT NULL CHECK(typeof(status)='integer' AND status BETWEEN 1 AND 6),created_us INTEGER NOT NULL CHECK(typeof(created_us)='integer'),dispatch_us INTEGER CHECK(dispatch_us IS NULL OR typeof(dispatch_us)='integer'),observed_us INTEGER CHECK(observed_us IS NULL OR typeof(observed_us)='integer'),fingerprint BLOB CHECK(fingerprint IS NULL OR (typeof(fingerprint)='blob' AND length(fingerprint)=32)),FOREIGN KEY(scope_key) REFERENCES native_effects(scope_key),UNIQUE(scope_key,revision),CHECK((lease_kind=1)=(deadline_us IS NOT NULL)));
                \\CREATE TABLE effect_observations(observation_id BLOB PRIMARY KEY NOT NULL CHECK(typeof(observation_id)='blob' AND length(observation_id)=32),intent_id BLOB NOT NULL,dispatch_us INTEGER NOT NULL,observed_us INTEGER NOT NULL,fingerprint BLOB NOT NULL CHECK(typeof(fingerprint)='blob' AND length(fingerprint)=32),state_kind INTEGER NOT NULL CHECK(state_kind BETWEEN 0 AND 3),deadline_us INTEGER,outcome INTEGER NOT NULL CHECK(outcome BETWEEN 1 AND 6),FOREIGN KEY(intent_id) REFERENCES effect_intents(intent_id),CHECK(observed_us>=dispatch_us),CHECK((state_kind=1)=(deadline_us IS NOT NULL)));
                \\CREATE TABLE confirmed_effect_events(event_id BLOB PRIMARY KEY NOT NULL CHECK(typeof(event_id)='blob' AND length(event_id)=32),scope_key BLOB NOT NULL,jail TEXT NOT NULL,decision_id BLOB NOT NULL CHECK(typeof(decision_id)='blob' AND length(decision_id)=32),confirmed_us INTEGER NOT NULL CHECK(typeof(confirmed_us)='integer'),UNIQUE(scope_key,jail,decision_id),FOREIGN KEY(scope_key) REFERENCES native_effects(scope_key));
                \\ALTER TABLE records ADD COLUMN zone_digest BLOB CHECK(zone_digest IS NULL OR (typeof(zone_digest)='blob' AND length(zone_digest)=32 AND native_time_kind IS NOT NULL));
                \\ALTER TABLE records ADD COLUMN zone_offset_seconds INTEGER CHECK(zone_offset_seconds IS NULL OR (typeof(zone_offset_seconds)='integer' AND zone_offset_seconds BETWEEN -2147483647 AND 2147483647));
                \\ALTER TABLE records ADD COLUMN zone_ambiguity INTEGER CHECK(zone_ambiguity IS NULL OR (typeof(zone_ambiguity)='integer' AND zone_ambiguity BETWEEN 0 AND 2));
                \\ALTER TABLE records ADD COLUMN zone_fold INTEGER CHECK(zone_fold IS NULL OR (typeof(zone_fold)='integer' AND zone_fold BETWEEN 0 AND 1));
                \\CREATE TRIGGER zone_provenance_update BEFORE UPDATE OF zone_digest,zone_offset_seconds,zone_ambiguity,zone_fold ON records WHEN NOT ((NEW.zone_digest IS NULL AND NEW.zone_offset_seconds IS NULL AND NEW.zone_ambiguity IS NULL AND NEW.zone_fold IS NULL) OR (NEW.zone_digest IS NOT NULL AND NEW.zone_offset_seconds IS NOT NULL AND NEW.zone_ambiguity IS NOT NULL AND NEW.zone_fold IS NOT NULL)) BEGIN SELECT RAISE(ABORT,'incomplete zone provenance'); END;
                \\PRAGMA user_version=11;
            );
            try self.fault(.before_effect_schema_commit);
            try self.commitTransaction();
            self.schema_version = @max(schema, 11);
        }

        pub fn effectSchema(self: *Store) Error!void {
            const schema = try self.integer("PRAGMA user_version;");
            if (schema < 11) return error.EffectStorageRequired;
            if (schema > latest_schema) return error.UnsupportedSchema;
            self.schema_version = schema;
        }
        pub fn enableTimeProvenance(self: *Store) Error!void {
            return self.enableEffects();
        }
        // Why: Column type codes are SQLITE_TEXT 3, SQLITE_BLOB 4 and SQLITE_NULL 5 (sqlite3.h).
        pub fn effectBlob(row: *Stmt, column: c_int, comptime length: usize) Error![length]u8 {
            if (row.store.api.column_type(row.ptr, column) != 4) return error.InvalidEffect;
            const bytes = try row.boundedBytes(column, length);
            if (bytes.len != length) return error.InvalidEffect;
            return bytes[0..length].*;
        }
        pub fn decodeStoredScope(self: *Store, row: *Stmt, column: c_int) Error!effects.Scope {
            if (self.api.column_type(row.ptr, column) != 4) return error.InvalidEffect;
            const bytes = try row.boundedBytes(column, effects.Scope.canonical_encoded_bytes);
            return if (self.schema_version >= 19)
                effects.Scope.decodeCanonical(bytes)
            else
                effects.Scope.decode(bytes);
        }
        pub fn effectLease(row: *Stmt, kind_col: c_int, deadline_col: c_int) Error!effects.Lease {
            const kind = try row.signed(kind_col);
            const deadline = try row.optionalSigned(deadline_col);
            return switch (kind) {
                0 => if (deadline == null) .absent else error.InvalidEffect,
                1 => .{ .finite = deadline orelse return error.InvalidEffect },
                2 => if (deadline == null) .permanent else error.InvalidEffect,
                else => error.InvalidEffect,
            };
        }
        pub fn originSql(self: *Store, comptime head: [:0]const u8, comptime column: [:0]const u8, comptime tail: [:0]const u8) [:0]const u8 {
            return if (self.schema_version >= origin_schema) head ++ column ++ tail else head ++ "1" ++ tail;
        }
        pub fn storedOrigin(row: *Stmt, column: c_int) Error!effects.Origin {
            return std.meta.intToEnum(effects.Origin, try row.signed(column)) catch error.InvalidEffect;
        }
        pub fn bindEffectLease(row: *Stmt, index: c_int, lease: effects.Lease) Error!void {
            try row.int(index, @intFromEnum(lease));
            if (lease == .finite) try row.int(index + 1, lease.finite) else try row.store.check(row.store.api.bind_null(row.ptr, index + 1));
        }
        pub fn readInstallation(self: *Store) Error!?effects.Installation {
            try self.effectSchema();
            var row = try self.statement("SELECT singleton,identity,backend,selector FROM effect_installation ORDER BY singleton;");
            defer row.deinit();
            if (!try row.row()) return null;
            if (try row.signed(0) != 1 or self.api.column_type(row.ptr, 3) != 3) return error.InvalidEffect;
            const backend = std.meta.intToEnum(effects.Backend, try row.signed(2)) catch return error.InvalidEffect;
            const result = try effects.Installation.init(try effectBlob(&row, 1, 16), backend, try row.boundedBytes(3, 256));
            if (try row.row()) return error.InvalidEffect;
            return result;
        }
        pub fn admitInstallation(self: *Store, installation: effects.Installation, admission: effects.NamespaceAdmission) Error!void {
            try installation.validate();
            if (!std.mem.eql(u8, installation.selector(), admission.selector)) return error.NamespaceAdmissionRequired;
            try self.beginWrite();
            errdefer self.rollback();
            if (try self.readInstallation()) |saved| {
                if (!std.meta.eql(saved, installation)) return error.InstallationMismatch;
            } else {
                if (admission.disposition != .verified_absent) return error.NamespaceAdmissionRequired;
                // Why: Scope keys derive from the installation, so effects stored before one exists could never verify against it.
                if (try self.integer("SELECT count(*) FROM native_effects;") != 0) return error.InvalidEffect;
                var row = try self.statement("INSERT INTO effect_installation VALUES(1,?1,?2,?3);");
                defer row.deinit();
                try row.blob(1, &installation.id);
                try row.int(2, @intFromEnum(installation.backend));
                try row.text(3, installation.selector());
                try row.done();
            }
            try self.commitTransaction();
        }
        pub fn effectClock(self: *Store, clock: effects.Clock) Error!i64 {
            const floor = try self.readAdmissionClock(self.schema_version);
            return clock.checked(if (floor) |value| value.us else null);
        }
        pub fn commitEffectClock(self: *Store, clock: effects.Clock) Error!i64 {
            const now = try self.effectClock(clock);
            var row = try self.statement("UPDATE effect_clock SET floor_us=?1 WHERE singleton=1;");
            defer row.deinit();
            try row.int(1, now);
            try row.done();
            if (self.api.changes(self.db) != 1) return error.InvalidEffect;
            return now;
        }
        pub fn advanceEffectSnapshot(self: *Store) Error!void {
            try self.exec("UPDATE effect_clock SET revision=revision+1 WHERE singleton=1 AND revision<9223372036854775807;");
            if (self.api.changes(self.db) != 1) return error.EffectCapacity;
        }

        pub const ReserveCost = struct {
            owners: i64 = 0,
            effects: i64 = 0,
            revisions: i64 = 0,
            intents: i64 = 0,
            observations: i64 = 0,
            targets: i64 = 0,
            live_owners: i64 = 0,
            retired_markers: i64 = 0,
        };
        pub const observations_per_intent = store.load_repair.observations_per_intent;

        pub fn reserveEffectRows(self: *Store, own: ReserveCost) Error!void {
            if (self.schema_version < store.load_repair_schema) return;
            const live = try self.integer("SELECT live FROM effect_owner_live WHERE id=1;");
            if (live < 0) return error.LiveOwnerCounterInvalid;
            const live_after = live + own.live_owners;
            if (live_after > effects.max_live_owners) return error.ReserveBackpressure;
            const unsettled_after = @max(0, live_after - (try self.integer("SELECT count(*) FROM confirmation_markers;") - own.retired_markers));
            const limits = [_]struct { table: store.TalliedTable, own: i64, reserve: i64, cap: i64 }{
                .{ .table = .effect_owners, .own = own.owners, .reserve = 0, .cap = effects.max_owners },
                .{ .table = .native_effects, .own = own.effects, .reserve = 0, .cap = effects.max_effects },
                .{ .table = .effect_owner_revisions, .own = own.revisions, .reserve = live_after, .cap = effects.max_owner_revisions },
                .{ .table = .effect_intents, .own = own.intents, .reserve = live_after, .cap = effects.max_intents },
                .{ .table = .effect_observations, .own = own.observations, .reserve = live_after * observations_per_intent, .cap = effects.max_observations },
                .{ .table = .action_targets, .own = own.targets, .reserve = 0, .cap = action_outcome.max_rows },
                .{ .table = .confirmed_effect_events, .own = 0, .reserve = unsettled_after, .cap = effects.max_confirmed_events },
                .{ .table = .confirmed_event_details, .own = 0, .reserve = unsettled_after, .cap = application_history.max_details },
            };
            for (limits) |limit| {
                if (try self.tableRows(limit.table) + limit.own + limit.reserve > limit.cap) return error.ReserveBackpressure;
            }
        }

        pub const LiveOwnerRecount = struct { stored: i64, counted: i64, prior_streak: i64 = 0 };
        const max_mismatch_streak = 1_000_000;
        // Why: Reconciliation compares sqlite_schema text to these strings exactly, so they must stay byte-identical to the creating DDL.
        const live_owner_triggers = [_]struct { name: []const u8, sql: []const u8 }{
            .{
                .name = "effect_owner_live_insert",
                .sql = "CREATE TRIGGER effect_owner_live_insert AFTER INSERT ON effect_owners WHEN NEW.lease_kind<>0 BEGIN UPDATE effect_owner_live SET live=live+1 WHERE id=1; END",
            },
            .{
                .name = "effect_owner_live_update",
                .sql = "CREATE TRIGGER effect_owner_live_update AFTER UPDATE OF lease_kind ON effect_owners WHEN (OLD.lease_kind<>0)<>(NEW.lease_kind<>0) BEGIN UPDATE effect_owner_live SET live=live+CASE WHEN NEW.lease_kind<>0 THEN 1 ELSE -1 END WHERE id=1; END",
            },
            .{
                .name = "effect_owner_live_delete",
                .sql = "CREATE TRIGGER effect_owner_live_delete AFTER DELETE ON effect_owners WHEN OLD.lease_kind<>0 BEGIN UPDATE effect_owner_live SET live=live-1 WHERE id=1; END",
            },
        };
        const owed_work_triggers = [_]struct { name: []const u8, table: []const u8, sql: []const u8 }{
            .{
                .name = "effect_owed_marker_insert",
                .table = "confirmation_markers",
                .sql = "CREATE TRIGGER effect_owed_marker_insert AFTER INSERT ON confirmation_markers BEGIN UPDATE effect_owed_work SET markers=markers+1 WHERE id=1; END",
            },
            .{
                .name = "effect_owed_marker_delete",
                .table = "confirmation_markers",
                .sql = "CREATE TRIGGER effect_owed_marker_delete AFTER DELETE ON confirmation_markers BEGIN UPDATE effect_owed_work SET markers=markers-1 WHERE id=1; END",
            },
            .{
                .name = "effect_owed_intent_insert",
                .table = "effect_intents",
                .sql = "CREATE TRIGGER effect_owed_intent_insert AFTER INSERT ON effect_intents WHEN NEW.status IN(1,2) BEGIN UPDATE effect_owed_work SET unsettled_intents=unsettled_intents+1 WHERE id=1; END",
            },
            .{
                .name = "effect_owed_intent_update",
                .table = "effect_intents",
                .sql = "CREATE TRIGGER effect_owed_intent_update AFTER UPDATE OF status ON effect_intents WHEN (OLD.status IN(1,2))<>(NEW.status IN(1,2)) BEGIN UPDATE effect_owed_work SET unsettled_intents=unsettled_intents+CASE WHEN NEW.status IN(1,2) THEN 1 ELSE -1 END WHERE id=1; END",
            },
            .{
                .name = "effect_owed_intent_delete",
                .table = "effect_intents",
                .sql = "CREATE TRIGGER effect_owed_intent_delete AFTER DELETE ON effect_intents WHEN OLD.status IN(1,2) BEGIN UPDATE effect_owed_work SET unsettled_intents=unsettled_intents-1 WHERE id=1; END",
            },
        };
        fn reconcileOwedWork(self: *Store) Error!void {
            for (owed_work_triggers) |trigger| {
                var row = try self.statement("SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=?1 AND tbl_name=?2;");
                defer row.deinit();
                try row.text(1, trigger.name);
                try row.text(2, trigger.table);
                if (!try row.row() or !std.mem.eql(u8, try row.bytes(0), trigger.sql) or try row.row()) return error.LiveOwnerCounterInvalid;
            }
            if (try self.integer("SELECT count(*) FROM effect_owed_work;") != 1) return error.LiveOwnerCounterInvalid;
            try self.exec("UPDATE effect_owed_work SET markers=(SELECT count(*) FROM confirmation_markers),unsettled_intents=(SELECT count(*) FROM effect_intents WHERE status IN(1,2)),reconciled=1 WHERE id=1;");
            if (self.api.changes(self.db) != 1) return error.LiveOwnerCounterInvalid;
        }

        // Why: Each rowid window is its own read transaction with a fresh work budget, so the scan finishes at any ban count.
        const owner_scan_rows: i64 = 8192;
        fn ownersWithoutRevisions(self: *Store) Error!i64 {
            const last = try self.integer("SELECT coalesce(max(rowid),0) FROM effect_owners;");
            var missing: i64 = 0;
            var after: i64 = 0;
            while (after < last) {
                const until = after + owner_scan_rows;
                try self.beginRead();
                errdefer self.rollback();
                var row = try self.statement("SELECT count(*) FROM effect_owners o WHERE o.rowid>?1 AND o.rowid<=?2 AND NOT EXISTS(SELECT 1 FROM effect_owner_revisions h WHERE h.scope_key=o.scope_key AND h.jail=o.jail AND h.revision=o.revision AND h.decision_id=o.decision_id AND h.lease_kind=o.lease_kind);");
                defer row.deinit();
                try row.int(1, after);
                try row.int(2, until);
                if (!try row.row()) return error.InvalidEffect;
                missing += try row.signed(0);
                try self.commitTransaction();
                after = until;
            }
            return missing;
        }
        pub fn reconcileLiveOwners(self: *Store) Error!?LiveOwnerRecount {
            if (self.schema_version >= store.load_repair_schema and try self.ownersWithoutRevisions() != 0) return error.InvalidEffect;
            try self.beginAdmissionWrite();
            errdefer self.rollback();
            if (self.schema_version < store.load_repair_schema) {
                try self.commitTransaction();
                return null;
            }
            for (live_owner_triggers) |trigger| {
                var row = try self.statement("SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=?1 AND tbl_name='effect_owners';");
                defer row.deinit();
                try row.text(1, trigger.name);
                if (!try row.row() or !std.mem.eql(u8, try row.bytes(0), trigger.sql) or try row.row()) return error.LiveOwnerCounterInvalid;
            }
            if (try self.integer("SELECT count(*) FROM effect_owner_live;") != 1) return error.LiveOwnerCounterInvalid;
            if (self.schema_version >= budget.owed_work_schema) try self.reconcileOwedWork();
            const stored = try self.integer("SELECT live FROM effect_owner_live WHERE id=1;");
            const streak = try self.integer("SELECT mismatch_streak FROM effect_owner_live WHERE id=1;");
            if (streak < 0) return error.LiveOwnerCounterInvalid;
            const counted = try self.integer("SELECT count(*) FROM effect_owners WHERE lease_kind<>0;");
            if (stored == counted) {
                if (streak != 0) try self.exec("UPDATE effect_owner_live SET mismatch_streak=0 WHERE id=1;");
                try self.commitTransaction();
                return null;
            }
            var repair = try self.statement("UPDATE effect_owner_live SET live=?1,mismatch_streak=?2 WHERE id=1;");
            defer repair.deinit();
            try repair.int(1, counted);
            try repair.int(2, @min(streak + 1, max_mismatch_streak));
            try repair.done();
            if (self.api.changes(self.db) != 1) return error.LiveOwnerCounterInvalid;
            try self.commitTransaction();
            return .{ .stored = stored, .counted = counted, .prior_streak = streak };
        }
        pub fn decodeEffect(self: *Store, row: *Stmt, installation: effects.Installation) Error!effects.Entry {
            const scope_key = try effectBlob(row, 0, 32);
            const scope = try self.decodeStoredScope(row, 1);
            if (!std.mem.eql(u8, &scope_key, &try scope.key(installation))) return error.InvalidEffect;
            const effect_revision = try row.signed(2);
            if (effect_revision <= 0 or effect_revision != try row.signed(8)) return error.InvalidEffect;
            const desired = try effectLease(row, 3, 4);
            const intent_id = try effectBlob(row, 5, 32);
            const status = std.meta.intToEnum(effects.Status, try row.signed(6)) catch return error.InvalidEffect;
            const decision_id = try effectBlob(row, 7, 32);
            if (!effects.Lease.eql(desired, try effectLease(row, 9, 10)) or !std.mem.eql(
                u8,
                &intent_id,
                &effects.intentId(installation.id, scope_key, decision_id, @intCast(effect_revision), desired),
            )) return error.InvalidEffect;
            const created = try row.signed(11);
            const dispatched = try row.optionalSigned(12);
            const observed = try row.optionalSigned(13);
            if (dispatched) |at| if (at < created) return error.InvalidEffect;
            if (observed) |at| {
                if (at < (dispatched orelse return error.InvalidEffect)) return error.InvalidEffect;
                _ = try effectBlob(row, 14, 32);
            } else if (self.api.column_type(row.ptr, 14) != 5) return error.InvalidEffect;
            if (status != .pending and dispatched == null) return error.InvalidEffect;
            if ((status == .applied or status == .absent or status == .expired) and observed == null) return error.InvalidEffect;
            if (status == .applied and desired == .absent) return error.InvalidEffect;
            if (status == .absent and desired != .absent) return error.InvalidEffect;
            if (status == .superseded) return error.InvalidEffect;
            var floor_row = try self.statement("SELECT floor_us FROM effect_clock WHERE singleton=1;");
            defer floor_row.deinit();
            if (!try floor_row.row()) return error.InvalidEffect;
            const effect_floor = try floor_row.optionalSigned(0) orelse return error.InvalidEffect;
            if (created > effect_floor or (dispatched != null and dispatched.? > effect_floor) or (observed != null and observed.? > effect_floor)) return error.InvalidEffect;

            var owner_rows: [effects.max_page]effects.Owner = undefined;
            const owner_count = try self.readOwners(scope_key, &owner_rows);
            if (owner_count == 0) return error.InvalidEffect;
            var aggregate: effects.Lease = .absent;
            for (owner_rows[0..owner_count]) |owner| {
                if (owner.decided_us > created or owner.revision > effect_revision) return error.InvalidEffect;
                switch (owner.lease) {
                    .absent => {},
                    .permanent => aggregate = .permanent,
                    .finite => |deadline| if (deadline > created and aggregate != .permanent and (aggregate == .absent or deadline > aggregate.finite)) {
                        aggregate = .{ .finite = deadline };
                    },
                }
            }
            if (!effects.Lease.eql(aggregate, desired)) return error.InvalidEffect;
            return .{
                .installation = installation,
                .scope = scope,
                .scope_key = scope_key,
                .revision = @intCast(effect_revision),
                .desired = desired,
                .intent_id = intent_id,
                .status = status,
                .intent_us = created,
            };
        }
        pub fn readEffect(self: *Store, key: effects.Hash, installation: effects.Installation) Error!?effects.Entry {
            var row = try self.statement(if (self.schema_version >= 19)
                "SELECT e.scope_key,e.canonical_scope,e.revision,e.lease_kind,e.deadline_us,e.intent_id,i.status,i.decision_id,i.revision,i.lease_kind,i.deadline_us,i.created_us,i.dispatch_us,i.observed_us,i.fingerprint FROM native_effects e LEFT JOIN effect_intents i ON i.intent_id=e.intent_id WHERE e.scope_key=?1;"
            else
                "SELECT e.scope_key,e.scope,e.revision,e.lease_kind,e.deadline_us,e.intent_id,i.status,i.decision_id,i.revision,i.lease_kind,i.deadline_us,i.created_us,i.dispatch_us,i.observed_us,i.fingerprint FROM native_effects e LEFT JOIN effect_intents i ON i.intent_id=e.intent_id WHERE e.scope_key=?1;");
            defer row.deinit();
            try row.blob(1, &key);
            if (!try row.row()) return null;
            return try self.decodeEffect(&row, installation);
        }
        pub fn effectPage(self: *Store, after: ?effects.Hash, expected_revision: ?u64, output: []effects.Entry) Error!effects.Page {
            if (output.len == 0 or output.len > effects.max_page) return error.EffectCapacity;
            try self.beginRead();
            errdefer self.rollback();
            const installation = try self.readInstallation() orelse return error.InstallationRequired;
            const effect_revision = try self.integer("SELECT revision FROM effect_clock WHERE singleton=1;");
            if (effect_revision < 0) return error.InvalidEffect;
            if (expected_revision) |expected| if (expected != effect_revision) return error.StaleEffect;
            var row = try self.statement(if (self.schema_version >= 19)
                (if (after == null)
                    "SELECT e.scope_key,e.canonical_scope,e.revision,e.lease_kind,e.deadline_us,e.intent_id,i.status,i.decision_id,i.revision,i.lease_kind,i.deadline_us,i.created_us,i.dispatch_us,i.observed_us,i.fingerprint FROM native_effects e LEFT JOIN effect_intents i ON i.intent_id=e.intent_id ORDER BY e.scope_key LIMIT ?1;"
                else
                    "SELECT e.scope_key,e.canonical_scope,e.revision,e.lease_kind,e.deadline_us,e.intent_id,i.status,i.decision_id,i.revision,i.lease_kind,i.deadline_us,i.created_us,i.dispatch_us,i.observed_us,i.fingerprint FROM native_effects e LEFT JOIN effect_intents i ON i.intent_id=e.intent_id WHERE e.scope_key>?1 ORDER BY e.scope_key LIMIT ?2;")
            else
                (if (after == null)
                    "SELECT e.scope_key,e.scope,e.revision,e.lease_kind,e.deadline_us,e.intent_id,i.status,i.decision_id,i.revision,i.lease_kind,i.deadline_us,i.created_us,i.dispatch_us,i.observed_us,i.fingerprint FROM native_effects e LEFT JOIN effect_intents i ON i.intent_id=e.intent_id ORDER BY e.scope_key LIMIT ?1;"
                else
                    "SELECT e.scope_key,e.scope,e.revision,e.lease_kind,e.deadline_us,e.intent_id,i.status,i.decision_id,i.revision,i.lease_kind,i.deadline_us,i.created_us,i.dispatch_us,i.observed_us,i.fingerprint FROM native_effects e LEFT JOIN effect_intents i ON i.intent_id=e.intent_id WHERE e.scope_key>?1 ORDER BY e.scope_key LIMIT ?2;"));
            defer row.deinit();
            const after_key = after orelse ([_]u8{0} ** 32);
            if (after != null) try row.blob(1, &after_key);
            try row.int(if (after == null) 1 else 2, @intCast(output.len + 1));
            var count: usize = 0;
            var more = false;
            while (try row.row()) {
                if (count == output.len) {
                    more = true;
                    break;
                }
                output[count] = try self.decodeEffect(&row, installation);
                count += 1;
            }
            try self.commitTransaction();
            return .{ .revision = @intCast(effect_revision), .count = count, .more = more };
        }
        pub fn readOwners(self: *Store, key: effects.Hash, output: []effects.Owner) Error!usize {
            var row = try self.statement(self.originSql(
                "SELECT o.jail,o.generation,o.decision_id,o.revision,o.lease_kind,o.deadline_us,o.decided_us,EXISTS(SELECT 1 FROM effect_owner_revisions h WHERE h.scope_key=o.scope_key AND h.jail=o.jail AND h.revision=o.revision AND h.generation=o.generation AND h.decision_id=o.decision_id AND h.lease_kind=o.lease_kind AND h.deadline_us IS o.deadline_us AND h.decided_us=o.decided_us),",
                "o.origin",
                " FROM effect_owners o WHERE o.scope_key=?1 ORDER BY o.jail LIMIT 65;",
            ));
            defer row.deinit();
            try row.blob(1, &key);
            var count: usize = 0;
            while (try row.row()) {
                if (count == output.len or count == effects.max_page) return error.EffectCapacity;
                if (self.api.column_type(row.ptr, 0) != 3 or try row.signed(7) != 1) return error.InvalidEffect;
                const effect_revision = try row.signed(3);
                if (effect_revision <= 0) return error.InvalidEffect;
                const lease = try effectLease(&row, 4, 5);
                const decided = try row.signed(6);
                if (lease == .finite and lease.finite <= decided) return error.InvalidEffect;
                output[count] = .{
                    .jail = detection.Name.init(try row.boundedBytes(0, 64)) catch return error.InvalidEffect,
                    .generation = try effectBlob(&row, 1, 32),
                    .decision_id = try effectBlob(&row, 2, 32),
                    .revision = @intCast(effect_revision),
                    .lease = lease,
                    .decided_us = decided,
                    .origin = try storedOrigin(&row, 8),
                };
                count += 1;
            }
            return count;
        }
        pub fn effectOwners(self: *Store, key: effects.Hash, expected_revision: u64, output: []effects.Owner) Error!usize {
            if (output.len > effects.max_page) return error.EffectCapacity;
            try self.beginRead();
            errdefer self.rollback();
            const installation = try self.readInstallation() orelse return error.InstallationRequired;
            const entry = try self.readEffect(key, installation) orelse return error.StaleEffect;
            if (entry.revision != expected_revision) return error.StaleEffect;
            const count = try self.readOwners(key, output);
            try self.commitTransaction();
            return count;
        }

        pub const OperatorOwner = struct {
            key: [32]u8,
            jail: detection.Name,
            scope: effects.Scope,
            lease: effects.Lease,
            decision_id: effects.Hash,
            ordinal: u64,
            origin: effects.Origin,
        };
        pub const owner_page_rows: usize = 4096;
        pub fn operatorOwnerPage(self: *Store, now_us: i64, output: []OperatorOwner, after: ?OperatorOwner) Error!usize {
            if (comptime build_options.diag) diag.count(.owner_full_pages, 1);
            if (output.len == 0 or output.len > owner_page_rows) return error.EffectCapacity;
            const RawCursor = struct {
                jail: [64]u8,
                jail_len: usize,
                key: effects.Hash,

                fn slice(value: *const @This()) []const u8 {
                    return value.jail[0..value.jail_len];
                }
            };
            var cursor: ?RawCursor = null;
            if (after) |last| {
                cursor = .{ .jail = last.jail.bytes, .jail_len = last.jail.len, .key = last.key };
            }
            var count: usize = 0;
            while (count < output.len) {
                // Why: LIMIT applies before the live-lease test, so an absent or expired tail costs at most 64 owner rows per transaction.
                const raw_limit: usize = 64;
                var scanned: usize = 0;
                var last_raw: RawCursor = undefined;
                {
                    try self.beginRead();
                    errdefer self.rollback();
                    const installation = try self.readInstallation() orelse return error.InstallationRequired;
                    if (self.schema_version < 19) return error.EffectStorageRequired;
                    const floor = try self.readAdmissionClock(self.schema_version);
                    if (floor) |value| if (now_us < value.us) return error.EffectClockReversed;
                    {
                        const head = "SELECT o.scope_key,n.canonical_scope,o.jail,o.decision_id,o.lease_kind,o.deadline_us,o.decided_us,d.ordinal," ++
                            "EXISTS(SELECT 1 FROM effect_owner_revisions h WHERE h.scope_key=o.scope_key AND h.jail=o.jail AND h.revision=o.revision AND h.generation=o.generation AND h.decision_id=o.decision_id AND h.lease_kind=o.lease_kind AND h.deadline_us IS o.deadline_us AND h.decided_us=o.decided_us),";
                        const joined = " FROM effect_owners o INDEXED BY effect_owners_jail CROSS JOIN native_effects n ON n.scope_key=o.scope_key LEFT JOIN retry_decision_details d ON d.jail=o.jail AND d.effect_decision_id=o.decision_id";
                        var row = try self.statement(if (cursor == null)
                            self.originSql(head, "o.origin", joined ++ " ORDER BY o.jail,o.scope_key LIMIT ?1;")
                        else
                            self.originSql(head, "o.origin", joined ++ " WHERE (o.jail,o.scope_key)>(?1,?2) ORDER BY o.jail,o.scope_key LIMIT ?3;"));
                        defer row.deinit();
                        if (cursor) |*key| {
                            try row.text(1, key.slice());
                            try row.blob(2, &key.key);
                            try row.int(3, @intCast(raw_limit));
                        } else {
                            try row.int(1, @intCast(raw_limit));
                        }
                        while (try row.row()) {
                            const jail = try row.boundedBytes(2, 64);
                            last_raw = .{ .jail = [_]u8{0} ** 64, .jail_len = jail.len, .key = try effectBlob(&row, 0, 32) };
                            @memcpy(last_raw.jail[0..jail.len], jail);
                            scanned += 1;
                            if (!(try effectLease(&row, 4, 5)).live(now_us)) continue;
                            output[count] = try self.decodeOperatorOwner(&row, installation, if (floor) |value| value.us else null, now_us);
                            count += 1;
                            // Why: Later rows are left for the next call, which resumes after this live row.
                            if (count == output.len) break;
                        }
                    }
                    try self.commitTransaction();
                }
                if (count == output.len or scanned < raw_limit) return count;
                cursor = last_raw;
            }
            return count;
        }

        fn decodeOperatorOwner(self: *Store, row: *Stmt, installation: effects.Installation, floor_us: ?i64, now_us: i64) Error!OperatorOwner {
            const key = try effectBlob(row, 0, 32);
            const scope = try self.decodeStoredScope(row, 1);
            if (!std.mem.eql(u8, &key, &try scope.key(installation))) return error.InvalidEffect;
            if (self.api.column_type(row.ptr, 2) != 3 or try row.signed(8) != 1) return error.InvalidEffect;
            const lease = try effectLease(row, 4, 5);
            const decided_us = try row.signed(6);
            if (!lease.live(now_us) or decided_us > (floor_us orelse return error.InvalidEffect)) return error.InvalidEffect;
            const stored_ordinal = try row.optionalSigned(7);
            if (stored_ordinal) |ordinal| if (ordinal <= 0) return error.InvalidEffect;
            return .{
                .key = key,
                .jail = detection.Name.init(try row.boundedBytes(2, 64)) catch return error.InvalidEffect,
                .scope = scope,
                .lease = lease,
                .decision_id = try effectBlob(row, 3, 32),
                .ordinal = if (stored_ordinal) |ordinal| @intCast(ordinal) else 1,
                .origin = try storedOrigin(row, 9),
            };
        }
        pub fn operatorOwnersForScope(self: *Store, key: effects.Hash, now_us: i64, output: []OperatorOwner) Error!usize {
            if (comptime build_options.diag) diag.count(.owner_scope_reads, 1);
            if (output.len > effects.max_page or self.startup_admission or self.api.get_autocommit(self.db) == 0) return error.EffectCapacity;
            try self.beginRead();
            errdefer self.rollback();
            const installation = try self.readInstallation() orelse return error.InstallationRequired;
            if (self.schema_version < 19) return error.EffectStorageRequired;
            const floor = try self.readAdmissionClock(self.schema_version);
            if (floor) |value| if (now_us < value.us) return error.EffectClockReversed;
            var row = try self.statement(self.originSql(
                "SELECT o.scope_key,n.canonical_scope,o.jail,o.decision_id,o.lease_kind,o.deadline_us,o.decided_us,d.ordinal," ++
                    "EXISTS(SELECT 1 FROM effect_owner_revisions h WHERE h.scope_key=o.scope_key AND h.jail=o.jail AND h.revision=o.revision AND h.generation=o.generation AND h.decision_id=o.decision_id AND h.lease_kind=o.lease_kind AND h.deadline_us IS o.deadline_us AND h.decided_us=o.decided_us),",
                "o.origin",
                " FROM effect_owners o JOIN native_effects n USING(scope_key) LEFT JOIN retry_decision_details d ON d.jail=o.jail AND d.effect_decision_id=o.decision_id " ++
                    "WHERE o.scope_key=?1 AND (o.lease_kind=2 OR (o.lease_kind=1 AND o.deadline_us>?2)) ORDER BY o.jail LIMIT ?3;",
            ));
            defer row.deinit();
            try row.blob(1, &key);
            try row.int(2, now_us);
            try row.int(3, @intCast(output.len + 1));
            var count: usize = 0;
            while (try row.row()) {
                if (count == output.len) return error.EffectCapacity;
                output[count] = try self.decodeOperatorOwner(&row, installation, if (floor) |value| value.us else null, now_us);
                count += 1;
            }
            try self.commitTransaction();
            return count;
        }
    };
}
