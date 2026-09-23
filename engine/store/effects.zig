// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const effects = @import("../core/native_effect.zig");
const detection = @import("../core/native_detection_record.zig");
const retry = @import("../core/native_retry.zig");
const store = @import("store.zig");
const Error = store.Error;
const Stmt = store.Stmt;
const latest_schema = store.latest_schema;

pub fn Methods(comptime Store: type) type {
    return struct {
        pub fn enableEffects(self: *Store) Error!void {
            try self.beginWrite();
            errdefer self.rollback();
            const schema = try self.integer("PRAGMA user_version;");
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
        fn decodeEffect(self: *Store, row: *Stmt, installation: effects.Installation) Error!effects.Entry {
            const scope_key = try effectBlob(row, 0, 32);
            const scope = try self.decodeStoredScope(row, 1);
            if (!std.mem.eql(u8, &scope_key, &try scope.key(installation))) return error.InvalidEffect;
            const effect_revision = try row.signed(2);
            if (effect_revision <= 0 or effect_revision != try row.signed(8)) return error.InvalidEffect;
            const desired = try effectLease(row, 3, 4);
            const intent_id = try effectBlob(row, 5, 32);
            const status = std.meta.intToEnum(effects.Status, try row.signed(6)) catch return error.InvalidEffect;
            const decision_id = try effectBlob(row, 7, 32);
            if (!effects.Lease.eql(desired, try effectLease(row, 9, 10)) or !std.mem.eql(u8, &intent_id, &effects.intentId(installation.id, scope_key, decision_id, @intCast(effect_revision), desired))) return error.InvalidEffect;
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
            return .{ .installation = installation, .scope = scope, .scope_key = scope_key, .revision = @intCast(effect_revision), .desired = desired, .intent_id = intent_id, .status = status };
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
                "SELECT e.scope_key,e.canonical_scope,e.revision,e.lease_kind,e.deadline_us,e.intent_id,i.status,i.decision_id,i.revision,i.lease_kind,i.deadline_us,i.created_us,i.dispatch_us,i.observed_us,i.fingerprint FROM native_effects e LEFT JOIN effect_intents i ON i.intent_id=e.intent_id WHERE (?1 IS NULL OR e.scope_key>?1) ORDER BY e.scope_key LIMIT ?2;"
            else
                "SELECT e.scope_key,e.scope,e.revision,e.lease_kind,e.deadline_us,e.intent_id,i.status,i.decision_id,i.revision,i.lease_kind,i.deadline_us,i.created_us,i.dispatch_us,i.observed_us,i.fingerprint FROM native_effects e LEFT JOIN effect_intents i ON i.intent_id=e.intent_id WHERE (?1 IS NULL OR e.scope_key>?1) ORDER BY e.scope_key LIMIT ?2;");
            defer row.deinit();
            const after_key = after orelse ([_]u8{0} ** 32);
            if (after != null) try row.blob(1, &after_key);
            try row.int(2, @intCast(output.len + 1));
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
            var row = try self.statement("SELECT o.jail,o.generation,o.decision_id,o.revision,o.lease_kind,o.deadline_us,o.decided_us,EXISTS(SELECT 1 FROM effect_owner_revisions h WHERE h.scope_key=o.scope_key AND h.jail=o.jail AND h.revision=o.revision AND h.generation=o.generation AND h.decision_id=o.decision_id AND h.lease_kind=o.lease_kind AND h.deadline_us IS o.deadline_us AND h.decided_us=o.decided_us) FROM effect_owners o WHERE o.scope_key=?1 ORDER BY o.jail LIMIT 65;");
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
                output[count] = .{ .jail = detection.Name.init(try row.boundedBytes(0, 64)) catch return error.InvalidEffect, .generation = try effectBlob(&row, 1, 32), .decision_id = try effectBlob(&row, 2, 32), .revision = @intCast(effect_revision), .lease = lease, .decided_us = decided };
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
            jail: detection.Name,
            scope: effects.Scope,
            lease: effects.Lease,
            decision_id: effects.Hash,
            ordinal: u64,
        };
        pub fn operatorOwners(self: *Store, now_us: i64, output: []OperatorOwner) Error!usize {
            if (output.len == 0 or output.len > effects.max_owners) return error.EffectCapacity;
            try self.beginRead();
            errdefer self.rollback();
            const installation = try self.readInstallation() orelse return error.InstallationRequired;
            if (self.schema_version < 19) return error.EffectStorageRequired;
            const floor = try self.readAdmissionClock(self.schema_version);
            if (floor) |value| if (now_us < value.us) return error.EffectClockReversed;
            var row = try self.statement(
                "SELECT o.scope_key,n.canonical_scope,o.jail,o.decision_id,o.lease_kind,o.deadline_us,o.decided_us,d.ordinal," ++
                    "EXISTS(SELECT 1 FROM effect_owner_revisions h WHERE h.scope_key=o.scope_key AND h.jail=o.jail AND h.revision=o.revision AND h.generation=o.generation AND h.decision_id=o.decision_id AND h.lease_kind=o.lease_kind AND h.deadline_us IS o.deadline_us AND h.decided_us=o.decided_us) " ++
                    "FROM effect_owners o JOIN native_effects n USING(scope_key) LEFT JOIN retry_decision_details d ON d.jail=o.jail AND d.effect_decision_id=o.decision_id " ++
                    "WHERE o.lease_kind=2 OR (o.lease_kind=1 AND o.deadline_us>?1) ORDER BY o.jail,o.scope_key LIMIT ?2;",
            );
            defer row.deinit();
            try row.int(1, now_us);
            try row.int(2, @intCast(output.len + 1));
            var count: usize = 0;
            while (try row.row()) {
                if (count == output.len) return error.EffectCapacity;
                const key = try effectBlob(&row, 0, 32);
                const scope = try self.decodeStoredScope(&row, 1);
                if (!std.mem.eql(u8, &key, &try scope.key(installation))) return error.InvalidEffect;
                if (self.api.column_type(row.ptr, 2) != 3 or try row.signed(8) != 1) return error.InvalidEffect;
                const lease = try effectLease(&row, 4, 5);
                const decided_us = try row.signed(6);
                if (!lease.live(now_us) or decided_us > (if (floor) |value| value.us else return error.InvalidEffect)) return error.InvalidEffect;
                const stored_ordinal = try row.optionalSigned(7);
                if (stored_ordinal) |ordinal| if (ordinal <= 0) return error.InvalidEffect;
                output[count] = .{
                    .jail = detection.Name.init(try row.boundedBytes(2, 64)) catch return error.InvalidEffect,
                    .scope = scope,
                    .lease = lease,
                    .decision_id = try effectBlob(&row, 3, 32),
                    .ordinal = if (stored_ordinal) |ordinal| @intCast(ordinal) else 1,
                };
                count += 1;
            }
            try self.commitTransaction();
            return count;
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
            if (try self.integer("SELECT count(*) FROM effect_intents;") >= effects.max_intents) return error.EffectCapacity;
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
            return .{ .installation = installation, .scope = scope, .scope_key = key, .revision = effect_revision, .desired = lease, .intent_id = id, .status = .pending };
        }
        pub fn setOwnerTx(self: *Store, change: effects.OwnerChange, now: i64) Error!effects.Entry {
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
            for (owners[0..count]) |owner| if (std.mem.eql(u8, owner.jail.slice(), jail.slice())) {
                owner_revision = owner.revision;
                if (!std.mem.eql(u8, &owner.generation, &change.generation)) return error.EffectGenerationMismatch;
                if (std.mem.eql(u8, &owner.decision_id, &change.decision_id)) {
                    if (!effects.Lease.eql(owner.lease, change.lease) or owner.decided_us != change.decided_us) return error.InvalidEffect;
                    return previous orelse error.InvalidEffect;
                }
            };
            if (owner_revision != change.expected_revision) return error.StaleEffect;
            if (try self.integer("SELECT count(*) FROM effect_owner_revisions;") >= effects.max_owner_revisions) return error.EffectCapacity;
            if (owner_revision == 0) {
                if (count == effects.max_page or try self.integer("SELECT count(*) FROM effect_owners;") >= effects.max_owners) return error.EffectCapacity;
            }
            const effect_revision = if (previous) |entry| std.math.add(u64, entry.revision, 1) catch return error.EffectCapacity else 1;
            if (effect_revision > std.math.maxInt(i64)) return error.EffectCapacity;
            if (previous == null) {
                if (try self.integer("SELECT count(*) FROM native_effects;") >= effects.max_effects) return error.EffectCapacity;
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
            }
            {
                var owner = try self.statement("INSERT INTO effect_owners VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(scope_key,jail) DO UPDATE SET decision_id=excluded.decision_id,revision=excluded.revision,lease_kind=excluded.lease_kind,deadline_us=excluded.deadline_us,decided_us=excluded.decided_us;");
                defer owner.deinit();
                try owner.blob(1, &key);
                try owner.text(2, change.jail);
                try owner.blob(3, &change.generation);
                try owner.blob(4, &change.decision_id);
                try owner.int(5, @intCast(owner_revision + 1));
                try bindEffectLease(&owner, 6, change.lease);
                try owner.int(8, change.decided_us);
                try owner.done();
            }
            try self.fault(.after_effect_owner);
            return self.replaceEffectIntent(installation, change.scope, key, effect_revision, change.decision_id, now);
        }
        pub fn setOwner(self: *Store, change: effects.OwnerChange, clock: effects.Clock) Error!effects.Entry {
            try self.beginWrite();
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
            change.scope.validate() catch return error.InvalidEffect;
            _ = detection.Name.init(change.jail) catch return error.InvalidEffect;
            if (change.expected_owner_revision == 0 or change.expected_owner_revision >= std.math.maxInt(i64) or change.occurred_us > now or std.mem.allEqual(u8, &change.transition_id, 0)) return error.InvalidEffect;
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
            if (try self.integer("SELECT count(*) FROM effect_owner_revisions;") >= effects.max_owner_revisions) return error.EffectCapacity;
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
        pub fn flushJailOwner(self: *Store, jail: []const u8, generation: effects.Hash, transition_id: effects.Hash, clock: effects.Clock) Error!?effects.Entry {
            _ = detection.Name.init(jail) catch return error.InvalidEffect;
            if (std.mem.allEqual(u8, &transition_id, 0)) return error.InvalidEffect;
            try self.beginWrite();
            errdefer self.rollback();
            try self.effectSchema();
            if (self.schema_version < 19) return error.EffectStorageRequired;
            const now = try self.effectClock(clock);
            var row = try self.statement("SELECT n.canonical_scope,o.revision FROM effect_owners o JOIN native_effects n USING(scope_key) WHERE o.jail=?1 AND o.generation=?2 AND o.lease_kind!=0 ORDER BY o.scope_key LIMIT 1;");
            defer row.deinit();
            try row.text(1, jail);
            try row.blob(2, &generation);
            if (!try row.row()) {
                _ = try self.commitEffectClock(clock);
                try self.commitTransaction();
                return null;
            }
            const scope = (try effects.Scope.decodeCanonical(&try effectBlob(&row, 0, effects.Scope.canonical_encoded_bytes))).canonical;
            const owner_revision_value = try row.signed(1);
            if (owner_revision_value <= 0 or try row.row()) return error.InvalidEffect;
            const result = try self.transitionOwnerTx(.{ .scope = scope, .jail = jail, .current_generation = generation, .next_generation = generation, .expected_owner_revision = @intCast(owner_revision_value), .transition_id = transition_id, .mode = .release, .occurred_us = now }, now);
            _ = try self.commitEffectClock(clock);
            try self.commitEffectTransaction(result.changed);
            return result.entry;
        }
        fn checkedEffectToken(self: *Store, token: effects.Token) Error!effects.Entry {
            const installation = try self.readInstallation() orelse return error.InstallationRequired;
            if (!std.mem.eql(u8, &installation.id, &token.installation)) return error.InstallationMismatch;
            const entry = try self.readEffect(token.scope_key, installation) orelse return error.StaleEffect;
            if (entry.revision != token.revision or !std.mem.eql(u8, &entry.intent_id, &token.intent_id)) return error.StaleEffect;
            return entry;
        }
        pub fn markDispatched(self: *Store, token: effects.Token, clock: effects.Clock) Error!void {
            try self.beginWrite();
            errdefer self.rollback();
            const entry = try self.checkedEffectToken(token);
            if (entry.status == .dispatched) return error.EffectReconciliationRequired;
            if (entry.status != .pending) return error.StaleEffect;
            const now = try self.effectClock(clock);
            if (entry.desired == .finite and !entry.desired.live(now)) return error.EffectExpired;
            var row = try self.statement("UPDATE effect_intents SET status=2,dispatch_us=?2,observed_us=NULL,fingerprint=NULL WHERE intent_id=?1 AND status=1;");
            defer row.deinit();
            try row.blob(1, &token.intent_id);
            try row.int(2, now);
            try row.done();
            if (self.api.changes(self.db) != 1) return error.StaleEffect;
            try self.advanceEffectSnapshot();
            try self.fault(.before_effect_dispatch_commit);
            const final = try self.commitEffectClock(clock);
            if (entry.desired == .finite and !entry.desired.live(final)) return error.EffectExpired;
            try self.commitEffectTransaction(true);
        }
        pub fn settleVerified(self: *Store, token: effects.Token, observation: effects.Observation, clock: effects.Clock) Error!effects.Settlement {
            if (observation.qualification != .complete_owned or !std.mem.eql(u8, &observation.installation, &token.installation) or !std.mem.eql(u8, &observation.scope_key, &token.scope_key)) return error.IncompleteEffectObservation;
            try self.beginWrite();
            errdefer self.rollback();
            const entry = try self.checkedEffectToken(token);
            if (entry.status != .dispatched and entry.status != .applied and entry.status != .absent and entry.status != .expired) return error.StaleEffect;
            const now = try self.effectClock(clock);
            if (observation.observed_us > now) return error.InvalidEffect;
            var dispatch = try self.statement("SELECT dispatch_us,observed_us,fingerprint FROM effect_intents WHERE intent_id=?1;");
            defer dispatch.deinit();
            try dispatch.blob(1, &token.intent_id);
            if (!try dispatch.row() or observation.observed_us < (try dispatch.optionalSigned(0) orelse return error.InvalidEffect)) return error.InvalidEffect;
            const previous_observed = try dispatch.optionalSigned(1);
            if (previous_observed) |previous| {
                if (observation.observed_us < previous) return error.StaleEffect;
                if (observation.observed_us == previous and !std.mem.eql(u8, &observation.fingerprint, &try effectBlob(&dispatch, 2, 32))) return error.StaleEffect;
            }
            const expired = entry.desired == .finite and !entry.desired.live(now);
            const matches = if (observation.state) |state| effects.Lease.eql(entry.desired, state) else false;
            const status: effects.Status = if (expired) .expired else if (!matches) .pending else if (entry.desired == .absent) .absent else .applied;
            if (previous_observed != null and observation.observed_us == previous_observed.? and status != entry.status) return error.StaleEffect;
            var stamps: [16]u8 = undefined;
            const dispatch_time = (try dispatch.optionalSigned(0)).?;
            std.mem.writeInt(i64, stamps[0..8], dispatch_time, .little);
            std.mem.writeInt(i64, stamps[8..16], observation.observed_us, .little);
            var observed_state: [10]u8 = [_]u8{0} ** 10;
            observed_state[0] = if (observation.state) |state| @intFromEnum(state) else 3;
            if (observation.state) |state| if (state == .finite) {
                std.mem.writeInt(i64, observed_state[1..9], state.finite, .little);
            };
            observed_state[9] = @intFromEnum(status);
            const observation_id = effects.hashParts("fail2zig-native-effect-observation-v1", &.{ &token.intent_id, &stamps, &observation.fingerprint, &observed_state });
            {
                var prior = try self.statement("SELECT 1 FROM effect_observations WHERE observation_id=?1;");
                defer prior.deinit();
                try prior.blob(1, &observation_id);
                if (!try prior.row()) {
                    if (try self.integer("SELECT count(*) FROM effect_observations;") >= effects.max_observations) return error.EffectCapacity;
                    var receipt = try self.statement("INSERT INTO effect_observations VALUES(?1,?2,?3,?4,?5,?6,?7,?8);");
                    defer receipt.deinit();
                    try receipt.blob(1, &observation_id);
                    try receipt.blob(2, &token.intent_id);
                    try receipt.int(3, dispatch_time);
                    try receipt.int(4, observation.observed_us);
                    try receipt.blob(5, &observation.fingerprint);
                    try receipt.int(6, observed_state[0]);
                    if (observation.state) |state| if (state == .finite) {
                        try receipt.int(7, state.finite);
                    };
                    try receipt.int(8, @intFromEnum(status));
                    try receipt.done();
                }
            }
            var row = try self.statement("UPDATE effect_intents SET status=?2,observed_us=?3,fingerprint=?4 WHERE intent_id=?1;");
            defer row.deinit();
            try row.blob(1, &token.intent_id);
            try row.int(2, @intFromEnum(status));
            try row.int(3, observation.observed_us);
            try row.blob(4, &observation.fingerprint);
            try row.done();
            if (status == .applied) {
                var owners: [effects.max_page]effects.Owner = undefined;
                const count = try self.readOwners(token.scope_key, &owners);
                for (owners[0..count]) |owner| if (owner.lease.live(now)) {
                    const event_id = effects.hashParts("fail2zig-native-confirmed-owner-v1", &.{ &token.installation, &token.scope_key, owner.jail.slice(), &owner.decision_id });
                    var existing = try self.statement("SELECT event_id FROM confirmed_effect_events WHERE scope_key=?1 AND jail=?2 AND decision_id=?3;");
                    defer existing.deinit();
                    try existing.blob(1, &token.scope_key);
                    try existing.text(2, owner.jail.slice());
                    try existing.blob(3, &owner.decision_id);
                    if (try existing.row()) {
                        if (!std.mem.eql(u8, &event_id, &try effectBlob(&existing, 0, 32))) return error.InvalidEffect;
                        continue;
                    }
                    if (try self.integer("SELECT count(*) FROM confirmed_effect_events;") >= effects.max_confirmed_events) return error.EffectCapacity;
                    var event = try self.statement("INSERT INTO confirmed_effect_events VALUES(?1,?2,?3,?4,?5) ON CONFLICT(scope_key,jail,decision_id) DO NOTHING;");
                    defer event.deinit();
                    try event.blob(1, &event_id);
                    try event.blob(2, &token.scope_key);
                    try event.text(3, owner.jail.slice());
                    try event.blob(4, &owner.decision_id);
                    try event.int(5, observation.observed_us);
                    try event.done();
                    if (self.schema_version >= 17) {
                        var detail_inserted = false;
                        var detail = try self.statement("INSERT INTO confirmed_event_details(event_id,source,occurrence,decided_us,ordinal,evidence) SELECT ?1,source,occurrence,decided_us,ordinal,evidence FROM retry_decision_details WHERE jail=?2 AND effect_decision_id=?3;");
                        defer detail.deinit();
                        try detail.blob(1, &event_id);
                        try detail.text(2, owner.jail.slice());
                        try detail.blob(3, &owner.decision_id);
                        try detail.done();
                        if (self.api.changes(self.db) > 1) return error.InvalidApplicationHistoryRow;
                        detail_inserted = self.api.changes(self.db) == 1;
                        if (self.schema_version >= 18 and detail_inserted) {
                            var summary = try self.statement("INSERT INTO confirmed_policy_summaries(jail,family,subject,confirmed_count,latest_confirmed_us) SELECT jail,family,subject,1,?3 FROM retry_decision_details WHERE jail=?1 AND effect_decision_id=?2 ON CONFLICT(jail,family,subject) DO UPDATE SET confirmed_count=confirmed_count+1,latest_confirmed_us=max(latest_confirmed_us,excluded.latest_confirmed_us);");
                            defer summary.deinit();
                            try summary.text(1, owner.jail.slice());
                            try summary.blob(2, &owner.decision_id);
                            try summary.int(3, observation.observed_us);
                            try summary.done();
                            if (self.api.changes(self.db) != 1) return error.InvalidRetryState;
                        }
                    }
                    if (self.schema_version >= 13) {
                        var sequenced = try self.statement("SELECT s.event_id FROM confirmed_history_stream h JOIN confirmed_history_sequence s ON s.sequence=h.head WHERE h.id=1;");
                        defer sequenced.deinit();
                        if (!try sequenced.row() or !std.mem.eql(u8, &try effectBlob(&sequenced, 0, 32), &event_id)) return error.HistoryGap;
                    }
                };
            }
            try self.advanceEffectSnapshot();
            try self.fault(.before_effect_receipt_commit);
            const final = try self.commitEffectClock(clock);
            if (status == .applied and entry.desired == .finite and !entry.desired.live(final)) return error.EffectExpired;
            try self.commitEffectTransaction(true);
            return if (expired) .expired else if (matches) .verified else .retry_same_intent;
        }
        pub fn prepareExpiry(self: *Store, key: effects.Hash, expected_revision: u64, clock: effects.Clock) Error!effects.Entry {
            try self.beginWrite();
            errdefer self.rollback();
            const installation = try self.readInstallation() orelse return error.InstallationRequired;
            const prior = try self.readEffect(key, installation) orelse return error.StaleEffect;
            if (prior.revision != expected_revision) return error.StaleEffect;
            if (prior.status == .dispatched) return error.EffectReconciliationRequired;
            const now = try self.effectClock(clock);
            var owners: [effects.max_page]effects.Owner = undefined;
            const count = try self.readOwners(key, &owners);
            var expired: u64 = 0;
            var expiring_count: u64 = 0;
            for (owners[0..count]) |owner| if (owner.lease == .finite and !owner.lease.live(now)) {
                expiring_count += 1;
            };
            if (try self.integer("SELECT count(*) FROM effect_owner_revisions;") > effects.max_owner_revisions - expiring_count) return error.EffectCapacity;
            for (owners[0..count]) |owner| if (owner.lease == .finite and !owner.lease.live(now)) {
                if (owner.revision == std.math.maxInt(i64)) return error.EffectCapacity;
                var row = try self.statement("UPDATE effect_owners SET lease_kind=0,deadline_us=NULL,revision=revision+1 WHERE scope_key=?1 AND jail=?2;");
                defer row.deinit();
                try row.blob(1, &key);
                try row.text(2, owner.jail.slice());
                try row.done();
                expired += 1;
            };
            var entry = prior;
            if (expired != 0) {
                const effect_revision = std.math.add(u64, prior.revision, expired) catch return error.EffectCapacity;
                if (effect_revision > std.math.maxInt(i64)) return error.EffectCapacity;
                entry = try self.replaceEffectIntent(installation, prior.scope, key, effect_revision, prior.intent_id, now);
            }
            _ = try self.commitEffectClock(clock);
            try self.commitEffectTransaction(expired != 0);
            return entry;
        }
        pub fn confirmedEffectEvents(self: *Store) Error!u64 {
            const count = try self.integer("SELECT count(*) FROM confirmed_effect_events;");
            return std.math.cast(u64, count) orelse error.InvalidEffect;
        }
        pub fn ownerRevision(self: *Store, key: effects.Hash, jail: []const u8, owner_revision: u64) Error!?effects.Owner {
            if (owner_revision == 0 or owner_revision > std.math.maxInt(i64)) return error.InvalidEffect;
            var row = try self.statement("SELECT generation,decision_id,lease_kind,deadline_us,decided_us FROM effect_owner_revisions WHERE scope_key=?1 AND jail=?2 AND revision=?3;");
            defer row.deinit();
            try row.blob(1, &key);
            try row.text(2, jail);
            try row.int(3, @intCast(owner_revision));
            if (!try row.row()) return null;
            const lease = try effectLease(&row, 2, 3);
            const decided = try row.signed(4);
            if (lease == .finite and lease.finite <= decided) return error.InvalidEffect;
            return .{ .jail = detection.Name.init(jail) catch return error.InvalidEffect, .generation = try effectBlob(&row, 0, 32), .decision_id = try effectBlob(&row, 1, 32), .revision = owner_revision, .lease = lease, .decided_us = decided };
        }
    };
}
