// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const store = @import("store.zig");
const Error = store.Error;
const Stmt = store.Stmt;
const Limits = store.Limits;
const Record = store.Record;
const ReceiptIdentity = store.ReceiptIdentity;
const latest_schema = store.latest_schema;
const native_time = @import("../core/native_time.zig");
const native_record = @import("../core/native_time_record.zig");
const detection = @import("../core/native_detection_record.zig");
const retry = @import("../core/native_retry.zig");
const consumers = @import("../core/native_consumer.zig");
const effects = @import("../core/native_effect.zig");
const effect_history = @import("../core/native_effect_history.zig");
const application_history = @import("../core/native_application_history.zig");
const action_outcome = @import("../core/native_action_outcome.zig");

pub fn Methods(comptime Store: type) type {
    return struct {
        pub fn enableReceipts(self: *Store, maximum_pending: usize) Error!void {
            if (maximum_pending == 0 or maximum_pending > Limits.pending_receipts) return error.ReceiptLimit;
            try self.beginWrite();
            errdefer self.rollback();
            const schema = try self.integer("PRAGMA user_version;");
            if (schema == 2) {
                try self.exec(
                    \\CREATE TABLE pending_receipts(jail TEXT NOT NULL,source TEXT NOT NULL,generation BLOB NOT NULL CHECK(length(generation)=32),occurrence TEXT NOT NULL,raw_hash BLOB NOT NULL CHECK(length(raw_hash)=32),cursor BLOB NOT NULL,receipt_us INTEGER NOT NULL CHECK(typeof(receipt_us)='integer'),PRIMARY KEY(jail,source));
                    \\ALTER TABLE records ADD COLUMN receipt_us INTEGER CHECK(receipt_us IS NULL OR typeof(receipt_us)='integer');
                    \\ALTER TABLE records ADD COLUMN receipt_generation BLOB CHECK((receipt_generation IS NULL AND receipt_us IS NULL) OR (receipt_generation IS NOT NULL AND length(receipt_generation)=32 AND receipt_us IS NOT NULL));
                    \\PRAGMA user_version=3;
                );
            } else if (schema < 3 or schema > latest_schema) return error.UnsupportedSchema;
            if (try self.integer("SELECT count(*) FROM pending_receipts;") > maximum_pending) return error.ReceiptLimit;
            try self.fault(.before_receipt_schema_commit);
            try self.commitTransaction();
            self.schema_version = @max(schema, 3);
            self.receipt_limit = maximum_pending;
        }

        pub fn validateReceiptIdentity(identity: ReceiptIdentity) Error!void {
            if (identity.jail.len == 0 or identity.jail.len > 4096 or identity.source.len == 0 or identity.source.len > Limits.source_bytes or
                identity.occurrence.len == 0 or identity.occurrence.len > 16384 or identity.cursor.len == 0 or identity.cursor.len > Limits.cursor_bytes)
                return error.InvalidRecord;
        }

        pub fn enableNativeTime(self: *Store) Error!void {
            if (self.receipt_limit == null) return error.ReceiptStorageRequired;
            try self.beginWrite();
            errdefer self.rollback();
            const schema = try self.integer("PRAGMA user_version;");
            if (schema == 3) {
                try self.exec(
                    \\ALTER TABLE records ADD COLUMN native_time_kind INTEGER CHECK(native_time_kind IS NULL OR (typeof(native_time_kind)='integer' AND native_time_kind BETWEEN 1 AND 11 AND receipt_us IS NOT NULL));
                    \\ALTER TABLE records ADD COLUMN original_us INTEGER CHECK(original_us IS NULL OR (typeof(original_us)='integer' AND native_time_kind IS NOT NULL));
                    \\ALTER TABLE records ADD COLUMN effective_us INTEGER CHECK(effective_us IS NULL OR (typeof(effective_us)='integer' AND native_time_kind BETWEEN 1 AND 6));
                    \\PRAGMA user_version=4;
                );
            } else if (schema < 4 or schema > latest_schema) return error.UnsupportedSchema;
            try self.fault(.before_native_time_schema_commit);
            try self.commitTransaction();
            self.schema_version = @max(schema, 4);
        }

        pub fn enableYearInference(self: *Store) Error!void {
            if (self.receipt_limit == null) return error.ReceiptStorageRequired;
            try self.beginWrite();
            errdefer self.rollback();
            const schema = try self.integer("PRAGMA user_version;");
            if (schema == 4) {
                try self.exec("ALTER TABLE records ADD COLUMN inferred_year INTEGER CHECK(inferred_year IS NULL OR (typeof(inferred_year)='integer' AND inferred_year BETWEEN 1 AND 9999 AND original_us IS NOT NULL AND native_time_kind IN (1,3,4,6,11))); PRAGMA user_version=5;");
            } else if (schema < 5 or schema > latest_schema) return error.UnsupportedSchema;
            try self.fault(.before_inference_schema_commit);
            try self.commitTransaction();
            self.schema_version = @max(schema, 5);
        }

        pub fn enableDetection(self: *Store) Error!void {
            if (self.receipt_limit == null) return error.ReceiptStorageRequired;
            try self.beginWrite();
            errdefer self.rollback();
            const schema = try self.integer("PRAGMA user_version;");
            if (schema < 4 or schema > latest_schema) return error.UnsupportedSchema;
            if (schema == 4) try self.exec("ALTER TABLE records ADD COLUMN inferred_year INTEGER CHECK(inferred_year IS NULL OR (typeof(inferred_year)='integer' AND inferred_year BETWEEN 1 AND 9999 AND original_us IS NOT NULL AND native_time_kind IN (1,3,4,6,11)));");
            if (schema < 6) try self.exec(
                \\CREATE TABLE record_detections(
                \\jail TEXT NOT NULL,source TEXT NOT NULL,occurrence TEXT NOT NULL,
                \\version INTEGER NOT NULL CHECK(typeof(version)='integer' AND version=1),
                \\kind INTEGER NOT NULL CHECK(typeof(kind)='integer' AND kind BETWEEN 1 AND 6),
                \\generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=32),
                \\filter TEXT NOT NULL CHECK(typeof(filter)='text' AND length(filter) BETWEEN 1 AND 64),
                \\pattern TEXT CHECK(pattern IS NULL OR (typeof(pattern)='text' AND length(pattern) BETWEEN 1 AND 64)),
                \\pattern_index INTEGER CHECK(pattern_index IS NULL OR (typeof(pattern_index)='integer' AND pattern_index BETWEEN 0 AND 65535)),
                \\family INTEGER CHECK(family IS NULL OR (typeof(family)='integer' AND family IN (4,6))),
                \\subject BLOB CHECK(subject IS NULL OR (typeof(subject)='blob' AND ((family=4 AND length(subject)=4) OR (family=6 AND length(subject)=16)))),
                \\CHECK((kind<=3 AND pattern IS NULL AND pattern_index IS NULL AND family IS NULL AND subject IS NULL) OR (kind>=4 AND pattern IS NOT NULL AND pattern_index IS NOT NULL AND family IS NOT NULL AND subject IS NOT NULL)),
                \\PRIMARY KEY(jail,source,occurrence),FOREIGN KEY(jail,source,occurrence) REFERENCES records(jail,source,occurrence));
                \\PRAGMA user_version=6;
            );
            try self.fault(.before_detection_schema_commit);
            try self.commitTransaction();
            self.schema_version = @max(schema, 6);
        }

        pub fn enableClockRecovery(self: *Store) Error!void {
            if (self.receipt_limit == null) return error.ReceiptStorageRequired;
            try self.beginWrite();
            errdefer self.rollback();
            const schema = try self.integer("PRAGMA user_version;");
            if (schema < 6 or schema > latest_schema) return error.UnsupportedSchema;
            if (schema == 6) {
                if (try self.integer("SELECT EXISTS(SELECT 1 FROM records WHERE receipt_us IS NOT NULL AND typeof(receipt_us)!='integer') OR EXISTS(SELECT 1 FROM pending_receipts WHERE typeof(receipt_us)!='integer');") != 0) return error.DatabaseFailure;
                try self.exec(
                    \\CREATE TABLE receipt_clock(id INTEGER PRIMARY KEY CHECK(id=1),floor_us INTEGER CHECK(floor_us IS NULL OR typeof(floor_us)='integer'));
                    \\INSERT INTO receipt_clock SELECT 1,MAX(value) FROM (SELECT MAX(receipt_us) AS value FROM records UNION ALL SELECT MAX(receipt_us) FROM pending_receipts);
                    \\PRAGMA user_version=7;
                );
            }
            _ = try self.readReceiptClock();
            try self.fault(.before_clock_schema_commit);
            try self.commitTransaction();
            self.schema_version = @max(schema, 7);
        }

        pub fn enableJournalDetection(self: *Store) Error!void {
            if (self.receipt_limit == null) return error.ReceiptStorageRequired;
            try self.beginWrite();
            errdefer self.rollback();
            const schema = try self.integer("PRAGMA user_version;");
            if (schema < 7 or schema > latest_schema) return error.UnsupportedSchema;
            _ = try self.readReceiptClock();
            if (schema == 7) {
                if (try self.integer("SELECT EXISTS(SELECT 1 FROM record_detections WHERE kind NOT BETWEEN 1 AND 6);") != 0) return error.DatabaseFailure;
                try self.exec(
                    \\CREATE TABLE record_detections_v8(
                    \\jail TEXT NOT NULL,source TEXT NOT NULL,occurrence TEXT NOT NULL,
                    \\version INTEGER NOT NULL CHECK(typeof(version)='integer' AND version=1),
                    \\kind INTEGER NOT NULL CHECK(typeof(kind)='integer' AND kind BETWEEN 1 AND 12),
                    \\generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=32),
                    \\filter TEXT NOT NULL CHECK(typeof(filter)='text' AND length(filter) BETWEEN 1 AND 64),
                    \\pattern TEXT CHECK(pattern IS NULL OR (typeof(pattern)='text' AND length(pattern) BETWEEN 1 AND 64)),
                    \\pattern_index INTEGER CHECK(pattern_index IS NULL OR (typeof(pattern_index)='integer' AND pattern_index BETWEEN 0 AND 65535)),
                    \\family INTEGER CHECK(family IS NULL OR (typeof(family)='integer' AND family IN (4,6))),
                    \\subject BLOB CHECK(subject IS NULL OR (typeof(subject)='blob' AND ((family=4 AND length(subject)=4) OR (family=6 AND length(subject)=16)))),
                    \\CHECK(((kind<=3 OR kind>=7) AND pattern IS NULL AND pattern_index IS NULL AND family IS NULL AND subject IS NULL) OR (kind BETWEEN 4 AND 6 AND pattern IS NOT NULL AND pattern_index IS NOT NULL AND family IS NOT NULL AND subject IS NOT NULL)),
                    \\PRIMARY KEY(jail,source,occurrence),FOREIGN KEY(jail,source,occurrence) REFERENCES records(jail,source,occurrence));
                    \\INSERT INTO record_detections_v8 SELECT * FROM record_detections;
                    \\DROP TABLE record_detections;
                    \\ALTER TABLE record_detections_v8 RENAME TO record_detections;
                    \\PRAGMA user_version=8;
                );
            }
            try self.fault(.before_journal_detection_schema_commit);
            try self.commitTransaction();
            self.schema_version = @max(schema, 8);
        }

        pub fn enableRetry(self: *Store) Error!void {
            if (self.receipt_limit == null) return error.ReceiptStorageRequired;
            try self.beginWrite();
            errdefer self.rollback();
            const schema = try self.integer("PRAGMA user_version;");
            if (schema < 8 or schema > latest_schema) return error.UnsupportedSchema;
            if (schema == 8) try self.exec(
                \\CREATE TABLE retry_policies(jail TEXT PRIMARY KEY NOT NULL,generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=32),policy BLOB NOT NULL CHECK(typeof(policy)='blob' AND length(policy)=32));
                \\CREATE TABLE retry_clock(id INTEGER PRIMARY KEY CHECK(id=1),floor_us INTEGER CHECK(floor_us IS NULL OR typeof(floor_us)='integer'));
                \\INSERT INTO retry_clock VALUES(1,NULL);
                \\CREATE TABLE retry_states(jail TEXT NOT NULL,family INTEGER NOT NULL CHECK(typeof(family)='integer' AND family IN (4,6)),subject BLOB NOT NULL CHECK(typeof(subject)='blob' AND length(subject)=CASE family WHEN 4 THEN 4 ELSE 16 END),last_processed_us INTEGER NOT NULL CHECK(typeof(last_processed_us)='integer'),expiry_us INTEGER CHECK(expiry_us IS NULL OR typeof(expiry_us)='integer'),decisions INTEGER NOT NULL CHECK(typeof(decisions)='integer' AND decisions>=0),attempts BLOB NOT NULL CHECK(typeof(attempts)='blob' AND length(attempts)<=5120 AND length(attempts)%40=0),PRIMARY KEY(jail,family,subject),FOREIGN KEY(jail) REFERENCES retry_policies(jail));
                \\CREATE TABLE retry_decisions(jail TEXT NOT NULL,source TEXT NOT NULL,occurrence TEXT NOT NULL,family INTEGER NOT NULL CHECK(typeof(family)='integer' AND family IN (4,6)),subject BLOB NOT NULL CHECK(typeof(subject)='blob' AND length(subject)=CASE family WHEN 4 THEN 4 ELSE 16 END),decided_us INTEGER NOT NULL CHECK(typeof(decided_us)='integer'),expiry_us INTEGER NOT NULL CHECK(typeof(expiry_us)='integer' AND expiry_us>decided_us),ordinal INTEGER NOT NULL CHECK(typeof(ordinal)='integer' AND ordinal>0),enforce INTEGER NOT NULL CHECK(typeof(enforce)='integer' AND enforce IN (0,1)),PRIMARY KEY(jail,source,occurrence),FOREIGN KEY(jail,source,occurrence) REFERENCES records(jail,source,occurrence));
                \\PRAGMA user_version=9;
            );
            try self.fault(.before_retry_schema_commit);
            try self.commitTransaction();
            self.schema_version = @max(schema, 9);
        }

        pub fn enableConsumers(self: *Store) Error!void {
            try self.beginWrite();
            errdefer self.rollback();
            const schema = try self.integer("PRAGMA user_version;");
            if (schema < 9 or schema > latest_schema) return error.UnsupportedSchema;
            if (schema == 9) try self.exec(
                \\CREATE TABLE consumer_checkpoints(kind INTEGER NOT NULL CHECK(typeof(kind)='integer' AND kind BETWEEN 1 AND 5),jail TEXT NOT NULL,source TEXT NOT NULL,rule TEXT NOT NULL,generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=32),format INTEGER NOT NULL CHECK(typeof(format)='integer' AND format BETWEEN 1 AND 65535),revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision>0),payload BLOB NOT NULL CHECK(typeof(payload)='blob' AND length(payload)<=65536),valid_until_us INTEGER CHECK(valid_until_us IS NULL OR typeof(valid_until_us)='integer'),PRIMARY KEY(kind,jail,source,rule,generation));
                \\CREATE TABLE consumer_clock(id INTEGER PRIMARY KEY CHECK(id=1),floor_us INTEGER CHECK(floor_us IS NULL OR typeof(floor_us)='integer'));
                \\INSERT INTO consumer_clock VALUES(1,NULL);
                \\PRAGMA user_version=10;
            );
            try self.fault(.before_consumer_schema_commit);
            try self.commitTransaction();
            self.schema_version = @max(schema, 10);
        }

        pub fn enableConsumerManifests(self: *Store) Error!void {
            try self.beginWrite();
            errdefer self.rollback();
            const schema = try self.integer("PRAGMA user_version;");
            if (schema < 11 or schema > latest_schema) return error.UnsupportedSchema;
            if (schema == 11) try self.exec(
                \\CREATE TABLE record_detections_v12(
                \\jail TEXT NOT NULL,source TEXT NOT NULL,occurrence TEXT NOT NULL,ordinal INTEGER NOT NULL CHECK(typeof(ordinal)='integer' AND ordinal BETWEEN 0 AND 15),
                \\version INTEGER NOT NULL CHECK(typeof(version)='integer' AND version=1),
                \\kind INTEGER NOT NULL CHECK(typeof(kind)='integer' AND kind BETWEEN 1 AND 12),
                \\generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=32),
                \\filter TEXT NOT NULL CHECK(typeof(filter)='text' AND length(filter) BETWEEN 1 AND 64),
                \\pattern TEXT CHECK(pattern IS NULL OR (typeof(pattern)='text' AND length(pattern) BETWEEN 1 AND 64)),
                \\pattern_index INTEGER CHECK(pattern_index IS NULL OR (typeof(pattern_index)='integer' AND pattern_index BETWEEN 0 AND 65535)),
                \\family INTEGER CHECK(family IS NULL OR (typeof(family)='integer' AND family IN (4,6))),
                \\subject BLOB CHECK(subject IS NULL OR (typeof(subject)='blob' AND ((family=4 AND length(subject)=4) OR (family=6 AND length(subject)=16)))),
                \\CHECK(((kind<=3 OR kind>=7) AND pattern IS NULL AND pattern_index IS NULL AND family IS NULL AND subject IS NULL) OR (kind BETWEEN 4 AND 6 AND pattern IS NOT NULL AND pattern_index IS NOT NULL AND family IS NOT NULL AND subject IS NOT NULL)),
                \\PRIMARY KEY(jail,source,occurrence,ordinal),FOREIGN KEY(jail,source,occurrence) REFERENCES records(jail,source,occurrence));
                \\INSERT INTO record_detections_v12 SELECT jail,source,occurrence,0,version,kind,generation,filter,pattern,pattern_index,family,subject FROM record_detections;
                \\DROP TABLE record_detections;
                \\ALTER TABLE record_detections_v12 RENAME TO record_detections;
                \\CREATE TABLE retry_decisions_v12(jail TEXT NOT NULL,source TEXT NOT NULL,occurrence TEXT NOT NULL,family INTEGER NOT NULL CHECK(typeof(family)='integer' AND family IN (4,6)),subject BLOB NOT NULL CHECK(typeof(subject)='blob' AND length(subject)=CASE family WHEN 4 THEN 4 ELSE 16 END),decided_us INTEGER NOT NULL CHECK(typeof(decided_us)='integer'),expiry_us INTEGER NOT NULL CHECK(typeof(expiry_us)='integer' AND expiry_us>decided_us),ordinal INTEGER NOT NULL CHECK(typeof(ordinal)='integer' AND ordinal>0),enforce INTEGER NOT NULL CHECK(typeof(enforce)='integer' AND enforce IN (0,1)),PRIMARY KEY(jail,source,occurrence,family,subject),FOREIGN KEY(jail,source,occurrence) REFERENCES records(jail,source,occurrence));
                \\INSERT INTO retry_decisions_v12 SELECT * FROM retry_decisions;
                \\DROP TABLE retry_decisions;
                \\ALTER TABLE retry_decisions_v12 RENAME TO retry_decisions;
                \\CREATE TABLE consumer_manifests(jail TEXT NOT NULL,source TEXT NOT NULL,generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=32),digest BLOB NOT NULL CHECK(typeof(digest)='blob' AND length(digest)=32),ready INTEGER NOT NULL CHECK(typeof(ready)='integer' AND ready IN(0,1)),required_count INTEGER NOT NULL CHECK(typeof(required_count)='integer' AND required_count BETWEEN 0 AND 16),PRIMARY KEY(jail,source));
                \\CREATE TABLE consumer_requirements(manifest_jail TEXT NOT NULL,manifest_source TEXT NOT NULL,kind INTEGER NOT NULL,jail TEXT NOT NULL,source TEXT NOT NULL,rule TEXT NOT NULL,generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=32),format INTEGER NOT NULL CHECK(typeof(format)='integer' AND format BETWEEN 1 AND 65535),PRIMARY KEY(manifest_jail,manifest_source,kind,jail,source,rule,generation),FOREIGN KEY(manifest_jail,manifest_source) REFERENCES consumer_manifests(jail,source));
                \\CREATE INDEX consumer_requirement_identity ON consumer_requirements(kind,jail,source,rule,generation,format);
                \\CREATE TABLE consumer_revision(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision>=0));
                \\INSERT INTO consumer_revision VALUES(1,0);
                \\PRAGMA user_version=12;
            );
            try self.fault(.before_manifest_schema_commit);
            try self.commitTransaction();
            self.schema_version = @max(schema, 12);
        }

        pub fn enableConfirmedHistory(self: *Store) Error!void {
            try self.beginWrite();
            errdefer self.rollback();
            const schema = try self.integer("PRAGMA user_version;");
            if (schema < 12 or schema > latest_schema) return error.UnsupportedSchema;
            if (schema == 12) {
                if (try self.integer("SELECT count(*) FROM confirmed_effect_events;") > effects.max_confirmed_events) return error.EffectCapacity;
                if (try self.integer("SELECT EXISTS(SELECT 1 FROM consumer_checkpoints WHERE kind=5) OR EXISTS(SELECT 1 FROM consumer_requirements WHERE kind=5);") != 0) return error.ConsumerMigrationRequired;
                try self.exec(
                    \\CREATE TABLE confirmed_history_stream(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision>=0 AND revision<9223372036854775807),head INTEGER NOT NULL CHECK(typeof(head)='integer' AND head>=0 AND head<9223372036854775807),retained_from INTEGER NOT NULL CHECK(typeof(retained_from)='integer' AND retained_from>=1 AND retained_from<=head+1));
                    \\INSERT INTO confirmed_history_stream VALUES(1,1,0,1);
                    \\CREATE TABLE confirmed_history_sequence(sequence INTEGER PRIMARY KEY CHECK(sequence>0),event_id BLOB UNIQUE NOT NULL CHECK(typeof(event_id)='blob' AND length(event_id)=32),FOREIGN KEY(event_id) REFERENCES confirmed_effect_events(event_id));
                    \\INSERT INTO confirmed_history_sequence SELECT row_number() OVER(ORDER BY confirmed_us,event_id),event_id FROM confirmed_effect_events;
                    \\UPDATE confirmed_history_stream SET head=(SELECT count(*) FROM confirmed_history_sequence),revision=1+(SELECT count(*) FROM confirmed_history_sequence) WHERE id=1;
                    \\CREATE TRIGGER confirmed_history_append AFTER INSERT ON confirmed_effect_events BEGIN SELECT CASE WHEN (SELECT count(*) FROM confirmed_history_stream WHERE id=1)!=1 THEN RAISE(ABORT,'missing confirmed history stream') END; UPDATE confirmed_history_stream SET head=head+1,revision=revision+1 WHERE id=1; INSERT INTO confirmed_history_sequence SELECT head,NEW.event_id FROM confirmed_history_stream WHERE id=1; END;
                    \\PRAGMA user_version=13;
                );
            }
            try self.fault(.before_consumer_input_commit);
            try self.commitTransaction();
            self.schema_version = @max(schema, 13);
        }

        pub fn enableMaintenance(self: *Store) Error!void {
            try self.beginWrite();
            errdefer self.rollback();
            const schema = try self.integer("PRAGMA user_version;");
            if (schema < 13 or schema > latest_schema) return error.UnsupportedSchema;
            if (schema == 13) try self.exec(
                \\CREATE TABLE source_maintenance(jail TEXT NOT NULL,source TEXT NOT NULL,generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=32),head_sequence INTEGER NOT NULL CHECK(typeof(head_sequence)='integer' AND head_sequence>=1 AND head_sequence<9223372036854775807),reject_below_sequence INTEGER NOT NULL CHECK(typeof(reject_below_sequence)='integer' AND reject_below_sequence>=1 AND reject_below_sequence<=head_sequence+1),cleanup_revision INTEGER NOT NULL CHECK(typeof(cleanup_revision)='integer' AND cleanup_revision>=0),sweep_sequence INTEGER NOT NULL CHECK(typeof(sweep_sequence)='integer' AND sweep_sequence>=0 AND sweep_sequence<reject_below_sequence),PRIMARY KEY(jail,source,generation));
                \\ALTER TABLE records ADD COLUMN source_generation BLOB;
                \\ALTER TABLE records ADD COLUMN source_sequence INTEGER;
                \\CREATE UNIQUE INDEX records_source_order ON records(jail,source,source_generation,source_sequence) WHERE source_sequence IS NOT NULL;
                \\CREATE TRIGGER records_source_order_insert BEFORE INSERT ON records WHEN NOT ((NEW.source_generation IS NULL AND NEW.source_sequence IS NULL) OR (typeof(NEW.source_generation)='blob' AND length(NEW.source_generation)=32 AND typeof(NEW.source_sequence)='integer' AND NEW.source_sequence>0)) BEGIN SELECT RAISE(ABORT,'invalid source order'); END;
                \\CREATE TRIGGER records_source_order_update BEFORE UPDATE OF source_generation,source_sequence ON records WHEN NOT ((NEW.source_generation IS NULL AND NEW.source_sequence IS NULL) OR (typeof(NEW.source_generation)='blob' AND length(NEW.source_generation)=32 AND typeof(NEW.source_sequence)='integer' AND NEW.source_sequence>0)) BEGIN SELECT RAISE(ABORT,'invalid source order'); END;
                \\CREATE TABLE replay_guards(jail TEXT NOT NULL,source TEXT NOT NULL,generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=32),occurrence_key BLOB NOT NULL CHECK(typeof(occurrence_key)='blob' AND length(occurrence_key)=32),identity_key BLOB NOT NULL CHECK(typeof(identity_key)='blob' AND length(identity_key)=32),receipt_us INTEGER CHECK(receipt_us IS NULL OR typeof(receipt_us)='integer'),source_sequence INTEGER NOT NULL CHECK(typeof(source_sequence)='integer' AND source_sequence>0),PRIMARY KEY(jail,source,generation,occurrence_key),UNIQUE(jail,source,occurrence_key),UNIQUE(jail,source,generation,source_sequence),FOREIGN KEY(jail,source,generation) REFERENCES source_maintenance(jail,source,generation));
                \\PRAGMA user_version=14;
            );
            try self.fault(.before_maintenance_schema_commit);
            try self.commitTransaction();
            self.schema_version = @max(schema, 14);
        }

        pub fn enableCleanup(self: *Store) Error!void {
            try self.beginWrite();
            errdefer self.rollback();
            const schema = try self.integer("PRAGMA user_version;");
            if (schema < 14 or schema > latest_schema) return error.UnsupportedSchema;
            if (schema == 14) try self.exec(
                \\CREATE TABLE maintenance_clock(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision>=0),floor_us INTEGER CHECK(floor_us IS NULL OR typeof(floor_us)='integer'));
                \\INSERT INTO maintenance_clock VALUES(1,0,NULL);
                \\CREATE TABLE retry_retired(jail TEXT NOT NULL,family INTEGER NOT NULL CHECK(family IN (4,6)),subject BLOB NOT NULL CHECK(typeof(subject)='blob' AND length(subject)=CASE family WHEN 4 THEN 4 ELSE 16 END),generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=32),last_processed_us INTEGER NOT NULL CHECK(typeof(last_processed_us)='integer'),decisions INTEGER NOT NULL CHECK(typeof(decisions)='integer' AND decisions>=0),PRIMARY KEY(jail,family,subject),FOREIGN KEY(jail) REFERENCES retry_policies(jail));
                \\CREATE TABLE retry_retired_totals(jail TEXT PRIMARY KEY,total INTEGER NOT NULL CHECK(typeof(total)='integer' AND total>=0),FOREIGN KEY(jail) REFERENCES retry_policies(jail));
                \\CREATE TRIGGER maintenance_source_insert AFTER INSERT ON source_maintenance BEGIN UPDATE maintenance_clock SET revision=revision+1 WHERE id=1; END;
                \\CREATE TRIGGER maintenance_source_update AFTER UPDATE ON source_maintenance BEGIN UPDATE maintenance_clock SET revision=revision+1 WHERE id=1; END;
                \\CREATE INDEX effect_owners_jail ON effect_owners(jail,scope_key);
                \\PRAGMA user_version=15;
            );
            try self.fault(.before_cleanup_schema_commit);
            try self.commitTransaction();
            self.schema_version = @max(schema, 15);
        }

        pub fn enableRetryLeases(self: *Store) Error!void {
            try self.beginWrite();
            errdefer self.rollback();
            const schema = try self.integer("PRAGMA user_version;");
            if (schema < 15 or schema > latest_schema) return error.UnsupportedSchema;
            if (schema == 15) {
                var names: [64][64]u8 = undefined;
                var lengths: [64]u8 = undefined;
                var policies: [64][retry.policy_bytes]u8 = undefined;
                var count: usize = 0;
                {
                    var rows = try self.statement("SELECT jail,policy FROM retry_policies ORDER BY jail;");
                    defer rows.deinit();
                    while (try rows.row()) {
                        if (count == names.len or self.api.column_type(rows.ptr, 0) != 3) return error.InvalidRetryState;
                        const jail = try rows.boundedBytes(0, 64);
                        if (jail.len == 0) return error.InvalidRetryState;
                        const raw = try rows.boundedBytes(1, retry.policy_bytes);
                        if (raw.len != retry.policy_bytes or (raw[4] != 1 and raw[4] != 2)) return error.InvalidRetryPolicy;
                        const policy = try retry.Policy.decode(raw);
                        if (policy.duration == .permanent) return error.InvalidRetryPolicy;
                        lengths[count] = @intCast(jail.len);
                        @memcpy(names[count][0..jail.len], jail);
                        policies[count] = try policy.encode();
                        count += 1;
                    }
                }
                try self.exec(
                    \\CREATE TABLE retry_states_v16(jail TEXT NOT NULL,family INTEGER NOT NULL CHECK(typeof(family)='integer' AND family IN (4,6)),subject BLOB NOT NULL CHECK(typeof(subject)='blob' AND length(subject)=CASE family WHEN 4 THEN 4 ELSE 16 END),last_processed_us INTEGER NOT NULL CHECK(typeof(last_processed_us)='integer'),lease_kind INTEGER NOT NULL CHECK(typeof(lease_kind)='integer' AND lease_kind BETWEEN 0 AND 2),deadline_us INTEGER CHECK(deadline_us IS NULL OR typeof(deadline_us)='integer'),decisions INTEGER NOT NULL CHECK(typeof(decisions)='integer' AND decisions>=0),attempts BLOB NOT NULL CHECK(typeof(attempts)='blob' AND length(attempts)<=5120 AND length(attempts)%40=0),PRIMARY KEY(jail,family,subject),FOREIGN KEY(jail) REFERENCES retry_policies(jail),CHECK((lease_kind=1)=(deadline_us IS NOT NULL)),CHECK(lease_kind=0 OR decisions>0),CHECK(lease_kind=0 OR length(attempts)=0),CHECK(deadline_us IS NULL OR deadline_us>last_processed_us));
                    \\INSERT INTO retry_states_v16 SELECT jail,family,subject,last_processed_us,CASE WHEN expiry_us IS NULL THEN 0 ELSE 1 END,expiry_us,decisions,attempts FROM retry_states;
                    \\DROP TABLE retry_states;
                    \\ALTER TABLE retry_states_v16 RENAME TO retry_states;
                    \\CREATE TABLE retry_decisions_v16(jail TEXT NOT NULL,source TEXT NOT NULL,occurrence TEXT NOT NULL,family INTEGER NOT NULL CHECK(typeof(family)='integer' AND family IN (4,6)),subject BLOB NOT NULL CHECK(typeof(subject)='blob' AND length(subject)=CASE family WHEN 4 THEN 4 ELSE 16 END),decided_us INTEGER NOT NULL CHECK(typeof(decided_us)='integer'),lease_kind INTEGER NOT NULL CHECK(typeof(lease_kind)='integer' AND lease_kind IN (1,2)),deadline_us INTEGER CHECK(deadline_us IS NULL OR typeof(deadline_us)='integer'),ordinal INTEGER NOT NULL CHECK(typeof(ordinal)='integer' AND ordinal>0),enforce INTEGER NOT NULL CHECK(typeof(enforce)='integer' AND enforce IN (0,1)),PRIMARY KEY(jail,source,occurrence,family,subject),UNIQUE(jail,family,subject,ordinal),FOREIGN KEY(jail,source,occurrence) REFERENCES records(jail,source,occurrence),CHECK((lease_kind=1)=(deadline_us IS NOT NULL)),CHECK(deadline_us IS NULL OR deadline_us>decided_us));
                    \\INSERT INTO retry_decisions_v16 SELECT jail,source,occurrence,family,subject,decided_us,1,expiry_us,ordinal,enforce FROM retry_decisions;
                    \\DROP TABLE retry_decisions;
                    \\ALTER TABLE retry_decisions_v16 RENAME TO retry_decisions;
                );
                for (0..count) |index| {
                    var update = try self.statement("UPDATE retry_policies SET policy=?2 WHERE jail=?1;");
                    defer update.deinit();
                    try update.text(1, names[index][0..lengths[index]]);
                    try update.blob(2, &policies[index]);
                    try update.done();
                    if (self.api.changes(self.db) != 1) return error.InvalidRetryState;
                }
                try self.exec("PRAGMA user_version=16;");
            }
            try self.fault(.before_retry_lease_schema_commit);
            try self.commitTransaction();
            self.schema_version = @max(schema, 16);
        }

        pub fn enableApplicationHistory(self: *Store) Error!void {
            try self.beginWrite();
            errdefer self.rollback();
            const schema = try self.integer("PRAGMA user_version;");
            if (schema < 16 or schema > latest_schema) return error.UnsupportedSchema;
            if (schema == 16) try self.exec(
                \\CREATE TABLE retry_decision_details(jail TEXT NOT NULL,source TEXT NOT NULL,occurrence TEXT NOT NULL,family INTEGER NOT NULL CHECK(typeof(family)='integer' AND family IN (4,6)),subject BLOB NOT NULL CHECK(typeof(subject)='blob' AND length(subject)=CASE family WHEN 4 THEN 4 ELSE 16 END),ordinal INTEGER NOT NULL CHECK(typeof(ordinal)='integer' AND ordinal>0),decided_us INTEGER NOT NULL CHECK(typeof(decided_us)='integer'),effect_decision_id BLOB UNIQUE CHECK(effect_decision_id IS NULL OR (typeof(effect_decision_id)='blob' AND length(effect_decision_id)=32)),evidence TEXT CHECK(evidence IS NULL OR (typeof(evidence)='text' AND length(CAST(evidence AS BLOB)) BETWEEN 1 AND 2048)),PRIMARY KEY(jail,source,occurrence,family,subject));
                \\CREATE TABLE confirmed_event_details(event_id BLOB PRIMARY KEY NOT NULL CHECK(typeof(event_id)='blob' AND length(event_id)=32),source TEXT NOT NULL,occurrence TEXT NOT NULL,decided_us INTEGER NOT NULL CHECK(typeof(decided_us)='integer'),ordinal INTEGER NOT NULL CHECK(typeof(ordinal)='integer' AND ordinal>0),evidence TEXT CHECK(evidence IS NULL OR (typeof(evidence)='text' AND length(CAST(evidence AS BLOB)) BETWEEN 1 AND 2048)),FOREIGN KEY(event_id) REFERENCES confirmed_effect_events(event_id));
                \\CREATE INDEX confirmed_effect_events_jail_time ON confirmed_effect_events(jail,confirmed_us,event_id);
                \\CREATE INDEX confirmed_effect_events_time ON confirmed_effect_events(confirmed_us,event_id);
                \\CREATE TABLE policy_summary_clock(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision BETWEEN 1 AND 9223372036854775806));
                \\INSERT INTO policy_summary_clock VALUES(1,1);
                \\CREATE TRIGGER policy_summary_state_insert AFTER INSERT ON retry_states BEGIN UPDATE policy_summary_clock SET revision=revision+1 WHERE id=1; END;
                \\CREATE TRIGGER policy_summary_state_update AFTER UPDATE ON retry_states BEGIN UPDATE policy_summary_clock SET revision=revision+1 WHERE id=1; END;
                \\CREATE TRIGGER policy_summary_state_delete AFTER DELETE ON retry_states BEGIN UPDATE policy_summary_clock SET revision=revision+1 WHERE id=1; END;
                \\CREATE TRIGGER policy_summary_retired_insert AFTER INSERT ON retry_retired BEGIN UPDATE policy_summary_clock SET revision=revision+1 WHERE id=1; END;
                \\CREATE TRIGGER policy_summary_retired_update AFTER UPDATE ON retry_retired BEGIN UPDATE policy_summary_clock SET revision=revision+1 WHERE id=1; END;
                \\CREATE TRIGGER policy_summary_retired_delete AFTER DELETE ON retry_retired BEGIN UPDATE policy_summary_clock SET revision=revision+1 WHERE id=1; END;
                \\PRAGMA user_version=17;
            );
            // Both are lookup keys for bounded detail reclamation. This additive
            // index change is safe for existing schema-17..23 databases and older
            // binaries; no stored record or checkpoint format changes.
            try self.exec(
                \\CREATE INDEX IF NOT EXISTS effect_owners_decision ON effect_owners(jail,decision_id);
                \\CREATE INDEX IF NOT EXISTS confirmed_effect_events_decision ON confirmed_effect_events(jail,decision_id);
            );
            try self.fault(.before_application_history_schema_commit);
            try self.commitTransaction();
            self.schema_version = @max(schema, 17);
        }

        pub fn enableEscalation(self: *Store) Error!void {
            try self.beginWrite();
            errdefer self.rollback();
            const schema = try self.integer("PRAGMA user_version;");
            if (schema < 17 or schema > latest_schema) return error.UnsupportedSchema;
            if (schema == 17) {
                try self.exec(
                    \\CREATE TABLE retry_escalation_policies(jail TEXT PRIMARY KEY NOT NULL,generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=32),policy BLOB NOT NULL CHECK(typeof(policy)='blob' AND length(policy)=40),FOREIGN KEY(jail) REFERENCES retry_policies(jail));
                    \\CREATE TABLE confirmed_policy_summaries(jail TEXT NOT NULL,family INTEGER NOT NULL CHECK(family IN (4,6)),subject BLOB NOT NULL CHECK(typeof(subject)='blob' AND length(subject)=CASE family WHEN 4 THEN 4 ELSE 16 END),confirmed_count INTEGER NOT NULL CHECK(typeof(confirmed_count)='integer' AND confirmed_count>0),latest_confirmed_us INTEGER NOT NULL CHECK(typeof(latest_confirmed_us)='integer'),PRIMARY KEY(jail,family,subject),FOREIGN KEY(jail) REFERENCES retry_policies(jail));
                    \\CREATE TABLE retry_decision_escalations(jail TEXT NOT NULL,source TEXT NOT NULL,occurrence TEXT NOT NULL,family INTEGER NOT NULL CHECK(family IN (4,6)),subject BLOB NOT NULL CHECK(typeof(subject)='blob' AND length(subject)=CASE family WHEN 4 THEN 4 ELSE 16 END),scope INTEGER NOT NULL CHECK(scope IN (1,2)),prior_confirmed INTEGER NOT NULL CHECK(typeof(prior_confirmed)='integer' AND prior_confirmed>=0),latest_confirmed_us INTEGER CHECK(latest_confirmed_us IS NULL OR typeof(latest_confirmed_us)='integer'),chosen_duration_us INTEGER NOT NULL CHECK(typeof(chosen_duration_us)='integer' AND chosen_duration_us>0 AND chosen_duration_us%1000000=0),jitter_us INTEGER NOT NULL CHECK(typeof(jitter_us)='integer' AND jitter_us>=0 AND jitter_us%1000000=0),PRIMARY KEY(jail,source,occurrence,family,subject),FOREIGN KEY(jail,source,occurrence,family,subject) REFERENCES retry_decisions(jail,source,occurrence,family,subject),CHECK((prior_confirmed=0)=(latest_confirmed_us IS NULL)));
                );
                const detailed = try self.integer("SELECT count(*) FROM confirmed_event_details;");
                const joinable = try self.integer("SELECT count(*) FROM confirmed_event_details d JOIN confirmed_effect_events e USING(event_id) JOIN retry_decision_details r ON r.jail=e.jail AND r.effect_decision_id=e.decision_id;");
                if (detailed != joinable) return error.RetryMigrationRequired;
                try self.exec("INSERT INTO confirmed_policy_summaries SELECT r.jail,r.family,r.subject,count(*),max(e.confirmed_us) FROM confirmed_event_details d JOIN confirmed_effect_events e USING(event_id) JOIN retry_decision_details r ON r.jail=e.jail AND r.effect_decision_id=e.decision_id GROUP BY r.jail,r.family,r.subject;");
                var names: [64][64]u8 = undefined;
                var lengths: [64]u8 = undefined;
                var generations: [64][32]u8 = undefined;
                var count: usize = 0;
                {
                    var rows = try self.statement("SELECT jail,generation FROM retry_policies ORDER BY jail;");
                    defer rows.deinit();
                    while (try rows.row()) {
                        if (count == names.len or self.api.column_type(rows.ptr, 0) != 3) return error.InvalidRetryState;
                        const jail = try rows.boundedBytes(0, 64);
                        const generation = try rows.boundedBytes(1, 32);
                        if (jail.len == 0 or generation.len != 32) return error.InvalidRetryState;
                        lengths[count] = @intCast(jail.len);
                        @memcpy(names[count][0..jail.len], jail);
                        @memcpy(&generations[count], generation);
                        count += 1;
                    }
                }
                const disabled = try (retry.Escalation{}).encode();
                for (0..count) |index| {
                    var insert = try self.statement("INSERT INTO retry_escalation_policies VALUES(?1,?2,?3);");
                    defer insert.deinit();
                    try insert.text(1, names[index][0..lengths[index]]);
                    try insert.blob(2, &generations[index]);
                    try insert.blob(3, &disabled);
                    try insert.done();
                }
                try self.exec("PRAGMA user_version=18;");
            }
            try self.fault(.before_escalation_schema_commit);
            try self.commitTransaction();
            self.schema_version = @max(schema, 18);
        }

        pub fn enableCanonicalEffects(self: *Store) Error!void {
            try self.beginWrite();
            errdefer self.rollback();
            const schema = try self.integer("PRAGMA user_version;");
            if (schema < 18 or schema > latest_schema) return error.UnsupportedSchema;
            if (schema == 18) {
                const installation = try self.readInstallation();
                var count: usize = 0;
                {
                    var rows = try self.statement("SELECT scope_key,scope FROM native_effects ORDER BY scope_key;");
                    defer rows.deinit();
                    while (try rows.row()) {
                        count += 1;
                        if (count > effects.max_effects) return error.EffectCapacity;
                        const scope = try effects.Scope.decode(&try Store.effectBlob(&rows, 1, effects.Scope.encoded_bytes));
                        const admitted = installation orelse return error.InstallationRequired;
                        if (!std.mem.eql(u8, &try Store.effectBlob(&rows, 0, 32), &try scope.key(admitted))) return error.InvalidEffect;
                    }
                }
                try self.exec(
                    \\ALTER TABLE native_effects ADD COLUMN canonical_scope BLOB CHECK(canonical_scope IS NULL OR (typeof(canonical_scope)='blob' AND length(canonical_scope)=92));
                    \\UPDATE native_effects SET canonical_scope=CAST(x'02'||substr(scope,2,1)||x'01'||substr(scope,3,1)||x'010000010101010101010100'||substr(scope,9,16)||zeroblob(60) AS BLOB);
                    \\CREATE TRIGGER native_effect_scope_v2_insert BEFORE INSERT ON native_effects WHEN NEW.canonical_scope IS NULL BEGIN SELECT RAISE(ABORT,'canonical effect scope required'); END;
                    \\CREATE TRIGGER native_effect_scope_v2_update BEFORE UPDATE OF canonical_scope ON native_effects WHEN NEW.canonical_scope IS NULL OR NEW.canonical_scope IS NOT OLD.canonical_scope BEGIN SELECT RAISE(ABORT,'canonical effect scope immutable'); END;
                    \\PRAGMA user_version=19;
                );
                var verified: usize = 0;
                {
                    var canonical_rows = try self.statement("SELECT canonical_scope FROM native_effects ORDER BY scope_key;");
                    defer canonical_rows.deinit();
                    while (try canonical_rows.row()) {
                        verified += 1;
                        _ = try effects.Scope.decodeCanonical(&try Store.effectBlob(&canonical_rows, 0, effects.Scope.canonical_encoded_bytes));
                    }
                }
                if (verified != count) return error.InvalidEffect;
            }
            try self.fault(.before_canonical_effect_schema_commit);
            try self.commitTransaction();
            self.schema_version = @max(schema, 19);
        }

        pub fn enableHistoryResets(self: *Store) Error!void {
            try self.beginWrite();
            errdefer self.rollback();
            const schema = try self.integer("PRAGMA user_version;");
            if (schema < 19 or schema > latest_schema) return error.UnsupportedSchema;
            if (schema == 19) try self.exec(
                \\CREATE TABLE history_reset_watermarks(scope INTEGER NOT NULL CHECK(scope IN(1,2)),jail TEXT NOT NULL CHECK((scope=1 AND length(jail) BETWEEN 1 AND 64) OR (scope=2 AND jail='')),family INTEGER NOT NULL CHECK(family IN(4,6)),subject BLOB NOT NULL CHECK(typeof(subject)='blob' AND length(subject)=CASE family WHEN 4 THEN 4 ELSE 16 END),through_sequence INTEGER NOT NULL CHECK(typeof(through_sequence)='integer' AND through_sequence>=0),reset_us INTEGER NOT NULL CHECK(typeof(reset_us)='integer'),revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision>0),intent_id BLOB NOT NULL CHECK(typeof(intent_id)='blob' AND length(intent_id)=32),PRIMARY KEY(scope,jail,family,subject));
                \\PRAGMA user_version=20;
            );
            try self.fault(.before_history_reset_schema_commit);
            try self.commitTransaction();
            self.schema_version = @max(schema, 20);
        }

        pub fn enableActionTargets(self: *Store) Error!void {
            try self.beginWrite();
            errdefer self.rollback();
            const schema = try self.integer("PRAGMA user_version;");
            if (schema < 20 or schema > latest_schema) return error.UnsupportedSchema;
            if (schema == 20) {
                const owner_count = try self.integer("SELECT count(*) FROM effect_owners;");
                if (owner_count < 0 or owner_count > action_outcome.max_rows / action_outcome.max_targets_per_action) return error.ActionTargetCapacity;
                try self.exec(
                    \\CREATE TABLE action_targets(action_id BLOB NOT NULL CHECK(typeof(action_id)='blob' AND length(action_id)=32),kind INTEGER NOT NULL CHECK(kind IN(1,2)),scope_key BLOB NOT NULL CHECK(typeof(scope_key)='blob' AND length(scope_key)=32),jail TEXT NOT NULL CHECK(length(jail) BETWEEN 1 AND 64),required INTEGER NOT NULL CHECK(required IN(0,1) AND required=(kind=1)),restored INTEGER NOT NULL CHECK(restored IN(0,1)),status INTEGER NOT NULL CHECK(status BETWEEN 1 AND 6),intent_us INTEGER NOT NULL CHECK(typeof(intent_us)='integer'),dispatch_us INTEGER CHECK(dispatch_us IS NULL OR (typeof(dispatch_us)='integer' AND dispatch_us>=intent_us)),settled_us INTEGER CHECK(settled_us IS NULL OR (typeof(settled_us)='integer' AND settled_us>=dispatch_us)),metadata TEXT CHECK(metadata IS NULL OR (typeof(metadata)='text' AND length(CAST(metadata AS BLOB)) BETWEEN 1 AND 512)),PRIMARY KEY(action_id,kind),CHECK((status=1 AND dispatch_us IS NULL AND settled_us IS NULL) OR (status=2 AND dispatch_us IS NOT NULL AND settled_us IS NULL) OR (status BETWEEN 3 AND 5 AND dispatch_us IS NOT NULL AND settled_us IS NOT NULL) OR (status=6 AND kind=2 AND restored=1 AND dispatch_us IS NULL AND settled_us=intent_us)),CHECK(kind!=1 OR status!=6),CHECK(kind!=2 OR restored=0 OR status=6));
                    \\INSERT INTO action_targets(action_id,kind,scope_key,jail,required,restored,status,intent_us) SELECT decision_id,1,scope_key,jail,1,1,1,decided_us FROM effect_owners;
                    \\INSERT INTO action_targets(action_id,kind,scope_key,jail,required,restored,status,intent_us,settled_us) SELECT decision_id,2,scope_key,jail,0,1,6,decided_us,decided_us FROM effect_owners;
                    \\PRAGMA user_version=21;
                );
            }
            try self.fault(.before_action_target_schema_commit);
            try self.commitTransaction();
            self.schema_version = @max(schema, 21);
        }
        pub fn enableAdminState(self: *Store) Error!void {
            try self.beginWrite();
            errdefer self.rollback();
            const schema = try self.integer("PRAGMA user_version;");
            if (schema < 21 or schema > latest_schema) return error.UnsupportedSchema;
            if (schema == 21) try self.exec(
                \\CREATE TABLE config_generations(generation BLOB NOT NULL PRIMARY KEY CHECK(typeof(generation)='blob' AND length(generation)=32),config_digest BLOB NOT NULL CHECK(typeof(config_digest)='blob' AND length(config_digest)=32),config_path TEXT NOT NULL CHECK(typeof(config_path)='text' AND length(config_path) BETWEEN 1 AND 4096),committed_us INTEGER NOT NULL CHECK(typeof(committed_us)='integer' AND committed_us>=0),published INTEGER NOT NULL CHECK(published IN(0,1)),mutation_revision INTEGER NOT NULL CHECK(typeof(mutation_revision)='integer' AND mutation_revision>=0)) WITHOUT ROWID;
                \\CREATE TABLE config_generation_jails(generation BLOB NOT NULL REFERENCES config_generations(generation) ON DELETE CASCADE,jail TEXT NOT NULL CHECK(typeof(jail)='text' AND length(jail) BETWEEN 1 AND 64),digest BLOB NOT NULL CHECK(typeof(digest)='blob' AND length(digest)=32),allowlist_snapshot BLOB NOT NULL CHECK(typeof(allowlist_snapshot)='blob' AND length(allowlist_snapshot)<=65536),PRIMARY KEY(generation,jail)) WITHOUT ROWID;
                \\CREATE TABLE jail_admin_states(jail TEXT NOT NULL PRIMARY KEY CHECK(typeof(jail)='text' AND length(jail) BETWEEN 1 AND 64),enabled INTEGER NOT NULL CHECK(enabled IN(0,1)),paused INTEGER NOT NULL CHECK(paused IN(0,1)),generation BLOB NOT NULL REFERENCES config_generations(generation),changed_us INTEGER NOT NULL CHECK(typeof(changed_us)='integer' AND changed_us>=0),request_id BLOB NOT NULL CHECK(typeof(request_id)='blob' AND length(request_id)=32)) WITHOUT ROWID;
                \\CREATE TABLE admin_requests(request_id BLOB NOT NULL PRIMARY KEY CHECK(typeof(request_id)='blob' AND length(request_id)=32),kind INTEGER NOT NULL CHECK(kind BETWEEN 1 AND 10),subject BLOB NOT NULL CHECK(typeof(subject)='blob' AND length(subject)<=4096),outcome INTEGER NOT NULL CHECK(outcome BETWEEN 1 AND 5),generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=32),mutation_revision INTEGER NOT NULL CHECK(typeof(mutation_revision)='integer' AND mutation_revision>=0),committed_us INTEGER NOT NULL CHECK(typeof(committed_us)='integer' AND committed_us>=0),detail BLOB NOT NULL CHECK(typeof(detail)='blob' AND length(detail)<=4096)) WITHOUT ROWID;
                \\CREATE INDEX admin_requests_by_revision ON admin_requests(mutation_revision);
                \\CREATE TABLE admin_revision(id INTEGER NOT NULL PRIMARY KEY CHECK(id=1),mutation_revision INTEGER NOT NULL CHECK(typeof(mutation_revision)='integer' AND mutation_revision>=0));
                \\INSERT INTO admin_revision(id,mutation_revision) VALUES(1,0);
                \\PRAGMA user_version=22;
            );
            try self.fault(.before_admin_schema_commit);
            try self.commitTransaction();
            self.schema_version = @max(schema, 22);
        }

        pub fn enableMigrationState(self: *Store) Error!void {
            try self.beginWrite();
            errdefer self.rollback();
            const schema = try self.integer("PRAGMA user_version;");
            if (schema < 22 or schema > latest_schema) return error.UnsupportedSchema;
            if (schema == 22) try self.exec(
                \\CREATE TABLE migration_runs(run_id BLOB NOT NULL PRIMARY KEY CHECK(typeof(run_id)='blob' AND length(run_id)=32),host_id BLOB NOT NULL CHECK(typeof(host_id)='blob' AND length(host_id)=32),source_db_fp BLOB NOT NULL CHECK(typeof(source_db_fp)='blob' AND length(source_db_fp)=32),source_cfg_fp BLOB NOT NULL CHECK(typeof(source_cfg_fp)='blob' AND length(source_cfg_fp)=32),plan_fp BLOB NOT NULL CHECK(typeof(plan_fp)='blob' AND length(plan_fp)=32),recovery_point TEXT NOT NULL CHECK(typeof(recovery_point)='text' AND length(recovery_point)<=4096),generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=32),state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 9),created_us INTEGER NOT NULL CHECK(typeof(created_us)='integer' AND created_us>=0),updated_us INTEGER NOT NULL CHECK(typeof(updated_us)='integer' AND updated_us>=created_us)) WITHOUT ROWID;
                \\CREATE TABLE migration_steps(run_id BLOB NOT NULL REFERENCES migration_runs(run_id),seq INTEGER NOT NULL CHECK(typeof(seq)='integer' AND seq>=1),step INTEGER NOT NULL CHECK(step BETWEEN 1 AND 9),intent BLOB NOT NULL CHECK(typeof(intent)='blob' AND length(intent)<=4096),outcome INTEGER NOT NULL CHECK(outcome BETWEEN 0 AND 7),detail BLOB NOT NULL CHECK(typeof(detail)='blob' AND length(detail)<=4096),started_us INTEGER NOT NULL CHECK(typeof(started_us)='integer' AND started_us>=0),finished_us INTEGER CHECK(finished_us IS NULL OR (typeof(finished_us)='integer' AND finished_us>=started_us)),PRIMARY KEY(run_id,seq),CHECK((outcome=0 AND finished_us IS NULL) OR (outcome>0 AND finished_us IS NOT NULL))) WITHOUT ROWID;
                \\CREATE TABLE migration_deltas(run_id BLOB NOT NULL REFERENCES migration_runs(run_id),seq INTEGER NOT NULL CHECK(typeof(seq)='integer' AND seq>=1),kind INTEGER NOT NULL CHECK(kind BETWEEN 1 AND 3),scope BLOB NOT NULL CHECK(typeof(scope)='blob' AND length(scope)=92),jail TEXT NOT NULL CHECK(typeof(jail)='text' AND length(jail) BETWEEN 1 AND 64),lease_kind INTEGER NOT NULL CHECK(lease_kind BETWEEN 0 AND 2),deadline_us INTEGER CHECK(deadline_us IS NULL OR typeof(deadline_us)='integer'),carry_back INTEGER NOT NULL CHECK(carry_back BETWEEN 1 AND 3),applied INTEGER NOT NULL CHECK(applied IN(0,1)),recorded_us INTEGER NOT NULL CHECK(typeof(recorded_us)='integer' AND recorded_us>=0),PRIMARY KEY(run_id,seq),CHECK((lease_kind=1 AND deadline_us IS NOT NULL) OR (lease_kind!=1 AND deadline_us IS NULL))) WITHOUT ROWID;
                \\CREATE TABLE migration_staged_owners(run_id BLOB NOT NULL REFERENCES migration_runs(run_id),seq INTEGER NOT NULL CHECK(typeof(seq)='integer' AND seq>=1),jail TEXT NOT NULL CHECK(typeof(jail)='text' AND length(jail) BETWEEN 1 AND 64),scope BLOB NOT NULL CHECK(typeof(scope)='blob' AND length(scope)=92),lease_kind INTEGER NOT NULL CHECK(lease_kind BETWEEN 1 AND 2),deadline_us INTEGER CHECK(deadline_us IS NULL OR typeof(deadline_us)='integer'),source_event_us INTEGER NOT NULL CHECK(typeof(source_event_us)='integer'),source_row INTEGER NOT NULL CHECK(typeof(source_row)='integer' AND source_row>=0),PRIMARY KEY(run_id,seq),CHECK((lease_kind=1 AND deadline_us IS NOT NULL) OR (lease_kind=2 AND deadline_us IS NULL))) WITHOUT ROWID;
                \\CREATE TABLE migration_staged_history(run_id BLOB NOT NULL REFERENCES migration_runs(run_id),seq INTEGER NOT NULL CHECK(typeof(seq)='integer' AND seq>=1),jail TEXT NOT NULL CHECK(typeof(jail)='text' AND length(jail) BETWEEN 1 AND 64),scope BLOB NOT NULL CHECK(typeof(scope)='blob' AND length(scope)=92),event_kind INTEGER NOT NULL CHECK(event_kind BETWEEN 1 AND 3),event_us INTEGER NOT NULL CHECK(typeof(event_us)='integer'),bancount INTEGER NOT NULL CHECK(typeof(bancount)='integer' AND bancount>=0),source_row INTEGER NOT NULL CHECK(typeof(source_row)='integer' AND source_row>=0),PRIMARY KEY(run_id,seq)) WITHOUT ROWID;
                \\PRAGMA user_version=23;
            );
            try self.fault(.before_migration_schema_commit);
            try self.commitTransaction();
            self.schema_version = @max(schema, 23);
        }
    };
}
