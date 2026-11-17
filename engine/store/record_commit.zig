// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Validates a source record and commits it with its detections, retry state, checkpoints, cursor and receipt in one transaction.
// Holds: A replayed occurrence with the stored raw hash returns already_committed unwritten; a different hash fails OccurrenceConflict.

const std = @import("std");
const native_record = @import("../time/time_record.zig");
const detection = @import("../detect/detection_record.zig");
const retry = @import("../detect/retry.zig");
const budget = @import("budget.zig");
const store = @import("store.zig");
const Error = store.Error;
const Limits = store.Limits;
const Record = store.Record;
const CommitResult = store.CommitResult;
const latest_schema = store.latest_schema;
const max_native_detections = store.max_native_detections;

pub fn Methods(comptime Store: type) type {
    return struct {
        const recordGeneration = Store.recordGeneration;
        fn recordDetections(record: *const Record) Error![]const detection.Outcome {
            if (record.native_detections) |values| {
                if (record.native_detection != null or values.len == 0 or values.len > max_native_detections) return error.InvalidRecord;
                for (values, 0..) |value, i| if (value.subject) |subject| {
                    for (values[0..i]) |prior| if (prior.subject) |previous| {
                        if (std.meta.eql(subject, previous)) return error.InvalidRecord;
                    };
                };
                return values;
            }
            if (record.native_detection) |*value| return @as(*const [1]detection.Outcome, @ptrCast(value));
            return &.{};
        }
        pub const RecordStep = struct { result: CommitResult, effect_changed: bool };
        pub fn commitRecord(self: *Store, record: Record) Error!CommitResult {
            try self.usable();
            const detections = try validateRecord(&record);
            try self.beginIntakeWrite(budget.record_pages);
            errdefer self.rollback();
            const step = try self.commitRecordStep(&record, detections);
            if (step.result == .already_committed) {
                try self.commitTransaction();
                return .already_committed;
            }
            if (try self.previousRange(&record)) |range| try self.releasePreviousRecords(range);
            try self.commitEffectTransaction(step.effect_changed);
            return .committed;
        }
        pub fn validateRecord(record: *const Record) Error![]const detection.Outcome {
            const detections = try recordDetections(record);
            if (record.jail.len == 0 or record.source.len == 0 or record.occurrence.len == 0 or record.cursor.len == 0 or
                record.jail.len > 4096 or record.source.len > Limits.source_bytes or record.occurrence.len > 16384 or record.cursor.len > Limits.cursor_bytes or
                record.checkpoint.len > Limits.checkpoint_bytes or record.disposition.len > 64) return error.InvalidRecord;
            if (record.source_path) |path| if (path.len > Limits.source_bytes or std.mem.indexOfScalar(u8, path, 0) != null) return error.InvalidRecord;
            if (record.event_time) |time| if (!std.math.isFinite(time)) return error.InvalidRecord;
            if (record.action_intent) |intent| if (intent.len > 1024 * 1024) return error.InvalidRecord;
            try record.retry_evidence.validate();
            if (record.retry_evidence.text != null and record.native_retry == null) return error.InvalidRecord;
            if (record.shared_state) |shared| {
                if (shared.name.len == 0 or shared.name.len > 4096 or std.mem.indexOfScalar(u8, shared.name, 0) != null) return error.InvalidRecord;
                if (shared.payload) |payload| if (payload.len > Limits.shared_bytes) return error.InvalidRecord;
            }
            if (record.consumers) |batch| try batch.validate();
            return detections;
        }
        pub fn commitRecordStep(self: *Store, record: *const Record, detections: []const detection.Outcome) Error!RecordStep {
            const schema = try self.integer("PRAGMA user_version;");
            if (schema < 2 or schema > latest_schema) return error.UnsupportedSchema;
            self.schema_version = schema;
            const source_generation = if (schema >= 14) try recordGeneration(record) else null;
            if (schema >= 9) {
                const registered = try self.readRetryPolicy(record.jail);
                if ((registered != null) != (record.native_retry != null)) return error.RetryAdmissionRequired;
                if (registered) |saved| {
                    const supplied = record.native_retry.?;
                    if (!std.mem.eql(u8, &saved.generation, &supplied.generation) or !try Store.retryPoliciesEqual(saved.policy, supplied.policy)) return error.RetryGenerationMismatch;
                    if (record.receipt) |receipt| {
                        if (!std.mem.eql(u8, &receipt.generation, &supplied.generation) or detections.len == 0 or
                            (supplied.processing_us orelse return error.InvalidRecord) < receipt.time.us) return error.InvalidRecord;
                    } else if (detections.len != 0 or supplied.processing_us != null) return error.InvalidRecord;
                }
            } else if (record.native_retry != null) return error.RetryStorageRequired;
            const native_values: ?native_record.Stored = if (record.native_time_outcome) |outcome| blk: {
                if (schema < 4 or record.event_time != null) return error.InvalidRecord;
                const receipt = record.receipt orelse return error.ReceiptRequired;
                if (!std.mem.eql(u8, outcome.disposition(), record.disposition)) return error.InvalidRecord;
                var values = native_record.Stored.fromOutcome(outcome, receipt.time) catch return error.InvalidRecord;
                if (record.zone_provenance) |zone| {
                    if (schema < 11) return error.EffectStorageRequired;
                    values.zone = zone;
                    _ = values.outcome(receipt.time) catch return error.InvalidRecord;
                }
                if (values.inferred_year != null and schema < 5) return error.InferenceStorageRequired;
                break :blk values;
            } else if (record.zone_provenance != null) return error.InvalidRecord else null;
            if (record.native_detections != null and schema < 12) return error.DetectionStorageRequired;
            for (detections) |value| {
                if (schema < 6) return error.DetectionStorageRequired;
                if (schema < 8 and @intFromEnum(value.kind) >= 7) return error.DetectionStorageRequired;
                const outcome = record.native_time_outcome orelse return error.InvalidRecord;
                value.validate(outcome) catch return error.InvalidRecord;
            }
            if (self.schema_version >= 3) {
                if (record.receipt) |receipt| {
                    const saved = try self.pendingReceipt(.{
                        .jail = record.jail,
                        .source = record.source,
                        .occurrence = record.occurrence,
                        .cursor = record.cursor,
                        .raw_hash = record.raw_hash,
                        .generation = receipt.generation,
                    });
                    if (saved) |value| {
                        if (value.us != receipt.time.us) return error.ReceiptConflict;
                    } else {
                        const committed = (try self.committedReceipt(.{
                            .jail = record.jail,
                            .source = record.source,
                            .occurrence = record.occurrence,
                            .cursor = record.cursor,
                            .raw_hash = record.raw_hash,
                            .generation = receipt.generation,
                        })) orelse return error.ReceiptRequired;
                        if (committed.us != receipt.time.us) return error.ReceiptConflict;
                    }
                } else {
                    var pending = try self.statement("SELECT 1 FROM pending_receipts WHERE jail=?1 AND source=?2;");
                    defer pending.deinit();
                    try pending.text(1, record.jail);
                    try pending.text(2, record.source);
                    if (try pending.row()) return error.ReceiptRequired;
                }
            } else if (record.receipt != null) return error.ReceiptStorageRequired;
            if (schema >= 12) {
                if (try self.manifestExists(record.jail, record.source) != (record.consumer_manifest != null)) return error.ConsumerManifestRequired;
                if (record.consumer_manifest) |manifest| {
                    if (!std.mem.eql(u8, manifest.jail, record.jail) or !std.mem.eql(u8, manifest.source, record.source)) return error.ConsumerManifestMismatch;
                    const status = try self.checkManifest(manifest);
                    for (manifest.required) |requirement| try self.checkRequiredState(requirement, status == .first_use);
                    if (record.receipt) |receipt| if (!std.mem.eql(u8, &receipt.generation, &manifest.source_generation)) return error.ConsumerManifestMismatch;
                }
            }
            {
                var prior = try self.statement("SELECT raw_hash FROM records WHERE jail=?1 AND source=?2 AND occurrence=?3;");
                defer prior.deinit();
                try prior.text(1, record.jail);
                try prior.text(2, record.source);
                try prior.text(3, record.occurrence);
                if (try prior.row()) {
                    if (!std.mem.eql(u8, try prior.boundedBytes(0, 32), &record.raw_hash)) return error.OccurrenceConflict;
                    if (schema >= 11 and !std.meta.eql(try self.readTimeProvenance(record.jail, record.source, record.occurrence), record.zone_provenance)) return error.OccurrenceConflict;
                    if (schema >= 14) if (try self.recordSequence(record.jail, record.source, record.occurrence)) |ordered| {
                        const supplied = source_generation orelse return error.OccurrenceConflict;
                        if (!std.mem.eql(u8, &supplied, &ordered.generation)) return error.OccurrenceConflict;
                    };
                    return .{ .result = .already_committed, .effect_changed = false };
                }
            }
            {
                const expected = record.expected_revision;
                var current = try self.statement("SELECT revision FROM checkpoints WHERE jail=?1;");
                defer current.deinit();
                try current.text(1, record.jail);
                var current_revision: u64 = 0;
                if (try current.row()) {
                    const stored_revision = self.api.column_int64(current.ptr, 0);
                    if (stored_revision <= 0) return error.DatabaseFailure;
                    current_revision = @intCast(stored_revision);
                }
                if (current_revision != expected or current_revision >= std.math.maxInt(i64)) return error.StaleCheckpoint;
            }
            if (record.shared_state) |shared| {
                var current = try self.statement("SELECT revision FROM shared_checkpoints WHERE name=?1;");
                defer current.deinit();
                try current.text(1, shared.name);
                var current_revision: u64 = 0;
                if (try current.row()) {
                    const stored_revision = self.api.column_int64(current.ptr, 0);
                    if (stored_revision <= 0) return error.DatabaseFailure;
                    current_revision = @intCast(stored_revision);
                }
                if (current_revision != shared.expected_revision or (shared.payload != null and current_revision >= std.math.maxInt(i64))) return error.StaleSharedCheckpoint;
            }
            if (schema >= 12) {
                if (record.consumer_manifest) |manifest| {
                    if (record.receipt == null and detections.len != 0) return error.ReceiptRequired;
                    const batch = record.consumers orelse return error.ConsumerManifestRequired;
                    try self.checkManifestBatch(manifest, batch, true, false);
                } else if (record.consumers != null) return error.ConsumerManifestRequired;
            } else if (record.consumer_manifest != null) return error.ConsumerStorageRequired;
            if (record.consumers) |batch| {
                if (schema < 10) return error.ConsumerStorageRequired;
                try self.checkConsumerBatch(batch, false);
            }
            {
                var stmt = try self.statement(if (record.receipt != null)
                    "INSERT INTO records(jail,source,occurrence,raw_hash,cursor,event_time,timestamp_us,disposition,receipt_us,receipt_generation) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10);"
                else
                    "INSERT INTO records(jail,source,occurrence,raw_hash,cursor,event_time,timestamp_us,disposition) VALUES(?1,?2,?3,?4,?5,?6,?7,?8);");
                defer stmt.deinit();
                try stmt.text(1, record.jail);
                try stmt.text(2, record.source);
                try stmt.text(3, record.occurrence);
                try stmt.blob(4, &record.raw_hash);
                try stmt.blob(5, record.cursor);
                var time_bits: [8]u8 = undefined;
                if (record.event_time) |time| {
                    // Why: event_time is stored as the 8 big-endian bytes of the f64 bit pattern.
                    std.mem.writeInt(u64, &time_bits, @bitCast(time), .big);
                    try stmt.blob(6, &time_bits);
                } else try self.check(self.api.bind_null(stmt.ptr, 6));
                var timestamp_buffer: [20]u8 = undefined;
                if (record.timestamp_us) |timestamp| {
                    const encoded = std.fmt.bufPrint(&timestamp_buffer, "{d}", .{timestamp}) catch return error.InvalidRecord;
                    try stmt.text(7, encoded);
                } else try self.check(self.api.bind_null(stmt.ptr, 7));
                try stmt.text(8, record.disposition);
                if (record.receipt) |receipt| {
                    try stmt.int(9, receipt.time.us);
                    try stmt.blob(10, &receipt.generation);
                }
                try stmt.done();
            }
            if (source_generation) |value| _ = try self.advanceSourceSequence(record, value);
            try self.fault(.after_record);
            if (native_values) |values| {
                var row = try self.statement(if (schema >= 5)
                    "UPDATE records SET native_time_kind=?4,original_us=?5,effective_us=?6,inferred_year=?7 WHERE jail=?1 AND source=?2 AND occurrence=?3;"
                else
                    "UPDATE records SET native_time_kind=?4,original_us=?5,effective_us=?6 WHERE jail=?1 AND source=?2 AND occurrence=?3;");
                defer row.deinit();
                try row.text(1, record.jail);
                try row.text(2, record.source);
                try row.text(3, record.occurrence);
                try row.int(4, @intFromEnum(values.kind));
                if (values.original_us) |value| try row.int(5, value) else try self.check(self.api.bind_null(row.ptr, 5));
                if (values.effective_us) |value| try row.int(6, value) else try self.check(self.api.bind_null(row.ptr, 6));
                if (schema >= 5) {
                    if (values.inferred_year) |year| try row.int(7, year) else try self.check(self.api.bind_null(row.ptr, 7));
                }
                try row.done();
            }
            if (record.zone_provenance) |zone| {
                var row = try self.statement("UPDATE records SET zone_digest=?4,zone_offset_seconds=?5,zone_ambiguity=?6,zone_fold=?7 WHERE jail=?1 AND source=?2 AND occurrence=?3;");
                defer row.deinit();
                try row.text(1, record.jail);
                try row.text(2, record.source);
                try row.text(3, record.occurrence);
                try row.blob(4, &zone.zone_digest);
                try row.int(5, zone.offset_seconds);
                try row.int(6, @intFromEnum(zone.ambiguity));
                try row.int(7, @intFromBool(zone.fold_selected));
                try row.done();
            }
            for (detections, 0..) |value, ordinal| {
                var row = try self.statement(if (schema >= 12)
                    "INSERT INTO record_detections(jail,source,occurrence,version,kind,generation,filter,pattern,pattern_index,family,subject,ordinal) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12);"
                else
                    "INSERT INTO record_detections(jail,source,occurrence,version,kind,generation,filter,pattern,pattern_index,family,subject) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11);");
                if (schema >= 12) try row.int(12, @intCast(ordinal));
                defer row.deinit();
                try row.text(1, record.jail);
                try row.text(2, record.source);
                try row.text(3, record.occurrence);
                try row.int(4, detection.version);
                try row.int(5, @intFromEnum(value.kind));
                try row.blob(6, &value.generation);
                try row.text(7, value.filter.slice());
                if (value.pattern != null) try row.text(8, value.pattern.?.slice());
                if (value.pattern_index) |index| try row.int(9, index);
                var subject_bytes: [16]u8 = undefined;
                if (value.subject) |subject| switch (subject) {
                    .v4 => |address| {
                        @memcpy(subject_bytes[0..4], &address);
                        try row.int(10, 4);
                        try row.blob(11, subject_bytes[0..4]);
                    },
                    .v6 => |address| {
                        @memcpy(&subject_bytes, &address);
                        try row.int(10, 6);
                        try row.blob(11, &subject_bytes);
                    },
                };
                try row.done();
                try self.fault(.after_detection);
            }
            if (record.native_retry) |admission| {
                if (!record.retry_suspended) {
                    if (detections.len == 0) try self.commitRetry(record.*, admission);
                    for (detections) |value| {
                        var scalar = record.*;
                        scalar.native_detection = value;
                        scalar.native_detections = null;
                        try self.commitRetry(scalar, admission);
                    }
                }
            }
            {
                var stmt = try self.statement("INSERT INTO checkpoints VALUES(?1,?2,1) ON CONFLICT(jail) DO UPDATE SET payload=excluded.payload,revision=checkpoints.revision+1;");
                defer stmt.deinit();
                try stmt.text(1, record.jail);
                try stmt.blob(2, record.checkpoint);
                try stmt.done();
            }
            try self.fault(.after_checkpoint);
            if (record.shared_state) |shared| if (shared.payload) |payload| {
                var stmt = try self.statement("INSERT INTO shared_checkpoints VALUES(?1,?2,1) ON CONFLICT(name) DO UPDATE SET payload=excluded.payload,revision=shared_checkpoints.revision+1;");
                defer stmt.deinit();
                try stmt.text(1, shared.name);
                try stmt.blob(2, payload);
                try stmt.done();
            };
            try self.fault(.after_shared_checkpoint);
            if (record.consumers) |batch| try self.writeConsumerBatch(batch);
            if (record.consumer_manifest) |manifest| try self.readyManifest(manifest);
            {
                var stmt = try self.statement("INSERT INTO source_cursors VALUES(?1,?2,?3,?4,?5) ON CONFLICT(jail,source) DO UPDATE SET cursor=excluded.cursor,occurrence=excluded.occurrence,path=excluded.path;");
                defer stmt.deinit();
                try stmt.text(1, record.jail);
                try stmt.text(2, record.source);
                try stmt.blob(3, record.cursor);
                try stmt.text(4, record.occurrence);
                if (record.source_path) |path| try stmt.text(5, path) else try self.check(self.api.bind_null(stmt.ptr, 5));
                try stmt.done();
            }
            if (record.action_intent) |intent| {
                var stmt = try self.statement("INSERT INTO action_intents(jail,source,occurrence,payload) VALUES(?1,?2,?3,?4);");
                defer stmt.deinit();
                try stmt.text(1, record.jail);
                try stmt.text(2, record.source);
                try stmt.text(3, record.occurrence);
                try stmt.blob(4, intent);
                try stmt.done();
            }
            if (record.receipt != null) {
                var pending = try self.statement("DELETE FROM pending_receipts WHERE jail=?1 AND source=?2;");
                defer pending.deinit();
                try pending.text(1, record.jail);
                try pending.text(2, record.source);
                try pending.done();
                if (self.api.changes(self.db) != 1) return error.ReceiptRequired;
                try self.fault(.after_receipt_delete);
            }
            try self.fault(.before_commit);
            if (record.consumers) |batch| try self.commitConsumerClock(batch);
            if (record.effects_clock) |clock| {
                if (schema < 11) return error.EffectStorageRequired;
                const now = try self.commitEffectClock(clock);
                var decisions: [max_native_detections]retry.Decision = undefined;
                const count = try self.retryDecisions(record.jail, record.source, record.occurrence, &decisions);
                for (decisions[0..count]) |decision| if (decision.enforce and !decision.lease.live(now)) return error.EffectExpired;
            }
            return .{ .result = .committed, .effect_changed = if (record.native_retry != null) try self.hasEnforcingDecision(record.*) else false };
        }
        fn hasEnforcingDecision(self: *Store, record: Record) Error!bool {
            var row = try self.statement("SELECT EXISTS(SELECT 1 FROM retry_decisions WHERE jail=?1 AND source=?2 AND occurrence=?3 AND enforce=1);");
            defer row.deinit();
            try row.text(1, record.jail);
            try row.text(2, record.source);
            try row.text(3, record.occurrence);
            if (!try row.row()) return error.DatabaseFailure;
            return try row.signed(0) == 1;
        }
    };
}
