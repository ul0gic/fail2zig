// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Reads the receipt, retry and admission clock floors and reserves, reads and validates pending source receipts.
// Holds: A receipt is reserved only at the jail's expected checkpoint revision, under the pending limit, for an uncommitted occurrence.

const std = @import("std");
const native_time = @import("../time/time.zig");
const native_record = @import("../time/time_record.zig");
const store = @import("store.zig");
const Error = store.Error;
const Limits = store.Limits;
const ReceiptIdentity = store.ReceiptIdentity;
const latest_schema = store.latest_schema;
const hashColumn = store.hashColumn;

pub fn Methods(comptime Store: type) type {
    return struct {
        pub fn receiptClock(self: *Store) Error!?native_time.Timestamp {
            try self.beginRead();
            errdefer self.rollback();
            const schema = try self.integer("PRAGMA user_version;");
            if (schema < 7 or schema > latest_schema) return error.UnsupportedSchema;
            const value = try self.readReceiptClock();
            try self.commitTransaction();
            self.schema_version = schema;
            return value;
        }
        pub fn readRetryClock(self: *Store) Error!?i64 {
            var row = try self.statement("SELECT id,floor_us FROM retry_clock ORDER BY id;");
            defer row.deinit();
            if (!try row.row() or try row.signed(0) != 1) return error.InvalidRetryState;
            const floor = try row.optionalSigned(1);
            if (try row.row()) return error.InvalidRetryState;
            return floor;
        }
        pub fn admissionClock(self: *Store) Error!?native_time.Timestamp {
            try self.beginRead();
            errdefer self.rollback();
            const schema = try self.integer("PRAGMA user_version;");
            if (schema < 7 or schema > latest_schema) return error.UnsupportedSchema;
            const value = try self.readAdmissionClock(schema);
            try self.commitTransaction();
            return value;
        }
        pub fn readAdmissionClock(self: *Store, schema: i64) Error!?native_time.Timestamp {
            var value = try self.readReceiptClock();
            if (schema >= 9) if (try self.readRetryClock()) |floor| {
                value = .{ .us = if (value) |receipt| @max(receipt.us, floor) else floor };
            };
            if (schema >= 10) {
                var row = try self.statement("SELECT id,floor_us FROM consumer_clock ORDER BY id;");
                defer row.deinit();
                if (!try row.row() or try row.signed(0) != 1) return error.InvalidConsumer;
                if (try row.optionalSigned(1)) |floor| value = .{ .us = if (value) |prior| @max(prior.us, floor) else floor };
                if (try row.row()) return error.InvalidConsumer;
            }
            if (schema >= 11) {
                var row = try self.statement("SELECT singleton,floor_us,revision FROM effect_clock ORDER BY singleton;");
                defer row.deinit();
                if (!try row.row() or try row.signed(0) != 1 or try row.signed(2) < 0) return error.InvalidEffect;
                if (try row.optionalSigned(1)) |floor| value = .{ .us = if (value) |prior| @max(prior.us, floor) else floor };
                if (try row.row()) return error.InvalidEffect;
            }
            if (schema >= 15) {
                var row = try self.statement("SELECT revision,floor_us FROM maintenance_clock WHERE id=1;");
                defer row.deinit();
                if (!try row.row() or try row.signed(0) < 0) return error.InvalidMaintenanceState;
                if (try row.optionalSigned(1)) |floor| value = .{ .us = if (value) |prior| @max(prior.us, floor) else floor };
            }
            return value;
        }
        pub fn readReceiptClock(self: *Store) Error!?native_time.Timestamp {
            var row = try self.statement("SELECT id,floor_us FROM receipt_clock ORDER BY id;");
            defer row.deinit();
            if (!try row.row() or try row.signed(0) != 1) return error.DatabaseFailure;
            const floor = try row.optionalSigned(1);
            if (try row.row()) return error.DatabaseFailure;
            return if (floor) |value| .{ .us = value } else null;
        }

        pub fn readTimeProvenance(self: *Store, jail: []const u8, source: []const u8, occurrence: ?[]const u8) Error!?native_record.Provenance {
            var row = try self.statement("SELECT zone_digest,zone_offset_seconds,zone_ambiguity,zone_fold,native_time_kind,original_us FROM records WHERE jail=?1 AND source=?2 AND occurrence=COALESCE(?3,(SELECT occurrence FROM source_cursors WHERE jail=?1 AND source=?2));");
            defer row.deinit();
            try row.text(1, jail);
            try row.text(2, source);
            if (occurrence) |value| try row.text(3, value);
            if (!try row.row()) return null;
            if (self.api.column_type(row.ptr, 0) == 5) {
                if (try row.optionalSigned(1) != null or try row.optionalSigned(2) != null or try row.optionalSigned(3) != null) return error.InvalidRecord;
                return null;
            }
            if (try row.optionalSigned(4) == null or try row.optionalSigned(5) == null) return error.InvalidRecord;
            const ambiguity = std.meta.intToEnum(@FieldType(native_record.Provenance, "ambiguity"), try row.signed(2)) catch return error.InvalidRecord;
            const fold = try row.signed(3);
            if (fold < 0 or fold > 1) return error.InvalidRecord;
            const result = native_record.Provenance{
                .zone_digest = try Store.effectBlob(&row, 0, 32),
                .offset_seconds = std.math.cast(i32, try row.signed(1)) orelse return error.InvalidRecord,
                .ambiguity = ambiguity,
                .fold_selected = fold == 1,
            };
            result.validate() catch return error.InvalidRecord;
            return result;
        }

        pub fn pendingReceipt(self: *Store, identity: ReceiptIdentity) Error!?native_time.Timestamp {
            try Store.validateReceiptIdentity(identity);
            if (self.schema_version < 3) return error.ReceiptStorageRequired;
            var row = try self.statement("SELECT generation,occurrence,raw_hash,cursor,receipt_us FROM pending_receipts WHERE jail=?1 AND source=?2;");
            defer row.deinit();
            try row.text(1, identity.jail);
            try row.text(2, identity.source);
            if (!try row.row()) return null;
            const generation = try hashColumn(&row, 0) orelse return error.ReceiptConflict;
            const raw_hash = try hashColumn(&row, 2) orelse return error.ReceiptConflict;
            const saved = ReceiptIdentity{
                .jail = identity.jail,
                .source = identity.source,
                .occurrence = try row.boundedBytes(1, 16384),
                .cursor = try row.boundedBytes(3, Limits.cursor_bytes),
                .raw_hash = raw_hash,
                .generation = generation,
            };
            if (!identity.sameRecord(saved)) return error.ReceiptConflict;
            return .{ .us = try row.signed(4) };
        }

        pub fn pendingReceiptCount(self: *Store) Error!usize {
            if (self.schema_version < 3) return error.ReceiptStorageRequired;
            return std.math.cast(usize, try self.integer("SELECT count(*) FROM pending_receipts;")) orelse error.DatabaseFailure;
        }

        pub fn committedReceipt(self: *Store, identity: ReceiptIdentity) Error!?native_time.Timestamp {
            try Store.validateReceiptIdentity(identity);
            if (self.schema_version < 3) return error.ReceiptStorageRequired;
            var row = try self.statement("SELECT raw_hash,cursor,receipt_generation,receipt_us FROM records WHERE jail=?1 AND source=?2 AND occurrence=?3;");
            defer row.deinit();
            try row.text(1, identity.jail);
            try row.text(2, identity.source);
            try row.text(3, identity.occurrence);
            if (!try row.row()) return null;
            const raw_hash = try hashColumn(&row, 0) orelse return error.ReceiptConflict;
            const generation = try hashColumn(&row, 2) orelse return error.ReceiptConflict;
            const saved = ReceiptIdentity{
                .jail = identity.jail,
                .source = identity.source,
                .occurrence = identity.occurrence,
                .cursor = try row.boundedBytes(1, Limits.cursor_bytes),
                .raw_hash = raw_hash,
                .generation = generation,
            };
            if (!identity.sameRecord(saved)) return error.ReceiptConflict;
            return .{ .us = try row.signed(3) };
        }

        pub fn validateReceiptGeneration(self: *Store, jail: []const u8, generation: [32]u8) Error!void {
            if (self.receipt_limit == null) return error.ReceiptStorageRequired;
            var row = try self.statement("SELECT 1 FROM pending_receipts WHERE jail=?1 AND (typeof(generation)!='blob' OR generation!=?2) LIMIT 1;");
            defer row.deinit();
            try row.text(1, jail);
            try row.blob(2, &generation);
            if (try row.row()) return error.ReceiptConflict;
        }

        pub fn visitPendingReceipts(self: *Store, callback: *const fn (ReceiptIdentity, native_time.Timestamp, ?*anyopaque) anyerror!void, context: ?*anyopaque) !void {
            const maximum = self.receipt_limit orelse return error.ReceiptStorageRequired;
            // Why: PRAGMA data_version changes when another connection commits, so a change during the walk means the rows read are stale.
            const initial_version = try self.integer("PRAGMA data_version;");
            if (try self.pendingReceiptCount() == 0) {
                if (try self.integer("PRAGMA data_version;") != initial_version) return error.StaleCheckpoint;
                return;
            }
            const buffer = try self.allocator.alloc(u8, 4096 + Limits.source_bytes + 16384 + Limits.cursor_bytes);
            defer self.allocator.free(buffer);
            const key = try self.allocator.alloc(u8, 4096 + Limits.source_bytes);
            defer self.allocator.free(key);
            var jail_len: usize = 0;
            var source_len: usize = 0;
            var count: usize = 0;
            while (true) {
                var identity: ReceiptIdentity = undefined;
                var stamp: native_time.Timestamp = undefined;
                const found = blk: {
                    var row = try self.statement(if (count == 0)
                        "SELECT jail,source,occurrence,cursor,raw_hash,generation,receipt_us FROM pending_receipts ORDER BY jail,source LIMIT 1;"
                    else
                        "SELECT jail,source,occurrence,cursor,raw_hash,generation,receipt_us FROM pending_receipts WHERE (jail,source)>(?1,?2) ORDER BY jail,source LIMIT 1;");
                    defer row.deinit();
                    if (count != 0) {
                        try row.text(1, key[0..jail_len]);
                        try row.text(2, key[jail_len..][0..source_len]);
                    }
                    if (!try row.row()) break :blk false;
                    if (count >= maximum) return error.ReceiptLimit;
                    inline for (0..6) |column| if (self.api.column_type(row.ptr, column) != (if (column < 3) @as(c_int, 3) else 4)) return error.DatabaseFailure;
                    var used: usize = 0;
                    var values: [4][]const u8 = undefined;
                    inline for (.{ 4096, Limits.source_bytes, 16384, Limits.cursor_bytes }, 0..) |limit, column| {
                        const bytes = try row.boundedBytes(column, limit);
                        @memcpy(buffer[used..][0..bytes.len], bytes);
                        values[column] = buffer[used..][0..bytes.len];
                        used += bytes.len;
                    }
                    const hash = try row.boundedBytes(4, 32);
                    const generation = try row.boundedBytes(5, 32);
                    if (hash.len != 32 or generation.len != 32) return error.DatabaseFailure;
                    identity = .{ .jail = values[0], .source = values[1], .occurrence = values[2], .cursor = values[3], .raw_hash = hash[0..32].*, .generation = generation[0..32].* };
                    try Store.validateReceiptIdentity(identity);
                    stamp = .{ .us = try row.signed(6) };
                    break :blk true;
                };
                if (try self.integer("PRAGMA data_version;") != initial_version) return error.StaleCheckpoint;
                if (!found) return;
                try callback(identity, stamp, context);
                if (try self.integer("PRAGMA data_version;") != initial_version) return error.StaleCheckpoint;
                jail_len = identity.jail.len;
                source_len = identity.source.len;
                @memcpy(key[0..jail_len], identity.jail);
                @memcpy(key[jail_len..][0..source_len], identity.source);
                count += 1;
            }
        }

        pub const ReceiptStep = struct { time: native_time.Timestamp, reserved: bool };
        pub fn beginReceipt(self: *Store, identity: ReceiptIdentity, proposed: native_time.Timestamp, expected_revision: u64) Error!native_time.Timestamp {
            try self.beginWrite();
            errdefer self.rollback();
            const step = try self.reserveReceiptStep(identity, proposed, expected_revision);
            if (step.reserved) try self.fault(.before_receipt_commit);
            try self.commitTransaction();
            if (step.reserved) try self.fault(.after_receipt_commit);
            return step.time;
        }
        pub fn reserveReceiptStep(self: *Store, identity: ReceiptIdentity, proposed: native_time.Timestamp, expected_revision: u64) Error!ReceiptStep {
            try Store.validateReceiptIdentity(identity);
            const maximum = self.receipt_limit orelse return error.ReceiptStorageRequired;
            const schema = try self.integer("PRAGMA user_version;");
            if (schema < 3 or schema > latest_schema) return error.UnsupportedSchema;
            self.schema_version = schema;
            if (schema >= 7) _ = try self.readReceiptClock();
            if (expected_revision >= std.math.maxInt(i64) or try self.revision(identity.jail) != expected_revision) return error.StaleCheckpoint;
            try self.validateReceiptGeneration(identity.jail, identity.generation);
            if (try self.hasRecord(identity.jail, identity.source, identity.occurrence, identity.raw_hash)) return error.ReceiptAlreadyCommitted;
            if (try self.pendingReceipt(identity)) |saved| return .{ .time = saved, .reserved = false };
            if (try self.pendingReceiptCount() >= maximum) return error.ReceiptLimit;
            {
                var row = try self.statement("INSERT INTO pending_receipts VALUES(?1,?2,?3,?4,?5,?6,?7);");
                defer row.deinit();
                try row.text(1, identity.jail);
                try row.text(2, identity.source);
                try row.blob(3, &identity.generation);
                try row.text(4, identity.occurrence);
                try row.blob(5, &identity.raw_hash);
                try row.blob(6, identity.cursor);
                try row.int(7, proposed.us);
                try row.done();
            }
            if (schema >= 7) {
                var clock = try self.statement("UPDATE receipt_clock SET floor_us=CASE WHEN floor_us IS NULL OR floor_us<?1 THEN ?1 ELSE floor_us END WHERE id=1;");
                defer clock.deinit();
                try clock.int(1, proposed.us);
                try clock.done();
            }
            self.schema_version = schema;
            return .{ .time = proposed, .reserved = true };
        }
    };
}
