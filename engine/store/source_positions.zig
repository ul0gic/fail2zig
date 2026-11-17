// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Advances per-source record sequences and reads source maintenance, cursors, jail and shared checkpoints and pending positions.
// Holds: A source sequence advances by exactly one from a head that matches the newest retained record, or fails InvalidMaintenanceState.

const std = @import("std");
const store = @import("store.zig");
const Error = store.Error;
const Limits = store.Limits;
const Record = store.Record;
const ReceiptIdentity = store.ReceiptIdentity;

pub fn Methods(comptime Store: type) type {
    return struct {
        pub const SourceMaintenance = struct {
            head_sequence: u64,
            reject_below_sequence: u64,
            cleanup_revision: u64,
            sweep_sequence: u64,
        };
        pub const RecordSequence = struct { generation: [32]u8, sequence: u64 };
        pub const SourceRange = struct { jail: []const u8, source: []const u8, generation: [32]u8, cutoff: u64 };
        pub fn maintenanceKey(jail: []const u8, source: []const u8) Error!void {
            if (jail.len == 0 or jail.len > 4096 or source.len == 0 or source.len > Limits.source_bytes or
                std.mem.indexOfScalar(u8, jail, 0) != null or std.mem.indexOfScalar(u8, source, 0) != null) return error.InvalidRecord;
        }
        pub fn sourceMaintenance(self: *Store, jail: []const u8, source: []const u8, generation: [32]u8) Error!?SourceMaintenance {
            try maintenanceKey(jail, source);
            if (self.schema_version < 14) return error.MaintenanceStorageRequired;
            var row = try self.statement("SELECT head_sequence,reject_below_sequence,cleanup_revision,sweep_sequence FROM source_maintenance WHERE jail=?1 AND source=?2 AND generation=?3;");
            defer row.deinit();
            try row.text(1, jail);
            try row.text(2, source);
            try row.blob(3, &generation);
            if (!try row.row()) return null;
            const head = try row.signed(0);
            const floor = try row.signed(1);
            const revision_value = try row.signed(2);
            const sweep = try row.signed(3);
            if (head < 1 or head == std.math.maxInt(i64) or floor < 1 or floor > head + 1 or revision_value < 0 or sweep < 0 or sweep >= floor) return error.InvalidMaintenanceState;
            return .{ .head_sequence = @intCast(head), .reject_below_sequence = @intCast(floor), .cleanup_revision = @intCast(revision_value), .sweep_sequence = @intCast(sweep) };
        }
        pub fn recordSequence(self: *Store, jail: []const u8, source: []const u8, occurrence: []const u8) Error!?RecordSequence {
            try maintenanceKey(jail, source);
            if (occurrence.len == 0 or occurrence.len > 16384) return error.InvalidRecord;
            if (self.schema_version < 14) return error.MaintenanceStorageRequired;
            var row = try self.statement("SELECT source_generation,source_sequence FROM records WHERE jail=?1 AND source=?2 AND occurrence=?3;");
            defer row.deinit();
            try row.text(1, jail);
            try row.text(2, source);
            try row.text(3, occurrence);
            if (!try row.row()) return null;
            const generation_null = self.api.column_type(row.ptr, 0) == 5;
            const sequence_null = self.api.column_type(row.ptr, 1) == 5;
            if (generation_null and sequence_null) return null;
            if (generation_null or sequence_null) return error.InvalidMaintenanceState;
            const generation = try Store.effectBlob(&row, 0, 32);
            const sequence = try row.signed(1);
            const state = try self.sourceMaintenance(jail, source, generation) orelse return error.InvalidMaintenanceState;
            if (sequence <= 0 or sequence > state.head_sequence) return error.InvalidMaintenanceState;
            return .{ .generation = generation, .sequence = @intCast(sequence) };
        }
        pub fn recordGeneration(record: *const Record) Error!?[32]u8 {
            var result: ?[32]u8 = if (record.receipt) |value| value.generation else null;
            const other = [_]?[32]u8{ if (record.native_retry) |value| value.generation else null, if (record.consumer_manifest) |value| value.source_generation else null };
            for (other) |candidate| if (candidate) |value| {
                if (result) |known| if (!std.mem.eql(u8, &known, &value)) return error.OccurrenceConflict;
                result = value;
            };
            return result;
        }
        pub fn previousRange(self: *Store, record: *const Record) Error!?SourceRange {
            if (self.schema_version < 15) return null;
            const generation = try recordGeneration(record) orelse return null;
            const state = try self.sourceMaintenance(record.jail, record.source, generation) orelse return error.InvalidMaintenanceState;
            return .{ .jail = record.jail, .source = record.source, .generation = generation, .cutoff = state.head_sequence - 1 };
        }
        pub fn advanceSourceSequence(self: *Store, record: *const Record, generation: [32]u8) Error!u64 {
            if (self.schema_version >= 15) _ = try self.maintenanceRevision();
            const old = try self.sourceMaintenance(record.jail, record.source, generation);
            if (old == null) {
                var retained = try self.statement("SELECT 1 FROM records WHERE jail=?1 AND source=?2 AND source_generation=?3 AND source_sequence IS NOT NULL LIMIT 1;");
                defer retained.deinit();
                try retained.text(1, record.jail);
                try retained.text(2, record.source);
                try retained.blob(3, &generation);
                if (try retained.row()) return error.InvalidMaintenanceState;
            }
            const prior: u64 = if (old) |value| value.head_sequence else 0;
            if (old != null) {
                var retained = try self.statement("SELECT source_sequence FROM records WHERE jail=?1 AND source=?2 AND source_generation=?3 AND source_sequence IS NOT NULL ORDER BY source_sequence DESC LIMIT 1;");
                defer retained.deinit();
                try retained.text(1, record.jail);
                try retained.text(2, record.source);
                try retained.blob(3, &generation);
                if (try retained.row() and try retained.signed(0) != prior) return error.InvalidMaintenanceState;
            }
            if (prior >= std.math.maxInt(i64) - 1) return error.StorageLimit;
            const next = prior + 1;
            var row = try self.statement("INSERT INTO source_maintenance VALUES(?1,?2,?3,?4,1,0,0) ON CONFLICT(jail,source,generation) DO UPDATE SET head_sequence=excluded.head_sequence WHERE source_maintenance.head_sequence=?5;");
            defer row.deinit();
            try row.text(1, record.jail);
            try row.text(2, record.source);
            try row.blob(3, &generation);
            try row.int(4, @intCast(next));
            try row.int(5, @intCast(prior));
            try row.done();
            if (self.api.changes(self.db) != 1) return error.InvalidMaintenanceState;
            var detail = try self.statement("UPDATE records SET source_generation=?4,source_sequence=?5 WHERE jail=?1 AND source=?2 AND occurrence=?3 AND source_generation IS NULL AND source_sequence IS NULL;");
            defer detail.deinit();
            try detail.text(1, record.jail);
            try detail.text(2, record.source);
            try detail.text(3, record.occurrence);
            try detail.blob(4, &generation);
            try detail.int(5, @intCast(next));
            try detail.done();
            if (self.api.changes(self.db) != 1) return error.InvalidMaintenanceState;
            try self.fault(.after_source_sequence);
            return next;
        }
        pub fn sourceCursor(self: *Store, allocator: std.mem.Allocator, jail: []const u8, source: []const u8) Error!?[]u8 {
            var stmt = try self.statement("SELECT cursor FROM source_cursors WHERE jail=?1 AND source=?2;");
            defer stmt.deinit();
            try stmt.text(1, jail);
            try stmt.text(2, source);
            if (!try stmt.row()) return null;
            return allocator.dupe(u8, try stmt.boundedBytes(0, Limits.cursor_bytes)) catch error.OutOfMemory;
        }
        pub fn revision(self: *Store, jail: []const u8) Error!u64 {
            var stmt = try self.statement("SELECT revision FROM checkpoints WHERE jail=?1;");
            defer stmt.deinit();
            try stmt.text(1, jail);
            if (!try stmt.row()) return 0;
            const value = self.api.column_int64(stmt.ptr, 0);
            if (value <= 0) return error.DatabaseFailure;
            return @intCast(value);
        }
        pub const Snapshot = struct {
            payload: ?[]u8,
            revision: u64,
            pub fn deinit(self: Snapshot, allocator: std.mem.Allocator) void {
                if (self.payload) |payload| allocator.free(payload);
            }
        };
        pub fn snapshot(self: *Store, allocator: std.mem.Allocator, jail: []const u8) Error!Snapshot {
            var stmt = try self.statement("SELECT payload,revision FROM checkpoints WHERE jail=?1;");
            defer stmt.deinit();
            try stmt.text(1, jail);
            if (!try stmt.row()) return .{ .payload = null, .revision = 0 };
            const saved_revision = self.api.column_int64(stmt.ptr, 1);
            if (saved_revision <= 0) return error.DatabaseFailure;
            return .{ .payload = allocator.dupe(u8, try stmt.boundedBytes(0, Limits.checkpoint_bytes)) catch return error.OutOfMemory, .revision = @intCast(saved_revision) };
        }
        pub fn sharedSnapshot(self: *Store, allocator: std.mem.Allocator, name: []const u8) Error!Snapshot {
            var stmt = try self.statement("SELECT payload,revision FROM shared_checkpoints WHERE name=?1;");
            defer stmt.deinit();
            try stmt.text(1, name);
            if (!try stmt.row()) return .{ .payload = null, .revision = 0 };
            const saved_revision = self.api.column_int64(stmt.ptr, 1);
            if (saved_revision <= 0) return error.DatabaseFailure;
            return .{ .payload = allocator.dupe(u8, try stmt.boundedBytes(0, Limits.shared_bytes)) catch return error.OutOfMemory, .revision = @intCast(saved_revision) };
        }
        pub fn checkpoint(self: *Store, allocator: std.mem.Allocator, jail: []const u8) Error!?[]u8 {
            var stmt = try self.statement("SELECT payload FROM checkpoints WHERE jail=?1;");
            defer stmt.deinit();
            try stmt.text(1, jail);
            if (!try stmt.row()) return null;
            return allocator.dupe(u8, try stmt.boundedBytes(0, Limits.checkpoint_bytes)) catch error.OutOfMemory;
        }

        pub fn visitSources(self: *Store, jail: []const u8, callback: *const fn ([]const u8, []const u8, []const u8, ?*anyopaque) anyerror!void, context: ?*anyopaque) !void {
            var stmt = try self.statement("SELECT source,path,cursor FROM source_cursors WHERE jail=?1 ORDER BY source;");
            defer stmt.deinit();
            try stmt.text(1, jail);
            while (try stmt.row()) try callback(try stmt.boundedBytes(0, Limits.source_bytes), try stmt.boundedBytes(1, Limits.source_bytes), try stmt.boundedBytes(2, Limits.cursor_bytes), context);
        }

        pub const SourcePosition = struct {
            source: []u8,
            path: []u8,
            cursor: []u8,
            pub fn deinit(self: SourcePosition, a: std.mem.Allocator) void {
                a.free(self.source);
                a.free(self.path);
                a.free(self.cursor);
            }
        };
        pub fn readSourcePosition(self: *Store, a: std.mem.Allocator, jail: []const u8, after_source: ?[]const u8, expected_revision: u64) Error!?SourcePosition {
            try self.beginRead();
            errdefer self.rollback();
            if (try self.revision(jail) != expected_revision) return error.StaleCheckpoint;
            const result: ?SourcePosition = blk: {
                var row = try self.statement("SELECT source,COALESCE(path,''),cursor FROM source_cursors WHERE jail=?1 AND (?2 IS NULL OR source>?2) ORDER BY source LIMIT 1;");
                defer row.deinit();
                try row.text(1, jail);
                if (after_source) |value| try row.text(2, value) else try self.check(self.api.bind_null(row.ptr, 2));
                if (!try row.row()) break :blk null;
                inline for (0..3) |i| if (self.api.column_type(row.ptr, i) != (if (i == 2) @as(c_int, 4) else 3)) return error.InvalidRecord;
                const source = try a.dupe(u8, try row.boundedBytes(0, Limits.source_bytes));
                errdefer a.free(source);
                const path = try a.dupe(u8, try row.boundedBytes(1, Limits.source_bytes));
                errdefer a.free(path);
                const cursor = try a.dupe(u8, try row.boundedBytes(2, Limits.cursor_bytes));
                break :blk .{ .source = source, .path = path, .cursor = cursor };
            };
            errdefer if (result) |value| value.deinit(a);
            try self.commitTransaction();
            return result;
        }
        pub const PendingSource = struct {
            identity: ReceiptIdentity,
            receipt_us: i64,
            pub fn deinit(self: PendingSource, a: std.mem.Allocator) void {
                a.free(self.identity.jail);
                a.free(self.identity.source);
                a.free(self.identity.occurrence);
                a.free(self.identity.cursor);
            }
        };
        pub fn readPendingSource(self: *Store, a: std.mem.Allocator, jail: []const u8, source: []const u8) Error!?PendingSource {
            return self.readPending(a, jail, source, false);
        }
        pub fn readPendingPosition(self: *Store, a: std.mem.Allocator, jail: []const u8, after_source: ?[]const u8) Error!?PendingSource {
            return self.readPending(a, jail, after_source, true);
        }
        fn readPending(self: *Store, a: std.mem.Allocator, jail: []const u8, selected: ?[]const u8, after: bool) Error!?PendingSource {
            if (self.receipt_limit == null) return error.ReceiptStorageRequired;
            var row = try self.statement(if (after)
                "SELECT jail,source,occurrence,cursor,raw_hash,generation,receipt_us FROM pending_receipts WHERE jail=?1 AND (?2 IS NULL OR source>?2) ORDER BY source LIMIT 1;"
            else
                "SELECT jail,source,occurrence,cursor,raw_hash,generation,receipt_us FROM pending_receipts WHERE jail=?1 AND source=?2;");
            defer row.deinit();
            try row.text(1, jail);
            if (selected) |value| try row.text(2, value) else try self.check(self.api.bind_null(row.ptr, 2));
            if (!try row.row()) return null;
            inline for (0..6) |i| if (self.api.column_type(row.ptr, i) != (if (i < 3) @as(c_int, 3) else 4)) return error.InvalidRecord;
            var copied: [4][]u8 = undefined;
            var count: usize = 0;
            errdefer for (copied[0..count]) |value| a.free(value);
            inline for (.{ 4096, Limits.source_bytes, 16384, Limits.cursor_bytes }, 0..) |limit, i| {
                copied[i] = try a.dupe(u8, try row.boundedBytes(i, limit));
                count += 1;
            }
            const raw_hash = try row.boundedBytes(4, 32);
            const generation = try row.boundedBytes(5, 32);
            if (raw_hash.len != 32 or generation.len != 32) return error.InvalidRecord;
            const identity = ReceiptIdentity{ .jail = copied[0], .source = copied[1], .occurrence = copied[2], .cursor = copied[3], .raw_hash = raw_hash[0..32].*, .generation = generation[0..32].* };
            try Store.validateReceiptIdentity(identity);
            return .{ .identity = identity, .receipt_us = try row.signed(6) };
        }

        pub fn hasRecord(self: *Store, jail: []const u8, source: []const u8, occurrence: []const u8, raw_hash: [32]u8) Error!bool {
            var stmt = try self.statement("SELECT raw_hash FROM records WHERE jail=?1 AND source=?2 AND occurrence=?3;");
            defer stmt.deinit();
            try stmt.text(1, jail);
            try stmt.text(2, source);
            try stmt.text(3, occurrence);
            if (!try stmt.row()) return false;
            if (!std.mem.eql(u8, try stmt.boundedBytes(0, 32), &raw_hash)) return error.OccurrenceConflict;
            return true;
        }
    };
}
