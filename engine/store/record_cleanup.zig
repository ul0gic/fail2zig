// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Deletes spent detection record groups and maintenance headers in bounded batches and validates maintenance headers.
// Holds: The record a source cursor names, and an internal record above the committed history sequence, are never deleted.

const std = @import("std");
const build_options = @import("build_options");
const diag_mod = @import("../diag/diag.zig");
const detection = @import("../detect/detection_record.zig");
const retry = @import("../detect/retry.zig");
const effects = @import("../effect/effect.zig");
const effect_history = @import("../effect/effect_history.zig");
const recurrence = @import("../detect/recurrence.zig");
const store = @import("store.zig");
const Error = store.Error;
const Stmt = store.Stmt;
const Limits = store.Limits;
const max_native_detections = store.max_native_detections;
const max_batch_records = @import("group_commit.zig").max_batch_records;

pub fn Methods(comptime Store: type) type {
    return struct {
        const SourceMaintenance = Store.SourceMaintenance;
        const ReceiptIdentity = store.ReceiptIdentity;
        pub const InternalSource = struct { jail: []const u8, generation: [32]u8 };
        pub const RecordCleanup = enum { idle, deleted, scanned };
        pub const max_cleanup_groups = 256;
        // Why: An interrupted write rolls back the whole transaction (sqlite3.h), so a group starts only while this many callbacks remain.
        const cleanup_work_reserve: u32 = 500;
        const max_group_rows = 1 + 3 * max_native_detections;
        const Retention = struct { now: i64, history: ?u64, installation: ?effects.Installation };
        fn committedHistorySequence(self: *Store) Error!?u64 {
            const installation = try self.readInstallation() orelse return null;
            const required = effect_history.key(try effect_history.generation(installation, effects.hashParts("fail2zig-native-confirmed-history-v1", &.{})));
            var row = try self.statement("SELECT payload FROM consumer_checkpoints WHERE kind=?1 AND jail=?2 AND source=?3 AND rule=?4 AND generation=?5;");
            defer row.deinit();
            try Store.bindConsumerKey(&row, &required);
            if (!try row.row() or self.api.column_type(row.ptr, 0) != 4) return null;
            return (try effect_history.Checkpoint.decode(try row.boundedBytes(0, effect_history.checkpoint_bytes))).last_sequence;
        }
        fn internalHeld(retention: Retention, source: []const u8, cursor: []const u8) Error!bool {
            if (!std.mem.eql(u8, source, recurrence.source_id)) return false;
            const committed = retention.history orelse return true;
            const sequence = std.fmt.parseInt(u64, cursor, 10) catch return error.InvalidMaintenanceState;
            return sequence > committed;
        }
        fn decisionOwnerPresent(self: *Store, retention: Retention, jail: []const u8, subject: detection.Subject) Error!bool {
            const installation = retention.installation orelse return false;
            if (subject.unenforceable()) return false;
            const key = try (try effects.Scope.host(subject)).key(installation);
            var row = try self.statement("SELECT lease_kind,deadline_us FROM effect_owners WHERE scope_key=?1 AND jail=?2;");
            defer row.deinit();
            try row.blob(1, &key);
            try row.text(2, jail);
            if (!try row.row()) return false;
            return switch (try row.signed(0)) {
                0 => false,
                1 => (try row.optionalSigned(1) orelse return error.InvalidEffect) > retention.now,
                2 => true,
                else => error.InvalidEffect,
            };
        }
        fn recordIsCursorAnchor(self: *Store, jail: []const u8, source: []const u8, occurrence: []const u8) Error!bool {
            var anchor = try self.statement("SELECT occurrence FROM source_cursors WHERE jail=?1 AND source=?2;");
            defer anchor.deinit();
            try anchor.text(1, jail);
            try anchor.text(2, source);
            if (!try anchor.row()) return false;
            if (self.api.column_type(anchor.ptr, 0) != 3) return error.InvalidMaintenanceState;
            return std.mem.eql(u8, try anchor.boundedBytes(0, 16384), occurrence);
        }
        fn recordCleanupPinned(self: *Store, retention: Retention, jail: []const u8, source: []const u8, occurrence: []const u8) Error!bool {
            var action = try self.statement("SELECT 1 FROM action_intents WHERE jail=?1 AND source=?2 AND occurrence=?3 LIMIT 1;");
            defer action.deinit();
            try action.text(1, jail);
            try action.text(2, source);
            try action.text(3, occurrence);
            if (try action.row()) return true;
            var decisions: [max_native_detections]retry.Decision = undefined;
            const decision_count = try self.retryDecisions(jail, source, occurrence, &decisions);
            for (decisions[0..decision_count]) |decision| if (decision.lease.live(retention.now) or try self.decisionOwnerPresent(retention, jail, decision.subject)) return true;
            return false;
        }
        fn orderedIdentity(row: *Stmt, jail: []const u8, source: []const u8, generation: [32]u8) Error!ReceiptIdentity {
            if (row.store.api.column_type(row.ptr, 0) != 3 or row.store.api.column_type(row.ptr, 2) != 4) return error.InvalidMaintenanceState;
            const receipt = try row.optionalSigned(3);
            if (receipt != null) {
                if (!std.mem.eql(u8, &try Store.effectBlob(row, 4, 32), &generation)) return error.InvalidMaintenanceState;
            } else if (row.store.api.column_type(row.ptr, 4) != 5) return error.InvalidMaintenanceState;
            const id = ReceiptIdentity{
                .jail = jail,
                .source = source,
                .generation = generation,
                .occurrence = try row.boundedBytes(0, 16384),
                .raw_hash = try Store.effectBlob(row, 1, 32),
                .cursor = try row.boundedBytes(2, Limits.cursor_bytes),
            };
            try Store.validateReceiptIdentity(id);
            return id;
        }
        fn updateCleanupState(self: *Store, jail: []const u8, source: []const u8, generation: [32]u8, old: SourceMaintenance, next: SourceMaintenance) Error!void {
            if (old.cleanup_revision >= std.math.maxInt(i64) - 1) return error.StorageLimit;
            var row = try self.statement("UPDATE source_maintenance SET reject_below_sequence=?4,cleanup_revision=?5,sweep_sequence=?6 WHERE jail=?1 AND source=?2 AND generation=?3 AND head_sequence=?7 AND cleanup_revision=?8;");
            defer row.deinit();
            try row.text(1, jail);
            try row.text(2, source);
            try row.blob(3, &generation);
            try row.int(4, @intCast(next.reject_below_sequence));
            try row.int(5, @intCast(next.cleanup_revision));
            try row.int(6, @intCast(next.sweep_sequence));
            try row.int(7, @intCast(old.head_sequence));
            try row.int(8, @intCast(old.cleanup_revision));
            try row.done();
            if (self.api.changes(self.db) != 1) return error.StaleMaintenance;
        }
        fn copyColumn(row: *Stmt, column: c_int, buffer: []u8) Error![]const u8 {
            const view = try row.boundedBytes(column, buffer.len);
            @memcpy(buffer[0..view.len], view);
            return buffer[0..view.len];
        }
        fn sweepSourceRange(self: *Store, retention: Retention, jail: []const u8, source: []const u8, generation: [32]u8, cutoff: u64, max_records: usize) Error!usize {
            const current = try self.sourceMaintenance(jail, source, generation) orelse return 0;
            const limit = @min(cutoff, current.head_sequence - 1);
            var next = current;
            var deleted: usize = 0;
            var handled: usize = 0;
            var occurrence_buffer: [16384]u8 = undefined;
            while (next.sweep_sequence < limit and handled < max_records and self.work_remaining >= cleanup_work_reserve) : (handled += 1) {
                var sequence: u64 = undefined;
                var occurrence: []const u8 = undefined;
                var held = false;
                {
                    var row = try self.statement("SELECT source_sequence,occurrence,cursor FROM records WHERE jail=?1 AND source=?2 AND source_generation=?3 AND source_sequence>?4 AND source_sequence<=?5 ORDER BY source_sequence LIMIT 1;");
                    defer row.deinit();
                    try row.text(1, jail);
                    try row.text(2, source);
                    try row.blob(3, &generation);
                    try row.int(4, @intCast(next.sweep_sequence));
                    try row.int(5, @intCast(limit));
                    if (!try row.row()) {
                        next.sweep_sequence = limit;
                        break;
                    }
                    if (self.api.column_type(row.ptr, 1) != 3 or self.api.column_type(row.ptr, 2) != 4) return error.InvalidMaintenanceState;
                    sequence = std.math.cast(u64, try row.signed(0)) orelse return error.InvalidMaintenanceState;
                    occurrence = try copyColumn(&row, 1, &occurrence_buffer);
                    held = try internalHeld(retention, source, try row.boundedBytes(2, Limits.cursor_bytes));
                }
                // Why: The record source_cursors still names is never deleted, and this watermark sweep cannot skip it, so it stops there.
                if (held or try self.recordIsCursorAnchor(jail, source, occurrence)) break;
                // Why: A pinned record keeps its row but drops its sequence, so the watermark can advance past it.
                if (try self.recordCleanupPinned(retention, jail, source, occurrence)) {
                    try self.detachRecord(jail, source, occurrence);
                } else {
                    _ = try self.deleteRecordGroup(jail, source, occurrence, max_group_rows) orelse return error.InvalidMaintenanceState;
                    deleted += 1;
                }
                next.sweep_sequence = sequence;
            }
            if (next.sweep_sequence == current.sweep_sequence) return deleted;
            next.reject_below_sequence = @max(current.reject_below_sequence, next.sweep_sequence + 1);
            next.cleanup_revision = std.math.add(u64, current.cleanup_revision, 1) catch return error.StorageLimit;
            try self.updateCleanupState(jail, source, generation, current, next);
            return deleted;
        }
        pub fn releasePreviousRecords(self: *Store, range: Store.SourceRange) Error!void {
            const internal = std.mem.eql(u8, range.source, recurrence.source_id);
            const retention = Retention{
                .now = try self.readRetryClock() orelse std.math.minInt(i64),
                .history = if (internal) try self.committedHistorySequence() else null,
                .installation = try self.readInstallation(),
            };
            const deleted = try self.sweepSourceRange(retention, range.jail, range.source, range.generation, range.cutoff, max_batch_records);
            if (comptime build_options.diag) diag_mod.count(.coupled_cleanup_groups, deleted);
        }
        pub fn releaseHistoryRecords(self: *Store, internal: InternalSource) Error!void {
            const retention = Retention{ .now = try self.readRetryClock() orelse std.math.minInt(i64), .history = try self.committedHistorySequence(), .installation = try self.readInstallation() };
            const deleted = try self.sweepSourceRange(retention, internal.jail, recurrence.source_id, internal.generation, std.math.maxInt(u64), effect_history.max_page);
            if (comptime build_options.diag) diag_mod.count(.history_cleanup_groups, deleted);
        }
        const RetiredStep = struct { deleted: usize, next: ?i64 };
        fn zeroRetiredStep(self: *Store) Error!RetiredStep {
            var window = try self.statement("SELECT max(rowid),count(*) FROM (SELECT rowid FROM retry_retired WHERE rowid>?1 ORDER BY rowid LIMIT ?2);");
            defer window.deinit();
            try window.int(1, self.retired_cursor);
            try window.int(2, max_cleanup_groups);
            if (!try window.row()) return error.DatabaseFailure;
            if (try window.signed(1) == 0) return .{ .deleted = 0, .next = null };
            const last = try window.signed(0);
            var remove = try self.statement("DELETE FROM retry_retired WHERE rowid>?1 AND rowid<=?2 AND decisions=0;");
            defer remove.deinit();
            try remove.int(1, self.retired_cursor);
            try remove.int(2, last);
            try remove.done();
            return .{ .deleted = std.math.cast(usize, self.api.changes(self.db)) orelse return error.DatabaseFailure, .next = last };
        }
        fn maintenanceHeadersHeld(self: *Store, jail: []const u8, retiring: bool) Error!bool {
            inline for (.{ "records", "source_cursors", "pending_receipts", "consumer_manifests" }) |table| {
                var row = try self.statement("SELECT 1 FROM " ++ table ++ " WHERE jail=?1 LIMIT 1;");
                defer row.deinit();
                try row.text(1, jail);
                if (try row.row()) return true;
            }
            {
                var row = try self.statement("SELECT 1 FROM consumer_requirements WHERE manifest_jail=?1 LIMIT 1;");
                defer row.deinit();
                try row.text(1, jail);
                if (try row.row()) return true;
            }
            if (!retiring) {
                inline for (.{ "checkpoints", "retry_policies", "jail_retirements" }) |table| {
                    var row = try self.statement("SELECT 1 FROM " ++ table ++ " WHERE jail=?1 LIMIT 1;");
                    defer row.deinit();
                    try row.text(1, jail);
                    if (try row.row()) return true;
                }
            }
            return false;
        }
        pub fn retireMaintenanceHeadersTx(self: *Store, jail: []const u8, max_rows: u8, clock: effects.Clock) Error!u16 {
            if (max_rows == 0 or max_rows > 64 or self.api.get_autocommit(self.db) != 0) return error.InvalidMaintenanceState;
            if (try self.maintenanceHeadersHeld(jail, true)) return error.MaintenancePinned;
            var deleted: u16 = 0;
            while (deleted < max_rows) : (deleted += 1) {
                const id = blk: {
                    var row = try self.statement("SELECT rowid FROM source_maintenance WHERE jail=?1 ORDER BY source,generation LIMIT 1;");
                    defer row.deinit();
                    try row.text(1, jail);
                    if (!try row.row()) break;
                    break :blk try row.signed(0);
                };
                var remove = try self.statement("DELETE FROM source_maintenance WHERE rowid=?1 AND jail=?2;");
                defer remove.deinit();
                try remove.int(1, id);
                try remove.text(2, jail);
                try remove.done();
                if (self.api.changes(self.db) != 1) return error.InvalidMaintenanceState;
            }
            if (deleted != 0) try self.finishCleanupClock(clock, clock.prepared_us);
            return deleted;
        }
        fn orphanHeaderStep(self: *Store) Error!RetiredStep {
            var position = self.source_header_cursor;
            var deleted: usize = 0;
            var jail_buffer: [4096]u8 = undefined;
            const configured = try self.latestConfigGeneration();
            for (0..8) |_| {
                if (self.work_remaining < cleanup_work_reserve) break;
                const jail = blk: {
                    var row = try self.statement("SELECT rowid,jail FROM source_maintenance WHERE rowid>?1 ORDER BY rowid LIMIT 1;");
                    defer row.deinit();
                    try row.int(1, position);
                    if (!try row.row()) return .{ .deleted = deleted, .next = null };
                    position = try row.signed(0);
                    if (self.api.column_type(row.ptr, 1) != 3) return error.InvalidMaintenanceState;
                    break :blk try copyColumn(&row, 1, &jail_buffer);
                };
                if (try self.maintenanceHeadersHeld(jail, false)) continue;
                if (configured) |*head| {
                    var row = try self.statement("SELECT 1 FROM config_generation_jails WHERE generation=?1 AND jail=?2;");
                    defer row.deinit();
                    try row.blob(1, &head.generation);
                    try row.text(2, jail);
                    if (try row.row()) continue;
                }
                var remove = try self.statement("DELETE FROM source_maintenance WHERE rowid=?1;");
                defer remove.deinit();
                try remove.int(1, position);
                try remove.done();
                if (self.api.changes(self.db) != 1) return error.InvalidMaintenanceState;
                deleted += 1;
            }
            return .{ .deleted = deleted, .next = position };
        }
        pub fn cleanupRecords(self: *Store, clock: effects.Clock) Error!RecordCleanup {
            if (self.schema_version < 15) return .idle;
            try self.beginWrite();
            errdefer self.rollback();
            const now = try self.cleanupClock(clock);
            _ = try self.maintenanceRevision();
            const headers: ?RetiredStep = if (self.schema_version < 28 or self.source_header_sweep_done) null else try self.orphanHeaderStep();
            const headers_deleted = if (headers) |step| step.deleted else 0;
            const retention = Retention{ .now = now, .history = try self.committedHistorySequence(), .installation = try self.readInstallation() };
            var position = self.cleanup_cursor;
            var deleted: usize = 0;
            var examined: usize = 0;
            var wrapped = false;
            var jail_buffer: [4096]u8 = undefined;
            var source_buffer: [Limits.source_bytes]u8 = undefined;
            var occurrence_buffer: [16384]u8 = undefined;
            while (examined < max_cleanup_groups and self.work_remaining >= cleanup_work_reserve) : (examined += 1) {
                var jail: []const u8 = undefined;
                var source: []const u8 = undefined;
                var occurrence: []const u8 = undefined;
                var order: ?Store.RecordSequence = null;
                var held = false;
                {
                    var row = try self.statement("SELECT rowid,jail,source,occurrence,cursor,source_generation,source_sequence FROM records WHERE rowid>?1 ORDER BY rowid LIMIT 1;");
                    defer row.deinit();
                    try row.int(1, position);
                    if (!try row.row()) {
                        wrapped = true;
                        break;
                    }
                    inline for (1..4) |column| if (self.api.column_type(row.ptr, column) != 3) return error.InvalidMaintenanceState;
                    if (self.api.column_type(row.ptr, 4) != 4) return error.InvalidMaintenanceState;
                    position = try row.signed(0);
                    jail = try copyColumn(&row, 1, &jail_buffer);
                    source = try copyColumn(&row, 2, &source_buffer);
                    occurrence = try copyColumn(&row, 3, &occurrence_buffer);
                    held = try internalHeld(retention, source, try row.boundedBytes(4, Limits.cursor_bytes));
                    if (try row.optionalSigned(6)) |sequence| order = .{
                        .generation = try Store.effectBlob(&row, 5, 32),
                        .sequence = std.math.cast(u64, sequence) orelse return error.InvalidMaintenanceState,
                    };
                }
                if (order) |sequenced| {
                    const state = try self.sourceMaintenance(jail, source, sequenced.generation) orelse return error.InvalidMaintenanceState;
                    // Why: advanceSourceSequence requires the newest retained sequence to equal head, so the head record is kept.
                    if (sequenced.sequence == state.head_sequence) continue;
                }
                if (held or try self.recordIsCursorAnchor(jail, source, occurrence) or try self.recordCleanupPinned(retention, jail, source, occurrence)) continue;
                _ = try self.deleteRecordGroup(jail, source, occurrence, max_group_rows) orelse return error.InvalidMaintenanceState;
                deleted += 1;
            }
            const retired: ?RetiredStep = if (self.retired_sweep_done or self.work_remaining < cleanup_work_reserve) null else try self.zeroRetiredStep();
            const retired_deleted = if (retired) |step| step.deleted else 0;
            if (deleted != 0 or retired_deleted != 0 or headers_deleted != 0) try self.finishCleanupClock(clock, now);
            try self.fault(.before_cleanup_commit);
            try self.commitTransaction();
            self.cleanup_cursor = if (wrapped) 0 else position;
            if (headers) |step| {
                if (step.next) |last| self.source_header_cursor = last else self.source_header_sweep_done = true;
            }
            if (retired) |step| {
                if (step.next) |last| {
                    self.retired_cursor = last;
                    self.retired_cycle_deleted = self.retired_cycle_deleted or step.deleted != 0;
                } else {
                    self.retired_sweep_done = !self.retired_cycle_deleted;
                    self.retired_cycle_deleted = false;
                    self.retired_cursor = 0;
                }
            }
            if (comptime build_options.diag) {
                diag_mod.count(.record_cleanup_groups, deleted);
                diag_mod.count(.retired_zero_rows, retired_deleted);
            }
            const cycle_deleted = self.cleanup_cycle_deleted or deleted != 0 or retired_deleted != 0 or headers_deleted != 0;
            self.cleanup_cycle_deleted = cycle_deleted and !wrapped;
            if (deleted != 0 or retired_deleted != 0 or headers_deleted != 0) return .deleted;
            if (headers != null and !self.source_header_sweep_done) return .scanned;
            return if (wrapped and !cycle_deleted) .idle else .scanned;
        }
        fn countRecordChildren(self: *Store, jail: []const u8, source: []const u8, occurrence: []const u8, comptime table: []const u8) Error!usize {
            var row = try self.statement("SELECT count(*) FROM " ++ table ++ " WHERE jail=?1 AND source=?2 AND occurrence=?3;");
            defer row.deinit();
            try row.text(1, jail);
            try row.text(2, source);
            try row.text(3, occurrence);
            if (!try row.row()) return error.InvalidMaintenanceState;
            const count = try row.signed(0);
            if (count < 0 or count > max_native_detections) return error.InvalidRecord;
            return @intCast(count);
        }
        fn recordGroupRows(self: *Store, jail: []const u8, source: []const u8, occurrence: []const u8) Error!usize {
            var rows = 1 + try self.countRecordChildren(jail, source, occurrence, "record_detections") + try self.countRecordChildren(jail, source, occurrence, "retry_decisions");
            if (self.schema_version >= 18) rows += try self.countRecordChildren(jail, source, occurrence, "retry_decision_escalations");
            return rows;
        }
        fn deleteRecordGroup(self: *Store, jail: []const u8, source: []const u8, occurrence_view: []const u8, budget: usize) Error!?usize {
            const group_rows = try self.recordGroupRows(jail, source, occurrence_view);
            if (group_rows > budget) return null;
            var occurrence_buffer: [16384]u8 = undefined;
            @memcpy(occurrence_buffer[0..occurrence_view.len], occurrence_view);
            const occurrence = occurrence_buffer[0..occurrence_view.len];
            var deleted: usize = 0;
            if (self.schema_version >= 18) {
                try self.fault(.before_cleanup_escalation_delete);
                var remove = try self.statement("DELETE FROM retry_decision_escalations WHERE jail=?1 AND source=?2 AND occurrence=?3;");
                defer remove.deinit();
                try remove.text(1, jail);
                try remove.text(2, source);
                try remove.text(3, occurrence);
                try remove.done();
                const changed = self.api.changes(self.db);
                if (changed < 0 or changed > budget - deleted) return error.InvalidMaintenanceState;
                deleted += @intCast(changed);
                try self.fault(.after_cleanup_escalation_delete);
                try self.fault(.after_cleanup_delete);
            }
            inline for (.{ "record_detections", "retry_decisions", "records" }) |table| {
                if (comptime std.mem.eql(u8, table, "retry_decisions")) try self.fault(.before_cleanup_retry_delete);
                var remove = try self.statement("DELETE FROM " ++ table ++ " WHERE jail=?1 AND source=?2 AND occurrence=?3;");
                defer remove.deinit();
                try remove.text(1, jail);
                try remove.text(2, source);
                try remove.text(3, occurrence);
                try remove.done();
                const changed = self.api.changes(self.db);
                if (changed < 0 or changed > budget - deleted) return error.InvalidMaintenanceState;
                deleted += @intCast(changed);
                if (comptime std.mem.eql(u8, table, "retry_decisions")) try self.fault(.after_cleanup_retry_delete);
                try self.fault(.after_cleanup_delete);
            }
            if (deleted != group_rows) return error.InvalidMaintenanceState;
            return deleted;
        }
        pub const RetiredRecordProgress = struct { examined: u16 = 0, deleted_rows: u16 = 0, done: bool = false };
        pub fn retireRecordGroupsTx(self: *Store, intent: Store.JailRetirementIntent, max_rows: u8, clock: effects.Clock) Error!RetiredRecordProgress {
            if (self.api.get_autocommit(self.db) != 0) return error.DatabaseFailure;
            if (max_rows == 0 or max_rows > 64) return error.InvalidEffect;
            const jail = intent.jail.slice();
            const current_intent = try self.jailRetirement(jail) orelse return error.StaleEffect;
            if (current_intent.keep_ignore_deadlines != intent.keep_ignore_deadlines) return error.StaleEffect;
            _ = try self.maintenanceRevision();
            const now = try self.cleanupClock(clock);
            var source_buffer: [Limits.source_bytes]u8 = undefined;
            var occurrence_buffer: [16384]u8 = undefined;
            var progress: RetiredRecordProgress = .{};
            var keys: usize = 0;
            while (progress.examined < max_rows and progress.deleted_rows < max_rows) {
                var found = false;
                var attached = false;
                var source: []const u8 = undefined;
                var occurrence: []const u8 = undefined;
                var cursor_len: usize = undefined;
                var sequence: u64 = undefined;
                var generation: [32]u8 = undefined;
                for ([_][:0]const u8{
                    "SELECT occurrence,raw_hash,cursor,receipt_us,receipt_generation,source,source_generation,source_sequence FROM records INDEXED BY records_source_order WHERE jail=?1 AND source_sequence IS NOT NULL ORDER BY source,source_generation,source_sequence LIMIT 1;",
                    "SELECT occurrence,raw_hash,cursor,receipt_us,receipt_generation,source,source_generation,source_sequence FROM records WHERE jail=?1 ORDER BY source,occurrence LIMIT 1;",
                }, 0..) |sql, selector| {
                    var row = try self.statement(sql);
                    defer row.deinit();
                    try row.text(1, jail);
                    if (!try row.row()) continue;
                    attached = selector == 0;
                    if (self.api.column_type(row.ptr, 0) != 3 or self.api.column_type(row.ptr, 5) != 3) return error.InvalidMaintenanceState;
                    const source_view = try row.boundedBytes(5, Limits.source_bytes);
                    const occurrence_view = try row.boundedBytes(0, occurrence_buffer.len);
                    @memcpy(source_buffer[0..source_view.len], source_view);
                    @memcpy(occurrence_buffer[0..occurrence_view.len], occurrence_view);
                    source = source_buffer[0..source_view.len];
                    occurrence = occurrence_buffer[0..occurrence_view.len];
                    if (attached) {
                        const saved_sequence = try row.signed(7);
                        if (saved_sequence <= 0) return error.InvalidMaintenanceState;
                        sequence = @intCast(saved_sequence);
                        generation = try Store.effectBlob(&row, 6, 32);
                        cursor_len = (try orderedIdentity(&row, jail, source, generation)).cursor.len;
                    } else {
                        if (self.api.column_type(row.ptr, 6) != 5 or self.api.column_type(row.ptr, 7) != 5 or self.api.column_type(row.ptr, 2) != 4) return error.InvalidMaintenanceState;
                        cursor_len = (try row.boundedBytes(2, Limits.cursor_bytes)).len;
                    }
                    found = true;
                    break;
                }
                if (!found) {
                    progress.done = true;
                    break;
                }
                progress.examined += 1;
                const state: ?SourceMaintenance = if (attached) try self.sourceMaintenance(jail, source, generation) orelse return error.InvalidMaintenanceState else null;
                if (state) |current| if (sequence <= current.sweep_sequence or sequence > current.head_sequence) return error.InvalidMaintenanceState;
                {
                    var action = try self.statement("SELECT 1 FROM action_intents WHERE jail=?1 AND source=?2 AND occurrence=?3 LIMIT 1;");
                    defer action.deinit();
                    try action.text(1, jail);
                    try action.text(2, source);
                    try action.text(3, occurrence);
                    if (try action.row()) return error.MaintenancePinned;
                }
                const group_rows = try self.recordGroupRows(jail, source, occurrence);
                const bytes = jail.len + source.len + occurrence.len + cursor_len + 64;
                if (bytes > 1024 * 1024 - keys or (progress.deleted_rows != 0 and group_rows > max_rows - progress.deleted_rows)) break;
                progress.deleted_rows += @intCast(try self.deleteRecordGroup(jail, source, occurrence, group_rows) orelse return error.InvalidMaintenanceState);
                if (state) |current| {
                    var next = current;
                    next.sweep_sequence = sequence;
                    next.reject_below_sequence = @max(current.reject_below_sequence, sequence + 1);
                    next.cleanup_revision = std.math.add(u64, current.cleanup_revision, 1) catch return error.StorageLimit;
                    try self.updateCleanupState(jail, source, generation, current, next);
                    try self.fault(.after_cleanup_mark);
                }
                keys += bytes;
            }
            if (progress.deleted_rows != 0) {
                try self.finishCleanupClock(clock, now);
                try self.fault(.before_cleanup_commit);
            }
            return progress;
        }
        fn detachRecord(self: *Store, jail: []const u8, source: []const u8, occurrence: []const u8) Error!void {
            var row = try self.statement("UPDATE records SET source_generation=NULL,source_sequence=NULL WHERE jail=?1 AND source=?2 AND occurrence=?3;");
            defer row.deinit();
            try row.text(1, jail);
            try row.text(2, source);
            try row.text(3, occurrence);
            try row.done();
            if (self.api.changes(self.db) != 1) return error.InvalidMaintenanceState;
        }
        pub const MaintenanceValidation = struct {
            phase: enum { headers, done } = .headers,
            revision: ?u64 = null,
            data_version: i64 = 0,
            jail: [4096]u8 = undefined,
            jail_len: usize = 0,
            source: [Limits.source_bytes]u8 = undefined,
            source_len: usize = 0,
            generation: [32]u8 = undefined,
            fn setKey(self: *MaintenanceValidation, jail: []const u8, source: []const u8, generation: [32]u8) void {
                @memcpy(self.jail[0..jail.len], jail);
                self.jail_len = jail.len;
                @memcpy(self.source[0..source.len], source);
                self.source_len = source.len;
                self.generation = generation;
            }
        };
        fn validateMaintenanceHeader(self: *Store, jail: []const u8, source: []const u8, generation: [32]u8) Error!void {
            const state = try self.sourceMaintenance(jail, source, generation) orelse return error.InvalidMaintenanceState;
            for ([_][:0]const u8{
                "SELECT source_sequence FROM records WHERE jail=?1 AND source=?2 AND source_generation=?3 AND source_sequence IS NOT NULL ORDER BY source_sequence LIMIT 1;",
                "SELECT source_sequence FROM records WHERE jail=?1 AND source=?2 AND source_generation=?3 AND source_sequence IS NOT NULL ORDER BY source_sequence DESC LIMIT 1;",
            }, 0..) |query, index| {
                var row = try self.statement(query);
                defer row.deinit();
                try row.text(1, jail);
                try row.text(2, source);
                try row.blob(3, &generation);
                if (!try row.row()) break;
                const value = try row.signed(0);
                if (value <= state.sweep_sequence or value > state.head_sequence or (index == 1 and value != state.head_sequence)) return error.InvalidMaintenanceState;
            }
            if ((state.cleanup_revision == 0) != (state.reject_below_sequence == 1 and state.sweep_sequence == 0)) return error.InvalidMaintenanceState;
        }
        pub fn validateMaintenanceTurn(self: *Store, cursor: *MaintenanceValidation) Error!bool {
            if (cursor.jail_len > cursor.jail.len or cursor.source_len > cursor.source.len) return error.InvalidMaintenanceState;
            try self.beginRead();
            errdefer self.rollback();
            const revision_value = try self.maintenanceRevision();
            const data_version = try self.integer("PRAGMA data_version;");
            var next = cursor.*;
            if (next.revision) |expected| {
                if (expected != revision_value or next.data_version != data_version) return error.StaleMaintenance;
            } else {
                next.revision = revision_value;
                next.data_version = data_version;
            }
            var key_bytes: usize = 0;
            for (0..16) |_| {
                if (next.phase == .done) break;
                var row = try self.statement(if (next.jail_len == 0) "SELECT jail,source,generation FROM source_maintenance ORDER BY jail,source,generation LIMIT 1;" else "SELECT jail,source,generation FROM source_maintenance WHERE (jail,source,generation)>(?1,?2,?3) ORDER BY jail,source,generation LIMIT 1;");
                defer row.deinit();
                if (next.jail_len != 0) {
                    try row.text(1, next.jail[0..next.jail_len]);
                    try row.text(2, next.source[0..next.source_len]);
                    try row.blob(3, &next.generation);
                }
                if (!try row.row()) {
                    next.phase = .done;
                    next.jail_len = 0;
                    next.source_len = 0;
                    break;
                }
                if (self.api.column_type(row.ptr, 0) != 3 or self.api.column_type(row.ptr, 1) != 3) return error.InvalidMaintenanceState;
                const jail = try row.boundedBytes(0, 4096);
                const source = try row.boundedBytes(1, Limits.source_bytes);
                const generation = try Store.effectBlob(&row, 2, 32);
                try Store.maintenanceKey(jail, source);
                try self.validateMaintenanceHeader(jail, source, generation);
                const bytes = jail.len + source.len + 104;
                if (bytes > 1024 * 1024 - key_bytes) break;
                key_bytes += bytes;
                next.setKey(jail, source, generation);
            }
            if (try self.maintenanceRevision() != revision_value or try self.integer("PRAGMA data_version;") != data_version) return error.StaleMaintenance;
            try self.commitTransaction();
            cursor.* = next;
            return next.phase == .done;
        }
        pub fn finishMaintenanceValidation(self: *Store, cursor: *const MaintenanceValidation) Error!void {
            if (cursor.phase != .done or cursor.revision == null or cursor.revision.? != try self.maintenanceRevision() or
                cursor.data_version != try self.integer("PRAGMA data_version;")) return error.StaleMaintenance;
        }
    };
}
