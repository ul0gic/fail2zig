// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const consumers = @import("../core/native_consumer.zig");
const detection = @import("../core/native_detection_record.zig");
const retry = @import("../core/native_retry.zig");
const effects = @import("../core/native_effect.zig");
const effect_history = @import("../core/native_effect_history.zig");
const application_history = @import("../core/native_application_history.zig");
const action_outcome = @import("../core/native_action_outcome.zig");
const store = @import("store.zig");
const Error = store.Error;
const Stmt = store.Stmt;
const Limits = store.Limits;
const latest_schema = store.latest_schema;
const max_native_detections = store.max_native_detections;

pub fn Methods(comptime Store: type) type {
    return struct {
        const SourceMaintenance = Store.SourceMaintenance;
        const ReceiptIdentity = store.ReceiptIdentity;
        const HistoryResetIntent = store.HistoryResetIntent;
        const HistoryResetResult = store.HistoryResetResult;
        pub fn adminRevision(self: *Store) Error!u64 {
            if (self.schema_version < 22) return error.AdminStorageRequired;
            const value = try self.integer("SELECT mutation_revision FROM admin_revision WHERE id=1;");
            if (value < 0) return error.DatabaseFailure;
            return @intCast(value);
        }

        pub const CleanupFence = struct {
            jail: []const u8,
            source: []const u8,
            generation: [32]u8,
            jail_revision: u64,
            consumer_revision: u64,
            effect_revision: u64,
            history: ?effect_history.PageToken = null,
            manifest: ?consumers.Manifest = null,
            clock: effects.Clock,
            preparations: enum { held, released } = .held,
        };
        pub const CleanupToken = struct { binding: [32]u8, state: SourceMaintenance };
        pub const CleanupProgress = struct { deleted_rows: u8, more: bool, state: SourceMaintenance };
        pub fn maintenanceRevision(self: *Store) Error!u64 {
            if (self.schema_version < 15) return error.MaintenanceStorageRequired;
            var row = try self.statement("SELECT revision FROM maintenance_clock WHERE id=1;");
            defer row.deinit();
            if (!try row.row()) return error.InvalidMaintenanceState;
            const value = try row.signed(0);
            if (value < 0 or value == std.math.maxInt(i64)) return error.InvalidMaintenanceState;
            return @intCast(value);
        }
        pub fn maintenanceConsumerRevision(self: *Store) Error!u64 {
            return self.consumerRevision();
        }
        pub fn cleanupResume(self: *Store, jail: []const u8, source: []const u8, generation: [32]u8) Error!?CleanupToken {
            _ = try self.maintenanceRevision();
            const state = try self.sourceMaintenance(jail, source, generation) orelse return null;
            if (state.sweep_sequence + 1 >= state.reject_below_sequence) return null;
            return .{ .binding = effects.hashParts("fail2zig-cleanup-source-v1", &.{ jail, source, &generation }), .state = state };
        }
        pub fn maintenanceEffectRevision(self: *Store) Error!u64 {
            const value = try self.integer("SELECT revision FROM effect_clock WHERE singleton=1;");
            if (value < 0) return error.InvalidEffect;
            return @intCast(value);
        }
        fn cleanupClock(self: *Store, clock: effects.Clock) Error!i64 {
            const now = clock.read(clock.context);
            if (now < clock.prepared_us) return error.ReceiptClockReversed;
            if (try self.readAdmissionClock(self.schema_version)) |floor| if (now < floor.us) return error.ReceiptClockReversed;
            return now;
        }
        fn finishCleanupClock(self: *Store, clock: effects.Clock, initial: i64) Error!void {
            const now = try self.cleanupClock(clock);
            if (now < initial) return error.ReceiptClockReversed;
            _ = try self.maintenanceRevision();
            var row = try self.statement("UPDATE maintenance_clock SET floor_us=?1,revision=revision+1 WHERE id=1 AND revision<9223372036854775806;");
            defer row.deinit();
            try row.int(1, now);
            try row.done();
            if (self.api.changes(self.db) != 1) return error.StorageLimit;
        }
        fn checkCleanupFence(self: *Store, fence: CleanupFence) Error!i64 {
            _ = try self.maintenanceRevision();
            try Store.maintenanceKey(fence.jail, fence.source);
            if (fence.preparations != .released) return error.MaintenancePinned;
            if (try self.revision(fence.jail) != fence.jail_revision or try self.consumerRevision() != fence.consumer_revision or
                try self.maintenanceEffectRevision() != fence.effect_revision) return error.StaleMaintenance;
            if (try self.readRetryPolicy(fence.jail)) |policy| if (!std.mem.eql(u8, &policy.generation, &fence.generation)) return error.RetryGenerationMismatch;
            var pending = try self.statement("SELECT 1 FROM pending_receipts WHERE jail=?1 LIMIT 1;");
            defer pending.deinit();
            try pending.text(1, fence.jail);
            if (try pending.row()) return error.MaintenancePinned;
            if (try self.manifestExists(fence.jail, fence.source) != (fence.manifest != null)) return error.ConsumerManifestRequired;
            if (fence.manifest) |manifest| {
                if (!std.mem.eql(u8, manifest.jail, fence.jail) or !std.mem.eql(u8, manifest.source, fence.source) or
                    !std.mem.eql(u8, &manifest.source_generation, &fence.generation)) return error.ConsumerManifestMismatch;
                if (try self.checkManifest(manifest) != .ready) return error.MissingRequiredConsumer;
                for (manifest.required) |requirement| try self.checkRequiredState(requirement, false);
            }
            if (try self.readInstallation()) |installation| {
                const token = fence.history orelse return error.HistoryGap;
                if (token.after_sequence != token.head_sequence or token.last_sequence != token.head_sequence) return error.HistoryGap;
                try self.validateConfirmedEffectPageTx(token);
                var owner = try effect_history.Consumer.init(installation, effects.hashParts("fail2zig-native-confirmed-history-v1", &.{}));
                const manifest = owner.manifest();
                if (try self.checkManifest(manifest) != .ready) return error.MissingRequiredConsumer;
                try self.checkRequiredState(manifest.required[0], false);
                var row = try self.statement("SELECT payload FROM consumer_checkpoints WHERE kind=?1 AND jail=?2 AND source=?3 AND rule=?4 AND generation=?5;");
                defer row.deinit();
                try Store.bindConsumerKey(&row, &manifest.required[0].key);
                if (!try row.row() or self.api.column_type(row.ptr, 0) != 4) return error.MissingRequiredConsumer;
                const saved = try effect_history.Checkpoint.decode(try row.boundedBytes(0, effect_history.checkpoint_bytes));
                if (saved.last_sequence != token.head_sequence or !std.mem.eql(u8, &saved.installation, &installation.id) or
                    !std.mem.eql(u8, &saved.generation, &manifest.source_generation)) return error.HistoryGap;
            } else if (fence.history != null or try self.integer("SELECT EXISTS(SELECT 1 FROM native_effects);") != 0) return error.InvalidEffect;
            return self.cleanupClock(fence.clock);
        }
        fn subjectEffectPinned(self: *Store, subject: detection.Subject) Error!bool {
            const installation = try self.readInstallation() orelse return false;
            const scope = try effects.Scope.host(subject);
            if (try self.readEffect(try scope.key(installation), installation)) |entry| {
                return entry.desired != .absent or entry.status != .absent;
            }
            return false;
        }
        fn recordCleanupPinned(self: *Store, fence: CleanupFence, occurrence: []const u8, now: i64) Error!bool {
            var anchor = try self.statement("SELECT occurrence FROM source_cursors WHERE jail=?1 AND source=?2;");
            defer anchor.deinit();
            try anchor.text(1, fence.jail);
            try anchor.text(2, fence.source);
            if (!try anchor.row() or self.api.column_type(anchor.ptr, 0) != 3) return error.InvalidMaintenanceState;
            if (std.mem.eql(u8, try anchor.boundedBytes(0, 16384), occurrence)) return true;
            var action = try self.statement("SELECT 1 FROM action_intents WHERE jail=?1 AND source=?2 AND occurrence=?3 LIMIT 1;");
            defer action.deinit();
            try action.text(1, fence.jail);
            try action.text(2, fence.source);
            try action.text(3, occurrence);
            if (try action.row()) return true;
            const policy = try self.readRetryPolicy(fence.jail);
            const occurrence_key = retry.occurrenceKey(fence.source, occurrence);
            var detections = try self.statement("SELECT family,subject FROM record_detections WHERE jail=?1 AND source=?2 AND occurrence=?3 AND kind=?4;");
            defer detections.deinit();
            try detections.text(1, fence.jail);
            try detections.text(2, fence.source);
            try detections.text(3, occurrence);
            try detections.int(4, @intFromEnum(detection.Kind.candidate));
            var count: usize = 0;
            while (try detections.row()) {
                count += 1;
                if (count > max_native_detections) return error.InvalidRecord;
                if (self.api.column_type(detections.ptr, 0) == 5 and self.api.column_type(detections.ptr, 1) == 5) continue;
                const subject = try self.decodeRetrySubject(&detections, 0, 1);
                if (try self.subjectEffectPinned(subject)) return true;
                if (policy) |admission| if (try self.readRetryState(fence.jail, subject, admission.policy)) |state| {
                    for (state.attempts[0..state.count]) |attempt| if (@as(i128, attempt.at_us) >= @as(i128, now) - admission.policy.window_us and std.mem.eql(u8, &attempt.occurrence, &occurrence_key)) return true;
                };
            }
            var decisions: [max_native_detections]retry.Decision = undefined;
            const decision_count = try self.retryDecisions(fence.jail, fence.source, occurrence, &decisions);
            for (decisions[0..decision_count]) |decision| if (decision.lease.live(now) or try self.subjectEffectPinned(decision.subject)) return true;
            return false;
        }
        fn orderRecord(self: *Store, fence: CleanupFence, sequence: u64) Error!Stmt {
            var row = try self.statement("SELECT occurrence,raw_hash,cursor,receipt_us,receipt_generation FROM records WHERE jail=?1 AND source=?2 AND source_generation=?3 AND source_sequence=?4 AND source_sequence IS NOT NULL;");
            errdefer row.deinit();
            try row.text(1, fence.jail);
            try row.text(2, fence.source);
            try row.blob(3, &fence.generation);
            try row.int(4, @intCast(sequence));
            return row;
        }
        fn orderedIdentity(row: *Stmt, fence: CleanupFence) Error!ReceiptIdentity {
            if (row.store.api.column_type(row.ptr, 0) != 3 or row.store.api.column_type(row.ptr, 2) != 4) return error.InvalidMaintenanceState;
            const receipt = try row.optionalSigned(3);
            if (receipt != null) {
                if (!std.mem.eql(u8, &try Store.effectBlob(row, 4, 32), &fence.generation)) return error.InvalidMaintenanceState;
            } else if (row.store.api.column_type(row.ptr, 4) != 5) return error.InvalidMaintenanceState;
            const id = ReceiptIdentity{ .jail = fence.jail, .source = fence.source, .generation = fence.generation, .occurrence = try row.boundedBytes(0, 16384), .raw_hash = try Store.effectBlob(row, 1, 32), .cursor = try row.boundedBytes(2, Limits.cursor_bytes) };
            try Store.validateReceiptIdentity(id);
            return id;
        }
        fn insertReplayGuard(self: *Store, id: ReceiptIdentity, receipt: ?i64, sequence: u64) Error!void {
            const occurrence_key = Store.occurrenceGuardKey(id.occurrence);
            const identity_key = Store.identityGuardKey(id);
            var row = try self.statement("INSERT INTO replay_guards VALUES(?1,?2,?3,?4,?5,?6,?7);");
            defer row.deinit();
            try row.text(1, id.jail);
            try row.text(2, id.source);
            try row.blob(3, &id.generation);
            try row.blob(4, &occurrence_key);
            try row.blob(5, &identity_key);
            if (receipt) |value| try row.int(6, value);
            try row.int(7, @intCast(sequence));
            try row.done();
        }
        fn updateCleanupState(self: *Store, fence: CleanupFence, old: SourceMaintenance, next: SourceMaintenance) Error!void {
            if (old.cleanup_revision >= std.math.maxInt(i64) - 1) return error.StorageLimit;
            var row = try self.statement("UPDATE source_maintenance SET reject_below_sequence=?4,cleanup_revision=?5,sweep_sequence=?6 WHERE jail=?1 AND source=?2 AND generation=?3 AND head_sequence=?7 AND cleanup_revision=?8;");
            defer row.deinit();
            try row.text(1, fence.jail);
            try row.text(2, fence.source);
            try row.blob(3, &fence.generation);
            try row.int(4, @intCast(next.reject_below_sequence));
            try row.int(5, @intCast(next.cleanup_revision));
            try row.int(6, @intCast(next.sweep_sequence));
            try row.int(7, @intCast(old.head_sequence));
            try row.int(8, @intCast(old.cleanup_revision));
            try row.done();
            if (self.api.changes(self.db) != 1) return error.StaleMaintenance;
        }
        pub fn cleanupAdvance(self: *Store, fence: CleanupFence, expected: SourceMaintenance, cutoff_sequence: u64) Error!?CleanupToken {
            try self.beginWrite();
            errdefer self.rollback();
            const now = try self.checkCleanupFence(fence);
            const current = try self.sourceMaintenance(fence.jail, fence.source, fence.generation) orelse return error.InvalidMaintenanceState;
            if (!std.meta.eql(current, expected) or cutoff_sequence > current.head_sequence) return error.StaleMaintenance;
            var next = current;
            var keys: usize = 0;
            var count: usize = 0;
            while (next.reject_below_sequence <= cutoff_sequence and count < 64) : (count += 1) {
                var row = try self.orderRecord(fence, next.reject_below_sequence);
                defer row.deinit();
                if (!try row.row()) return error.InvalidMaintenanceState;
                const id = try orderedIdentity(&row, fence);
                const bytes = id.jail.len + id.source.len + id.occurrence.len + id.cursor.len + 64;
                if (bytes > 1024 * 1024 - keys) break;
                if (try self.recordCleanupPinned(fence, id.occurrence, now)) break;
                try self.insertReplayGuard(id, try row.optionalSigned(3), next.reject_below_sequence);
                keys += bytes;
                next.reject_below_sequence += 1;
            }
            if (next.reject_below_sequence == current.reject_below_sequence) {
                try self.commitTransaction();
                return null;
            }
            next.cleanup_revision = std.math.add(u64, current.cleanup_revision, 1) catch return error.StorageLimit;
            try self.updateCleanupState(fence, current, next);
            try self.fault(.after_cleanup_mark);
            try self.finishCleanupClock(fence.clock, now);
            try self.commitTransaction();
            return .{ .binding = effects.hashParts("fail2zig-cleanup-source-v1", &.{ fence.jail, fence.source, &fence.generation }), .state = next };
        }
        fn countRecordChildren(self: *Store, fence: CleanupFence, occurrence: []const u8, comptime table: []const u8) Error!usize {
            var row = try self.statement("SELECT count(*) FROM " ++ table ++ " WHERE jail=?1 AND source=?2 AND occurrence=?3;");
            defer row.deinit();
            try row.text(1, fence.jail);
            try row.text(2, fence.source);
            try row.text(3, occurrence);
            if (!try row.row()) return error.InvalidMaintenanceState;
            const count = try row.signed(0);
            if (count < 0 or count > max_native_detections) return error.InvalidRecord;
            return @intCast(count);
        }
        pub fn cleanupDelete(self: *Store, fence: CleanupFence, token: CleanupToken) Error!CleanupProgress {
            try self.beginWrite();
            errdefer self.rollback();
            const now = try self.checkCleanupFence(fence);
            const current = try self.sourceMaintenance(fence.jail, fence.source, fence.generation) orelse return error.InvalidMaintenanceState;
            const binding = effects.hashParts("fail2zig-cleanup-source-v1", &.{ fence.jail, fence.source, &fence.generation });
            if (!std.mem.eql(u8, &binding, &token.binding) or !std.meta.eql(current, token.state)) return error.StaleMaintenance;
            var next = current;
            var deleted: usize = 0;
            var keys: usize = 0;
            while (next.sweep_sequence + 1 < next.reject_below_sequence and deleted < 64) {
                var row = try self.orderRecord(fence, next.sweep_sequence + 1);
                defer row.deinit();
                if (!try row.row()) return error.InvalidMaintenanceState;
                const id = try orderedIdentity(&row, fence);
                const bytes = id.jail.len + id.source.len + id.occurrence.len + id.cursor.len + 64;
                if (bytes > 1024 * 1024 - keys) break;
                var guarded = false;
                self.checkReplayGuard(id.jail, id.source, id.occurrence, id.raw_hash, id.cursor, id.generation, try row.optionalSigned(3)) catch |failure| {
                    if (failure != error.PrunedReplay) return failure;
                    guarded = true;
                };
                if (!guarded) return error.InvalidMaintenanceState;
                if (try self.recordCleanupPinned(fence, id.occurrence, now)) break;
                var group_rows = 1 + try self.countRecordChildren(fence, id.occurrence, "record_detections") + try self.countRecordChildren(fence, id.occurrence, "retry_decisions");
                // Escalation selections share their retry decision's lifetime and must remain visible to the physical row budget.
                if (self.schema_version >= 18) group_rows += try self.countRecordChildren(fence, id.occurrence, "retry_decision_escalations");
                if (group_rows > 64 - deleted) break;
                var occurrence_buffer: [16384]u8 = undefined;
                @memcpy(occurrence_buffer[0..id.occurrence.len], id.occurrence);
                const occurrence = occurrence_buffer[0..id.occurrence.len];
                const deleted_before = deleted;
                if (self.schema_version >= 18) {
                    try self.fault(.before_cleanup_escalation_delete);
                    var remove = try self.statement("DELETE FROM retry_decision_escalations WHERE jail=?1 AND source=?2 AND occurrence=?3;");
                    defer remove.deinit();
                    try remove.text(1, fence.jail);
                    try remove.text(2, fence.source);
                    try remove.text(3, occurrence);
                    try remove.done();
                    const changed = self.api.changes(self.db);
                    if (changed < 0 or changed > 64 - deleted) return error.InvalidMaintenanceState;
                    deleted += @intCast(changed);
                    try self.fault(.after_cleanup_escalation_delete);
                    try self.fault(.after_cleanup_delete);
                }
                inline for (.{ "record_detections", "retry_decisions", "records" }) |table| {
                    if (comptime std.mem.eql(u8, table, "retry_decisions")) try self.fault(.before_cleanup_retry_delete);
                    var remove = try self.statement("DELETE FROM " ++ table ++ " WHERE jail=?1 AND source=?2 AND occurrence=?3;");
                    defer remove.deinit();
                    try remove.text(1, fence.jail);
                    try remove.text(2, fence.source);
                    try remove.text(3, occurrence);
                    try remove.done();
                    const changed = self.api.changes(self.db);
                    if (changed < 0 or changed > 64 - deleted) return error.InvalidMaintenanceState;
                    deleted += @intCast(changed);
                    if (comptime std.mem.eql(u8, table, "retry_decisions")) try self.fault(.after_cleanup_retry_delete);
                    try self.fault(.after_cleanup_delete);
                }
                if (deleted - deleted_before != group_rows) return error.InvalidMaintenanceState;
                keys += bytes;
                next.sweep_sequence += 1;
            }
            if (deleted != 0) {
                next.cleanup_revision = std.math.add(u64, current.cleanup_revision, 1) catch return error.StorageLimit;
                try self.updateCleanupState(fence, current, next);
                try self.finishCleanupClock(fence.clock, now);
            }
            try self.fault(.before_cleanup_commit);
            try self.commitTransaction();
            return .{ .deleted_rows = @intCast(deleted), .more = next.sweep_sequence + 1 < next.reject_below_sequence, .state = next };
        }
        pub const RetryRetirementCandidate = struct { subject: detection.Subject, last_processed_us: i64, decisions: u64 };
        pub fn retryRetirementCandidate(self: *Store, jail: []const u8, after: ?detection.Subject) Error!?RetryRetirementCandidate {
            _ = try self.maintenanceRevision();
            try Store.maintenanceKey(jail, "@retired");
            var row = try self.statement(if (after == null)
                "SELECT family,subject,last_processed_us,decisions FROM retry_states WHERE jail=?1 ORDER BY family,subject LIMIT 1;"
            else
                "SELECT family,subject,last_processed_us,decisions FROM retry_states WHERE jail=?1 AND (family,subject)>(?2,?3) ORDER BY family,subject LIMIT 1;");
            defer row.deinit();
            try row.text(1, jail);
            if (after) |*subject| try Store.bindSubject(&row, subject);
            if (!try row.row()) return null;
            const decisions = try row.signed(3);
            if (decisions < 0) return error.InvalidRetryState;
            return .{ .subject = try self.decodeRetrySubject(&row, 0, 1), .last_processed_us = try row.signed(2), .decisions = @intCast(decisions) };
        }
        pub fn retiredTotal(self: *Store, jail: []const u8) Error!u64 {
            var row = try self.statement("SELECT total FROM retry_retired_totals WHERE jail=?1;");
            defer row.deinit();
            try row.text(1, jail);
            if (!try row.row()) {
                var retained = try self.statement("SELECT 1 FROM retry_retired WHERE jail=?1 LIMIT 1;");
                defer retained.deinit();
                try retained.text(1, jail);
                if (try retained.row()) return error.InvalidRetryState;
                return 0;
            }
            const total = try row.signed(0);
            if (total < 0) return error.InvalidRetryState;
            return @intCast(total);
        }
        pub fn changeRetiredTotal(self: *Store, jail: []const u8, decisions: u64, add: bool) Error!void {
            const prior = try self.retiredTotal(jail);
            const next = if (add) std.math.add(u64, prior, decisions) catch return error.StorageLimit else std.math.sub(u64, prior, decisions) catch return error.InvalidRetryState;
            if (next > std.math.maxInt(i64)) return error.StorageLimit;
            var row = try self.statement("INSERT INTO retry_retired_totals VALUES(?1,?2) ON CONFLICT(jail) DO UPDATE SET total=excluded.total;");
            defer row.deinit();
            try row.text(1, jail);
            try row.int(2, @intCast(next));
            try row.done();
        }
        pub fn readRetired(self: *Store, jail: []const u8, subject: detection.Subject) Error!?retry.State {
            if (self.schema_version < 15) return null;
            var row = try self.statement("SELECT generation,last_processed_us,decisions FROM retry_retired WHERE jail=?1 AND family=?2 AND subject=?3;");
            defer row.deinit();
            try row.text(1, jail);
            try Store.bindSubject(&row, &subject);
            if (!try row.row()) return null;
            const policy = try self.readRetryPolicy(jail) orelse return error.InvalidRetryState;
            if (!std.mem.eql(u8, &try Store.effectBlob(&row, 0, 32), &policy.generation)) return error.InvalidRetryState;
            const decisions = try row.signed(2);
            const last = try row.signed(1);
            if (decisions < 0 or last > ((try self.readRetryClock()) orelse return error.InvalidRetryState)) return error.InvalidRetryState;
            return .{ .last_processed_us = last, .decisions = @intCast(decisions) };
        }
        pub fn retireRetrySubject(self: *Store, fence: CleanupFence, candidate: RetryRetirementCandidate) Error!bool {
            try self.beginWrite();
            errdefer self.rollback();
            const now = try self.checkCleanupFence(fence);
            const admission = try self.readRetryPolicy(fence.jail) orelse return error.RetryAdmissionRequired;
            if (try self.readRetired(fence.jail, candidate.subject) != null) return error.StaleMaintenance;
            const state = try self.readRetryState(fence.jail, candidate.subject, admission.policy) orelse return error.StaleMaintenance;
            if (state.last_processed_us != candidate.last_processed_us or state.decisions != candidate.decisions) return error.StaleMaintenance;
            const logical = (try retry.prune(admission.policy, state, now)).state;
            const pinned = logical.lease != .absent or logical.count != 0;
            if (pinned or try self.subjectEffectPinned(candidate.subject)) {
                try self.commitTransaction();
                return false;
            }
            try self.changeRetiredTotal(fence.jail, state.decisions, true);
            var saved = try self.statement("INSERT INTO retry_retired VALUES(?1,?2,?3,?4,?5,?6);");
            defer saved.deinit();
            try saved.text(1, fence.jail);
            try Store.bindSubject(&saved, &candidate.subject);
            try saved.blob(4, &fence.generation);
            try saved.int(5, state.last_processed_us);
            try saved.int(6, @intCast(state.decisions));
            try saved.done();
            var remove = try self.statement("DELETE FROM retry_states WHERE jail=?1 AND family=?2 AND subject=?3;");
            defer remove.deinit();
            try remove.text(1, fence.jail);
            try Store.bindSubject(&remove, &candidate.subject);
            try remove.done();
            if (self.api.changes(self.db) != 1) return error.StaleMaintenance;
            var floor = try self.statement("UPDATE retry_clock SET floor_us=?1 WHERE id=1;");
            defer floor.deinit();
            try floor.int(1, now);
            try floor.done();
            if (self.api.changes(self.db) != 1) return error.InvalidRetryState;
            try self.fault(.after_retry_retire);
            try self.finishCleanupClock(fence.clock, now);
            try self.commitTransaction();
            return true;
        }

        pub const MaintenanceValidation = struct {
            phase: enum { headers, records, guards, retired, totals, done } = .headers,
            revision: ?u64 = null,
            data_version: i64 = 0,
            jail: [4096]u8 = undefined,
            jail_len: usize = 0,
            source: [Limits.source_bytes]u8 = undefined,
            source_len: usize = 0,
            generation: [32]u8 = undefined,
            sequence: u64 = 0,
            expected_end: u64 = 0,
            retired_sum: u64 = 0,
            subject: ?detection.Subject = null,
            fn resetKey(self: *MaintenanceValidation) void {
                self.jail_len = 0;
                self.source_len = 0;
                self.subject = null;
                self.sequence = 0;
                self.expected_end = 0;
                self.retired_sum = 0;
            }
            fn setKey(self: *MaintenanceValidation, jail: []const u8, source: []const u8, generation: [32]u8, sequence: u64) void {
                @memcpy(self.jail[0..jail.len], jail);
                self.jail_len = jail.len;
                @memcpy(self.source[0..source.len], source);
                self.source_len = source.len;
                self.generation = generation;
                self.sequence = sequence;
            }
            fn sameSource(self: *const MaintenanceValidation, jail: []const u8, source: []const u8, generation: [32]u8) bool {
                return self.jail_len != 0 and std.mem.eql(u8, self.jail[0..self.jail_len], jail) and
                    std.mem.eql(u8, self.source[0..self.source_len], source) and std.mem.eql(u8, &self.generation, &generation);
            }
        };
        fn validateMaintenanceHeader(self: *Store, jail: []const u8, source: []const u8, generation: [32]u8) Error!void {
            const state = try self.sourceMaintenance(jail, source, generation) orelse return error.InvalidMaintenanceState;
            for ([_][:0]const u8{
                "SELECT source_sequence FROM records WHERE jail=?1 AND source=?2 AND source_generation=?3 AND source_sequence IS NOT NULL ORDER BY source_sequence LIMIT 1;",
                "SELECT source_sequence FROM records WHERE jail=?1 AND source=?2 AND source_generation=?3 AND source_sequence IS NOT NULL ORDER BY source_sequence DESC LIMIT 1;",
                "SELECT source_sequence FROM replay_guards WHERE jail=?1 AND source=?2 AND generation=?3 ORDER BY source_sequence LIMIT 1;",
                "SELECT source_sequence FROM replay_guards WHERE jail=?1 AND source=?2 AND generation=?3 ORDER BY source_sequence DESC LIMIT 1;",
            }, 0..) |query, index| {
                var row = try self.statement(query);
                defer row.deinit();
                try row.text(1, jail);
                try row.text(2, source);
                try row.blob(3, &generation);
                const expected: u64 = switch (index) {
                    0 => state.sweep_sequence + 1,
                    1 => state.head_sequence,
                    2 => 1,
                    3 => state.reject_below_sequence - 1,
                    else => unreachable,
                };
                const empty = if (index < 2) state.head_sequence == state.sweep_sequence else state.reject_below_sequence == 1;
                if (try row.row()) {
                    const value = try row.signed(0);
                    if (empty or value <= 0 or value != expected) return error.InvalidMaintenanceState;
                } else if (!empty) return error.InvalidMaintenanceState;
            }
            if ((state.cleanup_revision == 0) != (state.reject_below_sequence == 1 and state.sweep_sequence == 0)) return error.InvalidMaintenanceState;
        }
        pub fn validateMaintenanceTurn(self: *Store, cursor: *MaintenanceValidation) Error!bool {
            if (cursor.jail_len > cursor.jail.len or cursor.source_len > cursor.source.len or cursor.sequence > std.math.maxInt(i64) or
                (cursor.phase == .retired and cursor.jail_len != 0 and cursor.subject == null)) return error.InvalidMaintenanceState;
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
            for (0..16) |_| switch (next.phase) {
                .done => break,
                .headers, .records, .guards => {
                    const headers = next.phase == .headers;
                    const records = next.phase == .records;
                    const query: [:0]const u8 = if (headers)
                        (if (next.jail_len == 0) "SELECT jail,source,generation FROM source_maintenance ORDER BY jail,source,generation LIMIT 1;" else "SELECT jail,source,generation FROM source_maintenance WHERE (jail,source,generation)>(?1,?2,?3) ORDER BY jail,source,generation LIMIT 1;")
                    else if (records)
                        (if (next.jail_len == 0) "SELECT jail,source,source_generation,source_sequence FROM records WHERE source_sequence IS NOT NULL ORDER BY jail,source,source_generation,source_sequence LIMIT 1;" else "SELECT jail,source,source_generation,source_sequence FROM records WHERE source_sequence IS NOT NULL AND (jail,source,source_generation,source_sequence)>(?1,?2,?3,?4) ORDER BY jail,source,source_generation,source_sequence LIMIT 1;")
                    else
                        (if (next.jail_len == 0) "SELECT jail,source,generation,source_sequence,occurrence_key,identity_key,receipt_us FROM replay_guards ORDER BY jail,source,generation,source_sequence LIMIT 1;" else "SELECT jail,source,generation,source_sequence,occurrence_key,identity_key,receipt_us FROM replay_guards WHERE (jail,source,generation,source_sequence)>(?1,?2,?3,?4) ORDER BY jail,source,generation,source_sequence LIMIT 1;");
                    var row = try self.statement(query);
                    defer row.deinit();
                    if (next.jail_len != 0) {
                        try row.text(1, next.jail[0..next.jail_len]);
                        try row.text(2, next.source[0..next.source_len]);
                        try row.blob(3, &next.generation);
                        if (!headers) try row.int(4, @intCast(next.sequence));
                    }
                    if (!try row.row()) {
                        if (!headers and next.jail_len != 0 and next.sequence != next.expected_end) return error.InvalidMaintenanceState;
                        next.phase = if (headers) .records else if (records) .guards else .retired;
                        next.resetKey();
                        continue;
                    }
                    if (self.api.column_type(row.ptr, 0) != 3 or self.api.column_type(row.ptr, 1) != 3) return error.InvalidMaintenanceState;
                    const jail = try row.boundedBytes(0, 4096);
                    const source = try row.boundedBytes(1, Limits.source_bytes);
                    const generation = try Store.effectBlob(&row, 2, 32);
                    try Store.maintenanceKey(jail, source);
                    var sequence: u64 = 0;
                    var bytes = jail.len + source.len + 104;
                    if (headers) {
                        try self.validateMaintenanceHeader(jail, source, generation);
                    } else {
                        const stored_sequence = try row.signed(3);
                        const state = try self.sourceMaintenance(jail, source, generation) orelse return error.InvalidMaintenanceState;
                        const first = if (records) state.sweep_sequence + 1 else 1;
                        const end = if (records) state.head_sequence else state.reject_below_sequence - 1;
                        const same = next.sameSource(jail, source, generation);
                        if (!same and next.jail_len != 0 and next.sequence != next.expected_end) return error.InvalidMaintenanceState;
                        if (stored_sequence <= 0 or stored_sequence != (if (same) next.sequence + 1 else first) or stored_sequence > end) return error.InvalidMaintenanceState;
                        sequence = @intCast(stored_sequence);
                        const fence = CleanupFence{ .jail = jail, .source = source, .generation = generation, .jail_revision = 0, .consumer_revision = 0, .effect_revision = 0, .clock = .{ .prepared_us = 0 } };
                        var detail = try self.orderRecord(fence, sequence);
                        defer detail.deinit();
                        if (try detail.row()) {
                            if (sequence <= state.sweep_sequence) return error.InvalidMaintenanceState;
                            const id = try orderedIdentity(&detail, fence);
                            bytes += id.occurrence.len + id.cursor.len;
                            if (!records and (!std.mem.eql(u8, &try Store.effectBlob(&row, 4, 32), &Store.occurrenceGuardKey(id.occurrence)) or
                                !std.mem.eql(u8, &try Store.effectBlob(&row, 5, 32), &Store.identityGuardKey(id)) or try row.optionalSigned(6) != try detail.optionalSigned(3))) return error.InvalidMaintenanceState;
                        } else {
                            if (records or sequence > state.sweep_sequence) return error.InvalidMaintenanceState;
                            _ = try Store.effectBlob(&row, 4, 32);
                            _ = try Store.effectBlob(&row, 5, 32);
                            _ = try row.optionalSigned(6);
                        }
                        if (bytes > 1024 * 1024 - key_bytes) break;
                        next.expected_end = end;
                    }
                    if (bytes > 1024 * 1024 - key_bytes) break;
                    key_bytes += bytes;
                    next.setKey(jail, source, generation, sequence);
                },
                .retired, .totals => {
                    const totals = next.phase == .totals;
                    var row = try self.statement(if (totals)
                        (if (next.jail_len == 0) "SELECT jail,total FROM retry_retired_totals ORDER BY jail LIMIT 1;" else "SELECT jail,total FROM retry_retired_totals WHERE jail>?1 ORDER BY jail LIMIT 1;")
                    else if (next.jail_len == 0)
                        "SELECT jail,family,subject FROM retry_retired ORDER BY jail,family,subject LIMIT 1;"
                    else
                        "SELECT jail,family,subject FROM retry_retired WHERE (jail,family,subject)>(?1,?2,?3) ORDER BY jail,family,subject LIMIT 1;");
                    defer row.deinit();
                    if (next.jail_len != 0) {
                        try row.text(1, next.jail[0..next.jail_len]);
                        if (!totals) try Store.bindSubject(&row, &next.subject.?);
                    }
                    if (!try row.row()) {
                        if (!totals and next.jail_len != 0 and next.retired_sum != try self.retiredTotal(next.jail[0..next.jail_len])) return error.InvalidRetryState;
                        next.phase = if (totals) .done else .totals;
                        next.resetKey();
                        continue;
                    }
                    if (self.api.column_type(row.ptr, 0) != 3) return error.InvalidRetryState;
                    const jail = try row.boundedBytes(0, 4096);
                    try Store.maintenanceKey(jail, "@retired");
                    if (totals) {
                        _ = try self.readRetryPolicy(jail) orelse return error.InvalidRetryState;
                        const total = try row.signed(1);
                        if (total < 0) return error.InvalidRetryState;
                        var existing = try self.statement("SELECT 1 FROM retry_retired WHERE jail=?1 LIMIT 1;");
                        defer existing.deinit();
                        try existing.text(1, jail);
                        if (!try existing.row() and total != 0) return error.InvalidRetryState;
                    } else {
                        const same = std.mem.eql(u8, next.jail[0..next.jail_len], jail);
                        if (!same) {
                            if (next.jail_len != 0 and next.retired_sum != try self.retiredTotal(next.jail[0..next.jail_len])) return error.InvalidRetryState;
                            next.retired_sum = 0;
                        }
                        const subject = try self.decodeRetrySubject(&row, 1, 2);
                        const state = try self.readRetired(jail, subject) orelse return error.InvalidRetryState;
                        var live = try self.statement("SELECT 1 FROM retry_states WHERE jail=?1 AND family=?2 AND subject=?3;");
                        defer live.deinit();
                        try live.text(1, jail);
                        try Store.bindSubject(&live, &subject);
                        if (try live.row()) return error.InvalidRetryState;
                        next.retired_sum = std.math.add(u64, next.retired_sum, state.decisions) catch return error.InvalidRetryState;
                        next.subject = subject;
                    }
                    @memcpy(next.jail[0..jail.len], jail);
                    next.jail_len = jail.len;
                },
            };
            if (try self.maintenanceRevision() != revision_value or try self.integer("PRAGMA data_version;") != data_version) return error.StaleMaintenance;
            try self.commitTransaction();
            cursor.* = next;
            return next.phase == .done;
        }
        pub fn finishMaintenanceValidation(self: *Store, cursor: *const MaintenanceValidation) Error!void {
            if (cursor.phase != .done or cursor.revision == null or cursor.revision.? != try self.maintenanceRevision() or
                cursor.data_version != try self.integer("PRAGMA data_version;")) return error.StaleMaintenance;
        }

        fn historyHead(self: *Store, installation: effects.Installation, after: u64) Error!effect_history.PageToken {
            if (self.schema_version < 13) return error.ConsumerStorageRequired;
            try installation.validate();
            const admitted = try self.readInstallation() orelse return error.InstallationRequired;
            if (!std.meta.eql(admitted, installation)) return error.InstallationMismatch;
            var row = try self.statement("SELECT revision,head,retained_from FROM confirmed_history_stream WHERE id=1;");
            defer row.deinit();
            if (!try row.row()) return error.HistoryGap;
            const stream_revision = try row.signed(0);
            const head = try row.signed(1);
            const floor = try row.signed(2);
            if (stream_revision <= 0 or head < 0 or floor <= 0) return error.InvalidHistoryPage;
            const token = effect_history.PageToken{ .installation = installation.id, .stream_revision = @intCast(stream_revision), .head_sequence = @intCast(head), .retained_from_sequence = @intCast(floor), .after_sequence = after, .last_sequence = after };
            try token.validate();
            return token;
        }
        fn confirmedEffectPageTx(self: *Store, installation: effects.Installation, after: u64, expected_revision: ?u64, output: []effect_history.Event) Error!effect_history.Page {
            if (output.len == 0 or output.len > effect_history.max_page) return error.InvalidHistoryPage;
            var token = try self.historyHead(installation, after);
            if (expected_revision) |wanted_revision| if (wanted_revision != token.stream_revision) return error.StaleHistoryPage;
            var row = try self.statement(if (self.schema_version >= 19)
                "SELECT s.sequence,e.event_id,e.scope_key,n.canonical_scope,e.jail,e.decision_id,e.confirmed_us,EXISTS(SELECT 1 FROM confirmed_event_details d WHERE d.event_id=e.event_id) FROM confirmed_history_sequence s JOIN confirmed_effect_events e ON e.event_id=s.event_id JOIN native_effects n ON n.scope_key=e.scope_key WHERE s.sequence>?1 ORDER BY s.sequence LIMIT ?2;"
            else if (self.schema_version >= 17)
                "SELECT s.sequence,e.event_id,e.scope_key,n.scope,e.jail,e.decision_id,e.confirmed_us,EXISTS(SELECT 1 FROM confirmed_event_details d WHERE d.event_id=e.event_id) FROM confirmed_history_sequence s JOIN confirmed_effect_events e ON e.event_id=s.event_id JOIN native_effects n ON n.scope_key=e.scope_key WHERE s.sequence>?1 ORDER BY s.sequence LIMIT ?2;"
            else
                "SELECT s.sequence,e.event_id,e.scope_key,n.scope,e.jail,e.decision_id,e.confirmed_us FROM confirmed_history_sequence s JOIN confirmed_effect_events e ON e.event_id=s.event_id JOIN native_effects n ON n.scope_key=e.scope_key WHERE s.sequence>?1 ORDER BY s.sequence LIMIT ?2;");
            defer row.deinit();
            try row.int(1, @intCast(after));
            try row.int(2, @intCast(output.len));
            var count: usize = 0;
            while (try row.row()) {
                const sequence = try row.signed(0);
                if (sequence <= 0 or sequence != after + count + 1 or sequence > token.head_sequence) return error.HistoryGap;
                const native_retry = if (self.schema_version >= 17) blk: {
                    const value = try row.signed(7);
                    if (value < 0 or value > 1) return error.InvalidHistoryEvent;
                    break :blk value == 1;
                } else false;
                const event = effect_history.Event{ .sequence = @intCast(sequence), .event_id = try Store.effectBlob(&row, 1, 32), .installation = installation, .scope_key = try Store.effectBlob(&row, 2, 32), .scope = try self.decodeStoredScope(&row, 3), .jail = detection.Name.init(try row.boundedBytes(4, 64)) catch return error.InvalidHistoryEvent, .decision_id = try Store.effectBlob(&row, 5, 32), .confirmed_us = try row.signed(6), .native_retry = native_retry };
                try event.validate();
                output[count] = event;
                count += 1;
            }
            if (count != @min(output.len, token.head_sequence - after)) return error.HistoryGap;
            token.last_sequence = after + count;
            const page = effect_history.Page{ .token = token, .count = count, .more = token.last_sequence < token.head_sequence };
            try page.validate();
            return page;
        }
        pub fn confirmedEffectPage(self: *Store, installation: effects.Installation, after_sequence: u64, expected_revision: ?u64, output: []effect_history.Event) Error!effect_history.Page {
            try self.beginRead();
            errdefer self.rollback();
            const page = try self.confirmedEffectPageTx(installation, after_sequence, expected_revision, output);
            try self.commitTransaction();
            return page;
        }

        pub fn historyEventEligible(self: *Store, event: effect_history.Event) Error!bool {
            try event.validate();
            if (self.schema_version < 20) return true;
            if (event.scope.canonical.subject.kind != .host) return error.InvalidHistoryReset;
            const subject: detection.Subject = switch (event.scope.canonical.subject.family) {
                .v4 => .{ .v4 = event.scope.canonical.subject.address[0..4].* },
                .v6 => .{ .v6 = event.scope.canonical.subject.address },
            };
            try self.beginRead();
            errdefer self.rollback();
            var row = try self.statement("SELECT max(through_sequence) FROM history_reset_watermarks WHERE family=?1 AND subject=?2 AND ((scope=1 AND jail=?3) OR (scope=2 AND jail=''));");
            defer row.deinit();
            try Store.bindSubjectAt(&row, &subject, 1);
            try row.text(3, event.jail.slice());
            if (!try row.row()) return error.InvalidHistoryReset;
            const through = try row.optionalSigned(0);
            if (try row.row()) return error.InvalidHistoryReset;
            try self.commitTransaction();
            if (through) |value| {
                if (value < 0) return error.InvalidHistoryReset;
                return event.sequence > @as(u64, @intCast(value));
            }
            return true;
        }

        pub fn resetHistory(self: *Store, intent: HistoryResetIntent, clock: effects.Clock) Error!HistoryResetResult {
            intent.subject.validate() catch return error.InvalidHistoryReset;
            if (intent.subject.unenforceable() or intent.expected_revision > std.math.maxInt(i64) or std.mem.allEqual(u8, &intent.intent_id, 0)) return error.InvalidHistoryReset;
            const scope_value: i64 = switch (intent.scope) {
                .jail => |name| blk: {
                    _ = detection.Name.init(name) catch return error.InvalidHistoryReset;
                    break :blk 1;
                },
                .overall => 2,
            };
            const jail = switch (intent.scope) {
                .jail => |name| name,
                .overall => "",
            };
            try self.beginWrite();
            errdefer self.rollback();
            if (self.schema_version < 20) return error.HistoryResetStorageRequired;
            var existing = try self.statement("SELECT through_sequence,reset_us,revision,intent_id FROM history_reset_watermarks WHERE scope=?1 AND jail=?2 AND family=?3 AND subject=?4;");
            defer existing.deinit();
            try existing.int(1, scope_value);
            try existing.text(2, jail);
            try Store.bindSubjectAt(&existing, &intent.subject, 3);
            var prior_revision: u64 = 0;
            if (try existing.row()) {
                const through = try existing.signed(0);
                const reset_us = try existing.signed(1);
                const saved_revision = try existing.signed(2);
                const prior_intent = try Store.effectBlob(&existing, 3, 32);
                if (through < 0 or saved_revision <= 0 or try existing.row()) return error.InvalidHistoryReset;
                if (std.mem.eql(u8, &prior_intent, &intent.intent_id)) {
                    try self.commitTransaction();
                    return .{ .revision = @intCast(saved_revision), .through_sequence = @intCast(through), .reset_us = reset_us };
                }
                prior_revision = @intCast(saved_revision);
            }
            if (prior_revision != intent.expected_revision) return error.StaleHistoryReset;
            if (prior_revision == std.math.maxInt(i64)) return error.InvalidHistoryReset;
            if (prior_revision == 0 and try self.integer("SELECT count(*) FROM history_reset_watermarks;") >= effects.max_effects) return error.EffectCapacity;
            const now = try self.effectClock(clock);
            const head_value = try self.integer("SELECT head FROM confirmed_history_stream WHERE id=1;");
            if (head_value < 0) return error.InvalidHistoryReset;
            const head: u64 = @intCast(head_value);
            {
                var write = try self.statement("INSERT INTO history_reset_watermarks VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(scope,jail,family,subject) DO UPDATE SET through_sequence=excluded.through_sequence,reset_us=excluded.reset_us,revision=excluded.revision,intent_id=excluded.intent_id;");
                defer write.deinit();
                try write.int(1, scope_value);
                try write.text(2, jail);
                try Store.bindSubjectAt(&write, &intent.subject, 3);
                try write.int(5, @intCast(head));
                try write.int(6, now);
                try write.int(7, @intCast(prior_revision + 1));
                try write.blob(8, &intent.intent_id);
                try write.done();
                if (self.api.changes(self.db) != 1) return error.InvalidHistoryReset;
            }
            {
                var summaries = try self.statement(if (scope_value == 1)
                    "DELETE FROM confirmed_policy_summaries WHERE jail=?1 AND family=?2 AND subject=?3;"
                else
                    "DELETE FROM confirmed_policy_summaries WHERE family=?1 AND subject=?2;");
                defer summaries.deinit();
                if (scope_value == 1) {
                    try summaries.text(1, jail);
                    try Store.bindSubjectAt(&summaries, &intent.subject, 2);
                } else try Store.bindSubjectAt(&summaries, &intent.subject, 1);
                try summaries.done();
            }
            try self.fault(.after_history_reset);
            _ = try self.commitEffectClock(clock);
            try self.commitTransaction();
            return .{ .revision = prior_revision + 1, .through_sequence = head, .reset_us = now };
        }

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
                var target = action_outcome.Target{ .action_id = action_id, .scope_key = try Store.effectBlob(&row, 0, 32), .jail = jail, .kind = kind, .required = required == 1, .restored = restored == 1, .status = status, .intent_us = intent_us, .dispatch_us = dispatch_us, .settled_us = settled_us, .metadata_len = 0 };
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
            if (try self.integer("SELECT count(*) FROM action_targets;") > action_outcome.max_rows - action_outcome.max_targets_per_action) return error.ActionTargetCapacity;
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
            }
            try self.fault(.after_action_target_intent);
        }

        pub fn prepareActionTargets(self: *Store, intent: action_outcome.Intent, clock: effects.Clock) Error!void {
            try self.beginWrite();
            errdefer self.rollback();
            if (self.schema_version < 21) return error.ActionTargetStorageRequired;
            const now = try self.effectClock(clock);
            try self.prepareActionTargetsTx(intent, now);
            _ = try self.commitEffectClock(clock);
            try self.commitTransaction();
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
            if (status == .dispatched) {
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
                var proof = try self.statement("SELECT count(*) FROM confirmed_effect_events WHERE scope_key=?1 AND jail=?2 AND decision_id=?3;");
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

        pub fn applicationHistoryPage(self: *Store, allocator: std.mem.Allocator, installation: effects.Installation, query: application_history.EventQuery, output: []application_history.Event) Error!application_history.EventPage {
            try query.validate();
            if (output.len == 0 or output.len > application_history.max_page or self.schema_version < 17) return error.InvalidApplicationHistoryQuery;
            try self.beginRead();
            errdefer self.rollback();
            const head = try self.historyHead(installation, query.after_sequence);
            if (query.expected_stream_revision) |expected| if (expected != head.stream_revision) return error.StaleHistoryPage;
            var row = try self.statement(if (self.schema_version >= 19)
                "SELECT s.sequence,e.event_id,e.scope_key,n.canonical_scope,e.jail,e.decision_id,e.confirmed_us,d.source,d.occurrence,d.decided_us,d.ordinal,d.evidence FROM confirmed_history_sequence s JOIN confirmed_effect_events e ON e.event_id=s.event_id JOIN native_effects n ON n.scope_key=e.scope_key LEFT JOIN confirmed_event_details d ON d.event_id=e.event_id WHERE s.sequence>?1 AND s.sequence<=?2 AND (?3 IS NULL OR e.jail=?3) AND (?4 IS NULL OR e.confirmed_us>=?4) AND (?5 IS NULL OR e.confirmed_us<?5) ORDER BY s.sequence LIMIT ?6;"
            else
                "SELECT s.sequence,e.event_id,e.scope_key,n.scope,e.jail,e.decision_id,e.confirmed_us,d.source,d.occurrence,d.decided_us,d.ordinal,d.evidence FROM confirmed_history_sequence s JOIN confirmed_effect_events e ON e.event_id=s.event_id JOIN native_effects n ON n.scope_key=e.scope_key LEFT JOIN confirmed_event_details d ON d.event_id=e.event_id WHERE s.sequence>?1 AND s.sequence<=?2 AND (?3 IS NULL OR e.jail=?3) AND (?4 IS NULL OR e.confirmed_us>=?4) AND (?5 IS NULL OR e.confirmed_us<?5) ORDER BY s.sequence LIMIT ?6;");
            defer row.deinit();
            try row.int(1, @intCast(query.after_sequence));
            try row.int(2, @intCast(head.head_sequence));
            if (query.jail) |jail| try row.text(3, jail) else try self.check(self.api.bind_null(row.ptr, 3));
            if (query.range.from_us) |stamp| try row.int(4, stamp) else try self.check(self.api.bind_null(row.ptr, 4));
            if (query.range.to_us) |stamp| try row.int(5, stamp) else try self.check(self.api.bind_null(row.ptr, 5));
            try row.int(6, @intCast(output.len + 1));
            var count: usize = 0;
            var more = false;
            var last = query.after_sequence;
            errdefer for (output[0..count]) |*event| event.deinit(allocator);
            while (try row.row()) {
                if (count == output.len) {
                    more = true;
                    break;
                }
                const sequence = try row.signed(0);
                if (sequence <= 0 or sequence <= last or sequence > head.head_sequence) return error.InvalidApplicationHistoryRow;
                const confirmed = effect_history.Event{ .sequence = @intCast(sequence), .event_id = try Store.effectBlob(&row, 1, 32), .installation = installation, .scope_key = try Store.effectBlob(&row, 2, 32), .scope = try self.decodeStoredScope(&row, 3), .jail = detection.Name.init(try row.boundedBytes(4, 64)) catch return error.InvalidApplicationHistoryRow, .decision_id = try Store.effectBlob(&row, 5, 32), .confirmed_us = try row.signed(6) };
                confirmed.validate() catch return error.InvalidApplicationHistoryRow;
                output[count] = .{ .confirmed = confirmed };
                if (self.api.column_type(row.ptr, 7) == 5) {
                    for (8..12) |column| if (self.api.column_type(row.ptr, @intCast(column)) != 5) return error.InvalidApplicationHistoryRow;
                } else {
                    if (self.api.column_type(row.ptr, 7) != 3 or self.api.column_type(row.ptr, 8) != 3) return error.InvalidApplicationHistoryRow;
                    const source = try row.boundedBytes(7, Limits.source_bytes);
                    const occurrence = try row.boundedBytes(8, Limits.source_bytes);
                    const decided = try row.signed(9);
                    const ordinal = try row.signed(10);
                    if (source.len == 0 or occurrence.len == 0 or decided > confirmed.confirmed_us or ordinal <= 0) return error.InvalidApplicationHistoryRow;
                    const source_copy = allocator.dupe(u8, source) catch return error.OutOfMemory;
                    errdefer allocator.free(source_copy);
                    const occurrence_copy = allocator.dupe(u8, occurrence) catch return error.OutOfMemory;
                    errdefer allocator.free(occurrence_copy);
                    var evidence_copy: ?[]u8 = null;
                    if (self.api.column_type(row.ptr, 11) != 5) {
                        if (self.api.column_type(row.ptr, 11) != 3) return error.InvalidApplicationHistoryRow;
                        const evidence = try row.boundedBytes(11, retry.max_evidence_text_bytes);
                        if (evidence.len == 0 or !std.unicode.utf8ValidateSlice(evidence)) return error.InvalidApplicationHistoryRow;
                        evidence_copy = allocator.dupe(u8, evidence) catch return error.OutOfMemory;
                    }
                    output[count].detail = .{ .source = source_copy, .occurrence = occurrence_copy, .decided_us = decided, .ordinal = @intCast(ordinal), .evidence = evidence_copy };
                }
                count += 1;
                last = @intCast(sequence);
            }
            try self.commitTransaction();
            return .{ .stream_revision = head.stream_revision, .head_sequence = head.head_sequence, .last_sequence = last, .count = count, .more = more };
        }

        pub fn applicationHistoryAggregates(self: *Store, installation: effects.Installation, query: application_history.AggregateQuery, output: []application_history.Aggregate) Error!application_history.AggregatePage {
            try query.validate();
            if (output.len == 0 or output.len > application_history.max_page + 1 or self.schema_version < 17) return error.InvalidApplicationHistoryQuery;
            try self.beginRead();
            errdefer self.rollback();
            const head = try self.historyHead(installation, 0);
            if (query.expected_stream_revision) |expected| if (expected != head.stream_revision) return error.StaleHistoryPage;
            const predicate = " FROM confirmed_effect_events WHERE (?1 IS NULL OR jail=?1) AND (?2 IS NULL OR confirmed_us>=?2) AND (?3 IS NULL OR confirmed_us<?3)";
            var overall = try self.statement("SELECT count(*),min(confirmed_us),max(confirmed_us)" ++ predicate ++ ";");
            defer overall.deinit();
            if (query.jail) |jail| try overall.text(1, jail) else try self.check(self.api.bind_null(overall.ptr, 1));
            if (query.range.from_us) |stamp| try overall.int(2, stamp) else try self.check(self.api.bind_null(overall.ptr, 2));
            if (query.range.to_us) |stamp| try overall.int(3, stamp) else try self.check(self.api.bind_null(overall.ptr, 3));
            if (!try overall.row()) return error.InvalidApplicationHistoryRow;
            const total = try overall.signed(0);
            if (total < 0) return error.InvalidApplicationHistoryRow;
            output[0] = .{ .jail = null, .confirmed = @intCast(total), .first_confirmed_us = try overall.optionalSigned(1), .latest_confirmed_us = try overall.optionalSigned(2) };
            if ((total == 0) != (output[0].first_confirmed_us == null and output[0].latest_confirmed_us == null)) return error.InvalidApplicationHistoryRow;

            var groups = try self.statement("SELECT jail,count(*),min(confirmed_us),max(confirmed_us)" ++ predicate ++ " GROUP BY jail ORDER BY jail LIMIT ?4;");
            defer groups.deinit();
            if (query.jail) |jail| try groups.text(1, jail) else try self.check(self.api.bind_null(groups.ptr, 1));
            if (query.range.from_us) |stamp| try groups.int(2, stamp) else try self.check(self.api.bind_null(groups.ptr, 2));
            if (query.range.to_us) |stamp| try groups.int(3, stamp) else try self.check(self.api.bind_null(groups.ptr, 3));
            try groups.int(4, @intCast(output.len));
            var count: usize = 1;
            var more = false;
            while (try groups.row()) {
                if (count == output.len) {
                    more = true;
                    break;
                }
                const group_count = try groups.signed(1);
                if (self.api.column_type(groups.ptr, 0) != 3 or group_count <= 0) return error.InvalidApplicationHistoryRow;
                output[count] = .{ .jail = detection.Name.init(try groups.boundedBytes(0, 64)) catch return error.InvalidApplicationHistoryRow, .confirmed = @intCast(group_count), .first_confirmed_us = try groups.optionalSigned(2), .latest_confirmed_us = try groups.optionalSigned(3) };
                if (output[count].first_confirmed_us == null or output[count].latest_confirmed_us == null) return error.InvalidApplicationHistoryRow;
                count += 1;
            }
            try self.commitTransaction();
            return .{ .stream_revision = head.stream_revision, .head_sequence = head.head_sequence, .count = count, .more = more };
        }
        fn validateConfirmedEffectPageTx(self: *Store, token: effect_history.PageToken) Error!void {
            try token.validate();
            const installation = try self.readInstallation() orelse return error.InstallationRequired;
            const current = try self.historyHead(installation, token.after_sequence);
            if (!std.mem.eql(u8, &current.installation, &token.installation)) return error.InstallationMismatch;
            if (current.stream_revision != token.stream_revision or current.head_sequence != token.head_sequence or current.retained_from_sequence != token.retained_from_sequence) return error.StaleHistoryPage;
            var events: [effect_history.max_page]effect_history.Event = undefined;
            const size: usize = @intCast(token.last_sequence - token.after_sequence);
            const page = try self.confirmedEffectPageTx(installation, token.after_sequence, token.stream_revision, events[0..@max(1, size)]);
            if (page.token.last_sequence != token.last_sequence) return error.StaleHistoryPage;
        }
        pub fn validateConfirmedEffectPage(self: *Store, token: effect_history.PageToken) Error!void {
            try self.beginRead();
            errdefer self.rollback();
            try self.validateConfirmedEffectPageTx(token);
            try self.commitTransaction();
        }
        pub const HistoryRetention = struct {
            age_us: i64 = 86_400 * 1_000_000,
            max_matches: u16 = 10,

            pub fn validate(self: HistoryRetention) Error!void {
                if (self.age_us < 0 or @mod(self.age_us, 1_000_000) != 0 or self.max_matches > 1024) return error.InvalidApplicationHistoryQuery;
            }
        };

        // Details are copied into confirmed_event_details at confirmation. Keep the
        // original while a current owner or retained event can still consume it.
        // One transaction removes at most 32 rows and 2 MiB of stored fields.
        pub fn pruneRetryDecisionDetailsTx(self: *Store) Error!usize {
            // A fully retained 65,536-row table takes more than the ordinary
            // statement budget to prove that no row is eligible. The table cap and
            // indexed decision lookups bound this scan; keep the larger allowance
            // local to this operation.
            const prior_work = self.work_remaining;
            if (self.runtime_limits) self.work_remaining = 5000;
            defer {
                if (self.runtime_limits) self.work_remaining = prior_work;
            }
            const query: [:0]const u8 = if (self.schema_version >= 21)
                "SELECT d.rowid,length(CAST(d.jail AS BLOB))+length(CAST(d.source AS BLOB))+length(CAST(d.occurrence AS BLOB))+length(d.subject)+coalesce(length(d.effect_decision_id),0)+coalesce(length(CAST(d.evidence AS BLOB)),0)+24 FROM retry_decision_details d WHERE d.effect_decision_id IS NULL OR (NOT EXISTS(SELECT 1 FROM effect_owners o WHERE o.jail=d.jail AND o.decision_id=d.effect_decision_id) AND NOT EXISTS(SELECT 1 FROM confirmed_effect_events e WHERE e.jail=d.jail AND e.decision_id=d.effect_decision_id) AND NOT EXISTS(SELECT 1 FROM action_targets a WHERE a.action_id=d.effect_decision_id AND a.status IN(1,2,5))) ORDER BY d.rowid LIMIT 32;"
            else
                "SELECT d.rowid,length(CAST(d.jail AS BLOB))+length(CAST(d.source AS BLOB))+length(CAST(d.occurrence AS BLOB))+length(d.subject)+coalesce(length(d.effect_decision_id),0)+coalesce(length(CAST(d.evidence AS BLOB)),0)+24 FROM retry_decision_details d WHERE d.effect_decision_id IS NULL OR (NOT EXISTS(SELECT 1 FROM effect_owners o WHERE o.jail=d.jail AND o.decision_id=d.effect_decision_id) AND NOT EXISTS(SELECT 1 FROM confirmed_effect_events e WHERE e.jail=d.jail AND e.decision_id=d.effect_decision_id)) ORDER BY d.rowid LIMIT 32;";
            var ids: [32]i64 = undefined;
            var count: usize = 0;
            var bytes: usize = 0;
            {
                var rows = try self.statement(query);
                defer rows.deinit();
                while (try rows.row()) {
                    const id = try rows.signed(0);
                    const row_bytes = try rows.signed(1);
                    if (id <= 0 or row_bytes <= 0) return error.InvalidApplicationHistoryRow;
                    const size = std.math.cast(usize, row_bytes) orelse return error.StorageLimit;
                    if (size > 2 * 1024 * 1024) return error.StorageLimit;
                    if (size > 2 * 1024 * 1024 - bytes) break;
                    ids[count] = id;
                    count += 1;
                    bytes += size;
                }
            }
            if (count == 0) return 0;
            var remove = try self.statement("DELETE FROM retry_decision_details WHERE rowid=?1;");
            defer remove.deinit();
            for (ids[0..count]) |id| {
                try remove.int(1, id);
                try remove.done();
                if (self.api.changes(self.db) != 1) return error.InvalidApplicationHistoryRow;
                try remove.reset();
            }
            try self.fault(.after_retry_detail_prune);
            return count;
        }

        pub fn pruneRetryDecisionDetailsOne(self: *Store) Error!bool {
            if (self.schema_version < 17) return false;
            try self.beginWrite();
            errdefer self.rollback();
            const deleted = try self.pruneRetryDecisionDetailsTx();
            try self.commitTransaction();
            return deleted != 0;
        }

        pub fn cleanupConfirmedHistoryOne(self: *Store, policy: HistoryRetention, now_us: i64) Error!bool {
            try policy.validate();
            try self.beginWrite();
            errdefer self.rollback();
            const schema = try self.integer("PRAGMA user_version;");
            if (schema < 18) return error.MaintenanceStorageRequired;
            if (schema > latest_schema) return error.UnsupportedSchema;
            var checkpoint_row = try self.statement("SELECT payload FROM consumer_checkpoints WHERE kind=5 AND jail='@history' AND source='confirmed-effects' AND rule='checkpoint';");
            defer checkpoint_row.deinit();
            if (!try checkpoint_row.row()) {
                try self.commitTransaction();
                return false;
            }
            const history_checkpoint = effect_history.Checkpoint.decode(try checkpoint_row.boundedBytes(0, effect_history.checkpoint_bytes)) catch return error.InvalidHistoryCheckpoint;
            if (try checkpoint_row.row()) return error.InvalidHistoryCheckpoint;
            const installation = try self.readInstallation() orelse return error.InstallationRequired;
            if (!std.mem.eql(u8, &history_checkpoint.installation, &installation.id)) return error.InvalidHistoryCheckpoint;
            const cutoff = std.math.sub(i64, now_us, policy.age_us) catch std.math.minInt(i64);
            var detail_candidate = try self.statement(
                "SELECT d.event_id FROM confirmed_event_details d JOIN confirmed_effect_events e USING(event_id) JOIN confirmed_history_sequence s USING(event_id) LEFT JOIN retry_decision_details r ON r.jail=e.jail AND r.effect_decision_id=e.decision_id WHERE s.sequence<=?1 AND (e.confirmed_us<=?2 OR (r.effect_decision_id IS NOT NULL AND ((SELECT count(*) FROM confirmed_event_details d2 JOIN confirmed_effect_events e2 USING(event_id) JOIN retry_decision_details r2 ON r2.jail=e2.jail AND r2.effect_decision_id=e2.decision_id WHERE r2.family=r.family AND r2.subject=r.subject)>?3 OR (d.evidence IS NOT NULL AND (SELECT coalesce(sum(length(CAST(d3.evidence AS BLOB))),0) FROM confirmed_event_details d3 JOIN confirmed_effect_events e3 USING(event_id) JOIN retry_decision_details r3 ON r3.jail=e3.jail AND r3.effect_decision_id=e3.decision_id WHERE r3.family=r.family AND r3.subject=r.subject)>16384)))) ORDER BY s.sequence LIMIT 1;",
            );
            defer detail_candidate.deinit();
            try detail_candidate.int(1, std.math.cast(i64, history_checkpoint.last_sequence) orelse return error.InvalidHistoryCheckpoint);
            try detail_candidate.int(2, cutoff);
            try detail_candidate.int(3, policy.max_matches);
            if (try detail_candidate.row()) {
                const detail_event = try Store.effectBlob(&detail_candidate, 0, 32);
                var prune_detail = try self.statement("DELETE FROM confirmed_event_details WHERE event_id=?1;");
                defer prune_detail.deinit();
                try prune_detail.blob(1, &detail_event);
                try prune_detail.done();
                if (self.api.changes(self.db) != 1) return error.HistoryGap;
                try self.fault(.after_history_detail_delete);
                try self.commitTransaction();
                return true;
            }
            var candidate = try self.statement("SELECT s.sequence,e.event_id,e.scope_key,e.jail,e.decision_id,e.confirmed_us FROM confirmed_history_sequence s JOIN confirmed_effect_events e USING(event_id) WHERE s.sequence=(SELECT retained_from FROM confirmed_history_stream WHERE id=1);");
            defer candidate.deinit();
            if (!try candidate.row()) {
                try self.commitTransaction();
                return false;
            }
            const sequence_value = try candidate.signed(0);
            const confirmed_us = try candidate.signed(5);
            if (sequence_value <= 0 or @as(u64, @intCast(sequence_value)) > history_checkpoint.last_sequence) {
                try self.commitTransaction();
                return false;
            }
            if (confirmed_us > cutoff) {
                try self.commitTransaction();
                return false;
            }
            const event_id = try Store.effectBlob(&candidate, 1, 32);
            const scope_key = try Store.effectBlob(&candidate, 2, 32);
            if (self.api.column_type(candidate.ptr, 3) != 3) return error.InvalidHistoryEvent;
            const jail = try candidate.boundedBytes(3, 64);
            const decision_id = try Store.effectBlob(&candidate, 4, 32);
            var owner = try self.statement("SELECT lease_kind,deadline_us FROM effect_owners WHERE scope_key=?1 AND jail=?2 AND decision_id=?3;");
            defer owner.deinit();
            try owner.blob(1, &scope_key);
            try owner.text(2, jail);
            try owner.blob(3, &decision_id);
            if (try owner.row()) {
                const lease = try Store.effectLease(&owner, 0, 1);
                if (lease.live(now_us)) {
                    try self.commitTransaction();
                    return false;
                }
            }
            var pending = try self.statement("SELECT 1 FROM effect_intents WHERE scope_key=?1 AND status IN(1,2) LIMIT 1;");
            defer pending.deinit();
            try pending.blob(1, &scope_key);
            if (try pending.row()) {
                try self.commitTransaction();
                return false;
            }
            var detail = try self.statement("DELETE FROM confirmed_event_details WHERE event_id=?1;");
            defer detail.deinit();
            try detail.blob(1, &event_id);
            try detail.done();
            try self.fault(.after_history_detail_delete);
            var sequence = try self.statement("DELETE FROM confirmed_history_sequence WHERE sequence=?1 AND event_id=?2;");
            defer sequence.deinit();
            try sequence.int(1, sequence_value);
            try sequence.blob(2, &event_id);
            try sequence.done();
            if (self.api.changes(self.db) != 1) return error.HistoryGap;
            var event = try self.statement("DELETE FROM confirmed_effect_events WHERE event_id=?1;");
            defer event.deinit();
            try event.blob(1, &event_id);
            try event.done();
            if (self.api.changes(self.db) != 1) return error.HistoryGap;
            try self.fault(.after_history_event_delete);
            var stream = try self.statement("UPDATE confirmed_history_stream SET retained_from=?1,revision=revision+1 WHERE id=1 AND retained_from=?2;");
            defer stream.deinit();
            try stream.int(1, sequence_value + 1);
            try stream.int(2, sequence_value);
            try stream.done();
            if (self.api.changes(self.db) != 1) return error.HistoryGap;
            try self.commitTransaction();
            return true;
        }
        /// A scope whose current owner still has an unsettled action outcome, if any.
        pub fn unsettledActionScope(self: *Store) Error!?effects.Hash {
            if (self.schema_version < 21) return null;
            var row = try self.statement("SELECT a.scope_key FROM action_targets a JOIN effect_owners o ON o.scope_key=a.scope_key AND o.decision_id=a.action_id WHERE a.status IN(1,2,5) LIMIT 1;");
            defer row.deinit();
            if (!try row.row()) return null;
            return try Store.effectBlob(&row, 0, 32);
        }
        /// Removes one bounded step of a spent enforcement scope. A scope is spent when its
        /// desired lease and current intent are absent, no owner holds a lease, no retained
        /// confirmed event references it and no intent or action target is unsettled.
        /// Without this, scopes accumulate for the life of the database until the fixed
        /// effect capacities refuse new decisions. Child rows go in chunks; the final step
        /// removes owners, the current intent and the scope row together and invalidates
        /// the published effect view.
        pub fn pruneSpentEffectOne(self: *Store) Error!bool {
            if (self.schema_version < 13) return false;
            try self.beginWrite();
            errdefer self.rollback();
            var candidate = try self.statement(if (self.schema_version >= 21)
                "SELECT n.scope_key,n.intent_id FROM native_effects n JOIN effect_intents i ON i.intent_id=n.intent_id WHERE n.lease_kind=0 AND i.status=4 AND NOT EXISTS(SELECT 1 FROM effect_owners o WHERE o.scope_key=n.scope_key AND o.lease_kind<>0) AND NOT EXISTS(SELECT 1 FROM confirmed_effect_events e WHERE e.scope_key=n.scope_key) AND NOT EXISTS(SELECT 1 FROM action_targets a WHERE a.scope_key=n.scope_key AND a.status IN(1,2,5)) AND NOT EXISTS(SELECT 1 FROM effect_intents p WHERE p.scope_key=n.scope_key AND p.status IN(1,2)) ORDER BY n.scope_key LIMIT 1;"
            else
                "SELECT n.scope_key,n.intent_id FROM native_effects n JOIN effect_intents i ON i.intent_id=n.intent_id WHERE n.lease_kind=0 AND i.status=4 AND NOT EXISTS(SELECT 1 FROM effect_owners o WHERE o.scope_key=n.scope_key AND o.lease_kind<>0) AND NOT EXISTS(SELECT 1 FROM confirmed_effect_events e WHERE e.scope_key=n.scope_key) AND NOT EXISTS(SELECT 1 FROM effect_intents p WHERE p.scope_key=n.scope_key AND p.status IN(1,2)) ORDER BY n.scope_key LIMIT 1;");
            defer candidate.deinit();
            if (!try candidate.row()) {
                try self.commitTransaction();
                return false;
            }
            const scope_key = try Store.effectBlob(&candidate, 0, 32);
            const current = try Store.effectBlob(&candidate, 1, 32);
            const chunks = [_][:0]const u8{
                "DELETE FROM effect_observations WHERE rowid IN (SELECT o.rowid FROM effect_intents i JOIN effect_observations o ON o.intent_id=i.intent_id WHERE i.scope_key=?1 LIMIT 256);",
                "DELETE FROM effect_intents WHERE rowid IN (SELECT rowid FROM effect_intents WHERE scope_key=?1 AND intent_id<>?2 LIMIT 256);",
                "DELETE FROM effect_owner_revisions WHERE rowid IN (SELECT h.rowid FROM effect_owner_revisions h WHERE h.scope_key=?1 AND NOT EXISTS(SELECT 1 FROM effect_owners o WHERE o.scope_key=h.scope_key AND o.jail=h.jail AND o.revision=h.revision) LIMIT 256);",
                "DELETE FROM action_targets WHERE rowid IN (SELECT rowid FROM action_targets WHERE scope_key=?1 LIMIT 256);",
            };
            for (chunks, 0..) |sql, index| {
                if (index == 3 and self.schema_version < 21) break;
                var chunk = try self.statement(sql);
                defer chunk.deinit();
                try chunk.blob(1, &scope_key);
                if (index == 1) try chunk.blob(2, &current);
                try chunk.done();
                if (self.api.changes(self.db) != 0) {
                    try self.commitTransaction();
                    return true;
                }
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
            if (self.api.changes(self.db) != 1) return error.InvalidEffect;
            try self.advanceEffectSnapshot();
            try self.commitEffectTransaction(true);
            return true;
        }
        pub fn canonicalHistoryManifest(manifest: consumers.Manifest) bool {
            return std.mem.eql(u8, manifest.jail, "@history") and std.mem.eql(u8, manifest.source, "confirmed-effects") and manifest.required.len == 1 and
                manifest.required[0].format_version == effect_history.version and consumers.Key.eql(manifest.required[0].key, effect_history.key(manifest.source_generation));
        }
        fn checkHistoryBatch(manifest: consumers.Manifest, batch: consumers.Batch, installation: [16]u8) Error!effect_history.Checkpoint {
            try batch.validate();
            _ = try manifest.digest();
            if (!canonicalHistoryManifest(manifest) or batch.deltas.len != 1 or batch.dependencies.len != 0) return error.InvalidHistoryTransition;
            const delta = batch.deltas[0];
            if (!consumers.Key.eql(delta.key, manifest.required[0].key) or delta.format_version != effect_history.version or delta.valid_until_us != null) return error.InvalidHistoryTransition;
            const history_checkpoint = try effect_history.Checkpoint.decode(delta.payload);
            if (!std.mem.eql(u8, &history_checkpoint.generation, &manifest.source_generation) or !std.mem.eql(u8, &history_checkpoint.installation, &installation)) return error.HistoryGenerationMismatch;
            return history_checkpoint;
        }
        pub fn bootstrapConfirmedHistory(self: *Store, manifest: consumers.Manifest, batch: consumers.Batch, installation: effects.Installation) Error!void {
            const history_checkpoint = try checkHistoryBatch(manifest, batch, installation.id);
            if (history_checkpoint.last_sequence != 0 or batch.deltas[0].expected_revision != 0) return error.InvalidHistoryTransition;
            try self.beginAdmissionWrite();
            errdefer self.rollback();
            _ = try self.historyHead(installation, 0);
            try self.admitManifestTx(manifest);
            try self.checkManifestBatch(manifest, batch, true, true);
            try self.writeConsumerBatch(batch);
            try self.readyManifest(manifest);
            try self.fault(.before_consumer_input_commit);
            try self.commitConsumerClock(batch);
            try self.commitTransaction();
        }
        pub fn commitConfirmedHistory(self: *Store, manifest: consumers.Manifest, batch: consumers.Batch, token: effect_history.PageToken) Error!void {
            const next = try checkHistoryBatch(manifest, batch, token.installation);
            try self.beginWrite();
            errdefer self.rollback();
            try self.validateConfirmedEffectPageTx(token);
            try self.checkManifestBatch(manifest, batch, false, true);
            if (token.last_sequence == token.after_sequence) return error.HistoryCaughtUp;
            var row = try self.statement("SELECT payload FROM consumer_checkpoints WHERE kind=?1 AND jail=?2 AND source=?3 AND rule=?4 AND generation=?5;");
            defer row.deinit();
            const required_key = manifest.required[0].key;
            try Store.bindConsumerKey(&row, &required_key);
            if (!try row.row()) return error.MissingRequiredConsumer;
            const previous = try effect_history.Checkpoint.decode(try row.boundedBytes(0, effect_history.checkpoint_bytes));
            var events: [effect_history.max_page]effect_history.Event = undefined;
            const installation = try self.readInstallation() orelse return error.InstallationRequired;
            const size: usize = @intCast(token.last_sequence - token.after_sequence);
            const page = try self.confirmedEffectPageTx(installation, token.after_sequence, token.stream_revision, events[0..size]);
            for (events[0..page.count]) |event| if (event.confirmed_us > batch.prepared_us) return error.InvalidHistoryEvent;
            try effect_history.validateTransition(previous, next, page, events[0..page.count]);
            try self.writeConsumerBatch(batch);
            try self.fault(.before_consumer_input_commit);
            try self.commitConsumerClock(batch);
            try self.commitTransaction();
        }
    };
}
