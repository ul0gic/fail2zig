// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Retires idle retry subjects in bounded batches under a cleanup fence and keeps each jail's retired-decision total.
// Holds: A retry subject is retired only while the fence's jail, consumer and effect revisions and retry policy generation still match.

const std = @import("std");
const detection = @import("../detect/detection_record.zig");
const retry = @import("../detect/retry.zig");
const effects = @import("../effect/effect.zig");
const store = @import("store.zig");
const Error = store.Error;

pub fn Methods(comptime Store: type) type {
    return struct {
        pub const CleanupFence = struct {
            jail: []const u8,
            source: []const u8,
            generation: [32]u8,
            jail_revision: u64,
            consumer_revision: u64,
            effect_revision: u64,
            clock: effects.Clock,
        };
        fn subjectEffectPinned(self: *Store, subject: detection.Subject) Error!bool {
            const installation = try self.readInstallation() orelse return false;
            const scope = try effects.Scope.host(subject);
            if (try self.readEffect(try scope.key(installation), installation)) |entry| {
                return entry.desired != .absent or entry.status != .absent;
            }
            return false;
        }
        pub const RetryRetirementCandidate = struct { subject: detection.Subject, last_processed_us: i64, decisions: u64, lease: retry.Lease };
        pub fn retryRetirementCandidate(self: *Store, jail: []const u8, after: ?detection.Subject) Error!?RetryRetirementCandidate {
            _ = try self.maintenanceRevision();
            try Store.maintenanceKey(jail, "@retired");
            // Why: Eligibility is tested by the caller, not in WHERE, so each returned row costs one examination and the scan is bounded.
            var row = try self.statement(if (self.schema_version >= 16)
                (if (after == null)
                    "SELECT family,subject,last_processed_us,decisions,lease_kind,deadline_us FROM retry_states WHERE jail=?1 ORDER BY family,subject LIMIT 1;"
                else
                    "SELECT family,subject,last_processed_us,decisions,lease_kind,deadline_us FROM retry_states WHERE jail=?1 AND (family,subject)>(?2,?3) ORDER BY family,subject LIMIT 1;")
            else
                (if (after == null)
                    "SELECT family,subject,last_processed_us,decisions,CASE WHEN expiry_us IS NULL THEN 0 ELSE 1 END,expiry_us FROM retry_states WHERE jail=?1 ORDER BY family,subject LIMIT 1;"
                else
                    "SELECT family,subject,last_processed_us,decisions,CASE WHEN expiry_us IS NULL THEN 0 ELSE 1 END,expiry_us FROM retry_states WHERE jail=?1 AND (family,subject)>(?2,?3) ORDER BY family,subject LIMIT 1;"));
            defer row.deinit();
            try row.text(1, jail);
            if (after) |*subject| try Store.bindSubject(&row, subject);
            if (!try row.row()) return null;
            const decisions = try row.signed(3);
            if (decisions < 0) return error.InvalidRetryState;
            const kind = try row.signed(4);
            const deadline = try row.optionalSigned(5);
            const lease: retry.Lease = switch (kind) {
                0 => if (deadline == null) .absent else return error.InvalidRetryState,
                1 => .{ .finite = deadline orelse return error.InvalidRetryState },
                2 => if (deadline == null) .permanent else return error.InvalidRetryState,
                else => return error.InvalidRetryState,
            };
            return .{ .subject = try self.decodeRetrySubject(&row, 0, 1), .last_processed_us = try row.signed(2), .decisions = @intCast(decisions), .lease = lease };
        }
        fn checkRetirementFence(self: *Store, fence: CleanupFence) Error!i64 {
            _ = try self.maintenanceRevision();
            try Store.maintenanceKey(fence.jail, "@retired");
            if (try self.revision(fence.jail) != fence.jail_revision or try self.consumerRevision() != fence.consumer_revision or
                try self.maintenanceEffectRevision() != fence.effect_revision) return error.StaleMaintenance;
            if (try self.readRetryPolicy(fence.jail)) |policy| if (!std.mem.eql(u8, &policy.generation, &fence.generation)) return error.RetryGenerationMismatch;
            return self.cleanupClock(fence.clock);
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
            var row = try self.statement("SELECT last_processed_us,decisions FROM retry_retired WHERE jail=?1 AND family=?2 AND subject=?3;");
            defer row.deinit();
            try row.text(1, jail);
            try Store.bindSubject(&row, &subject);
            if (!try row.row()) return null;
            const decisions = try row.signed(1);
            const last = try row.signed(0);
            if (decisions < 0 or last > ((try self.readRetryClock()) orelse return error.InvalidRetryState)) return error.InvalidRetryState;
            return .{ .last_processed_us = last, .decisions = @intCast(decisions) };
        }
        pub fn retireRetrySubject(self: *Store, fence: CleanupFence, candidate: RetryRetirementCandidate) Error!bool {
            try self.beginWrite();
            errdefer self.rollback();
            const now = try self.checkRetirementFence(fence);
            const admission = try self.readRetryPolicy(fence.jail) orelse return error.RetryAdmissionRequired;
            if (try self.retireOneTx(fence, admission.policy, candidate, now) != .retired) {
                try self.commitTransaction();
                return false;
            }
            try self.finishRetirementTx(fence, now);
            try self.commitTransaction();
            return true;
        }
        pub const max_retirement_batch = Store.attribution_batch;
        const retirement_examinations_per_slot: usize = 4;
        pub const RetirementBatch = struct {
            examined: usize = 0,
            retired: usize = 0,
            pinned_state: usize = 0,
            pinned_effect: usize = 0,
            last: ?detection.Subject = null,
            exhausted: bool = false,
            next_check_us: ?i64 = null,
            retry_revision: u64 = 0,
            effect_revision: u64 = 0,
            yielded: bool = false,
        };
        pub fn retireRetrySubjects(self: *Store, fence: CleanupFence, after: ?detection.Subject, now_us: i64, window_us: i64, max: usize) Error!RetirementBatch {
            if (max == 0 or max > max_retirement_batch) return error.InvalidRetryState;
            const prior_rollback = self.rollback_error_code;
            self.rollback_error_code = null;
            const batch = self.retireRetrySubjectsTx(fence, after, now_us, window_us, max) catch |failure| {
                // Why: The errdefer in retireRetrySubjectsTx has already rolled back, so only a clean rollback lets an interruption yield.
                const clean = !self.reopen_required and self.rollback_error_code == null and self.api.get_autocommit(self.db) != 0;
                if (self.rollback_error_code == null) self.rollback_error_code = prior_rollback;
                if (failure != error.Interrupted or !clean) return failure;
                if (max <= 1) return error.MaintenanceWorkExhausted;
                return .{ .yielded = true };
            };
            if (self.rollback_error_code == null) self.rollback_error_code = prior_rollback;
            return batch;
        }
        fn retirementNextCheck(candidate: RetryRetirementCandidate, window_us: i64) ?i64 {
            if (candidate.lease == .permanent) return null;
            // Why: Eligibility needs an age strictly past the window, so the first eligible instant is one microsecond after it ends.
            var next = @as(i128, candidate.last_processed_us) + @as(i128, window_us) + 1;
            if (candidate.lease == .finite) next = @max(next, @as(i128, candidate.lease.finite));
            return std.math.cast(i64, next);
        }
        fn retireRetrySubjectsTx(self: *Store, fence: CleanupFence, after: ?detection.Subject, now_us: i64, window_us: i64, max: usize) Error!RetirementBatch {
            try self.beginWrite();
            errdefer self.rollback();
            const now = try self.checkRetirementFence(fence);
            const admission = try self.readRetryPolicy(fence.jail) orelse return error.RetryAdmissionRequired;
            var batch = RetirementBatch{};
            var cursor = after;
            while (batch.retired < max and batch.examined < max * retirement_examinations_per_slot) {
                const candidate = (try self.retryRetirementCandidate(fence.jail, cursor)) orelse {
                    batch.exhausted = true;
                    break;
                };
                cursor = candidate.subject;
                batch.last = candidate.subject;
                batch.examined += 1;
                const outcome = if (candidate.last_processed_us >= now_us -| window_us or candidate.lease.live(now_us))
                    Retirement.pinned_state
                else
                    try self.retireOneTx(fence, admission.policy, candidate, now);
                switch (outcome) {
                    .retired => batch.retired += 1,
                    .pinned_state => {
                        batch.pinned_state += 1;
                        if (retirementNextCheck(candidate, window_us)) |next| {
                            batch.next_check_us = if (batch.next_check_us) |prior| @min(prior, next) else next;
                        }
                    },
                    .pinned_effect => batch.pinned_effect += 1,
                }
            }
            if (batch.retired != 0) try self.finishRetirementTx(fence, now);
            const retry_revision = try self.integer("SELECT revision FROM policy_summary_clock WHERE id=1;");
            if (retry_revision <= 0) return error.InvalidPolicySummary;
            batch.retry_revision = @intCast(retry_revision);
            batch.effect_revision = try self.maintenanceEffectRevision();
            try self.commitTransaction();
            return batch;
        }
        fn finishRetirementTx(self: *Store, fence: CleanupFence, now: i64) Error!void {
            var floor = try self.statement("UPDATE retry_clock SET floor_us=?1 WHERE id=1;");
            defer floor.deinit();
            try floor.int(1, now);
            try floor.done();
            if (self.api.changes(self.db) != 1) return error.InvalidRetryState;
            try self.fault(.after_retry_retire);
            try self.finishCleanupClock(fence.clock, now);
        }
        const Retirement = enum { retired, pinned_state, pinned_effect };
        fn retireOneTx(self: *Store, fence: CleanupFence, policy: retry.Policy, candidate: RetryRetirementCandidate, now: i64) Error!Retirement {
            try self.requireRetryProjectionMutationTx();
            if (try self.readRetired(fence.jail, candidate.subject) != null) return error.StaleMaintenance;
            const state = try self.readRetryState(fence.jail, candidate.subject, policy) orelse return error.StaleMaintenance;
            if (state.last_processed_us != candidate.last_processed_us or state.decisions != candidate.decisions) return error.StaleMaintenance;
            const logical = (try retry.prune(policy, state, now)).state;
            if (logical.lease != .absent or logical.count != 0) return .pinned_state;
            if (try self.subjectEffectPinned(candidate.subject)) return .pinned_effect;
            if (state.decisions != 0) {
                try self.changeRetiredTotal(fence.jail, state.decisions, true);
                var saved = try self.statement("INSERT INTO retry_retired VALUES(?1,?2,?3,?4,?5,?6);");
                defer saved.deinit();
                try saved.text(1, fence.jail);
                try Store.bindSubject(&saved, &candidate.subject);
                try saved.blob(4, &fence.generation);
                try saved.int(5, state.last_processed_us);
                try saved.int(6, @intCast(state.decisions));
                try saved.done();
                _ = try self.evictMemoryRows(.retired, now);
            }
            var remove = try self.statement("DELETE FROM retry_states WHERE jail=?1 AND family=?2 AND subject=?3;");
            defer remove.deinit();
            try remove.text(1, fence.jail);
            try Store.bindSubject(&remove, &candidate.subject);
            try remove.done();
            self.deletedRows(.retry_states);
            if (self.api.changes(self.db) != 1) return error.StaleMaintenance;
            try self.removeRetryProjectionRowTx(fence.jail, &candidate.subject);
            try self.changeRetryJailSummaryTx(fence.jail, 0, 0);
            return .retired;
        }
    };
}
