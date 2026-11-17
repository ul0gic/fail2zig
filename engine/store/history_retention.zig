// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Applies history retention policy: caps retained match details and prunes the consumed confirmed-history prefix.
// Holds: History is pruned only at or below the consumer's committed sequence, and the prefix advances from retained_from without gaps.

const std = @import("std");
const detection = @import("../detect/detection_record.zig");
const retry = @import("../detect/retry.zig");
const effects = @import("../effect/effect.zig");
const effect_history = @import("../effect/effect_history.zig");
const store = @import("store.zig");
const Error = store.Error;
const Stmt = store.Stmt;
const Limits = store.Limits;
const latest_schema = store.latest_schema;

pub fn Methods(comptime Store: type) type {
    return struct {
        const HistoryRetention = Store.HistoryRetention;
        pub fn pruneRetryDecisionDetailsTx(self: *Store) Error!usize {
            // Why: This scan may cover the whole retained table before finding no eligible row, so it runs with 5000 callbacks, not 1000.
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
            self.deletedRows(.retry_decision_details);
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

        pub const JailRetentionLimit = struct { jail: []const u8, max_matches: ?u16 };
        pub const RetentionUpdate = struct { global_max_matches: u16, jails: []const JailRetentionLimit };
        pub const RetentionPolicy = struct { generation: i64, max_matches: i64, published: bool, sweep_cursor: i64, retry_cursor: ?i64 = null, subject_cursor: ?i64 = null };
        pub const RetentionOutcome = enum { idle, rebuilt, published, details, prefix, yielded };
        const retained_evidence_limit = "16384";
        const age_path_threshold: i64 = 4096;
        const prefix_page: usize = 64;
        pub const history_overload_events: i64 = @divTrunc(effects.max_confirmed_events * 9, 10);
        const overload_notice_us: i64 = 60 * 1_000_000;

        fn readRetentionPolicy(self: *Store) Error!RetentionPolicy {
            var row = try self.statement(if (self.schema_version >= 27)
                "SELECT generation,max_matches,state,sweep_cursor,retry_evidence_sweep_cursor,history_subject_sweep_cursor FROM retention_policy WHERE id=1;"
            else
                "SELECT generation,max_matches,state,sweep_cursor,NULL,NULL FROM retention_policy WHERE id=1;");
            defer row.deinit();
            if (!try row.row()) return error.InvalidApplicationHistoryRow;
            const state = try row.signed(2);
            const result = RetentionPolicy{
                .generation = try row.signed(0),
                .max_matches = try row.signed(1),
                .published = state == 2,
                .sweep_cursor = try row.signed(3),
                .retry_cursor = try row.optionalSigned(4),
                .subject_cursor = try row.optionalSigned(5),
            };
            if (result.generation <= 0 or result.max_matches < 0 or result.max_matches > 1024 or result.sweep_cursor < 0 or (state != 1 and state != 2) or (result.retry_cursor orelse 0) < 0 or (result.subject_cursor orelse 0) < 0) return error.InvalidApplicationHistoryRow;
            return result;
        }

        pub fn effectiveHistoryLimitTx(self: *Store, jail: []const u8) Error!u16 {
            _ = detection.Name.init(jail) catch return error.InvalidApplicationHistoryQuery;
            const policy = try self.readRetentionPolicy();
            if (self.schema_version < 27) return @intCast(policy.max_matches);
            var row = try self.statement("SELECT max_matches FROM history_jail_limits WHERE jail=?1;");
            defer row.deinit();
            try row.text(1, jail);
            const override = if (try row.row()) try row.optionalSigned(0) else null;
            if (override) |value| if (value < 0 or value > 1024) return error.InvalidApplicationHistoryRow;
            return @intCast(@min(policy.max_matches, override orelse policy.max_matches));
        }

        pub fn applyRetentionPolicyTx(self: *Store, update: RetentionUpdate) Error!bool {
            if (self.api.get_autocommit(self.db) != 0 or self.schema_version < 27) return error.MaintenanceStorageRequired;
            if (update.global_max_matches > 1024 or update.jails.len > 256) return error.InvalidApplicationHistoryQuery;
            for (update.jails, 0..) |item, i| {
                _ = detection.Name.init(item.jail) catch return error.InvalidApplicationHistoryQuery;
                if (item.max_matches) |value| if (value > 1024) return error.InvalidApplicationHistoryQuery;
                for (update.jails[0..i]) |previous| if (std.mem.eql(u8, item.jail, previous.jail)) return error.InvalidApplicationHistoryQuery;
            }
            var count: usize = 0;
            var equal = true;
            {
                var row = try self.statement("SELECT jail,max_matches FROM history_jail_limits ORDER BY jail LIMIT 257;");
                defer row.deinit();
                while (try row.row()) {
                    if (count == 256) return error.InvalidApplicationHistoryRow;
                    if (self.api.column_type(row.ptr, 0) != 3) return error.InvalidApplicationHistoryRow;
                    const name = detection.Name.init(try row.boundedBytes(0, 64)) catch return error.InvalidApplicationHistoryRow;
                    const value = try row.optionalSigned(1);
                    if (value) |limit| if (limit < 0 or limit > 1024) return error.InvalidApplicationHistoryRow;
                    var found = false;
                    for (update.jails) |item| if (std.mem.eql(u8, name.slice(), item.jail)) {
                        found = true;
                        if (value != if (item.max_matches) |limit| @as(?i64, limit) else null) equal = false;
                        break;
                    };
                    equal = equal and found;
                    count += 1;
                }
            }
            const current = try self.readRetentionPolicy();
            if (equal and count == update.jails.len and current.max_matches == update.global_max_matches) return false;
            try self.exec("DELETE FROM history_jail_limits;");
            for (update.jails) |item| {
                var row = try self.statement("INSERT INTO history_jail_limits(jail,max_matches) VALUES(?1,?2);");
                defer row.deinit();
                try row.text(1, item.jail);
                if (item.max_matches) |value| try row.int(2, value) else try self.check(self.api.bind_null(row.ptr, 2));
                try row.done();
            }
            try self.advanceRetentionGenerationTx(update.global_max_matches, current.generation);
            return true;
        }

        pub fn setRetentionPolicies(self: *Store, update: RetentionUpdate) Error!bool {
            try self.beginAdmissionWrite();
            errdefer self.rollback();
            const changed = try self.applyRetentionPolicyTx(update);
            try self.commitTransaction();
            return changed;
        }
        pub fn setRetentionPolicy(self: *Store, max_matches: u16) Error!bool {
            if (self.schema_version >= 27) return self.setRetentionPolicies(.{ .global_max_matches = max_matches, .jails = &.{} });
            if (max_matches > 1024) return error.InvalidApplicationHistoryQuery;
            try self.beginWrite();
            errdefer self.rollback();
            if (self.schema_version < store.load_repair_schema) return error.MaintenanceStorageRequired;
            const started = try self.beginRetentionGenerationTx(max_matches);
            try self.commitTransaction();
            return started;
        }
        fn advanceRetentionGenerationTx(self: *Store, max_matches: i64, generation: i64) Error!void {
            var row = try self.statement(if (self.schema_version >= 27)
                "UPDATE retention_policy SET generation=generation+1,max_matches=?1,state=1,sweep_cursor=0,retry_evidence_sweep_cursor=0 WHERE id=1 AND generation=?2 AND generation<9223372036854775807;"
            else
                "UPDATE retention_policy SET generation=generation+1,max_matches=?1,state=1,sweep_cursor=0 WHERE id=1 AND generation=?2 AND generation<9223372036854775807;");
            defer row.deinit();
            try row.int(1, max_matches);
            try row.int(2, generation);
            try row.done();
            if (self.api.changes(self.db) != 1) return error.StorageLimit;
        }
        fn beginRetentionGenerationTx(self: *Store, max_matches: i64) Error!bool {
            const current = try self.readRetentionPolicy();
            if (current.max_matches == max_matches) return false;
            try self.advanceRetentionGenerationTx(max_matches, current.generation);
            return true;
        }

        pub fn retainDetailDeferredTx(self: *Store, family: i64, subject: []const u8, bytes: ?i64, sequence: i64) Error!void {
            try self.accountRetainedDetailTx(family, subject, bytes, sequence, false);
        }
        pub fn refreshRetainedSubjectTx(self: *Store, subject: detection.Subject) Error!void {
            const policy = try self.readRetentionPolicy();
            switch (subject) {
                .v4 => |value| try self.updateCandidateTx(4, &value, policy),
                .v6 => |value| try self.updateCandidateTx(6, &value, policy),
            }
        }
        fn accountRetainedDetailTx(self: *Store, family: i64, subject: []const u8, bytes: ?i64, sequence: i64, local: bool) Error!void {
            const policy = try self.readRetentionPolicy();
            var row = try self.statement("INSERT INTO retained_subject_summaries(family,subject,detail_count,evidence_bytes,earliest_sequence,earliest_evidence_sequence,evaluated_generation,candidate_sequence) VALUES(?1,?2,1,coalesce(?3,0),?4,CASE WHEN ?3 IS NOT NULL THEN ?4 END,?5,NULL) ON CONFLICT(family,subject) DO UPDATE SET detail_count=detail_count+1,evidence_bytes=evidence_bytes+excluded.evidence_bytes,earliest_sequence=min(earliest_sequence,excluded.earliest_sequence),earliest_evidence_sequence=CASE WHEN earliest_evidence_sequence IS NULL THEN excluded.earliest_evidence_sequence WHEN excluded.earliest_evidence_sequence IS NULL THEN earliest_evidence_sequence ELSE min(earliest_evidence_sequence,excluded.earliest_evidence_sequence) END;");
            defer row.deinit();
            try row.int(1, family);
            try row.blob(2, subject);
            if (bytes) |value| try row.int(3, value) else try self.check(self.api.bind_null(row.ptr, 3));
            try row.int(4, sequence);
            try row.int(5, policy.generation);
            try row.done();
            if (local) try self.updateCandidateTx(family, subject, policy) else try self.updateGlobalCandidateTx(family, subject, policy);
        }
        fn updateGlobalCandidateTx(self: *Store, family: i64, subject: []const u8, policy: RetentionPolicy) Error!void {
            var row = try self.statement("UPDATE retained_subject_summaries SET candidate_sequence=CASE WHEN detail_count>?3 THEN earliest_sequence WHEN evidence_bytes>" ++ retained_evidence_limit ++ " THEN earliest_evidence_sequence END,evaluated_generation=?4 WHERE family=?1 AND subject=?2;");
            defer row.deinit();
            try row.int(1, family);
            try row.blob(2, subject);
            try row.int(3, policy.max_matches);
            try row.int(4, policy.generation);
            try row.done();
            if (self.api.changes(self.db) != 1) return error.InvalidApplicationHistoryRow;
        }

        // Holds: Runs only when the subject's retained count fits the global cap; a larger total is refused as an invalid row.
        fn localVictimsTx(self: *Store, family: i64, subject: []const u8, policy: RetentionPolicy, total: i64, output: []i64) Error!usize {
            if (self.schema_version < 27) return 0;
            if (total <= 0 or total > policy.max_matches) return error.InvalidApplicationHistoryRow;
            var row = try self.statement("SELECT sequence,ordinal,max_matches FROM (SELECT d.sequence,row_number() OVER(PARTITION BY e.jail ORDER BY d.sequence DESC) AS ordinal,l.max_matches FROM (SELECT sequence,event_id FROM confirmed_event_details INDEXED BY confirmed_details_subject WHERE family=?1 AND subject=?2 ORDER BY sequence LIMIT ?3) d JOIN confirmed_effect_events e ON e.event_id=d.event_id LEFT JOIN history_jail_limits l ON l.jail=e.jail) ORDER BY sequence;");
            defer row.deinit();
            try row.int(1, family);
            try row.blob(2, subject);
            try row.int(3, total + 1);
            var examined: i64 = 0;
            var count: usize = 0;
            while (try row.row()) {
                examined += 1;
                if (examined > total) return error.InvalidApplicationHistoryRow;
                const override = try row.optionalSigned(2);
                if (override) |value| if (value < 0 or value > 1024) return error.InvalidApplicationHistoryRow;
                if (try row.signed(1) <= @min(policy.max_matches, override orelse policy.max_matches)) continue;
                if (count == output.len) return error.InvalidApplicationHistoryRow;
                output[count] = try row.signed(0);
                if (output[count] <= 0 or (count > 0 and output[count] <= output[count - 1])) return error.InvalidApplicationHistoryRow;
                count += 1;
            }
            if (examined != total) return error.InvalidApplicationHistoryRow;
            return count;
        }
        fn updateCandidateTx(self: *Store, family: i64, subject: []const u8, policy: RetentionPolicy) Error!void {
            try self.updateGlobalCandidateTx(family, subject, policy);
            var summary = try self.statement("SELECT detail_count,candidate_sequence FROM retained_subject_summaries WHERE family=?1 AND subject=?2;");
            defer summary.deinit();
            try summary.int(1, family);
            try summary.blob(2, subject);
            if (!try summary.row()) return error.InvalidApplicationHistoryRow;
            const count = try summary.signed(0);
            if (count <= 0 or count > policy.max_matches or try summary.optionalSigned(1) != null) return;
            var victims: [1024]i64 = undefined;
            if (try self.localVictimsTx(family, subject, policy, count, &victims) == 0) return;
            try self.setLocalCandidateTx(family, subject, victims[0]);
        }
        fn setLocalCandidateTx(self: *Store, family: i64, subject: []const u8, sequence: i64) Error!void {
            var row = try self.statement("UPDATE retained_subject_summaries SET candidate_sequence=?3 WHERE family=?1 AND subject=?2 AND candidate_sequence IS NULL;");
            defer row.deinit();
            try row.int(1, family);
            try row.blob(2, subject);
            try row.int(3, sequence);
            try row.done();
        }

        const RetainedDetail = struct {
            sequence: i64,
            event_id: [32]u8,
            family: ?i64,
            subject: [16]u8 = undefined,
            subject_len: usize = 0,
            bytes: ?i64,

            fn read(row: *Stmt) Error!RetainedDetail {
                var detail = RetainedDetail{ .sequence = try row.signed(0), .event_id = try Store.effectBlob(row, 1, 32), .family = try row.optionalSigned(2), .bytes = try row.optionalSigned(4) };
                if (detail.family != null) {
                    const subject = try row.boundedBytes(3, detail.subject.len);
                    @memcpy(detail.subject[0..subject.len], subject);
                    detail.subject_len = subject.len;
                    if ((detail.family != 4 and detail.family != 6) or subject.len != (if (detail.family == 4) @as(usize, 4) else 16)) return error.InvalidApplicationHistoryRow;
                }
                if ((detail.bytes orelse 0) < 0 or (detail.bytes orelse 0) > retry.max_evidence_text_bytes) return error.InvalidApplicationHistoryRow;
                if (detail.sequence <= 0) return error.InvalidApplicationHistoryRow;
                return detail;
            }
        };

        fn deleteRetainedDetailTx(self: *Store, detail: RetainedDetail, policy: RetentionPolicy) Error!void {
            {
                var remove = try self.statement("DELETE FROM confirmed_event_details WHERE event_id=?1 AND sequence=?2;");
                defer remove.deinit();
                try remove.blob(1, &detail.event_id);
                try remove.int(2, detail.sequence);
                try remove.done();
                self.deletedRows(.confirmed_event_details);
                if (self.api.changes(self.db) != 1) return error.HistoryGap;
            }
            try self.fault(.after_history_detail_delete);
            const family = detail.family orelse return;
            const subject = detail.subject[0..detail.subject_len];
            {
                var last = try self.statement("DELETE FROM retained_subject_summaries WHERE family=?1 AND subject=?2 AND detail_count=1;");
                defer last.deinit();
                try last.int(1, family);
                try last.blob(2, subject);
                try last.done();
                if (self.api.changes(self.db) == 1) return;
            }
            {
                var decrement = try self.statement("UPDATE retained_subject_summaries SET detail_count=detail_count-1,evidence_bytes=evidence_bytes-?3,candidate_sequence=NULL,earliest_sequence=(SELECT min(sequence) FROM confirmed_event_details INDEXED BY confirmed_details_subject WHERE family=?1 AND subject=?2),earliest_evidence_sequence=(SELECT min(sequence) FROM confirmed_event_details INDEXED BY confirmed_details_evidence WHERE family=?1 AND subject=?2 AND evidence_bytes IS NOT NULL) WHERE family=?1 AND subject=?2 AND detail_count>1;");
                defer decrement.deinit();
                try decrement.int(1, family);
                try decrement.blob(2, subject);
                try decrement.int(3, detail.bytes orelse 0);
                try decrement.done();
                if (self.api.changes(self.db) != 1) return error.InvalidApplicationHistoryRow;
            }
            try self.updateGlobalCandidateTx(family, subject, policy);
        }

        fn historyFence(self: *Store) Error!?i64 {
            var row = try self.statement("SELECT payload FROM consumer_checkpoints WHERE kind=5 AND jail='@history' AND source='confirmed-effects' AND rule='checkpoint';");
            defer row.deinit();
            if (!try row.row()) return null;
            const saved = effect_history.Checkpoint.decode(try row.boundedBytes(0, effect_history.checkpoint_bytes)) catch return error.InvalidHistoryCheckpoint;
            if (try row.row()) return error.InvalidHistoryCheckpoint;
            const installation = try self.readInstallation() orelse return error.InstallationRequired;
            if (!std.mem.eql(u8, &saved.installation, &installation.id)) return error.InvalidHistoryCheckpoint;
            return std.math.cast(i64, saved.last_sequence) orelse error.InvalidHistoryCheckpoint;
        }

        fn reserveSubjectWindowTx(self: *Store, detail: RetainedDetail, touched: []const RetainedDetail, policy: RetentionPolicy, budget: *usize) Error!bool {
            const family = detail.family orelse return true;
            for (touched) |previous| if (previous.family == family and std.mem.eql(u8, previous.subject[0..previous.subject_len], detail.subject[0..detail.subject_len])) return true;
            var row = try self.statement("SELECT detail_count FROM retained_subject_summaries WHERE family=?1 AND subject=?2;");
            defer row.deinit();
            try row.int(1, family);
            try row.blob(2, detail.subject[0..detail.subject_len]);
            if (!try row.row()) return error.InvalidApplicationHistoryRow;
            const count = try row.signed(0);
            if (count <= 0) return error.InvalidApplicationHistoryRow;
            const cost: usize = @intCast(@min(count, policy.max_matches));
            if (cost > budget.*) return false;
            budget.* -= cost;
            return true;
        }
        fn refreshDetailsTx(self: *Store, rows: []const RetainedDetail, policy: RetentionPolicy) Error!void {
            for (rows, 0..) |detail, i| {
                const family = detail.family orelse continue;
                var seen = false;
                for (rows[0..i]) |previous| if (previous.family == family and std.mem.eql(u8, previous.subject[0..previous.subject_len], detail.subject[0..detail.subject_len])) {
                    seen = true;
                    break;
                };
                if (seen) continue;
                var row = try self.statement("SELECT 1 FROM retained_subject_summaries WHERE family=?1 AND subject=?2;");
                defer row.deinit();
                try row.int(1, family);
                try row.blob(2, detail.subject[0..detail.subject_len]);
                if (try row.row()) try self.updateCandidateTx(family, detail.subject[0..detail.subject_len], policy);
            }
        }
        fn detailAtSequenceTx(self: *Store, sequence: i64) Error!RetainedDetail {
            var row = try self.statement("SELECT sequence,event_id,family,subject,evidence_bytes FROM confirmed_event_details INDEXED BY confirmed_details_sequence WHERE sequence=?1;");
            defer row.deinit();
            try row.int(1, sequence);
            if (!try row.row()) return error.InvalidApplicationHistoryRow;
            const detail = try RetainedDetail.read(&row);
            if (try row.row()) return error.InvalidApplicationHistoryRow;
            return detail;
        }
        fn deleteDetailPage(self: *Store, policy: RetentionPolicy, fence: i64, cutoff: i64, page: usize) Error!usize {
            const competing: ?i64 = blk: {
                var row = try self.statement("SELECT min(candidate_sequence) FROM retained_subject_summaries INDEXED BY retained_subject_candidates WHERE candidate_sequence IS NOT NULL;");
                defer row.deinit();
                if (!try row.row()) return error.DatabaseFailure;
                const value = try row.optionalSigned(0) orelse break :blk null;
                break :blk if (value <= fence) value else null;
            };
            const limit = if (competing) |value| value - 1 else fence;
            var rows: [store.max_retention_page]RetainedDetail = undefined;
            var count: usize = 0;
            if (limit > 0) {
                const age_count = blk: {
                    var row = try self.statement("SELECT count(*) FROM (SELECT 1 FROM confirmed_event_details INDEXED BY confirmed_details_age WHERE confirmed_us<=?1 LIMIT ?2);");
                    defer row.deinit();
                    try row.int(1, cutoff);
                    try row.int(2, age_path_threshold);
                    if (!try row.row()) return error.DatabaseFailure;
                    break :blk try row.signed(0);
                };
                var row = try self.statement(if (age_count >= age_path_threshold)
                    "SELECT sequence,event_id,family,subject,evidence_bytes FROM confirmed_event_details INDEXED BY confirmed_details_sequence WHERE sequence<=?2 AND confirmed_us<=?1 ORDER BY sequence LIMIT ?3;"
                else
                    "SELECT sequence,event_id,family,subject,evidence_bytes FROM confirmed_event_details INDEXED BY confirmed_details_age WHERE confirmed_us<=?1 AND sequence<=?2 ORDER BY sequence LIMIT ?3;");
                defer row.deinit();
                try row.int(1, cutoff);
                try row.int(2, limit);
                try row.int(3, @intCast(page));
                while (try row.row()) {
                    if (count == rows.len) return error.InvalidApplicationHistoryRow;
                    rows[count] = try RetainedDetail.read(&row);
                    count += 1;
                }
            }
            if (count != 0) {
                var accepted: usize = 0;
                var budget: usize = 1024;
                for (rows[0..count]) |detail| {
                    if (!try self.reserveSubjectWindowTx(detail, rows[0..accepted], policy, &budget)) break;
                    try self.deleteRetainedDetailTx(detail, policy);
                    accepted += 1;
                }
                try self.refreshDetailsTx(rows[0..accepted], policy);
                return accepted;
            }
            const sequence = competing orelse return 0;
            const candidate = try self.detailAtSequenceTx(sequence);
            const family = candidate.family orelse return error.InvalidApplicationHistoryRow;
            const subject = candidate.subject[0..candidate.subject_len];
            var total: i64 = undefined;
            var bytes: i64 = undefined;
            {
                var row = try self.statement("SELECT detail_count,evidence_bytes,candidate_sequence,earliest_sequence,earliest_evidence_sequence FROM retained_subject_summaries WHERE family=?1 AND subject=?2;");
                defer row.deinit();
                try row.int(1, family);
                try row.blob(2, subject);
                if (!try row.row() or try row.optionalSigned(2) != sequence) return error.InvalidApplicationHistoryRow;
                total = try row.signed(0);
                bytes = try row.signed(1);
                if (total > policy.max_matches and try row.signed(3) != sequence) return error.InvalidApplicationHistoryRow;
                if (total <= policy.max_matches and bytes > 16384 and try row.optionalSigned(4) != sequence) return error.InvalidApplicationHistoryRow;
            }
            if (total <= policy.max_matches and bytes <= 16384) {
                var victims: [1024]i64 = undefined;
                const n = try self.localVictimsTx(family, subject, policy, total, &victims);
                if (n == 0 or victims[0] != sequence) return error.InvalidApplicationHistoryRow;
                while (count < n and count < page and victims[count] <= fence) : (count += 1) {
                    try self.deleteRetainedDetailTx(try self.detailAtSequenceTx(victims[count]), policy);
                }
                if (count < n) try self.setLocalCandidateTx(family, subject, victims[count]);
                return count;
            }
            var next: ?i64 = sequence;
            while (count < page) {
                const selected = next orelse break;
                if (selected > fence) break;
                try self.deleteRetainedDetailTx(try self.detailAtSequenceTx(selected), policy);
                count += 1;
                var row = try self.statement("SELECT candidate_sequence FROM retained_subject_summaries WHERE family=?1 AND subject=?2;");
                defer row.deinit();
                try row.int(1, family);
                try row.blob(2, subject);
                next = if (try row.row()) try row.optionalSigned(0) else null;
            }
            try self.refreshDetailsTx(&.{candidate}, policy);
            return count;
        }

        fn prunePrefixPage(self: *Store, policy: RetentionPolicy, fence: i64, cutoff: i64, now_us: i64) Error!usize {
            var events = try self.integer("SELECT count(*) FROM confirmed_effect_events;");
            var pruned: usize = 0;
            var overloaded = false;
            var touched: [prefix_page]RetainedDetail = undefined;
            var touched_count: usize = 0;
            var budget: usize = 1024;
            while (pruned < @min(prefix_page, self.retention_page)) {
                const retained_from = blk: {
                    var stream = try self.statement("SELECT retained_from,head FROM confirmed_history_stream WHERE id=1;");
                    defer stream.deinit();
                    if (!try stream.row()) return error.HistoryGap;
                    const from = try stream.signed(0);
                    if (from > try stream.signed(1) or from > fence) return self.finishPrefixTx(policy, touched[0..touched_count], pruned, overloaded, events, now_us);
                    break :blk from;
                };
                const over = events >= history_overload_events;
                var candidate = try self.statement("SELECT e.event_id,e.confirmed_us,EXISTS(SELECT 1 FROM effect_intents p INDEXED BY effect_intents_pending WHERE p.scope_key=e.scope_key AND p.status IN(1,2)),EXISTS(SELECT 1 FROM action_targets a WHERE a.action_id=e.decision_id AND a.scope_key=e.scope_key AND a.jail=e.jail AND a.status IN(1,2,5)) FROM confirmed_history_sequence s JOIN confirmed_effect_events e ON e.event_id=s.event_id WHERE s.sequence=?1;");
                defer candidate.deinit();
                try candidate.int(1, retained_from);
                if (!try candidate.row()) return error.HistoryGap;
                const event_id = try Store.effectBlob(&candidate, 0, 32);
                if ((!over and try candidate.signed(1) > cutoff) or try candidate.signed(2) != 0 or try candidate.signed(3) != 0) break;
                {
                    var detail = try self.statement("SELECT sequence,event_id,family,subject,evidence_bytes FROM confirmed_event_details WHERE event_id=?1;");
                    defer detail.deinit();
                    try detail.blob(1, &event_id);
                    if (try detail.row()) {
                        const retained = try RetainedDetail.read(&detail);
                        if (retained.sequence != retained_from) return error.HistoryGap;
                        if (!try self.reserveSubjectWindowTx(retained, touched[0..touched_count], policy, &budget)) break;
                        try self.deleteRetainedDetailTx(retained, policy);
                        touched[touched_count] = retained;
                        touched_count += 1;
                    }
                }
                var sequence = try self.statement("DELETE FROM confirmed_history_sequence WHERE sequence=?1 AND event_id=?2;");
                defer sequence.deinit();
                try sequence.int(1, retained_from);
                try sequence.blob(2, &event_id);
                try sequence.done();
                if (self.api.changes(self.db) != 1) return error.HistoryGap;
                var event = try self.statement("DELETE FROM confirmed_effect_events WHERE event_id=?1;");
                defer event.deinit();
                try event.blob(1, &event_id);
                try event.done();
                self.deletedRows(.confirmed_effect_events);
                if (self.api.changes(self.db) != 1) return error.HistoryGap;
                try self.fault(.after_history_event_delete);
                var stream = try self.statement("UPDATE confirmed_history_stream SET retained_from=?1,revision=revision+1 WHERE id=1 AND retained_from=?2;");
                defer stream.deinit();
                try stream.int(1, retained_from + 1);
                try stream.int(2, retained_from);
                try stream.done();
                if (self.api.changes(self.db) != 1) return error.HistoryGap;
                pruned += 1;
                events -= 1;
                overloaded = overloaded or over;
            }
            return self.finishPrefixTx(policy, touched[0..touched_count], pruned, overloaded, events, now_us);
        }
        fn finishPrefixTx(self: *Store, policy: RetentionPolicy, touched: []const RetainedDetail, pruned: usize, overloaded: bool, events: i64, now_us: i64) Error!usize {
            try self.refreshDetailsTx(touched, policy);
            return self.prefixPruned(pruned, overloaded, events, now_us);
        }
        fn prefixPruned(self: *Store, pruned: usize, overloaded: bool, events: i64, now_us: i64) Error!usize {
            if (!overloaded) return pruned;
            if (self.history_overload_notice_us) |last| if (now_us -| last < overload_notice_us) return pruned;
            self.history_overload_notice_us = now_us;
            const horizon = try self.integer("SELECT coalesce(min(e.confirmed_us),0) FROM confirmed_history_stream h JOIN confirmed_history_sequence s ON s.sequence=h.retained_from JOIN confirmed_effect_events e ON e.event_id=s.event_id WHERE h.id=1;");
            std.log.warn(
                "native history: {d} confirmed events at the overload threshold; consumed history is pruned before its retention age, oldest retained confirmation at {d} us",
                .{ events, horizon },
            );
            return pruned;
        }

        fn sweepCandidatesTx(self: *Store, policy: RetentionPolicy) Error!RetentionOutcome {
            const Summary = struct { rowid: i64, family: i64, subject: [16]u8, len: usize, cost: usize };
            var summaries: [64]Summary = undefined;
            var count: usize = 0;
            const quantum = @min(summaries.len, self.retention_page);
            {
                var row = try self.statement("SELECT rowid,family,subject,detail_count,evidence_bytes FROM retained_subject_summaries WHERE rowid>?1 ORDER BY rowid LIMIT ?2;");
                defer row.deinit();
                try row.int(1, policy.sweep_cursor);
                try row.int(2, @intCast(quantum));
                while (try row.row()) {
                    if (count == summaries.len) return error.InvalidApplicationHistoryRow;
                    const total = try row.signed(3);
                    const bytes = try row.signed(4);
                    if (total <= 0 or bytes < 0) return error.InvalidApplicationHistoryRow;
                    const stored = try row.boundedBytes(2, 16);
                    summaries[count] = .{
                        .rowid = try row.signed(0),
                        .family = try row.signed(1),
                        .subject = undefined,
                        .len = stored.len,
                        .cost = if (total <= policy.max_matches and bytes <= 16384) @intCast(total) else 0,
                    };
                    @memcpy(summaries[count].subject[0..stored.len], stored);
                    count += 1;
                }
            }
            var high = policy.sweep_cursor;
            var budget: usize = 1024;
            var processed: usize = 0;
            for (summaries[0..count]) |summary| {
                if (summary.cost > budget) break;
                budget -= summary.cost;
                try self.updateCandidateTx(summary.family, summary.subject[0..summary.len], policy);
                high = summary.rowid;
                processed += 1;
            }
            const done = processed == count and count < quantum;
            var advance = try self.statement(if (done)
                "UPDATE retention_policy SET state=2,sweep_cursor=0 WHERE id=1 AND generation=?2 AND state=1 AND ?1>=0;"
            else
                "UPDATE retention_policy SET sweep_cursor=?1 WHERE id=1 AND generation=?2 AND state=1;");
            defer advance.deinit();
            try advance.int(1, high);
            try advance.int(2, policy.generation);
            try advance.done();
            if (self.api.changes(self.db) != 1) return error.InvalidApplicationHistoryRow;
            return if (done) .published else .rebuilt;
        }

        pub fn clearConfirmedRetryEvidenceTx(self: *Store, jail: []const u8, decision_id: effects.Hash) Error!void {
            var row = try self.statement("UPDATE retry_decision_details SET evidence=NULL WHERE effect_decision_id=?1 AND jail=?2 AND evidence IS NOT NULL;");
            defer row.deinit();
            try row.blob(1, &decision_id);
            try row.text(2, jail);
            try row.done();
        }
        fn advanceEvidenceCursorTx(self: *Store, subject: bool, next: ?i64) Error!void {
            var row = try self.statement(if (subject)
                "UPDATE retention_policy SET history_subject_sweep_cursor=?1 WHERE id=1;"
            else
                "UPDATE retention_policy SET retry_evidence_sweep_cursor=?1 WHERE id=1;");
            defer row.deinit();
            if (next) |value| try row.int(1, value) else try self.check(self.api.bind_null(row.ptr, 1));
            try row.done();
            if (self.api.changes(self.db) != 1) return error.InvalidApplicationHistoryRow;
        }
        fn sweepRetryEvidenceTx(self: *Store, cursor: i64, quantum: usize) Error!void {
            var ids: [32]i64 = undefined;
            var count: usize = 0;
            {
                var row = try self.statement("SELECT rowid FROM retry_decision_details WHERE rowid>?1 ORDER BY rowid LIMIT ?2;");
                defer row.deinit();
                try row.int(1, cursor);
                try row.int(2, @intCast(quantum));
                while (try row.row()) {
                    if (count == ids.len) return error.InvalidApplicationHistoryRow;
                    ids[count] = try row.signed(0);
                    count += 1;
                }
            }
            for (ids[0..count]) |id| {
                var clear = false;
                {
                    var row = try self.statement("SELECT d.jail,d.evidence,EXISTS(SELECT 1 FROM confirmed_effect_events e INDEXED BY confirmed_effect_events_decision WHERE e.jail=d.jail AND e.decision_id=d.effect_decision_id),EXISTS(SELECT 1 FROM effect_owners o INDEXED BY effect_owners_decision JOIN confirmation_markers m ON m.scope_key=o.scope_key AND m.jail=o.jail AND m.decision_id=o.decision_id WHERE o.jail=d.jail AND o.decision_id=d.effect_decision_id) FROM retry_decision_details d WHERE d.rowid=?1;");
                    defer row.deinit();
                    try row.int(1, id);
                    if (!try row.row()) return error.InvalidApplicationHistoryRow;
                    const jail = detection.Name.init(try row.boundedBytes(0, 64)) catch return error.InvalidApplicationHistoryRow;
                    if (self.api.column_type(row.ptr, 1) != 5) {
                        if (self.api.column_type(row.ptr, 1) != 3) return error.InvalidApplicationHistoryRow;
                        const evidence = try row.boundedBytes(1, retry.max_evidence_text_bytes);
                        if (evidence.len == 0 or !std.unicode.utf8ValidateSlice(evidence)) return error.InvalidApplicationHistoryRow;
                        clear = try self.effectiveHistoryLimitTx(jail.slice()) == 0 or try row.signed(2) != 0 or try row.signed(3) != 0;
                    }
                }
                if (clear) {
                    var row = try self.statement("UPDATE retry_decision_details SET evidence=NULL WHERE rowid=?1;");
                    defer row.deinit();
                    try row.int(1, id);
                    try row.done();
                    if (self.api.changes(self.db) != 1) return error.InvalidApplicationHistoryRow;
                }
            }
            try self.advanceEvidenceCursorTx(false, if (count == quantum) ids[count - 1] else null);
        }
        fn completeLegacySubjectTx(self: *Store, sequence: i64, policy: RetentionPolicy, fence: ?i64) Error!?RetainedDetail {
            var source: []u8 = undefined;
            var occurrence: []u8 = undefined;
            var evidence: ?[]u8 = null;
            var detail: RetainedDetail = undefined;
            var decided: i64 = undefined;
            var ordinal: i64 = undefined;
            var confirmed: i64 = undefined;
            var recovered_family: i64 = undefined;
            var recovered_subject: [16]u8 = undefined;
            var recovered_len: usize = undefined;
            {
                var row = try self.statement("SELECT d.sequence,d.event_id,d.family,d.subject,d.evidence_bytes,d.source,d.occurrence,d.decided_us,d.ordinal,d.evidence,d.confirmed_us,e.canonical_scope,e.scope_key,e.jail,e.confirmed_us FROM confirmed_event_details d INDEXED BY confirmed_details_sequence JOIN confirmed_effect_events e ON e.event_id=d.event_id JOIN confirmed_history_sequence h ON h.sequence=d.sequence AND h.event_id=d.event_id WHERE d.sequence=?1;");
                defer row.deinit();
                try row.int(1, sequence);
                if (!try row.row()) return error.InvalidApplicationHistoryRow;
                detail = try RetainedDetail.read(&row);
                if (detail.family != null) return null;
                if (self.api.column_type(row.ptr, 3) != 5) return error.InvalidApplicationHistoryRow;
                const jail = detection.Name.init(try row.boundedBytes(13, 64)) catch return error.InvalidApplicationHistoryRow;
                const installation = try self.readInstallation() orelse return error.InstallationRequired;
                const scope = try self.decodeStoredScope(&row, 11);
                const host = effects.Scope.fromCanonical(scope.canonical) catch return error.InvalidApplicationHistoryRow;
                if (!std.mem.eql(u8, &try host.key(installation), &try Store.effectBlob(&row, 12, 32))) return error.InvalidApplicationHistoryRow;
                if (try self.effectiveHistoryLimitTx(jail.slice()) == 0 and sequence <= (fence orelse -1)) {
                    try self.deleteRetainedDetailTx(detail, policy);
                    return null;
                }
                recovered_family = @intFromEnum(host.canonical.subject.family);
                recovered_len = if (recovered_family == 4) 4 else 16;
                recovered_subject = host.canonical.subject.address;
                decided = try row.signed(7);
                ordinal = try row.signed(8);
                confirmed = try row.signed(10);
                if (ordinal <= 0 or decided > confirmed or confirmed != try row.signed(14)) return error.InvalidApplicationHistoryRow;
                if (self.api.column_type(row.ptr, 5) != 3 or self.api.column_type(row.ptr, 6) != 3) return error.InvalidApplicationHistoryRow;
                const stored_source = try row.boundedBytes(5, Limits.source_bytes);
                const stored_occurrence = try row.boundedBytes(6, Limits.source_bytes);
                if (stored_source.len == 0 or stored_occurrence.len == 0) return error.InvalidApplicationHistoryRow;
                source = self.allocator.dupe(u8, stored_source) catch return error.OutOfMemory;
                errdefer self.allocator.free(source);
                occurrence = self.allocator.dupe(u8, stored_occurrence) catch return error.OutOfMemory;
                errdefer self.allocator.free(occurrence);
                if (self.api.column_type(row.ptr, 9) != 5) {
                    if (self.api.column_type(row.ptr, 9) != 3) return error.InvalidApplicationHistoryRow;
                    const stored_evidence = try row.boundedBytes(9, retry.max_evidence_text_bytes);
                    if (stored_evidence.len == 0 or !std.unicode.utf8ValidateSlice(stored_evidence) or detail.bytes != @as(
                        i64,
                        @intCast(stored_evidence.len),
                    )) return error.InvalidApplicationHistoryRow;
                    evidence = self.allocator.dupe(u8, stored_evidence) catch return error.OutOfMemory;
                } else if (detail.bytes != null) return error.InvalidApplicationHistoryRow;
            }
            defer self.allocator.free(source);
            defer self.allocator.free(occurrence);
            defer if (evidence) |value| self.allocator.free(value);
            try self.deleteRetainedDetailTx(detail, policy);
            {
                var row = try self.statement("INSERT INTO confirmed_event_details(event_id,source,occurrence,decided_us,ordinal,evidence,family,subject,sequence,confirmed_us,evidence_bytes) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11);");
                defer row.deinit();
                try row.blob(1, &detail.event_id);
                try row.text(2, source);
                try row.text(3, occurrence);
                try row.int(4, decided);
                try row.int(5, ordinal);
                if (evidence) |value| try row.text(6, value);
                try row.int(7, recovered_family);
                try row.blob(8, recovered_subject[0..recovered_len]);
                try row.int(9, sequence);
                try row.int(10, confirmed);
                if (detail.bytes) |value| try row.int(11, value);
                try row.done();
                self.insertedRows(.confirmed_event_details, 1);
            }
            try self.accountRetainedDetailTx(recovered_family, recovered_subject[0..recovered_len], detail.bytes, sequence, false);
            detail.family = recovered_family;
            detail.subject = recovered_subject;
            detail.subject_len = recovered_len;
            return detail;
        }
        fn sweepLegacySubjectsTx(self: *Store, cursor: i64, quantum: usize, policy: RetentionPolicy, fence: ?i64) Error!void {
            var ids: [32]i64 = undefined;
            var count: usize = 0;
            {
                var row = try self.statement("SELECT sequence FROM confirmed_event_details INDEXED BY confirmed_details_sequence WHERE sequence>?1 ORDER BY sequence LIMIT ?2;");
                defer row.deinit();
                try row.int(1, cursor);
                try row.int(2, @intCast(quantum));
                while (try row.row()) {
                    if (count == ids.len) return error.InvalidApplicationHistoryRow;
                    ids[count] = try row.signed(0);
                    count += 1;
                }
            }
            var repaired: [32]RetainedDetail = undefined;
            var repaired_count: usize = 0;
            for (ids[0..count]) |id| if (try self.completeLegacySubjectTx(id, policy, fence)) |detail| {
                repaired[repaired_count] = detail;
                repaired_count += 1;
            };
            try self.refreshDetailsTx(repaired[0..repaired_count], policy);
            try self.advanceEvidenceCursorTx(true, if (count == quantum) ids[count - 1] else null);
        }

        fn hasRetentionCandidateTx(self: *Store) Error!bool {
            var row = try self.statement("SELECT 1 FROM retained_subject_summaries INDEXED BY retained_subject_candidates WHERE candidate_sequence IS NOT NULL LIMIT 1;");
            defer row.deinit();
            return row.row();
        }
        pub fn historyRetentionStep(self: *Store, policy: HistoryRetention, now_us: i64) Error!RetentionOutcome {
            try policy.validate();
            try self.beginWrite();
            errdefer self.rollback();
            const outcome = self.historyRetentionTx(policy, now_us) catch |failure| {
                if (failure != error.Interrupted) return failure;
                // Why: An interrupted step leaves nothing to commit, so the transaction is rolled back and the next page halved instead.
                return self.yieldRetention();
            };
            try self.fault(.before_history_retention_commit);
            try self.commitTransaction();
            self.retention_aux_turn = if (self.retention_aux_turn == 2) 0 else self.retention_aux_turn + 1;
            if (outcome != .idle and outcome != .yielded) self.retention_page = @min(store.max_retention_page, self.retention_page *| 2);
            return outcome;
        }
        fn historyRetentionTx(self: *Store, policy: HistoryRetention, now_us: i64) Error!RetentionOutcome {
            const schema = try self.integer("PRAGMA user_version;");
            if (schema < store.load_repair_schema) return error.MaintenanceStorageRequired;
            if (schema > latest_schema) return error.UnsupportedSchema;
            var current = try self.readRetentionPolicy();
            if (current.max_matches != policy.max_matches) {
                _ = try self.beginRetentionGenerationTx(policy.max_matches);
                current = try self.readRetentionPolicy();
            }
            const fence = try self.historyFence();
            const quantum = @min(@as(usize, 32), self.retention_page);
            if (self.retention_aux_turn == 0) if (current.subject_cursor) |cursor| {
                try self.sweepLegacySubjectsTx(cursor, quantum, current, fence);
                return .rebuilt;
            };
            if (self.retention_aux_turn == 1) if (current.retry_cursor) |cursor| {
                try self.sweepRetryEvidenceTx(cursor, quantum);
                return .rebuilt;
            };
            if (!current.published) return self.sweepCandidatesTx(current);
            const consumed = fence orelse return if (current.subject_cursor != null or current.retry_cursor != null or try self.hasRetentionCandidateTx()) .yielded else .idle;
            const cutoff = std.math.sub(i64, now_us, policy.age_us) catch std.math.minInt(i64);
            if (try self.deleteDetailPage(current, consumed, cutoff, self.retention_page) != 0) return .details;
            if (try self.prunePrefixPage(current, consumed, cutoff, now_us) != 0) return .prefix;
            return if (current.subject_cursor != null or current.retry_cursor != null or try self.hasRetentionCandidateTx()) .yielded else .idle;
        }
        fn yieldRetention(self: *Store) Error!RetentionOutcome {
            const prior_rollback = self.rollback_error_code;
            self.rollback_error_code = null;
            self.rollback();
            const clean = !self.reopen_required and self.rollback_error_code == null and self.api.get_autocommit(self.db) != 0;
            if (self.rollback_error_code == null) self.rollback_error_code = prior_rollback;
            if (!clean) return error.Interrupted;
            if (self.retention_page <= 1) return error.MaintenanceWorkExhausted;
            self.retention_page /= 2;
            return .yielded;
        }

        pub fn shedHistoryPage(self: *Store, kind: enum { details, prefix }, now_us: i64) Error!?usize {
            try self.beginClassWrite(.reclamation);
            errdefer self.rollback();
            const current = try self.readRetentionPolicy();
            const fence = if (current.published) try self.historyFence() else null;
            const rows = if (fence) |consumed| (switch (kind) {
                .details => self.deleteDetailPage(current, consumed, now_us, self.retention_page),
                .prefix => self.prunePrefixPage(current, consumed, now_us, now_us),
            }) catch |failure| {
                if (failure != error.Interrupted) return failure;
                _ = try self.yieldRetention();
                return null;
            } else 0;
            try self.commitTransaction();
            return rows;
        }
    };
}
