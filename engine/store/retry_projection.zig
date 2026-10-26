// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const build_options = @import("build_options");
const diag = @import("../core/diag.zig");
const detection = @import("../core/native_detection_record.zig");
const retry = @import("../core/native_retry.zig");
const store = @import("store.zig");
const Error = store.Error;
const Stmt = store.Stmt;
const max_jails = 64;
const max_page = 256;

pub fn Methods(comptime Store: type) type {
    return struct {
        pub const RetryAdmissionProgress = enum { ready, progressed };
        pub const RetryPoolSample = struct { occupancy: Store.PoolOccupancy, as_of_us: i64 };
        pub const RetryJailSummary = struct { decisions: u64, revision: u64 };
        pub const RetryAdmissionVictim = struct { jail: detection.Name, subject: detection.Subject, last_processed_us: i64 };
        const Cursor = struct { jail_id: u8, subject: detection.Subject };
        const Meta = struct { total: i64, live: i64, as_of_us: i64, target_us: ?i64, ready: bool, cursor: ?Cursor };
        const Jail = struct { id: u8, name: detection.Name };
        const Narrow = struct { last_processed_us: i64, lease: retry.Lease };
        const Head = struct { jail_id: u8, victim: ?RetryAdmissionVictim };

        fn projectionInteger(row: *Stmt, column: c_int) Error!i64 {
            if (row.store.api.column_type(row.ptr, column) != 1) return error.InvalidRetryState;
            return row.signed(column);
        }
        fn projectionOptionalInteger(row: *Stmt, column: c_int) Error!?i64 {
            if (row.store.api.column_type(row.ptr, column) == 5) return null;
            return try projectionInteger(row, column);
        }
        fn projectionId(value: i64) Error!u8 {
            if (value < 0 or value >= max_jails) return error.InvalidRetryState;
            return @intCast(value);
        }
        fn projectionName(row: *Stmt, column: c_int) Error!detection.Name {
            if (row.store.api.column_type(row.ptr, column) != 3) return error.InvalidRetryState;
            return detection.Name.init(try row.boundedBytes(column, 64)) catch error.InvalidRetryState;
        }
        fn projectionNarrow(row: *Stmt, last_column: c_int) Error!Narrow {
            const last = try projectionInteger(row, last_column);
            const kind = try projectionInteger(row, last_column + 1);
            const deadline = try projectionOptionalInteger(row, last_column + 2);
            const lease: retry.Lease = switch (kind) {
                0 => if (deadline == null) .absent else return error.InvalidRetryState,
                1 => .{ .finite = deadline orelse return error.InvalidRetryState },
                2 => if (deadline == null) .permanent else return error.InvalidRetryState,
                else => return error.InvalidRetryState,
            };
            if (deadline) |value| if (value <= last) return error.InvalidRetryState;
            return .{ .last_processed_us = last, .lease = lease };
        }
        fn projectionMeta(self: *Store) Error!Meta {
            if (self.reopen_required) return error.ReopenRequired;
            if (!self.retry_projection_initialized) return error.RetryEligibilityPending;
            var row = try self.statement("SELECT total,live,as_of_us,target_us,ready,cursor_jail_id,cursor_family,cursor_subject FROM temp.retry_admission_meta WHERE id=1;");
            defer row.deinit();
            if (!try row.row()) return error.InvalidRetryState;
            const total = try projectionInteger(&row, 0);
            const live = try projectionInteger(&row, 1);
            const as_of = try projectionInteger(&row, 2);
            const target = try projectionOptionalInteger(&row, 3);
            const ready = try projectionInteger(&row, 4);
            if (total < 0 or total > 2 * @as(i64, retry.max_pool_subjects) or live < 0 or live > total or (ready != 0 and ready != 1)) return error.InvalidRetryState;
            if (target) |value| if (value < as_of or ready == 0) return error.InvalidRetryState;
            var cursor: ?Cursor = null;
            if (try projectionOptionalInteger(&row, 5)) |id| {
                cursor = .{ .jail_id = try projectionId(id), .subject = try self.decodeRetrySubject(&row, 6, 7) };
            } else if (self.api.column_type(row.ptr, 6) != 5 or self.api.column_type(row.ptr, 7) != 5) return error.InvalidRetryState;
            return .{ .total = total, .live = live, .as_of_us = as_of, .target_us = target, .ready = ready == 1, .cursor = cursor };
        }
        fn projectionJail(self: *Store, jail: []const u8) Error!u8 {
            var row = try self.statement("SELECT jail_id FROM temp.retry_publication_jails WHERE jail=?1;");
            defer row.deinit();
            try row.text(1, jail);
            if (!try row.row()) return error.RetryAdmissionRequired;
            return projectionId(try projectionInteger(&row, 0));
        }
        fn projectionJailName(self: *Store, id: u8) Error!detection.Name {
            var row = try self.statement("SELECT jail FROM temp.retry_publication_jails WHERE jail_id=?1;");
            defer row.deinit();
            try row.int(1, id);
            if (!try row.row()) return error.InvalidRetryState;
            return projectionName(&row, 0);
        }
        fn projectionClock(self: *Store, now_us: i64) Error!void {
            if (try self.readRetryClock()) |floor| if (now_us < floor) return error.ReceiptClockReversed;
        }
        fn projectionHint(self: *Store, now_us: i64) void {
            if (self.retry_admission_target_hint == null) self.retry_admission_target_hint = now_us;
        }
        fn projectionReadStart(self: *Store) Error!void {
            if (self.reopen_required) return error.ReopenRequired;
            if (self.startup_admission or self.api.get_autocommit(self.db) == 0) return error.DatabaseFailure;
            if (!self.retry_projection_initialized) return error.RetryEligibilityPending;
            try self.beginRead();
        }
        fn projectionSummaryTx(self: *Store, jail: []const u8) Error!RetryJailSummary {
            var row = try self.statement("SELECT decisions,revision FROM temp.retry_publication_jails WHERE jail=?1;");
            defer row.deinit();
            try row.text(1, jail);
            if (!try row.row()) return error.RetryAdmissionRequired;
            if (self.api.column_type(row.ptr, 0) != 4) return error.InvalidRetryState;
            const bytes = try row.bytes(0);
            const revision = try projectionInteger(&row, 1);
            if (bytes.len != 8 or revision <= 0) return error.InvalidRetryState;
            return .{ .decisions = std.mem.readInt(u64, bytes[0..8], .little), .revision = @intCast(revision) };
        }
        fn projectionWriteSummary(self: *Store, jail: []const u8, value: RetryJailSummary) Error!void {
            var bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &bytes, value.decisions, .little);
            var row = try self.statement("UPDATE temp.retry_publication_jails SET decisions=?2,revision=?3 WHERE jail=?1;");
            defer row.deinit();
            try row.text(1, jail);
            try row.blob(2, &bytes);
            try row.int(3, @intCast(value.revision));
            try row.done();
            if (self.api.changes(self.db) != 1) return error.InvalidRetryState;
        }
        fn projectionInsertJail(self: *Store, jail: []const u8, id: u8, total: u64) Error!void {
            var bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &bytes, total, .little);
            var row = try self.statement("INSERT INTO temp.retry_publication_jails VALUES(?1,?2,?3,1);");
            defer row.deinit();
            try row.int(1, id);
            try row.text(2, jail);
            try row.blob(3, &bytes);
            try row.done();
        }
        pub fn prepareRetryAdmissionView(self: *Store, names: []const []const u8, now_us: i64) Error!void {
            if (self.reopen_required) return error.ReopenRequired;
            if (self.retry_projection_initialized or self.startup_admission or self.api.get_autocommit(self.db) == 0) return error.DatabaseFailure;
            if (self.schema_version != store.latest_schema) return error.RetryStorageRequired;
            if (names.len > max_jails) return error.RetryCapacity;
            for (names, 0..) |name, i| {
                _ = detection.Name.init(name) catch return error.InvalidRecord;
                for (names[0..i]) |prior| if (std.mem.eql(u8, prior, name)) return error.InvalidRecord;
            }
            try self.projectionClock(now_us);
            try self.exec("PRAGMA temp_store=MEMORY;");
            try self.beginWrite();
            errdefer self.rollback();
            try self.exec(
                \\CREATE TEMP TABLE retry_publication_jails(jail_id INTEGER PRIMARY KEY CHECK(jail_id BETWEEN 0 AND 63),jail TEXT NOT NULL UNIQUE,decisions BLOB NOT NULL CHECK(typeof(decisions)='blob' AND length(decisions)=8),revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision>0));
                \\CREATE TEMP TABLE retry_admission_rows(jail_id INTEGER NOT NULL,family INTEGER NOT NULL,subject BLOB NOT NULL,last_processed_us INTEGER NOT NULL,lease_kind INTEGER NOT NULL,deadline_us INTEGER,live INTEGER NOT NULL,PRIMARY KEY(jail_id,family,subject)) WITHOUT ROWID;
                \\CREATE INDEX temp.retry_admission_deadlines ON retry_admission_rows(deadline_us,jail_id,family,subject) WHERE live=1 AND lease_kind=1;
                \\CREATE INDEX temp.retry_admission_class ON retry_admission_rows(jail_id,live,last_processed_us,family,subject);
                \\CREATE TEMP TABLE retry_admission_meta(id INTEGER PRIMARY KEY,total INTEGER NOT NULL,live INTEGER NOT NULL,as_of_us INTEGER NOT NULL,target_us INTEGER,ready INTEGER NOT NULL,cursor_jail_id INTEGER,cursor_family INTEGER,cursor_subject BLOB);
                \\CREATE TEMP TRIGGER projection_ai AFTER INSERT ON retry_admission_rows BEGIN UPDATE retry_admission_meta SET total=total+1,live=live+new.live; END;
                \\CREATE TEMP TRIGGER projection_ad AFTER DELETE ON retry_admission_rows BEGIN UPDATE retry_admission_meta SET total=total-1,live=live-old.live; END;
                \\CREATE TEMP TRIGGER projection_au AFTER UPDATE ON retry_admission_rows BEGIN UPDATE retry_admission_meta SET live=live+new.live-old.live; END;
            );
            var meta = try self.statement("INSERT INTO temp.retry_admission_meta VALUES(1,0,0,?1,NULL,0,NULL,NULL,NULL);");
            defer meta.deinit();
            try meta.int(1, now_us);
            try meta.done();
            for (names, 0..) |name, i| try self.projectionInsertJail(name, @intCast(i), try self.retiredTotal(name));
            try self.commitTransaction();
            self.retry_projection_initialized = true;
            self.retry_admission_target_hint = null;
        }
        pub fn requireRetryProjectionMutationTx(self: *Store) Error!void {
            if (self.reopen_required) return error.ReopenRequired;
            if (self.api.get_autocommit(self.db) != 0) return error.DatabaseFailure;
            if (!self.retry_projection_initialized) return;
            if (!(try self.projectionMeta()).ready) return error.RetryEligibilityPending;
        }
        pub fn admitRetryProjectionJailTx(self: *Store, jail: []const u8) Error!void {
            try self.requireRetryProjectionMutationTx();
            if (!self.retry_projection_initialized) return;
            _ = detection.Name.init(jail) catch return error.InvalidRecord;
            var used = [_]bool{false} ** max_jails;
            var rows = try self.statement("SELECT jail_id,jail FROM temp.retry_publication_jails ORDER BY jail_id;");
            defer rows.deinit();
            while (try rows.row()) {
                const id = try projectionId(try projectionInteger(&rows, 0));
                const name = try projectionName(&rows, 1);
                if (std.mem.eql(u8, name.slice(), jail)) return;
                used[id] = true;
            }
            const id: u8 = for (used, 0..) |present, i| {
                if (!present) break @intCast(i);
            } else return error.RetryCapacity;
            var prior = try self.statement("SELECT 1 FROM retry_states WHERE jail=?1 UNION ALL SELECT 1 FROM retry_retired WHERE jail=?1 UNION ALL SELECT 1 FROM retry_retired_totals WHERE jail=?1 LIMIT 1;");
            defer prior.deinit();
            try prior.text(1, jail);
            if (try prior.row()) return error.InvalidRetryState;
            try self.projectionInsertJail(jail, id, 0);
        }
        pub fn changeRetryJailSummaryTx(self: *Store, jail: []const u8, removed: u64, added: u64) Error!void {
            try self.requireRetryProjectionMutationTx();
            if (!self.retry_projection_initialized) return;
            var summary = try self.projectionSummaryTx(jail);
            summary.decisions = std.math.sub(u64, summary.decisions, removed) catch return error.InvalidRetryState;
            summary.decisions = std.math.add(u64, summary.decisions, added) catch return error.StorageLimit;
            if (summary.revision == std.math.maxInt(i64)) return error.StorageLimit;
            summary.revision += 1;
            try self.projectionWriteSummary(jail, summary);
        }
        pub fn retryJailSummary(self: *Store, jail: []const u8) Error!RetryJailSummary {
            try self.projectionReadStart();
            errdefer self.rollback();
            if (!(try self.projectionMeta()).ready) return error.RetryEligibilityPending;
            const result = try self.projectionSummaryTx(jail);
            try self.commitTransaction();
            return result;
        }
        fn projectionPut(self: *Store, id: u8, subject: *const detection.Subject, narrow: Narrow, at_us: i64) Error!void {
            var row = try self.statement("INSERT INTO temp.retry_admission_rows VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(jail_id,family,subject) DO UPDATE SET last_processed_us=excluded.last_processed_us,lease_kind=excluded.lease_kind,deadline_us=excluded.deadline_us,live=excluded.live;");
            defer row.deinit();
            try row.int(1, id);
            try Store.bindSubjectAt(&row, subject, 2);
            try row.int(4, narrow.last_processed_us);
            try row.int(5, @intFromEnum(narrow.lease));
            if (narrow.lease == .finite) try row.int(6, narrow.lease.finite);
            try row.int(7, @intFromBool(narrow.lease.live(at_us)));
            try row.done();
        }
        pub fn syncRetryProjectionRowTx(self: *Store, jail: []const u8, subject: *const detection.Subject) Error!void {
            try self.requireRetryProjectionMutationTx();
            if (!self.retry_projection_initialized) return;
            const meta = try self.projectionMeta();
            const id = try self.projectionJail(jail);
            var row = try self.statement("SELECT last_processed_us,lease_kind,deadline_us FROM retry_states WHERE jail=?1 AND family=?2 AND subject=?3;");
            defer row.deinit();
            try row.text(1, jail);
            try Store.bindSubject(&row, subject);
            if (!try row.row()) return error.InvalidRetryState;
            try self.projectionPut(id, subject, try projectionNarrow(&row, 0), meta.target_us orelse meta.as_of_us);
            _ = try self.projectionMeta();
        }
        pub fn removeRetryProjectionRowTx(self: *Store, jail: []const u8, subject: *const detection.Subject) Error!void {
            try self.requireRetryProjectionMutationTx();
            if (!self.retry_projection_initialized) return;
            const id = try self.projectionJail(jail);
            var row = try self.statement("DELETE FROM temp.retry_admission_rows WHERE jail_id=?1 AND family=?2 AND subject=?3;");
            defer row.deinit();
            try row.int(1, id);
            try Store.bindSubjectAt(&row, subject, 2);
            try row.done();
            if (self.api.changes(self.db) != 1) return error.InvalidRetryState;
            _ = try self.projectionMeta();
        }
        pub fn retireRetryProjectionJailTx(self: *Store, jail: []const u8) Error!void {
            try self.requireRetryProjectionMutationTx();
            if (!self.retry_projection_initialized) return;
            const id = self.projectionJail(jail) catch |failure| {
                if (failure == error.RetryAdmissionRequired) return;
                return failure;
            };
            // Member rows were removed by committed retirement pages.
            var members = try self.statement("SELECT 1 FROM temp.retry_admission_rows WHERE jail_id=?1 LIMIT 1;");
            defer members.deinit();
            try members.int(1, id);
            if (try members.row() or (try self.projectionSummaryTx(jail)).decisions != 0) return error.InvalidRetryState;
            var row = try self.statement("DELETE FROM temp.retry_publication_jails WHERE jail_id=?1;");
            defer row.deinit();
            try row.int(1, id);
            try row.done();
            if (self.api.changes(self.db) != 1) return error.InvalidRetryState;
            _ = try self.projectionMeta();
        }
        fn projectionCopyPage(self: *Store, initial: Meta, max_rows: u16) Error!bool {
            var cursor = initial.cursor;
            var contributions = [_]u64{0} ** max_jails;
            var touched = [_]bool{false} ** max_jails;
            const floor = try self.readRetryClock();
            var examined: u16 = 0;
            var complete = false;
            while (examined < max_rows) : (examined += 1) {
                const after_name: ?detection.Name = if (cursor) |after| try self.projectionJailName(after.jail_id) else null;
                var row = try self.statement(if (cursor == null)
                    "SELECT jail,family,subject,last_processed_us,lease_kind,deadline_us,decisions FROM retry_states ORDER BY jail,family,subject LIMIT 1;"
                else
                    "SELECT jail,family,subject,last_processed_us,lease_kind,deadline_us,decisions FROM retry_states WHERE (jail,family,subject)>(?1,?2,?3) ORDER BY jail,family,subject LIMIT 1;");
                defer row.deinit();
                if (after_name) |*previous_name| {
                    try row.text(1, previous_name.slice());
                    try Store.bindSubjectAt(&row, &cursor.?.subject, 2);
                }
                if (!try row.row()) {
                    complete = true;
                    break;
                }
                const name = try projectionName(&row, 0);
                const subject = try self.decodeRetrySubject(&row, 1, 2);
                const narrow = try projectionNarrow(&row, 3);
                const decisions = try projectionInteger(&row, 6);
                if (decisions < 0 or narrow.last_processed_us > (floor orelse return error.InvalidRetryState) or (narrow.lease != .absent and decisions == 0)) return error.InvalidRetryState;
                const id = self.projectionJail(name.slice()) catch |failure| return if (failure == error.RetryAdmissionRequired) error.InvalidRetryState else failure;
                try self.projectionPut(id, &subject, narrow, initial.as_of_us);
                contributions[id] = std.math.add(u64, contributions[id], @intCast(decisions)) catch return error.InvalidRetryState;
                touched[id] = true;
                cursor = .{ .jail_id = id, .subject = subject };
            }
            for (touched, 0..) |changed, i| if (changed) {
                const name = try self.projectionJailName(@intCast(i));
                var summary = try self.projectionSummaryTx(name.slice());
                summary.decisions = std.math.add(u64, summary.decisions, contributions[i]) catch return error.InvalidRetryState;
                try self.projectionWriteSummary(name.slice(), summary);
            };
            var update = try self.statement("UPDATE temp.retry_admission_meta SET ready=?1,cursor_jail_id=?2,cursor_family=?3,cursor_subject=?4 WHERE id=1;");
            defer update.deinit();
            try update.int(1, @intFromBool(complete));
            if (cursor) |*last| {
                try update.int(2, last.jail_id);
                try Store.bindSubjectAt(&update, &last.subject, 3);
            }
            try update.done();
            _ = try self.projectionMeta();
            return complete;
        }
        fn projectionFirstDeadline(self: *Store) Error!?i64 {
            var row = try self.statement("SELECT deadline_us FROM temp.retry_admission_rows WHERE live=1 AND lease_kind=1 ORDER BY deadline_us,jail_id,family,subject LIMIT 1;");
            defer row.deinit();
            return if (try row.row()) try projectionInteger(&row, 0) else null;
        }
        fn projectionExact(self: *Store, meta: Meta, now_us: i64) Error!bool {
            if (!meta.ready or meta.target_us != null or now_us < meta.as_of_us) return false;
            const deadline = try self.projectionFirstDeadline();
            return deadline == null or deadline.? > now_us;
        }
        fn projectionSetTarget(self: *Store, target: i64) Error!void {
            var row = try self.statement("UPDATE temp.retry_admission_meta SET target_us=?1 WHERE id=1;");
            defer row.deinit();
            try row.int(1, target);
            try row.done();
        }
        fn projectionFinishTime(self: *Store, target: i64) Error!void {
            var row = try self.statement("UPDATE temp.retry_admission_meta SET as_of_us=?1,target_us=NULL WHERE id=1;");
            defer row.deinit();
            try row.int(1, target);
            try row.done();
        }
        fn projectionClockPage(self: *Store, target: i64, remaining: *u16) Error!bool {
            while (remaining.* != 0) {
                var row = try self.statement("SELECT jail_id,family,subject FROM temp.retry_admission_rows WHERE live=1 AND lease_kind=1 AND deadline_us<=?1 ORDER BY deadline_us,jail_id,family,subject LIMIT 1;");
                defer row.deinit();
                try row.int(1, target);
                if (!try row.row()) {
                    try self.projectionFinishTime(target);
                    return true;
                }
                const id = try projectionId(try projectionInteger(&row, 0));
                const subject = try self.decodeRetrySubject(&row, 1, 2);
                remaining.* -= 1;
                var update = try self.statement("UPDATE temp.retry_admission_rows SET live=0 WHERE jail_id=?1 AND family=?2 AND subject=?3 AND live=1;");
                defer update.deinit();
                try update.int(1, id);
                try Store.bindSubjectAt(&update, &subject, 2);
                try update.done();
                if (self.api.changes(self.db) != 1) return error.InvalidRetryState;
            }
            return false;
        }
        pub fn retryAdmissionStep(self: *Store, max_rows: u16) Error!RetryAdmissionProgress {
            if (max_rows == 0 or max_rows > max_page) return error.InvalidRetryState;
            if (self.startup_admission or self.api.get_autocommit(self.db) == 0) return error.DatabaseFailure;
            if (!self.retry_projection_initialized) return error.RetryEligibilityPending;
            try self.beginWrite();
            errdefer self.rollback();
            const meta = try self.projectionMeta();
            var complete: bool = undefined;
            if (!meta.ready) {
                complete = try self.projectionCopyPage(meta, max_rows);
            } else if (meta.target_us orelse self.retry_admission_target_hint) |target| {
                if (target <= meta.as_of_us and meta.target_us == null) {
                    complete = true;
                } else {
                    if (meta.target_us == null) try self.projectionSetTarget(target);
                    var remaining = max_rows;
                    complete = try self.projectionClockPage(target, &remaining);
                }
            } else complete = true;
            const final = try self.projectionMeta();
            try self.commitTransaction();
            if (comptime build_options.diag) if (!meta.ready or meta.target_us != null or (self.retry_admission_target_hint != null and self.retry_admission_target_hint.? > meta.as_of_us)) diag.count(.retry_projection_pages, 1);
            if (self.retry_admission_target_hint) |hint| if (final.ready and hint <= final.as_of_us) {
                self.retry_admission_target_hint = null;
            };
            if (self.retry_admission_target_hint != null) complete = false;
            return if (complete) .ready else .progressed;
        }
        pub fn requireRetryAdmissionTimeTx(self: *Store, now_us: i64) Error!void {
            errdefer |failure| if (comptime build_options.diag) {
                if (failure == error.RetryEligibilityPending) diag.count(.retry_projection_pending, 1);
            };
            if (self.reopen_required) return error.ReopenRequired;
            if (self.api.get_autocommit(self.db) != 0) return error.DatabaseFailure;
            try self.projectionClock(now_us);
            if (!self.retry_projection_initialized) {
                self.projectionHint(now_us);
                return error.RetryEligibilityPending;
            }
            var meta = try self.projectionMeta();
            if (!meta.ready or now_us < (meta.target_us orelse meta.as_of_us)) {
                self.projectionHint(now_us);
                return error.RetryEligibilityPending;
            }
            while (true) {
                if (try self.projectionExact(meta, now_us)) {
                    try self.projectionFinishTime(now_us);
                    return;
                }
                const target = meta.target_us orelse blk: {
                    const hint = self.retry_admission_target_hint;
                    const chosen = if (hint != null and hint.? > meta.as_of_us) hint.? else now_us;
                    if (chosen > now_us) return error.RetryEligibilityPending;
                    try self.projectionSetTarget(chosen);
                    break :blk chosen;
                };
                if (!try self.projectionClockPage(target, &self.retry_admission_work_left)) {
                    self.projectionHint(now_us);
                    return error.RetryEligibilityPending;
                }
                meta = try self.projectionMeta();
            }
        }
        pub fn retryAdmissionCountsTx(self: *Store) Error!struct { total: i64, live: i64 } {
            const meta = try self.projectionMeta();
            if (!meta.ready or meta.target_us != null) return error.RetryEligibilityPending;
            return .{ .total = meta.total, .live = meta.live };
        }
        pub fn retryPoolOccupancy(self: *Store, now_us: i64) Error!?RetryPoolSample {
            if (self.reopen_required) return error.ReopenRequired;
            if (!self.retry_projection_initialized) {
                self.projectionHint(now_us);
                return null;
            }
            try self.projectionReadStart();
            errdefer self.rollback();
            try self.projectionClock(now_us);
            const meta = try self.projectionMeta();
            const exact = try self.projectionExact(meta, now_us);
            try self.commitTransaction();
            if (!exact) {
                self.projectionHint(now_us);
                return null;
            }
            return .{ .occupancy = .{ .tracked = @intCast(meta.total - meta.live), .banned = @intCast(meta.live), .tracking_limit = retry.max_pool_subjects, .ban_limit = retry.max_pool_subjects }, .as_of_us = now_us };
        }
        fn subjectLess(a: detection.Subject, b: detection.Subject) bool {
            if (a == .v4 and b == .v6) return true;
            if (a == .v6 and b == .v4) return false;
            return if (a == .v4) std.mem.order(u8, &a.v4, &b.v4) == .lt else std.mem.order(u8, &a.v6, &b.v6) == .lt;
        }
        const LiveCursor = struct { last_processed_us: i64, subject: detection.Subject };
        const LivePage = struct { count: usize, last: ?LiveCursor };
        fn projectionLivePage(self: *Store, jail: []const u8, now_us: i64, after: ?LiveCursor, output: []Store.ActiveDecision) Error!LivePage {
            try self.projectionReadStart();
            errdefer self.rollback();
            try self.projectionClock(now_us);
            if (!try self.projectionExact(try self.projectionMeta(), now_us)) {
                self.projectionHint(now_us);
                return error.RetryEligibilityPending;
            }
            const id = try self.projectionJail(jail);
            var row = try self.statement(if (after == null)
                "SELECT family,subject,last_processed_us,lease_kind,deadline_us FROM temp.retry_admission_rows WHERE jail_id=?1 AND live=1 ORDER BY last_processed_us,family,subject LIMIT ?2;"
            else
                "SELECT family,subject,last_processed_us,lease_kind,deadline_us FROM temp.retry_admission_rows WHERE jail_id=?1 AND live=1 AND (last_processed_us,family,subject)>(?3,?4,?5) ORDER BY last_processed_us,family,subject LIMIT ?2;");
            defer row.deinit();
            try row.int(1, id);
            try row.int(2, @intCast(output.len));
            if (after) |*previous| {
                try row.int(3, previous.last_processed_us);
                try Store.bindSubjectAt(&row, &previous.subject, 4);
            }
            var count: usize = 0;
            var last: ?LiveCursor = null;
            while (try row.row()) {
                if (count == output.len) return error.InvalidRetryState;
                const subject = try self.decodeRetrySubject(&row, 0, 1);
                const narrow = try projectionNarrow(&row, 2);
                if (!narrow.lease.live(now_us)) return error.InvalidRetryState;
                var main = try self.statement("SELECT decisions FROM retry_states WHERE jail=?1 AND family=?2 AND subject=?3;");
                defer main.deinit();
                try main.text(1, jail);
                try Store.bindSubject(&main, &subject);
                if (!try main.row()) return error.InvalidRetryState;
                const ordinal = try projectionInteger(&main, 0);
                if (ordinal <= 0) return error.InvalidRetryState;
                output[count] = .{ .subject = subject, .lease = narrow.lease, .ordinal = @intCast(ordinal) };
                last = .{ .last_processed_us = narrow.last_processed_us, .subject = subject };
                count += 1;
            }
            try self.commitTransaction();
            return .{ .count = count, .last = last };
        }
        pub fn retryLiveDecisions(self: *Store, jail: []const u8, now_us: i64, output: []Store.ActiveDecision) Error!usize {
            if (comptime build_options.diag) diag.count(.retry_live_reads, 1);
            var count: usize = 0;
            var after: ?LiveCursor = null;
            // Synchronous worker-only pages cannot interleave another Store mutation.
            while (true) {
                if (count == output.len) {
                    var probe: [1]Store.ActiveDecision = undefined;
                    if ((try self.projectionLivePage(jail, now_us, after, &probe)).count != 0) return error.RetryCapacity;
                    break;
                }
                const want = @min(max_page, output.len - count);
                const page = try self.projectionLivePage(jail, now_us, after, output[count..][0..want]);
                count += page.count;
                if (page.count < want) break;
                after = page.last;
            }
            std.mem.sort(Store.ActiveDecision, output[0..count], {}, struct {
                fn less(_: void, a: Store.ActiveDecision, b: Store.ActiveDecision) bool {
                    return subjectLess(a.subject, b.subject);
                }
            }.less);
            return count;
        }
        fn projectionHead(self: *Store, jail: Jail, after: ?RetryAdmissionVictim) Error!?RetryAdmissionVictim {
            var row = try self.statement(if (after == null)
                "SELECT family,subject,last_processed_us FROM temp.retry_admission_rows WHERE jail_id=?1 AND live=0 ORDER BY last_processed_us,family,subject LIMIT 1;"
            else
                "SELECT family,subject,last_processed_us FROM temp.retry_admission_rows WHERE jail_id=?1 AND live=0 AND (last_processed_us,family,subject)>(?2,?3,?4) ORDER BY last_processed_us,family,subject LIMIT 1;");
            defer row.deinit();
            try row.int(1, jail.id);
            if (after) |*last| {
                try row.int(2, last.last_processed_us);
                try Store.bindSubjectAt(&row, &last.subject, 3);
            }
            if (!try row.row()) return null;
            return .{ .jail = jail.name, .subject = try self.decodeRetrySubject(&row, 0, 1), .last_processed_us = try projectionInteger(&row, 2) };
        }
        fn victimLess(a: RetryAdmissionVictim, b: RetryAdmissionVictim) bool {
            if (a.last_processed_us != b.last_processed_us) return a.last_processed_us < b.last_processed_us;
            const names = std.mem.order(u8, a.jail.slice(), b.jail.slice());
            if (names != .eq) return names == .lt;
            return subjectLess(a.subject, b.subject);
        }
        pub fn retryAdmissionVictimsTx(self: *Store, now_us: i64, output: []RetryAdmissionVictim) Error!usize {
            if (output.len != 16) return error.InvalidRetryState;
            try self.requireRetryAdmissionTimeTx(now_us);
            var heads: [max_jails]Head = undefined;
            var count: usize = 0;
            var jails = try self.statement("SELECT jail_id,jail FROM temp.retry_publication_jails ORDER BY jail_id;");
            defer jails.deinit();
            while (try jails.row()) {
                if (count == heads.len) return error.InvalidRetryState;
                const jail = Jail{ .id = try projectionId(try projectionInteger(&jails, 0)), .name = try projectionName(&jails, 1) };
                heads[count] = .{ .jail_id = jail.id, .victim = try self.projectionHead(jail, null) };
                count += 1;
            }
            var written: usize = 0;
            while (written < output.len) {
                var best: ?usize = null;
                for (heads[0..count], 0..) |head, i| if (head.victim) |victim| {
                    if (best == null or victimLess(victim, heads[best.?].victim.?)) best = i;
                };
                const selected = best orelse break;
                const victim = heads[selected].victim.?;
                output[written] = victim;
                written += 1;
                heads[selected].victim = try self.projectionHead(.{ .id = heads[selected].jail_id, .name = victim.jail }, victim);
            }
            return written;
        }
    };
}
