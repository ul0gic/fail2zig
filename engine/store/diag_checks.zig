// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const build_options = @import("build_options");
const diag_mod = @import("../core/diag.zig");
const effects = @import("../core/native_effect.zig");
const retry = @import("../core/native_retry.zig");
const action_outcome = @import("../core/native_action_outcome.zig");
const application_history = @import("../core/native_application_history.zig");
const store = @import("store.zig");

const StatementPtr = @FieldType(store.Stmt, "ptr");
const sample_interval_ns = 10 * std.time.ns_per_s;
const check_interval_ns = 60 * std.time.ns_per_s;
// The kernel times an element out on its own clock, so one whose deadline is this close to the readback may be present or gone.
const kernel_deadline_slack_us = std.time.us_per_s;
const recent_records = 4096;

const Check = enum { kernel_live, live_owner_counter, retired_totals, retired_overlap, receipt_floor, source_sequence_head };
const check_count = @typeInfo(Check).@"enum".fields.len;

const TableLimit = struct { which: diag_mod.Limit, sql: [:0]const u8, cap: u64 };
const table_limits = [_]TableLimit{
    .{ .which = .live_bans, .sql = "SELECT live FROM effect_owner_live WHERE id=1;", .cap = effects.max_live_owners },
    .{ .which = .effect_owners, .sql = "SELECT count(*) FROM effect_owners;", .cap = effects.max_owners },
    .{ .which = .effects, .sql = "SELECT count(*) FROM native_effects;", .cap = effects.max_effects },
    .{ .which = .owner_revisions, .sql = "SELECT count(*) FROM effect_owner_revisions;", .cap = effects.max_owner_revisions },
    .{ .which = .intents, .sql = "SELECT count(*) FROM effect_intents;", .cap = effects.max_intents },
    .{ .which = .observations, .sql = "SELECT count(*) FROM effect_observations;", .cap = effects.max_observations },
    .{ .which = .action_targets, .sql = "SELECT count(*) FROM action_targets;", .cap = action_outcome.max_rows },
    .{ .which = .confirmed_events, .sql = "SELECT count(*) FROM confirmed_effect_events;", .cap = effects.max_confirmed_events },
    .{ .which = .event_details, .sql = "SELECT count(*) FROM confirmed_event_details;", .cap = application_history.max_details },
};

const consistency = [_]struct { check: Check, sql: [:0]const u8 }{
    .{ .check = .live_owner_counter, .sql = "SELECT (SELECT live FROM effect_owner_live WHERE id=1)-(SELECT count(*) FROM effect_owners WHERE lease_kind<>0);" },
    .{ .check = .retired_totals, .sql = "SELECT (SELECT count(*) FROM retry_retired_totals t WHERE t.total<>(SELECT IFNULL(SUM(r.decisions),0) FROM retry_retired r WHERE r.jail=t.jail))+(SELECT count(DISTINCT jail) FROM retry_retired WHERE jail NOT IN (SELECT jail FROM retry_retired_totals));" },
    .{ .check = .retired_overlap, .sql = "SELECT count(*) FROM retry_retired r JOIN retry_states s ON s.jail=r.jail AND s.family=r.family AND s.subject=r.subject;" },
    .{ .check = .receipt_floor, .sql = "SELECT IFNULL(MAX(0,MAX(v)-(SELECT floor_us FROM receipt_clock WHERE id=1)),0) FROM (SELECT MAX(receipt_us) AS v FROM pending_receipts UNION ALL SELECT MAX(receipt_us) FROM (SELECT receipt_us FROM records ORDER BY rowid DESC LIMIT " ++ std.fmt.comptimePrint("{d}", .{recent_records}) ++ "));" },
    .{ .check = .source_sequence_head, .sql = "SELECT count(*) FROM source_maintenance m WHERE m.head_sequence<>(SELECT MAX(v) FROM (SELECT MAX(r.source_sequence) AS v FROM records r WHERE r.jail=m.jail AND r.source=m.source AND r.source_generation=m.generation UNION ALL SELECT MAX(g.source_sequence) FROM replay_guards g WHERE g.jail=m.jail AND g.source=m.source AND g.generation=m.generation));" },
};

var last_sample: ?std.time.Instant = null;
var last_check: ?std.time.Instant = null;
var last_kernel_check: ?std.time.Instant = null;
var reported: [check_count]?i64 = [_]?i64{null} ** check_count;

fn due(last: *?std.time.Instant, interval_ns: u64) bool {
    const now = std.time.Instant.now() catch return false;
    if (last.*) |prior| if (now.since(prior) < interval_ns) return false;
    last.* = now;
    return true;
}

fn report(check: Check, difference: ?i64, detail: []const u8) void {
    const index = @intFromEnum(check);
    const value = difference orelse {
        reported[index] = null;
        return;
    };
    if (reported[index] == value) return;
    reported[index] = value;
    diag_mod.event(.consistency_mismatch, .{ .cause = @tagName(check), .detail = detail, .value = @abs(value) });
}

pub fn Methods(comptime Store: type) type {
    return struct {
        fn diagQuiet(self: *Store) bool {
            return self.reopen_required or self.startup_admission or self.api.get_autocommit(self.db) == 0 or self.schema_version != store.latest_schema;
        }

        fn diagInteger(self: *Store, sql: [:0]const u8, binds: []const i64) ?i64 {
            var ptr: ?StatementPtr = null;
            if (self.api.prepare(self.db, sql, -1, &ptr, null) != 0) return null;
            const statement = ptr orelse return null;
            defer _ = self.api.finalize(statement);
            for (binds, 1..) |value, index| if (self.api.bind_int64(statement, @intCast(index), value) != 0) return null;
            const saved = self.work_remaining;
            self.work_remaining = 1000;
            defer self.work_remaining = saved;
            if (self.api.step(statement) != 100 or self.api.column_type(statement, 0) == 5) return null;
            return self.api.column_int64(statement, 0);
        }

        fn diagCount(self: *Store, sql: [:0]const u8, binds: []const i64) ?u64 {
            return std.math.cast(u64, self.diagInteger(sql, binds) orelse return null);
        }

        pub fn diagMarkChanges(self: *Store) void {
            const total_changes = @extern(*const fn (*anyopaque) callconv(.c) i64, .{ .name = "sqlite3_total_changes64" });
            self.diag_changes = total_changes(self.db);
        }

        pub fn diagCommitted(self: *Store) void {
            const before = self.diag_changes;
            self.diagMarkChanges();
            const rows = std.math.cast(u64, self.diag_changes - before) orelse return;
            if (rows == 0) return;
            diag_mod.count(.write_commits, 1);
            diag_mod.count(.commit_rows, rows);
            diag_mod.gauge(.commit_rows_last, rows);
        }

        pub fn diagSweep(self: *Store, now_us: i64) void {
            if (self.diagQuiet()) return;
            if (due(&last_sample, sample_interval_ns)) self.diagSampleLimits(now_us);
            if (due(&last_check, check_interval_ns)) self.diagCheckConsistency();
        }

        fn diagSampleLimits(self: *Store, now_us: i64) void {
            for (table_limits) |table| if (self.diagCount(table.sql, &.{})) |used| diag_mod.limit(table.which, used, table.cap);
            if (self.diagCount("SELECT count(*) FROM retry_states WHERE lease_kind=2 OR (lease_kind=1 AND deadline_us>?1);", &.{now_us})) |banned| diag_mod.limit(.banned_subjects, banned, retry.max_pool_subjects);
            if (self.receipt_limit) |maximum| if (self.diagCount("SELECT count(*) FROM pending_receipts;", &.{})) |pending| diag_mod.limit(.pending_receipts, pending, maximum);
            if (self.runtime_limits) if (self.diagCount("PRAGMA page_count;", &.{})) |pages| if (self.diagCount("PRAGMA max_page_count;", &.{})) |maximum| diag_mod.limit(.state_pages, pages, maximum);
            const memory_used = @extern(*const fn () callconv(.c) i64, .{ .name = "sqlite3_memory_used" });
            const hard_heap_limit = @extern(*const fn (i64) callconv(.c) i64, .{ .name = "sqlite3_hard_heap_limit64" });
            diag_mod.limit(.sqlite_heap, std.math.lossyCast(u64, memory_used()), std.math.lossyCast(u64, hard_heap_limit(-1)));
        }

        fn diagCheckConsistency(self: *Store) void {
            for (consistency) |item| {
                const difference = self.diagInteger(item.sql, &.{}) orelse {
                    diag_mod.count(.consistency_skipped, 1);
                    continue;
                };
                diag_mod.count(.consistency_checks, 1);
                report(item.check, if (difference == 0) null else difference, "");
            }
        }

        pub fn diagKernelCheck(self: *Store, elements: usize, start_us: i64, end_us: i64) void {
            if (self.diagQuiet() or !due(&last_kernel_check, check_interval_ns)) return;
            const sql = "SELECT count(*) FROM native_effects WHERE lease_kind=2 OR (lease_kind=1 AND deadline_us>?1);";
            const fewest = self.diagCount(sql, &.{end_us +| kernel_deadline_slack_us});
            const most = self.diagCount(sql, &.{start_us -| kernel_deadline_slack_us});
            if (fewest == null or most == null) {
                diag_mod.count(.consistency_skipped, 1);
                return;
            }
            diag_mod.count(.consistency_checks, 1);
            const kernel: i64 = @intCast(elements);
            const low: i64 = @intCast(fewest.?);
            const high: i64 = @intCast(most.?);
            const difference = if (kernel < low) kernel - low else if (kernel > high) kernel - high else 0;
            var buffer: [96]u8 = undefined;
            const detail = std.fmt.bufPrint(&buffer, "kernel={d} database={d}..{d}", .{ kernel, low, high }) catch "";
            report(.kernel_live, if (difference == 0) null else difference, detail);
        }
    };
}
