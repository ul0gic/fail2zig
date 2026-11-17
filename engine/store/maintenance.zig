// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Schedules one bounded storage maintenance step at a time and owns the maintenance clock revision and its cleanup floor.
// Holds: A cleanup clock reading below the prepared time or the admission floor is refused, and the revision stays below maxInt(i64).

const std = @import("std");
const effects = @import("../effect/effect.zig");
const health = @import("../platform/storage_health.zig");
const store = @import("store.zig");
const Error = store.Error;

pub fn Methods(comptime Store: type) type {
    return struct {
        pub fn adminRevision(self: *Store) Error!u64 {
            if (self.schema_version < 22) return error.AdminStorageRequired;
            const value = try self.integer("SELECT mutation_revision FROM admin_revision WHERE id=1;");
            if (value < 0) return error.DatabaseFailure;
            return @intCast(value);
        }

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
        pub fn maintenanceEffectRevision(self: *Store) Error!u64 {
            const value = try self.integer("SELECT revision FROM effect_clock WHERE singleton=1;");
            if (value < 0) return error.InvalidEffect;
            return @intCast(value);
        }
        pub fn cleanupClock(self: *Store, clock: effects.Clock) Error!i64 {
            const now = clock.read(clock.context);
            if (now < clock.prepared_us) return error.ReceiptClockReversed;
            if (try self.readAdmissionClock(self.schema_version)) |floor| if (now < floor.us) return error.ReceiptClockReversed;
            return now;
        }
        pub fn finishCleanupClock(self: *Store, clock: effects.Clock, initial: i64) Error!void {
            const now = try self.cleanupClock(clock);
            if (now < initial) return error.ReceiptClockReversed;
            _ = try self.maintenanceRevision();
            // Why: The bound keeps revision+1 below maxInt(i64), which maintenanceRevision rejects as invalid.
            var row = try self.statement("UPDATE maintenance_clock SET floor_us=?1,revision=revision+1 WHERE id=1 AND revision<9223372036854775806;");
            defer row.deinit();
            try row.int(1, now);
            try row.done();
            if (self.api.changes(self.db) != 1) return error.StorageLimit;
        }
        pub const HistoryRetention = struct {
            age_us: i64 = 86_400 * 1_000_000,
            max_matches: u16 = 10,

            pub fn validate(self: HistoryRetention) Error!void {
                if (self.age_us < 0 or @mod(self.age_us, 1_000_000) != 0 or self.max_matches > 1024) return error.InvalidApplicationHistoryQuery;
            }
        };

        pub const MaintenanceRequest = struct {
            retention: HistoryRetention,
            now_us: i64,
            history_caught_up: bool,
            spent_scopes: bool,
            shed: ?*ShedCounts = null,
        };
        pub const ShedCounts = struct { spent_pages: u64 = 0, detail_rows: u64 = 0, consumed_events: u64 = 0, memory_rows: u64 = 0 };
        pub fn maintenanceStep(self: *Store, request: MaintenanceRequest) Error!health.MaintenanceOutcome {
            const outcome = try self.maintenanceStepInner(request);
            self.maintenance_operation = null;
            return outcome;
        }
        pub fn shedStep(self: *Store, now_us: i64, spent_scopes: bool, counts: *ShedCounts) Error!?health.MaintenanceOutcome {
            self.maintenance_operation = .spent_scopes;
            if (spent_scopes) switch (try self.pruneSpentEffects(self.prune_batch)) {
                .idle => {},
                .yielded, .scanned => return .{ .wait = .spent_scopes },
                .pruned => {
                    counts.spent_pages +|= 1;
                    return .{ .progress = .spent_scopes };
                },
            };
            self.maintenance_operation = .obsolete_rows;
            switch (try self.reclaimObsoleteOne()) {
                .idle => {},
                .scanned => return .{ .wait = .obsolete_rows },
                .deleted => {
                    counts.spent_pages +|= 1;
                    return .{ .progress = .obsolete_rows };
                },
            }
            if (self.schema_version >= store.load_repair_schema) {
                self.maintenance_operation = .history_details;
                const details = try self.shedHistoryPage(.details, now_us) orelse return .{ .wait = .history_details };
                if (details != 0) {
                    counts.detail_rows +|= details;
                    return .{ .progress = .history_details };
                }
                self.maintenance_operation = .history_prefix;
                const consumed = try self.shedHistoryPage(.prefix, now_us) orelse return .{ .wait = .history_prefix };
                if (consumed != 0) {
                    counts.consumed_events +|= consumed;
                    return .{ .progress = .history_prefix };
                }
            }
            self.maintenance_operation = .obsolete_rows;
            try self.beginClassWrite(.reclamation);
            errdefer self.rollback();
            const evicted = @as(u64, try self.evictMemoryRows(.retired, now_us)) + try self.evictMemoryRows(.summaries, now_us);
            try self.commitTransaction();
            if (evicted == 0) return null;
            counts.memory_rows +|= evicted;
            return .{ .progress = .obsolete_rows };
        }
        fn maintenanceStepInner(self: *Store, request: MaintenanceRequest) Error!health.MaintenanceOutcome {
            if (request.shed) |counts| if (self.intake_closed) if (try self.shedStep(request.now_us, request.spent_scopes, counts)) |outcome| return outcome;
            const history_pending = self.history_retention_rest;
            if (request.history_caught_up) self.history_retention_rest = false;
            if (request.history_caught_up and !history_pending) {
                self.maintenance_operation = .history_details;
                const result = try self.historyRetentionStep(request.retention, request.now_us);
                self.history_retention_rest = result != .idle;
                switch (result) {
                    .idle => {},
                    .yielded => return .{ .wait = .history_details },
                    .rebuilt, .published => return .{ .progress = .history_rebuild },
                    .details => return .{ .progress = .history_details },
                    .prefix => return .{ .progress = .history_prefix },
                }
            }
            self.maintenance_operation = .retry_details;
            if (self.retry_detail_rest != 0) {
                self.retry_detail_rest -= 1;
            } else if (try self.pruneRetryDecisionDetailsOne()) {
                return .{ .progress = .retry_details };
            } else self.retry_detail_rest = 63;
            const serviced = self.reclaim_turn;
            self.reclaim_turn = false;
            if (serviced) if (try self.reclaimStep()) |outcome| return outcome;
            self.maintenance_operation = .spent_scopes;
            if (request.spent_scopes) switch (try self.pruneSpentEffects(self.prune_batch)) {
                .idle => {},
                .yielded => return .{ .wait = .spent_scopes },
                .scanned => {
                    self.reclaim_turn = true;
                    return .{ .wait = .spent_scopes };
                },
                .pruned => {
                    self.reclaim_turn = true;
                    return .{ .progress = .spent_scopes };
                },
            };
            if (!serviced) if (try self.reclaimStep()) |outcome| return outcome;
            return if (history_pending) .{ .wait = .history_details } else .idle;
        }
        fn reclaimStep(self: *Store) Error!?health.MaintenanceOutcome {
            self.maintenance_operation = .obsolete_rows;
            return switch (try self.reclaimObsoleteOne()) {
                .deleted => .{ .progress = .obsolete_rows },
                .scanned => .{ .wait = .obsolete_rows },
                .idle => null,
            };
        }
    };
}
