// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Stores the retry policies, states and decisions that turn matched records into bans and checks startup state ownership.
// Holds: A new ban past the banned-subject cap is refused, and a full tracking pool evicts only subjects whose effect is wholly absent.

const std = @import("std");
const build_options = @import("build_options");
const diag_mod = @import("../diag/diag.zig");
const consumers = @import("../detect/consumer.zig");
const detection = @import("../detect/detection_record.zig");
const retry = @import("../detect/retry.zig");
const effects = @import("../effect/effect.zig");
const application_history = @import("../effect/application_history.zig");
const effect_history = @import("../effect/effect_history.zig");
const action_context = @import("../effect/action_context.zig");
const action_outcome = @import("../effect/action_outcome.zig");
const store = @import("store.zig");
const Error = store.Error;
const Stmt = store.Stmt;
const latest_schema = store.latest_schema;
const Record = store.Record;
const EscalationSelection = store.EscalationSelection;
const max_native_detections = store.max_native_detections;
const eviction_warn_interval_us: i64 = 60 * 1_000_000;

pub const Evictions = struct {
    slots: [max_jail_slots]Slot = [_]Slot{.{}} ** max_jail_slots,
    used: u8 = 0,

    const max_jail_slots = 64;
    const Slot = struct { jail: detection.Name = .{ .len = 0 }, total: u64 = 0, unreported: u64 = 0, warned_us: ?i64 = null };

    fn find(self: *const Evictions, jail: []const u8) ?usize {
        for (self.slots[0..self.used], 0..) |*slot, i| if (std.mem.eql(u8, slot.jail.slice(), jail)) return i;
        return null;
    }

    pub fn count(self: *const Evictions, jail: []const u8) u64 {
        return if (self.find(jail)) |i| self.slots[i].total else 0;
    }

    fn note(self: *Evictions, jail: []const u8, now_us: i64) error{InvalidRecord}!void {
        const index = self.find(jail) orelse blk: {
            const name = detection.Name.init(jail) catch return error.InvalidRecord;
            var chosen: usize = self.used;
            if (self.used == max_jail_slots) {
                chosen = 0;
                for (self.slots, 0..) |slot, i| {
                    const oldest = self.slots[chosen].warned_us orelse std.math.minInt(i64);
                    if ((slot.warned_us orelse std.math.minInt(i64)) < oldest) chosen = i;
                }
            } else self.used += 1;
            self.slots[chosen] = .{ .jail = name };
            break :blk chosen;
        };
        const slot = &self.slots[index];
        slot.total +|= 1;
        slot.unreported +|= 1;
        if (slot.warned_us) |last| if (now_us - last < eviction_warn_interval_us) return;
        std.log.warn("native: jail={} tracking pool full: evicted {d} idle subjects in the last 60 s", .{ std.zig.fmtEscapes(jail), slot.unreported });
        slot.unreported = 0;
        slot.warned_us = now_us;
    }
};

pub fn Methods(comptime Store: type) type {
    return struct {
        pub const EvictionReport = struct { evicted: ?detection.Subject, last_processed_us: i64 };
        pub const PoolOccupancy = struct { tracked: u32, banned: u32, tracking_limit: u32, ban_limit: u32 };
        const PoolPressure = enum { none, tracking, banned };
        pub fn admitRetry(self: *Store, jail: []const u8, generation: [32]u8, policy: retry.Policy) Error!void {
            if (jail.len == 0 or jail.len > 64 or std.mem.indexOfScalar(u8, jail, 0) != null) return error.InvalidRecord;
            _ = try policy.encode();
            try self.beginAdmissionWrite();
            errdefer self.rollback();
            try self.admitRetryProjectionJailTx(jail);
            if (!try self.checkRetryAdmission(jail, generation, policy)) {
                const encoded = try policy.encode();
                var insert = try self.statement("INSERT INTO retry_policies VALUES(?1,?2,?3);");
                defer insert.deinit();
                try insert.text(1, jail);
                try insert.blob(2, &generation);
                try insert.blob(3, &encoded);
                try insert.done();
                if (self.schema_version >= 18) {
                    const escalation = try policy.escalation.encode();
                    var escalation_insert = try self.statement("INSERT INTO retry_escalation_policies VALUES(?1,?2,?3);");
                    defer escalation_insert.deinit();
                    try escalation_insert.text(1, jail);
                    try escalation_insert.blob(2, &generation);
                    try escalation_insert.blob(3, &escalation);
                    try escalation_insert.done();
                }
            } else if (try self.readRetryPolicy(jail)) |saved| {
                if (saved.policy.max_subjects != policy.max_subjects) {
                    const encoded = try policy.encode();
                    var update = try self.statement("UPDATE retry_policies SET policy=?3 WHERE jail=?1 AND generation=?2;");
                    defer update.deinit();
                    try update.text(1, jail);
                    try update.blob(2, &generation);
                    try update.blob(3, &encoded);
                    try update.done();
                }
            }
            try self.commitTransaction();
        }

        fn checkRetryAdmission(self: *Store, jail: []const u8, generation: [32]u8, policy: retry.Policy) Error!bool {
            if (jail.len == 0 or jail.len > 64 or std.mem.indexOfScalar(u8, jail, 0) != null) return error.InvalidRecord;
            _ = try policy.encode();
            const schema = try self.integer("PRAGMA user_version;");
            if (schema < 9 or schema > latest_schema) return error.RetryStorageRequired;
            if (schema < 16 and policy.duration == .permanent) return error.RetryStorageRequired;
            if (schema < 18 and policy.escalation.enabled) return error.RetryStorageRequired;
            if (try self.readRetryPolicy(jail)) |saved| {
                if (!std.mem.eql(u8, &saved.generation, &generation) or !try retryPoliciesEqual(saved.policy, policy)) return error.RetryGenerationMismatch;
                return true;
            }
            if (try self.revision(jail) != 0) return error.RetryMigrationRequired;
            var pending = try self.statement("SELECT 1 FROM pending_receipts WHERE jail=?1 LIMIT 1;");
            defer pending.deinit();
            try pending.text(1, jail);
            if (try pending.row()) return error.RetryMigrationRequired;
            return false;
        }

        pub const RuntimeAdmission = struct {
            jail: []const u8,
            generation: [32]u8,
            policy: retry.Policy,
            custom: bool = false,
        };
        pub fn validateRuntimeAdmissions(self: *Store, admissions: []const RuntimeAdmission, resolver_generation: ?[32]u8) !void {
            if (admissions.len == 0 or admissions.len > 64) return error.InvalidRecord;
            try self.beginRead();
            errdefer self.rollback();
            var names: [64][]const u8 = undefined;
            for (admissions, 0..) |binding, i| {
                names[i] = binding.jail;
                for (names[0..i]) |prior| if (std.mem.eql(u8, prior, binding.jail)) return error.InvalidRecord;
                _ = try self.checkRetryAdmission(binding.jail, binding.generation, binding.policy);
                var pending = try self.statement("SELECT 1 FROM pending_receipts WHERE jail=?1 AND generation!=?2 LIMIT 1;");
                defer pending.deinit();
                try pending.text(1, binding.jail);
                try pending.blob(2, &binding.generation);
                if (try pending.row()) return error.SourceGenerationMismatch;
            }
            try self.validateOwnerNamesTx(names[0..admissions.len]);
            try self.requireManifestSchema();
            var manifests = try self.statement("SELECT jail,generation FROM consumer_manifests GROUP BY jail,generation;");
            defer manifests.deinit();
            var count: usize = 0;
            while (try manifests.row()) {
                count += 1;
                // Why: Besides one generation per admitted jail, only @shared and @history may hold manifests.
                if (count > admissions.len + 2) return error.ConsumerGenerationMismatch;
                const jail = try manifests.boundedBytes(0, 64);
                const saved = try Store.effectBlob(&manifests, 1, 32);
                if (std.mem.eql(u8, jail, "@history")) continue;
                if (std.mem.eql(u8, jail, "@shared")) {
                    const expected = resolver_generation orelse return error.UnconfiguredStateOwner;
                    if (!std.mem.eql(u8, &saved, &expected)) return error.ConsumerGenerationMismatch;
                    continue;
                }
                for (admissions) |binding| {
                    if (!std.mem.eql(u8, jail, binding.jail)) continue;
                    if (!binding.custom) return error.UnconfiguredStateOwner;
                    if (!std.mem.eql(u8, &saved, &binding.generation)) return error.ConsumerGenerationMismatch;
                    break;
                } else return error.UnconfiguredStateOwner;
            }
            try self.commitTransaction();
        }

        pub fn readRetryPolicy(self: *Store, jail: []const u8) Error!?retry.Admission {
            var row = try self.statement(if (self.schema_version >= 18)
                "SELECT p.generation,p.policy,e.generation,e.policy FROM retry_policies p JOIN retry_escalation_policies e USING(jail) WHERE p.jail=?1;"
            else
                "SELECT generation,policy FROM retry_policies WHERE jail=?1;");
            defer row.deinit();
            try row.text(1, jail);
            if (!try row.row()) return null;
            if (self.api.column_type(row.ptr, 0) != 4 or self.api.column_type(row.ptr, 1) != 4) return error.InvalidRetryState;
            const generation = try row.boundedBytes(0, 32);
            if (generation.len != 32) return error.InvalidRetryState;
            const raw = try row.boundedBytes(1, retry.policy_bytes);
            if (self.schema_version >= 16 and (raw.len != retry.policy_bytes or raw[4] != 2)) return error.InvalidRetryPolicy;
            var result = retry.Admission{ .generation = undefined, .policy = try retry.Policy.decode(raw) };
            @memcpy(&result.generation, generation);
            if (self.schema_version >= 18) {
                if (self.api.column_type(row.ptr, 2) != 4 or self.api.column_type(row.ptr, 3) != 4) return error.InvalidRetryState;
                const escalation_generation = try row.boundedBytes(2, 32);
                const escalation_raw = try row.boundedBytes(3, retry.escalation_bytes);
                if (escalation_generation.len != 32 or !std.mem.eql(u8, generation, escalation_generation)) return error.InvalidRetryState;
                result.policy.escalation = try retry.Escalation.decode(escalation_raw);
                try result.policy.validate();
            }
            return result;
        }

        pub fn retryPoliciesEqual(left: retry.Policy, right: retry.Policy) Error!bool {
            const left_base = try left.identity();
            const right_base = try right.identity();
            if (!std.mem.eql(u8, &left_base, &right_base)) return false;
            const left_escalation = try left.escalation.encode();
            const right_escalation = try right.escalation.encode();
            return std.mem.eql(u8, &left_escalation, &right_escalation);
        }

        pub fn bindSubjectAt(row: *Stmt, subject: *const detection.Subject, family_index: c_int) Error!void {
            subject.validate() catch return error.InvalidRetryState;
            if (subject.unenforceable()) return error.InvalidRetryState;
            switch (subject.*) {
                .v4 => {
                    try row.int(family_index, 4);
                    try row.blob(family_index + 1, &subject.v4);
                },
                .v6 => {
                    try row.int(family_index, 6);
                    try row.blob(family_index + 1, &subject.v6);
                },
            }
        }
        pub fn bindSubject(row: *Stmt, subject: *const detection.Subject) Error!void {
            return bindSubjectAt(row, subject, 2);
        }

        fn retryLease(row: *Stmt, kind_col: c_int, deadline_col: c_int) Error!retry.Lease {
            const kind = try row.signed(kind_col);
            const deadline = try row.optionalSigned(deadline_col);
            return switch (kind) {
                0 => if (deadline == null) .absent else error.InvalidRetryState,
                1 => .{ .finite = deadline orelse return error.InvalidRetryState },
                2 => if (deadline == null) .permanent else error.InvalidRetryState,
                else => error.InvalidRetryState,
            };
        }

        fn bindRetryLease(row: *Stmt, index: c_int, lease: retry.Lease) Error!void {
            try row.int(index, @intFromEnum(lease));
            if (lease == .finite) try row.int(index + 1, lease.finite) else try row.store.check(row.store.api.bind_null(row.ptr, index + 1));
        }

        fn readWorkingRetryState(self: *Store, jail: []const u8, subject: detection.Subject, policy: retry.Policy) Error!?retry.State {
            var row = try self.statement(if (self.schema_version >= 16)
                "SELECT last_processed_us,lease_kind,deadline_us,decisions,attempts FROM retry_states WHERE jail=?1 AND family=?2 AND subject=?3;"
            else
                "SELECT last_processed_us,CASE WHEN expiry_us IS NULL THEN 0 ELSE 1 END,expiry_us,decisions,attempts FROM retry_states WHERE jail=?1 AND family=?2 AND subject=?3;");
            defer row.deinit();
            try row.text(1, jail);
            try bindSubject(&row, &subject);
            if (!try row.row()) return null;
            const result = try self.decodeRetryState(&row, policy);
            if (result.last_processed_us > ((try self.readRetryClock()) orelse return error.InvalidRetryState)) return error.InvalidRetryState;
            return result;
        }

        pub fn readRetryState(self: *Store, jail: []const u8, subject: detection.Subject, policy: retry.Policy) Error!?retry.State {
            const working = try self.readWorkingRetryState(jail, subject, policy);
            const retired = try self.readRetired(jail, subject);
            if (working != null and retired != null) return error.InvalidRetryState;
            return working orelse retired;
        }

        fn decodeRetryState(self: *Store, row: *Stmt, policy: retry.Policy) Error!retry.State {
            const decisions = try row.signed(3);
            if (decisions < 0 or self.api.column_type(row.ptr, 4) != 4) return error.InvalidRetryState;
            var result = retry.State{ .last_processed_us = try row.signed(0), .lease = try retryLease(row, 1, 2), .decisions = @intCast(decisions) };
            try result.decodeAttempts(try row.boundedBytes(4, retry.max_attempts * retry.attempt_bytes), policy);
            return result;
        }

        pub fn retryState(self: *Store, jail: []const u8, subject: detection.Subject) Error!?retry.State {
            try self.beginRead();
            errdefer self.rollback();
            const schema = try self.integer("PRAGMA user_version;");
            if (schema < 9 or schema > latest_schema) return error.RetryStorageRequired;
            const admission = (try self.readRetryPolicy(jail)) orelse return error.RetryAdmissionRequired;
            const result = try self.readRetryState(jail, subject, admission.policy);
            try self.commitTransaction();
            return result;
        }

        pub fn validateRuntimeOwnerNames(self: *Store, names: []const []const u8) !void {
            if (names.len == 0 or names.len > 64) return error.InvalidRecord;
            try self.beginRead();
            errdefer self.rollback();
            try self.validateOwnerNamesTx(names);
            try self.commitTransaction();
        }
        pub fn validateCustomSourceManifests(self: *Store, jail: []const u8) Error!void {
            if (jail.len == 0 or jail.len > 64) return error.InvalidConsumer;
            try self.beginRead();
            errdefer self.rollback();
            try self.requireManifestSchema();
            var missing = try self.statement("SELECT 1 FROM (SELECT source FROM source_cursors WHERE jail=?1 UNION SELECT source FROM pending_receipts WHERE jail=?1) s LEFT JOIN consumer_manifests m ON m.jail=?1 AND m.source=s.source WHERE m.source IS NULL OR m.ready!=1 LIMIT 1;");
            defer missing.deinit();
            try missing.text(1, jail);
            if (try missing.row()) return error.MissingRequiredConsumer;
            try self.commitTransaction();
        }
        fn validateOwnerNamesTx(self: *Store, names: []const []const u8) !void {
            var row = try self.statement("SELECT jail FROM checkpoints UNION SELECT jail FROM pending_receipts UNION SELECT jail FROM source_cursors UNION SELECT jail FROM retry_policies;");
            defer row.deinit();
            var count: usize = 0;
            while (try row.row()) {
                count += 1;
                if (count > names.len or self.api.column_type(row.ptr, 0) != 3) return error.UnconfiguredStateOwner;
                const jail = try row.boundedBytes(0, 64);
                for (names) |name| {
                    if (std.mem.eql(u8, jail, name)) break;
                } else return error.UnconfiguredStateOwner;
            }
            if (try self.integer("SELECT EXISTS(SELECT 1 FROM source_cursors c LEFT JOIN checkpoints p ON c.jail=p.jail LEFT JOIN records r ON c.jail=r.jail AND c.source=r.source AND c.occurrence=r.occurrence WHERE p.jail IS NULL OR r.jail IS NULL);") != 0) return error.InvalidRecord;
        }
        pub fn validateConsumerOwnership(self: *Store, names: []const []const u8, expected_manifest_count: usize, expected_consumer_revision: u64, allow_history: bool) !void {
            if (names.len == 0 or names.len > 64 or expected_manifest_count > 4096) return error.InvalidRecord;
            try self.beginRead();
            errdefer self.rollback();
            try self.requireManifestSchema();
            if (try self.consumerRevision() != expected_consumer_revision) return error.StaleConsumerCheckpoint;
            if (try self.integer("SELECT count(*) FROM consumer_manifests;") != expected_manifest_count) return error.ConsumerManifestMismatch;
            var rows = try self.statement("SELECT jail,source,generation,ready FROM consumer_manifests ORDER BY jail,source;");
            defer rows.deinit();
            var count: usize = 0;
            while (try rows.row()) {
                count += 1;
                if (count > expected_manifest_count) return error.ConsumerCapacity;
                const jail = try rows.boundedBytes(0, 64);
                if (try rows.signed(3) != 1) return error.MissingRequiredConsumer;
                if (std.mem.eql(u8, jail, "@history")) {
                    if (!allow_history or !std.mem.eql(u8, try rows.boundedBytes(1, 16384), "confirmed-effects")) return error.UnconfiguredStateOwner;
                    const binding = try Store.effectBlob(&rows, 2, 32);
                    const required = [_]consumers.Requirement{.{ .key = effect_history.key(binding), .format_version = effect_history.version }};
                    const manifest = consumers.Manifest{ .jail = "@history", .source = "confirmed-effects", .source_generation = binding, .required = &required };
                    if (try self.checkManifest(manifest) != .ready) return error.MissingRequiredConsumer;
                    try self.checkRequiredState(required[0], false);
                } else if (!std.mem.eql(u8, jail, "@shared")) {
                    for (names) |name| {
                        if (std.mem.eql(u8, jail, name)) break;
                    } else return error.UnconfiguredStateOwner;
                }
            }
            if (try self.integer("SELECT EXISTS(SELECT 1 FROM consumer_checkpoints c WHERE NOT EXISTS(SELECT 1 FROM consumer_requirements r WHERE r.kind=c.kind AND r.jail=c.jail AND r.source=c.source AND r.rule=c.rule AND r.generation=c.generation AND r.format=c.format));") != 0) return error.ConsumerManifestMismatch;
            try self.validateOwnerNamesTx(names);
            try self.commitTransaction();
        }

        pub const ActiveDecision = struct { subject: detection.Subject, lease: retry.Lease, ordinal: u64 };
        pub fn retryStateRevision(self: *Store) Error!u64 {
            try self.beginRead();
            errdefer self.rollback();
            const revision_value = try self.integer("SELECT revision FROM policy_summary_clock WHERE id=1;");
            if (revision_value <= 0) return error.InvalidPolicySummary;
            try self.commitTransaction();
            return @intCast(revision_value);
        }

        pub fn validateRetry(self: *Store, jail: []const u8, generation: [32]u8, policy: retry.Policy) Error!void {
            try self.beginRead();
            errdefer self.rollback();
            const schema = try self.integer("PRAGMA user_version;");
            if (schema < 9 or schema > latest_schema) return error.RetryStorageRequired;
            const admission = (try self.readRetryPolicy(jail)) orelse return error.RetryAdmissionRequired;
            if (!std.mem.eql(u8, &admission.generation, &generation) or !try retryPoliciesEqual(admission.policy, policy)) return error.RetryGenerationMismatch;
            const floor = try self.readRetryClock();
            var row = try self.statement(if (self.schema_version >= 16)
                "SELECT last_processed_us,lease_kind,deadline_us,decisions,attempts,family,subject FROM retry_states WHERE jail=?1;"
            else
                "SELECT last_processed_us,CASE WHEN expiry_us IS NULL THEN 0 ELSE 1 END,expiry_us,decisions,attempts,family,subject FROM retry_states WHERE jail=?1;");
            defer row.deinit();
            try row.text(1, jail);
            var count: usize = 0;
            while (try row.row()) {
                count += 1;
                if (count > @as(usize, policy.max_subjects) + retry.max_pool_subjects) return error.RetryCapacity;
                const state = try self.decodeRetryState(&row, policy);
                if (state.last_processed_us > (floor orelse return error.InvalidRetryState)) return error.InvalidRetryState;
                _ = try self.decodeRetrySubject(&row, 5, 6);
            }
            try self.commitTransaction();
        }

        pub fn decodeRetrySubject(self: *Store, row: *Stmt, family_col: c_int, subject_col: c_int) Error!detection.Subject {
            if (self.api.column_type(row.ptr, subject_col) != 4) return error.InvalidRetryState;
            const bytes = try row.boundedBytes(subject_col, 16);
            const family = try row.signed(family_col);
            var subject: detection.Subject = undefined;
            if (family == 4 and bytes.len == 4) {
                subject = .{ .v4 = undefined };
                @memcpy(&subject.v4, bytes);
            } else if (family == 6 and bytes.len == 16) {
                subject = .{ .v6 = undefined };
                @memcpy(&subject.v6, bytes);
            } else return error.InvalidRetryState;
            subject.validate() catch return error.InvalidRetryState;
            if (subject.unenforceable()) return error.InvalidRetryState;
            return subject;
        }

        pub fn retryDecisions(self: *Store, jail: []const u8, source: []const u8, occurrence: ?[]const u8, output: []retry.Decision) Error!usize {
            if (output.len == 0 or output.len > max_native_detections) return error.ConsumerCapacity;
            var row = try self.statement(if (self.schema_version >= 16)
                if (occurrence != null)
                    "SELECT family,subject,decided_us,lease_kind,deadline_us,ordinal,enforce FROM retry_decisions WHERE jail=?1 AND source=?2 AND occurrence=?3;"
                else
                    "SELECT d.family,d.subject,d.decided_us,d.lease_kind,d.deadline_us,d.ordinal,d.enforce FROM retry_decisions d JOIN source_cursors c USING(jail,source,occurrence) WHERE d.jail=?1 AND d.source=?2;"
            else if (occurrence != null)
                "SELECT family,subject,decided_us,1,expiry_us,ordinal,enforce FROM retry_decisions WHERE jail=?1 AND source=?2 AND occurrence=?3;"
            else
                "SELECT d.family,d.subject,d.decided_us,1,d.expiry_us,d.ordinal,d.enforce FROM retry_decisions d JOIN source_cursors c USING(jail,source,occurrence) WHERE d.jail=?1 AND d.source=?2;");
            defer row.deinit();
            try row.text(1, jail);
            try row.text(2, source);
            if (occurrence) |value| try row.text(3, value);
            var count: usize = 0;
            while (try row.row()) {
                if (count >= output.len) return error.ConsumerCapacity;
                const ordinal = try row.signed(5);
                const enforce = try row.signed(6);
                const now = try row.signed(2);
                const lease = try retryLease(&row, 3, 4);
                if (ordinal <= 0 or enforce < 0 or enforce > 1 or lease == .absent or (lease == .finite and lease.finite <= now)) return error.InvalidRetryState;
                output[count] = .{ .subject = try self.decodeRetrySubject(&row, 0, 1), .decided_us = now, .lease = lease, .ordinal = @intCast(ordinal), .enforce = enforce == 1 };
                count += 1;
            }
            return count;
        }

        fn readEscalationHistory(self: *Store, jail: []const u8, subject: detection.Subject, scope: retry.EscalationScope, decay: retry.EscalationDecay, now_us: i64, policy: retry.Policy) Error!retry.EscalationHistoryInput {
            if (decay.window_us < 0) return error.InvalidEscalationInput;
            const history = history: {
                var row = try self.statement(switch (scope) {
                    .per_jail => "SELECT confirmed_count,latest_confirmed_us FROM confirmed_policy_summaries WHERE jail=?1 AND family=?2 AND subject=?3;",
                    .overall => "SELECT coalesce(sum(confirmed_count),0),max(latest_confirmed_us) FROM confirmed_policy_summaries WHERE ?1 IS NOT NULL AND family=?2 AND subject=?3;",
                });
                defer row.deinit();
                try row.text(1, jail);
                try bindSubject(&row, &subject);
                if (!try row.row()) return .{};
                const signed_count = try row.signed(0);
                if (signed_count < 0) return error.InvalidRetryState;
                const count: u64 = @intCast(signed_count);
                const latest = try row.optionalSigned(1);
                if ((count == 0) != (latest == null) or try row.row()) return error.InvalidRetryState;
                break :history retry.EscalationHistoryInput{ .prior_confirmed = count, .latest_confirmed_us = latest };
            };
            if (decay.window_us == 0 or history.prior_confirmed == 0) return history;
            const ban_end = try self.lastBanEnd(jail, subject, scope, now_us, history, policy) orelse return history;
            if (@as(i128, ban_end) >= @as(i128, now_us) - decay.window_us) return history;
            var forget = try self.statement(switch (scope) {
                .per_jail => "DELETE FROM confirmed_policy_summaries WHERE jail=?1 AND family=?2 AND subject=?3;",
                .overall => "DELETE FROM confirmed_policy_summaries WHERE ?1 IS NOT NULL AND family=?2 AND subject=?3;",
            });
            defer forget.deinit();
            try forget.text(1, jail);
            try bindSubject(&forget, &subject);
            try forget.done();
            return .{};
        }

        fn lastBanEnd(self: *Store, jail: []const u8, subject: detection.Subject, scope: retry.EscalationScope, now_us: i64, history: retry.EscalationHistoryInput, policy: retry.Policy) Error!?i64 {
            var row = try self.statement(switch (scope) {
                .per_jail => "SELECT max(permanent),max(deadline_us) FROM (SELECT lease_kind=2 AS permanent,deadline_us FROM retry_states WHERE jail=?1 AND family=?2 AND subject=?3 UNION ALL SELECT lease_kind=2,deadline_us FROM retry_decisions WHERE jail=?1 AND family=?2 AND subject=?3);",
                .overall => "SELECT max(permanent),max(deadline_us) FROM (SELECT lease_kind=2 AS permanent,deadline_us FROM retry_states WHERE ?1 IS NOT NULL AND family=?2 AND subject=?3 UNION ALL SELECT lease_kind=2,deadline_us FROM retry_decisions WHERE ?1 IS NOT NULL AND family=?2 AND subject=?3);",
            });
            defer row.deinit();
            try row.text(1, jail);
            try bindSubject(&row, &subject);
            if (!try row.row()) return error.DatabaseFailure;
            if ((try row.optionalSigned(0) orelse 0) == 1) return null;
            if (try row.optionalSigned(1)) |deadline| return if (deadline > now_us) null else deadline;
            const confirmed_us = history.latest_confirmed_us orelse return error.InvalidRetryState;
            const last_term = policy.escalation.duration(policy.duration, history.prior_confirmed - 1, 0) catch |err| switch (err) {
                error.InvalidEscalationPolicy => return null,
                else => return err,
            };
            return switch (last_term) {
                .finite_us => |term_us| std.math.add(i64, confirmed_us, term_us) catch null,
                .permanent => null,
            };
        }

        fn retryPoolPressure(self: *Store, now_us: i64, new_row: bool, banning: bool, tracking_limit: u32) Error!PoolPressure {
            const total = try self.tableRows(.retry_states);
            if (comptime build_options.diag) diag_mod.limit(.retry_rows, std.math.lossyCast(u64, total), @as(u64, tracking_limit) + retry.max_pool_subjects);
            const total_full = new_row and total >= @as(i64, tracking_limit) + retry.max_pool_subjects;
            const limit: i64 = if (banning) retry.max_pool_subjects else tracking_limit;
            if (!total_full and total < limit) return .none;
            try self.requireRetryAdmissionTimeTx(now_us);
            const banned = (try self.retryAdmissionCountsTx()).live;
            if (comptime build_options.diag) diag_mod.limit(.banned_subjects, std.math.lossyCast(u64, banned), retry.max_pool_subjects);
            if (banning and banned >= retry.max_pool_subjects) return .banned;
            if (total_full or (!banning and total - banned >= limit)) return .tracking;
            return .none;
        }

        pub fn evictIdleSubject(self: *Store, jail: []const u8, now_us: i64) Error!EvictionReport {
            if (self.schema_version < 16) return .{ .evicted = null, .last_processed_us = 0 };
            const installation = try self.readInstallation();
            var candidates: [16]Store.RetryAdmissionVictim = undefined;
            const count = try self.retryAdmissionVictimsTx(now_us, &candidates);
            for (candidates[0..count]) |candidate| {
                const subject = candidate.subject;
                if (installation) |owner| {
                    if (try self.readEffect(try (try effects.Scope.host(subject)).key(owner), owner)) |entry|
                        if (entry.desired != .absent or entry.status != .absent) continue;
                }
                const victim_jail = candidate.jail;
                const last_processed_us = candidate.last_processed_us;
                var state = try self.statement("SELECT last_processed_us,decisions FROM retry_states WHERE jail=?1 AND family=?2 AND subject=?3;");
                defer state.deinit();
                try state.text(1, victim_jail.slice());
                try bindSubject(&state, &subject);
                if (!try state.row() or try state.signed(0) != last_processed_us) return error.InvalidRetryState;
                const signed_decisions = try state.signed(1);
                if (signed_decisions < 0) return error.InvalidRetryState;
                const decisions: u64 = @intCast(signed_decisions);
                if (decisions > 0) {
                    const victim_policy = try self.readRetryPolicy(victim_jail.slice()) orelse return error.InvalidRetryState;
                    try self.changeRetiredTotal(victim_jail.slice(), decisions, true);
                    var saved = try self.statement("INSERT INTO retry_retired VALUES(?1,?2,?3,?4,?5,?6);");
                    defer saved.deinit();
                    try saved.text(1, victim_jail.slice());
                    try bindSubject(&saved, &subject);
                    try saved.blob(4, &victim_policy.generation);
                    try saved.int(5, last_processed_us);
                    try saved.int(6, signed_decisions);
                    try saved.done();
                    _ = try self.evictMemoryRows(.retired, now_us);
                }
                var remove = try self.statement("DELETE FROM retry_states WHERE jail=?1 AND family=?2 AND subject=?3;");
                defer remove.deinit();
                try remove.text(1, victim_jail.slice());
                try bindSubject(&remove, &subject);
                try remove.done();
                self.deletedRows(.retry_states);
                if (self.api.changes(self.db) != 1) return error.InvalidRetryState;
                try self.removeRetryProjectionRowTx(victim_jail.slice(), &subject);
                try self.changeRetryJailSummaryTx(victim_jail.slice(), 0, 0);
                try self.retry_evictions.note(jail, now_us);
                return .{ .evicted = subject, .last_processed_us = last_processed_us };
            }
            return .{ .evicted = null, .last_processed_us = 0 };
        }

        pub fn evictionCount(self: *Store, jail: []const u8) u64 {
            return self.retry_evictions.count(jail);
        }

        pub fn commitRetry(self: *Store, record: Record, admission: retry.Admission) Error!void {
            try self.requireRetryProjectionMutationTx();
            if (admission.processing_us) |now| {
                if (try self.readRetryClock()) |floor| if (now < floor) return error.ReceiptClockReversed;
                var clock = try self.statement("UPDATE retry_clock SET floor_us=CASE WHEN floor_us IS NULL OR floor_us<?1 THEN ?1 ELSE floor_us END WHERE id=1;");
                defer clock.deinit();
                try clock.int(1, now);
                try clock.done();
                if (self.api.changes(self.db) != 1) return error.InvalidRetryState;
            }
            const detected = record.native_detection orelse return;
            if (detected.kind != .candidate) return;
            const outcome = record.native_time_outcome orelse return error.InvalidRecord;
            if (outcome != .eligible) return error.InvalidRecord;
            const now = admission.processing_us orelse return error.InvalidRecord;
            const subject = detected.subject orelse return error.InvalidRecord;
            const previous = try self.readRetryState(record.jail, subject, admission.policy);
            const retired = try self.readRetired(record.jail, subject);
            const current_attempt = retry.Attempt{ .at_us = outcome.eligible.timestamp.us, .occurrence = retry.occurrenceKey(record.source, record.occurrence) };
            var next = try retry.advanceWithEvidence(admission.policy, previous, subject, current_attempt, now, record.retry_evidence);
            const new_row = previous == null or retired != null;
            const newly_banned = next.decision != null and !(if (previous) |prior| prior.lease.live(now) else false);
            if (new_row or newly_banned) switch (try self.retryPoolPressure(now, new_row, newly_banned, admission.policy.max_subjects)) {
                .none => {},
                .banned => return error.RetryCapacity,
                .tracking => if ((try self.evictIdleSubject(record.jail, now)).evicted == null) return error.RetryCapacity,
            };
            var escalation_selection: ?EscalationSelection = null;
            if (next.decision != null and admission.policy.escalation.enabled) {
                if (self.schema_version < 18) return error.RetryStorageRequired;
                const history = try self.readEscalationHistory(record.jail, subject, admission.policy.escalation.scope, admission.decay, now, admission.policy);
                var sampled_seconds: u64 = 0;
                if (history.prior_confirmed > 0 and admission.policy.escalation.jitter_us > 0) {
                    const maximum: u64 = @intCast(@divExact(admission.policy.escalation.jitter_us, 1_000_000));
                    sampled_seconds = self.escalation_jitter(self.escalation_jitter_context, maximum);
                    if (sampled_seconds > maximum) return error.InvalidEscalationInput;
                }
                const sampled_us = std.math.mul(i64, @as(i64, @intCast(sampled_seconds)), 1_000_000) catch return error.InvalidEscalationInput;
                const chosen = try admission.policy.escalation.duration(admission.policy.duration, history.prior_confirmed, sampled_us);
                const chosen_us = switch (chosen) {
                    .finite_us => |value| value,
                    .permanent => return error.InvalidEscalationInput,
                };
                var selected_policy = admission.policy;
                selected_policy.duration = chosen;
                next = try retry.advanceWithEvidence(selected_policy, previous, subject, current_attempt, now, record.retry_evidence);
                if (next.decision == null) return error.InvalidRetryState;
                escalation_selection = .{
                    .scope = admission.policy.escalation.scope,
                    .prior_confirmed = history.prior_confirmed,
                    .latest_confirmed_us = history.latest_confirmed_us,
                    .chosen_duration_us = chosen_us,
                    .jitter_us = sampled_us,
                };
            }
            if (next.decision) |*decision| decision.enforce = admission.enforces();
            var prepared_context: ?action_context.Context = null;
            if (next.decision) |decision| {
                const confirmed_history_count: ?u64 = if (self.schema_version >= 18)
                    (try self.readEscalationHistory(record.jail, subject, .per_jail, .{}, now, admission.policy)).prior_confirmed
                else
                    null;
                prepared_context = try action_context.fromRetry(
                    record.jail,
                    record.source,
                    record.occurrence,
                    detected,
                    outcome.eligible.timestamp.us,
                    decision,
                    @intCast(admission.policy.maxretry),
                    confirmed_history_count,
                );
            }
            if (retired) |prior| {
                try self.changeRetiredTotal(record.jail, prior.decisions, false);
                var remove = try self.statement("DELETE FROM retry_retired WHERE jail=?1 AND family=?2 AND subject=?3;");
                defer remove.deinit();
                try remove.text(1, record.jail);
                try bindSubject(&remove, &subject);
                try remove.done();
                if (self.api.changes(self.db) != 1) return error.InvalidRetryState;
            }
            var bytes: [retry.max_attempts * retry.attempt_bytes]u8 = undefined;
            if (self.schema_version < 16 and next.state.lease == .permanent) return error.RetryStorageRequired;
            var row = try self.statement(if (self.schema_version >= 16)
                "INSERT INTO retry_states VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(jail,family,subject) DO UPDATE SET last_processed_us=excluded.last_processed_us,lease_kind=excluded.lease_kind,deadline_us=excluded.deadline_us,decisions=excluded.decisions,attempts=excluded.attempts;"
            else
                "INSERT INTO retry_states VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(jail,family,subject) DO UPDATE SET last_processed_us=excluded.last_processed_us,expiry_us=excluded.expiry_us,decisions=excluded.decisions,attempts=excluded.attempts;");
            defer row.deinit();
            try row.text(1, record.jail);
            try bindSubject(&row, &subject);
            try row.int(4, next.state.last_processed_us);
            if (self.schema_version >= 16) {
                try bindRetryLease(&row, 5, next.state.lease);
                try row.int(7, @intCast(next.state.decisions));
                try row.blob(8, next.state.encodeAttempts(&bytes));
            } else {
                if (next.state.lease == .finite) try row.int(5, next.state.lease.finite);
                try row.int(6, @intCast(next.state.decisions));
                try row.blob(7, next.state.encodeAttempts(&bytes));
            }
            try row.done();
            if (new_row) self.insertedRows(.retry_states, 1);
            try self.syncRetryProjectionRowTx(record.jail, &subject);
            try self.changeRetryJailSummaryTx(record.jail, if (previous) |prior| prior.decisions else 0, next.state.decisions);
            try self.fault(.after_retry_state);
            if (next.decision) |decision| {
                var effect_identity: ?effects.Hash = null;
                const context = prepared_context orelse return error.InvalidActionContext;
                var decision_row = try self.statement(if (self.schema_version >= 16)
                    "INSERT INTO retry_decisions(jail,family,subject,source,occurrence,decided_us,lease_kind,deadline_us,ordinal,enforce) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10);"
                else
                    "INSERT INTO retry_decisions(jail,family,subject,source,occurrence,decided_us,expiry_us,ordinal,enforce) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9);");
                defer decision_row.deinit();
                try decision_row.text(1, record.jail);
                try bindSubject(&decision_row, &subject);
                try decision_row.text(4, record.source);
                try decision_row.text(5, record.occurrence);
                try decision_row.int(6, decision.decided_us);
                if (self.schema_version >= 16) {
                    try bindRetryLease(&decision_row, 7, decision.lease);
                    try decision_row.int(9, @intCast(decision.ordinal));
                    try decision_row.int(10, @intFromBool(decision.enforce));
                } else {
                    if (decision.lease != .finite) return error.RetryStorageRequired;
                    try decision_row.int(7, decision.lease.finite);
                    try decision_row.int(8, @intCast(decision.ordinal));
                    try decision_row.int(9, @intFromBool(decision.enforce));
                }
                try decision_row.done();
                if (escalation_selection) |selection| {
                    var selected = try self.statement("INSERT INTO retry_decision_escalations(jail,family,subject,source,occurrence,scope,prior_confirmed,latest_confirmed_us,chosen_duration_us,jitter_us) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10);");
                    defer selected.deinit();
                    try selected.text(1, record.jail);
                    try bindSubject(&selected, &subject);
                    try selected.text(4, record.source);
                    try selected.text(5, record.occurrence);
                    try selected.int(6, @intFromEnum(selection.scope));
                    try selected.int(7, std.math.cast(i64, selection.prior_confirmed) orelse return error.InvalidEscalationInput);
                    if (selection.latest_confirmed_us) |latest| try selected.int(8, latest);
                    try selected.int(9, selection.chosen_duration_us);
                    try selected.int(10, selection.jitter_us);
                    try selected.done();
                }
                try self.fault(.after_retry_decision);
                if (decision.enforce) {
                    if (self.schema_version < 11) return error.EffectStorageRequired;
                    const clock = record.effects_clock orelse return error.InstallationRequired;
                    const effect_now = try self.effectClock(clock);
                    const installation = try self.readInstallation() orelse return error.InstallationRequired;
                    const scope = try context.legacyEffectScope();
                    const key = try scope.key(installation);
                    var owners: [effects.max_page]effects.Owner = undefined;
                    const count = try self.readOwners(key, &owners);
                    var effect_revision: u64 = 0;
                    var kept_existing = false;
                    for (owners[0..count]) |owner| if (std.mem.eql(u8, owner.jail.slice(), record.jail)) {
                        effect_revision = owner.revision;
                        kept_existing = owner.lease.live(effect_now);
                    };
                    const identity = if (self.schema_version >= 12)
                        effects.hashParts("fail2zig-native-effect-decision-v2", &.{ record.jail, record.source, record.occurrence, &admission.generation, &key })
                    else
                        effects.hashParts("fail2zig-native-effect-decision-v1", &.{ record.jail, record.source, record.occurrence, &admission.generation });
                    effect_identity = identity;
                    if (!kept_existing) {
                        const targets: i64 = if (self.schema_version >= 21) @intCast(action_outcome.max_targets_per_action) else 0;
                        _ = try self.setOwnerReservedTx(
                            .{
                                .scope = scope,
                                .jail = record.jail,
                                .generation = admission.generation,
                                .decision_id = identity,
                                .expected_revision = effect_revision,
                                .lease = decision.lease,
                                .decided_us = decision.decided_us,
                            },
                            effect_now,
                            targets,
                        );
                        if (self.schema_version >= 21) try self.prepareActionTargetsTx(.{ .action_id = identity, .scope_key = key, .jail = record.jail }, effect_now);
                    }
                }
                if (self.schema_version >= 17) {
                    if (try self.tableRows(.retry_decision_details) >= application_history.max_details) {
                        if (try self.pruneRetryDecisionDetailsTx() == 0) return error.HistoryCapacity;
                    }
                    var detail = try self.statement("INSERT INTO retry_decision_details(jail,family,subject,source,occurrence,ordinal,decided_us,effect_decision_id,evidence) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9);");
                    defer detail.deinit();
                    try detail.text(1, record.jail);
                    try bindSubject(&detail, &subject);
                    try detail.text(4, record.source);
                    try detail.text(5, record.occurrence);
                    try detail.int(6, @intCast(decision.ordinal));
                    try detail.int(7, decision.decided_us);
                    if (effect_identity) |identity| try detail.blob(8, &identity);
                    if (self.schema_version < 27 or try self.effectiveHistoryLimitTx(record.jail) != 0) {
                        if (record.retry_evidence.text) |evidence| try detail.text(9, evidence);
                    }
                    try detail.done();
                    self.insertedRows(.retry_decision_details, 1);
                }
            }
        }
    };
}
