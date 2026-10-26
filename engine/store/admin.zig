// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const retry = @import("../core/native_retry.zig");
const effects = @import("../core/native_effect.zig");
const consumers = @import("../core/native_consumer.zig");
const detection = @import("../core/native_detection_record.zig");
const Error = @import("store.zig").Error;

pub fn Methods(comptime Store: type) type {
    return struct {
        const PolicyTransition = Store.PolicyTransition;
        const HistoryResetScope = @import("store.zig").HistoryResetScope;
        const effectBlob = Store.effectBlob;
        const effectLease = Store.effectLease;
        const retryPoliciesEqual = Store.retryPoliciesEqual;
        const bindSubjectAt = Store.bindSubjectAt;
        pub fn transitionRetryPolicy(self: *Store, jail: []const u8, generation: [32]u8, expected: retry.Policy, next: retry.Policy) Error!void {
            try self.beginWrite();
            errdefer self.rollback();
            if (self.schema_version < 22) return error.AdminStorageRequired;
            try self.transitionJailGenerationTx(.{ .jail = jail, .generation = generation, .next_generation = generation, .expected = expected, .next = next }, std.time.microTimestamp());
            try self.bumpAdminRevisionTx();
            try self.fault(.before_policy_transition_commit);
            try self.commitTransaction();
        }
        fn transitionJailGenerationTx(self: *Store, change: PolicyTransition, now_us: i64) Error!void {
            const jail = change.jail;
            if (jail.len == 0 or jail.len > 64 or std.mem.indexOfScalar(u8, jail, 0) != null) return error.InvalidRecord;
            const encoded = try change.next.encode();
            const escalation = try change.next.escalation.encode();
            const saved = try self.readRetryPolicy(jail) orelse return error.RetryAdmissionRequired;
            if (!std.mem.eql(u8, &saved.generation, &change.generation)) return error.RetryGenerationMismatch;
            if (!try retryPoliciesEqual(saved.policy, change.expected)) return error.StalePolicyTransition;
            var pending = try self.statement("SELECT 1 FROM pending_receipts WHERE jail=?1 LIMIT 1;");
            defer pending.deinit();
            try pending.text(1, jail);
            if (try pending.row()) return error.RetryPolicyInFlight;
            {
                var update = try self.statement("UPDATE retry_policies SET generation=?4,policy=?2 WHERE jail=?1 AND generation=?3;");
                defer update.deinit();
                try update.text(1, jail);
                try update.blob(2, &encoded);
                try update.blob(3, &change.generation);
                try update.blob(4, &change.next_generation);
                try update.done();
                if (self.api.changes(self.db) != 1) return error.StalePolicyTransition;
            }
            {
                var update = try self.statement("UPDATE retry_escalation_policies SET generation=?4,policy=?2 WHERE jail=?1 AND generation=?3;");
                defer update.deinit();
                try update.text(1, jail);
                try update.blob(2, &escalation);
                try update.blob(3, &change.generation);
                try update.blob(4, &change.next_generation);
                try update.done();
                if (self.api.changes(self.db) != 1) return error.StalePolicyTransition;
            }
            if (std.mem.eql(u8, &change.generation, &change.next_generation)) return;
            try self.exec("PRAGMA defer_foreign_keys=ON;");
            var discarded = Store.RekeyReport{ .retry_rows = 0, .pending_receipts = 0, .manifests = 0, .cursors = 0 };
            try self.rekeyGenerationTablesTx(jail, change.generation, change.next_generation, &discarded);
            if (change.cursor_rebinding) |rebinding| {
                var old_fragment: [256]u8 = undefined;
                var new_fragment: [256]u8 = undefined;
                const old_text = try cursorBindingFragment(&old_fragment, rebinding.old);
                const new_text = try cursorBindingFragment(&new_fragment, rebinding.new);
                var update = try self.statement("UPDATE source_cursors SET cursor=CAST(replace(CAST(cursor AS TEXT),?2,?3) AS BLOB) WHERE jail=?1;");
                defer update.deinit();
                try update.text(1, jail);
                try update.text(2, old_text);
                try update.text(3, new_text);
                try update.done();
            }
            if (try self.rekeyOwnersTx(jail, change.generation, change.next_generation, now_us, error.StalePolicyTransition)) self.rekeyed_owners = true;
            var stale = try self.statement("SELECT 1 FROM effect_owners WHERE jail=?1 AND generation!=?2 LIMIT 1;");
            defer stale.deinit();
            try stale.text(1, jail);
            try stale.blob(2, &change.next_generation);
            if (try stale.row()) return error.StalePolicyTransition;
        }

        pub const ConfigIgnoreUpdate = struct {
            jail: []const u8,
            entries: []const @import("shared").types.TimedEntry,
            deadlines: []?i64,
        };

        pub const ConfigConsumerUpdate = struct { manifest: consumers.Manifest, batch: consumers.Batch };

        pub fn commitReloadGeneration(self: *Store, transitions: []const PolicyTransition, record: ConfigGenerationRecord, jails: []const ConfigGenerationJail, ignores: []const ConfigIgnoreUpdate, custom: []const ConfigConsumerUpdate, admitted_jails: []const []const u8, retired_jails: []const []const u8, retention: Store.RetentionUpdate, clock: effects.Clock) Error!void {
            if (transitions.len > 64 or ignores.len > 64 or custom.len > 64 or admitted_jails.len > 64 or retired_jails.len > 64) return error.InvalidAdminRequest;
            for (admitted_jails, 0..) |name, i| {
                _ = detection.Name.init(name) catch return error.InvalidAdminRequest;
                for (admitted_jails[0..i]) |prior| if (std.mem.eql(u8, prior, name)) return error.InvalidAdminRequest;
            }
            for (retired_jails, 0..) |name, i| {
                _ = detection.Name.init(name) catch return error.InvalidAdminRequest;
                for (retired_jails[0..i]) |prior| if (std.mem.eql(u8, prior, name)) return error.InvalidAdminRequest;
            }
            for (custom, 0..) |update, i| {
                if (update.batch.deltas.len != 1) return error.InvalidAdminRequest;
                const delta = update.batch.deltas[0];
                if (delta.key.kind != .ignore or !std.mem.eql(u8, delta.key.jail, update.manifest.jail) or !std.mem.eql(u8, delta.key.source, "@shared") or !std.mem.eql(u8, delta.key.rule, "allowlist") or delta.expected_revision == 0) return error.InvalidAdminRequest;
                for (custom[0..i]) |previous| if (std.mem.eql(u8, previous.manifest.jail, update.manifest.jail)) return error.InvalidAdminRequest;
            }
            try self.beginWrite();
            errdefer self.rollback();
            if (self.schema_version < 22) return error.AdminStorageRequired;
            for (retired_jails) |name| try self.beginJailRetirementTx(name, false);
            for (admitted_jails) |name| try self.admitRetryProjectionJailTx(name);
            self.rekeyed_owners = false;
            const now = try self.effectClock(clock);
            for (custom) |update| try self.applyConsumerInputTx(update.manifest, update.batch, false);
            for (transitions) |change| try self.transitionJailGenerationTx(change, now);
            for (ignores) |change| try self.applyConfigDeadlines(.ignoreip, change.jail, change.entries, record.committed_us, change.deadlines);
            if (self.rekeyed_owners) _ = try self.commitEffectClock(clock);
            try self.bumpAdminRevisionTx();
            const mutation_revision = try self.integer("SELECT mutation_revision FROM admin_revision WHERE id=1;");
            var pinned = record;
            pinned.mutation_revision = @intCast(mutation_revision);
            pinned.published = true;
            try self.exec("UPDATE config_generations SET published=0 WHERE published=1;");
            try self.recordConfigGenerationTx(pinned, jails);
            _ = try self.applyRetentionPolicyTx(retention);
            try self.fault(.before_config_generation_commit);
            try self.commitEffectTransaction(self.rekeyed_owners);
            self.rekeyed_owners = false;
        }

        fn cursorBindingFragment(buffer: []u8, binding: [32]u8) Error![]const u8 {
            var stream = std.io.fixedBufferStream(buffer);
            const w = stream.writer();
            w.writeAll("\"codec_configuration_hash\":[") catch return error.InvalidAdminRequest;
            for (binding, 0..) |byte, i| {
                if (i != 0) w.writeByte(',') catch return error.InvalidAdminRequest;
                w.print("{d}", .{byte}) catch return error.InvalidAdminRequest;
            }
            w.writeByte(']') catch return error.InvalidAdminRequest;
            return stream.getWritten();
        }
        fn bumpAdminRevisionTx(self: *Store) Error!void {
            const current = try self.integer("SELECT mutation_revision FROM admin_revision WHERE id=1;");
            if (current < 0 or current == std.math.maxInt(i64)) return error.DatabaseFailure;
            var update = try self.statement("UPDATE admin_revision SET mutation_revision=?1 WHERE id=1;");
            defer update.deinit();
            try update.int(1, current + 1);
            try update.done();
            if (self.api.changes(self.db) != 1) return error.DatabaseFailure;
        }

        pub const ConfigGenerationRecord = struct {
            generation: [32]u8,
            config_digest: [32]u8,
            config_path: []const u8,
            committed_us: i64,
            published: bool,
            mutation_revision: u64,
        };
        pub const ConfigGenerationJail = struct {
            jail: []const u8,
            digest: [32]u8,
            allowlist_snapshot: []const u8,
        };

        pub fn recordConfigGeneration(self: *Store, record: ConfigGenerationRecord, jails: []const ConfigGenerationJail, retention: Store.RetentionUpdate) Error!void {
            try self.beginAdmissionWrite();
            errdefer self.rollback();
            if (self.schema_version < 22) return error.AdminStorageRequired;
            try self.recordConfigGenerationTx(record, jails);
            _ = try self.applyRetentionPolicyTx(retention);
            try self.fault(.before_config_generation_commit);
            try self.commitTransaction();
        }
        fn recordConfigGenerationTx(self: *Store, record: ConfigGenerationRecord, jails: []const ConfigGenerationJail) Error!void {
            if (record.config_path.len == 0 or record.config_path.len > 4096 or record.committed_us < 0 or record.mutation_revision > std.math.maxInt(i64) or jails.len > 64) return error.InvalidAdminRequest;
            for (jails) |jail| if (jail.jail.len == 0 or jail.jail.len > 64 or jail.allowlist_snapshot.len > 65536) return error.InvalidAdminRequest;
            {
                var exists = try self.statement("SELECT 1 FROM config_generations WHERE generation=?1;");
                defer exists.deinit();
                try exists.blob(1, &record.generation);
                if (try exists.row()) return error.ConfigGenerationExists;
            }
            {
                var insert = try self.statement("INSERT INTO config_generations VALUES(?1,?2,?3,?4,?5,?6);");
                defer insert.deinit();
                try insert.blob(1, &record.generation);
                try insert.blob(2, &record.config_digest);
                try insert.text(3, record.config_path);
                try insert.int(4, record.committed_us);
                try insert.int(5, @intFromBool(record.published));
                try insert.int(6, @intCast(record.mutation_revision));
                try insert.done();
            }
            for (jails) |jail| {
                var insert = try self.statement("INSERT INTO config_generation_jails VALUES(?1,?2,?3,?4);");
                defer insert.deinit();
                try insert.blob(1, &record.generation);
                try insert.text(2, jail.jail);
                try insert.blob(3, &jail.digest);
                try insert.blob(4, jail.allowlist_snapshot);
                try insert.done();
            }
        }

        pub fn publishConfigGeneration(self: *Store, generation: [32]u8) Error!void {
            try self.beginWrite();
            errdefer self.rollback();
            if (self.schema_version < 22) return error.AdminStorageRequired;
            try self.exec("UPDATE config_generations SET published=0 WHERE published=1;");
            var update = try self.statement("UPDATE config_generations SET published=1 WHERE generation=?1;");
            defer update.deinit();
            try update.blob(1, &generation);
            try update.done();
            if (self.api.changes(self.db) != 1) return error.ConfigGenerationMissing;
            try self.fault(.before_config_generation_publish);
            try self.commitTransaction();
        }

        pub fn discardUnpublishedConfigGeneration(self: *Store, generation: [32]u8) Error!void {
            try self.beginWrite();
            errdefer self.rollback();
            if (self.schema_version < 22) return error.AdminStorageRequired;
            var delete = try self.statement("DELETE FROM config_generations WHERE generation=?1 AND published=0;");
            defer delete.deinit();
            try delete.blob(1, &generation);
            try delete.done();
            try self.commitTransaction();
        }

        pub const ConfigGenerationHead = struct { generation: [32]u8, config_digest: [32]u8, published: bool, committed_us: i64 };
        pub fn latestConfigGeneration(self: *Store) Error!?ConfigGenerationHead {
            if (self.schema_version < 22) return error.AdminStorageRequired;
            var row = try self.statement("SELECT generation,config_digest,published,committed_us FROM config_generations ORDER BY committed_us DESC, generation DESC LIMIT 1;");
            defer row.deinit();
            if (!try row.row()) return null;
            return .{ .generation = try effectBlob(&row, 0, 32), .config_digest = try effectBlob(&row, 1, 32), .published = (try row.signed(2)) == 1, .committed_us = try row.signed(3) };
        }

        pub const AdminKind = enum(u8) { group_enable = 1, group_disable, group_pause, group_resume, setting_batch, ban, unban, history_reset, migration_activate, migration_rollback, ignore_add, ignore_remove, repair_source, firewall_withdraw };
        pub const AdminOutcome = enum(u8) { applied = 1, rejected, absent, partial, uncertain };
        pub const admin_request_retention = 4096;
        pub const admin_request_max_age_us: i64 = 30 * 24 * 60 * 60 * 1_000_000;
        pub const AdminRequestRecord = struct {
            request_id: [32]u8,
            kind: AdminKind,
            subject: []const u8,
            outcome: AdminOutcome,
            generation: [32]u8,
            committed_us: i64,
            detail: []const u8,
            admission_revision: ?u64 = null,
        };
        pub fn adminDecisionId(request_id: [32]u8, admission_revision: u64) [32]u8 {
            var revision: [8]u8 = undefined;
            std.mem.writeInt(u64, &revision, admission_revision, .little);
            return effects.hashParts("fail2zig-admin-decision-v2", &.{ &request_id, &revision });
        }
        pub const AdminReplay = struct { kind: AdminKind, outcome: AdminOutcome, mutation_revision: u64 };
        pub const AdminAdmission = union(enum) { fresh, replayed: AdminReplay };
        const unpinned_admin_request = "NOT (kind=2 AND outcome IN(4,5) AND EXISTS(SELECT 1 FROM jail_admin_states s WHERE s.jail=CAST(admin_requests.subject AS TEXT) AND s.enabled=0 AND s.request_id=admin_requests.request_id AND EXISTS(SELECT 1 FROM config_generation_jails c WHERE c.generation=?2 AND c.jail=s.jail)))";
        pub const JailAdminState = struct {
            jail: []const u8,
            enabled: bool,
            paused: bool,
            generation: [32]u8,
            changed_us: i64,
            request_id: [32]u8,
        };

        pub fn admitAdminRequest(self: *Store, request_id: [32]u8, expected_mutation_revision: u64) Error!AdminAdmission {
            if (std.mem.allEqual(u8, &request_id, 0)) return error.InvalidAdminRequest;
            try self.beginRead();
            errdefer self.rollback();
            if (self.schema_version < 22) return error.AdminStorageRequired;
            var row = try self.statement("SELECT kind,outcome,mutation_revision FROM admin_requests WHERE request_id=?1;");
            defer row.deinit();
            try row.blob(1, &request_id);
            if (try row.row()) {
                const kind = std.meta.intToEnum(AdminKind, try row.signed(0)) catch return error.DatabaseFailure;
                const outcome = std.meta.intToEnum(AdminOutcome, try row.signed(1)) catch return error.DatabaseFailure;
                const recorded_revision = try row.signed(2);
                try self.commitTransaction();
                return .{ .replayed = .{ .kind = kind, .outcome = outcome, .mutation_revision = @intCast(recorded_revision) } };
            }
            const current = try self.integer("SELECT mutation_revision FROM admin_revision WHERE id=1;");
            try self.commitTransaction();
            if (current < 0 or @as(u64, @intCast(current)) != expected_mutation_revision) return error.StaleAdminRevision;
            return .fresh;
        }

        pub fn finishAdminRequest(self: *Store, record: AdminRequestRecord, state: ?JailAdminState) Error!u64 {
            if (std.mem.allEqual(u8, &record.request_id, 0) or record.subject.len > 4096 or record.detail.len > 4096 or record.committed_us < 0) return error.InvalidAdminRequest;
            if (state) |value| if (value.jail.len == 0 or value.jail.len > 64 or value.changed_us < 0) return error.InvalidAdminRequest;
            try self.beginWrite();
            errdefer self.rollback();
            if (self.schema_version < 22) return error.AdminStorageRequired;
            if (@intFromEnum(record.kind) >= @intFromEnum(AdminKind.ignore_add) and self.schema_version < @import("store.zig").latest_schema) return error.AdminStorageRequired;
            if (record.admission_revision) |value| if (value > std.math.maxInt(i64)) return error.InvalidAdminRequest;
            if (record.outcome != .rejected) try self.bumpAdminRevisionTx();
            const mutation_revision = try self.integer("SELECT mutation_revision FROM admin_revision WHERE id=1;");
            if (mutation_revision < 0) return error.DatabaseFailure;
            {
                var insert = try self.statement(if (self.schema_version >= @import("store.zig").load_repair_schema)
                    "INSERT INTO admin_requests(request_id,kind,subject,outcome,generation,mutation_revision,committed_us,detail,admission_revision) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9);"
                else
                    "INSERT INTO admin_requests(request_id,kind,subject,outcome,generation,mutation_revision,committed_us,detail) VALUES(?1,?2,?3,?4,?5,?6,?7,?8);");
                defer insert.deinit();
                try insert.blob(1, &record.request_id);
                try insert.int(2, @intFromEnum(record.kind));
                try insert.blob(3, record.subject);
                try insert.int(4, @intFromEnum(record.outcome));
                try insert.blob(5, &record.generation);
                try insert.int(6, mutation_revision);
                try insert.int(7, record.committed_us);
                try insert.blob(8, record.detail);
                if (self.schema_version >= @import("store.zig").load_repair_schema) {
                    if (record.admission_revision) |value| try insert.int(9, @intCast(value));
                } else if (record.admission_revision != null) return error.AdminStorageRequired;
                try insert.done();
            }
            if (state) |value| {
                var upsert = try self.statement("INSERT INTO jail_admin_states VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(jail) DO UPDATE SET enabled=excluded.enabled,paused=excluded.paused,generation=excluded.generation,changed_us=excluded.changed_us,request_id=excluded.request_id;");
                defer upsert.deinit();
                try upsert.text(1, value.jail);
                try upsert.int(2, @intFromBool(value.enabled));
                try upsert.int(3, @intFromBool(value.paused));
                try upsert.blob(4, &value.generation);
                try upsert.int(5, value.changed_us);
                try upsert.blob(6, &value.request_id);
                try upsert.done();
            }
            {
                var age = try self.statement("DELETE FROM admin_requests WHERE committed_us<?1 AND " ++ unpinned_admin_request ++ ";");
                defer age.deinit();
                try age.int(1, record.committed_us -| admin_request_max_age_us);
                try age.blob(2, &record.generation);
                try age.done();
            }
            {
                var overflow = try self.statement("DELETE FROM admin_requests WHERE request_id IN (SELECT request_id FROM admin_requests WHERE " ++ unpinned_admin_request ++ " ORDER BY mutation_revision ASC, committed_us ASC LIMIT max(0,(SELECT count(*) FROM admin_requests)-?1));");
                defer overflow.deinit();
                try overflow.int(1, admin_request_retention);
                try overflow.blob(2, &record.generation);
                try overflow.done();
            }
            try self.fault(.after_admin_request);
            try self.commitTransaction();
            return @intCast(mutation_revision);
        }

        pub fn updateJailDisableOutcome(self: *Store, jail: []const u8, request_id: effects.Hash, expected: AdminOutcome, next: AdminOutcome, detail: []const u8, effect_epoch: u64, committed_us: i64) Error!?u64 {
            if ((expected != .partial and expected != .uncertain) or (next != .partial and next != .uncertain and next != .applied) or detail.len > 4096 or committed_us < 0) return error.InvalidAdminRequest;
            if (expected == next) return null;
            try self.beginWrite();
            errdefer self.rollback();
            if (self.schema_version < 22) return error.AdminStorageRequired;
            if (next == .applied and effect_epoch != self.effect_publication_epoch) return error.StaleEffect;
            {
                var row = try self.statement("SELECT a.outcome FROM admin_requests a JOIN jail_admin_states s ON s.jail=?1 WHERE a.request_id=?2 AND a.kind=2 AND a.subject=CAST(?1 AS BLOB) AND s.enabled=0 AND s.request_id=a.request_id;");
                defer row.deinit();
                try row.text(1, jail);
                try row.blob(2, &request_id);
                if (!try row.row() or try row.signed(0) != @intFromEnum(expected)) {
                    try self.commitTransaction();
                    return null;
                }
            }
            try self.bumpAdminRevisionTx();
            const revision = try self.integer("SELECT mutation_revision FROM admin_revision WHERE id=1;");
            if (revision < 0) return error.DatabaseFailure;
            var update = try self.statement("UPDATE admin_requests SET outcome=?3,mutation_revision=?4,committed_us=?5,detail=?6 WHERE request_id=?1 AND kind=2 AND subject=CAST(?2 AS BLOB) AND outcome=?7;");
            defer update.deinit();
            try update.blob(1, &request_id);
            try update.text(2, jail);
            try update.int(3, @intFromEnum(next));
            try update.int(4, revision);
            try update.int(5, committed_us);
            try update.blob(6, detail);
            try update.int(7, @intFromEnum(expected));
            try update.done();
            if (self.api.changes(self.db) != 1) return error.StaleAdminRevision;
            try self.fault(.after_admin_request);
            try self.commitTransaction();
            return @intCast(revision);
        }

        pub fn jailAdminState(self: *Store, jail: []const u8, output: *JailAdminState) Error!bool {
            if (self.schema_version < 22) return error.AdminStorageRequired;
            var row = try self.statement("SELECT enabled,paused,generation,changed_us,request_id FROM jail_admin_states WHERE jail=?1;");
            defer row.deinit();
            try row.text(1, jail);
            if (!try row.row()) return false;
            output.* = .{ .jail = jail, .enabled = (try row.signed(0)) == 1, .paused = (try row.signed(1)) == 1, .generation = try effectBlob(&row, 2, 32), .changed_us = try row.signed(3), .request_id = try effectBlob(&row, 4, 32) };
            return true;
        }

        pub fn currentOwner(self: *Store, key: effects.Hash, jail: []const u8) Error!?effects.Owner {
            try self.beginRead();
            errdefer self.rollback();
            var row = try self.statement(self.originSql("SELECT generation,decision_id,revision,lease_kind,deadline_us,decided_us,", "origin", " FROM effect_owners WHERE scope_key=?1 AND jail=?2;"));
            defer row.deinit();
            try row.blob(1, &key);
            try row.text(2, jail);
            if (!try row.row()) {
                try self.commitTransaction();
                return null;
            }
            const effect_revision = try row.signed(2);
            if (effect_revision <= 0) return error.InvalidEffect;
            const owner = effects.Owner{ .jail = detection.Name.init(jail) catch return error.InvalidEffect, .generation = try effectBlob(&row, 0, 32), .decision_id = try effectBlob(&row, 1, 32), .revision = @intCast(effect_revision), .lease = try effectLease(&row, 3, 4), .decided_us = try row.signed(5), .origin = try Store.storedOrigin(&row, 6) };
            try self.commitTransaction();
            return owner;
        }

        pub fn historyResetRevision(self: *Store, scope: HistoryResetScope, subject: detection.Subject) Error!u64 {
            if (self.schema_version < 20) return error.HistoryResetStorageRequired;
            const scope_value: i64 = switch (scope) {
                .jail => 1,
                .overall => 2,
            };
            const jail = switch (scope) {
                .jail => |name| name,
                .overall => "",
            };
            try self.beginRead();
            errdefer self.rollback();
            var row = try self.statement("SELECT revision FROM history_reset_watermarks WHERE scope=?1 AND jail=?2 AND family=?3 AND subject=?4;");
            defer row.deinit();
            try row.int(1, scope_value);
            try row.text(2, jail);
            try bindSubjectAt(&row, &subject, 3);
            const prior: u64 = if (try row.row()) @intCast(@max(0, try row.signed(0))) else 0;
            try self.commitTransaction();
            return prior;
        }
    };
}
