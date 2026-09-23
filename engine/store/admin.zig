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
            const rekeyed = [_][:0]const u8{
                "UPDATE records SET source_generation=?3 WHERE jail=?1 AND source_generation=?2;",
                "UPDATE checkpoints SET payload=substr(payload,1,8)||?3||substr(payload,41) WHERE jail=?1 AND substr(payload,1,4)=CAST('F2NT' AS BLOB) AND substr(payload,9,32)=?2;",
                "UPDATE checkpoints SET payload=substr(payload,1,6)||?3||substr(payload,39) WHERE jail=?1 AND substr(payload,1,4)=CAST('F2JC' AS BLOB) AND substr(payload,7,32)=?2;",
                "UPDATE source_maintenance SET generation=?3 WHERE jail=?1 AND generation=?2;",
                "UPDATE replay_guards SET generation=?3 WHERE jail=?1 AND generation=?2;",
                "UPDATE consumer_checkpoints SET generation=?3 WHERE jail=?1 AND generation=?2;",
                "UPDATE consumer_manifests SET generation=?3 WHERE jail=?1 AND generation=?2;",
                "UPDATE consumer_requirements SET generation=?3 WHERE jail=?1 AND generation=?2;",
            };
            for (rekeyed) |sql| {
                var update = try self.statement(sql);
                defer update.deinit();
                try update.text(1, jail);
                try update.blob(2, &change.generation);
                try update.blob(3, &change.next_generation);
                try update.done();
            }
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
            const canonical_scope = @import("../firewall/scope.zig");
            const Held = struct { key: [32]u8, revision: u64, scope: [canonical_scope.encoded_bytes]u8 };
            var held = std.ArrayListUnmanaged(Held){};
            defer held.deinit(self.allocator);
            {
                var owners = try self.statement("SELECT o.scope_key,o.revision,n.canonical_scope FROM effect_owners o JOIN native_effects n USING(scope_key) WHERE o.jail=?1 AND o.generation=?2 ORDER BY o.scope_key;");
                defer owners.deinit();
                try owners.text(1, jail);
                try owners.blob(2, &change.generation);
                while (try owners.row()) {
                    if (held.items.len == effects.max_effects) return error.EffectCapacity;
                    const owner_revision = try owners.signed(1);
                    if (owner_revision <= 0) return error.InvalidEffect;
                    try held.append(self.allocator, .{ .key = try effectBlob(&owners, 0, 32), .revision = @intCast(owner_revision), .scope = try effectBlob(&owners, 2, canonical_scope.encoded_bytes) });
                }
            }
            for (held.items) |owner| {
                const scope = canonical_scope.Scope.decode(&owner.scope) catch return error.InvalidEffect;
                const transition_id = effects.hashParts("fail2zig-generation-rekey-v1", &.{ &change.next_generation, &owner.key });
                _ = try self.transitionOwnerTx(.{ .scope = scope, .jail = jail, .current_generation = change.generation, .next_generation = change.next_generation, .expected_owner_revision = owner.revision, .transition_id = transition_id, .mode = .retain, .occurred_us = now_us }, now_us);
            }
            if (held.items.len != 0) self.rekeyed_owners = true;
            var stale = try self.statement("SELECT 1 FROM effect_owners WHERE jail=?1 AND generation!=?2 LIMIT 1;");
            defer stale.deinit();
            try stale.text(1, jail);
            try stale.blob(2, &change.next_generation);
            if (try stale.row()) return error.StalePolicyTransition;
        }

        pub fn commitReloadGeneration(self: *Store, transitions: []const PolicyTransition, record: ConfigGenerationRecord, jails: []const ConfigGenerationJail, clock: effects.Clock) Error!void {
            if (transitions.len > 64) return error.InvalidAdminRequest;
            try self.beginWrite();
            errdefer self.rollback();
            if (self.schema_version < 22) return error.AdminStorageRequired;
            self.rekeyed_owners = false;
            const now = try self.effectClock(clock);
            for (transitions) |change| try self.transitionJailGenerationTx(change, now);
            if (self.rekeyed_owners) _ = try self.commitEffectClock(clock);
            try self.bumpAdminRevisionTx();
            const mutation_revision = try self.integer("SELECT mutation_revision FROM admin_revision WHERE id=1;");
            var pinned = record;
            pinned.mutation_revision = @intCast(mutation_revision);
            pinned.published = true;
            try self.exec("UPDATE config_generations SET published=0 WHERE published=1;");
            try self.recordConfigGenerationTx(pinned, jails);
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

        pub fn recordConfigGeneration(self: *Store, record: ConfigGenerationRecord, jails: []const ConfigGenerationJail) Error!void {
            try self.beginWrite();
            errdefer self.rollback();
            if (self.schema_version < 22) return error.AdminStorageRequired;
            try self.recordConfigGenerationTx(record, jails);
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

        pub const AdminKind = enum(u8) { group_enable = 1, group_disable, group_pause, group_resume, setting_batch, ban, unban, history_reset, migration_activate, migration_rollback };
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
        };
        pub const AdminReplay = struct { kind: AdminKind, outcome: AdminOutcome, mutation_revision: u64 };
        pub const AdminAdmission = union(enum) { fresh, replayed: AdminReplay };
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
            if (record.outcome != .rejected) try self.bumpAdminRevisionTx();
            const mutation_revision = try self.integer("SELECT mutation_revision FROM admin_revision WHERE id=1;");
            if (mutation_revision < 0) return error.DatabaseFailure;
            {
                var insert = try self.statement("INSERT INTO admin_requests VALUES(?1,?2,?3,?4,?5,?6,?7,?8);");
                defer insert.deinit();
                try insert.blob(1, &record.request_id);
                try insert.int(2, @intFromEnum(record.kind));
                try insert.blob(3, record.subject);
                try insert.int(4, @intFromEnum(record.outcome));
                try insert.blob(5, &record.generation);
                try insert.int(6, mutation_revision);
                try insert.int(7, record.committed_us);
                try insert.blob(8, record.detail);
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
                var age = try self.statement("DELETE FROM admin_requests WHERE committed_us<?1;");
                defer age.deinit();
                try age.int(1, record.committed_us -| admin_request_max_age_us);
                try age.done();
            }
            {
                var overflow = try self.statement("DELETE FROM admin_requests WHERE request_id IN (SELECT request_id FROM admin_requests ORDER BY mutation_revision ASC, committed_us ASC LIMIT max(0,(SELECT count(*) FROM admin_requests)-?1));");
                defer overflow.deinit();
                try overflow.int(1, admin_request_retention);
                try overflow.done();
            }
            try self.fault(.after_admin_request);
            try self.commitTransaction();
            return @intCast(mutation_revision);
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
            var row = try self.statement("SELECT generation,decision_id,revision,lease_kind,deadline_us,decided_us FROM effect_owners WHERE scope_key=?1 AND jail=?2;");
            defer row.deinit();
            try row.blob(1, &key);
            try row.text(2, jail);
            if (!try row.row()) {
                try self.commitTransaction();
                return null;
            }
            const effect_revision = try row.signed(2);
            if (effect_revision <= 0) return error.InvalidEffect;
            const owner = effects.Owner{ .jail = detection.Name.init(jail) catch return error.InvalidEffect, .generation = try effectBlob(&row, 0, 32), .decision_id = try effectBlob(&row, 1, 32), .revision = @intCast(effect_revision), .lease = try effectLease(&row, 3, 4), .decided_us = try row.signed(5) };
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
