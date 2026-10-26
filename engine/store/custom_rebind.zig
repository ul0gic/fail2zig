// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const store = @import("store.zig");
const consumers = @import("../core/native_consumer.zig");
const detection = @import("../core/native_detection_record.zig");
const effects = @import("../core/native_effect.zig");
const retry = @import("../core/native_retry.zig");
const files = @import("../core/durable_file_source.zig");
const journal = @import("../core/native_journal_session.zig");
const processor = @import("../core/native_source_processor.zig");
const Error = store.Error;

fn hash(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}
fn same(a: [32]u8, b: [32]u8) bool {
    return std.mem.eql(u8, &a, &b);
}

pub fn Methods(comptime Store: type) type {
    return struct {
        pub fn rekeyConsumerManifestsTx(self: *Store, jail: []const u8, old: [32]u8, new: [32]u8) Error!u32 {
            var after: [store.Limits.source_bytes]u8 = undefined;
            var after_len: usize = 0;
            var examined: usize = 0;
            var changed: u32 = 0;
            while (true) {
                var arena = std.heap.ArenaAllocator.init(self.allocator);
                defer arena.deinit();
                const allocator = arena.allocator();
                const source = blk: {
                    var row = try self.statement("SELECT source,generation FROM consumer_manifests WHERE jail=?1 AND source>?2 ORDER BY source LIMIT 1;");
                    defer row.deinit();
                    try row.text(1, jail);
                    try row.text(2, after[0..after_len]);
                    if (!try row.row()) break;
                    if (examined == 4096) return error.ConsumerCapacity;
                    examined += 1;
                    if (self.api.column_type(row.ptr, 0) != 3) return error.InvalidConsumer;
                    const value = try row.boundedBytes(0, after.len);
                    if (value.len == 0) return error.InvalidConsumer;
                    @memcpy(after[0..value.len], value);
                    after_len = value.len;
                    if (!same(try Store.effectBlob(&row, 1, 32), old)) continue;
                    break :blk allocator.dupe(u8, value) catch return error.OutOfMemory;
                };
                var requirements: [consumers.max_dependencies]consumers.Requirement = undefined;
                var count: usize = 0;
                {
                    var row = try self.statement("SELECT kind,jail,source,rule,generation,format FROM consumer_requirements WHERE manifest_jail=?1 AND manifest_source=?2 LIMIT 17;");
                    defer row.deinit();
                    try row.text(1, jail);
                    try row.text(2, source);
                    while (try row.row()) {
                        if (count == requirements.len) return error.ConsumerCapacity;
                        const kind = std.meta.intToEnum(consumers.Kind, try row.signed(0)) catch return error.InvalidConsumer;
                        const format = std.math.cast(u16, try row.signed(5)) orelse return error.InvalidConsumer;
                        inline for (.{ 1, 2, 3 }) |column| if (self.api.column_type(row.ptr, column) != 3) return error.InvalidConsumer;
                        requirements[count] = .{ .key = .{
                            .kind = kind,
                            .jail = allocator.dupe(u8, try row.boundedBytes(1, 64)) catch return error.OutOfMemory,
                            .source = allocator.dupe(u8, try row.boundedBytes(2, store.Limits.source_bytes)) catch return error.OutOfMemory,
                            .rule = allocator.dupe(u8, try row.boundedBytes(3, 64)) catch return error.OutOfMemory,
                            .generation = try Store.effectBlob(&row, 4, 32),
                        }, .format_version = format };
                        count += 1;
                    }
                }
                var manifest = consumers.Manifest{ .jail = jail, .source = source, .source_generation = old, .required = requirements[0..count] };
                const status = try self.checkManifest(manifest);
                const old_digest = try manifest.digest();
                manifest.source_generation = new;
                const new_digest = try manifest.digest();
                var update = try self.statement("UPDATE consumer_manifests SET generation=?3,digest=?4 WHERE jail=?1 AND source=?2 AND generation=?5 AND digest=?6 AND ready=?7;");
                defer update.deinit();
                try update.text(1, jail);
                try update.text(2, source);
                try update.blob(3, &new);
                try update.blob(4, &new_digest);
                try update.blob(5, &old);
                try update.blob(6, &old_digest);
                try update.int(7, @intFromEnum(status));
                try update.done();
                if (self.api.changes(self.db) != 1) return error.StaleConsumerCheckpoint;
                changed += 1;
            }
            if (changed != 0) try self.bumpConsumerRevision();
            return changed;
        }
        pub const CustomEvidenceCursor = struct { generation: [32]u8, jail: detection.Name };
        pub const CustomEvidence = struct {
            cursor: CustomEvidenceCursor,
            digest: [32]u8,
            published: bool,
            payload: []u8,
            pub fn deinit(self: CustomEvidence, allocator: std.mem.Allocator) void {
                allocator.free(self.payload);
            }
        };
        pub const CustomRebindTarget = struct {
            jail: detection.Name,
            old_parent: [32]u8,
            new_parent: [32]u8,
            old_generation: [32]u8,
            new_generation: [32]u8,
            cursors: Store.CursorRekey,
            expected_consumer_revision: u64,
            expected_checkpoint_revision: u64,
            old_ignore_revision: u64,
            old_ignore_sha256: [32]u8,
            evidence: ?CustomEvidenceCursor,
            evidence_sha256: [32]u8,
            source_count: u16,
            source_proof_sha256: [32]u8,
        };
        pub const CustomCheckpointRebind = struct {
            old_key: consumers.Key,
            new_key: consumers.Key,
            old_format: u16,
            new_format: u16,
            revision: u64,
            old_payload_sha256: [32]u8,
            new_payload: []const u8,
            valid_until_us: ?i64,
        };
        pub const CustomSourceRebind = struct {
            old_manifest: consumers.Manifest,
            new_manifest: consumers.Manifest,
            status: Store.ManifestStatus,
            expected_consumer_revision: u64,
            checkpoints: []const CustomCheckpointRebind,
        };
        pub const CustomIdentityPhase = enum { records, pending_receipts, source_cursors, checkpoint, retry_retired, source_maintenance, replay_guards, owners, policies, orphan_check, done };
        pub const CustomIdentityCursor = struct {
            phase: CustomIdentityPhase = .records,
            after_rowid: ?i64 = null,
            expected_consumer_revision: u64,
            examined: u64 = 0,
            changed: u64 = 0,
            owners_changed: bool = false,
        };
        pub const CustomIdentityProgress = struct { cursor: CustomIdentityCursor, consumer_revision: u64, done: bool };

        pub const CustomIgnoreState = struct {
            parent: [32]u8,
            value: Store.ConsumerSnapshot,
            consumer_revision: u64,
            pub fn deinit(self: CustomIgnoreState, allocator: std.mem.Allocator) void {
                self.value.deinit(allocator);
            }
        };
        pub fn customIgnoreState(self: *Store, allocator: std.mem.Allocator, jail: []const u8) Error!?CustomIgnoreState {
            _ = detection.Name.init(jail) catch return error.InvalidConsumer;
            try self.beginRead();
            errdefer self.rollback();
            var parent: ?[32]u8 = null;
            {
                var row = try self.statement("SELECT generation FROM consumer_checkpoints WHERE kind=4 AND jail=?1 AND source='@shared' AND rule='allowlist' ORDER BY generation LIMIT 2;");
                defer row.deinit();
                try row.text(1, jail);
                if (try row.row()) parent = try Store.effectBlob(&row, 0, 32);
                if (parent != null and try row.row()) return error.ConsumerManifestMismatch;
            }
            const generation = parent orelse {
                try self.commitTransaction();
                return null;
            };
            const value = try self.consumerSnapshot(allocator, .{ .kind = .ignore, .jail = jail, .source = "@shared", .rule = "allowlist", .generation = generation });
            errdefer value.deinit(allocator);
            if (value.revision == 0 or value.payload == null) return error.InvalidConsumer;
            const revision = try self.consumerRevision();
            try self.commitTransaction();
            return .{ .parent = generation, .value = value, .consumer_revision = revision };
        }

        pub fn customEvidenceNext(self: *Store, allocator: std.mem.Allocator, after: ?CustomEvidenceCursor) Error!?CustomEvidence {
            if (after) |cursor| {
                if (cursor.jail.len == 0 or cursor.jail.len > cursor.jail.bytes.len) return error.InvalidConsumer;
                _ = detection.Name.init(cursor.jail.slice()) catch return error.InvalidConsumer;
            }
            try self.beginRead();
            errdefer self.rollback();
            var result: ?CustomEvidence = null;
            errdefer if (result) |value| value.deinit(allocator);
            {
                var row = try self.statement(if (after != null)
                    "SELECT generation,jail,digest,allowlist_snapshot FROM config_generation_jails WHERE (generation,jail)>(?1,?2) ORDER BY generation,jail LIMIT 1;"
                else
                    "SELECT generation,jail,digest,allowlist_snapshot FROM config_generation_jails ORDER BY generation,jail LIMIT 1;");
                defer row.deinit();
                if (after) |*cursor| {
                    try row.blob(1, &cursor.generation);
                    try row.text(2, cursor.jail.slice());
                }
                if (try row.row()) {
                    if (self.api.column_type(row.ptr, 1) != 3 or self.api.column_type(row.ptr, 3) != 4) return error.InvalidRecord;
                    const cursor = CustomEvidenceCursor{ .generation = try Store.effectBlob(&row, 0, 32), .jail = detection.Name.init(try row.boundedBytes(1, 64)) catch return error.InvalidRecord };
                    const digest = try Store.effectBlob(&row, 2, 32);
                    const payload = try row.boundedBytes(3, consumers.max_payload);
                    result = .{ .cursor = cursor, .digest = digest, .published = false, .payload = try allocator.dupe(u8, payload) };
                }
            }
            if (result) |*value| {
                var row = try self.statement("SELECT published FROM config_generations WHERE generation=?1;");
                defer row.deinit();
                try row.blob(1, &value.cursor.generation);
                if (!try row.row()) return error.InvalidRecord;
                const published = try row.signed(0);
                if (published != 0 and published != 1) return error.InvalidRecord;
                value.published = published == 1;
            }
            try self.commitTransaction();
            return result;
        }

        fn customIgnoreKey(target: *const CustomRebindTarget, old: bool) consumers.Key {
            return .{ .kind = .ignore, .jail = target.jail.slice(), .source = "@shared", .rule = "allowlist", .generation = if (old) target.old_parent else target.new_parent };
        }
        fn customStartup(self: *Store, target: *const CustomRebindTarget, revision: u64) Error!void {
            if (!self.startupAdmissionActive()) return error.InvalidConsumer;
            if (target.jail.len == 0 or target.jail.len > target.jail.bytes.len) return error.InvalidConsumer;
            _ = detection.Name.init(target.jail.slice()) catch return error.InvalidConsumer;
            if (same(target.old_parent, target.new_parent) or same(target.old_generation, target.new_generation) or target.source_count == 0 or target.source_count > 4096 or revision > std.math.maxInt(i64) or target.expected_checkpoint_revision > std.math.maxInt(i64) or target.old_ignore_revision == 0 or target.old_ignore_revision > std.math.maxInt(i64)) return error.InvalidConsumer;
            try self.beginAdmissionWrite();
            errdefer self.rollback();
            if (try self.consumerRevision() != revision) return error.StaleConsumerCheckpoint;
        }
        fn customCheckpointFenceTx(self: *Store, target: *const CustomRebindTarget) Error!void {
            var row = try self.statement("SELECT revision FROM checkpoints WHERE jail=?1;");
            defer row.deinit();
            try row.text(1, target.jail.slice());
            const revision: i64 = if (try row.row()) try row.signed(0) else 0;
            if (revision < 0 or revision != @as(i64, @intCast(target.expected_checkpoint_revision))) return error.StaleCheckpoint;
        }
        fn customEvidenceFenceTx(self: *Store, target: *const CustomRebindTarget) Error!void {
            const cursor = target.evidence orelse return;
            if (cursor.jail.len == 0 or cursor.jail.len > cursor.jail.bytes.len) return error.InvalidConsumer;
            if (!std.mem.eql(u8, cursor.jail.slice(), target.jail.slice())) return error.ConsumerManifestMismatch;
            var row = try self.statement("SELECT j.allowlist_snapshot,g.published FROM config_generation_jails j JOIN config_generations g USING(generation) WHERE j.generation=?1 AND j.jail=?2;");
            defer row.deinit();
            try row.blob(1, &cursor.generation);
            try row.text(2, cursor.jail.slice());
            if (!try row.row() or self.api.column_type(row.ptr, 0) != 4) return error.CustomLegacyProofRequired;
            const head = try row.signed(1);
            if (head != 0 and head != 1) return error.InvalidRecord;
            if (!same(hash(try row.boundedBytes(0, consumers.max_payload)), target.evidence_sha256)) return error.StaleConsumerCheckpoint;
        }
        fn customChangeShape(change: *const CustomCheckpointRebind) Error!void {
            try change.old_key.validate();
            try change.new_key.validate();
            if (change.old_key.kind != change.new_key.kind or !std.mem.eql(u8, change.old_key.jail, change.new_key.jail) or !std.mem.eql(u8, change.old_key.source, change.new_key.source) or !std.mem.eql(u8, change.old_key.rule, change.new_key.rule) or same(change.old_key.generation, change.new_key.generation) or change.old_format == 0 or change.new_format == 0 or change.revision == 0 or change.revision > std.math.maxInt(i64) or change.new_payload.len > consumers.max_payload) return error.InvalidConsumer;
        }
        fn customCheckOldTx(self: *Store, change: *const CustomCheckpointRebind) Error!void {
            var row = try self.statement("SELECT format,revision,valid_until_us,payload FROM consumer_checkpoints WHERE kind=?1 AND jail=?2 AND source=?3 AND rule=?4 AND generation=?5;");
            defer row.deinit();
            try Store.bindConsumerKey(&row, &change.old_key);
            if (!try row.row()) return error.StaleConsumerCheckpoint;
            if (try row.signed(0) != change.old_format or try row.signed(1) != change.revision or try row.optionalSigned(2) != change.valid_until_us or self.api.column_type(row.ptr, 3) != 4) return error.StaleConsumerCheckpoint;
            if (!same(hash(try row.boundedBytes(3, consumers.max_payload)), change.old_payload_sha256)) return error.StaleConsumerCheckpoint;
        }
        fn customInsertTx(self: *Store, change: *const CustomCheckpointRebind) Error!void {
            {
                var row = try self.statement("SELECT 1 FROM consumer_checkpoints WHERE kind=?1 AND jail=?2 AND source=?3 AND rule=?4 AND generation=?5;");
                defer row.deinit();
                try Store.bindConsumerKey(&row, &change.new_key);
                if (try row.row()) return error.ConsumerManifestExists;
            }
            var row = try self.statement("INSERT INTO consumer_checkpoints(kind,jail,source,rule,generation,format,revision,payload,valid_until_us) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9);");
            defer row.deinit();
            try Store.bindConsumerKey(&row, &change.new_key);
            try row.int(6, change.new_format);
            try row.int(7, @intCast(change.revision));
            try row.blob(8, change.new_payload);
            if (change.valid_until_us) |expiry| try row.int(9, expiry);
            try row.done();
        }
        fn customUnreferencedTx(self: *Store, key: *const consumers.Key) Error!bool {
            var row = try self.statement("SELECT 1 FROM consumer_requirements INDEXED BY consumer_requirement_identity WHERE kind=?1 AND jail=?2 AND source=?3 AND rule=?4 AND generation=?5 LIMIT 1;");
            defer row.deinit();
            try Store.bindConsumerKey(&row, key);
            return !try row.row();
        }
        fn customDeleteTx(self: *Store, key: *const consumers.Key) Error!void {
            if (!try self.customUnreferencedTx(key)) return error.ConsumerManifestMismatch;
            var row = try self.statement("DELETE FROM consumer_checkpoints WHERE kind=?1 AND jail=?2 AND source=?3 AND rule=?4 AND generation=?5;");
            defer row.deinit();
            try Store.bindConsumerKey(&row, key);
            try row.done();
            if (self.api.changes(self.db) != 1) return error.StaleConsumerCheckpoint;
        }
        pub fn rebindUnopenedCustom(self: *Store, target: *const CustomRebindTarget) Error!void {
            if (!self.startupAdmissionActive()) return error.InvalidConsumer;
            if (target.jail.len == 0 or target.jail.len > target.jail.bytes.len) return error.InvalidConsumer;
            _ = detection.Name.init(target.jail.slice()) catch return error.InvalidConsumer;
            if (target.source_count != 0 or target.old_ignore_revision != 0 or target.expected_checkpoint_revision != 0 or same(target.old_parent, target.new_parent) or same(target.old_generation, target.new_generation) or target.expected_consumer_revision > std.math.maxInt(i64)) return error.InvalidConsumer;
            if (target.evidence == null) return error.CustomLegacyProofRequired;
            try self.beginAdmissionWrite();
            errdefer self.rollback();
            if (try self.consumerRevision() != target.expected_consumer_revision) return error.StaleConsumerCheckpoint;
            try self.customEvidenceFenceTx(target);
            // Each refusal uses an existing jail-leading primary key or explicit index prefix.
            for ([_][:0]const u8{
                "SELECT 1 FROM checkpoints WHERE jail=?1 LIMIT 1;",
                "SELECT 1 FROM records WHERE jail=?1 LIMIT 1;",
                "SELECT 1 FROM pending_receipts WHERE jail=?1 LIMIT 1;",
                "SELECT 1 FROM source_cursors WHERE jail=?1 LIMIT 1;",
                "SELECT 1 FROM source_maintenance WHERE jail=?1 LIMIT 1;",
                "SELECT 1 FROM replay_guards WHERE jail=?1 LIMIT 1;",
                "SELECT 1 FROM consumer_manifests WHERE jail=?1 LIMIT 1;",
                "SELECT 1 FROM action_intents WHERE jail=?1 LIMIT 1;",
                "SELECT 1 FROM retry_states WHERE jail=?1 LIMIT 1;",
                "SELECT 1 FROM retry_retired WHERE jail=?1 LIMIT 1;",
                "SELECT 1 FROM retry_retired_totals WHERE jail=?1 LIMIT 1;",
                "SELECT 1 FROM retry_decisions WHERE jail=?1 LIMIT 1;",
                "SELECT 1 FROM retry_decision_details WHERE jail=?1 LIMIT 1;",
                "SELECT 1 FROM retry_decision_escalations WHERE jail=?1 LIMIT 1;",
                "SELECT 1 FROM consumer_requirements WHERE manifest_jail=?1 LIMIT 1;",
                "SELECT 1 FROM effect_owners INDEXED BY effect_owners_jail WHERE jail=?1 LIMIT 1;",
            }) |sql| {
                var row = try self.statement(sql);
                defer row.deinit();
                try row.text(1, target.jail.slice());
                if (try row.row()) return error.ConsumerManifestMismatch;
            }
            for ([_]consumers.Kind{ .rule, .correlation, .dns, .ignore, .history }) |kind| {
                for ([_][:0]const u8{
                    "SELECT 1 FROM consumer_checkpoints WHERE kind=?1 AND jail=?2 LIMIT 1;",
                    "SELECT 1 FROM consumer_requirements INDEXED BY consumer_requirement_identity WHERE kind=?1 AND jail=?2 LIMIT 1;",
                }) |sql| {
                    var row = try self.statement(sql);
                    defer row.deinit();
                    try row.int(1, @intFromEnum(kind));
                    try row.text(2, target.jail.slice());
                    if (try row.row()) return error.ConsumerManifestMismatch;
                }
            }
            const saved = try self.readRetryPolicy(target.jail.slice()) orelse return error.RetryAdmissionRequired;
            if (!same(saved.generation, target.old_generation)) return error.RetryGenerationMismatch;
            var policy: [retry.policy_bytes]u8 = undefined;
            var escalation: [retry.escalation_bytes]u8 = undefined;
            {
                var row = try self.statement("SELECT p.policy,e.policy FROM retry_policies p JOIN retry_escalation_policies e USING(jail) WHERE p.jail=?1 AND p.generation=?2 AND e.generation=?2;");
                defer row.deinit();
                try row.text(1, target.jail.slice());
                try row.blob(2, &target.old_generation);
                if (!try row.row()) return error.RetryGenerationMismatch;
                policy = try Store.effectBlob(&row, 0, policy.len);
                escalation = try Store.effectBlob(&row, 1, escalation.len);
            }
            for ([_][:0]const u8{
                "UPDATE retry_policies SET generation=?3 WHERE jail=?1 AND generation=?2 AND policy=?4;",
                "UPDATE retry_escalation_policies SET generation=?3 WHERE jail=?1 AND generation=?2 AND policy=?4;",
            }, 0..) |sql, i| {
                var row = try self.statement(sql);
                defer row.deinit();
                try row.text(1, target.jail.slice());
                try row.blob(2, &target.old_generation);
                try row.blob(3, &target.new_generation);
                if (i == 0) try row.blob(4, &policy) else try row.blob(4, &escalation);
                try row.done();
                if (self.api.changes(self.db) != 1) return error.RetryGenerationMismatch;
            }
            try self.fault(.before_consumer_input_commit);
            try self.commitTransaction();
        }

        pub fn stageCustomIgnoreRebind(self: *Store, target: *const CustomRebindTarget, change: CustomCheckpointRebind) Error!u64 {
            try self.customStartup(target, target.expected_consumer_revision);
            errdefer self.rollback();
            try customChangeShape(&change);
            if (!consumers.Key.eql(change.old_key, customIgnoreKey(target, true)) or !consumers.Key.eql(change.new_key, customIgnoreKey(target, false)) or change.revision != target.old_ignore_revision or !same(change.old_payload_sha256, target.old_ignore_sha256) or change.valid_until_us != null or change.old_format != 1 or change.new_format != 2) return error.ConsumerManifestMismatch;
            try self.customCheckpointFenceTx(target);
            try self.customEvidenceFenceTx(target);
            try self.customCheckOldTx(&change);
            try self.customInsertTx(&change);
            try self.bumpConsumerRevision();
            const revision = try self.consumerRevision();
            try self.fault(.before_consumer_input_commit);
            try self.commitTransaction();
            return revision;
        }

        pub fn rebindCustomSource(self: *Store, target: *const CustomRebindTarget, source: CustomSourceRebind) Error!u64 {
            try self.customStartup(target, source.expected_consumer_revision);
            errdefer self.rollback();
            const old = source.old_manifest;
            const new = source.new_manifest;
            _ = try old.digest();
            const digest = try new.digest();
            if (source.status != .ready or source.checkpoints.len == 0 or source.checkpoints.len > 8 or !std.mem.eql(u8, old.jail, target.jail.slice()) or !std.mem.eql(u8, new.jail, old.jail) or !std.mem.eql(u8, old.source, new.source) or !same(old.source_generation, target.old_generation) or !same(new.source_generation, target.new_generation) or old.required.len != new.required.len) return error.ConsumerManifestMismatch;
            var bytes: usize = 0;
            for (source.checkpoints, 0..) |*change, i| {
                try customChangeShape(change);
                if ((change.old_key.kind != .rule and change.old_key.kind != .correlation) or !std.mem.eql(u8, change.old_key.jail, old.jail) or !std.mem.eql(u8, change.old_key.source, old.source)) return error.ConsumerManifestMismatch;
                for (source.checkpoints[0..i]) |previous| if (consumers.Key.eql(previous.old_key, change.old_key) or consumers.Key.eql(previous.new_key, change.new_key)) return error.InvalidConsumer;
                bytes = std.math.add(usize, bytes, change.new_payload.len + change.old_key.source.len + change.new_key.source.len + change.old_key.rule.len + change.new_key.rule.len + change.old_key.jail.len + change.new_key.jail.len) catch return error.ConsumerCapacity;
                if (bytes > consumers.max_prepared_bytes) return error.ConsumerCapacity;
            }
            var shared_ignore: usize = 0;
            var authorities: usize = 0;
            for (old.required) |required| {
                var replacement = required;
                if (consumers.Key.eql(required.key, customIgnoreKey(target, true))) {
                    if (required.format_version != 1) return error.ConsumerManifestMismatch;
                    shared_ignore += 1;
                    replacement.key = customIgnoreKey(target, false);
                    replacement.format_version = 2;
                } else if (required.key.kind == .rule or required.key.kind == .correlation) {
                    var found = false;
                    for (source.checkpoints) |change| if (consumers.Key.eql(required.key, change.old_key) and required.format_version == change.old_format) {
                        replacement = .{ .key = change.new_key, .format_version = change.new_format };
                        found = true;
                        break;
                    };
                    if (!found) return error.ConsumerManifestMismatch;
                } else if (required.key.kind == .dns) {
                    if (!std.mem.eql(u8, required.key.jail, "@shared") or !std.mem.eql(u8, required.key.source, "@resolver") or !std.mem.eql(u8, required.key.rule, "authority") or required.format_version != 1) return error.ConsumerManifestMismatch;
                    authorities += 1;
                } else return error.ConsumerManifestMismatch;
                for (new.required) |item| if (consumers.Key.eql(item.key, replacement.key) and item.format_version == replacement.format_version) break else continue else return error.ConsumerManifestMismatch;
            }
            if (shared_ignore != 1 or authorities > 1) return error.ConsumerManifestMismatch;
            for (source.checkpoints) |change| {
                if (change.old_format != 1 or change.new_format != 1) return error.ConsumerManifestMismatch;
                for (old.required) |required| if (consumers.Key.eql(required.key, change.old_key) and required.format_version == change.old_format) break else continue else return error.ConsumerManifestMismatch;
            }
            if (try self.checkManifest(old) != source.status) return error.StaleConsumerCheckpoint;
            for (old.required) |required| try self.checkRequiredState(required, false);
            for (source.checkpoints) |*change| {
                try self.customCheckOldTx(change);
                try self.customInsertTx(change);
            }
            {
                var row = try self.statement("DELETE FROM consumer_requirements WHERE manifest_jail=?1 AND manifest_source=?2;");
                defer row.deinit();
                try row.text(1, old.jail);
                try row.text(2, old.source);
                try row.done();
                if (self.api.changes(self.db) != old.required.len) return error.ConsumerManifestMismatch;
            }
            for (new.required) |required| {
                try self.checkRequiredState(required, false);
                var row = try self.statement("INSERT INTO consumer_requirements(kind,jail,source,rule,generation,manifest_jail,manifest_source,format) VALUES(?1,?2,?3,?4,?5,?6,?7,?8);");
                defer row.deinit();
                try Store.bindConsumerKey(&row, &required.key);
                try row.text(6, new.jail);
                try row.text(7, new.source);
                try row.int(8, required.format_version);
                try row.done();
            }
            {
                var row = try self.statement("UPDATE consumer_manifests SET generation=?3,digest=?4 WHERE jail=?1 AND source=?2 AND generation=?5 AND ready=1;");
                defer row.deinit();
                try row.text(1, new.jail);
                try row.text(2, new.source);
                try row.blob(3, &new.source_generation);
                try row.blob(4, &digest);
                try row.blob(5, &old.source_generation);
                try row.done();
                if (self.api.changes(self.db) != 1) return error.ConsumerManifestMismatch;
            }
            for (source.checkpoints) |*change| try self.customDeleteTx(&change.old_key);
            try self.bumpConsumerRevision();
            const revision = try self.consumerRevision();
            try self.fault(.before_consumer_input_commit);
            try self.commitTransaction();
            return revision;
        }
        fn customCursor(self: *Store, target: *const CustomRebindTarget, saved: []const u8) Error![]u8 {
            return switch (target.cursors) {
                .none => error.InvalidRecord,
                .file => |binding| files.FileSource.rebindCursor(self.allocator, saved, binding.legacy, binding.planned) catch |failure| switch (failure) {
                    error.OutOfMemory => error.OutOfMemory,
                    else => error.InvalidRecord,
                },
                .journal => blk: {
                    const converted = journal.rebindCheckpoint(saved, target.old_generation, target.new_generation) catch return error.InvalidRecord;
                    break :blk try self.allocator.dupe(u8, &converted);
                },
            };
        }
        fn customRawNextTx(self: *Store, phase: CustomIdentityPhase, after: ?i64, jail: []const u8) Error!?struct { rowid: i64, matches: bool } {
            const sql: [:0]const u8 = switch (phase) {
                .records => if (after != null) "SELECT rowid,jail FROM records WHERE rowid>?1 ORDER BY rowid LIMIT 1;" else "SELECT rowid,jail FROM records ORDER BY rowid LIMIT 1;",
                .pending_receipts => if (after != null) "SELECT rowid,jail FROM pending_receipts WHERE rowid>?1 ORDER BY rowid LIMIT 1;" else "SELECT rowid,jail FROM pending_receipts ORDER BY rowid LIMIT 1;",
                .source_cursors => if (after != null) "SELECT rowid,jail FROM source_cursors WHERE rowid>?1 ORDER BY rowid LIMIT 1;" else "SELECT rowid,jail FROM source_cursors ORDER BY rowid LIMIT 1;",
                .retry_retired => if (after != null) "SELECT rowid,jail FROM retry_retired WHERE rowid>?1 ORDER BY rowid LIMIT 1;" else "SELECT rowid,jail FROM retry_retired ORDER BY rowid LIMIT 1;",
                .source_maintenance => if (after != null) "SELECT rowid,jail FROM source_maintenance WHERE rowid>?1 ORDER BY rowid LIMIT 1;" else "SELECT rowid,jail FROM source_maintenance ORDER BY rowid LIMIT 1;",
                .replay_guards => if (after != null) "SELECT rowid,jail FROM replay_guards WHERE rowid>?1 ORDER BY rowid LIMIT 1;" else "SELECT rowid,jail FROM replay_guards ORDER BY rowid LIMIT 1;",
                .owners => if (after != null) "SELECT rowid,jail FROM effect_owners WHERE rowid>?1 ORDER BY rowid LIMIT 1;" else "SELECT rowid,jail FROM effect_owners ORDER BY rowid LIMIT 1;",
                .orphan_check => if (after != null) "SELECT rowid,jail FROM consumer_checkpoints WHERE rowid>?1 ORDER BY rowid LIMIT 1;" else "SELECT rowid,jail FROM consumer_checkpoints ORDER BY rowid LIMIT 1;",
                else => return error.InvalidConsumer,
            };
            var row = try self.statement(sql);
            defer row.deinit();
            if (after) |value| try row.int(1, value);
            if (!try row.row()) return null;
            if (self.api.column_type(row.ptr, 1) != 3) return error.InvalidRecord;
            return .{ .rowid = try row.signed(0), .matches = std.mem.eql(u8, try row.boundedBytes(1, 4096), jail) };
        }
        fn customRecordTx(self: *Store, target: *const CustomRebindTarget, rowid: i64, pending: bool) Error!bool {
            var saved: []u8 = undefined;
            {
                var row = try self.statement(if (pending)
                    "SELECT generation,NULL,cursor FROM pending_receipts WHERE rowid=?1;"
                else
                    "SELECT source_generation,receipt_generation,cursor FROM records WHERE rowid=?1;");
                defer row.deinit();
                try row.int(1, rowid);
                if (!try row.row()) return error.InvalidRecord;
                var matches = false;
                var foreign = false;
                for (0..2) |column| if (self.api.column_type(row.ptr, @intCast(column)) != 5) {
                    const generation = try Store.effectBlob(&row, @intCast(column), 32);
                    if (same(generation, target.new_generation)) return error.CustomLegacyIdentityMismatch;
                    matches = matches or same(generation, target.old_generation);
                    foreign = foreign or !same(generation, target.old_generation);
                };
                if (matches and foreign) return error.CustomLegacyIdentityMismatch;
                if (!matches) return false;
                if (self.api.column_type(row.ptr, 2) != 4) return error.InvalidRecord;
                saved = try self.allocator.dupe(u8, try row.boundedBytes(2, store.Limits.cursor_bytes));
            }
            defer self.allocator.free(saved);
            const converted = try self.customCursor(target, saved);
            defer self.allocator.free(converted);
            if (converted.len > store.Limits.cursor_bytes) return error.InvalidRecord;
            var row = try self.statement(if (pending)
                "UPDATE pending_receipts SET generation=?3,cursor=?4 WHERE rowid=?1 AND generation=?2;"
            else
                "UPDATE records SET source_generation=CASE WHEN source_generation=?2 THEN ?3 ELSE source_generation END,receipt_generation=CASE WHEN receipt_generation=?2 THEN ?3 ELSE receipt_generation END,cursor=?4 WHERE rowid=?1 AND (source_generation=?2 OR receipt_generation=?2);");
            defer row.deinit();
            try row.int(1, rowid);
            try row.blob(2, &target.old_generation);
            try row.blob(3, &target.new_generation);
            try row.blob(4, converted);
            try row.done();
            if (self.api.changes(self.db) != 1) return error.InvalidRecord;
            return true;
        }
        fn customSourceCursorTx(self: *Store, target: *const CustomRebindTarget, rowid: i64) Error!bool {
            const saved = blk: {
                var row = try self.statement("SELECT cursor FROM source_cursors WHERE rowid=?1;");
                defer row.deinit();
                try row.int(1, rowid);
                if (!try row.row() or self.api.column_type(row.ptr, 0) != 4) return error.InvalidRecord;
                break :blk try self.allocator.dupe(u8, try row.boundedBytes(0, store.Limits.cursor_bytes));
            };
            defer self.allocator.free(saved);
            const converted = try self.customCursor(target, saved);
            defer self.allocator.free(converted);
            if (converted.len > store.Limits.cursor_bytes) return error.InvalidRecord;
            var row = try self.statement("UPDATE source_cursors SET cursor=?2 WHERE rowid=?1;");
            defer row.deinit();
            try row.int(1, rowid);
            try row.blob(2, converted);
            try row.done();
            if (self.api.changes(self.db) != 1) return error.InvalidRecord;
            return true;
        }
        fn customJailCheckpointTx(self: *Store, target: *const CustomRebindTarget) Error!bool {
            var payload: [journal.checkpoint_bytes]u8 = undefined;
            var length: usize = 0;
            {
                var row = try self.statement("SELECT CAST(payload AS BLOB),revision,typeof(payload) FROM checkpoints WHERE jail=?1;");
                defer row.deinit();
                try row.text(1, target.jail.slice());
                if (!try row.row()) {
                    if (target.expected_checkpoint_revision != 0) return error.StaleCheckpoint;
                    return false;
                }
                if (try row.signed(1) != target.expected_checkpoint_revision) return error.StaleCheckpoint;
                const storage = try row.boundedBytes(2, 8);
                if (!std.mem.eql(u8, storage, "blob") and !std.mem.eql(u8, storage, "text")) return error.InvalidRecord;
                const saved = try row.boundedBytes(0, payload.len);
                if (saved.len < 4) return error.InvalidRecord;
                if (std.mem.eql(u8, saved[0..4], "F2NT")) {
                    var converted: [processor.checkpoint_bytes]u8 = undefined;
                    processor.Processor.rebindCheckpoint(target.old_generation, target.new_generation, saved, &converted) catch return error.InvalidRecord;
                    length = converted.len;
                    @memcpy(payload[0..length], &converted);
                } else if (std.mem.eql(u8, saved[0..4], "F2JC")) {
                    payload = journal.rebindCheckpoint(saved, target.old_generation, target.new_generation) catch return error.InvalidRecord;
                    length = payload.len;
                } else return error.InvalidRecord;
            }
            var row = try self.statement("UPDATE checkpoints SET payload=?2 WHERE jail=?1 AND revision=?3;");
            defer row.deinit();
            try row.text(1, target.jail.slice());
            try row.blob(2, payload[0..length]);
            try row.int(3, @intCast(target.expected_checkpoint_revision));
            try row.done();
            if (self.api.changes(self.db) != 1) return error.StaleCheckpoint;
            return true;
        }
        fn customGenerationRowTx(self: *Store, target: *const CustomRebindTarget, rowid: i64, maintenance: bool) Error!bool {
            var row = try self.statement(if (maintenance)
                "UPDATE source_maintenance SET generation=?3 WHERE rowid=?1 AND generation=?2;"
            else
                "UPDATE retry_retired SET generation=?3 WHERE rowid=?1 AND generation=?2;");
            defer row.deinit();
            try row.int(1, rowid);
            try row.blob(2, &target.old_generation);
            try row.blob(3, &target.new_generation);
            try row.done();
            return self.api.changes(self.db) == 1;
        }
        fn customGuardTx(self: *Store, target: *const CustomRebindTarget, rowid: i64) Error!bool {
            var source: []u8 = undefined;
            var sequence: i64 = undefined;
            var occurrence_key: [32]u8 = undefined;
            var identity_key: [32]u8 = undefined;
            var receipt_us: ?i64 = undefined;
            {
                var row = try self.statement("SELECT generation,source,source_sequence,occurrence_key,identity_key,receipt_us FROM replay_guards WHERE rowid=?1;");
                defer row.deinit();
                try row.int(1, rowid);
                if (!try row.row()) return error.InvalidMaintenanceState;
                if (!same(try Store.effectBlob(&row, 0, 32), target.old_generation)) return false;
                if (self.api.column_type(row.ptr, 1) != 3) return error.InvalidMaintenanceState;
                source = try self.allocator.dupe(u8, try row.boundedBytes(1, store.Limits.source_bytes));
                errdefer self.allocator.free(source);
                sequence = try row.signed(2);
                occurrence_key = try Store.effectBlob(&row, 3, 32);
                identity_key = try Store.effectBlob(&row, 4, 32);
                receipt_us = try row.optionalSigned(5);
                if (source.len == 0 or sequence <= 0) return error.InvalidMaintenanceState;
            }
            defer self.allocator.free(source);
            const maintenance = try self.sourceMaintenance(target.jail.slice(), source, target.new_generation) orelse return error.InvalidMaintenanceState;
            if (sequence > @as(i64, @intCast(maintenance.sweep_sequence))) {
                var row = try self.statement("SELECT occurrence,raw_hash,cursor,receipt_us,receipt_generation FROM records INDEXED BY records_source_order WHERE jail=?1 AND source=?2 AND source_generation=?3 AND source_sequence=?4;");
                defer row.deinit();
                try row.text(1, target.jail.slice());
                try row.text(2, source);
                try row.blob(3, &target.new_generation);
                try row.int(4, sequence);
                if (!try row.row() or self.api.column_type(row.ptr, 0) != 3 or self.api.column_type(row.ptr, 2) != 4 or try row.optionalSigned(3) != receipt_us) return error.InvalidMaintenanceState;
                if (receipt_us != null) {
                    if (!same(try Store.effectBlob(&row, 4, 32), target.new_generation)) return error.InvalidMaintenanceState;
                } else if (self.api.column_type(row.ptr, 4) != 5) return error.InvalidMaintenanceState;
                const identity = store.ReceiptIdentity{ .jail = target.jail.slice(), .source = source, .generation = target.new_generation, .occurrence = try row.boundedBytes(0, 16384), .raw_hash = try Store.effectBlob(&row, 1, 32), .cursor = try row.boundedBytes(2, store.Limits.cursor_bytes) };
                try Store.validateReceiptIdentity(identity);
                if (!same(Store.occurrenceGuardKey(identity.occurrence), occurrence_key)) return error.InvalidMaintenanceState;
                identity_key = Store.identityGuardKey(identity);
            }
            var row = try self.statement("UPDATE replay_guards SET generation=?3,identity_key=?4 WHERE rowid=?1 AND generation=?2;");
            defer row.deinit();
            try row.int(1, rowid);
            try row.blob(2, &target.old_generation);
            try row.blob(3, &target.new_generation);
            try row.blob(4, &identity_key);
            try row.done();
            if (self.api.changes(self.db) != 1) return error.InvalidMaintenanceState;
            return true;
        }
        fn customPoliciesTx(self: *Store, target: *const CustomRebindTarget) Error!bool {
            var changed = false;
            for ([_][:0]const u8{
                "UPDATE retry_policies SET generation=?3 WHERE jail=?1 AND generation=?2;",
                "UPDATE retry_escalation_policies SET generation=?3 WHERE jail=?1 AND generation=?2;",
            }) |sql| {
                var row = try self.statement(sql);
                defer row.deinit();
                try row.text(1, target.jail.slice());
                try row.blob(2, &target.old_generation);
                try row.blob(3, &target.new_generation);
                try row.done();
                changed = changed or self.api.changes(self.db) != 0;
            }
            var row = try self.statement("SELECT generation FROM retry_policies WHERE jail=?1;");
            defer row.deinit();
            try row.text(1, target.jail.slice());
            if (!try row.row() or !same(try Store.effectBlob(&row, 0, 32), target.new_generation)) return error.RetryGenerationMismatch;
            return changed;
        }
        fn customOrphanTx(self: *Store, target: *const CustomRebindTarget, rowid: i64) Error!void {
            var source_buffer: [store.Limits.source_bytes]u8 = undefined;
            var rule_buffer: [64]u8 = undefined;
            var key: consumers.Key = undefined;
            var format: i64 = undefined;
            {
                var row = try self.statement("SELECT kind,source,rule,generation,format FROM consumer_checkpoints WHERE rowid=?1;");
                defer row.deinit();
                try row.int(1, rowid);
                if (!try row.row() or self.api.column_type(row.ptr, 1) != 3 or self.api.column_type(row.ptr, 2) != 3) return error.InvalidConsumer;
                const source = try row.boundedBytes(1, source_buffer.len);
                const rule = try row.boundedBytes(2, rule_buffer.len);
                @memcpy(source_buffer[0..source.len], source);
                @memcpy(rule_buffer[0..rule.len], rule);
                key = .{ .kind = std.meta.intToEnum(consumers.Kind, try row.signed(0)) catch return error.InvalidConsumer, .jail = target.jail.slice(), .source = source_buffer[0..source.len], .rule = rule_buffer[0..rule.len], .generation = try Store.effectBlob(&row, 3, 32) };
                format = try row.signed(4);
                try key.validate();
            }
            if (consumers.Key.eql(key, customIgnoreKey(target, true))) return;
            if (key.kind != .rule and key.kind != .correlation and !consumers.Key.eql(key, customIgnoreKey(target, false))) return error.ConsumerManifestMismatch;
            var row = try self.statement("SELECT r.manifest_jail,r.manifest_source,r.format,m.generation,m.ready FROM consumer_requirements r INDEXED BY consumer_requirement_identity LEFT JOIN consumer_manifests m ON m.jail=r.manifest_jail AND m.source=r.manifest_source WHERE r.kind=?1 AND r.jail=?2 AND r.source=?3 AND r.rule=?4 AND r.generation=?5;");
            defer row.deinit();
            try Store.bindConsumerKey(&row, &key);
            var count: usize = 0;
            while (try row.row()) {
                count += 1;
                if (count > 4096 or !std.mem.eql(u8, try row.boundedBytes(0, 64), target.jail.slice()) or try row.signed(2) != format or !same(try Store.effectBlob(&row, 3, 32), target.new_generation) or try row.signed(4) != 1) return error.ConsumerManifestMismatch;
                if ((key.kind == .rule or key.kind == .correlation) and !std.mem.eql(u8, try row.boundedBytes(1, store.Limits.source_bytes), key.source)) return error.ConsumerManifestMismatch;
            }
            if (count == 0) return error.ConsumerManifestMismatch;
        }
        fn customOwnerPageTx(self: *Store, target: *const CustomRebindTarget, cursor: *CustomIdentityCursor, maximum: u8) Error!void {
            var held: [64]Store.OwnerHeld = undefined;
            var count: usize = 0;
            var raw: usize = 0;
            while (raw < maximum) : (raw += 1) {
                const next = try self.customRawNextTx(.owners, cursor.after_rowid, target.jail.slice()) orelse {
                    cursor.phase = .policies;
                    cursor.after_rowid = null;
                    break;
                };
                cursor.after_rowid = next.rowid;
                cursor.examined = std.math.add(u64, cursor.examined, 1) catch return error.ConsumerCapacity;
                if (next.matches) if (try self.readRekeyOwnerRowTx(next.rowid, target.jail.slice(), target.old_generation)) |owner| {
                    held[count] = owner;
                    count += 1;
                };
            }
            if (count == 0) return;
            const clock = effects.Clock{ .prepared_us = 0 };
            const now = try self.effectClock(clock);
            var live: i64 = 0;
            for (held[0..count]) |owner| if (!owner.absent) {
                live += 1;
            };
            try self.reserveEffectRows(.{ .revisions = @intCast(count), .intents = live, .observations = live * store.load_repair.observations_per_intent });
            if (try self.tableRows(.effect_owner_revisions) + @as(i64, @intCast(count)) > effects.max_owner_revisions) return error.EffectCapacity;
            for (held[0..count]) |owner| try self.rekeyOwnerHeldTx(owner, target.jail.slice(), target.old_generation, target.new_generation, now, error.StaleEffect);
            _ = try self.commitEffectClock(clock);
            cursor.changed = std.math.add(u64, cursor.changed, count) catch return error.ConsumerCapacity;
            cursor.owners_changed = true;
        }
        pub fn customIdentityStep(self: *Store, target: *const CustomRebindTarget, cursor: CustomIdentityCursor, max_rows: u8) Error!CustomIdentityProgress {
            if (max_rows == 0 or max_rows > 64) return error.InvalidConsumer;
            try self.customStartup(target, cursor.expected_consumer_revision);
            errdefer self.rollback();
            try self.exec("PRAGMA defer_foreign_keys=ON;");
            var next = cursor;
            if (cursor.phase == .owners) {
                try self.customOwnerPageTx(target, &next, max_rows);
            } else if (cursor.phase == .checkpoint or cursor.phase == .policies) {
                const changed = if (cursor.phase == .checkpoint) try self.customJailCheckpointTx(target) else try self.customPoliciesTx(target);
                if (changed) next.changed = std.math.add(u64, next.changed, 1) catch return error.ConsumerCapacity;
                next.phase = if (cursor.phase == .checkpoint) .retry_retired else .orphan_check;
                next.after_rowid = null;
            } else if (cursor.phase != .done) {
                var examined: u8 = 0;
                while (examined < max_rows) : (examined += 1) {
                    const raw = try self.customRawNextTx(cursor.phase, next.after_rowid, target.jail.slice()) orelse {
                        next.phase = switch (cursor.phase) {
                            .records => .pending_receipts,
                            .pending_receipts => .source_cursors,
                            .source_cursors => .checkpoint,
                            .retry_retired => .source_maintenance,
                            .source_maintenance => .replay_guards,
                            .replay_guards => .owners,
                            .orphan_check => .done,
                            else => return error.InvalidConsumer,
                        };
                        next.after_rowid = null;
                        break;
                    };
                    next.after_rowid = raw.rowid;
                    next.examined = std.math.add(u64, next.examined, 1) catch return error.ConsumerCapacity;
                    if (!raw.matches) continue;
                    const changed = switch (cursor.phase) {
                        .records => try self.customRecordTx(target, raw.rowid, false),
                        .pending_receipts => try self.customRecordTx(target, raw.rowid, true),
                        .source_cursors => try self.customSourceCursorTx(target, raw.rowid),
                        .retry_retired => try self.customGenerationRowTx(target, raw.rowid, false),
                        .source_maintenance => try self.customGenerationRowTx(target, raw.rowid, true),
                        .replay_guards => try self.customGuardTx(target, raw.rowid),
                        .orphan_check => blk: {
                            try self.customOrphanTx(target, raw.rowid);
                            break :blk false;
                        },
                        else => return error.InvalidConsumer,
                    };
                    if (changed) next.changed = std.math.add(u64, next.changed, 1) catch return error.ConsumerCapacity;
                }
            }
            if (next.changed != cursor.changed) try self.bumpConsumerRevision();
            const revision = try self.consumerRevision();
            next.expected_consumer_revision = revision;
            try self.fault(.before_consumer_input_commit);
            try self.commitTransaction();
            if (next.owners_changed != cursor.owners_changed or (cursor.phase == .owners and next.changed != cursor.changed)) self.startup_rebind_effects_changed = true;
            return .{ .cursor = next, .consumer_revision = revision, .done = next.phase == .done };
        }

        pub fn finishCustomRebind(self: *Store, target: *const CustomRebindTarget, expected_revision: u64, sources: u16, old_source_proof_sha256: [32]u8) Error!u64 {
            try self.customStartup(target, expected_revision);
            errdefer self.rollback();
            if (sources != target.source_count or !same(old_source_proof_sha256, target.source_proof_sha256)) return error.CustomLegacyIdentityMismatch;
            {
                var row = try self.statement("SELECT generation FROM retry_policies WHERE jail=?1;");
                defer row.deinit();
                try row.text(1, target.jail.slice());
                if (!try row.row() or !same(try Store.effectBlob(&row, 0, 32), target.new_generation)) return error.RetryGenerationMismatch;
            }
            const old_ignore = customIgnoreKey(target, true);
            try self.customDeleteTx(&old_ignore);
            try self.bumpConsumerRevision();
            const revision = try self.consumerRevision();
            try self.fault(.before_consumer_input_commit);
            try self.commitTransaction();
            return revision;
        }
    };
}
