// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const consumers = @import("../core/native_consumer.zig");
const detection = @import("../core/native_detection_record.zig");
const retry = @import("../core/native_retry.zig");
const effects = @import("../core/native_effect.zig");
const application_history = @import("../core/native_application_history.zig");
const effect_history = @import("../core/native_effect_history.zig");
const action_context = @import("../core/native_action_context.zig");
const store = @import("store.zig");
const Error = store.Error;
const Stmt = store.Stmt;
const Limits = store.Limits;
const latest_schema = store.latest_schema;
const Record = store.Record;
const EscalationSelection = store.EscalationSelection;
const max_native_detections = store.max_native_detections;

pub fn Methods(comptime Store: type) type {
    return struct {
        const SourceMaintenance = Store.SourceMaintenance;
        pub const ManifestMode = enum { first_use, @"resume" };
        pub const ManifestStatus = enum { first_use, ready };
        pub const ManifestSnapshot = struct {
            status: ManifestStatus,
            digest: [32]u8,
            revision: u64,
            count: usize = 0,
            states: [consumers.max_dependencies]ConsumerSnapshot = undefined,
            pub fn deinit(self: *ManifestSnapshot, allocator: std.mem.Allocator) void {
                for (self.states[0..self.count]) |state| state.deinit(allocator);
                self.count = 0;
            }
        };
        pub const ManifestKey = struct {
            source: []u8,
            generation: [32]u8,
            digest: [32]u8,
            status: ManifestStatus,
            pub fn deinit(self: ManifestKey, allocator: std.mem.Allocator) void {
                allocator.free(self.source);
            }
        };
        pub const ManifestPage = struct { revision: u64, count: usize, more: bool };
        fn consumerHash(row: *Stmt, column: c_int) Error![32]u8 {
            if (row.store.api.column_type(row.ptr, column) != 4) return error.InvalidConsumer;
            const bytes = try row.boundedBytes(column, 32);
            if (bytes.len != 32) return error.InvalidConsumer;
            return bytes[0..32].*;
        }
        pub fn consumerRevision(self: *Store) Error!u64 {
            var row = try self.statement("SELECT revision FROM consumer_revision WHERE id=1;");
            defer row.deinit();
            if (!try row.row()) return error.InvalidConsumer;
            const current_revision = try row.signed(0);
            if (current_revision < 0) return error.InvalidConsumer;
            return @intCast(current_revision);
        }
        fn bumpConsumerRevision(self: *Store) Error!void {
            if (try self.consumerRevision() == std.math.maxInt(i64)) return error.ConsumerCapacity;
            try self.exec("UPDATE consumer_revision SET revision=revision+1 WHERE id=1;");
            if (self.api.changes(self.db) != 1) return error.InvalidConsumer;
        }
        pub fn consumerManifestKeysPage(self: *Store, allocator: std.mem.Allocator, jail: []const u8, after_source: ?[]const u8, expected_revision: ?u64, output: []ManifestKey) Error!ManifestPage {
            if (output.len == 0 or output.len > consumers.max_dependencies or jail.len == 0 or jail.len > 64 or std.mem.indexOfScalar(u8, jail, 0) != null) return error.InvalidConsumer;
            if (after_source) |after| if (after.len == 0 or after.len > Limits.source_bytes or std.mem.indexOfScalar(u8, after, 0) != null) return error.InvalidConsumer;
            try self.beginRead();
            errdefer self.rollback();
            try self.requireManifestSchema();
            const current_revision = try self.consumerRevision();
            if (expected_revision) |expected| if (expected != current_revision) return error.StaleConsumerCheckpoint;
            var row = try self.statement("SELECT source,generation,digest,ready,required_count FROM consumer_manifests WHERE jail=?1 AND source>COALESCE(?2,'') ORDER BY source LIMIT ?3;");
            defer row.deinit();
            try row.text(1, jail);
            if (after_source) |after| try row.text(2, after);
            try row.int(3, @intCast(output.len + 1));
            var count: usize = 0;
            errdefer for (output[0..count]) |entry| entry.deinit(allocator);
            while (try row.row()) {
                if (count == output.len) {
                    try self.commitTransaction();
                    return .{ .revision = current_revision, .count = count, .more = true };
                }
                if (self.api.column_type(row.ptr, 0) != 3) return error.InvalidConsumer;
                const source = try row.boundedBytes(0, Limits.source_bytes);
                if (source.len == 0 or std.mem.indexOfScalar(u8, source, 0) != null) return error.InvalidConsumer;
                const generation = try consumerHash(&row, 1);
                const digest = try consumerHash(&row, 2);
                const ready = try row.signed(3);
                const required = try row.signed(4);
                if (ready < 0 or ready > 1 or required < 0 or required > consumers.max_dependencies) return error.InvalidConsumer;
                output[count] = .{ .source = try allocator.dupe(u8, source), .generation = generation, .digest = digest, .status = if (ready == 1) .ready else .first_use };
                count += 1;
            }
            try self.commitTransaction();
            return .{ .revision = current_revision, .count = count, .more = false };
        }
        fn requireManifestSchema(self: *Store) Error!void {
            const schema = try self.integer("PRAGMA user_version;");
            if (schema < 12 or schema > latest_schema) return error.ConsumerStorageRequired;
            self.schema_version = schema;
        }
        pub fn manifestExists(self: *Store, jail: []const u8, source: []const u8) Error!bool {
            var row = try self.statement("SELECT 1 FROM consumer_manifests WHERE jail=?1 AND source=?2;");
            defer row.deinit();
            try row.text(1, jail);
            try row.text(2, source);
            return row.row();
        }
        pub fn checkManifest(self: *Store, manifest: consumers.Manifest) Error!ManifestStatus {
            const digest = try manifest.digest();
            var row = try self.statement("SELECT generation,digest,ready,required_count FROM consumer_manifests WHERE jail=?1 AND source=?2;");
            defer row.deinit();
            try row.text(1, manifest.jail);
            try row.text(2, manifest.source);
            if (!try row.row()) return error.ConsumerManifestMissing;
            if (!std.mem.eql(u8, &try consumerHash(&row, 0), &manifest.source_generation) or
                !std.mem.eql(u8, &try consumerHash(&row, 1), &digest)) return error.ConsumerManifestMismatch;
            const ready = try row.signed(2);
            if (ready < 0 or ready > 1 or try row.signed(3) != manifest.required.len) return error.InvalidConsumer;
            var count = try self.statement("SELECT count(*) FROM consumer_requirements WHERE manifest_jail=?1 AND manifest_source=?2;");
            defer count.deinit();
            try count.text(1, manifest.jail);
            try count.text(2, manifest.source);
            if (!try count.row() or try count.signed(0) != manifest.required.len) return error.InvalidConsumer;
            for (manifest.required) |requirement| {
                var item = try self.statement("SELECT format FROM consumer_requirements WHERE kind=?1 AND jail=?2 AND source=?3 AND rule=?4 AND generation=?5 AND manifest_jail=?6 AND manifest_source=?7;");
                defer item.deinit();
                try bindConsumerKey(&item, &requirement.key);
                try item.text(6, manifest.jail);
                try item.text(7, manifest.source);
                if (!try item.row() or try item.signed(0) != requirement.format_version) return error.InvalidConsumer;
            }
            if (ready == 0) {
                var history = try self.statement("SELECT 1 FROM records WHERE jail=?1 AND source=?2 LIMIT 1;");
                defer history.deinit();
                try history.text(1, manifest.jail);
                try history.text(2, manifest.source);
                if (try history.row()) return error.MissingRequiredConsumer;
            }
            return if (ready == 1) .ready else .first_use;
        }
        pub fn checkRequiredState(self: *Store, requirement: consumers.Requirement, missing_allowed: bool) Error!void {
            var row = try self.statement("SELECT format,revision,typeof(payload),length(payload),valid_until_us,payload FROM consumer_checkpoints WHERE kind=?1 AND jail=?2 AND source=?3 AND rule=?4 AND generation=?5;");
            defer row.deinit();
            try bindConsumerKey(&row, &requirement.key);
            if (!try row.row()) {
                if (!missing_allowed) return error.MissingRequiredConsumer;
                return;
            }
            if (try row.signed(0) != requirement.format_version or try row.signed(1) <= 0 or
                !std.mem.eql(u8, try row.boundedBytes(2, 8), "blob") or try row.signed(3) > consumers.max_payload)
                return error.InvalidConsumer;
            const expiry = try row.optionalSigned(4);
            if (dnsAuthority(requirement.key) and (requirement.format_version != 1 or try row.signed(1) != 1 or expiry != null or
                !std.mem.eql(u8, try row.boundedBytes(5, 32), &requirement.key.generation))) return error.InvalidConsumer;
        }
        pub fn admitManifestTx(self: *Store, manifest: consumers.Manifest) Error!void {
            const digest = try manifest.digest();
            if (try self.manifestExists(manifest.jail, manifest.source)) return error.ConsumerManifestExists;
            if (try self.integer("SELECT count(*) FROM consumer_manifests;") >= 4096 or
                try self.integer("SELECT count(*) FROM consumer_requirements;") > 65536 - manifest.required.len) return error.ConsumerCapacity;
            var old = try self.statement("SELECT 1 FROM records WHERE jail=?1 AND source=?2 UNION ALL SELECT 1 FROM pending_receipts WHERE jail=?1 AND source=?2 LIMIT 1;");
            defer old.deinit();
            try old.text(1, manifest.jail);
            try old.text(2, manifest.source);
            if (try old.row()) return error.ConsumerMigrationRequired;
            for (manifest.required) |requirement| {
                var incompatible = try self.statement("SELECT 1 FROM consumer_checkpoints WHERE kind=?1 AND jail=?2 AND source=?3 AND rule=?4 AND (generation!=?5 OR format!=?6) UNION ALL SELECT 1 FROM consumer_requirements WHERE kind=?1 AND jail=?2 AND source=?3 AND rule=?4 AND (generation!=?5 OR format!=?6) LIMIT 1;");
                defer incompatible.deinit();
                try bindConsumerKey(&incompatible, &requirement.key);
                try incompatible.int(6, requirement.format_version);
                if (try incompatible.row()) return error.ConsumerMigrationRequired;
                var prior = try self.statement("SELECT 1 FROM consumer_checkpoints c WHERE kind=?1 AND jail=?2 AND source=?3 AND rule=?4 AND generation=?5 AND NOT EXISTS(SELECT 1 FROM consumer_requirements r WHERE r.kind=c.kind AND r.jail=c.jail AND r.source=c.source AND r.rule=c.rule AND r.generation=c.generation AND r.format=c.format);");
                defer prior.deinit();
                try bindConsumerKey(&prior, &requirement.key);
                if (try prior.row()) return error.ConsumerMigrationRequired;
                try self.checkRequiredState(requirement, true);
            }
            var insert = try self.statement("INSERT INTO consumer_manifests VALUES(?1,?2,?3,?4,0,?5);");
            defer insert.deinit();
            try insert.text(1, manifest.jail);
            try insert.text(2, manifest.source);
            try insert.blob(3, &manifest.source_generation);
            try insert.blob(4, &digest);
            try insert.int(5, @intCast(manifest.required.len));
            try insert.done();
            for (manifest.required) |requirement| {
                var item = try self.statement("INSERT INTO consumer_requirements(kind,jail,source,rule,generation,manifest_jail,manifest_source,format) VALUES(?1,?2,?3,?4,?5,?6,?7,?8);");
                defer item.deinit();
                try bindConsumerKey(&item, &requirement.key);
                try item.text(6, manifest.jail);
                try item.text(7, manifest.source);
                try item.int(8, requirement.format_version);
                try item.done();
            }
        }
        pub fn admitConsumerManifest(self: *Store, manifest: consumers.Manifest, mode: ManifestMode) Error!void {
            _ = try manifest.digest();
            try self.beginWrite();
            errdefer self.rollback();
            try self.requireManifestSchema();
            switch (mode) {
                .first_use => try self.admitManifestTx(manifest),
                .@"resume" => {
                    const status = try self.checkManifest(manifest);
                    for (manifest.required) |requirement| try self.checkRequiredState(requirement, status == .first_use);
                },
            }
            if (mode == .first_use) try self.bumpConsumerRevision();
            try self.fault(.before_manifest_commit);
            try self.commitTransaction();
        }
        pub fn consumerManifestSnapshot(self: *Store, allocator: std.mem.Allocator, manifest: consumers.Manifest) Error!ManifestSnapshot {
            try self.beginRead();
            errdefer self.rollback();
            try self.requireManifestSchema();
            var result = ManifestSnapshot{ .status = try self.checkManifest(manifest), .digest = try manifest.digest(), .revision = try self.consumerRevision() };
            errdefer result.deinit(allocator);
            var bytes: usize = 0;
            for (manifest.required) |requirement| {
                try self.checkRequiredState(requirement, result.status == .first_use);
                const state = try self.consumerSnapshot(allocator, requirement.key);
                result.states[result.count] = state;
                result.count += 1;
                bytes += if (state.payload) |payload| payload.len else 0;
                if (bytes > consumers.max_prepared_bytes) return error.ConsumerCapacity;
            }
            try self.commitTransaction();
            return result;
        }
        pub fn validateConsumerManifestSnapshot(self: *Store, manifest: consumers.Manifest, saved_snapshot: *const ManifestSnapshot) Error!void {
            if (saved_snapshot.count != manifest.required.len or !std.mem.eql(u8, &saved_snapshot.digest, &try manifest.digest())) return error.ConsumerManifestMismatch;
            try self.beginRead();
            errdefer self.rollback();
            try self.requireManifestSchema();
            if (try self.checkManifest(manifest) != saved_snapshot.status or try self.consumerRevision() != saved_snapshot.revision) return error.StaleConsumerCheckpoint;
            for (manifest.required, saved_snapshot.states[0..saved_snapshot.count]) |requirement, state| {
                try self.checkRequiredState(requirement, saved_snapshot.status == .first_use);
                if (state.revision != 0 and state.format_version != requirement.format_version) return error.InvalidConsumer;
                try self.checkConsumerRevision(requirement.key, state.revision, .{ .value = state.valid_until_us });
            }
            try self.commitTransaction();
        }
        pub fn checkManifestBatch(self: *Store, manifest: consumers.Manifest, batch: consumers.Batch, allow_first_use: bool, allow_history: bool) Error!void {
            const status = try self.checkManifest(manifest);
            if (!allow_first_use and status == .first_use) return error.MissingRequiredConsumer;
            for (manifest.required) |requirement| {
                try self.checkRequiredState(requirement, status == .first_use);
                var covered = false;
                for (batch.deltas) |delta| if (consumers.Key.eql(requirement.key, delta.key)) {
                    if (delta.format_version != requirement.format_version) return error.InvalidConsumer;
                    covered = true;
                };
                for (batch.dependencies) |dependency| if (consumers.Key.eql(requirement.key, dependency.key)) {
                    if (dependency.expected_revision == 0 and !covered) return error.MissingRequiredConsumer;
                    covered = true;
                };
                if (!covered) return error.MissingRequiredConsumer;
            }
            for (batch.deltas) |delta| {
                for (manifest.required) |requirement| {
                    if (consumers.Key.eql(requirement.key, delta.key)) break;
                } else return error.ConsumerManifestMismatch;
            }
            for (batch.dependencies) |dependency| {
                for (manifest.required) |requirement| {
                    if (consumers.Key.eql(requirement.key, dependency.key)) break;
                } else try self.checkSharedDnsDependency(manifest, batch, dependency);
            }
            try self.checkConsumerBatch(batch, allow_history);
        }
        fn dnsAuthority(key: consumers.Key) bool {
            return key.kind == .dns and std.mem.eql(u8, key.jail, "@shared") and std.mem.eql(u8, key.source, "@resolver") and std.mem.eql(u8, key.rule, "authority");
        }
        fn checkSharedDnsDependency(self: *Store, manifest: consumers.Manifest, batch: consumers.Batch, dependency: consumers.Dependency) Error!void {
            const key = dependency.key;
            if (key.kind != .dns or !std.mem.eql(u8, key.jail, "@shared") or key.source.len > 253 or
                !(std.mem.eql(u8, key.rule, "v4") or std.mem.eql(u8, key.rule, "v6") or std.mem.eql(u8, key.rule, "both")) or dependency.expected_revision == 0 or dependency.valid_until_us == null) return error.ConsumerManifestMismatch;
            var bound = false;
            for (manifest.required) |requirement| {
                if (!dnsAuthority(requirement.key) or requirement.format_version != 1 or !std.mem.eql(u8, &requirement.key.generation, &key.generation)) continue;
                try self.checkRequiredState(requirement, false);
                for (batch.dependencies) |read| if (consumers.Key.eql(read.key, requirement.key) and read.expected_revision == 1 and read.valid_until_us == null) {
                    bound = true;
                    break;
                };
            }
            if (!bound) return error.ConsumerManifestMismatch;
            var name: [260]u8 = undefined;
            const source = std.fmt.bufPrint(&name, "{s}:{s}", .{ key.rule, key.source }) catch return error.ConsumerManifestMismatch;
            const required = [_]consumers.Requirement{.{ .key = key, .format_version = 1 }};
            const shared_manifest = consumers.Manifest{ .jail = "@shared", .source = source, .source_generation = key.generation, .required = &required };
            if (try self.checkManifest(shared_manifest) != .ready) return error.MissingRequiredConsumer;
            try self.checkRequiredState(required[0], false);
        }
        pub fn readyManifest(self: *Store, manifest: consumers.Manifest) Error!void {
            for (manifest.required) |requirement| try self.checkRequiredState(requirement, false);
            var row = try self.statement("UPDATE consumer_manifests SET ready=1 WHERE jail=?1 AND source=?2;");
            defer row.deinit();
            try row.text(1, manifest.jail);
            try row.text(2, manifest.source);
            try row.done();
            if (self.api.changes(self.db) != 1) return error.ConsumerManifestMissing;
            try self.fault(.after_manifest_ready);
        }
        pub fn commitConsumerInput(self: *Store, manifest: consumers.Manifest, batch: consumers.Batch) Error!void {
            try self.consumerInput(manifest, batch, false);
        }
        pub fn bootstrapConsumerManifest(self: *Store, manifest: consumers.Manifest, batch: consumers.Batch) Error!void {
            try self.consumerInput(manifest, batch, true);
        }
        fn consumerInput(self: *Store, manifest: consumers.Manifest, batch: consumers.Batch, initialize: bool) Error!void {
            try batch.validate();
            _ = try manifest.digest();
            if (initialize) try self.beginAdmissionWrite() else try self.beginWrite();
            errdefer self.rollback();
            try self.requireManifestSchema();
            if (initialize) try self.admitManifestTx(manifest);
            try self.checkManifestBatch(manifest, batch, initialize, false);
            try self.writeConsumerBatch(batch);
            try self.readyManifest(manifest);
            try self.fault(.before_consumer_input_commit);
            try self.commitConsumerClock(batch);
            try self.commitTransaction();
        }

        pub const ConsumerSnapshot = struct {
            revision: u64 = 0,
            format_version: u16 = 0,
            valid_until_us: ?i64 = null,
            payload: ?[]u8 = null,
            pub fn deinit(self: ConsumerSnapshot, allocator: std.mem.Allocator) void {
                if (self.payload) |bytes| allocator.free(bytes);
            }
        };
        pub fn bindConsumerKey(row: *Stmt, key: *const consumers.Key) Error!void {
            try key.validate();
            try row.int(1, @intFromEnum(key.kind));
            try row.text(2, key.jail);
            try row.text(3, key.source);
            try row.text(4, key.rule);
            try row.blob(5, &key.generation);
        }
        pub fn consumerSnapshot(self: *Store, allocator: std.mem.Allocator, key: consumers.Key) Error!ConsumerSnapshot {
            const schema = try self.integer("PRAGMA user_version;");
            if (schema < 10 or schema > latest_schema) return error.ConsumerStorageRequired;
            self.schema_version = schema;
            var row = try self.statement("SELECT revision,format,valid_until_us,payload FROM consumer_checkpoints WHERE kind=?1 AND jail=?2 AND source=?3 AND rule=?4 AND generation=?5;");
            defer row.deinit();
            try bindConsumerKey(&row, &key);
            if (!try row.row()) return .{};
            const revision_value = try row.signed(0);
            const format = try row.signed(1);
            if (revision_value <= 0 or format <= 0 or format > std.math.maxInt(u16)) return error.DatabaseFailure;
            const expiry: ?i64 = if (self.api.column_type(row.ptr, 2) == 5) null else try row.signed(2);
            if (self.api.column_type(row.ptr, 3) != 4) return error.InvalidConsumer;
            const bytes = try row.boundedBytes(3, consumers.max_payload);
            return .{ .revision = @intCast(revision_value), .format_version = @intCast(format), .valid_until_us = expiry, .payload = try allocator.dupe(u8, bytes) };
        }
        fn checkConsumerRevision(self: *Store, key: consumers.Key, expected: u64, deadline: ?struct { value: ?i64 }) Error!void {
            var row = try self.statement("SELECT revision,valid_until_us FROM consumer_checkpoints WHERE kind=?1 AND jail=?2 AND source=?3 AND rule=?4 AND generation=?5;");
            defer row.deinit();
            try bindConsumerKey(&row, &key);
            var current: u64 = 0;
            var expiry: ?i64 = null;
            if (try row.row()) {
                const saved = try row.signed(0);
                if (saved <= 0) return error.DatabaseFailure;
                current = @intCast(saved);
                if (self.api.column_type(row.ptr, 1) != 5) expiry = try row.signed(1);
            }
            if (current != expected) return error.StaleConsumerCheckpoint;
            if (deadline) |required| if (required.value != expiry) return error.StaleConsumerCheckpoint;
        }
        pub fn checkConsumerBatch(self: *Store, batch: consumers.Batch, allow_history: bool) Error!void {
            for (batch.dependencies) |dependency|
                try self.checkConsumerRevision(dependency.key, dependency.expected_revision, .{ .value = dependency.valid_until_us });
            for (batch.deltas) |delta| {
                if (delta.key.kind == .history and !allow_history) return error.InvalidHistoryTransition;
                if (dnsAuthority(delta.key) and (delta.expected_revision != 0 or delta.format_version != 1 or delta.valid_until_us != null or !std.mem.eql(u8, delta.payload, &delta.key.generation))) return error.InvalidConsumer;
                try self.checkConsumerRevision(delta.key, delta.expected_revision, null);
            }
            _ = try self.checkConsumerTime(batch);
        }
        fn checkConsumerTime(self: *Store, batch: consumers.Batch) Error!i64 {
            const durable_floor = try self.readAdmissionClock(self.schema_version);
            self.consumer_clock_floor_us = if (durable_floor) |floor| @max(batch.prepared_us, floor.us) else batch.prepared_us;
            return batch.checkedTime(self.consumer_clock_floor_us);
        }
        pub fn commitConsumerClock(self: *Store, batch: consumers.Batch) Error!void {
            const now = try self.checkConsumerTime(batch);
            var row = try self.statement("UPDATE consumer_clock SET floor_us=?1 WHERE id=1 AND (floor_us IS NULL OR floor_us<=?1);");
            defer row.deinit();
            try row.int(1, now);
            try row.done();
            if (self.api.changes(self.db) != 1) return error.ConsumerClockReversed;
        }
        pub fn writeConsumerBatch(self: *Store, batch: consumers.Batch) Error!void {
            for (batch.deltas) |delta| {
                var row = try self.statement("INSERT INTO consumer_checkpoints VALUES(?1,?2,?3,?4,?5,?6,1,?7,?8) ON CONFLICT(kind,jail,source,rule,generation) DO UPDATE SET format=excluded.format,revision=consumer_checkpoints.revision+1,payload=excluded.payload,valid_until_us=excluded.valid_until_us;");
                defer row.deinit();
                try bindConsumerKey(&row, &delta.key);
                try row.int(6, delta.format_version);
                try row.blob(7, delta.payload);
                if (delta.valid_until_us) |expiry| try row.int(8, expiry);
                try row.done();
                try self.fault(.after_consumer_delta);
            }
            if (self.schema_version >= 12) try self.bumpConsumerRevision();
        }

        pub fn admitRetry(self: *Store, jail: []const u8, generation: [32]u8, policy: retry.Policy) Error!void {
            if (jail.len == 0 or jail.len > 64 or std.mem.indexOfScalar(u8, jail, 0) != null) return error.InvalidRecord;
            _ = try policy.encode();
            try self.beginAdmissionWrite();
            errdefer self.rollback();
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
            const left_base = try left.encode();
            const right_base = try right.encode();
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

        pub fn retryStateAt(self: *Store, jail: []const u8, subject: detection.Subject, now_us: i64) Error!?retry.State {
            try self.beginRead();
            errdefer self.rollback();
            const schema = try self.integer("PRAGMA user_version;");
            if (schema < 9 or schema > latest_schema) return error.RetryStorageRequired;
            const admission = (try self.readRetryPolicy(jail)) orelse return error.RetryAdmissionRequired;
            if (try self.readRetryClock()) |floor| if (now_us < floor) return error.ReceiptClockReversed;
            const working = try self.readWorkingRetryState(jail, subject, admission.policy);
            const retired = try self.readRetired(jail, subject);
            if (working != null and retired != null) return error.InvalidRetryState;
            const result = if (working) |state| (try retry.prune(admission.policy, state, now_us)).state else retired;
            try self.commitTransaction();
            return result;
        }

        pub fn validateRuntimeOwners(self: *Store, names: []const []const u8) !void {
            return self.validateOwners(names, null);
        }
        pub fn validateRuntimeOwnersWithManifests(self: *Store, names: []const []const u8, manifests: []const consumers.Manifest) !void {
            return self.validateOwners(names, manifests);
        }
        fn validateOwners(self: *Store, names: []const []const u8, manifests: ?[]const consumers.Manifest) !void {
            if (names.len == 0 or names.len > 64) return error.InvalidRecord;
            try self.beginRead();
            errdefer self.rollback();
            if (manifests) |required| {
                try self.requireManifestSchema();
                if (required.len > 4096) return error.ConsumerCapacity;
                if (try self.integer("SELECT count(*) FROM consumer_manifests;") != required.len) return error.ConsumerManifestMismatch;
                for (required, 0..) |manifest, i| {
                    for (required[0..i]) |prior| if (std.mem.eql(u8, prior.jail, manifest.jail) and std.mem.eql(u8, prior.source, manifest.source)) return error.ConsumerManifestMismatch;
                    if (!std.mem.eql(u8, manifest.jail, "@shared") and !Store.canonicalHistoryManifest(manifest)) {
                        for (names) |name| {
                            if (std.mem.eql(u8, name, manifest.jail)) break;
                        } else return error.UnconfiguredStateOwner;
                    }
                    const status = try self.checkManifest(manifest);
                    for (manifest.required) |requirement| try self.checkRequiredState(requirement, status == .first_use);
                }
                if (try self.integer("SELECT EXISTS(SELECT 1 FROM consumer_checkpoints c WHERE NOT EXISTS(SELECT 1 FROM consumer_requirements r WHERE r.kind=c.kind AND r.jail=c.jail AND r.source=c.source AND r.rule=c.rule AND r.generation=c.generation AND r.format=c.format));") != 0) return error.ConsumerManifestMismatch;
            } else if (try self.integer("PRAGMA user_version;") >= 10 and
                try self.integer("SELECT EXISTS(SELECT 1 FROM consumer_checkpoints);") != 0)
                return error.NativeConsumersNotIntegrated;
            try self.validateOwnerNamesTx(names);
            try self.commitTransaction();
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
        pub const RetrySummary = struct { subjects: usize = 0, active: usize = 0, decisions: u64 = 0 };
        pub fn retrySummary(self: *Store, jail: []const u8, now_us: i64, output: []ActiveDecision) Error!RetrySummary {
            try self.beginRead();
            errdefer self.rollback();
            const admission = (try self.readRetryPolicy(jail)) orelse return error.RetryAdmissionRequired;
            if (output.len < admission.policy.max_subjects) return error.RetryCapacity;
            const floor = try self.readRetryClock();
            if (floor) |value| if (now_us < value) return error.ReceiptClockReversed;
            var row = try self.statement(if (self.schema_version >= 16)
                "SELECT last_processed_us,lease_kind,deadline_us,decisions,attempts,family,subject FROM retry_states WHERE jail=?1 ORDER BY family,subject;"
            else
                "SELECT last_processed_us,CASE WHEN expiry_us IS NULL THEN 0 ELSE 1 END,expiry_us,decisions,attempts,family,subject FROM retry_states WHERE jail=?1 ORDER BY family,subject;");
            defer row.deinit();
            try row.text(1, jail);
            var summary = RetrySummary{};
            while (try row.row()) {
                summary.subjects += 1;
                if (summary.subjects > admission.policy.max_subjects) return error.RetryCapacity;
                const stored = try self.decodeRetryState(&row, admission.policy);
                if (stored.last_processed_us > (floor orelse return error.InvalidRetryState)) return error.InvalidRetryState;
                const state = (try retry.prune(admission.policy, stored, now_us)).state;
                const subject = try self.decodeRetrySubject(&row, 5, 6);
                summary.decisions = std.math.add(u64, summary.decisions, state.decisions) catch return error.InvalidRetryState;
                if (state.lease.live(now_us)) {
                    output[summary.active] = .{ .subject = subject, .lease = state.lease, .ordinal = state.decisions };
                    summary.active += 1;
                }
            }
            if (self.schema_version >= 15)
                summary.decisions = std.math.add(u64, summary.decisions, try self.retiredTotal(jail)) catch return error.InvalidRetryState;
            try self.commitTransaction();
            return summary;
        }

        pub fn retryPolicySummaryPage(self: *Store, query: application_history.PolicyQuery, output: []application_history.PolicySummary) Error!application_history.PolicyPage {
            try query.validate();
            if (output.len == 0 or output.len > application_history.max_page or self.schema_version < 17) return error.InvalidPolicySummary;
            try self.beginRead();
            errdefer self.rollback();
            const revision_value = try self.integer("SELECT revision FROM policy_summary_clock WHERE id=1;");
            if (revision_value <= 0) return error.InvalidPolicySummary;
            const current_revision: u64 = @intCast(revision_value);
            if (query.expected_revision) |expected| if (expected != current_revision) return error.StalePolicySummary;
            var row = try self.statement("WITH summaries(jail,family,subject,generation,last_processed_us,lease_kind,deadline_us,decisions,retired) AS (SELECT s.jail,s.family,s.subject,p.generation,s.last_processed_us,s.lease_kind,s.deadline_us,s.decisions,0 FROM retry_states s JOIN retry_policies p ON p.jail=s.jail UNION ALL SELECT r.jail,r.family,r.subject,r.generation,r.last_processed_us,0,NULL,r.decisions,1 FROM retry_retired r) SELECT jail,family,subject,generation,last_processed_us,lease_kind,deadline_us,decisions,retired FROM summaries WHERE (?1 IS NULL OR jail=?1) AND (?2 IS NULL OR jail>?2 OR (jail=?2 AND (family>?3 OR (family=?3 AND subject>?4)))) ORDER BY jail,family,subject LIMIT ?5;");
            defer row.deinit();
            if (query.jail) |jail| try row.text(1, jail) else try self.check(self.api.bind_null(row.ptr, 1));
            if (query.after) |after| {
                try row.text(2, after.jail.slice());
                switch (after.subject) {
                    .v4 => |address| {
                        try row.int(3, 4);
                        try row.blob(4, &address);
                    },
                    .v6 => |address| {
                        try row.int(3, 6);
                        try row.blob(4, &address);
                    },
                }
            } else {
                try self.check(self.api.bind_null(row.ptr, 2));
                try self.check(self.api.bind_null(row.ptr, 3));
                try self.check(self.api.bind_null(row.ptr, 4));
            }
            try row.int(5, @intCast(output.len + 1));
            var count: usize = 0;
            var more = false;
            while (try row.row()) {
                if (count == output.len) {
                    more = true;
                    break;
                }
                if (self.api.column_type(row.ptr, 0) != 3) return error.InvalidPolicySummary;
                const jail = detection.Name.init(try row.boundedBytes(0, 64)) catch return error.InvalidPolicySummary;
                const subject = try self.decodeRetrySubject(&row, 1, 2);
                const generation = try Store.effectBlob(&row, 3, 32);
                const decisions = try row.signed(7);
                const retired = try row.signed(8);
                const lease = try retryLease(&row, 5, 6);
                if (decisions < 0 or retired < 0 or retired > 1 or (retired == 1 and lease != .absent)) return error.InvalidPolicySummary;
                if (count > 0 and std.mem.eql(u8, output[count - 1].jail.slice(), jail.slice()) and std.meta.eql(output[count - 1].subject, subject)) return error.InvalidPolicySummary;
                output[count] = .{ .jail = jail, .subject = subject, .generation = generation, .last_processed_us = try row.signed(4), .lease = lease, .decisions = @intCast(decisions), .retired = retired == 1 };
                count += 1;
            }
            try self.commitTransaction();
            return .{ .revision = current_revision, .count = count, .more = more };
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
                if (count > policy.max_subjects) return error.RetryCapacity;
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

        pub fn retryDecision(self: *Store, jail: []const u8, source: []const u8, occurrence: ?[]const u8) Error!?retry.Decision {
            var output: [max_native_detections]retry.Decision = undefined;
            const count = try self.retryDecisions(jail, source, occurrence, &output);
            if (count > 1) return error.AmbiguousRetryDecision;
            return if (count == 0) null else output[0];
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

        pub fn retryEscalationDecision(self: *Store, jail: []const u8, source: []const u8, occurrence: []const u8, subject: detection.Subject) Error!?EscalationSelection {
            if (self.schema_version < 18) return error.RetryStorageRequired;
            var row = try self.statement("SELECT scope,prior_confirmed,latest_confirmed_us,chosen_duration_us,jitter_us FROM retry_decision_escalations WHERE jail=?1 AND family=?2 AND subject=?3 AND source=?4 AND occurrence=?5;");
            defer row.deinit();
            try row.text(1, jail);
            try bindSubject(&row, &subject);
            try row.text(4, source);
            try row.text(5, occurrence);
            if (!try row.row()) return null;
            const scope_value = try row.signed(0);
            const prior = try row.signed(1);
            const latest = try row.optionalSigned(2);
            const chosen = try row.signed(3);
            const jitter = try row.signed(4);
            if (prior < 0 or (prior == 0) != (latest == null) or chosen <= 0 or @mod(chosen, 1_000_000) != 0 or jitter < 0 or @mod(jitter, 1_000_000) != 0 or try row.row()) return error.InvalidRetryState;
            return .{
                .scope = std.meta.intToEnum(retry.EscalationScope, scope_value) catch return error.InvalidRetryState,
                .prior_confirmed = @intCast(prior),
                .latest_confirmed_us = latest,
                .chosen_duration_us = chosen,
                .jitter_us = jitter,
            };
        }

        pub const RetryProlongation = struct {
            jail: []const u8,
            generation: [32]u8,
            subject: detection.Subject,
            ordinal: u64,
            expected_owner_revision: u64,
            requested: retry.Lease,
        };
        pub const RetryProlongationResult = struct { changed: bool, lease: retry.Lease, effect: effects.Entry };

        pub fn prolongRetryDecision(self: *Store, change: RetryProlongation, clock: effects.Clock) Error!RetryProlongationResult {
            if (change.ordinal == 0 or change.ordinal > std.math.maxInt(i64) or change.requested == .absent) return error.InvalidRetryState;
            try self.beginWrite();
            errdefer self.rollback();
            try self.effectSchema();
            if (self.schema_version < 16) return error.RetryStorageRequired;
            const now = try self.effectClock(clock);
            if (!change.requested.live(now)) return error.LeaseExpired;
            const admission = (try self.readRetryPolicy(change.jail)) orelse return error.RetryAdmissionRequired;
            if (!std.mem.eql(u8, &admission.generation, &change.generation)) return error.RetryGenerationMismatch;

            var decision_row = try self.statement("SELECT d.source,d.occurrence,d.decided_us,d.lease_kind,d.deadline_us,d.enforce,s.lease_kind,s.deadline_us,s.decisions FROM retry_decisions d JOIN retry_states s ON s.jail=d.jail AND s.family=d.family AND s.subject=d.subject WHERE d.jail=?1 AND d.family=?2 AND d.subject=?3 AND d.ordinal=?4;");
            defer decision_row.deinit();
            try decision_row.text(1, change.jail);
            try bindSubject(&decision_row, &change.subject);
            try decision_row.int(4, @intCast(change.ordinal));
            if (!try decision_row.row() or self.api.column_type(decision_row.ptr, 0) != 3 or self.api.column_type(decision_row.ptr, 1) != 3) return error.InvalidRetryState;
            const source = try decision_row.boundedBytes(0, Limits.source_bytes);
            const occurrence = try decision_row.boundedBytes(1, Limits.source_bytes);
            const decided_us = try decision_row.signed(2);
            const current = try retryLease(&decision_row, 3, 4);
            const enforce = try decision_row.signed(5);
            const state_lease = try retryLease(&decision_row, 6, 7);
            const decisions = try decision_row.signed(8);
            if (enforce != 1 or decisions != change.ordinal or !retry.Lease.eql(current, state_lease)) return error.InvalidRetryState;
            const prolonged = try current.prolonged(change.requested, now);

            const installation = try self.readInstallation() orelse return error.InstallationRequired;
            const scope = try effects.Scope.host(change.subject);
            const key = try scope.key(installation);
            const entry = try self.readEffect(key, installation) orelse return error.StaleEffect;
            if (entry.status == .dispatched) return error.EffectReconciliationRequired;
            const decision_id = effects.hashParts("fail2zig-native-effect-decision-v2", &.{ change.jail, source, occurrence, &change.generation, &key });
            var owners: [effects.max_page]effects.Owner = undefined;
            const owner_count = try self.readOwners(key, &owners);
            var owner: ?effects.Owner = null;
            for (owners[0..owner_count]) |candidate| if (std.mem.eql(u8, candidate.jail.slice(), change.jail)) {
                if (owner != null) return error.InvalidEffect;
                owner = candidate;
            };
            const existing = owner orelse return error.StaleEffect;
            if (existing.revision != change.expected_owner_revision) return error.StaleEffect;
            if (!std.mem.eql(u8, &existing.generation, &change.generation) or !std.mem.eql(u8, &existing.decision_id, &decision_id)) return error.EffectGenerationMismatch;
            if (existing.decided_us != decided_us or !effects.Lease.eql(existing.lease, current)) return error.InvalidEffect;
            if (!prolonged.changed) {
                try self.commitTransaction();
                return .{ .changed = false, .lease = current, .effect = entry };
            }

            {
                var state = try self.statement("UPDATE retry_states SET lease_kind=?4,deadline_us=?5 WHERE jail=?1 AND family=?2 AND subject=?3;");
                defer state.deinit();
                try state.text(1, change.jail);
                try bindSubject(&state, &change.subject);
                try bindRetryLease(&state, 4, prolonged.lease);
                try state.done();
                if (self.api.changes(self.db) != 1) return error.InvalidRetryState;
            }
            try self.fault(.after_retry_state);
            {
                var decision = try self.statement("UPDATE retry_decisions SET lease_kind=?5,deadline_us=?6 WHERE jail=?1 AND family=?2 AND subject=?3 AND ordinal=?4;");
                defer decision.deinit();
                try decision.text(1, change.jail);
                try bindSubject(&decision, &change.subject);
                try decision.int(4, @intCast(change.ordinal));
                try bindRetryLease(&decision, 5, prolonged.lease);
                try decision.done();
                if (self.api.changes(self.db) != 1) return error.InvalidRetryState;
            }
            try self.fault(.after_retry_decision);
            if (existing.revision >= std.math.maxInt(i64) or entry.revision >= std.math.maxInt(i64) or try self.integer("SELECT count(*) FROM effect_owner_revisions;") >= effects.max_owner_revisions) return error.EffectCapacity;
            {
                var update = try self.statement("UPDATE effect_owners SET revision=?4,lease_kind=?5,deadline_us=?6 WHERE scope_key=?1 AND jail=?2 AND revision=?3;");
                defer update.deinit();
                try update.blob(1, &key);
                try update.text(2, change.jail);
                try update.int(3, @intCast(existing.revision));
                try update.int(4, @intCast(existing.revision + 1));
                try Store.bindEffectLease(&update, 5, prolonged.lease);
                try update.done();
                if (self.api.changes(self.db) != 1) return error.StaleEffect;
            }
            try self.fault(.after_effect_owner);
            const next = try self.replaceEffectIntent(installation, scope, key, entry.revision + 1, decision_id, now);
            const final = try self.commitEffectClock(clock);
            if (!prolonged.lease.live(final) or (next.desired == .finite and !next.desired.live(final))) return error.EffectExpired;
            try self.commitEffectTransaction(true);
            return .{ .changed = true, .lease = prolonged.lease, .effect = next };
        }

        fn readEscalationHistory(self: *Store, jail: []const u8, subject: detection.Subject, scope: retry.EscalationScope) Error!retry.EscalationHistoryInput {
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
            return .{ .prior_confirmed = count, .latest_confirmed_us = latest };
        }

        pub fn commitRetry(self: *Store, record: Record, admission: retry.Admission) Error!void {
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
            if (previous == null or retired != null) {
                var count = try self.statement("SELECT count(*) FROM retry_states WHERE jail=?1;");
                defer count.deinit();
                try count.text(1, record.jail);
                if (!try count.row()) return error.DatabaseFailure;
                if (try count.signed(0) >= admission.policy.max_subjects) return error.RetryCapacity;
            }
            const current_attempt = retry.Attempt{ .at_us = outcome.eligible.timestamp.us, .occurrence = retry.occurrenceKey(record.source, record.occurrence) };
            var next = try retry.advanceWithEvidence(admission.policy, previous, subject, current_attempt, now, record.retry_evidence);
            var escalation_selection: ?EscalationSelection = null;
            if (next.decision != null and admission.policy.escalation.enabled) {
                if (self.schema_version < 18) return error.RetryStorageRequired;
                const history = try self.readEscalationHistory(record.jail, subject, admission.policy.escalation.scope);
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
                    (try self.readEscalationHistory(record.jail, subject, .per_jail)).prior_confirmed
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
                        _ = try self.setOwnerTx(.{ .scope = scope, .jail = record.jail, .generation = admission.generation, .decision_id = identity, .expected_revision = effect_revision, .lease = decision.lease, .decided_us = decision.decided_us }, effect_now);
                        if (self.schema_version >= 21) try self.prepareActionTargetsTx(.{ .action_id = identity, .scope_key = key, .jail = record.jail }, effect_now);
                    }
                }
                if (self.schema_version >= 17) {
                    if (try self.integer("SELECT count(*) FROM retry_decision_details;") >= application_history.max_details) {
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
                    if (record.retry_evidence.text) |evidence| try detail.text(9, evidence);
                    try detail.done();
                }
            }
        }
    };
}
