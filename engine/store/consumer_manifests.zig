// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Stores consumer manifests and checkpoints, applies consumer input batches and rekeys a jail's saved generations.
// Holds: Consumer input applied here is written only after every dependency and delta matches its saved checkpoint revision.

const std = @import("std");
const consumers = @import("../detect/consumer.zig");
const effects = @import("../effect/effect.zig");
const store = @import("store.zig");
const canonical_scope = @import("../firewall/scope.zig");
const Error = @import("store.zig").Error;
const Stmt = @import("store.zig").Stmt;
const Limits = store.Limits;
const latest_schema = @import("store.zig").latest_schema;

pub fn Methods(comptime Store: type) type {
    return struct {
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
        pub fn consumerHash(row: *Stmt, column: c_int) Error![32]u8 {
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
        pub fn bumpConsumerRevision(self: *Store) Error!void {
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
        pub fn requireManifestSchema(self: *Store) Error!void {
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
        // Does:  Retires the jail's first manifest with its requirements and every checkpoint no other manifest still requires.
        pub fn retireJailManifestTx(self: *Store, jail: []const u8) Error!u16 {
            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();
            const allocator = arena.allocator();
            var generation: [32]u8 = undefined;
            const source = blk: {
                var row = try self.statement("SELECT source,generation FROM consumer_manifests WHERE jail=?1 ORDER BY source LIMIT 1;");
                defer row.deinit();
                try row.text(1, jail);
                if (!try row.row()) return 0;
                if (self.api.column_type(row.ptr, 0) != 3) return error.InvalidConsumer;
                generation = try consumerHash(&row, 1);
                break :blk try allocator.dupe(u8, try row.boundedBytes(0, 16384));
            };
            return self.retireManifestGroupTx(jail, source, generation);
        }
        pub fn retireManifestGroupTx(self: *Store, jail: []const u8, source: []const u8, generation: [32]u8) Error!u16 {
            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();
            const allocator = arena.allocator();
            var required: [consumers.max_dependencies]consumers.Requirement = undefined;
            var count: usize = 0;
            {
                var rows = try self.statement("SELECT kind,jail,source,rule,generation,format FROM consumer_requirements WHERE manifest_jail=?1 AND manifest_source=?2 ORDER BY kind,jail,source,rule,generation LIMIT 17;");
                defer rows.deinit();
                try rows.text(1, jail);
                try rows.text(2, source);
                while (try rows.row()) {
                    if (count == required.len) return error.ConsumerCapacity;
                    inline for (.{ 0, 5 }) |column| if (self.api.column_type(rows.ptr, column) != 1) return error.InvalidConsumer;
                    inline for (.{ 1, 2, 3 }) |column| if (self.api.column_type(rows.ptr, column) != 3) return error.InvalidConsumer;
                    const kind = std.meta.intToEnum(consumers.Kind, try rows.signed(0)) catch return error.InvalidConsumer;
                    const format = try rows.signed(5);
                    if (format <= 0 or format > std.math.maxInt(u16)) return error.InvalidConsumer;
                    required[count] = .{ .key = .{
                        .kind = kind,
                        .jail = try allocator.dupe(u8, try rows.boundedBytes(1, 64)),
                        .source = try allocator.dupe(u8, try rows.boundedBytes(2, 16384)),
                        .rule = try allocator.dupe(u8, try rows.boundedBytes(3, 64)),
                        .generation = try consumerHash(&rows, 4),
                    }, .format_version = @intCast(format) };
                    count += 1;
                }
            }
            const manifest: consumers.Manifest = .{ .jail = jail, .source = source, .source_generation = generation, .required = required[0..count] };
            _ = try self.checkManifest(manifest);
            var deleted: u16 = 0;
            for (required[0..count]) |*requirement| {
                var row = try self.statement("DELETE FROM consumer_requirements WHERE kind=?1 AND jail=?2 AND source=?3 AND rule=?4 AND generation=?5 AND manifest_jail=?6 AND manifest_source=?7 AND format=?8;");
                defer row.deinit();
                try bindConsumerKey(&row, &requirement.key);
                try row.text(6, jail);
                try row.text(7, source);
                try row.int(8, requirement.format_version);
                try row.done();
                if (self.api.changes(self.db) != 1) return error.InvalidConsumer;
                deleted += 1;
            }
            {
                var row = try self.statement("DELETE FROM consumer_manifests WHERE jail=?1 AND source=?2;");
                defer row.deinit();
                try row.text(1, jail);
                try row.text(2, source);
                try row.done();
                if (self.api.changes(self.db) != 1) return error.InvalidConsumer;
                deleted += 1;
            }
            for (required[0..count]) |*requirement| {
                var row = try self.statement("DELETE FROM consumer_checkpoints WHERE kind=?1 AND jail=?2 AND source=?3 AND rule=?4 AND generation=?5 AND format=?6 AND NOT EXISTS(SELECT 1 FROM consumer_requirements INDEXED BY consumer_requirement_identity WHERE kind=?1 AND jail=?2 AND source=?3 AND rule=?4 AND generation=?5 AND format=?6);");
                defer row.deinit();
                try bindConsumerKey(&row, &requirement.key);
                try row.int(6, requirement.format_version);
                try row.done();
                deleted += @intCast(self.api.changes(self.db));
            }
            try self.bumpConsumerRevision();
            return deleted;
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
            try self.beginAdmissionWrite();
            errdefer self.rollback();
            try self.applyConsumerInputTx(manifest, batch, initialize);
            try self.commitTransaction();
        }
        pub fn applyConsumerInputTx(self: *Store, manifest: consumers.Manifest, batch: consumers.Batch, initialize: bool) Error!void {
            if (self.api.get_autocommit(self.db) != 0) return error.InvalidConsumer;
            try batch.validate();
            _ = try manifest.digest();
            try self.requireManifestSchema();
            if (initialize) try self.admitManifestTx(manifest);
            try self.checkManifestBatch(manifest, batch, initialize, false);
            try self.writeConsumerBatch(batch);
            try self.readyManifest(manifest);
            try self.fault(.before_consumer_input_commit);
            try self.commitConsumerClock(batch);
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
                if (dnsAuthority(delta.key) and (delta.expected_revision != 0 or delta.format_version != 1 or delta.valid_until_us != null or !std.mem.eql(
                    u8,
                    delta.payload,
                    &delta.key.generation,
                ))) return error.InvalidConsumer;
                try self.checkConsumerRevision(delta.key, delta.expected_revision, null);
            }
            _ = try self.checkConsumerTime(batch);
        }
        pub fn checkConsumerTime(self: *Store, batch: consumers.Batch) Error!i64 {
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

        pub const RekeyReport = struct { retry_rows: u32, pending_receipts: u32, manifests: u32, cursors: u32 };
        pub const CursorRekey = union(enum) { none, file: struct { legacy: [32]u8, planned: [32]u8 }, journal };

        // Why: A rekey rewrites a jail's records in single statements, which can exceed the default 1,000-callback progress budget.
        const rekey_work_callbacks: u32 = 100_000;
        pub const OwnerHeld = struct { key: [32]u8, revision: u64, scope: [canonical_scope.encoded_bytes]u8, absent: bool };

        fn cursorBindingFragment(buffer: []u8, binding: [32]u8) Error![]const u8 {
            var stream = std.io.fixedBufferStream(buffer);
            const w = stream.writer();
            w.writeAll("\"codec_configuration_hash\":[") catch return error.InvalidRecord;
            for (binding, 0..) |byte, i| {
                if (i != 0) w.writeByte(',') catch return error.InvalidRecord;
                w.print("{d}", .{byte}) catch return error.InvalidRecord;
            }
            w.writeByte(']') catch return error.InvalidRecord;
            return stream.getWritten();
        }

        pub fn rekeySavedGenerations(self: *Store, jail: []const u8, legacy: [32]u8, planned: [32]u8, cursors: CursorRekey) Error!RekeyReport {
            var report = RekeyReport{ .retry_rows = 0, .pending_receipts = 0, .manifests = 0, .cursors = 0 };
            if (std.mem.eql(u8, &legacy, &planned)) return report;
            if (jail.len == 0 or jail.len > 64 or std.mem.indexOfScalar(u8, jail, 0) != null) return error.InvalidRecord;
            try self.beginAdmissionWrite();
            errdefer self.rollback();
            if (self.schema_version < 22) return error.AdminStorageRequired;
            const prior_work = self.work_remaining;
            if (self.runtime_limits) self.work_remaining = rekey_work_callbacks;
            defer if (self.runtime_limits) {
                self.work_remaining = prior_work;
            };
            var old_fragment: [256]u8 = undefined;
            var new_fragment: [256]u8 = undefined;
            const old_text = switch (cursors) {
                .file => |binding| try cursorBindingFragment(&old_fragment, binding.legacy),
                .none, .journal => "",
            };
            const new_text = switch (cursors) {
                .file => |binding| try cursorBindingFragment(&new_fragment, binding.planned),
                .none, .journal => "",
            };
            const bound = blk: {
                {
                    var row = try self.statement("SELECT 1 FROM retry_policies WHERE jail=?1 AND generation=?2;");
                    defer row.deinit();
                    try row.text(1, jail);
                    try row.blob(2, &legacy);
                    if (try row.row()) break :blk true;
                }
                switch (cursors) {
                    .none => break :blk false,
                    .file => {
                        var row = try self.statement("SELECT 1 FROM source_cursors WHERE jail=?1 AND instr(CAST(cursor AS TEXT),?2)>0 LIMIT 1;");
                        defer row.deinit();
                        try row.text(1, jail);
                        try row.text(2, old_text);
                        break :blk try row.row();
                    },
                    .journal => {
                        var row = try self.statement("SELECT 1 FROM source_cursors WHERE jail=?1 AND substr(CAST(cursor AS BLOB),1,4)=CAST('F2JC' AS BLOB) AND substr(CAST(cursor AS BLOB),7,32)=?2 LIMIT 1;");
                        defer row.deinit();
                        try row.text(1, jail);
                        try row.blob(2, &legacy);
                        break :blk try row.row();
                    },
                }
            };
            if (!bound) {
                try self.commitTransaction();
                return report;
            }
            try self.exec("PRAGMA defer_foreign_keys=ON;");
            for ([_][:0]const u8{
                "UPDATE retry_policies SET generation=?3 WHERE jail=?1 AND generation=?2;",
                "UPDATE retry_escalation_policies SET generation=?3 WHERE jail=?1 AND generation=?2;",
            }) |sql| report.retry_rows = std.math.add(u32, report.retry_rows, try self.rekeyRows(sql, jail, legacy, planned)) catch return error.StorageLimit;
            try self.rekeyGenerationTablesTx(jail, legacy, planned, &report);
            switch (cursors) {
                .none => {},
                .file => {
                    var update = try self.statement("UPDATE source_cursors SET cursor=CAST(replace(CAST(cursor AS TEXT),?2,?3) AS BLOB) WHERE jail=?1 AND instr(CAST(cursor AS TEXT),?2)>0;");
                    defer update.deinit();
                    try update.text(1, jail);
                    try update.text(2, old_text);
                    try update.text(3, new_text);
                    try update.done();
                    report.cursors = std.math.add(u32, report.cursors, std.math.cast(u32, self.api.changes(self.db)) orelse return error.StorageLimit) catch return error.StorageLimit;
                },
                .journal => {},
            }
            const owners_changed = try self.rekeyOwnersTx(jail, legacy, planned, null, error.StaleEffect);
            try self.commitEffectTransaction(owners_changed);
            return report;
        }

        const GenerationStatement = struct { sql: [:0]const u8, counted: enum { pending, manifests, cursors, none } };
        const generation_statements = [_]GenerationStatement{
            .{ .sql = "UPDATE pending_receipts SET generation=?3 WHERE jail=?1 AND generation=?2;", .counted = .pending },
            .{ .sql = "UPDATE records SET source_generation=?3 WHERE jail=?1 AND source_generation=?2;", .counted = .none },
            .{ .sql = "UPDATE records SET receipt_generation=?3 WHERE jail=?1 AND receipt_generation=?2;", .counted = .none },
            .{
                .sql = "UPDATE checkpoints SET payload=CAST(substr(CAST(payload AS BLOB),1,8)||?3||substr(CAST(payload AS BLOB),41) AS BLOB) WHERE jail=?1 AND substr(CAST(payload AS BLOB),1,4)=CAST('F2NT' AS BLOB) AND substr(CAST(payload AS BLOB),9,32)=?2;",
                .counted = .none,
            },
            .{
                .sql = "UPDATE checkpoints SET payload=CAST(substr(CAST(payload AS BLOB),1,6)||?3||substr(CAST(payload AS BLOB),39) AS BLOB) WHERE jail=?1 AND substr(CAST(payload AS BLOB),1,4)=CAST('F2JC' AS BLOB) AND substr(CAST(payload AS BLOB),7,32)=?2;",
                .counted = .none,
            },
            .{ .sql = "UPDATE source_maintenance SET generation=?3 WHERE jail=?1 AND generation=?2;", .counted = .none },
            .{ .sql = "UPDATE consumer_checkpoints SET generation=?3 WHERE jail=?1 AND generation=?2;", .counted = .none },
            .{ .sql = "UPDATE consumer_requirements SET generation=?3 WHERE jail=?1 AND generation=?2;", .counted = .none },
            .{
                .sql = "UPDATE source_cursors SET cursor=CAST(substr(CAST(cursor AS BLOB),1,6)||?3||substr(CAST(cursor AS BLOB),39) AS BLOB) WHERE jail=?1 AND substr(CAST(cursor AS BLOB),1,4)=CAST('F2JC' AS BLOB) AND substr(CAST(cursor AS BLOB),7,32)=?2;",
                .counted = .cursors,
            },
        };

        pub fn rekeyGenerationTablesTx(self: *Store, jail: []const u8, old: [32]u8, new: [32]u8, report: *RekeyReport) Error!void {
            report.manifests = std.math.add(u32, report.manifests, try self.rekeyConsumerManifestsTx(jail, old, new)) catch return error.StorageLimit;
            for (generation_statements) |entry| {
                const rows = try self.rekeyRows(entry.sql, jail, old, new);
                const total: *u32 = switch (entry.counted) {
                    .pending => &report.pending_receipts,
                    .manifests => &report.manifests,
                    .cursors => &report.cursors,
                    .none => continue,
                };
                total.* = std.math.add(u32, total.*, rows) catch return error.StorageLimit;
            }
        }

        pub const GenerationRepair = struct { receipts: u32, cursors: u32 };

        pub fn completeGenerationRekey(self: *Store, jail: []const u8) Error!GenerationRepair {
            var repair = GenerationRepair{ .receipts = 0, .cursors = 0 };
            if (jail.len == 0 or jail.len > 64 or std.mem.indexOfScalar(u8, jail, 0) != null) return error.InvalidRecord;
            try self.beginAdmissionWrite();
            errdefer self.rollback();
            if (self.schema_version < 22) return error.AdminStorageRequired;
            const prior_work = self.work_remaining;
            if (self.runtime_limits) self.work_remaining = rekey_work_callbacks;
            defer if (self.runtime_limits) {
                self.work_remaining = prior_work;
            };
            const bound = (try self.readRetryPolicy(jail)) orelse {
                try self.commitTransaction();
                return repair;
            };
            {
                var update = try self.statement("UPDATE records SET receipt_generation=?2 WHERE jail=?1 AND receipt_us IS NOT NULL AND (source_generation IS NULL OR source_generation=?2) AND receipt_generation IS NOT ?2;");
                defer update.deinit();
                try update.text(1, jail);
                try update.blob(2, &bound.generation);
                try update.done();
                repair.receipts = std.math.cast(u32, self.api.changes(self.db)) orelse return error.StorageLimit;
            }
            {
                var update = try self.statement("UPDATE source_cursors SET cursor=CAST(substr(CAST(cursor AS BLOB),1,6)||?2||substr(CAST(cursor AS BLOB),39) AS BLOB) WHERE jail=?1 AND substr(CAST(cursor AS BLOB),1,4)=CAST('F2JC' AS BLOB) AND substr(CAST(cursor AS BLOB),7,32) IS NOT ?2;");
                defer update.deinit();
                try update.text(1, jail);
                try update.blob(2, &bound.generation);
                try update.done();
                repair.cursors = std.math.cast(u32, self.api.changes(self.db)) orelse return error.StorageLimit;
            }
            try self.commitEffectTransaction(false);
            return repair;
        }

        fn rekeyRows(self: *Store, sql: [:0]const u8, jail: []const u8, legacy: [32]u8, planned: [32]u8) Error!u32 {
            var update = try self.statement(sql);
            defer update.deinit();
            try update.text(1, jail);
            try update.blob(2, &legacy);
            try update.blob(3, &planned);
            try update.done();
            return std.math.cast(u32, self.api.changes(self.db)) orelse error.StorageLimit;
        }

        // Does:  Moves the jail's owners to the planned generation; with now_us null it commits the effect clock only if one moved.
        pub fn rekeyOwnersTx(self: *Store, jail: []const u8, legacy: [32]u8, planned: [32]u8, now_us: ?i64, stale_failure: error{ StaleEffect, StalePolicyTransition }) Error!bool {
            var held = std.ArrayListUnmanaged(OwnerHeld){};
            defer held.deinit(self.allocator);
            {
                var owners = try self.statement("SELECT o.scope_key,o.revision,n.canonical_scope,o.lease_kind,o.deadline_us,EXISTS(SELECT 1 FROM effect_owner_revisions h WHERE h.scope_key=o.scope_key AND h.jail=o.jail AND h.revision=o.revision AND h.generation=o.generation AND h.decision_id=o.decision_id AND h.lease_kind=o.lease_kind AND h.deadline_us IS o.deadline_us AND h.decided_us=o.decided_us) FROM effect_owners o JOIN native_effects n USING(scope_key) WHERE o.jail=?1 AND o.generation=?2 ORDER BY o.scope_key;");
                defer owners.deinit();
                try owners.text(1, jail);
                try owners.blob(2, &legacy);
                while (try owners.row()) {
                    if (held.items.len == effects.max_effects) return error.EffectCapacity;
                    const owner_revision = try owners.signed(1);
                    if (owner_revision <= 0 or owner_revision >= std.math.maxInt(i64) or try owners.signed(5) != 1) return error.InvalidEffect;
                    const lease = try Store.effectLease(&owners, 3, 4);
                    try held.append(
                        self.allocator,
                        .{
                            .key = try Store.effectBlob(&owners, 0, 32),
                            .revision = @intCast(owner_revision),
                            .scope = try Store.effectBlob(&owners, 2, canonical_scope.encoded_bytes),
                            .absent = lease == .absent,
                        },
                    );
                }
            }
            if (held.items.len == 0 and now_us == null) return false;
            const clock = effects.Clock{ .prepared_us = 0 };
            const now = now_us orelse try self.effectClock(clock);
            const count: i64 = @intCast(held.items.len);
            var live_count: i64 = 0;
            for (held.items) |owner| if (!owner.absent) {
                live_count += 1;
            };
            try self.reserveEffectRows(.{ .revisions = count, .intents = live_count, .observations = live_count * store.load_repair.observations_per_intent });
            if (try self.tableRows(.effect_owner_revisions) + count > effects.max_owner_revisions) return error.EffectCapacity;
            for (held.items) |owner| try self.rekeyOwnerHeldTx(owner, jail, legacy, planned, now, stale_failure);
            if (now_us == null) _ = try self.commitEffectClock(clock);
            return held.items.len != 0;
        }

        pub fn readRekeyOwnerRowTx(self: *Store, rowid: i64, jail: []const u8, legacy: [32]u8) Error!?OwnerHeld {
            var row = try self.statement("SELECT o.scope_key,o.revision,n.canonical_scope,o.lease_kind,o.deadline_us,EXISTS(SELECT 1 FROM effect_owner_revisions h WHERE h.scope_key=o.scope_key AND h.jail=o.jail AND h.revision=o.revision AND h.generation=o.generation AND h.decision_id=o.decision_id AND h.lease_kind=o.lease_kind AND h.deadline_us IS o.deadline_us AND h.decided_us=o.decided_us) FROM effect_owners o LEFT JOIN native_effects n USING(scope_key) WHERE o.rowid=?1 AND o.jail=?2 AND o.generation=?3;");
            defer row.deinit();
            try row.int(1, rowid);
            try row.text(2, jail);
            try row.blob(3, &legacy);
            if (!try row.row()) return null;
            const revision = try row.signed(1);
            if (revision <= 0 or revision >= std.math.maxInt(i64) or try row.signed(5) != 1) return error.InvalidEffect;
            return .{
                .key = try Store.effectBlob(&row, 0, 32),
                .revision = @intCast(revision),
                .scope = try Store.effectBlob(&row, 2, canonical_scope.encoded_bytes),
                .absent = try Store.effectLease(&row, 3, 4) == .absent,
            };
        }
        pub fn rekeyOwnerHeldTx(self: *Store, owner: OwnerHeld, jail: []const u8, legacy: [32]u8, planned: [32]u8, now: i64, stale_failure: error{ StaleEffect, StalePolicyTransition }) Error!void {
            const scope = canonical_scope.Scope.decode(&owner.scope) catch return error.InvalidEffect;
            if (owner.absent) {
                const installation = try self.readInstallation() orelse return error.InstallationRequired;
                const exact = try effects.Scope.exact(scope);
                if (!std.mem.eql(u8, &owner.key, &try exact.key(installation))) return error.InvalidEffect;
                var update = try self.statement("UPDATE effect_owners SET generation=?4,revision=?5 WHERE scope_key=?1 AND jail=?2 AND revision=?3 AND generation=?6 AND lease_kind=0 AND deadline_us IS NULL;");
                defer update.deinit();
                try update.blob(1, &owner.key);
                try update.text(2, jail);
                try update.int(3, @intCast(owner.revision));
                try update.blob(4, &planned);
                try update.int(5, @intCast(owner.revision + 1));
                try update.blob(6, &legacy);
                try update.done();
                if (self.api.changes(self.db) != 1) return stale_failure;
                self.insertedRows(.effect_owner_revisions, 1);
                try self.advanceEffectSnapshot();
                return;
            }
            const transition_id = effects.hashParts("fail2zig-generation-rekey-v1", &.{ &planned, &owner.key });
            _ = try self.transitionOwnerReservedTx(
                .{
                    .scope = scope,
                    .jail = jail,
                    .current_generation = legacy,
                    .next_generation = planned,
                    .expected_owner_revision = owner.revision,
                    .transition_id = transition_id,
                    .mode = .retain,
                    .occurred_us = now,
                },
                now,
                false,
            );
        }
    };
}
