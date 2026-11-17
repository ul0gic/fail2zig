// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Retires expired shared DNS results and unused shared DNS manifests with the checkpoints only they require.
// Holds: A shared DNS result is retired only while the consumer revision, expiry and payload digest still match the caller's proof.

const std = @import("std");
const consumers = @import("../detect/consumer.zig");
const dns = @import("../detect/dns.zig");
const Error = @import("store.zig").Error;

pub fn Methods(comptime Store: type) type {
    return struct {
        const consumerHash = Store.consumerHash;
        const bindConsumerKey = Store.bindConsumerKey;
        pub const DnsRetirement = struct {
            key: consumers.Key,
            expected_revision: u64,
            expected_expiry_us: i64,
            payload_sha256: [32]u8,
            expected_consumer_revision: u64,
        };
        pub const DnsRetirementCommit = enum { durable, startup_staged };
        pub const DnsRetired = struct { consumer_revision: u64, commit: DnsRetirementCommit };
        pub const DnsRetirementOutcome = union(enum) { retired: DnsRetired, stale, pinned };

        pub fn retireDnsResult(self: *Store, proof: DnsRetirement, clock: consumers.Batch) Error!DnsRetirementOutcome {
            try proof.key.validate();
            if (proof.key.kind != .dns or !std.mem.eql(u8, proof.key.jail, "@shared") or
                !(std.mem.eql(u8, proof.key.rule, "v4") or std.mem.eql(u8, proof.key.rule, "v6") or std.mem.eql(u8, proof.key.rule, "both")) or
                proof.key.source.len > 253 or proof.expected_revision == 0 or proof.expected_revision > std.math.maxInt(i64) or
                clock.deltas.len != 0 or clock.dependencies.len != 0) return error.InvalidConsumer;
            const name = dns.Name.init(proof.key.source) catch return error.InvalidConsumer;
            if (!std.mem.eql(u8, name.slice(), proof.key.source)) return error.InvalidConsumer;
            const staged = self.startupAdmissionActive();
            try self.beginAdmissionWrite();
            var committed = false;
            defer if (!committed) self.rollback();
            try self.requireManifestSchema();
            if (try self.consumerRevision() != proof.expected_consumer_revision) return .stale;
            const now = try self.checkConsumerTime(clock);
            if (now < proof.expected_expiry_us) return .stale;
            var source_buffer: [260]u8 = undefined;
            const source = std.fmt.bufPrint(&source_buffer, "{s}:{s}", .{ proof.key.rule, proof.key.source }) catch return error.InvalidConsumer;
            const required = [_]consumers.Requirement{.{ .key = proof.key, .format_version = dns.version }};
            const manifest = consumers.Manifest{ .jail = "@shared", .source = source, .source_generation = proof.key.generation, .required = &required };
            const status = self.checkManifest(manifest) catch |failure| {
                if (failure == error.ConsumerManifestMissing) return .stale;
                return failure;
            };
            if (status != .ready) return error.MissingRequiredConsumer;
            {
                var row = try self.statement("SELECT format,revision,valid_until_us,payload FROM consumer_checkpoints WHERE kind=?1 AND jail=?2 AND source=?3 AND rule=?4 AND generation=?5;");
                defer row.deinit();
                try bindConsumerKey(&row, &proof.key);
                if (!try row.row()) return .stale;
                if (try row.signed(0) != dns.version or self.api.column_type(row.ptr, 3) != 4) return error.InvalidConsumer;
                const saved_revision = try row.signed(1);
                const expiry = try row.optionalSigned(2) orelse return error.InvalidConsumer;
                if (saved_revision <= 0) return error.InvalidConsumer;
                if (saved_revision != proof.expected_revision or expiry != proof.expected_expiry_us) return .stale;
                const payload = try row.boundedBytes(3, dns.cache_entry_bytes);
                if (payload.len != dns.cache_entry_bytes) return error.InvalidConsumer;
                var digest: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(payload, &digest, .{});
                if (!std.mem.eql(u8, &digest, &proof.payload_sha256)) return .stale;
            }
            {
                var pin = try self.statement("SELECT 1 FROM consumer_requirements INDEXED BY consumer_requirement_identity WHERE kind=?1 AND jail=?2 AND source=?3 AND rule=?4 AND generation=?5 AND NOT(manifest_jail=?6 AND manifest_source=?7) LIMIT 1;");
                defer pin.deinit();
                try bindConsumerKey(&pin, &proof.key);
                try pin.text(6, manifest.jail);
                try pin.text(7, manifest.source);
                if (try pin.row()) return .pinned;
            }
            {
                var remove = try self.statement("DELETE FROM consumer_requirements WHERE kind=?1 AND jail=?2 AND source=?3 AND rule=?4 AND generation=?5 AND manifest_jail=?6 AND manifest_source=?7;");
                defer remove.deinit();
                try bindConsumerKey(&remove, &proof.key);
                try remove.text(6, manifest.jail);
                try remove.text(7, manifest.source);
                try remove.done();
                if (self.api.changes(self.db) != 1) return .stale;
            }
            {
                var remove = try self.statement("DELETE FROM consumer_manifests WHERE jail=?1 AND source=?2 AND generation=?3;");
                defer remove.deinit();
                try remove.text(1, manifest.jail);
                try remove.text(2, manifest.source);
                try remove.blob(3, &manifest.source_generation);
                try remove.done();
                if (self.api.changes(self.db) != 1) return .stale;
            }
            {
                var remove = try self.statement("DELETE FROM consumer_checkpoints WHERE kind=?1 AND jail=?2 AND source=?3 AND rule=?4 AND generation=?5 AND revision=?6 AND valid_until_us=?7;");
                defer remove.deinit();
                try bindConsumerKey(&remove, &proof.key);
                try remove.int(6, @intCast(proof.expected_revision));
                try remove.int(7, proof.expected_expiry_us);
                try remove.done();
                if (self.api.changes(self.db) != 1) return .stale;
            }
            try self.bumpConsumerRevision();
            const next_revision = try self.consumerRevision();
            try self.fault(.before_consumer_input_commit);
            try self.commitConsumerClock(clock);
            try self.commitTransaction();
            committed = true;
            return .{ .retired = .{ .consumer_revision = next_revision, .commit = if (staged) .startup_staged else .durable } };
        }
        pub const UnusedSharedDnsPage = enum { progressed, done, pinned };
        const SharedDnsManifestKey = struct { source: [260]u8, len: usize, generation: [32]u8 };
        fn firstSharedDnsManifest(self: *Store, after: ?[]const u8) Error!?SharedDnsManifestKey {
            var row = try self.statement(if (after == null)
                "SELECT source,generation FROM consumer_manifests WHERE jail='@shared' ORDER BY source LIMIT 1;"
            else
                "SELECT source,generation FROM consumer_manifests WHERE jail='@shared' AND source>?1 ORDER BY source LIMIT 1;");
            defer row.deinit();
            if (after) |key| try row.text(1, key);
            if (!try row.row()) return null;
            if (self.api.column_type(row.ptr, 0) != 3) return error.InvalidConsumer;
            const source = try row.boundedBytes(0, 260);
            var key: SharedDnsManifestKey = .{ .source = undefined, .len = source.len, .generation = try consumerHash(&row, 1) };
            @memcpy(key.source[0..source.len], source);
            return key;
        }
        pub fn retireUnusedSharedDnsPage(self: *Store) Error!UnusedSharedDnsPage {
            try self.beginWrite();
            errdefer self.rollback();
            try self.requireManifestSchema();
            var key = try self.firstSharedDnsManifest(null) orelse {
                var pin = try self.statement("SELECT 1 FROM consumer_requirements INDEXED BY consumer_requirement_identity WHERE kind=3 AND jail='@shared' LIMIT 1;");
                defer pin.deinit();
                if (try pin.row()) {
                    try self.commitTransaction();
                    return .pinned;
                }
                var orphan = try self.statement("SELECT 1 FROM consumer_checkpoints WHERE kind=3 AND jail='@shared' LIMIT 1;");
                defer orphan.deinit();
                if (try orphan.row()) return error.ConsumerManifestMismatch;
                try self.commitTransaction();
                return .done;
            };
            if (std.mem.eql(u8, key.source[0..key.len], "@resolver"))
                key = try self.firstSharedDnsManifest("@resolver") orelse key;
            const source = key.source[0..key.len];
            const authority = std.mem.eql(u8, source, "@resolver");
            var name: dns.Name = undefined;
            var family: dns.Family = undefined;
            const consumer_key: consumers.Key = if (authority)
                .{ .kind = .dns, .jail = "@shared", .source = "@resolver", .rule = "authority", .generation = key.generation }
            else blk: {
                const colon = std.mem.indexOfScalar(u8, source, ':') orelse return error.InvalidConsumer;
                family = std.meta.stringToEnum(dns.Family, source[0..colon]) orelse return error.InvalidConsumer;
                name = dns.Name.init(source[colon + 1 ..]) catch return error.InvalidConsumer;
                if (!std.mem.eql(u8, name.slice(), source[colon + 1 ..])) return error.InvalidConsumer;
                break :blk .{ .kind = .dns, .jail = "@shared", .source = name.slice(), .rule = @tagName(family), .generation = key.generation };
            };
            const required = [_]consumers.Requirement{.{ .key = consumer_key, .format_version = if (authority) 1 else dns.version }};
            const manifest: consumers.Manifest = .{ .jail = "@shared", .source = source, .source_generation = key.generation, .required = &required };
            const status = try self.checkManifest(manifest);
            try self.checkRequiredState(required[0], status == .first_use);
            if (!authority) {
                var row = try self.statement("SELECT revision,valid_until_us,payload FROM consumer_checkpoints WHERE kind=?1 AND jail=?2 AND source=?3 AND rule=?4 AND generation=?5;");
                defer row.deinit();
                try bindConsumerKey(&row, &consumer_key);
                if (try row.row()) {
                    const revision = try row.signed(0);
                    const expiry = try row.optionalSigned(1) orelse return error.InvalidConsumer;
                    const payload = try row.boundedBytes(2, dns.cache_entry_bytes);
                    const decoded = dns.decodeCheckpoint(payload) catch return error.InvalidConsumer;
                    if (revision <= 0 or decoded.revision != @as(u64, @intCast(revision)) or decoded.result.valid_until_us != expiry or
                        decoded.result.request.family != family or !std.mem.eql(u8, decoded.result.request.name.slice(), name.slice()) or
                        !std.mem.eql(u8, &decoded.result.request.generation, &key.generation)) return error.InvalidConsumer;
                }
            }
            {
                var pin = try self.statement("SELECT 1 FROM consumer_requirements INDEXED BY consumer_requirement_identity WHERE kind=?1 AND jail=?2 AND source=?3 AND rule=?4 AND generation=?5 AND NOT(manifest_jail=?6 AND manifest_source=?7) LIMIT 1;");
                defer pin.deinit();
                try bindConsumerKey(&pin, &consumer_key);
                try pin.text(6, manifest.jail);
                try pin.text(7, manifest.source);
                if (try pin.row()) {
                    try self.commitTransaction();
                    return .pinned;
                }
            }
            _ = try self.retireManifestGroupTx(manifest.jail, manifest.source, manifest.source_generation);
            try self.commitTransaction();
            return .progressed;
        }
    };
}
