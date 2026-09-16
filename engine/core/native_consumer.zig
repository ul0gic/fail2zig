// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");

pub const max_deltas = 16;
pub const max_dependencies = 16;
pub const max_payload = 64 * 1024;
pub const max_prepared_bytes = 1024 * 1024;
pub const Error = error{ InvalidConsumer, ConsumerCapacity, ConsumerExpired, ConsumerClockReversed };
pub const Kind = enum(u8) { rule = 1, correlation, dns, ignore, history };

pub const Key = struct {
    kind: Kind,
    jail: []const u8,
    source: []const u8,
    rule: []const u8,
    generation: [32]u8,

    pub fn validate(self: Key) Error!void {
        if (self.jail.len == 0 or self.jail.len > 64 or self.source.len == 0 or
            self.source.len > 16384 or self.rule.len == 0 or self.rule.len > 64)
            return error.InvalidConsumer;
        for ([_][]const u8{ self.jail, self.source, self.rule }) |value|
            if (std.mem.indexOfScalar(u8, value, 0) != null) return error.InvalidConsumer;
    }

    pub fn eql(a: Key, b: Key) bool {
        return a.kind == b.kind and std.mem.eql(u8, a.jail, b.jail) and
            std.mem.eql(u8, a.source, b.source) and std.mem.eql(u8, a.rule, b.rule) and
            std.mem.eql(u8, &a.generation, &b.generation);
    }
};

pub const Delta = struct {
    key: Key,
    format_version: u16,
    expected_revision: u64,
    payload: []const u8,
    valid_until_us: ?i64 = null,
};
pub const Dependency = struct {
    key: Key,
    expected_revision: u64,
    valid_until_us: ?i64 = null,
};
pub const Requirement = struct { key: Key, format_version: u16 };
pub const Manifest = struct {
    jail: []const u8,
    source: []const u8,
    source_generation: [32]u8,
    required: []const Requirement,

    pub fn digest(self: Manifest) Error![32]u8 {
        try (Key{ .kind = .rule, .jail = self.jail, .source = self.source, .rule = "manifest", .generation = self.source_generation }).validate();
        if (self.required.len > max_dependencies) return error.ConsumerCapacity;
        var hashes: [max_dependencies][32]u8 = undefined;
        for (self.required, 0..) |requirement, i| {
            try requirement.key.validate();
            if (requirement.format_version == 0) return error.InvalidConsumer;
            for (self.required[0..i]) |prior| if (Key.eql(prior.key, requirement.key)) return error.InvalidConsumer;
            var item = std.crypto.hash.sha2.Sha256.init(.{});
            item.update("fail2zig-required-consumer-v1\x00");
            var format: [2]u8 = undefined;
            std.mem.writeInt(u16, &format, requirement.format_version, .little);
            item.update(&format);
            item.update(&.{@intFromEnum(requirement.key.kind)});
            item.update(&requirement.key.generation);
            for ([_][]const u8{ requirement.key.jail, requirement.key.source, requirement.key.rule }) |value| {
                var length: [8]u8 = undefined;
                std.mem.writeInt(u64, &length, value.len, .little);
                item.update(&length);
                item.update(value);
            }
            item.final(&hashes[i]);
        }
        const Order = struct {
            fn less(_: void, a: [32]u8, b: [32]u8) bool {
                return std.mem.order(u8, &a, &b) == .lt;
            }
        };
        std.mem.sort([32]u8, hashes[0..self.required.len], {}, Order.less);
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("fail2zig-consumer-manifest-v1\x00");
        hash.update(&self.source_generation);
        for ([_][]const u8{ self.jail, self.source }) |value| {
            var length: [8]u8 = undefined;
            std.mem.writeInt(u64, &length, value.len, .little);
            hash.update(&length);
            hash.update(value);
        }
        for (hashes[0..self.required.len]) |value| hash.update(&value);
        return hash.finalResult();
    }
};
pub const Batch = struct {
    deltas: []const Delta = &.{},
    dependencies: []const Dependency = &.{},
    prepared_us: i64,
    commit_before_us: ?i64 = null,
    clock_context: ?*anyopaque = null,
    clock: *const fn (?*anyopaque) i64 = systemClock,
    admission: ?*const fn (?*anyopaque) Error!void = null,

    fn systemClock(_: ?*anyopaque) i64 {
        return std.time.microTimestamp();
    }

    pub fn checkedTime(self: Batch, floor_us: ?i64) Error!i64 {
        if (self.admission) |validate_admission| try validate_admission(self.clock_context);
        const now = self.clock(self.clock_context);
        if (now < self.prepared_us or (floor_us != null and now < floor_us.?)) return error.ConsumerClockReversed;
        if (self.commit_before_us) |deadline| if (now >= deadline) return error.ConsumerExpired;
        for (self.deltas) |delta| if (delta.valid_until_us) |expiry|
            if (now >= expiry) return error.ConsumerExpired;
        for (self.dependencies) |dependency| if (dependency.valid_until_us) |expiry|
            if (now >= expiry) return error.ConsumerExpired;
        return now;
    }

    pub fn validate(self: Batch) Error!void {
        if (self.deltas.len > max_deltas or self.dependencies.len > max_dependencies)
            return error.ConsumerCapacity;
        var bytes: usize = self.deltas.len * @sizeOf(Delta) + self.dependencies.len * @sizeOf(Dependency);
        for (self.deltas, 0..) |delta, i| {
            try delta.key.validate();
            if (delta.format_version == 0 or delta.expected_revision >= std.math.maxInt(i64))
                return error.InvalidConsumer;
            if (delta.payload.len > max_payload) return error.ConsumerCapacity;
            bytes = std.math.add(usize, bytes, delta.payload.len + delta.key.jail.len + delta.key.source.len + delta.key.rule.len) catch return error.ConsumerCapacity;
            if (bytes > max_prepared_bytes) return error.ConsumerCapacity;
            for (self.deltas[0..i]) |prior|
                if (Key.eql(prior.key, delta.key)) return error.InvalidConsumer;
        }
        for (self.dependencies, 0..) |dependency, i| {
            try dependency.key.validate();
            bytes = std.math.add(usize, bytes, dependency.key.jail.len + dependency.key.source.len + dependency.key.rule.len) catch return error.ConsumerCapacity;
            if (bytes > max_prepared_bytes) return error.ConsumerCapacity;
            if (dependency.expected_revision > std.math.maxInt(i64) or
                (dependency.expected_revision == 0 and dependency.valid_until_us != null))
                return error.InvalidConsumer;
            for (self.dependencies[0..i]) |prior|
                if (Key.eql(prior.key, dependency.key)) return error.InvalidConsumer;
            for (self.deltas) |delta| if (Key.eql(delta.key, dependency.key) and
                delta.expected_revision != dependency.expected_revision) return error.InvalidConsumer;
        }
    }
};
