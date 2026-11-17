// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Collects read-back entries and scoped rule groups into one sorted, fingerprinted snapshot.
// Holds: A finished snapshot holds no entry twice: a repeated host fails as DumpInterrupted, any other repeat as UnknownState.

const std = @import("std");
const mem = @import("std").mem;
const Entry = @import("inspection.zig").Entry;
const Error = @import("inspection.zig").Error;
const Installation = @import("inspection.zig").Installation;
const Limits = @import("inspection.zig").Limits;
const ScopedRuleMetadata = @import("inspection.zig").ScopedRuleMetadata;
const Snapshot = @import("inspection.zig").Snapshot;
const subjectAddress = @import("inspection.zig").subjectAddress;
const entryLess = @import("inspection_entries.zig").entryLess;
const entryScope = @import("inspection_entries.zig").entryScope;

pub const Builder = struct {
    allocator: mem.Allocator,
    installation: Installation,
    limits: Limits,
    entries: std.ArrayList(Entry),
    present: bool = false,
    transient_bytes: usize = 0,
    topology: std.crypto.hash.sha2.Sha256 = std.crypto.hash.sha2.Sha256.init(.{}),
    pub fn init(a: mem.Allocator, i: Installation, limits: Limits) Builder {
        return .{ .allocator = a, .installation = i, .limits = limits, .entries = std.ArrayList(Entry).init(a) };
    }
    pub fn deinit(self: *Builder) void {
        self.entries.deinit();
    }
    pub fn add(self: *Builder, e: Entry) Error!void {
        if (self.entries.items.len >= self.limits.max_entries or
            self.entries.items.len >= self.limits.max_bytes / @sizeOf(Entry)) return error.LimitExceeded;
        if (self.transient_bytes > self.limits.max_bytes) return error.LimitExceeded;
        const capacity_limit = @min(self.limits.max_entries, (self.limits.max_bytes - self.transient_bytes) / (2 * @sizeOf(Entry)));
        if (self.entries.items.len >= capacity_limit) return error.LimitExceeded;
        if (self.entries.items.len == self.entries.capacity) {
            const capacity = @min(capacity_limit, self.entries.capacity + self.entries.capacity / 2 + 8);
            try self.entries.ensureTotalCapacityPrecise(capacity);
        }
        self.entries.appendAssumeCapacity(e);
    }
    pub fn structureDigest(self: *const Builder) [32]u8 {
        var structure = self.topology;
        structure.update(&.{@intFromBool(self.present)});
        var digest: [32]u8 = undefined;
        structure.final(&digest);
        return digest;
    }
    pub fn finish(self: *Builder, start: u64, end: u64) Error!Snapshot {
        mem.sort(Entry, self.entries.items, {}, entryLess);
        for (self.entries.items, 0..) |e, index| {
            // Why: Walking a hash set during a kernel resize can yield an element twice, so a duplicate host is a read to repeat.
            if (index > 0 and !entryLess(
                {},
                self.entries.items[index - 1],
                e,
            )) return if (e.scope == null and self.entries.items[index - 1].scope == null) error.DumpInterrupted else error.UnknownState;
            const scope_bytes = entryScope(e).encode() catch return error.UnknownState;
            self.topology.update(&scope_bytes);
            self.topology.update(&.{ @intFromBool(e.remaining_ms != null), @intFromBool(e.deadline_us != null), @intFromBool(e.effect_id != null), @intFromBool(e.partial) });
            if (e.deadline_us) |deadline| self.topology.update(mem.asBytes(&deadline));
            if (e.effect_id) |identity| self.topology.update(&identity);
        }
        self.topology.update(&.{@intFromBool(self.present)});
        var fingerprint: [32]u8 = undefined;
        self.topology.final(&fingerprint);
        return .{
            .allocator = self.allocator,
            .installation = self.installation,
            .state = if (self.present) .owned else .absent,
            .entries = try self.entries.toOwnedSlice(),
            .fingerprint = fingerprint,
            .observed_start_ns = start,
            .observed_end_ns = end,
        };
    }
};

pub const ScopedGroup = struct { metadata: ScopedRuleMetadata, parts: u32 = 0, partial: bool = false };

pub fn collectScopedGroup(groups: *std.ArrayList(ScopedGroup), metadata: ScopedRuleMetadata, limits: Limits) Error!void {
    var group_index: ?usize = null;
    for (groups.items, 0..) |group, index| if (mem.eql(u8, &group.metadata.effect_id, &metadata.effect_id)) {
        group_index = index;
        break;
    };
    if (group_index == null) {
        if (groups.items.len >= limits.max_entries or groups.items.len >= limits.max_bytes / @sizeOf(ScopedGroup)) return error.LimitExceeded;
        try groups.append(.{ .metadata = metadata });
        group_index = groups.items.len - 1;
    }
    const group = &groups.items[group_index.?];
    if (!std.meta.eql(group.metadata.scope, metadata.scope) or group.metadata.count != metadata.count or metadata.part >= 32)
        return error.ForeignState;
    if (group.metadata.deadline_us != metadata.deadline_us) group.partial = true;
    const bit = @as(u32, 1) << @intCast(metadata.part);
    if (group.parts & bit != 0) group.partial = true;
    group.parts |= bit;
}

pub fn finishScopedGroups(builder: *Builder, groups: []const ScopedGroup) Error!void {
    for (groups) |group| {
        const wanted = (@as(u32, 1) << @intCast(group.metadata.count)) - 1;
        try builder.add(.{
            .address = subjectAddress(group.metadata.scope.subject),
            .scope = group.metadata.scope,
            .deadline_us = group.metadata.deadline_us,
            .effect_id = group.metadata.effect_id,
            .partial = group.partial or group.parts != wanted,
        });
    }
}
