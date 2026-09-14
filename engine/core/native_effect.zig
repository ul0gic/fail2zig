// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Durable canonical effect identities and the byte-stable legacy projection.
//! This module performs no transport or filesystem operations.
const std = @import("std");
const detection = @import("native_detection_record.zig");
const canonical_scope = @import("../firewall/scope.zig");
const native_lease = @import("native_lease.zig");
pub const Hash = [32]u8;
pub const max_effects = 4096;
pub const max_owners = 16384;
pub const max_intents = 65536;
pub const max_owner_revisions = 65536;
pub const max_confirmed_events = 65536;
pub const max_observations = 262144;
pub const max_page = 64;
pub const Error = error{ InvalidEffect, EffectScopeNotRealized, EffectStorageRequired, InstallationRequired, InstallationMismatch, NamespaceAdmissionRequired, EffectCapacity, StaleEffect, EffectGenerationMismatch, EffectReconciliationRequired, EffectExpired, EffectClockReversed, IncompleteEffectObservation };
pub const Backend = enum(u8) { nftables = 1, iptables = 2, ipset = 3 };
pub const Installation = struct {
    id: [16]u8,
    backend: Backend,
    selector_len: u16,
    selector_bytes: [256]u8 = [_]u8{0} ** 256,
    pub fn init(id: [16]u8, backend: Backend, selector_value: []const u8) Error!Installation {
        if (std.mem.allEqual(u8, &id, 0) or selector_value.len == 0 or selector_value.len > 256 or std.mem.indexOfScalar(u8, selector_value, 0) != null) return error.InvalidEffect;
        var result = Installation{ .id = id, .backend = backend, .selector_len = @intCast(selector_value.len) };
        @memcpy(result.selector_bytes[0..selector_value.len], selector_value);
        return result;
    }
    pub fn selector(self: *const Installation) []const u8 {
        return self.selector_bytes[0..self.selector_len];
    }
    pub fn validate(self: *const Installation) Error!void {
        if (self.selector_len > 256) return error.InvalidEffect;
        const canonical = try init(self.id, self.backend, self.selector());
        if (!std.mem.eql(u8, &canonical.selector_bytes, &self.selector_bytes)) return error.InvalidEffect;
    }
};
/// Caller assertion after read-only namespace/topology verification, not proof
/// supplied by the store. Runtime namespace inode must never enter this value.
pub const NamespaceAdmission = struct { selector: []const u8, disposition: enum { verified_absent, verified_owned } };

pub const Scope = struct {
    canonical: canonical_scope.Scope,
    pub const encoded_bytes = 24;
    pub const canonical_encoded_bytes = canonical_scope.encoded_bytes;
    pub fn host(subject: detection.Subject) Error!Scope {
        subject.validate() catch return error.InvalidEffect;
        if (subject.unenforceable()) return error.InvalidEffect;
        const address: @import("shared").IpAddress = switch (subject) {
            .v4 => |value| .{ .ipv4 = std.mem.readInt(u32, &value, .big) },
            .v6 => |value| .{ .ipv6 = std.mem.readInt(u128, &value, .big) },
        };
        return .{ .canonical = .{ .subject = canonical_scope.Subject.host(address) } };
    }
    /// Pre-schema-19 storage admits only the exact legacy host/all/all INPUT
    /// DROP realization. Validate the complete canonical value before this
    /// projection so a richer valid scope is never widened.
    pub fn fromCanonical(value: canonical_scope.Scope) Error!Scope {
        value.validate() catch return error.InvalidEffect;
        if (value.subject.kind != .host or !value.protocols.isAll() or !value.ports.isAll())
            return error.EffectScopeNotRealized;
        const subject: detection.Subject = switch (value.subject.family) {
            .v4 => .{ .v4 = value.subject.address[0..4].* },
            .v6 => .{ .v6 = value.subject.address },
        };
        return host(subject);
    }
    pub fn exact(value: canonical_scope.Scope) Error!Scope {
        value.validate() catch return error.InvalidEffect;
        return .{ .canonical = value };
    }
    pub fn toCanonical(self: Scope) Error!canonical_scope.Scope {
        try self.validate();
        return self.canonical;
    }
    pub fn validate(self: Scope) Error!void {
        self.canonical.validate() catch return error.InvalidEffect;
        if (self.canonical.subject.kind == .host) {
            const subject: detection.Subject = switch (self.canonical.subject.family) {
                .v4 => .{ .v4 = self.canonical.subject.address[0..4].* },
                .v6 => .{ .v6 = self.canonical.subject.address },
            };
            subject.validate() catch return error.InvalidEffect;
            if (subject.unenforceable()) return error.InvalidEffect;
        }
    }
    /// Wire: version1,family4/6,prefix32/128,protocol0(any),hook1(INPUT),
    /// verdict1(DROP),port-count0,interface-length0,network-order address16.
    pub fn encode(self: Scope) Error![encoded_bytes]u8 {
        try self.validate();
        if (self.canonical.subject.kind != .host or !self.canonical.protocols.isAll() or !self.canonical.ports.isAll())
            return error.EffectScopeNotRealized;
        var bytes = [_]u8{0} ** encoded_bytes;
        bytes[0] = 1;
        bytes[1] = @intFromEnum(self.canonical.subject.family);
        bytes[2] = self.canonical.subject.prefix;
        bytes[4] = 1;
        bytes[5] = 1;
        @memcpy(bytes[8..24], &self.canonical.subject.address);
        return bytes;
    }
    pub fn encodeCanonical(self: Scope) Error![canonical_encoded_bytes]u8 {
        try self.validate();
        return self.canonical.encode() catch return error.InvalidEffect;
    }
    pub fn decode(bytes: []const u8) Error!Scope {
        if (bytes.len != encoded_bytes) return error.InvalidEffect;
        const family = std.meta.intToEnum(canonical_scope.Family, bytes[1]) catch return error.InvalidEffect;
        const address: @import("shared").IpAddress = switch (family) {
            .v4 => .{ .ipv4 = std.mem.readInt(u32, bytes[8..12], .big) },
            .v6 => .{ .ipv6 = std.mem.readInt(u128, bytes[8..24], .big) },
        };
        const result = Scope{ .canonical = .{ .subject = canonical_scope.Subject.host(address) } };
        if (!std.mem.eql(u8, bytes, &try result.encode())) return error.InvalidEffect;
        return result;
    }
    pub fn decodeCanonical(bytes: []const u8) Error!Scope {
        const value = canonical_scope.Scope.decode(bytes) catch return error.InvalidEffect;
        return exact(value);
    }
    pub fn key(self: Scope, installation: Installation) Error!Hash {
        try installation.validate();
        if (self.canonical.subject.kind == .host and self.canonical.protocols.isAll() and self.canonical.ports.isAll()) {
            const wire = try self.encode();
            return hashParts("fail2zig-native-physical-effect-v1", &.{ &installation.id, &.{@intFromEnum(installation.backend)}, &wire });
        }
        const wire = try self.encodeCanonical();
        return hashParts("fail2zig-native-physical-effect-v2", &.{ &installation.id, &.{@intFromEnum(installation.backend)}, &wire });
    }
};
pub const Lease = native_lease.Lease;
pub const Status = enum(u8) { pending = 1, dispatched, applied, absent, superseded, expired };
pub const Token = struct { installation: [16]u8, scope_key: Hash, intent_id: Hash, revision: u64 };
pub const Entry = struct {
    installation: Installation,
    scope: Scope,
    scope_key: Hash,
    revision: u64,
    desired: Lease,
    intent_id: Hash,
    status: Status,
    pub fn token(self: Entry) Token {
        return .{ .installation = self.installation.id, .scope_key = self.scope_key, .intent_id = self.intent_id, .revision = self.revision };
    }
};
pub const Owner = struct {
    jail: detection.Name,
    generation: Hash,
    decision_id: Hash,
    revision: u64,
    lease: Lease,
    decided_us: i64,
};
pub const OwnerChange = struct {
    scope: Scope,
    jail: []const u8,
    generation: Hash,
    decision_id: Hash,
    expected_revision: u64,
    lease: Lease,
    decided_us: i64,
};
pub const CanonicalOwnerChange = struct {
    scope: canonical_scope.Scope,
    jail: []const u8,
    generation: Hash,
    decision_id: Hash,
    expected_revision: u64,
    lease: Lease,
    decided_us: i64,

    pub fn legacy(self: CanonicalOwnerChange) Error!OwnerChange {
        return .{
            .scope = try Scope.fromCanonical(self.scope),
            .jail = self.jail,
            .generation = self.generation,
            .decision_id = self.decision_id,
            .expected_revision = self.expected_revision,
            .lease = self.lease,
            .decided_us = self.decided_us,
        };
    }
    pub fn exact(self: CanonicalOwnerChange) Error!OwnerChange {
        return .{
            .scope = try Scope.exact(self.scope),
            .jail = self.jail,
            .generation = self.generation,
            .decision_id = self.decision_id,
            .expected_revision = self.expected_revision,
            .lease = self.lease,
            .decided_us = self.decided_us,
        };
    }
};
pub const OwnerTransitionMode = enum { retain, release };
pub const OwnerTransition = struct {
    scope: canonical_scope.Scope,
    jail: []const u8,
    current_generation: Hash,
    next_generation: Hash,
    expected_owner_revision: u64,
    transition_id: Hash,
    mode: OwnerTransitionMode,
    occurred_us: i64,
};
pub const Page = struct { revision: u64, count: usize, more: bool };
pub const Observation = struct {
    installation: [16]u8,
    scope_key: Hash,
    fingerprint: Hash,
    observed_us: i64,
    qualification: enum { complete_owned, incomplete, foreign, changed },
    /// Exact verified lease. The transport adapter applies its admitted timeout
    /// tolerance before projecting the desired original deadline here.
    state: ?Lease,
};
pub const Settlement = enum { verified, retry_same_intent, expired };
pub const Clock = struct {
    prepared_us: i64,
    context: ?*anyopaque = null,
    read: *const fn (?*anyopaque) i64 = system,
    fn system(_: ?*anyopaque) i64 {
        return std.time.microTimestamp();
    }
    pub fn checked(self: Clock, floor_us: ?i64) Error!i64 {
        const now = self.read(self.context);
        if (now < self.prepared_us or (floor_us != null and now < floor_us.?)) return error.EffectClockReversed;
        return now;
    }
};
pub fn hashParts(domain: []const u8, parts: []const []const u8) Hash {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(domain);
    hash.update(&.{0});
    for (parts) |part| {
        var size: [8]u8 = undefined;
        std.mem.writeInt(u64, &size, part.len, .little);
        hash.update(&size);
        hash.update(part);
    }
    var result: Hash = undefined;
    hash.final(&result);
    return result;
}
pub fn intentId(installation: [16]u8, scope_key: Hash, decision_id: Hash, revision: u64, lease: Lease) Hash {
    var number: [8]u8 = undefined;
    std.mem.writeInt(u64, &number, revision, .little);
    var deadline: [8]u8 = [_]u8{0} ** 8;
    if (lease == .finite) std.mem.writeInt(i64, &deadline, lease.finite, .little);
    return hashParts("fail2zig-native-effect-intent-v1", &.{ &installation, &scope_key, &decision_id, &number, &.{@intFromEnum(lease)}, &deadline });
}
