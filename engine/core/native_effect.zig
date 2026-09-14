// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Pure durable N2 host INPUT DROP identities. No transport or filesystem imports.
const std = @import("std");
const detection = @import("native_detection_record.zig");
pub const Hash = [32]u8;
pub const max_effects = 4096;
pub const max_owners = 16384;
pub const max_intents = 65536;
pub const max_owner_revisions = 65536;
pub const max_confirmed_events = 65536;
pub const max_observations = 262144;
pub const max_page = 64;
pub const Error = error{ InvalidEffect, EffectStorageRequired, InstallationRequired, InstallationMismatch, NamespaceAdmissionRequired, EffectCapacity, StaleEffect, EffectGenerationMismatch, EffectReconciliationRequired, EffectExpired, EffectClockReversed, IncompleteEffectObservation };
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
    family: enum(u8) { v4 = 4, v6 = 6 },
    address: [16]u8,
    pub const encoded_bytes = 24;
    pub fn host(subject: detection.Subject) Error!Scope {
        subject.validate() catch return error.InvalidEffect;
        if (subject.unenforceable()) return error.InvalidEffect;
        var result = Scope{ .family = if (subject == .v4) .v4 else .v6, .address = [_]u8{0} ** 16 };
        switch (subject) {
            .v4 => |v| @memcpy(result.address[0..4], &v),
            .v6 => |v| result.address = v,
        }
        return result;
    }
    pub fn validate(self: Scope) Error!void {
        const subject: detection.Subject = switch (self.family) {
            .v4 => .{ .v4 = self.address[0..4].* },
            .v6 => .{ .v6 = self.address },
        };
        const canonical = try host(subject);
        if (!std.mem.eql(u8, &self.address, &canonical.address)) return error.InvalidEffect;
    }
    /// Wire: version1,family4/6,prefix32/128,protocol0(any),hook1(INPUT),
    /// verdict1(DROP),port-count0,interface-length0,network-order address16.
    pub fn encode(self: Scope) Error![encoded_bytes]u8 {
        try self.validate();
        var bytes = [_]u8{0} ** encoded_bytes;
        bytes[0] = 1;
        bytes[1] = @intFromEnum(self.family);
        bytes[2] = if (self.family == .v4) 32 else 128;
        bytes[4] = 1;
        bytes[5] = 1;
        @memcpy(bytes[8..24], &self.address);
        return bytes;
    }
    pub fn decode(bytes: []const u8) Error!Scope {
        if (bytes.len != encoded_bytes) return error.InvalidEffect;
        const family = std.meta.intToEnum(@FieldType(Scope, "family"), bytes[1]) catch return error.InvalidEffect;
        const result = Scope{ .family = family, .address = bytes[8..24].* };
        if (!std.mem.eql(u8, bytes, &try result.encode())) return error.InvalidEffect;
        return result;
    }
    pub fn key(self: Scope, installation: Installation) Error!Hash {
        try installation.validate();
        const wire = try self.encode();
        return hashParts("fail2zig-native-physical-effect-v1", &.{ &installation.id, &.{@intFromEnum(installation.backend)}, &wire });
    }
};
pub const Lease = union(enum(u8)) {
    absent = 0,
    finite: i64 = 1,
    permanent = 2,
    pub fn live(self: Lease, now_us: i64) bool {
        return switch (self) {
            .absent => false,
            .finite => |until| until > now_us,
            .permanent => true,
        };
    }
    pub fn eql(a: Lease, b: Lease) bool {
        return std.meta.eql(a, b);
    }
};
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
