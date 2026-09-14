// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Bounded typed metadata passed from a native retry decision to action
//! preparation. This is not a template namespace or a durable schema.
const std = @import("std");
const shared = @import("shared");
const detection = @import("native_detection_record.zig");
const retry = @import("native_retry.zig");
const canonical = @import("../firewall/scope.zig");
const effects = @import("native_effect.zig");

pub const version: u8 = 1;
pub const encoded_bytes: usize = 1108;
pub const max_name_bytes: usize = 64;
pub const max_value_bytes: usize = 256;
pub const max_event_count: u8 = 128;

pub const Error = error{InvalidActionContext};

fn FixedText(comptime maximum: usize, comptime Length: type) type {
    return struct {
        bytes: [maximum]u8 = [_]u8{0} ** maximum,
        len: Length,

        const Self = @This();

        pub fn init(value: []const u8) error{InvalidActionContext}!Self {
            if (value.len == 0 or value.len > maximum or
                std.mem.indexOfScalar(u8, value, 0) != null or !std.unicode.utf8ValidateSlice(value))
                return error.InvalidActionContext;
            var result = Self{ .len = @intCast(value.len) };
            @memcpy(result.bytes[0..value.len], value);
            return result;
        }

        pub fn slice(self: *const Self) []const u8 {
            return self.bytes[0..self.len];
        }

        fn validate(self: *const Self) error{InvalidActionContext}!void {
            if (self.len == 0 or self.len > maximum) return error.InvalidActionContext;
            const expected = try init(self.slice());
            if (!std.mem.eql(u8, &expected.bytes, &self.bytes)) return error.InvalidActionContext;
        }
    };
}

pub const Name = FixedText(max_name_bytes, u8);
pub const Value = FixedText(max_value_bytes, u16);

pub const Input = struct {
    jail: []const u8,
    filter: []const u8,
    pattern: ?[]const u8 = null,
    source: []const u8,
    occurrence: []const u8,
    enforcement: ?canonical.Subject = null,
    correlation: ?[]const u8 = null,
    user: ?[]const u8 = null,
    port: ?u16 = null,
    event_us: i64,
    decision_us: i64,
    ordinal: u64,
    event_count: u8,
    confirmed_history_count: ?u64 = null,
    source_digest: bool = false,
    occurrence_digest: bool = false,
};

pub const Context = struct {
    jail: Name,
    filter: Name,
    pattern: ?Name,
    source: Name,
    occurrence: Value,
    enforcement: ?canonical.Subject,
    correlation: ?Value,
    user: ?Value,
    /// Captured metadata only. A selected firewall port remains part of the
    /// canonical enforcement scope and must never be inferred from this field.
    port: ?u16,
    event_us: i64,
    decision_us: i64,
    ordinal: u64,
    event_count: u8,
    confirmed_history_count: ?u64,
    /// Oversized physical source/occurrence identities remain authoritative in
    /// the record store. The action view uses an explicit canonical digest.
    source_digest: bool,
    occurrence_digest: bool,

    pub fn init(input: Input) Error!Context {
        const result = Context{
            .jail = try Name.init(input.jail),
            .filter = try Name.init(input.filter),
            .pattern = if (input.pattern) |value| try Name.init(value) else null,
            .source = try Name.init(input.source),
            .occurrence = try Value.init(input.occurrence),
            .enforcement = input.enforcement,
            .correlation = if (input.correlation) |value| try Value.init(value) else null,
            .user = if (input.user) |value| try Value.init(value) else null,
            .port = input.port,
            .event_us = input.event_us,
            .decision_us = input.decision_us,
            .ordinal = input.ordinal,
            .event_count = input.event_count,
            .confirmed_history_count = input.confirmed_history_count,
            .source_digest = input.source_digest,
            .occurrence_digest = input.occurrence_digest,
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: *const Context) Error!void {
        try self.jail.validate();
        try self.filter.validate();
        if (self.pattern) |*value| try value.validate();
        try self.source.validate();
        try self.occurrence.validate();
        if (self.enforcement) |subject| subject.validate() catch return error.InvalidActionContext;
        if (self.correlation) |*value| try value.validate();
        if (self.user) |*value| try value.validate();
        if (self.enforcement == null and self.correlation == null) return error.InvalidActionContext;
        if (self.port) |value| if (value == 0) return error.InvalidActionContext;
        if (self.event_us > self.decision_us or self.ordinal == 0 or self.event_count == 0 or self.event_count > max_event_count)
            return error.InvalidActionContext;
        if (self.source_digest and !canonicalDigest(self.source.slice(), false)) return error.InvalidActionContext;
        if (self.occurrence_digest and !canonicalDigest(self.occurrence.slice(), true)) return error.InvalidActionContext;
    }

    /// The current durable effect format realizes only a canonical host with
    /// all protocols and ports. `fromCanonical` rejects a valid network here;
    /// it never masks or widens it into a host effect.
    pub fn legacyEffectScope(self: *const Context) (Error || effects.Error)!effects.Scope {
        try self.validate();
        const subject = self.enforcement orelse return error.InvalidActionContext;
        return effects.Scope.fromCanonical(.{ .subject = subject });
    }

    pub fn encode(self: *const Context) Error![encoded_bytes]u8 {
        try self.validate();
        var out = [_]u8{0} ** encoded_bytes;
        @memcpy(out[0..4], "F2AC");
        out[4] = version;
        if (self.enforcement != null) out[5] |= 1 << 0;
        if (self.correlation != null) out[5] |= 1 << 1;
        if (self.user != null) out[5] |= 1 << 2;
        if (self.port != null) out[5] |= 1 << 3;
        if (self.pattern != null) out[5] |= 1 << 4;
        if (self.confirmed_history_count != null) out[5] |= 1 << 5;
        if (self.source_digest) out[5] |= 1 << 6;
        if (self.occurrence_digest) out[5] |= 1 << 7;
        if (self.enforcement) |subject| {
            out[6] = @intFromEnum(subject.family);
            out[7] = @intFromEnum(subject.kind);
            out[8] = subject.prefix;
            @memcpy(out[16..32], &subject.address);
        }
        putName(&out, 32, &self.jail);
        putName(&out, 97, &self.filter);
        if (self.pattern) |*value| putName(&out, 162, value);
        putName(&out, 227, &self.source);
        putValue(&out, 292, &self.occurrence);
        if (self.correlation) |*value| putValue(&out, 550, value);
        if (self.user) |*value| putValue(&out, 808, value);
        if (self.port) |value| std.mem.writeInt(u16, out[1066..1068], value, .little);
        std.mem.writeInt(i64, out[1068..1076], self.event_us, .little);
        std.mem.writeInt(i64, out[1076..1084], self.decision_us, .little);
        std.mem.writeInt(u64, out[1084..1092], self.ordinal, .little);
        out[1092] = self.event_count;
        if (self.confirmed_history_count) |value| std.mem.writeInt(u64, out[1100..1108], value, .little);
        return out;
    }

    pub fn decode(bytes: []const u8) Error!Context {
        if (bytes.len != encoded_bytes or !std.mem.eql(u8, bytes[0..4], "F2AC") or bytes[4] != version or
            !std.mem.allEqual(u8, bytes[9..16], 0) or !std.mem.allEqual(u8, bytes[1093..1100], 0))
            return error.InvalidActionContext;
        const flags = bytes[5];
        const enforcement: ?canonical.Subject = if (flags & (1 << 0) != 0) .{
            .family = std.meta.intToEnum(canonical.Family, bytes[6]) catch return error.InvalidActionContext,
            .kind = std.meta.intToEnum(canonical.SubjectKind, bytes[7]) catch return error.InvalidActionContext,
            .prefix = bytes[8],
            .address = bytes[16..32].*,
        } else null;
        const result = try init(.{
            .jail = try nameSlice(bytes, 32),
            .filter = try nameSlice(bytes, 97),
            .pattern = if (flags & (1 << 4) != 0) try nameSlice(bytes, 162) else null,
            .source = try nameSlice(bytes, 227),
            .occurrence = try valueSlice(bytes, 292),
            .enforcement = enforcement,
            .correlation = if (flags & (1 << 1) != 0) try valueSlice(bytes, 550) else null,
            .user = if (flags & (1 << 2) != 0) try valueSlice(bytes, 808) else null,
            .port = if (flags & (1 << 3) != 0) std.mem.readInt(u16, bytes[1066..1068], .little) else null,
            .event_us = std.mem.readInt(i64, bytes[1068..1076], .little),
            .decision_us = std.mem.readInt(i64, bytes[1076..1084], .little),
            .ordinal = std.mem.readInt(u64, bytes[1084..1092], .little),
            .event_count = bytes[1092],
            .confirmed_history_count = if (flags & (1 << 5) != 0) std.mem.readInt(u64, bytes[1100..1108], .little) else null,
            .source_digest = flags & (1 << 6) != 0,
            .occurrence_digest = flags & (1 << 7) != 0,
        });
        const canonical_bytes = try result.encode();
        if (!std.mem.eql(u8, bytes, &canonical_bytes)) return error.InvalidActionContext;
        return result;
    }
};

pub fn fromRetry(
    jail: []const u8,
    source: []const u8,
    occurrence: []const u8,
    outcome: detection.Outcome,
    event_us: i64,
    decision: retry.Decision,
    event_count: u8,
    confirmed_history_count: ?u64,
) Error!Context {
    outcome.validate(.{ .eligible = .{ .timestamp = .{ .us = event_us }, .original = .{ .us = event_us }, .receipt = .{ .us = event_us }, .origin = .event } }) catch return error.InvalidActionContext;
    if (outcome.kind != .candidate or !std.meta.eql(outcome.subject.?, decision.subject)) return error.InvalidActionContext;
    const enforcement = subjectFromDetection(decision.subject);
    var source_buffer: [64]u8 = undefined;
    var occurrence_buffer: [71]u8 = undefined;
    const bounded_source = try boundedIdentity(source, max_name_bytes, false, &source_buffer);
    const bounded_occurrence = try boundedIdentity(occurrence, max_value_bytes, true, &occurrence_buffer);
    return Context.init(.{
        .jail = jail,
        .filter = outcome.filter.slice(),
        .pattern = outcome.pattern.?.slice(),
        .source = bounded_source.value,
        .occurrence = bounded_occurrence.value,
        .enforcement = enforcement,
        .event_us = event_us,
        .decision_us = decision.decided_us,
        .ordinal = decision.ordinal,
        .event_count = event_count,
        .confirmed_history_count = confirmed_history_count,
        .source_digest = bounded_source.digest,
        .occurrence_digest = bounded_occurrence.digest,
    });
}

const BoundedIdentity = struct { value: []const u8, digest: bool };

fn boundedIdentity(value: []const u8, maximum: usize, prefixed: bool, buffer: []u8) Error!BoundedIdentity {
    if (value.len == 0 or std.mem.indexOfScalar(u8, value, 0) != null or !std.unicode.utf8ValidateSlice(value))
        return error.InvalidActionContext;
    if (value.len <= maximum) return .{ .value = value, .digest = false };
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(value, &digest, .{});
    const rendered = if (prefixed)
        std.fmt.bufPrint(buffer, "sha256:{s}", .{std.fmt.fmtSliceHexLower(&digest)}) catch return error.InvalidActionContext
    else
        std.fmt.bufPrint(buffer, "{s}", .{std.fmt.fmtSliceHexLower(&digest)}) catch return error.InvalidActionContext;
    if (rendered.len > maximum) return error.InvalidActionContext;
    return .{ .value = rendered, .digest = true };
}

fn canonicalDigest(value: []const u8, prefixed: bool) bool {
    const digest = if (prefixed) blk: {
        if (!std.mem.startsWith(u8, value, "sha256:")) return false;
        break :blk value[7..];
    } else value;
    if (digest.len != 64) return false;
    for (digest) |byte| if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return false;
    return true;
}

fn subjectFromDetection(subject: detection.Subject) canonical.Subject {
    const address: shared.IpAddress = switch (subject) {
        .v4 => |value| .{ .ipv4 = std.mem.readInt(u32, &value, .big) },
        .v6 => |value| .{ .ipv6 = std.mem.readInt(u128, &value, .big) },
    };
    return canonical.Subject.host(address);
}

fn putName(out: *[encoded_bytes]u8, at: usize, value: *const Name) void {
    out[at] = value.len;
    @memcpy(out[at + 1 .. at + 1 + value.len], value.slice());
}

fn putValue(out: *[encoded_bytes]u8, at: usize, value: *const Value) void {
    std.mem.writeInt(u16, out[at..][0..2], value.len, .little);
    @memcpy(out[at + 2 .. at + 2 + value.len], value.slice());
}

fn nameSlice(bytes: []const u8, at: usize) error{InvalidActionContext}![]const u8 {
    const len = bytes[at];
    if (len == 0 or len > max_name_bytes) return error.InvalidActionContext;
    return bytes[at + 1 .. at + 1 + len];
}

fn valueSlice(bytes: []const u8, at: usize) error{InvalidActionContext}![]const u8 {
    const len = std.mem.readInt(u16, bytes[at..][0..2], .little);
    if (len == 0 or len > max_value_bytes) return error.InvalidActionContext;
    return bytes[at + 2 .. at + 2 + len];
}
