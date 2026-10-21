// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const shared = @import("shared");

pub const encoded_version: u8 = 2;
pub const max_port_endpoint_units: usize = 15;
pub const max_port_ranges: usize = max_port_endpoint_units;
pub const encoded_bytes: usize = 32 + max_port_ranges * 4;
pub const Hash = [32]u8;

pub const Error = error{
    InvalidSubject,
    NonCanonicalNetwork,
    InvalidProtocol,
    InvalidPorts,
    PortLimitExceeded,
    UnsupportedCombination,
    UnsupportedTopology,
    UnsupportedVerdict,
    UnsupportedTarget,
    InvalidEncoding,
};

pub const Family = enum(u8) { v4 = 4, v6 = 6 };
pub const SubjectKind = enum(u8) { host = 1, network = 2 };

pub const Subject = struct {
    family: Family,
    kind: SubjectKind,
    prefix: u8,
    address: [16]u8,

    pub fn host(address: shared.IpAddress) Subject {
        return fromAddress(address, .host, if (address == .ipv4) 32 else 128);
    }

    pub fn network(address: shared.IpAddress, prefix: u8) Error!Subject {
        const result = fromAddress(address, .network, prefix);
        try result.validate();
        return result;
    }

    pub fn parseHost(text: []const u8) Error!Subject {
        if (std.mem.indexOfScalar(u8, text, '/')) |_| return error.InvalidSubject;
        const address = shared.IpAddress.parse(text) catch return error.InvalidSubject;
        if (address == .ipv4 and std.mem.indexOfScalar(u8, text, ':') != null) return error.InvalidSubject;
        return host(address);
    }

    pub fn parseNetwork(text: []const u8) Error!Subject {
        const slash = std.mem.indexOfScalar(u8, text, '/') orelse return error.InvalidSubject;
        if (slash == 0 or slash + 1 == text.len or std.mem.indexOfScalarPos(u8, text, slash + 1, '/') != null) return error.InvalidSubject;
        const address = shared.IpAddress.parse(text[0..slash]) catch return error.InvalidSubject;
        if (address == .ipv4 and std.mem.indexOfScalar(u8, text[0..slash], ':') != null) return error.InvalidSubject;
        const prefix = std.fmt.parseInt(u8, text[slash + 1 ..], 10) catch return error.InvalidSubject;
        return network(address, prefix);
    }

    fn fromAddress(address: shared.IpAddress, kind: SubjectKind, prefix: u8) Subject {
        var result = Subject{
            .family = if (address == .ipv4) .v4 else .v6,
            .kind = kind,
            .prefix = prefix,
            .address = [_]u8{0} ** 16,
        };
        switch (address) {
            .ipv4 => |value| std.mem.writeInt(u32, result.address[0..4], value, .big),
            .ipv6 => |value| std.mem.writeInt(u128, &result.address, value, .big),
        }
        return result;
    }

    pub fn validate(self: Subject) Error!void {
        const width: u8 = if (self.family == .v4) 32 else 128;
        if (self.prefix > width) return error.InvalidSubject;
        if (self.family == .v4 and !std.mem.allEqual(u8, self.address[4..], 0)) return error.InvalidSubject;
        if (self.kind == .host) {
            if (self.prefix != width) return error.InvalidSubject;
            return;
        }

        const canonical = switch (self.family) {
            .v4 => blk: {
                const value = std.mem.readInt(u32, self.address[0..4], .big);
                const mask = prefixMask(u32, self.prefix);
                break :blk (value & mask) == value;
            },
            .v6 => blk: {
                const value = std.mem.readInt(u128, &self.address, .big);
                const mask = prefixMask(u128, self.prefix);
                break :blk (value & mask) == value;
            },
        };
        if (!canonical) return error.NonCanonicalNetwork;
    }

    fn prefixMask(comptime T: type, prefix: u8) T {
        const bits = @bitSizeOf(T);
        if (prefix == 0) return 0;
        if (prefix == bits) return ~@as(T, 0);
        return (~@as(T, 0)) << @intCast(bits - prefix);
    }
};

pub const Protocol = enum(u8) {
    all = 0,
    tcp = 1,
    udp = 2,
    icmp_v4 = 3,
    icmp_v6 = 4,

    pub fn familyIcmp(family: Family) Protocol {
        return if (family == .v4) .icmp_v4 else .icmp_v6;
    }
};

pub const Protocols = struct {
    mask: u8,

    const all_bit: u8 = 1 << 0;
    const tcp_bit: u8 = 1 << 1;
    const udp_bit: u8 = 1 << 2;
    const icmp_v4_bit: u8 = 1 << 3;
    const icmp_v6_bit: u8 = 1 << 4;
    const known_bits = all_bit | tcp_bit | udp_bit | icmp_v4_bit | icmp_v6_bit;

    pub fn all() Protocols {
        return .{ .mask = all_bit };
    }

    pub fn one(value: Protocol) Error!Protocols {
        if (value == .all) return all();
        return list(&.{value});
    }

    pub fn list(values: []const Protocol) Error!Protocols {
        if (values.len == 0) return error.InvalidProtocol;
        var result = Protocols{ .mask = 0 };
        for (values) |value| {
            if (value == .all) return error.InvalidProtocol;
            result.mask |= bit(value);
        }
        if (result.mask == 0) return error.InvalidProtocol;
        return result;
    }

    pub fn validate(self: Protocols, family: Family) Error!void {
        if (self.mask == 0 or self.mask & ~known_bits != 0) return error.InvalidProtocol;
        if (self.mask & all_bit != 0) {
            if (self.mask != all_bit) return error.InvalidProtocol;
            return;
        }
        if (family == .v4 and self.mask & icmp_v6_bit != 0) return error.InvalidProtocol;
        if (family == .v6 and self.mask & icmp_v4_bit != 0) return error.InvalidProtocol;
    }

    pub fn isAll(self: Protocols) bool {
        return self.mask == all_bit;
    }

    pub fn containsIcmp(self: Protocols) bool {
        return self.mask & (icmp_v4_bit | icmp_v6_bit) != 0;
    }

    pub fn contains(self: Protocols, value: Protocol) bool {
        return self.mask & bit(value) != 0;
    }

    pub fn portsMeaningful(self: Protocols) bool {
        return !self.isAll() and !self.containsIcmp() and self.mask & (tcp_bit | udp_bit) != 0;
    }

    fn bit(value: Protocol) u8 {
        return @as(u8, 1) << @intCast(@intFromEnum(value));
    }
};

pub const PortRange = struct {
    first: u16,
    last: u16,

    pub fn one(port: u16) PortRange {
        return .{ .first = port, .last = port };
    }
};

pub const Ports = struct {
    ranges: [max_port_ranges]PortRange = [_]PortRange{.{ .first = 0, .last = 0 }} ** max_port_ranges,
    len: u8 = 0,
    endpoint_units: u8 = 0,

    pub fn all() Ports {
        return .{};
    }

    pub fn list(values: []const PortRange) Error!Ports {
        if (values.len == 0) return error.InvalidPorts;
        if (values.len > max_port_ranges) return error.PortLimitExceeded;
        var sorted: [max_port_ranges]PortRange = [_]PortRange{.{ .first = 0, .last = 0 }} ** max_port_ranges;
        for (values, 0..) |value, index| {
            if (value.first == 0 or value.last < value.first) return error.InvalidPorts;
            sorted[index] = value;
        }
        var index: usize = 1;
        while (index < values.len) : (index += 1) {
            const value = sorted[index];
            var at = index;
            while (at > 0 and lessThan(value, sorted[at - 1])) : (at -= 1) sorted[at] = sorted[at - 1];
            sorted[at] = value;
        }

        var result = Ports{};
        for (sorted[0..values.len]) |value| {
            if (result.len != 0) {
                const prior = &result.ranges[result.len - 1];
                if (value.first <= prior.last) return error.InvalidPorts;
                if (prior.last != std.math.maxInt(u16) and value.first == prior.last + 1) {
                    prior.last = value.last;
                    continue;
                }
            }
            result.ranges[result.len] = value;
            result.len += 1;
        }
        var units: usize = 0;
        for (result.slice()) |value| units += if (value.first == value.last) 1 else 2;
        if (units > max_port_endpoint_units) return error.PortLimitExceeded;
        result.endpoint_units = @intCast(units);
        return result;
    }

    pub fn validate(self: Ports) Error!void {
        if (self.len > max_port_ranges) return error.InvalidPorts;
        if (self.len == 0) {
            if (self.endpoint_units != 0 or !allZero(self.ranges[0..])) return error.InvalidPorts;
            return;
        }
        const canonical = try list(self.slice());
        if (!std.meta.eql(self, canonical)) return error.InvalidPorts;
    }

    pub fn isAll(self: Ports) bool {
        return self.len == 0;
    }

    pub const Shape = enum { all, one, range, multi };

    pub fn shape(self: Ports) Shape {
        if (self.len == 0) return .all;
        if (self.len > 1) return .multi;
        return if (self.ranges[0].first == self.ranges[0].last) .one else .range;
    }

    pub fn slice(self: *const Ports) []const PortRange {
        return self.ranges[0..self.len];
    }

    fn lessThan(a: PortRange, b: PortRange) bool {
        return a.first < b.first or (a.first == b.first and a.last < b.last);
    }

    fn allZero(values: []const PortRange) bool {
        for (values) |value| if (value.first != 0 or value.last != 0) return false;
        return true;
    }
};

pub const MatchDirection = enum(u8) { source = 1, destination = 2 };
pub const Hook = enum(u8) { input = 1, output = 2, forward = 3 };
pub const Plane = enum(u8) { filter = 1, nat = 2, raw = 3, mangle = 4 };
pub const Path = enum(u8) { local = 1, bridge = 2 };
pub const InterfaceScope = enum(u8) { any = 1, explicit = 2 };
pub const Attachment = enum(u8) { managed = 1, custom_table = 2, custom_chain = 3, custom_priority = 4, pre_rule = 5 };
pub const Verdict = enum(u8) { drop = 1, reject = 2, accept = 3, @"return" = 4, jump = 5, custom = 6 };
pub const Target = enum(u8) { firewall = 1, provider = 2, action = 3 };

pub const Topology = struct {
    match: MatchDirection = .source,
    hook: Hook = .input,
    plane: Plane = .filter,
    path: Path = .local,
    interface: InterfaceScope = .any,
    attachment: Attachment = .managed,

    pub fn validate(self: Topology) Error!void {
        if (self.match != .source or self.hook != .input or self.plane != .filter or
            self.path != .local or self.interface != .any or self.attachment != .managed)
            return error.UnsupportedTopology;
    }
};

pub const Scope = struct {
    subject: Subject,
    protocols: Protocols = Protocols.all(),
    ports: Ports = Ports.all(),
    topology: Topology = .{},
    verdict: Verdict = .drop,
    target: Target = .firewall,

    pub fn validate(self: Scope) Error!void {
        try self.subject.validate();
        try self.protocols.validate(self.subject.family);
        try self.ports.validate();
        try self.topology.validate();
        if (self.verdict != .drop) return error.UnsupportedVerdict;
        if (self.target != .firewall) return error.UnsupportedTarget;
        if (!self.ports.isAll() and !self.protocols.portsMeaningful()) return error.UnsupportedCombination;
    }

    pub fn encode(self: Scope) Error![encoded_bytes]u8 {
        try self.validate();
        var bytes = [_]u8{0} ** encoded_bytes;
        bytes[0] = encoded_version;
        bytes[1] = @intFromEnum(self.subject.family);
        bytes[2] = @intFromEnum(self.subject.kind);
        bytes[3] = self.subject.prefix;
        bytes[4] = self.protocols.mask;
        bytes[5] = self.ports.len;
        bytes[6] = self.ports.endpoint_units;
        bytes[7] = @intFromEnum(self.topology.match);
        bytes[8] = @intFromEnum(self.topology.hook);
        bytes[9] = @intFromEnum(self.topology.plane);
        bytes[10] = @intFromEnum(self.topology.path);
        bytes[11] = @intFromEnum(self.topology.interface);
        bytes[12] = @intFromEnum(self.topology.attachment);
        bytes[13] = @intFromEnum(self.verdict);
        bytes[14] = @intFromEnum(self.target);
        @memcpy(bytes[16..32], &self.subject.address);
        for (self.ports.slice(), 0..) |value, index| {
            const at = 32 + index * 4;
            std.mem.writeInt(u16, bytes[at..][0..2], value.first, .big);
            std.mem.writeInt(u16, bytes[at + 2 ..][0..2], value.last, .big);
        }
        return bytes;
    }

    pub fn decode(bytes: []const u8) Error!Scope {
        if (bytes.len != encoded_bytes or bytes[0] != encoded_version or bytes[15] != 0) return error.InvalidEncoding;
        const family = std.meta.intToEnum(Family, bytes[1]) catch return error.InvalidEncoding;
        const kind = std.meta.intToEnum(SubjectKind, bytes[2]) catch return error.InvalidEncoding;
        const match = std.meta.intToEnum(MatchDirection, bytes[7]) catch return error.InvalidEncoding;
        const hook = std.meta.intToEnum(Hook, bytes[8]) catch return error.InvalidEncoding;
        const plane = std.meta.intToEnum(Plane, bytes[9]) catch return error.InvalidEncoding;
        const path = std.meta.intToEnum(Path, bytes[10]) catch return error.InvalidEncoding;
        const interface = std.meta.intToEnum(InterfaceScope, bytes[11]) catch return error.InvalidEncoding;
        const attachment = std.meta.intToEnum(Attachment, bytes[12]) catch return error.InvalidEncoding;
        const verdict = std.meta.intToEnum(Verdict, bytes[13]) catch return error.InvalidEncoding;
        const target = std.meta.intToEnum(Target, bytes[14]) catch return error.InvalidEncoding;
        if (bytes[5] > max_port_ranges) return error.InvalidEncoding;
        var ports = Ports{ .len = bytes[5], .endpoint_units = bytes[6] };
        for (ports.ranges[0..ports.len], 0..) |*value, index| {
            const at = 32 + index * 4;
            value.* = .{
                .first = std.mem.readInt(u16, bytes[at..][0..2], .big),
                .last = std.mem.readInt(u16, bytes[at + 2 ..][0..2], .big),
            };
        }
        const result = Scope{
            .subject = .{ .family = family, .kind = kind, .prefix = bytes[3], .address = bytes[16..32].* },
            .protocols = .{ .mask = bytes[4] },
            .ports = ports,
            .topology = .{ .match = match, .hook = hook, .plane = plane, .path = path, .interface = interface, .attachment = attachment },
            .verdict = verdict,
            .target = target,
        };
        const canonical = result.encode() catch return error.InvalidEncoding;
        if (!std.mem.eql(u8, bytes, &canonical)) return error.InvalidEncoding;
        return result;
    }

    pub fn identity(self: Scope) Error!Hash {
        const bytes = try self.encode();
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("fail2zig-native-firewall-scope-v2\x00");
        hash.update(&bytes);
        var result: Hash = undefined;
        hash.final(&result);
        return result;
    }
};
