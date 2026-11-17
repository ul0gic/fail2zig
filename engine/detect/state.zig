// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Parses CIDR text into a network and mask and tests whether an address falls inside it.
// Holds: A parsed network has its host bits cleared, so contains is one mask-and-compare per family.

const std = @import("std");
const shared = @import("shared");

const IpAddress = shared.IpAddress;

pub const max_attempts_per_ip: usize = 128;

pub const Cidr = union(enum) {
    v4: struct { net: u32, mask: u32 },
    v6: struct { net: u128, mask: u128 },

    pub const ParseError = error{InvalidCidr};

    pub fn parse(s: []const u8) ParseError!Cidr {
        var prefix: ?u8 = null;
        var addr_part: []const u8 = s;
        if (std.mem.indexOfScalar(u8, s, '/')) |idx| {
            if (idx == 0 or idx == s.len - 1) return error.InvalidCidr;
            addr_part = s[0..idx];
            const p = std.fmt.parseInt(u8, s[idx + 1 ..], 10) catch
                return error.InvalidCidr;
            prefix = p;
        }

        const ip = IpAddress.parse(addr_part) catch return error.InvalidCidr;
        switch (ip) {
            .ipv4 => |v| {
                const p = prefix orelse 32;
                if (p > 32) return error.InvalidCidr;
                const mask = maskIpv4(p);
                return .{ .v4 = .{ .net = v & mask, .mask = mask } };
            },
            .ipv6 => |v| {
                const p = prefix orelse 128;
                if (p > 128) return error.InvalidCidr;
                const mask = maskIpv6(p);
                return .{ .v6 = .{ .net = v & mask, .mask = mask } };
            },
        }
    }

    pub fn contains(self: Cidr, ip: IpAddress) bool {
        return switch (self) {
            .v4 => |n| switch (ip) {
                .ipv4 => |v| (v & n.mask) == n.net,
                .ipv6 => false,
            },
            .v6 => |n| switch (ip) {
                .ipv6 => |v| (v & n.mask) == n.net,
                .ipv4 => false,
            },
        };
    }
};

fn maskIpv4(prefix: u8) u32 {
    if (prefix == 0) return 0;
    if (prefix >= 32) return 0xFFFF_FFFF;
    return @as(u32, 0xFFFF_FFFF) << @intCast(32 - prefix);
}

fn maskIpv6(prefix: u8) u128 {
    if (prefix == 0) return 0;
    if (prefix >= 128) return ~@as(u128, 0);
    const ones: u128 = ~@as(u128, 0);
    return ones << @intCast(128 - prefix);
}
