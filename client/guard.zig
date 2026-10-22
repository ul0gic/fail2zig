// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const shared = @import("shared");

const IpAddress = shared.IpAddress;
const IgnoreEntry = shared.types.IgnoreEntry;
const SelfAddresses = shared.self_addresses.SelfAddresses;

pub const GuardReason = enum { loopback, host_address, ssh_peer };

pub const GuardVerdict = union(enum) {
    allowed,
    protected: struct { matched: IpAddress, reason: GuardReason },
};

const Loopback = struct { range: IgnoreEntry, address: IpAddress };

const loopbacks = [_]Loopback{
    .{ .range = .{ .family = .v4, .address = .{ 127, 0, 0, 0 } ++ .{0} ** 12, .prefix = 8 }, .address = .{ .ipv4 = 0x7f00_0001 } },
    .{ .range = .{ .family = .v6, .address = .{0} ** 15 ++ .{1}, .prefix = 128 }, .address = .{ .ipv6 = 1 } },
};

pub fn check(target: IgnoreEntry, self: SelfAddresses, ssh_connection: ?[]const u8) GuardVerdict {
    for (loopbacks) |loopback| {
        if (loopback.range.contains(target.network())) return protect(target.network(), .loopback);
        if (target.contains(loopback.address)) return protect(loopback.address, .loopback);
    }
    for (self.addresses) |address| {
        if (target.contains(address)) return protect(address, .host_address);
    }
    if (sshPeer(ssh_connection)) |peer| {
        if (target.contains(peer)) return protect(peer, .ssh_peer);
    }
    return .allowed;
}

fn protect(matched: IpAddress, reason: GuardReason) GuardVerdict {
    return .{ .protected = .{ .matched = matched, .reason = reason } };
}

fn sshPeer(ssh_connection: ?[]const u8) ?IpAddress {
    const value = ssh_connection orelse return null;
    var fields = std.mem.tokenizeScalar(u8, value, ' ');
    const first = fields.next() orelse return null;
    const address = first[0 .. std.mem.indexOfScalar(u8, first, '%') orelse first.len];
    return IpAddress.parse(address) catch null;
}
