// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const types = @import("types.zig");

const linux = std.os.linux;
const mem = std.mem;
const native_endian = @import("builtin").cpu.arch.endian();

const IpAddress = types.IpAddress;

pub const max_self_addresses: u16 = 256;

// The kernel caps one netlink dump skb at 32 KiB (net/netlink/af_netlink.c netlink_dump).
const receive_buffer_bytes: usize = 32 * 1024;
const request_sequence: u32 = 1;

pub const Error = error{ KernelUnavailable, OutOfMemory };

pub const SelfAddresses = struct {
    addresses: []const IpAddress,
    count: u16,
    truncated: bool,

    pub fn deinit(self: *SelfAddresses, allocator: mem.Allocator) void {
        allocator.free(self.addresses);
        self.* = .{ .addresses = &.{}, .count = 0, .truncated = false };
    }
};

const IfAddrMsg = extern struct {
    family: u8,
    prefixlen: u8,
    flags: u8,
    scope: u8,
    index: u32,
};

const Request = extern struct {
    header: linux.nlmsghdr,
    message: IfAddrMsg,
};

const header_bytes = alignMessage(@sizeOf(linux.nlmsghdr));

pub fn read(allocator: mem.Allocator) Error!SelfAddresses {
    const opened = linux.socket(linux.AF.NETLINK, linux.SOCK.RAW | linux.SOCK.CLOEXEC, linux.NETLINK.ROUTE);
    if (linux.E.init(opened) != .SUCCESS) return error.KernelUnavailable;
    const fd: i32 = @intCast(opened);
    defer _ = linux.close(fd);

    var local = linux.sockaddr.nl{ .pid = 0, .groups = 0 };
    if (linux.E.init(linux.bind(fd, @ptrCast(&local), @sizeOf(linux.sockaddr.nl))) != .SUCCESS)
        return error.KernelUnavailable;

    const request = Request{
        .header = .{
            .len = @sizeOf(Request),
            .type = .RTM_GETADDR,
            .flags = linux.NLM_F_REQUEST | linux.NLM_F_DUMP,
            .seq = request_sequence,
            .pid = 0,
        },
        .message = .{ .family = linux.AF.UNSPEC, .prefixlen = 0, .flags = 0, .scope = 0, .index = 0 },
    };
    var kernel = linux.sockaddr.nl{ .pid = 0, .groups = 0 };
    const sent = linux.sendto(fd, mem.asBytes(&request), @sizeOf(Request), 0, @ptrCast(&kernel), @sizeOf(linux.sockaddr.nl));
    if (linux.E.init(sent) != .SUCCESS or sent != @sizeOf(Request)) return error.KernelUnavailable;

    const buffer = try allocator.alloc(u8, receive_buffer_bytes);
    defer allocator.free(buffer);

    var list: std.ArrayListUnmanaged(IpAddress) = .empty;
    errdefer list.deinit(allocator);
    var truncated = false;

    while (true) {
        const received = try receive(fd, buffer);
        var offset: usize = 0;
        while (offset < received.len) {
            const tail = received[offset..];
            if (tail.len < header_bytes) return error.KernelUnavailable;
            const header: linux.nlmsghdr = @bitCast(tail[0..@sizeOf(linux.nlmsghdr)].*);
            const length: usize = header.len;
            if (length < header_bytes or length > tail.len) return error.KernelUnavailable;
            offset += @min(alignMessage(length), tail.len);
            if (header.seq != request_sequence) continue;
            switch (header.type) {
                .DONE => {
                    const count: u16 = @intCast(list.items.len);
                    return .{ .addresses = try list.toOwnedSlice(allocator), .count = count, .truncated = truncated };
                },
                .ERROR => return error.KernelUnavailable,
                .RTM_NEWADDR => {
                    const address = (try hostAddress(tail[header_bytes..length])) orelse continue;
                    if (contains(list.items, address)) continue;
                    if (list.items.len >= max_self_addresses) {
                        truncated = true;
                        continue;
                    }
                    try list.append(allocator, address);
                },
                else => {},
            }
        }
    }
}

fn receive(fd: i32, buffer: []u8) Error![]const u8 {
    while (true) {
        var sender = linux.sockaddr.nl{ .pid = 0, .groups = 0 };
        var sender_len: linux.socklen_t = @sizeOf(linux.sockaddr.nl);
        const rc = linux.recvfrom(fd, buffer.ptr, buffer.len, linux.MSG.TRUNC, @ptrCast(&sender), &sender_len);
        switch (linux.E.init(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.KernelUnavailable,
        }
        if (rc == 0 or rc > buffer.len) return error.KernelUnavailable;
        if (sender_len != @sizeOf(linux.sockaddr.nl) or sender.pid != 0) return error.KernelUnavailable;
        return buffer[0..rc];
    }
}

fn hostAddress(payload: []const u8) Error!?IpAddress {
    const fixed = alignMessage(@sizeOf(IfAddrMsg));
    if (payload.len < fixed) return error.KernelUnavailable;
    const family = payload[0];
    var local: ?[]const u8 = null;
    var peer: ?[]const u8 = null;
    var offset: usize = fixed;
    while (offset < payload.len) {
        const tail = payload[offset..];
        if (tail.len < @sizeOf(linux.rtattr)) return error.KernelUnavailable;
        const length: usize = mem.readInt(u16, tail[0..2], native_endian);
        const kind = mem.readInt(u16, tail[2..4], native_endian);
        if (length < @sizeOf(linux.rtattr) or length > tail.len) return error.KernelUnavailable;
        offset += @min(alignMessage(length), tail.len);
        const value = tail[@sizeOf(linux.rtattr)..length];
        if (kind == @intFromEnum(linux.IFA.LOCAL)) local = value;
        if (kind == @intFromEnum(linux.IFA.ADDRESS)) peer = value;
    }
    // On a point-to-point link IFA_ADDRESS is the remote end; IFA_LOCAL is this host's own address.
    const bytes = local orelse peer orelse return null;
    if (family == linux.AF.INET and bytes.len == 4) return .{ .ipv4 = mem.readInt(u32, bytes[0..4], .big) };
    if (family == linux.AF.INET6 and bytes.len == 16)
        return IpAddress.fromIpv6Bits(mem.readInt(u128, bytes[0..16], .big)) catch null;
    return null;
}

fn contains(addresses: []const IpAddress, address: IpAddress) bool {
    for (addresses) |existing| {
        if (existing.eql(address)) return true;
    }
    return false;
}

fn alignMessage(length: usize) usize {
    return (length + 3) & ~@as(usize, 3);
}
