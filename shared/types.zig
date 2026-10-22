// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const duration = @import("duration.zig");

pub const Timestamp = i64;
pub const Duration = u64;

pub const BanState = enum(u8) {
    monitoring = 0,
    banned = 1,
    expired = 2,
};

pub const IpAddress = union(enum) {
    ipv4: u32,
    ipv6: u128,

    pub const Error = error{Invalid};

    pub fn parse(s: []const u8) Error!IpAddress {
        if (parseIpv4(s)) |v| return .{ .ipv4 = v };
        if (parseIpv6(s)) |v| return fromIpv6Bits(v);
        return error.Invalid;
    }

    pub fn fromIpv6Bits(v: u128) Error!IpAddress {
        const mapped_prefix: u128 = 0x0000_0000_0000_0000_0000_ffff_0000_0000;
        const mapped_mask: u128 = 0xffff_ffff_ffff_ffff_ffff_ffff_0000_0000;
        if ((v & mapped_mask) == mapped_prefix) {
            return .{ .ipv4 = @truncate(v) };
        }
        const compat_mask: u128 = 0xffff_ffff_ffff_ffff_ffff_ffff_0000_0000;
        if ((v & compat_mask) == 0) {
            const low32: u32 = @truncate(v);
            if (low32 != 0 and low32 != 1) {
                return error.Invalid;
            }
        }
        return .{ .ipv6 = v };
    }

    pub fn eql(a: IpAddress, b: IpAddress) bool {
        return std.meta.eql(a, b);
    }

    pub fn isUnenforceable(self: IpAddress) bool {
        switch (self) {
            .ipv4 => |v| {
                if ((v & 0xff00_0000) == 0x0000_0000) return true;
                if ((v & 0xff00_0000) == 0x7f00_0000) return true;
                return false;
            },
            .ipv6 => |v| {
                return v == 0 or v == 1;
            },
        }
    }

    pub fn format(
        self: IpAddress,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        switch (self) {
            .ipv4 => |v| try writer.print("{}.{}.{}.{}", .{
                (v >> 24) & 0xff,
                (v >> 16) & 0xff,
                (v >> 8) & 0xff,
                v & 0xff,
            }),
            .ipv6 => |v| try formatIpv6(v, writer),
        }
    }

    fn parseIpv4(s: []const u8) ?u32 {
        if (s.len < 7 or s.len > 15) return null;

        var result: u32 = 0;
        var octets: u8 = 0;
        var current: u32 = 0;
        var digits: u8 = 0;

        for (s) |c| {
            switch (c) {
                '0'...'9' => {
                    current = current * 10 + @as(u32, c - '0');
                    digits += 1;
                    if (digits > 3 or current > 255) return null;
                },
                '.' => {
                    if (digits == 0 or octets >= 3) return null;
                    result = (result << 8) | current;
                    octets += 1;
                    current = 0;
                    digits = 0;
                },
                else => return null,
            }
        }
        if (digits == 0 or octets != 3) return null;
        return (result << 8) | current;
    }

    fn parseIpv6(s: []const u8) ?u128 {
        const addr = std.net.Ip6Address.parse(s, 0) catch return null;
        return std.mem.readInt(u128, &addr.sa.addr, .big);
    }

    fn formatIpv6(v: u128, writer: anytype) !void {
        var groups: [8]u16 = undefined;
        inline for (0..8) |i| {
            const shift: u7 = @intCast((7 - i) * 16);
            groups[i] = @truncate(v >> shift);
        }

        var best_start: isize = -1;
        var best_len: usize = 0;
        var i: usize = 0;
        while (i < 8) {
            if (groups[i] == 0) {
                var j = i;
                while (j < 8 and groups[j] == 0) : (j += 1) {}
                const run = j - i;
                if (run >= 2 and run > best_len) {
                    best_start = @intCast(i);
                    best_len = run;
                }
                i = j;
            } else {
                i += 1;
            }
        }

        if (best_start < 0) {
            for (groups, 0..) |g, idx| {
                if (idx > 0) try writer.writeAll(":");
                try writer.print("{x}", .{g});
            }
            return;
        }

        const bs: usize = @intCast(best_start);
        const be: usize = bs + best_len;

        for (0..bs) |idx| {
            if (idx > 0) try writer.writeAll(":");
            try writer.print("{x}", .{groups[idx]});
        }
        try writer.writeAll("::");
        for (be..8) |idx| {
            if (idx > be) try writer.writeAll(":");
            try writer.print("{x}", .{groups[idx]});
        }
    }
};

pub const IgnoreEntry = struct {
    family: Family,
    address: [16]u8,
    prefix: u8,

    pub const Family = enum(u8) { v4 = 4, v6 = 6 };
    pub const max_text_bytes: usize = 64;

    pub fn parse(text: []const u8) error{ InvalidAddress, InvalidPrefix }!IgnoreEntry {
        if (text.len == 0 or text.len > max_text_bytes) return error.InvalidAddress;
        const slash = std.mem.indexOfScalar(u8, text, '/');
        const ip = IpAddress.parse(text[0 .. slash orelse text.len]) catch return error.InvalidAddress;
        const requested: ?u8 = if (slash) |index|
            std.fmt.parseInt(u8, text[index + 1 ..], 10) catch return error.InvalidPrefix
        else
            null;
        var address = [_]u8{0} ** 16;
        switch (ip) {
            .ipv4 => |bits| {
                const prefix = requested orelse 32;
                if (prefix > 32) return error.InvalidPrefix;
                std.mem.writeInt(u32, address[0..4], bits & prefixMask(u32, prefix), .big);
                return .{ .family = .v4, .address = address, .prefix = prefix };
            },
            .ipv6 => |bits| {
                const prefix = requested orelse 128;
                if (prefix > 128) return error.InvalidPrefix;
                std.mem.writeInt(u128, &address, bits & prefixMask(u128, prefix), .big);
                return .{ .family = .v6, .address = address, .prefix = prefix };
            },
        }
    }

    pub fn network(self: IgnoreEntry) IpAddress {
        return switch (self.family) {
            .v4 => .{ .ipv4 = std.mem.readInt(u32, self.address[0..4], .big) },
            .v6 => .{ .ipv6 = std.mem.readInt(u128, &self.address, .big) },
        };
    }

    pub fn canonical(self: IgnoreEntry, buf: *[64]u8) []const u8 {
        const full_prefix: u8 = if (self.family == .v4) 32 else 128;
        const printed = if (self.prefix == full_prefix)
            std.fmt.bufPrint(buf, "{}", .{self.network()})
        else
            std.fmt.bufPrint(buf, "{}/{d}", .{ self.network(), self.prefix });
        // Longest form is 39 address bytes plus "/128", inside the 64-byte buffer.
        return printed catch unreachable;
    }

    pub fn contains(self: IgnoreEntry, ip: IpAddress) bool {
        return switch (ip) {
            .ipv4 => |bits| self.family == .v4 and (bits & prefixMask(u32, self.prefix)) == std.mem.readInt(u32, self.address[0..4], .big),
            .ipv6 => |bits| self.family == .v6 and (bits & prefixMask(u128, self.prefix)) == std.mem.readInt(u128, &self.address, .big),
        };
    }

    pub fn order(a: IgnoreEntry, b: IgnoreEntry) std.math.Order {
        const family = std.math.order(@intFromEnum(a.family), @intFromEnum(b.family));
        if (family != .eq) return family;
        const address = std.mem.order(u8, &a.address, &b.address);
        if (address != .eq) return address;
        return std.math.order(a.prefix, b.prefix);
    }

    fn prefixMask(comptime T: type, prefix: u8) T {
        if (prefix == 0) return 0;
        return ~@as(T, 0) << @intCast(@bitSizeOf(T) - prefix);
    }
};

pub const Origin = enum(u8) {
    detection = 1,
    manual = 2,
    config = 3,
};

pub const TimedEntry = struct {
    entry: IgnoreEntry,
    duration_s: ?u64,

    pub const max_duration_s: u64 = 100 * 366 * 86_400;

    pub fn parse(text: []const u8, default_duration_s: ?u64) error{ InvalidAddress, InvalidPrefix, InvalidDuration }!TimedEntry {
        const address = addressText(text);
        const entry = try IgnoreEntry.parse(address);
        const rest = std.mem.trim(u8, text[address.len..], &std.ascii.whitespace);
        if (rest.len == 0) return .{ .entry = entry, .duration_s = default_duration_s };
        if (std.mem.indexOfAny(u8, rest, &std.ascii.whitespace) != null) return error.InvalidDuration;
        const parsed = duration.parse(rest, false) catch return error.InvalidDuration;
        const seconds = parsed.nativeSeconds() catch return error.InvalidDuration;
        if (seconds < 1 or seconds > max_duration_s) return error.InvalidDuration;
        return .{ .entry = entry, .duration_s = seconds };
    }

    pub fn addressText(text: []const u8) []const u8 {
        return text[0 .. std.mem.indexOfAny(u8, text, &std.ascii.whitespace) orelse text.len];
    }
};

pub const JailId = struct {
    bytes: [max_len]u8 = [_]u8{0} ** max_len,
    len: u8 = 0,

    pub const max_len: usize = 64;
    pub const Error = error{ JailIdTooLong, JailIdEmpty };

    pub fn fromSlice(s: []const u8) Error!JailId {
        if (s.len == 0) return error.JailIdEmpty;
        if (s.len > max_len) return error.JailIdTooLong;
        var j: JailId = .{};
        @memcpy(j.bytes[0..s.len], s);
        j.len = @intCast(s.len);
        return j;
    }

    pub fn slice(self: *const JailId) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn eql(a: JailId, b: JailId) bool {
        if (a.len != b.len) return false;
        return std.mem.eql(u8, a.bytes[0..a.len], b.bytes[0..b.len]);
    }

    pub fn format(
        self: JailId,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.writeAll(self.bytes[0..self.len]);
    }
};
