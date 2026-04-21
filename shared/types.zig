const std = @import("std");

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

    /// Canonicalize a u128 IPv6 address into its semantically-equivalent
    /// form. IPv4-mapped IPv6 (`::ffff:a.b.c.d`, RFC 4291 §2.5.5.2) is
    /// folded to a plain `.ipv4` variant so the state tracker can't be
    /// tricked into treating `1.2.3.4` and `::ffff:1.2.3.4` as distinct
    /// offenders. The deprecated IPv4-compatible range (`::a.b.c.d`, RFC
    /// 4291 §2.5.5.1, formally deprecated in RFC 4291 and unrouted) is
    /// rejected: no legitimate peer emits it and accepting it would be
    /// a second evasion surface. `::` (all-zeros, unspecified) is left
    /// intact — it's a distinct address with no IPv4 equivalent.
    pub fn fromIpv6Bits(v: u128) Error!IpAddress {
        // IPv4-mapped: bits 80..95 == 0xffff, bits 0..79 == 0.
        const mapped_prefix: u128 = 0x0000_0000_0000_0000_0000_ffff_0000_0000;
        const mapped_mask: u128 = 0xffff_ffff_ffff_ffff_ffff_ffff_0000_0000;
        if ((v & mapped_mask) == mapped_prefix) {
            return .{ .ipv4 = @truncate(v) };
        }
        // IPv4-compatible (deprecated): top 96 bits zero, low 32 bits non-zero,
        // and NOT the special ::0, ::1 addresses. Reject to close the evasion
        // window without breaking loopback / unspecified.
        const compat_mask: u128 = 0xffff_ffff_ffff_ffff_ffff_ffff_0000_0000;
        if ((v & compat_mask) == 0) {
            const low32: u32 = @truncate(v);
            // Preserve :: (0) and ::1 as legitimate IPv6 addresses.
            if (low32 != 0 and low32 != 1) {
                return error.Invalid;
            }
        }
        return .{ .ipv6 = v };
    }

    pub fn eql(a: IpAddress, b: IpAddress) bool {
        return std.meta.eql(a, b);
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
        // Delegate to std.net for correctness; it handles full form,
        // compressed (::), and IPv4-mapped (::ffff:a.b.c.d) variants.
        const addr = std.net.Ip6Address.parse(s, 0) catch return null;
        return std.mem.readInt(u128, &addr.sa.addr, .big);
    }

    fn formatIpv6(v: u128, writer: anytype) !void {
        // Canonical RFC 5952: lowercase hex, `::` compresses the longest run
        // of two or more zero groups. Emit as prefix `::` suffix, where the
        // `::` itself supplies the colons on either side — the next group
        // must NOT add a leading colon.
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

// ============================================================================
// Tests
// ============================================================================

test "IpAddress: parse ipv4 typical" {
    const ip = try IpAddress.parse("192.168.1.1");
    try std.testing.expectEqual(@as(u32, 0xC0A80101), ip.ipv4);
}

test "IpAddress: parse ipv4 all-zeros" {
    const ip = try IpAddress.parse("0.0.0.0");
    try std.testing.expectEqual(@as(u32, 0), ip.ipv4);
}

test "IpAddress: parse ipv4 all-ones" {
    const ip = try IpAddress.parse("255.255.255.255");
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), ip.ipv4);
}

test "IpAddress: reject invalid ipv4" {
    try std.testing.expectError(error.Invalid, IpAddress.parse("256.0.0.1"));
    try std.testing.expectError(error.Invalid, IpAddress.parse("192.168.1"));
    try std.testing.expectError(error.Invalid, IpAddress.parse("192.168.1.1.1"));
    try std.testing.expectError(error.Invalid, IpAddress.parse("192.168..1"));
    try std.testing.expectError(error.Invalid, IpAddress.parse(".192.168.1.1"));
    try std.testing.expectError(error.Invalid, IpAddress.parse("192.168.1.1."));
    try std.testing.expectError(error.Invalid, IpAddress.parse("192.168.1.a"));
    try std.testing.expectError(error.Invalid, IpAddress.parse(""));
    try std.testing.expectError(error.Invalid, IpAddress.parse("1.2.3.4 "));
}

test "IpAddress: parse ipv6 full" {
    const ip = try IpAddress.parse("2001:0db8:85a3:0000:0000:8a2e:0370:7334");
    const expected: u128 = 0x20010db885a3000000008a2e03707334;
    try std.testing.expectEqual(expected, ip.ipv6);
}

test "IpAddress: parse ipv6 compressed loopback" {
    const ip = try IpAddress.parse("::1");
    try std.testing.expectEqual(@as(u128, 1), ip.ipv6);
}

test "IpAddress: parse ipv6 compressed all-zeros" {
    const ip = try IpAddress.parse("::");
    try std.testing.expectEqual(@as(u128, 0), ip.ipv6);
}

test "IpAddress: parse ipv6 ipv4-mapped folds to ipv4" {
    // SEC-001: `::ffff:a.b.c.d` MUST canonicalize to the IPv4 variant so
    // the state tracker treats it as the same offender as a plain `a.b.c.d`.
    const mapped = try IpAddress.parse("::ffff:192.168.1.1");
    const plain = try IpAddress.parse("192.168.1.1");
    try std.testing.expect(IpAddress.eql(mapped, plain));
    try std.testing.expectEqual(@as(u32, 0xC0A80101), mapped.ipv4);
}

test "IpAddress: deprecated ipv4-compatible ::a.b.c.d is rejected" {
    // SEC-001: the deprecated `::a.b.c.d` range (RFC 4291 §2.5.5.1) is
    // another potential evasion vector — reject so it can never reach
    // the state tracker.
    try std.testing.expectError(error.Invalid, IpAddress.parse("::1.2.3.4"));
    try std.testing.expectError(error.Invalid, IpAddress.parse("::192.168.1.1"));
    // But :: and ::1 must still parse (they have no IPv4 equivalent).
    _ = try IpAddress.parse("::");
    _ = try IpAddress.parse("::1");
}

test "IpAddress: fromIpv6Bits folds mapped low bits" {
    // Direct test of the canonicalizer.
    const raw: u128 = 0x00000000000000000000ffff01020304;
    const ip = try IpAddress.fromIpv6Bits(raw);
    try std.testing.expectEqual(@as(u32, 0x01020304), ip.ipv4);
}

test "IpAddress: fromIpv6Bits preserves unspecified and loopback" {
    const unspec = try IpAddress.fromIpv6Bits(0);
    try std.testing.expectEqual(@as(u128, 0), unspec.ipv6);
    const loop = try IpAddress.fromIpv6Bits(1);
    try std.testing.expectEqual(@as(u128, 1), loop.ipv6);
}

test "IpAddress: format ipv4 roundtrip" {
    var buf: [32]u8 = undefined;
    const ip: IpAddress = .{ .ipv4 = 0xC0A80101 };
    const out = try std.fmt.bufPrint(&buf, "{}", .{ip});
    try std.testing.expectEqualStrings("192.168.1.1", out);
}

test "IpAddress: format ipv6 loopback" {
    var buf: [64]u8 = undefined;
    const ip: IpAddress = .{ .ipv6 = 1 };
    const out = try std.fmt.bufPrint(&buf, "{}", .{ip});
    try std.testing.expectEqualStrings("::1", out);
}

test "IpAddress: format ipv6 all-zeros" {
    var buf: [64]u8 = undefined;
    const ip: IpAddress = .{ .ipv6 = 0 };
    const out = try std.fmt.bufPrint(&buf, "{}", .{ip});
    try std.testing.expectEqualStrings("::", out);
}

test "IpAddress: format ipv6 typical compression" {
    var buf: [64]u8 = undefined;
    const ip: IpAddress = .{ .ipv6 = 0x20010db8000000000000000000000001 };
    const out = try std.fmt.bufPrint(&buf, "{}", .{ip});
    try std.testing.expectEqualStrings("2001:db8::1", out);
}

test "IpAddress: format ipv6 compression in middle" {
    var buf: [64]u8 = undefined;
    const ip: IpAddress = .{ .ipv6 = 0x00010000000000000000000000000002 };
    const out = try std.fmt.bufPrint(&buf, "{}", .{ip});
    try std.testing.expectEqualStrings("1::2", out);
}

test "IpAddress: format ipv6 compression at end" {
    var buf: [64]u8 = undefined;
    const ip: IpAddress = .{ .ipv6 = 0x00010000000000000000000000000000 };
    const out = try std.fmt.bufPrint(&buf, "{}", .{ip});
    try std.testing.expectEqualStrings("1::", out);
}

test "IpAddress: format ipv6 no compression eligible" {
    var buf: [64]u8 = undefined;
    // All groups non-zero, so no `::` expected.
    const ip: IpAddress = .{ .ipv6 = 0x00010002000300040005000600070008 };
    const out = try std.fmt.bufPrint(&buf, "{}", .{ip});
    try std.testing.expectEqualStrings("1:2:3:4:5:6:7:8", out);
}

test "IpAddress: eql" {
    const a: IpAddress = .{ .ipv4 = 1 };
    const b: IpAddress = .{ .ipv4 = 1 };
    const c: IpAddress = .{ .ipv4 = 2 };
    const d: IpAddress = .{ .ipv6 = 1 };
    try std.testing.expect(IpAddress.eql(a, b));
    try std.testing.expect(!IpAddress.eql(a, c));
    try std.testing.expect(!IpAddress.eql(a, d));
}

test "JailId: fromSlice typical" {
    const j = try JailId.fromSlice("sshd");
    try std.testing.expectEqualStrings("sshd", j.slice());
    try std.testing.expectEqual(@as(u8, 4), j.len);
}

test "JailId: fromSlice rejects empty" {
    try std.testing.expectError(error.JailIdEmpty, JailId.fromSlice(""));
}

test "JailId: fromSlice rejects too long" {
    const long = [_]u8{'a'} ** 65;
    try std.testing.expectError(error.JailIdTooLong, JailId.fromSlice(&long));
}

test "JailId: fromSlice accepts max length" {
    const at_limit = [_]u8{'a'} ** 64;
    const j = try JailId.fromSlice(&at_limit);
    try std.testing.expectEqual(@as(u8, 64), j.len);
    try std.testing.expectEqualStrings(&at_limit, j.slice());
}

test "JailId: eql" {
    const a = try JailId.fromSlice("sshd");
    const b = try JailId.fromSlice("sshd");
    const c = try JailId.fromSlice("nginx");
    try std.testing.expect(JailId.eql(a, b));
    try std.testing.expect(!JailId.eql(a, c));
}

test "BanState: discriminants stable" {
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(BanState.monitoring));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(BanState.banned));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(BanState.expired));
}
