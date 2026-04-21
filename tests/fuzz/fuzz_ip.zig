// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Fuzz corpus for the IP address parser.
//!
//! `shared.IpAddress.parse` is the only entry point that turns an
//! attacker-supplied dotted-quad or colon-hex string into a banable
//! key. It must never crash and must be deterministic — two calls with
//! the same bytes return the same result.
//!
//! Seed corpus below exercises:
//!   * Valid v4 boundaries (0.0.0.0, 255.255.255.255).
//!   * Valid v6 shapes: full, `::`, IPv4-mapped, scoped link-local.
//!   * Malformed v4: over-255 octets, too few / too many octets,
//!     leading / trailing dots, embedded non-digit chars.
//!   * Malformed v6: excess colons, double `::`, non-hex chars.
//!   * Integer-overflow probes (long digit runs).
//!   * Pure garbage / UTF-8 / control characters.
//!   * Length extremes (0 bytes, 1 byte, 1000 bytes).

const std = @import("std");
const shared = @import("shared");

const IpAddress = shared.IpAddress;
const testing = std.testing;

// ============================================================================
// Curated adversarial seeds.
// ============================================================================

const seeds = [_][]const u8{
    // Boundary valid v4.
    "0.0.0.0",
    "255.255.255.255",
    "127.0.0.1",

    // Malformed v4.
    "",
    " ",
    ".",
    "...",
    "1",
    "1.2",
    "1.2.3",
    "1.2.3.",
    ".1.2.3.4",
    "1..2.3.4",
    "1.2.3.4.",
    "1.2.3.4.5",
    "256.0.0.0",
    "1000.0.0.0",
    "999.999.999.999",
    "1.2.3.a",
    "a.b.c.d",
    "01.02.03.04", // leading zeros — our parser accepts these as 1.2.3.4
    "1.2.3.4 ",
    " 1.2.3.4",
    "1.2.3.4\n",

    // Integer overflow probes.
    "99999999999999999999.1.1.1",
    ("9" ** 100) ++ ".1.1.1",

    // Valid v6.
    "::",
    "::1",
    "2001:db8::1",
    "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
    "::ffff:1.2.3.4",

    // Malformed v6.
    ":",
    ":::",
    "::::",
    "gggg::",
    "1:2:3:4:5:6:7:8:9",
    "1::2::3",
    "2001:db8::g",
    "[::1]",
    "::1/128",
    "::1%eth0",
    "fe80::1%",

    // Very long garbage that looks v6-ish.
    ("a:" ** 64) ++ "1",
    ("1234:" ** 32),
    ("::" ** 32),

    // Control characters & high-bit bytes.
    "\x00",
    "\x00\x00\x00\x00",
    "\xff\xff\xff\xff",
    "1.2.\x00.4",
    "1.\x01.3.4",

    // Unicode homographs — U+FF0E "FULLWIDTH FULL STOP" (looks like '.').
    "1\xef\xbc\x8e2.3.4",

    // Absurd lengths.
    "1." ** 500,
    "0" ** 1000,
};

// ============================================================================
// Tests
// ============================================================================

test "fuzz_ip: seed corpus does not crash IpAddress.parse" {
    for (seeds) |s| {
        _ = IpAddress.parse(s) catch {};
    }
}

test "fuzz_ip: parse is deterministic across repeat invocations" {
    for (seeds) |s| {
        const a = IpAddress.parse(s) catch null;
        const b = IpAddress.parse(s) catch null;
        // If one errored the other must too; if both succeeded they must
        // match bitwise (we rely on the union eql implementation).
        if (a == null) {
            try testing.expect(b == null);
        } else {
            try testing.expect(IpAddress.eql(a.?, b.?));
        }
    }
}

test "fuzz_ip: PRNG-driven random ASCII does not crash" {
    var prng = std.Random.DefaultPrng.init(0xB10C_DEADBEEF);
    const rand = prng.random();

    var i: usize = 0;
    while (i < 20_000) : (i += 1) {
        var buf: [64]u8 = undefined;
        const len = rand.intRangeAtMost(usize, 0, buf.len);
        // Mostly digit / dot / colon / hex — keep the alphabet narrow so
        // we hit interesting branches more often than pure-random ASCII.
        for (buf[0..len]) |*b| {
            b.* = switch (rand.intRangeAtMost(u8, 0, 10)) {
                0...4 => rand.intRangeAtMost(u8, '0', '9'),
                5 => '.',
                6 => ':',
                7 => rand.intRangeAtMost(u8, 'a', 'f'),
                8 => rand.intRangeAtMost(u8, 'A', 'F'),
                9 => rand.int(u8), // full random byte
                else => ' ',
            };
        }
        _ = IpAddress.parse(buf[0..len]) catch {};
    }
}

test "fuzz_ip: PRNG-driven arbitrary bytes do not crash" {
    var prng = std.Random.DefaultPrng.init(0xFACE_B00C_CAFE);
    const rand = prng.random();
    var i: usize = 0;
    while (i < 10_000) : (i += 1) {
        var buf: [64]u8 = undefined;
        const len = rand.intRangeAtMost(usize, 0, buf.len);
        rand.bytes(buf[0..len]);
        _ = IpAddress.parse(buf[0..len]) catch {};
    }
}

test "fuzz_ip: IPv4-mapped IPv6 folds to v4 (SEC-001 fixed)" {
    const ip = try IpAddress.parse("::ffff:1.2.3.4");
    try testing.expect(ip == .ipv4);
    const v4 = try IpAddress.parse("1.2.3.4");
    try testing.expect(v4 == .ipv4);
    try testing.expect(IpAddress.eql(ip, v4));
}
