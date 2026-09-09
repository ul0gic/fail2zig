// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const shared = @import("shared");

const parser = @import("parser");

const testing = std.testing;

const seeds = [_][]const u8{
    "",
    "\n",
    " ",
    "\x00",

    "Failed password for root from 1.2.3.4",
    "Failed password for root from ::1",

    "Failed password for root from 999.999.999.999",
    "Failed password for root from 1.2.3",
    "Failed password for root from 1.2.3.4.5",
    "Failed password for root from ...",
    "Failed password for root from :::::::::::",
    "Failed password for root from 1.2.3.-4",
    "Failed password for root from 256.256.256.256",

    "Failed password for root from 99999999.99999999.99999999.99999999",

    "2026-04-20T14:30:22Z sshd from 1.2.3.4",
    "9999-99-99T99:99:99Z sshd from 1.2.3.4",
    "0000-00-00T00:00:00Z sshd from 1.2.3.4",
    "2026-13-40T25:61:61+99:99 sshd from 1.2.3.4",
    "Apr 99 99:99:99 host sshd 1.2.3.4",
    "9999999999999999999999 sshd from 1.2.3.4",

    "Failed password for root from a:b:c:d:e:f:0123456789abcdef:0123456789abcdef:z",
    "Failed password for root from :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::",

    "Failed password for root from " ++ ("A" ** 8000) ++ " 1.2.3.4",

    "\xff\xff\xff\xff\xff\xff\xff\xff",
    "\xc3\xa9\xc3\xa9\xc3\xa9 1.2.3.4",

    "Failed password for root from",

    "Failed password for 1.2.3.4 and 5.6.7.8 from 9.9.9.9",

    "Failed password for root from 2001:DB8:AAAA:BBBB::1",

    "Failed password for root from ::ffff:1.2.3.4",

    "Failed password\x01for root\x02from\t1.2.3.4",

    "Failed\x00password for root from 1.2.3.4",
};

const sshd_pattern = "Failed password for <*> from <IP>";
const ts_pattern = "<TIMESTAMP> <*> from <IP>";

fn runOne(match_fn: parser.MatchFn, input: []const u8) !void {
    _ = match_fn(input);
}

test "fuzz_parser: sshd pattern over full seed corpus" {
    const m = comptime parser.compile(sshd_pattern);
    for (seeds) |s| {
        try runOne(m, s);
    }
}

test "fuzz_parser: timestamped pattern over full seed corpus" {
    const m = comptime parser.compile(ts_pattern);
    for (seeds) |s| {
        try runOne(m, s);
    }
}

test "fuzz_parser: extractors on raw adversarial bytes" {
    for (seeds) |s| {
        _ = parser.extractIpv4(s);
        _ = parser.extractIpv6(s);
        _ = parser.extractTimestamp(s);
    }
}

test "fuzz_parser: multi-pattern matcher rejects garbage cleanly" {
    const m = comptime parser.matcher.Matcher.init(&.{
        .{
            .pattern = sshd_pattern,
            .jail = shared.JailId.fromSlice("sshd") catch unreachable,
            .id = 1,
        },
        .{
            .pattern = ts_pattern,
            .jail = shared.JailId.fromSlice("sshd") catch unreachable,
            .id = 2,
        },
    });
    for (seeds) |s| {
        _ = m.match(s);
    }
}

test "fuzz_parser: random byte streams do not crash the parser" {
    var prng = std.Random.DefaultPrng.init(0xDEADBEEF_CAFEBABE);
    const rand = prng.random();
    const m = comptime parser.compile(sshd_pattern);

    var i: usize = 0;
    while (i < 10_000) : (i += 1) {
        var buf: [256]u8 = undefined;
        const len = rand.intRangeAtMost(usize, 0, buf.len);
        rand.bytes(buf[0..len]);
        _ = m(buf[0..len]);
    }
}
