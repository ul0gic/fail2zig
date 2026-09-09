// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const shared = @import("shared");
const protocol = shared.protocol;

const testing = std.testing;

const seeds = [_][]const u8{
    "",

    "\x00\x00\x00\x00",

    "\x01\x00\x10\x00",

    "\xff\xff\xff\xff",

    "\x01\x00\x00\x00\x06",

    "\x01\x00\x00\x00\x00",

    "\x01\x00\x00\x00\xfe",

    "\x10\x00\x00\x00",
    "\x10\x00\x00\x00\x00",

    "\x14\x00\x00\x00" ++
        "\x01" ++
        "\x04" ++
        "\x01\x02\x03\x04" ++
        "\x04" ++
        "sshd" ++
        "\x01" ++
        "\x58\x02\x00\x00\x00\x00\x00\x00",

    "\x0a\x00\x00\x00" ++
        "\x01" ++
        "\xff" ++
        "\x00\x00\x00\x00\x00\x00\x00\x00",
    "\x07\x00\x00\x00" ++
        "\x01" ++
        "\x04" ++
        "\x01\x02\x03\x04" ++
        "\xff",

    "\x07\x00\x00\x00" ++
        "\x01" ++ "\x04" ++ "\x01\x02\x03\x04" ++ "\x00",

    "\x07\x00\x00\x00" ++
        "\x02" ++ "\x04" ++ "\x01\x02\x03\x04" ++ "\x05",

    "\x01\x00\x00\x00\x04",
    "\x01\x00\x00\x00\x05",

    "\x0a\x00\x00\x00" ++
        "\x00" ++
        "\x05\x00\x00\x00" ++
        "hello",

    "\x0e\x00\x00\x00" ++
        "\x01" ++
        "\x2a\x00" ++
        "\x09\x00\x00\x00" ++
        "not found",
    "\x09\x00\x00\x00" ++
        "\x00" ++
        "\xff\xff\xff\xff",

    "\x09\x00\x00\x00" ++
        "\x00" ++
        "\x00\x01\x00\x00" ++
        "short",

    "\x01\x00\x00\x00\xff",
};

fn deserializeCmdOnce(bytes: []const u8) void {
    var stream = std.io.fixedBufferStream(bytes);
    _ = protocol.deserializeCommand(stream.reader()) catch {};
}

fn deserializeRespOnce(bytes: []const u8, a: std.mem.Allocator) void {
    var stream = std.io.fixedBufferStream(bytes);
    if (protocol.deserializeResponse(stream.reader(), a)) |r| {
        r.deinit(a);
    } else |_| {}
}

test "fuzz_protocol: deserializeCommand on curated seeds does not crash" {
    for (seeds) |s| deserializeCmdOnce(s);
}

test "fuzz_protocol: deserializeResponse on curated seeds does not crash" {
    for (seeds) |s| deserializeRespOnce(s, testing.allocator);
}

test "fuzz_protocol: deserializer is bounded by a tight FixedBufferAllocator" {
    var fba_buf: [2 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&fba_buf);
    const a = fba.allocator();

    for (seeds) |s| {
        fba.reset();
        deserializeRespOnce(s, a);
    }
}

test "fuzz_protocol: PRNG-driven command frames" {
    var prng = std.Random.DefaultPrng.init(0xC0DE_1234_5678);
    const rand = prng.random();
    var i: usize = 0;
    while (i < 20_000) : (i += 1) {
        var buf: [256]u8 = undefined;
        const len = rand.intRangeAtMost(usize, 0, buf.len);
        rand.bytes(buf[0..len]);
        if (len >= 4 and rand.boolean()) {
            const claimed: u32 = rand.intRangeAtMost(u32, 0, 128);
            std.mem.writeInt(u32, buf[0..4], claimed, .little);
        }
        deserializeCmdOnce(buf[0..len]);
    }
}

test "fuzz_protocol: PRNG-driven response frames under bounded allocator" {
    var prng = std.Random.DefaultPrng.init(0xBEEF_F00D_D00D);
    const rand = prng.random();

    var fba_buf: [8 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&fba_buf);
    const a = fba.allocator();

    var i: usize = 0;
    while (i < 20_000) : (i += 1) {
        fba.reset();
        var buf: [256]u8 = undefined;
        const len = rand.intRangeAtMost(usize, 0, buf.len);
        rand.bytes(buf[0..len]);
        deserializeRespOnce(buf[0..len], a);
    }
}

test "fuzz_protocol: claimed-size injection never over-allocates" {
    var frame: [9]u8 = undefined;
    std.mem.writeInt(u32, frame[0..4], 5, .little);
    frame[4] = 0;
    std.mem.writeInt(u32, frame[5..9], protocol.max_payload_size + 1, .little);

    var stream = std.io.fixedBufferStream(&frame);
    try testing.expectError(
        error.PayloadTooLarge,
        protocol.deserializeResponse(stream.reader(), testing.allocator),
    );
}
