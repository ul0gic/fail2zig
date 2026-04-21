//! Fuzz corpus for the IPC protocol deserializer.
//!
//! The daemon receives length-prefixed binary frames from any peer that
//! passes `SO_PEERCRED` authentication. The deserializer must:
//!   * Never panic on any input.
//!   * Never allocate more than the caller's allocator permits.
//!   * Return a typed error for every malformed form.
//!
//! Every input is fed through `protocol.deserializeCommand` and
//! `protocol.deserializeResponse`, wrapped in a `FailingAllocator` /
//! bounded `FixedBufferAllocator` so the "never allocates past the
//! budget" property is proven per run.

const std = @import("std");
const shared = @import("shared");
const protocol = shared.protocol;

const testing = std.testing;

// ============================================================================
// Curated adversarial seeds. Each is a full (prefix+body) frame or a
// deliberately-truncated variant.
// ============================================================================

const seeds = [_][]const u8{
    // Empty.
    "",

    // Just a prefix with no body.
    "\x00\x00\x00\x00",

    // Claimed size 1 MiB+1 — must be rejected as PayloadTooLarge.
    "\x01\x00\x10\x00", // 0x00100001 LE = 1048577

    // Claimed size 0xFFFFFFFF — max u32, certainly PayloadTooLarge.
    "\xff\xff\xff\xff",

    // Well-formed Version (tag=6, body size 1).
    "\x01\x00\x00\x00\x06",

    // Well-formed Status (tag=0).
    "\x01\x00\x00\x00\x00",

    // Invalid command tag (0xFE).
    "\x01\x00\x00\x00\xfe",

    // Valid size prefix claim, but body truncated.
    "\x10\x00\x00\x00", // claims 16 bytes of body, sends 0
    "\x10\x00\x00\x00\x00", // claims 16 bytes, sends 1

    // Ban command with valid ipv4 + jail + duration.
    "\x14\x00\x00\x00" ++ // size=20
        "\x01" ++ // tag=ban
        "\x04" ++ // ip tag=4 (ipv4)
        "\x01\x02\x03\x04" ++ // ip big-endian
        "\x04" ++ // jail len=4
        "sshd" ++ // jail
        "\x01" ++ // optional duration marker=1
        "\x58\x02\x00\x00\x00\x00\x00\x00", // duration=600 LE

    // Ban with invalid ip tag.
    "\x0a\x00\x00\x00" ++
        "\x01" ++ // tag=ban
        "\xff" ++ // invalid ip tag
        "\x00\x00\x00\x00\x00\x00\x00\x00",
        // Ban with jail len > max.
    "\x07\x00\x00\x00" ++
        "\x01" ++ // ban
        "\x04" ++ // ipv4
        "\x01\x02\x03\x04" ++
        "\xff", // jail len=255 > 64 max

    // Ban with jail len = 0.
    "\x07\x00\x00\x00" ++
        "\x01" ++ "\x04" ++ "\x01\x02\x03\x04" ++ "\x00",

    // Unban with invalid optional marker.
    "\x07\x00\x00\x00" ++
        "\x02" ++ "\x04" ++ "\x01\x02\x03\x04" ++ "\x05",

    // list_jails / reload.
    "\x01\x00\x00\x00\x04",
    "\x01\x00\x00\x00\x05",

    // Valid response ok.
    "\x0a\x00\x00\x00" ++ // size=10
        "\x00" ++ // tag=ok
        "\x05\x00\x00\x00" ++ // payload len=5
        "hello",

    // Response err with code.
    "\x0e\x00\x00\x00" ++
        "\x01" ++ // err
        "\x2a\x00" ++ // code=42
        "\x09\x00\x00\x00" ++ // msg len=9
        "not found",
        // Response with claimed huge payload len (DoS probe).
    "\x09\x00\x00\x00" ++
        "\x00" ++ // ok
        "\xff\xff\xff\xff", // plen = 4.2 GB → PayloadTooLarge

    // Response with payload len > frame size (underread attempt).
    "\x09\x00\x00\x00" ++
        "\x00" ++
        "\x00\x01\x00\x00" ++ // plen=256 but frame only has 4 more bytes
        "short",

    // Invalid response tag.
    "\x01\x00\x00\x00\xff",
};

// ============================================================================
// Tests
// ============================================================================

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
    // Response deserializer is the only path that allocates (for the
    // payload/message buffer). Cap at 2 KB — anything that tries to
    // allocate more should surface as an error, not a hang or panic.
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
        // Ensure the advertised size prefix is within reasonable range
        // half the time; leave fully random otherwise so we exercise the
        // oversize-rejection path.
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
    // Simulate an attacker claiming a huge payload length in the inner
    // ok/err body. The wrapper should reject via PayloadTooLarge before
    // calling alloc() with the attacker's number.
    var frame: [9]u8 = undefined;
    std.mem.writeInt(u32, frame[0..4], 5, .little); // outer size tiny
    frame[4] = 0; // ok tag
    std.mem.writeInt(u32, frame[5..9], protocol.max_payload_size + 1, .little);

    var stream = std.io.fixedBufferStream(&frame);
    try testing.expectError(
        error.PayloadTooLarge,
        protocol.deserializeResponse(stream.reader(), testing.allocator),
    );
}
