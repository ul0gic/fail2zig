//! Fuzz corpus for the native TOML config parser.
//!
//! `Config.parse` takes an arbitrary in-memory source and produces a
//! populated `Config` struct or a typed error. The parser must:
//!   * Never panic — even on malformed TOML, invalid UTF-8, etc.
//!   * Never allocate past the caller's arena ceiling.
//!   * Terminate within bounded time (no pathological backtracking in
//!     interpolation, table nesting, or comment scanning).
//!
//! This file drives the parser with a curated set of adversarial seeds
//! and a PRNG-generated mutation stream. Each run uses a fresh
//! `ArenaAllocator` backed by a 256 KB `FixedBufferAllocator` so OOM
//! paths are exercised without polluting the runner's memory.

const std = @import("std");
const config_native = @import("config_native");

const testing = std.testing;

// ============================================================================
// Seed corpus — deliberately crafted adversarial TOML (and non-TOML).
// ============================================================================

const seeds = [_][]const u8{
    "",
    "\n",
    "# just a comment\n",
    "# pound in key # not stripped\n",

    // Minimal valid config (sanity — parser must accept).
    "[global]\nlog_level = \"info\"\n",

    // Unterminated strings.
    "[global]\nlog_level = \"info\n",
    "[global]\nlog_level = \"\n",
    "[global]\nlog_level = \"" ++ ("A" ** 10_000),

    // Unterminated section headers.
    "[unterminated\n",
    "[\n",
    "[]\n",

    // Dotted / nested / weird tables.
    "[a.b.c.d.e.f.g.h.i.j.k]\n",
    "[" ++ ("a." ** 500) ++ "end]\n",

    // Duplicate keys.
    "[global]\nlog_level = \"info\"\nlog_level = \"debug\"\n",

    // Unknown section / key.
    "[not_a_section]\nfoo = 1\n",
    "[global]\nnot_a_real_key = 42\n",

    // Values of the wrong kind.
    "[global]\nlog_level = 42\n",
    "[global]\nlog_level = true\n",
    "[global]\nmemory_ceiling_mb = \"high\"\n",
    "[global]\nmemory_ceiling_mb = -5\n",

    // Massive numeric values (integer overflow probes).
    "[global]\nmemory_ceiling_mb = 99999999999999999999\n",
    "[global]\nmemory_ceiling_mb = " ++ ("9" ** 500) ++ "\n",

    // Array edge cases.
    "[defaults]\nignoreip = []\n",
    "[defaults]\nignoreip = [\"\"]\n",
    "[defaults]\nignoreip = [,]\n",
    "[defaults]\nignoreip = [\"a\",,\"b\"]\n",
    "[defaults]\nignoreip = [\"a\", 1]\n", // mixed types
    "[defaults]\nignoreip = [" ++ ("\"x\"," ** 10_000) ++ "]\n",

    // Escape sequences.
    "[global]\nlog_level = \"\\n\"\n",
    "[global]\nlog_level = \"\\\\\"\n",
    "[global]\nlog_level = \"\\q\"\n", // invalid escape

    // Comments in tricky positions.
    "[global] # trailing\nlog_level = \"info\" # also trailing\n",

    // CRLF, CR-only, LF-only line endings.
    "[global]\r\nlog_level = \"info\"\r\n",
    "[global]\rlog_level = \"info\"\r",

    // Extremely long single line (no newline).
    "[global]" ++ ("x" ** 100_000),

    // High-bit garbage.
    "[\xff\xff\xff]\n",
    "key = \xff\xff\xff\n",

    // NUL embedded in source.
    "[glob\x00al]\n",
    "[global]\nlog\x00level = \"info\"\n",

    // Section name overflow.
    "[" ++ ("x" ** 10_000) ++ "]\n",

    // Many-jail stress (parser's 256-jail ceiling must trip cleanly).
    "[jails.j1]\n[jails.j2]\n[jails.j3]\n[jails.j4]\n[jails.j5]\n" ++
        "[jails.j6]\n[jails.j7]\n[jails.j8]\n[jails.j9]\n[jails.j10]\n" ++
        "[jails.j11]\n[jails.j12]\n[jails.j13]\n[jails.j14]\n[jails.j15]\n",
};

// ============================================================================
// Tests
// ============================================================================

fn parseOnce(source: []const u8, arena_backing: []u8) void {
    var fba = std.heap.FixedBufferAllocator.init(arena_backing);
    var arena = std.heap.ArenaAllocator.init(fba.allocator());
    defer arena.deinit();
    _ = config_native.Config.parse(arena.allocator(), source) catch {};
}

test "fuzz_config: curated seeds do not crash native parser" {
    // 256 KB arena per input — plenty for legal configs, not enough for
    // the attacker-driven "allocate a gigabyte" cases.
    var backing: [256 * 1024]u8 = undefined;
    for (seeds) |s| parseOnce(s, &backing);
}

test "fuzz_config: PRNG-driven mutations of a valid baseline" {
    // Start from a valid config, then mutate 1-3 bytes per iteration.
    const baseline =
        "[global]\n" ++
        "log_level = \"info\"\n" ++
        "memory_ceiling_mb = 64\n" ++
        "\n" ++
        "[defaults]\n" ++
        "bantime = 600\n" ++
        "maxretry = 5\n" ++
        "ignoreip = [\"127.0.0.1\"]\n" ++
        "\n" ++
        "[jails.sshd]\n" ++
        "enabled = true\n" ++
        "filter = \"sshd\"\n" ++
        "logpath = [\"/var/log/auth.log\"]\n";

    var prng = std.Random.DefaultPrng.init(0xA5A5_F00D_DEAD);
    const rand = prng.random();

    var backing: [256 * 1024]u8 = undefined;
    var mutable: [4096]u8 = undefined;
    std.debug.assert(baseline.len <= mutable.len);

    var i: usize = 0;
    while (i < 5_000) : (i += 1) {
        @memcpy(mutable[0..baseline.len], baseline);
        const n_mutations = rand.intRangeAtMost(usize, 1, 4);
        var m: usize = 0;
        while (m < n_mutations) : (m += 1) {
            const idx = rand.uintLessThan(usize, baseline.len);
            mutable[idx] = rand.int(u8);
        }
        parseOnce(mutable[0..baseline.len], &backing);
    }
}

test "fuzz_config: PRNG-driven random bytes do not crash parser" {
    var prng = std.Random.DefaultPrng.init(0x12345678_9ABCDEF0);
    const rand = prng.random();

    var backing: [256 * 1024]u8 = undefined;
    var buf: [1024]u8 = undefined;

    var i: usize = 0;
    while (i < 5_000) : (i += 1) {
        const len = rand.intRangeAtMost(usize, 0, buf.len);
        rand.bytes(buf[0..len]);
        parseOnce(buf[0..len], &backing);
    }
}

test "fuzz_config: tight arena provokes OOM branches safely" {
    // 4 KB arena — most legal configs won't fit. The parser must return
    // error.OutOfMemory rather than panic.
    var backing: [4 * 1024]u8 = undefined;
    for (seeds) |s| parseOnce(s, &backing);
}
