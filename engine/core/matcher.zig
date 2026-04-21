//! Multi-pattern matcher.
//!
//! Holds up to 256 comptime-compiled `MatchFn`s, each carrying its
//! `JailId` / pattern id, and attempts them against incoming log lines.
//! First matching pattern wins. The entire pattern set is materialized
//! at comptime — there is no heap state and no per-line allocation.
//!
//! Early-exit optimizations:
//!   * `min_line_len`: lines shorter than the shortest pattern's fixed
//!     text are rejected immediately.
//!   * `first_byte_prefix`: when a pattern begins with an anchored
//!     literal, its first byte is cached. Matcher checks the line's
//!     first byte against the union of all first-byte possibilities
//!     before dispatching; a mismatch on every pattern rejects the line
//!     without calling any match function.
//!
//! Public API:
//!     const defs = [_]PatternDef{ .{ .pattern = "...", .jail = id, .id = 1 } };
//!     const m = Matcher.init(defs);
//!     if (m.match(line)) |res| { ... }

const std = @import("std");
const shared = @import("shared");
const parser = @import("parser.zig");

pub const MAX_PATTERNS: usize = 256;

/// Declarative pattern input. `pattern` is a comptime string interpreted by
/// `parser.compile`. `jail` tags which jail owns the pattern (returned
/// alongside the parse result). `id` is a stable identifier set by the
/// caller — typically the pattern's index in the original list.
pub const PatternDef = struct {
    pattern: []const u8,
    jail: shared.JailId,
    id: u16,
};

/// Result produced by `Matcher.match`. Extends `parser.ParseResult` with
/// the owning jail so callers can route decisions (ban, unban, metric tag).
pub const MatchResult = struct {
    ip: shared.IpAddress,
    timestamp: ?shared.Timestamp,
    jail: shared.JailId,
    pattern_id: u16,
};

/// Multi-pattern matcher. Construct via `init(comptime patterns)`.
pub const Matcher = struct {
    fns: []const parser.MatchFn,
    ids: []const u16,
    jails: []const shared.JailId,
    min_line_len: usize,
    // Bitmap of viable first bytes across all patterns. Index = byte value.
    // `true` means at least one pattern's anchored literal starts with this
    // byte (or at least one pattern has no anchored literal, in which case
    // every first byte is viable — the bitmap is saturated).
    first_byte_mask: [256]bool,

    /// Build a matcher from a comptime list of pattern definitions. All
    /// match functions are generated at comptime and stored as a static
    /// slice — no runtime allocation.
    pub fn init(comptime patterns: []const PatternDef) Matcher {
        comptime {
            if (patterns.len == 0) @compileError("Matcher.init: at least one pattern required");
            if (patterns.len > MAX_PATTERNS) {
                @compileError("Matcher.init: too many patterns (max 256)");
            }
        }

        const built = comptime buildCompiled(patterns);
        return .{
            .fns = built.fns_slice,
            .ids = built.ids_slice,
            .jails = built.jails_slice,
            .min_line_len = built.min_line_len,
            .first_byte_mask = built.first_byte_mask,
        };
    }

    /// Try each pattern in order. Returns the first match, or null if
    /// no pattern matches. Zero allocation.
    pub fn match(self: *const Matcher, line: []const u8) ?MatchResult {
        if (line.len < self.min_line_len) {
            @branchHint(.unlikely);
            return null;
        }
        if (line.len >= 1 and !self.first_byte_mask[line[0]]) {
            @branchHint(.unlikely);
            return null;
        }

        for (self.fns, self.ids, self.jails) |f, id, jail| {
            if (f(line)) |r| {
                return .{
                    .ip = r.ip,
                    .timestamp = r.timestamp,
                    .jail = jail,
                    .pattern_id = id,
                };
            }
        }
        return null;
    }

    pub fn len(self: *const Matcher) usize {
        return self.fns.len;
    }
};

// ============================================================================
// Comptime construction
// ============================================================================

const Built = struct {
    fns_slice: []const parser.MatchFn,
    ids_slice: []const u16,
    jails_slice: []const shared.JailId,
    min_line_len: usize,
    first_byte_mask: [256]bool,
};

fn buildCompiled(comptime patterns: []const PatternDef) Built {
    comptime {
        @setEvalBranchQuota(200_000);
        var fns_arr: [patterns.len]parser.MatchFn = undefined;
        var ids_arr: [patterns.len]u16 = undefined;
        var jails_arr: [patterns.len]shared.JailId = undefined;
        var min_line_len: usize = std.math.maxInt(usize);
        var first_byte_mask: [256]bool = [_]bool{false} ** 256;

        for (patterns, 0..) |p, i| {
            fns_arr[i] = parser.compile(p.pattern);
            ids_arr[i] = p.id;
            jails_arr[i] = p.jail;

            const fixed = fixedLen(p.pattern);
            if (fixed < min_line_len) min_line_len = fixed;

            // First-byte analysis: if the pattern starts with a literal
            // segment, its first byte constrains the line. Otherwise the
            // pattern accepts any first byte (saturate the mask).
            if (firstAnchoredByte(p.pattern)) |b| {
                first_byte_mask[b] = true;
            } else {
                // Saturate — no first-byte filter possible for this pattern.
                for (&first_byte_mask) |*slot| slot.* = true;
            }
        }
        if (min_line_len == std.math.maxInt(usize)) min_line_len = 0;

        // Freeze the arrays into immutable const slices.
        const fns_const = fns_arr;
        const ids_const = ids_arr;
        const jails_const = jails_arr;
        return .{
            .fns_slice = &fns_const,
            .ids_slice = &ids_const,
            .jails_slice = &jails_const,
            .min_line_len = min_line_len,
            .first_byte_mask = first_byte_mask,
        };
    }
}

/// Minimum possible length of a line that can match `pattern`. Dynamic
/// tokens contribute their shortest legal width: `<IP>` = 7 (`0.0.0.0`),
/// `<TIMESTAMP>` = 10 (shortest epoch), `<HOST>` = 1, `<*>` = 0.
fn fixedLen(comptime pattern: []const u8) usize {
    comptime {
        var total: usize = 0;
        var i: usize = 0;
        while (i < pattern.len) {
            if (pattern[i] == '<') {
                var j = i + 1;
                while (j < pattern.len and pattern[j] != '>') : (j += 1) {}
                const name = pattern[i + 1 .. j];
                if (std.mem.eql(u8, name, "IP")) {
                    total += 7;
                } else if (std.mem.eql(u8, name, "TIMESTAMP")) {
                    total += 10;
                } else if (std.mem.eql(u8, name, "HOST")) {
                    total += 1;
                } else if (std.mem.eql(u8, name, "*")) {
                    // no minimum contribution
                }
                i = j + 1;
            } else {
                total += 1;
                i += 1;
            }
        }
        return total;
    }
}

fn firstAnchoredByte(comptime pattern: []const u8) ?u8 {
    comptime {
        if (pattern.len == 0) return null;
        // If the pattern starts with '<', the first segment is dynamic —
        // no useful first-byte constraint.
        if (pattern[0] == '<') return null;
        return pattern[0];
    }
}

// ============================================================================
// Tests
// ============================================================================

fn comptimeJail(comptime name: []const u8) shared.JailId {
    comptime {
        return shared.JailId.fromSlice(name) catch unreachable;
    }
}

test "matcher: single pattern matches sshd line" {
    const m = comptime Matcher.init(&.{
        .{ .pattern = "Failed password for <*> from <IP>", .jail = comptimeJail("sshd"), .id = 1 },
    });
    const r = m.match("Failed password for root from 1.2.3.4").?;
    try std.testing.expectEqual(@as(u32, 0x01020304), r.ip.ipv4);
    try std.testing.expectEqual(@as(u16, 1), r.pattern_id);
    try std.testing.expectEqualStrings("sshd", r.jail.slice());
}

test "matcher: three patterns -- first-match wins" {
    const m = comptime Matcher.init(&.{
        .{ .pattern = "Failed password for <*> from <IP>", .jail = comptimeJail("sshd"), .id = 10 },
        .{ .pattern = "<IP> - - <*> HTTP/1.1\" 401", .jail = comptimeJail("nginx"), .id = 20 },
        .{ .pattern = "reject: RCPT from <*>[<IP>]", .jail = comptimeJail("postfix"), .id = 30 },
    });

    const r1 = m.match("Failed password for admin from 10.0.0.1").?;
    try std.testing.expectEqual(@as(u16, 10), r1.pattern_id);
    try std.testing.expectEqualStrings("sshd", r1.jail.slice());

    const r2 = m.match("192.168.1.1 - - [20/Apr/2026:14:30:22 +0000] \"GET /admin HTTP/1.1\" 401").?;
    try std.testing.expectEqual(@as(u16, 20), r2.pattern_id);
    try std.testing.expectEqualStrings("nginx", r2.jail.slice());

    const r3 = m.match("reject: RCPT from unknown[203.0.113.5]").?;
    try std.testing.expectEqual(@as(u16, 30), r3.pattern_id);
    try std.testing.expectEqualStrings("postfix", r3.jail.slice());
}

test "matcher: returns null on non-matching line" {
    const m = comptime Matcher.init(&.{
        .{ .pattern = "Failed password for <*> from <IP>", .jail = comptimeJail("sshd"), .id = 1 },
    });
    try std.testing.expect(m.match("Accepted publickey for root") == null);
    try std.testing.expect(m.match("") == null);
}

test "matcher: min_line_len early exit" {
    const m = comptime Matcher.init(&.{
        // Fixed bytes: "Failed password for  from " (26) + 7 for <IP> = 33.
        .{ .pattern = "Failed password for <*> from <IP>", .jail = comptimeJail("sshd"), .id = 1 },
    });
    try std.testing.expect(m.min_line_len >= 26);
    try std.testing.expect(m.match("short") == null);
}

test "matcher: first-byte filter rejects mismatched prefix" {
    const m = comptime Matcher.init(&.{
        .{ .pattern = "Failed password for <*> from <IP>", .jail = comptimeJail("sshd"), .id = 1 },
        .{ .pattern = "Invalid user <*> from <IP>", .jail = comptimeJail("sshd"), .id = 2 },
    });
    // 'F' and 'I' are viable, 'Z' is not.
    try std.testing.expect(m.first_byte_mask['F']);
    try std.testing.expect(m.first_byte_mask['I']);
    try std.testing.expect(!m.first_byte_mask['Z']);
    try std.testing.expect(m.match("Zebra crossing from 1.2.3.4") == null);
}

test "matcher: first-byte filter saturates when any pattern is unanchored" {
    const m = comptime Matcher.init(&.{
        .{ .pattern = "Fixed prefix <IP>", .jail = comptimeJail("any"), .id = 1 },
        .{ .pattern = "<*><IP>", .jail = comptimeJail("any"), .id = 2 },
    });
    // Saturated — every first byte must be accepted.
    for (0..256) |b| try std.testing.expect(m.first_byte_mask[@intCast(b)]);
    const r = m.match("arbitrary prefix 9.9.9.9").?;
    try std.testing.expectEqual(@as(u16, 2), r.pattern_id);
}

test "matcher: pattern with timestamp populates result" {
    const m = comptime Matcher.init(&.{
        .{ .pattern = "<TIMESTAMP> <*> from <IP>", .jail = comptimeJail("sshd"), .id = 1 },
    });
    const r = m.match("2026-04-20T14:30:22Z sshd from 10.0.0.1").?;
    try std.testing.expectEqual(@as(i64, 1_776_695_422), r.timestamp.?);
    try std.testing.expectEqual(@as(u32, 0x0A000001), r.ip.ipv4);
}

test "matcher: ipv6 match via wildcard prefix" {
    const m = comptime Matcher.init(&.{
        .{ .pattern = "Failed password for <*> from <IP>", .jail = comptimeJail("sshd"), .id = 1 },
    });
    const r = m.match("Failed password for root from 2001:db8::1").?;
    try std.testing.expectEqual(@as(u128, 0x20010db8000000000000000000000001), r.ip.ipv6);
}
