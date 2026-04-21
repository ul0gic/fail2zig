// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Parser engine: comptime pattern DSL + hot-path token extractors.
//!
//! The DSL compiles a pattern string at comptime into a specialized
//! `MatchFn = fn(line: []const u8) ?ParseResult`. The generated function
//! walks the input with a mix of literal memcmp / indexOf probes and
//! token extractors (`<IP>`, `<TIMESTAMP>`, `<HOST>`, `<*>`). There is
//! NO runtime regex engine — every pattern is code at comptime.
//!
//! Supported tokens:
//!   <IP>         IPv4 or IPv6 address (required, extracted into result)
//!   <TIMESTAMP>  BSD syslog / ISO 8601 / epoch-seconds timestamp (optional)
//!   <HOST>       Hostname chars [A-Za-z0-9.-_]+
//!   <*>          Non-greedy any-chars-until-next-literal
//!
//! The hot path (log line -> ParseResult) is allocation-free: everything
//! operates on slices of the caller-provided buffer. Parse errors on
//! attacker-controlled input return `null`, never panic.
//!
//! ALL input is attacker-controlled. No `@panic`, no `unreachable`,
//! `@branchHint(.unlikely)` on reject paths.

const std = @import("std");
const shared = @import("shared");

// matcher.zig sits on top of this module; importing it here ensures the
// multi-pattern matcher's tests are reached through parser.zig's test block
// (main.zig already imports parser). See `test { _ = matcher; }` below.
pub const matcher = @import("matcher.zig");

// ============================================================================
// Public types
// ============================================================================

/// Result produced by a generated match function. `ip` is always populated
/// (every pattern must include an `<IP>` token), `timestamp` is populated
/// when the pattern contains `<TIMESTAMP>`, and `matched_pattern_id` is
/// assigned by the caller (e.g. the multi-pattern `Matcher`).
pub const ParseResult = struct {
    ip: shared.IpAddress,
    timestamp: ?shared.Timestamp = null,
    matched_pattern_id: u16 = 0,
};

/// Signature of every comptime-generated match function.
pub const MatchFn = *const fn (line: []const u8) ?ParseResult;

/// Byte-counted IPv4 extraction result.
pub const Ipv4Match = struct { ip: u32, len: u8 };

/// Byte-counted IPv6 extraction result.
pub const Ipv6Match = struct { ip: u128, len: u16 };

/// Byte-counted generic IP extraction result.
pub const IpMatch = struct { ip: shared.IpAddress, len: u16 };

/// Byte-counted timestamp extraction result.
pub const TimestampMatch = struct { ts: shared.Timestamp, len: u16 };

// ============================================================================
// Extractors — hot-path, zero-allocation
// ============================================================================

/// IPv4 scan-and-validate in one pass.
/// Returns the parsed 32-bit big-endian u32 and the number of bytes consumed.
/// Zero allocation. Reject paths are hinted cold.
pub fn extractIpv4(text: []const u8) ?Ipv4Match {
    if (text.len < 7) {
        @branchHint(.unlikely);
        return null;
    }

    var result: u32 = 0;
    var octets: u8 = 0;
    var current: u32 = 0;
    var digits: u8 = 0;
    var consumed: u8 = 0;

    for (text, 0..) |c, i| {
        // Hard bound: 15 bytes max (e.g. 255.255.255.255). Past that we are
        // clearly past the address; let the terminator check below handle it.
        if (i >= 15) break;

        switch (c) {
            '0'...'9' => {
                current = current * 10 + @as(u32, c - '0');
                digits += 1;
                if (digits > 3 or current > 255) {
                    @branchHint(.unlikely);
                    return null;
                }
                consumed = @intCast(i + 1);
            },
            '.' => {
                // Dot after the 4th octet is a terminator, not part of the
                // address — stop here and let the final octet validate below.
                if (octets >= 3) break;
                if (digits == 0) {
                    @branchHint(.unlikely);
                    return null;
                }
                result = (result << 8) | current;
                octets += 1;
                current = 0;
                digits = 0;
                consumed = @intCast(i + 1);
            },
            else => break,
        }
    }

    if (digits == 0 or octets != 3) {
        @branchHint(.unlikely);
        return null;
    }
    result = (result << 8) | current;
    return .{ .ip = result, .len = consumed };
}

/// IPv6 scan-and-validate. Single-pass structural validator: counts the
/// number of hex groups, enforces at most one `::` compression run, and
/// allows a trailing dotted-quad (IPv4-mapped / IPv4-compat forms). No
/// allocation, O(n) in the length of the literal, and — unlike the
/// previous truncation loop — does NOT call the full `std.net` parser
/// once per byte on adversarial input (SEC-009).
///
/// The returned `ip` is the raw big-endian u128; callers that want
/// `::ffff:a.b.c.d` folded to the IPv4 variant go through
/// `shared.IpAddress.fromIpv6Bits` in `extractIp`.
pub fn extractIpv6(text: []const u8) ?Ipv6Match {
    // Allowed bytes inside an IPv6 literal: hex digits, ':', '.'.
    // A well-formed IPv6 is at most 45 bytes (`xxxx:...:xxxx:255.255.255.255`).
    // Cap the scan at 64 bytes to be safe against garbage.
    const cap: usize = @min(text.len, 64);
    var scan_len: usize = 0;
    while (scan_len < cap) : (scan_len += 1) {
        const c = text[scan_len];
        const ok = switch (c) {
            '0'...'9', 'a'...'f', 'A'...'F', ':', '.' => true,
            else => false,
        };
        if (!ok) break;
    }

    if (scan_len < 2) {
        @branchHint(.unlikely);
        return null;
    }

    // Structural validator. We walk left-to-right, consuming groups of up
    // to 4 hex digits separated by ':'. At most one '::' compression run
    // is allowed. If a '.' is encountered inside a group, the tail is
    // interpreted as a dotted-quad IPv4 literal occupying the final two
    // 16-bit groups. We track the longest structurally-valid prefix and
    // commit the parse at that boundary.
    //
    // `groups_seen` counts 16-bit groups collected so far (left side +
    // right side of a '::' compression). Must end at exactly 8 (or at
    // most 8 when compressed).
    var i: usize = 0;
    var groups_seen: u8 = 0;
    var saw_double: bool = false;
    var last_valid_end: usize = 0;
    var last_valid_groups: u8 = 0;
    var last_valid_double: bool = false;

    while (i < scan_len) {
        // Handle colon boundaries first.
        if (text[i] == ':') {
            if (i + 1 < scan_len and text[i + 1] == ':') {
                if (saw_double) {
                    @branchHint(.unlikely);
                    break; // Second '::' is invalid; stop at the last valid prefix.
                }
                saw_double = true;
                i += 2;
                // A trailing '::' at end-of-literal is valid (`1::`).
                if (i == scan_len or !isIpv6Byte(text[i])) {
                    // Valid terminator after compression.
                    if (groups_seen <= 8) {
                        last_valid_end = i;
                        last_valid_groups = groups_seen;
                        last_valid_double = saw_double;
                    }
                    break;
                }
                continue;
            }
            // Single ':' not at start (':: handled above') — must be
            // between groups; if we're at the very start, invalid.
            if (i == 0) {
                @branchHint(.unlikely);
                break;
            }
            // Otherwise consume and expect a group next.
            i += 1;
            // Dangling ':' at end means we stopped mid-literal; not valid
            // past the previous group boundary — break without committing.
            if (i == scan_len or !isIpv6Byte(text[i])) break;
            continue;
        }

        // Collect a hex group of 1..4 digits.
        const group_start = i;
        var hex_digits: u8 = 0;
        while (i < scan_len and isHex(text[i]) and hex_digits < 4) : (i += 1) {
            hex_digits += 1;
        }
        if (hex_digits == 0) {
            @branchHint(.unlikely);
            break;
        }
        // If a '.' follows, the group is actually the first octet of a
        // dotted-quad IPv4 suffix. Re-scan from group_start as IPv4.
        if (i < scan_len and text[i] == '.') {
            const v4 = extractIpv4(text[group_start..scan_len]) orelse break;
            // IPv4 occupies two 16-bit groups.
            if (groups_seen + 2 > 8) break;
            groups_seen += 2;
            const end = group_start + v4.len;
            // Valid total count: 8 without compression, or <=8 with.
            const ok_count = if (saw_double) groups_seen <= 8 else groups_seen == 8;
            if (ok_count) {
                last_valid_end = end;
                last_valid_groups = groups_seen;
                last_valid_double = saw_double;
            }
            i = end;
            break; // IPv4 suffix terminates the literal.
        }

        groups_seen += 1;
        if (groups_seen > 8) {
            @branchHint(.unlikely);
            break;
        }

        // After a group, valid terminators: end-of-literal, non-ipv6 byte,
        // or another ':'. If we're at a valid end boundary, record it.
        const at_end = (i == scan_len) or !isIpv6Byte(text[i]);
        const ok_count = if (saw_double) groups_seen <= 8 else groups_seen == 8;
        if (at_end and ok_count) {
            last_valid_end = i;
            last_valid_groups = groups_seen;
            last_valid_double = saw_double;
        }
        if (at_end) break;
        // Otherwise it's a ':' — the top of the next iteration handles it.
    }

    if (last_valid_end < 2) {
        @branchHint(.unlikely);
        return null;
    }
    // Require at least one ':' so pure IPv4 doesn't reach here.
    var has_colon = false;
    for (text[0..last_valid_end]) |c| {
        if (c == ':') {
            has_colon = true;
            break;
        }
    }
    if (!has_colon) {
        @branchHint(.unlikely);
        return null;
    }
    // Final count validation.
    if (last_valid_double) {
        if (last_valid_groups > 8) return null;
    } else {
        if (last_valid_groups != 8) return null;
    }

    // Delegate only the final algebra (group-to-u128) to std.net on the
    // proven-valid prefix. This is ONE call, not O(n) calls — SEC-009.
    const addr = std.net.Ip6Address.parse(text[0..last_valid_end], 0) catch return null;
    const ip = std.mem.readInt(u128, &addr.sa.addr, .big);
    return .{ .ip = ip, .len = @intCast(last_valid_end) };
}

inline fn isHex(c: u8) bool {
    return (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
}

inline fn isIpv6Byte(c: u8) bool {
    return isHex(c) or c == ':' or c == '.';
}

/// Extract an IPv4 OR IPv6 address at `text[0..]`. Tries IPv6 first because
/// a valid IPv6 prefix never looks like a valid IPv4 — the presence of `:`
/// is disqualifying for IPv4. IPv4 is the common case; most of our callers
/// will end up in the IPv4 branch.
///
/// SEC-001: any IPv4-mapped IPv6 result (`::ffff:a.b.c.d`) is canonicalized
/// to the `.ipv4` variant via `shared.IpAddress.fromIpv6Bits`. Deprecated
/// `::a.b.c.d` values are rejected. This closes the ban-evasion path where
/// an attacker toggles representations to get two independent tracker
/// entries for a single address.
fn extractIp(text: []const u8) ?IpMatch {
    // Fast path: first byte is hex letter or the second byte is ':' — v6.
    // Otherwise try v4 first, then v6 as a fallback.
    if (text.len >= 1) {
        const c0 = text[0];
        const looks_v6 = switch (c0) {
            'a'...'f', 'A'...'F', ':' => true,
            else => false,
        };
        if (looks_v6) {
            if (extractIpv6(text)) |r| {
                const canon = shared.IpAddress.fromIpv6Bits(r.ip) catch return null;
                return .{ .ip = canon, .len = r.len };
            }
        }
    }
    if (extractIpv4(text)) |r| {
        return .{ .ip = .{ .ipv4 = r.ip }, .len = r.len };
    }
    if (extractIpv6(text)) |r| {
        const canon = shared.IpAddress.fromIpv6Bits(r.ip) catch return null;
        return .{ .ip = canon, .len = r.len };
    }
    return null;
}

// ----------------------------------------------------------------------------
// Timestamp extraction
// ----------------------------------------------------------------------------

const SECS_PER_DAY: i64 = 86_400;

fn isLeapYear(y: i64) bool {
    return (@mod(y, 4) == 0 and @mod(y, 100) != 0) or @mod(y, 400) == 0;
}

fn daysFromCivil(y: i64, m: u8, d: u8) i64 {
    // Howard Hinnant's date algorithm. Returns days since 1970-01-01 for
    // (y, m, d) in the proleptic Gregorian calendar.
    const y_adj: i64 = if (m <= 2) y - 1 else y;
    const era: i64 = @divFloor(y_adj, 400);
    const yoe: i64 = y_adj - era * 400; // [0, 399]
    const m_i: i64 = @intCast(m);
    const d_i: i64 = @intCast(d);
    const m_off: i64 = if (m > 2) m_i - 3 else m_i + 9;
    const doy: i64 = @divFloor(153 * m_off + 2, 5) + d_i - 1; // [0, 365]
    const doe: i64 = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146_097 + doe - 719_468;
}

fn monthFromBsdName(s: []const u8) ?u8 {
    if (s.len != 3) return null;
    const months = [_][]const u8{
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    };
    inline for (months, 0..) |name, i| {
        if (std.mem.eql(u8, s, name)) return @intCast(i + 1);
    }
    return null;
}

fn parseU(comptime T: type, s: []const u8) ?T {
    if (s.len == 0) return null;
    var v: T = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        v = v * 10 + @as(T, c - '0');
    }
    return v;
}

/// Parse the timestamp starting at `text[0..]`. On success returns the unix
/// epoch `i64` and the number of bytes consumed. Supports three shapes:
///
///   1. BSD syslog:  `MMM  D HH:MM:SS` or `MMM DD HH:MM:SS`  (15 bytes)
///      The year is assumed to be the current year (we don't have one
///      in the line). For fail2zig's purposes, relative ordering within
///      findtime is what matters — we expose the parsed calendar seconds.
///   2. ISO 8601:    `YYYY-MM-DDTHH:MM:SS` optionally followed by `Z`
///                   or `+HH:MM` / `-HH:MM`.
///   3. Epoch seconds: a run of 10-11 ASCII digits (covers years
///      ~2001-5138). We explicitly bound the digit count so arbitrary
///      numbers embedded in log lines don't get misread as timestamps.
pub fn extractTimestamp(text: []const u8) ?TimestampMatch {
    return extractTimestampWithYear(text, null);
}

/// Same as `extractTimestamp` but allows the caller to pin the year used
/// for BSD syslog timestamps (which lack a year). When `year` is null we
/// default to 1970 — callers embedding this in a real daemon should pass
/// the current wall-clock year.
pub fn extractTimestampWithYear(
    text: []const u8,
    year: ?i64,
) ?TimestampMatch {
    if (text.len == 0) {
        @branchHint(.unlikely);
        return null;
    }

    // ---- ISO 8601: starts with 4 digits + '-' ----
    if (text.len >= 19 and text[4] == '-' and text[7] == '-' and
        (text[10] == 'T' or text[10] == ' ') and
        text[13] == ':' and text[16] == ':')
    {
        const y = parseU(i64, text[0..4]) orelse return null;
        const mo = parseU(u8, text[5..7]) orelse return null;
        const d = parseU(u8, text[8..10]) orelse return null;
        const hh = parseU(u8, text[11..13]) orelse return null;
        const mm = parseU(u8, text[14..16]) orelse return null;
        const ss = parseU(u8, text[17..19]) orelse return null;
        if (mo == 0 or mo > 12 or d == 0 or d > 31 or hh > 23 or mm > 59 or ss > 60) {
            @branchHint(.unlikely);
            return null;
        }

        const days = daysFromCivil(y, mo, d);
        var ts: i64 = days * SECS_PER_DAY + @as(i64, hh) * 3600 +
            @as(i64, mm) * 60 + @as(i64, ss);

        var consumed: usize = 19;
        // Optional fractional seconds — skip but don't interpret.
        if (consumed < text.len and text[consumed] == '.') {
            consumed += 1;
            while (consumed < text.len and text[consumed] >= '0' and text[consumed] <= '9') {
                consumed += 1;
            }
        }
        // Optional timezone: 'Z', '+HH:MM', '-HH:MM'
        if (consumed < text.len) {
            const c = text[consumed];
            if (c == 'Z') {
                consumed += 1;
            } else if ((c == '+' or c == '-') and consumed + 6 <= text.len and text[consumed + 3] == ':') {
                const sign: i64 = if (c == '-') -1 else 1;
                const off_h = parseU(i64, text[consumed + 1 .. consumed + 3]) orelse return null;
                const off_m = parseU(i64, text[consumed + 4 .. consumed + 6]) orelse return null;
                if (off_h > 23 or off_m > 59) return null;
                ts -= sign * (off_h * 3600 + off_m * 60);
                consumed += 6;
            }
        }
        return .{ .ts = ts, .len = @intCast(consumed) };
    }

    // ---- BSD syslog: `MMM ` then ` D HH:MM:SS` or `DD HH:MM:SS` (15 bytes total) ----
    if (text.len >= 15 and text[3] == ' ') {
        const mo = monthFromBsdName(text[0..3]) orelse {
            @branchHint(.unlikely);
            return null;
        };
        // Day slot is always text[4..6], two chars. When the day is a
        // single digit, traditional syslog right-pads with a leading space
        // ("Apr  5"), so text[4] is ' ' and text[5] is the digit. Space
        // then follows at text[6] before the time segment.
        const day_slice = std.mem.trim(u8, text[4..6], " ");
        const d = parseU(u8, day_slice) orelse {
            @branchHint(.unlikely);
            return null;
        };
        if (text[6] != ' ') return null;

        // Time: HH:MM:SS at text[7..15].
        const t: usize = 7;
        if (text[t + 2] != ':' or text[t + 5] != ':') return null;
        const hh = parseU(u8, text[t .. t + 2]) orelse return null;
        const mm = parseU(u8, text[t + 3 .. t + 5]) orelse return null;
        const ss = parseU(u8, text[t + 6 .. t + 8]) orelse return null;
        if (mo == 0 or mo > 12 or d == 0 or d > 31 or hh > 23 or mm > 59 or ss > 60) {
            @branchHint(.unlikely);
            return null;
        }

        const y = year orelse 1970;
        const days = daysFromCivil(y, mo, d);
        const ts = days * SECS_PER_DAY + @as(i64, hh) * 3600 +
            @as(i64, mm) * 60 + @as(i64, ss);
        return .{ .ts = ts, .len = @intCast(t + 8) };
    }

    // ---- Epoch seconds: 10-11 ASCII digits. Anchored. ----
    {
        var i: usize = 0;
        while (i < text.len and i < 12 and text[i] >= '0' and text[i] <= '9') : (i += 1) {}
        if (i >= 10 and i <= 11) {
            // Must not be followed by more digits (would be a bigger number)
            if (i < text.len and text[i] >= '0' and text[i] <= '9') {
                @branchHint(.unlikely);
                return null;
            }
            const ts = parseU(i64, text[0..i]) orelse return null;
            return .{ .ts = ts, .len = @intCast(i) };
        }
    }

    return null;
}

// ----------------------------------------------------------------------------
// Syslog prefix stripping — QA-001
// ----------------------------------------------------------------------------

/// Strip a standard RFC 3164 syslog prefix from `line` if one is present.
/// Returns a subslice of `line` pointing at the message body; zero
/// allocation. Callers feed the returned slice to `Parser.parseLine` so
/// filter patterns can remain position-0 anchored against the "real"
/// log message rather than the syslog envelope.
///
/// Recognized shapes:
///   * `MMM [D]D HH:MM:SS host prog[pid]: body...`     -> `body...`
///   * `MMM [D]D HH:MM:SS host prog: body...`          -> `body...`
///   * `YYYY-MM-DDTHH:MM:SS... host prog[pid]: body...` -> `body...`
///   * Any other shape -> returned unchanged.
///
/// The detector accepts only well-formed BSD / ISO 8601 prefixes — a log
/// line that genuinely starts with `"Failed password..."` is returned
/// untouched.
pub fn stripSyslogPrefix(line: []const u8) []const u8 {
    // Detect a timestamp prefix. If present, skip it; then look for the
    // program-tag-colon-space separator and return everything after it.
    const ts_hit = extractTimestamp(line);
    if (ts_hit == null) return line;
    const after_ts = ts_hit.?.len;
    if (after_ts >= line.len or line[after_ts] != ' ') return line;
    // Bounded scan for `": "`. Cap at 256 bytes after the timestamp —
    // beyond that, this is not a syslog prefix, it's a log message that
    // happens to contain a colon. 256 covers every realistic
    // `hostname program[pid]:` combination.
    const scan_cap = @min(line.len, after_ts + 256);
    var i: usize = after_ts + 1;
    while (i + 1 < scan_cap) : (i += 1) {
        if (line[i] == ':' and line[i + 1] == ' ') {
            return line[i + 2 ..];
        }
    }
    return line;
}

// ----------------------------------------------------------------------------
// Hostname extraction — bounded, chars-only scan
// ----------------------------------------------------------------------------

fn extractHost(text: []const u8) ?u16 {
    // A hostname byte: [A-Za-z0-9._-]. Bound to 253 bytes (DNS max).
    const cap = @min(text.len, 253);
    var i: usize = 0;
    while (i < cap) : (i += 1) {
        const c = text[i];
        const ok = switch (c) {
            'a'...'z', 'A'...'Z', '0'...'9', '.', '-', '_' => true,
            else => false,
        };
        if (!ok) break;
    }
    if (i == 0) return null;
    return @intCast(i);
}

// ============================================================================
// Comptime pattern compiler
// ============================================================================

const Token = enum { literal, ip, timestamp, host, wildcard };

const Segment = struct {
    tok: Token,
    lit: []const u8, // only meaningful when tok == .literal
};

/// Split a pattern string into a list of segments at comptime.
fn compileSegments(comptime pattern: []const u8) []const Segment {
    comptime {
        @setEvalBranchQuota(100_000);
        var segs: []const Segment = &.{};
        var i: usize = 0;
        var lit_start: usize = 0;
        while (i < pattern.len) {
            if (pattern[i] == '<') {
                // Flush any pending literal first.
                if (i > lit_start) {
                    segs = segs ++ &[_]Segment{.{ .tok = .literal, .lit = pattern[lit_start..i] }};
                }
                // Parse the token up to the matching '>'.
                const name_start = i + 1;
                var j = name_start;
                while (j < pattern.len and pattern[j] != '>') : (j += 1) {}
                if (j >= pattern.len) {
                    @compileError("pattern: unterminated token '<' near: " ++ pattern[i..]);
                }
                const name = pattern[name_start..j];
                const tok: Token = blk: {
                    if (std.mem.eql(u8, name, "IP")) break :blk .ip;
                    if (std.mem.eql(u8, name, "TIMESTAMP")) break :blk .timestamp;
                    if (std.mem.eql(u8, name, "HOST")) break :blk .host;
                    if (std.mem.eql(u8, name, "*")) break :blk .wildcard;
                    @compileError("pattern: unknown token <" ++ name ++ ">");
                };
                segs = segs ++ &[_]Segment{.{ .tok = tok, .lit = "" }};
                i = j + 1;
                lit_start = i;
            } else {
                i += 1;
            }
        }
        if (lit_start < pattern.len) {
            segs = segs ++ &[_]Segment{.{ .tok = .literal, .lit = pattern[lit_start..] }};
        }
        return segs;
    }
}

/// Validate constraints on a pattern at comptime:
///   * exactly one `<IP>` token (every match produces an IP)
///   * at most one `<TIMESTAMP>` token
///   * `<*>` may precede any token (including other dynamics) — it means
///     "scan until the next extractor succeeds or the next literal
///     matches". Two non-wildcard dynamic tokens adjacent (e.g.
///     `<IP><HOST>`) are rejected as ambiguous.
fn validatePattern(comptime segs: []const Segment) void {
    comptime {
        var ip_count: usize = 0;
        var ts_count: usize = 0;
        var prev: ?Token = null;
        for (segs) |s| {
            if (s.tok == .ip) ip_count += 1;
            if (s.tok == .timestamp) ts_count += 1;
            if (prev) |p| {
                const both_dyn = p != .literal and s.tok != .literal;
                const prev_is_wild = p == .wildcard;
                if (both_dyn and !prev_is_wild) {
                    @compileError(
                        "pattern: two non-wildcard dynamic tokens may not be adjacent (insert a literal or <*>)",
                    );
                }
            }
            prev = s.tok;
        }
        if (ip_count != 1) {
            @compileError("pattern: exactly one <IP> token is required");
        }
        if (ts_count > 1) {
            @compileError("pattern: at most one <TIMESTAMP> token is allowed");
        }
    }
}

/// Build a specialized match function for the given pattern.
///
/// The returned function walks the input once, advancing a cursor
/// through each segment:
///   * literal: `mem.indexOfPos(line, cursor, lit)` — the first literal
///     is anchored (must be at position 0), later literals may sit
///     after a wildcard/host/ip/timestamp.
///   * <IP>: `extractIp(line[cursor..])` — required, populates ip.
///   * <TIMESTAMP>: `extractTimestamp(line[cursor..])` — populates ts.
///   * <HOST>: `extractHost(line[cursor..])` — advances cursor.
///   * <*>: defer — consumed by the following literal's indexOf.
pub fn compile(comptime pattern: []const u8) MatchFn {
    const segs = compileSegments(pattern);
    validatePattern(segs);

    const Gen = struct {
        fn match(line: []const u8) ?ParseResult {
            var cursor: usize = 0;
            var result: ParseResult = .{ .ip = .{ .ipv4 = 0 } };
            var pending_wild: bool = false;

            inline for (segs, 0..) |seg, idx| {
                switch (seg.tok) {
                    .literal => {
                        if (pending_wild) {
                            const found = std.mem.indexOfPos(u8, line, cursor, seg.lit) orelse {
                                @branchHint(.unlikely);
                                return null;
                            };
                            cursor = found + seg.lit.len;
                            pending_wild = false;
                        } else if (idx == 0) {
                            // Anchored literal at start.
                            if (line.len < seg.lit.len or
                                !std.mem.eql(u8, line[0..seg.lit.len], seg.lit))
                            {
                                @branchHint(.unlikely);
                                return null;
                            }
                            cursor = seg.lit.len;
                        } else {
                            // Unanchored: must match exactly at cursor.
                            const end = cursor + seg.lit.len;
                            if (end > line.len or
                                !std.mem.eql(u8, line[cursor..end], seg.lit))
                            {
                                @branchHint(.unlikely);
                                return null;
                            }
                            cursor = end;
                        }
                    },
                    .ip => {
                        const hit = scanForIp(line, cursor, pending_wild) orelse {
                            @branchHint(.unlikely);
                            return null;
                        };
                        result.ip = hit.ip;
                        cursor = hit.end;
                        pending_wild = false;
                    },
                    .timestamp => {
                        const hit = scanForTimestamp(line, cursor, pending_wild) orelse {
                            @branchHint(.unlikely);
                            return null;
                        };
                        result.timestamp = hit.ts;
                        cursor = hit.end;
                        pending_wild = false;
                    },
                    .host => {
                        const hit = scanForHost(line, cursor, pending_wild) orelse {
                            @branchHint(.unlikely);
                            return null;
                        };
                        cursor = hit;
                        pending_wild = false;
                    },
                    .wildcard => {
                        pending_wild = true;
                    },
                }
            }
            return result;
        }
    };

    return &Gen.match;
}

// ----------------------------------------------------------------------------
// Pattern-compiler scan helpers (non-comptime — called from generated fn)
// ----------------------------------------------------------------------------

const IpHit = struct { ip: shared.IpAddress, end: usize };
const TimestampHit = struct { ts: shared.Timestamp, end: usize };

/// When `scan` is false, the IP must sit exactly at `cursor`. When `scan`
/// is true (i.e. a prior `<*>` is pending), advance through the line
/// until we find a valid IP — bounded by line length, so cost is O(n).
fn scanForIp(line: []const u8, cursor: usize, scan: bool) ?IpHit {
    if (!scan) {
        if (cursor > line.len) return null;
        const r = extractIp(line[cursor..]) orelse return null;
        return .{ .ip = r.ip, .end = cursor + r.len };
    }
    var i: usize = cursor;
    while (i < line.len) : (i += 1) {
        if (extractIp(line[i..])) |r| {
            return .{ .ip = r.ip, .end = i + r.len };
        }
    }
    return null;
}

fn scanForTimestamp(line: []const u8, cursor: usize, scan: bool) ?TimestampHit {
    if (!scan) {
        if (cursor > line.len) return null;
        const r = extractTimestamp(line[cursor..]) orelse return null;
        return .{ .ts = r.ts, .end = cursor + r.len };
    }
    var i: usize = cursor;
    while (i < line.len) : (i += 1) {
        if (extractTimestamp(line[i..])) |r| {
            return .{ .ts = r.ts, .end = i + r.len };
        }
    }
    return null;
}

fn scanForHost(line: []const u8, cursor: usize, scan: bool) ?usize {
    if (!scan) {
        if (cursor > line.len) return null;
        const n = extractHost(line[cursor..]) orelse return null;
        return cursor + n;
    }
    var i: usize = cursor;
    while (i < line.len) : (i += 1) {
        if (extractHost(line[i..])) |n| {
            return i + n;
        }
    }
    return null;
}

// ============================================================================
// Legacy Parser wrapper — keeps the pre-existing API surface alive for now.
// Phase 4 will retire this in favor of direct `Matcher` use.
// ============================================================================

pub const Error = error{NoMatch};

pub const Parser = struct {
    allocator: std.mem.Allocator,
    match_fn: MatchFn,

    pub fn init(allocator: std.mem.Allocator) Parser {
        // Default to a permissive "match any line that contains an IP" pattern.
        const default_match = comptime compile("<*><IP>");
        return .{ .allocator = allocator, .match_fn = default_match };
    }

    pub fn withMatcher(allocator: std.mem.Allocator, match_fn: MatchFn) Parser {
        return .{ .allocator = allocator, .match_fn = match_fn };
    }

    pub fn parseLine(self: *const Parser, line: []const u8) Error!ParseResult {
        return self.match_fn(line) orelse error.NoMatch;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "parser: extractIpv4 typical" {
    const r = extractIpv4("192.168.1.1 rest of line").?;
    try std.testing.expectEqual(@as(u32, 0xC0A80101), r.ip);
    try std.testing.expectEqual(@as(u8, 11), r.len);
}

test "parser: extractIpv4 at exact end of slice" {
    const r = extractIpv4("10.0.0.1").?;
    try std.testing.expectEqual(@as(u32, 0x0A000001), r.ip);
    try std.testing.expectEqual(@as(u8, 8), r.len);
}

test "parser: extractIpv4 rejects too short" {
    try std.testing.expect(extractIpv4("1.2.3") == null);
    try std.testing.expect(extractIpv4("") == null);
}

test "parser: extractIpv4 rejects invalid octet" {
    try std.testing.expect(extractIpv4("256.0.0.1") == null);
    try std.testing.expect(extractIpv4("999.0.0.0") == null);
    // Ends on '.5' — consumes 1.2.3.4 and stops at the next dot boundary.
    const r = extractIpv4("1.2.3.4.5").?;
    try std.testing.expectEqual(@as(u32, 0x01020304), r.ip);
    try std.testing.expectEqual(@as(u8, 7), r.len);
}

test "parser: extractIpv4 stops at non-digit-non-dot" {
    const r = extractIpv4("1.2.3.4 from somewhere").?;
    try std.testing.expectEqual(@as(u32, 0x01020304), r.ip);
    try std.testing.expectEqual(@as(u8, 7), r.len);
}

test "parser: extractIpv4 consumes just the address" {
    const r = extractIpv4("8.8.8.8:443").?;
    try std.testing.expectEqual(@as(u8, 7), r.len);
}

test "parser: extractIpv6 loopback" {
    const r = extractIpv6("::1 tail").?;
    try std.testing.expectEqual(@as(u128, 1), r.ip);
    try std.testing.expectEqual(@as(u16, 3), r.len);
}

test "parser: extractIpv6 full form" {
    const r = extractIpv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334 tail").?;
    try std.testing.expectEqual(@as(u128, 0x20010db885a3000000008a2e03707334), r.ip);
}

test "parser: extractIpv6 ipv4-mapped" {
    // extractIpv6 still returns the raw u128; canonicalization happens in extractIp.
    const r = extractIpv6("::ffff:192.168.1.1 tail").?;
    const expected: u128 = 0x00000000000000000000ffffc0a80101;
    try std.testing.expectEqual(expected, r.ip);
    try std.testing.expectEqual(@as(u16, 18), r.len);
}

test "parser: extractIpv6 rejects plain v4" {
    // No colons -> not v6.
    try std.testing.expect(extractIpv6("192.168.1.1") == null);
}

test "parser: extractIp folds ::ffff: into ipv4 (SEC-001)" {
    // Same attacker address in two representations must produce equal keys.
    const mapped = extractIp("::ffff:1.2.3.4 tail").?;
    const plain = extractIp("1.2.3.4 tail").?;
    try std.testing.expect(shared.IpAddress.eql(mapped.ip, plain.ip));
    try std.testing.expectEqual(@as(u32, 0x01020304), mapped.ip.ipv4);
}

test "parser: extractIp rejects deprecated ::a.b.c.d (SEC-001)" {
    // IPv4-compatible form is deprecated and becomes an evasion vector —
    // reject outright. `extractIpv6` still returns the raw bits; extractIp
    // filters via fromIpv6Bits.
    try std.testing.expect(extractIp("::1.2.3.4") == null);
}

test "parser: extractIpv6 single-pass rejects double '::' (SEC-009)" {
    // The previous truncation-loop implementation would keep retrying
    // shorter prefixes. The structural validator should return null or
    // a short prefix — never hang or burn O(n) std.net calls.
    try std.testing.expect(extractIpv6("::1::2") == null or extractIpv6("::1::2").?.len <= 3);
}

test "parser: extractIpv6 adversarial garbage input (SEC-009)" {
    // Worst-case input for the old loop: 60+ bytes of ipv6-lookalike that
    // never parses until the last attempt. The structural validator should
    // reject it in a single pass.
    const adversarial = "a:b:c:d:e:f:0123456789abcdef:0123456789abcdef:z tail";
    _ = extractIpv6(adversarial); // Must not panic; structural check rejects.
}

test "parser: extractTimestamp ISO 8601 Z" {
    const r = extractTimestamp("2026-04-20T14:30:22Z tail").?;
    // 2026-04-20T14:30:22Z == 1776695422 (verified against python calendar.timegm)
    try std.testing.expectEqual(@as(i64, 1_776_695_422), r.ts);
    try std.testing.expectEqual(@as(u16, 20), r.len);
}

test "parser: extractTimestamp ISO 8601 with offset" {
    const r = extractTimestamp("2026-04-20T14:30:22+02:00 tail").?;
    // 2026-04-20T14:30:22+02:00 == 2026-04-20T12:30:22Z == epoch 1776688222
    try std.testing.expectEqual(@as(i64, 1_776_688_222), r.ts);
}

test "parser: extractTimestamp BSD syslog 2-digit day" {
    const r = extractTimestampWithYear("Apr 20 14:30:22 host sshd", 2026).?;
    try std.testing.expectEqual(@as(i64, 1_776_695_422), r.ts);
    try std.testing.expectEqual(@as(u16, 15), r.len);
}

test "parser: extractTimestamp BSD syslog single-digit padded day" {
    const r = extractTimestampWithYear("Apr  5 14:30:22 host sshd", 2026).?;
    // Days from 1970-01-01 to 2026-04-05 * 86400 + 14:30:22
    const expected_days = daysFromCivil(2026, 4, 5);
    const expected_ts = expected_days * SECS_PER_DAY + 14 * 3600 + 30 * 60 + 22;
    try std.testing.expectEqual(expected_ts, r.ts);
    try std.testing.expectEqual(@as(u16, 15), r.len);
}

test "parser: extractTimestamp epoch seconds" {
    const r = extractTimestamp("1713624622 tail").?;
    try std.testing.expectEqual(@as(i64, 1_713_624_622), r.ts);
    try std.testing.expectEqual(@as(u16, 10), r.len);
}

test "parser: extractTimestamp rejects random digits" {
    // Only 5 digits — too short to be an epoch.
    try std.testing.expect(extractTimestamp("12345 tail") == null);
}

test "parser: stripSyslogPrefix BSD rsyslog sshd line (QA-001)" {
    // QA-001: a real /var/log/auth.log line must come out of
    // stripSyslogPrefix as just the program message body, so that
    // position-0-anchored filter patterns can match.
    const raw = "Apr 21 10:15:03 host sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2";
    const stripped = stripSyslogPrefix(raw);
    try std.testing.expectEqualStrings(
        "Failed password for root from 1.2.3.4 port 22 ssh2",
        stripped,
    );
}

test "parser: stripSyslogPrefix ISO 8601 variant (QA-001)" {
    const raw = "2026-04-21T10:15:03Z host nginx: 1.2.3.4 - - [21/Apr] \"GET /wp-login.php HTTP/1.1\" 404 0";
    const stripped = stripSyslogPrefix(raw);
    try std.testing.expectEqualStrings(
        "1.2.3.4 - - [21/Apr] \"GET /wp-login.php HTTP/1.1\" 404 0",
        stripped,
    );
}

test "parser: stripSyslogPrefix passes non-syslog lines through (QA-001)" {
    // journalctl-piped or test-harness lines already start with the
    // program message body — stripSyslogPrefix must return them unchanged.
    const raw = "Failed password for root from 1.2.3.4 port 22 ssh2";
    const stripped = stripSyslogPrefix(raw);
    try std.testing.expectEqualStrings(raw, stripped);
}

test "parser: stripSyslogPrefix leaves lines with no colon intact (QA-001)" {
    // A timestamped line without the `program: ` separator must not be
    // mangled — returned as-is.
    const raw = "Apr 21 10:15:03 host notquitesyslog";
    const stripped = stripSyslogPrefix(raw);
    try std.testing.expectEqualStrings(raw, stripped);
}

test "parser: compile matches syslog-prefixed sshd via stripSyslogPrefix (QA-001)" {
    // The integration: sshd pattern + real rsyslog line. Without
    // stripping, this would fail because `Failed password` sits at
    // byte 32, not byte 0. After stripping, the anchored literal
    // matches at position 0.
    const m = comptime compile("Failed password for <*> from <IP>");
    const raw = "Apr 21 10:15:03 host sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2";
    const body = stripSyslogPrefix(raw);
    const r = m(body).?;
    try std.testing.expectEqual(@as(u32, 0x01020304), r.ip.ipv4);
}

test "parser: compile sshd-style pattern" {
    const m = comptime compile("Failed password for <*> from <IP>");
    const r = m("Failed password for root from 1.2.3.4").?;
    try std.testing.expectEqual(@as(u32, 0x01020304), r.ip.ipv4);
}

test "parser: compile sshd pattern rejects non-matching line" {
    const m = comptime compile("Failed password for <*> from <IP>");
    try std.testing.expect(m("Accepted password for root from 1.2.3.4") == null);
}

test "parser: compile pattern with timestamp" {
    const m = comptime compile("<TIMESTAMP> <*> from <IP>");
    const r = m("2026-04-20T14:30:22Z sshd from 10.0.0.1").?;
    try std.testing.expectEqual(@as(u32, 0x0A000001), r.ip.ipv4);
    try std.testing.expectEqual(@as(i64, 1_776_695_422), r.timestamp.?);
}

test "parser: compile pattern with ipv6" {
    const m = comptime compile("Failed password for <*> from <IP>");
    const r = m("Failed password for root from 2001:db8::1").?;
    try std.testing.expectEqual(@as(u128, 0x20010db8000000000000000000000001), r.ip.ipv6);
}

test "parser: compile anchored literal failure" {
    const m = comptime compile("Failed <*> from <IP>");
    try std.testing.expect(m("  Failed whatever from 1.2.3.4") == null);
}

test "parser: compile pattern with host" {
    const m = comptime compile("<HOST> has IP <IP>");
    const r = m("web01.example.com has IP 10.0.0.5").?;
    try std.testing.expectEqual(@as(u32, 0x0A000005), r.ip.ipv4);
}

test "parser: compile pattern has zero heap allocation" {
    // Wrap std.testing.allocator in a FailingAllocator that denies every
    // request — if the match fn ever tried to allocate, the test would
    // crash with a failure. The generated match fn is slice arithmetic
    // only, so the allocator is never touched.
    var fa = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    const a = fa.allocator();
    const m = comptime compile("Failed password for <*> from <IP>");
    const p = Parser.withMatcher(a, m);
    const r = try p.parseLine("Failed password for root from 9.9.9.9");
    try std.testing.expectEqual(@as(u32, 0x09090909), r.ip.ipv4);
    // No alloc / resize attempt ever reached the FailingAllocator.
    try std.testing.expectEqual(@as(usize, 0), fa.alloc_index);
    try std.testing.expectEqual(@as(usize, 0), fa.allocations);
}

test "parser: Parser wrapper parseLine default pattern" {
    const p = Parser.init(std.testing.allocator);
    const r = try p.parseLine("some prefix 1.2.3.4 tail");
    try std.testing.expectEqual(@as(u32, 0x01020304), r.ip.ipv4);
}

test "parser: Parser wrapper rejects line with no IP" {
    const p = Parser.init(std.testing.allocator);
    try std.testing.expectError(error.NoMatch, p.parseLine("no ip here"));
}

test "parser: Parser wrapper with custom match fn" {
    const m = comptime compile("ssh <IP>");
    const p = Parser.withMatcher(std.testing.allocator, m);
    const r = try p.parseLine("ssh 10.0.0.1");
    try std.testing.expectEqual(@as(u32, 0x0A000001), r.ip.ipv4);
}

test {
    // Surface the matcher module's tests through parser.zig so main.zig
    // doesn't need to be modified to reach them.
    _ = matcher;
}
