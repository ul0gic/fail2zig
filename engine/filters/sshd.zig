// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Matches OpenSSH sshd authentication failure messages and takes the peer address from them.
// Holds: Each pattern is anchored at the message start, and a line holding two complete peer candidates matches nothing.

const std = @import("std");
const shared = @import("shared");
const types = @import("types.zig");
const parser = @import("../detect/parser.zig");

pub const PatternDef = types.PatternDef;

pub const patterns = [_]PatternDef{
    .{
        .name = "failed-password-invalid-user",
        .match = fieldMatcher("Failed password for invalid user ", " from ", .password),
    },
    .{
        .name = "failed-password",
        .match = fieldMatcher("Failed password for ", " from ", .password),
    },
    .{
        .name = "invalid-user",
        .match = fieldMatcher("Invalid user ", " from ", .plain),
    },
    .{
        .name = "connection-closed-auth",
        .match = fieldMatcher("Connection closed by authenticating user ", " ", .authenticating),
    },
    .{
        .name = "disconnected-auth",
        .match = fieldMatcher("Disconnected from authenticating user ", " ", .authenticating),
    },
    .{
        .name = "pam-auth-failure",
        .match = fieldMatcher("error: PAM: Authentication failure for ", " from ", .pam),
    },
    .{
        .name = "received-disconnect-preauth",
        .match = receivedDisconnect,
    },
    .{
        .name = "bad-protocol",
        .match = fieldMatcher("Bad protocol version identification '", "' from ", .plain),
    },
    .{
        .name = "max-auth-attempts",
        .match = fieldMatcher("maximum authentication attempts exceeded for ", " from ", .maximum),
    },
};

const Suffix = enum { plain, authenticating, password, pam, maximum };
const Peer = struct { ip: shared.IpAddress, end: usize };

fn exactIp(token: []const u8) ?shared.IpAddress {
    if (token.len == 0 or token.len > 64) return null;
    if (parser.extractIpv4(token)) |value| {
        if (value.len == token.len) return .{ .ipv4 = value.ip };
    }
    if (parser.extractIpv6(token)) |value| {
        if (value.len == token.len) return shared.IpAddress.fromIpv6Bits(value.ip) catch null;
    }
    return null;
}

fn peerAt(line: []const u8, start: usize, allow_reason: bool) ?Peer {
    const end = std.mem.indexOfScalarPos(u8, line, start, ' ') orelse line.len;
    const token = line[start..end];
    if (exactIp(token)) |ip| return .{ .ip = ip, .end = end };
    if (allow_reason and std.mem.endsWith(u8, token, ":")) {
        if (exactIp(token[0 .. token.len - 1])) |ip| return .{ .ip = ip, .end = end - 1 };
    }
    return null;
}

fn decimalEnd(text: []const u8, start: usize) ?usize {
    var end = start;
    var value: u32 = 0;
    while (end < text.len and std.ascii.isDigit(text[end])) : (end += 1) {
        if (end - start >= 5) return null;
        value = value * 10 + text[end] - '0';
        if (value > 65535) return null;
    }
    return if (end > start) end else null;
}

fn completeSuffix(text: []const u8, comptime suffix: Suffix) bool {
    var cursor: usize = 0;
    if (suffix == .pam and std.mem.startsWith(u8, text, " via ")) {
        const via = peerAt(text, 5, false) orelse return false;
        cursor = via.end;
    }
    // Why: sshd writes a port after the peer in authenticating-user events, so an address without one is not taken as the peer.
    if (suffix == .authenticating and !std.mem.startsWith(u8, text[cursor..], " port ")) return false;
    if (std.mem.startsWith(u8, text[cursor..], " port ")) {
        cursor = decimalEnd(text, cursor + 6) orelse return false;
    }
    if (suffix == .password or suffix == .maximum) {
        if (std.mem.startsWith(u8, text[cursor..], " ssh1") or std.mem.startsWith(u8, text[cursor..], " ssh2")) cursor += 5;
    }
    // Why: Text after `: ` is sshd auth info that may hold addresses; the outer scan still refuses a line with two candidates.
    if (suffix == .password and std.mem.startsWith(u8, text[cursor..], ": ")) return true;
    if (std.mem.startsWith(u8, text[cursor..], " [preauth]")) cursor += 10;
    return cursor == text.len;
}

fn fieldMatcher(comptime prefix: []const u8, comptime separator: []const u8, comptime suffix: Suffix) parser.MatchFn {
    return &struct {
        fn match(input: []const u8) ?parser.ParseResult {
            const line = if (suffix == .maximum and std.mem.startsWith(u8, input, "error: ")) input[7..] else input;
            if (!std.mem.startsWith(u8, line, prefix)) return null;
            const fields = line[prefix.len..];
            // Why: Invalid-user lines belong to failed-password-invalid-user, so this pattern never claims one that pattern refused.
            if (comptime std.mem.eql(u8, prefix, "Failed password for ")) {
                if (std.mem.startsWith(u8, fields, "invalid user ")) return null;
            }
            var candidate: ?shared.IpAddress = null;
            var cursor: usize = 0;
            while (std.mem.indexOfPos(u8, fields, cursor, separator)) |found| {
                const start = found + separator.len;
                cursor = start;
                const peer = peerAt(fields, start, suffix == .password) orelse continue;
                if (!completeSuffix(fields[peer.end..], suffix)) continue;
                // Why: A username can carry a forged separator and address, so the first candidate does not win by position.
                if (candidate != null) return null;
                candidate = peer.ip;
            }
            return .{ .ip = candidate orelse return null };
        }
    }.match;
}

fn receivedDisconnect(input: []const u8) ?parser.ParseResult {
    const line = if (std.mem.startsWith(u8, input, "error: ")) input[7..] else input;
    const prefix = "Received disconnect from ";
    if (!std.mem.startsWith(u8, line, prefix)) return null;
    const fields = line[prefix.len..];
    const space = std.mem.indexOfScalar(u8, fields, ' ') orelse return null;
    var ip: shared.IpAddress = undefined;
    var cursor: usize = undefined;
    if (std.mem.startsWith(u8, fields[space..], " port ")) {
        ip = exactIp(fields[0..space]) orelse return null;
        cursor = decimalEnd(fields, space + 6) orelse return null;
        if (cursor >= fields.len or fields[cursor] != ':') return null;
        cursor += 1;
    } else {
        // Why: Older sshd messages write the peer with no port and end it with `: `, IPv6 addresses included.
        if (space == 0 or fields[space - 1] != ':') return null;
        ip = exactIp(fields[0 .. space - 1]) orelse return null;
        cursor = space + 1;
    }
    cursor = decimalEnd(fields, cursor) orelse return null;
    if (!std.mem.startsWith(u8, fields[cursor..], ": ")) return null;
    cursor += 2;
    if (!std.mem.endsWith(u8, fields[cursor..], " [preauth]")) return null;
    return .{ .ip = ip };
}
