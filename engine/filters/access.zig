// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Parses web access log lines and builds matchers on a requested path fragment or a user-agent substring.
// Holds: The address comes only from the first field; a line whose request is not exactly method, path and HTTP/ version matches nothing.

const std = @import("std");
const shared = @import("shared");
const parser = @import("../detect/parser.zig");

const Quoted = struct { text: []const u8, end: usize };

fn quoted(line: []const u8, start: usize) ?Quoted {
    const open = std.mem.indexOfScalarPos(u8, line, start, '"') orelse return null;
    var pos = open + 1;
    while (pos < line.len) : (pos += 1) {
        // Why: Apache logs a quote inside a field as \" (mod_log_config), so an escaped quote does not end the field.
        if (line[pos] == '\\') {
            pos += 1;
            continue;
        }
        if (line[pos] == '"') return .{ .text = line[open + 1 .. pos], .end = pos + 1 };
    }
    return null;
}

const Access = struct { ip: shared.IpAddress, path: []const u8, status: u16, agent: []const u8 };

fn parse(line: []const u8) ?Access {
    const first_space = std.mem.indexOfScalar(u8, line, ' ') orelse return null;
    const ip = shared.IpAddress.parse(line[0..first_space]) catch return null;
    const request = quoted(line, first_space) orelse return null;
    var words = std.mem.tokenizeScalar(u8, request.text, ' ');
    _ = words.next() orelse return null;
    const path = words.next() orelse return null;
    const protocol = words.next() orelse return null;
    if (!std.mem.startsWith(u8, protocol, "HTTP/") or words.next() != null) return null;
    const tail = std.mem.trimLeft(u8, line[request.end..], " ");
    if (tail.len < 4 or tail[3] != ' ') return null;
    const status = std.fmt.parseInt(u16, tail[0..3], 10) catch return null;
    var agent: []const u8 = "";
    if (quoted(line, request.end)) |referer| {
        if (quoted(line, referer.end)) |user_agent| agent = user_agent.text;
    }
    return .{ .ip = ip, .path = path, .status = status, .agent = agent };
}

pub fn pathMatcher(comptime fragment: []const u8, comptime allow_forbidden: bool) parser.MatchFn {
    return struct {
        fn match(line: []const u8) ?parser.ParseResult {
            const entry = parse(line) orelse return null;
            if (entry.status != 404 and !(allow_forbidden and entry.status == 403)) return null;
            const index = std.mem.indexOf(u8, entry.path, fragment) orelse return null;
            const end = index + fragment.len;
            // Why: A path boundary must follow the fragment, so a request for /.envoy does not match the /.env fragment.
            if (end < entry.path.len and std.mem.indexOfScalar(u8, "/.?", entry.path[end]) == null) return null;
            return .{ .ip = entry.ip };
        }
    }.match;
}

pub fn agentMatcher(comptime name: []const u8) parser.MatchFn {
    return struct {
        fn match(line: []const u8) ?parser.ParseResult {
            const entry = parse(line) orelse return null;
            if (std.mem.indexOf(u8, entry.agent, name) == null) return null;
            return .{ .ip = entry.ip };
        }
    }.match;
}
