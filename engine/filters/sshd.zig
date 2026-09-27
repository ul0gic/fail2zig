// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const types = @import("types.zig");
const parser = @import("../core/parser.zig");

pub const PatternDef = types.PatternDef;

pub const patterns = [_]PatternDef{
    .{
        .name = "failed-password-invalid-user",
        .match = parser.compile("Failed password for invalid user <*> from <IP>"),
    },
    .{
        .name = "failed-password",
        .match = parser.compile("Failed password for <*> from <IP>"),
    },
    .{
        .name = "invalid-user",
        .match = parser.compile("Invalid user <*> from <IP>"),
    },
    .{
        .name = "connection-closed-auth",
        .match = parser.compile("Connection closed by authenticating user <*><IP>"),
    },
    .{
        .name = "disconnected-auth",
        .match = parser.compile("Disconnected from authenticating user <*><IP>"),
    },
    .{
        .name = "pam-auth-failure",
        .match = parser.compile("error: PAM: Authentication failure for <*> from <IP>"),
    },
    .{
        .name = "received-disconnect-preauth",
        .match = parser.compile("Received disconnect from <IP> <*>[preauth]"),
    },
    .{
        .name = "bad-protocol",
        .match = parser.compile("Bad protocol version identification <*> from <IP>"),
    },
    .{
        .name = "max-auth-attempts",
        .match = parser.compile("maximum authentication attempts exceeded for <*> from <IP>"),
    },
};

const testing = std.testing;

fn firstMatch(line: []const u8) ?usize {
    for (patterns, 0..) |p, i| {
        if (p.match(line)) |_| return i;
    }
    return null;
}

test "sshd: received-disconnect requires [preauth] (SYS-011 regression)" {
    try testing.expect(firstMatch("Received disconnect from 1.2.3.4 port 22:11: Bye Bye [preauth]") != null);
    try testing.expect(firstMatch("Received disconnect from 203.0.113.5 port 5555:11: disconnected by user [preauth]") != null);
    try testing.expect(firstMatch("Received disconnect from 2001:db8::1 port 22:11: Bye Bye [preauth]") != null);

    try testing.expect(firstMatch("Received disconnect from 1.2.3.4 port 22:11: disconnected by user") == null);
    try testing.expect(firstMatch("Received disconnect from 192.168.1.1 port 2222: disconnected by server request") == null);
}
