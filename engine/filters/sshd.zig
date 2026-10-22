// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

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
