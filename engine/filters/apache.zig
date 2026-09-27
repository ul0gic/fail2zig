// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const types = @import("types.zig");
const parser = @import("../core/parser.zig");
const access = @import("access.zig");

pub const PatternDef = types.PatternDef;

pub const auth_patterns = [_]PatternDef{
    .{
        .name = "auth-failure",
        .match = parser.compile("<*>[client <IP>:<*>] user <*>authentication failure"),
    },
    .{
        .name = "user-not-found",
        .match = parser.compile("<*>[client <IP>:<*>] user <*>not found"),
    },
    .{
        .name = "password-mismatch",
        .match = parser.compile("<*>[client <IP>:<*>] <*>password mismatch"),
    },
};

pub const badbots_patterns = [_]PatternDef{
    .{
        .name = "ahrefs",
        .match = access.agentMatcher("AhrefsBot"),
    },
    .{
        .name = "semrush",
        .match = access.agentMatcher("SemrushBot"),
    },
    .{
        .name = "mj12",
        .match = access.agentMatcher("MJ12bot"),
    },
    .{
        .name = "dot",
        .match = access.agentMatcher("DotBot"),
    },
    .{
        .name = "wp-login-404",
        .match = access.pathMatcher("/wp-login", false),
    },
    .{
        .name = "xmlrpc-404",
        .match = access.pathMatcher("/xmlrpc", false),
    },
};

pub const overflows_patterns = [_]PatternDef{
    .{
        .name = "invalid-uri",
        .match = parser.compile("<*>[client <IP>:<*>] Invalid URI in request"),
    },
    .{
        .name = "request-line-too-long",
        .match = parser.compile("<*>[client <IP>:<*>] request failed: URI too long"),
    },
    .{
        .name = "request-header-too-long",
        .match = parser.compile("<*>[client <IP>:<*>] request failed: error reading the headers"),
    },
};
