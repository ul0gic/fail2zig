// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Lists the built-in patterns for nginx basic-auth failures, request and connection limiting, and bot path probes.
// Holds: Every error-log pattern reads the address right after `client: `, and the path patterns match only 404 or 403 responses.

const types = @import("types.zig");
const parser = @import("../detect/parser.zig");
const access = @import("access.zig");

pub const PatternDef = types.PatternDef;

pub const http_auth_patterns = [_]PatternDef{
    .{
        .name = "no-user-password",
        .match = parser.compile("<*>no user/password was provided for basic authentication<*>client: <IP>"),
    },
    .{
        .name = "user-not-found",
        .match = parser.compile("<*>was not found in<*>client: <IP>"),
    },
    .{
        .name = "password-mismatch",
        .match = parser.compile("<*>password mismatch<*>client: <IP>"),
    },
};

pub const limit_req_patterns = [_]PatternDef{
    .{
        .name = "limit-req-zone",
        .match = parser.compile("<*>limiting requests, excess:<*>by zone<*>client: <IP>"),
    },
    .{
        .name = "limit-conn-zone",
        .match = parser.compile("<*>limiting connections by zone<*>client: <IP>"),
    },
};

pub const botsearch_patterns = [_]PatternDef{
    .{
        .name = "wp-login",
        .match = access.pathMatcher("/wp-login", true),
    },
    .{
        .name = "xmlrpc",
        .match = access.pathMatcher("/xmlrpc", true),
    },
    .{
        .name = "phpmyadmin",
        .match = access.pathMatcher("/phpmyadmin", true),
    },
    .{
        .name = "env-file",
        .match = access.pathMatcher("/.env", true),
    },
    .{
        .name = "git-folder",
        .match = access.pathMatcher("/.git", true),
    },
};
