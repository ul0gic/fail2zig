// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const types = @import("types.zig");
const parser = @import("../core/parser.zig");

pub const PatternDef = types.PatternDef;

pub const named_refused_patterns = [_]PatternDef{
    .{
        .name = "query-denied",
        .match = parser.compile("<*>client <*><IP>#<*>denied"),
    },
    .{
        .name = "query-refused",
        .match = parser.compile("<*>client <IP>#<*>REFUSED"),
    },
};

fn matchRecidiveBan(line: []const u8) ?parser.ParseResult {
    const bare = comptime parser.compile("ban: jail='<*>' ip=<IP>");
    const prefixed = comptime parser.compile("<*> ban: jail='<*>' ip=<IP>");
    return bare(line) orelse prefixed(line);
}

pub const recidive_patterns = [_]PatternDef{
    .{
        .name = "fail2zig-ban",
        .match = matchRecidiveBan,
    },
};

pub const vsftpd_patterns = [_]PatternDef{
    .{
        .name = "fail-login",
        .match = parser.compile("<*>FAIL LOGIN: Client \"<IP>\""),
    },
    .{
        .name = "auth-failed",
        .match = parser.compile("<*>Authentication failed for <*>from <IP>"),
    },
};

pub const proftpd_patterns = [_]PatternDef{
    .{
        .name = "no-such-user",
        .match = parser.compile("<*>no such user <*>from <IP>"),
    },
    .{
        .name = "login-failed",
        .match = parser.compile("<*>USER <*>Login failed<*>from <IP>"),
    },
    .{
        .name = "security-violation",
        .match = parser.compile("<*>SECURITY VIOLATION<*>from <IP>"),
    },
};

pub const mysqld_auth_patterns = [_]PatternDef{
    .{
        .name = "access-denied",
        .match = parser.compile("<*>Access denied for user <*>from '<IP>"),
    },
    .{
        .name = "access-denied-at",
        .match = parser.compile("<*>Access denied for user <*>@'<IP>"),
    },
};
