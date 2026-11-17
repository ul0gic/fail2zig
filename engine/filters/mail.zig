// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Lists the built-in patterns for Postfix, Dovecot and Courier mail server failures.
// Holds: In every pattern the address must start right after a fixed literal such as `[`, `rip=` or `relay=`; it is never searched for.

const types = @import("types.zig");
const parser = @import("../detect/parser.zig");

pub const PatternDef = types.PatternDef;

pub const postfix_patterns = [_]PatternDef{
    .{
        .name = "rcpt-reject",
        .match = parser.compile("<*>NOQUEUE: reject: RCPT from <*>[<IP>]"),
    },
    .{
        .name = "sasl-auth-failed",
        .match = parser.compile("<*>warning: <*>[<IP>]: SASL <*>authentication failed"),
    },
    .{
        .name = "lost-connection-auth",
        .match = parser.compile("<*>lost connection after AUTH from <*>[<IP>]"),
    },
};

pub const dovecot_patterns = [_]PatternDef{
    .{
        .name = "imap-auth-failed",
        .match = parser.compile("<*>imap-login: <*>auth failed<*>rip=<IP>"),
    },
    .{
        .name = "pop3-auth-failed",
        .match = parser.compile("<*>pop3-login: <*>auth failed<*>rip=<IP>"),
    },
    .{
        .name = "pam-auth-failed",
        .match = parser.compile("<*>auth-worker<*>pam(<*>,<IP>)<*>pam_authenticate()"),
    },
};

pub const courier_patterns = [_]PatternDef{
    .{
        .name = "login-failed",
        .match = parser.compile("<*>LOGIN FAILED<*>ip=[<IP>"),
    },
    .{
        .name = "auth-failed",
        .match = parser.compile("<*>imaplogin: FAILED<*>ip=[<IP>"),
    },
    .{
        .name = "smtp-auth-failed",
        .match = parser.compile("<*>error,relay=<IP>,<*>msg=\"535 Authentication failed.\""),
    },
};
