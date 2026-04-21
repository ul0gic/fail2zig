// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Remaining built-in filters:
//!   * `named_refused` — BIND DNS queries denied.
//!   * `recidive`      — fail2zig's own ban log (meta-jail for repeat offenders).
//!   * `vsftpd`        — vsftpd FTP login failures.
//!   * `proftpd`       — ProFTPD login failures.
//!   * `mysqld_auth`   — MySQL / MariaDB access-denied messages.
//!
//! The `recidive` filter is fail2zig-specific. It matches the daemon's
//! own ban log line format — see the `std.log.info("ban: jail=...")` in
//! `engine/main.zig`'s `lineCallback`. The canonical form is:
//!
//!   `info: ban: jail='sshd' ip=1.2.3.4 duration=3600s ban_count=1`
//!
//! An operator enables recidive by pointing its jail at the fail2zig
//! log file and configuring a higher bantime so IPs that repeatedly
//! get banned graduate to a longer blockade.

const std = @import("std");
const types = @import("types.zig");
const parser = @import("../core/parser.zig");

pub const PatternDef = types.PatternDef;

/// `named-refused` — BIND DNS query denied.
pub const named_refused_patterns = [_]PatternDef{
    // `client @0x... 1.2.3.4#53 (example.com): query (cache) 'example.com/A/IN' denied`
    .{
        .name = "query-denied",
        .match = parser.compile("<*>client <*><IP>#<*>denied"),
    },
    // `client 1.2.3.4#53: REFUSED` — newer BIND syntax.
    .{
        .name = "query-refused",
        .match = parser.compile("<*>client <IP>#<*>REFUSED"),
    },
};

/// `recidive` — matches fail2zig's own "ban:" log line. Used by a
/// meta-jail to escalate bans for repeat offenders.
pub const recidive_patterns = [_]PatternDef{
    .{
        .name = "fail2zig-ban",
        // Anchor on " ban: " (with a leading space) so that "unban: ..." lines
        // — which also contain the substring "ban:" — do NOT match. The leading
        // `<*>` absorbs the timestamp / log-level prefix.
        .match = parser.compile("<*> ban: jail='<*>' ip=<IP>"),
    },
};

/// `vsftpd` — FTP login failures.
pub const vsftpd_patterns = [_]PatternDef{
    // `[pid 1234] [user] FAIL LOGIN: Client "1.2.3.4"`
    .{
        .name = "fail-login",
        .match = parser.compile("<*>FAIL LOGIN: Client \"<IP>\""),
    },
    // Older: `Authentication failed for user x from 1.2.3.4`
    .{
        .name = "auth-failed",
        .match = parser.compile("<*>Authentication failed for <*>from <IP>"),
    },
};

/// `proftpd` — ProFTPD login failures.
pub const proftpd_patterns = [_]PatternDef{
    // `mod_auth.c(..): no such user 'admin' from 1.2.3.4`
    .{
        .name = "no-such-user",
        .match = parser.compile("<*>no such user <*>from <IP>"),
    },
    // `mod_auth.c(..): USER admin (Login failed): Incorrect password from 1.2.3.4`
    .{
        .name = "login-failed",
        .match = parser.compile("<*>USER <*>Login failed<*>from <IP>"),
    },
    // Older message: `SECURITY VIOLATION: .* from 1.2.3.4`
    .{
        .name = "security-violation",
        .match = parser.compile("<*>SECURITY VIOLATION<*>from <IP>"),
    },
};

/// `mysqld-auth` — MySQL / MariaDB access denied.
pub const mysqld_auth_patterns = [_]PatternDef{
    // `[Warning] Access denied for user 'root'@'1.2.3.4' (using password: YES)`
    .{
        .name = "access-denied",
        .match = parser.compile("<*>Access denied for user <*>from '<IP>"),
    },
    // MySQL 8 format: `Access denied for user 'x'@'1.2.3.4'`
    .{
        .name = "access-denied-at",
        .match = parser.compile("<*>Access denied for user <*>@'<IP>"),
    },
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

fn firstMatchIn(patterns: []const PatternDef, line: []const u8) ?usize {
    for (patterns, 0..) |p, i| {
        if (p.match(line)) |_| return i;
    }
    return null;
}

// ---------- named-refused ----------

test "named-refused: query denied" {
    try testing.expect(firstMatchIn(&named_refused_patterns, "21-Apr-2026 12:00:00.000 client @0x7f00 1.2.3.4#53 (example.com): query (cache) 'example.com/A/IN' denied") != null);
    try testing.expect(firstMatchIn(&named_refused_patterns, "21-Apr-2026 12:00:01 client @0x7f00 203.0.113.1#53 (foo.org): query 'foo.org/AAAA/IN' denied") != null);
    try testing.expect(firstMatchIn(&named_refused_patterns, "client @0x7f00 8.8.8.8#54321 (evil.com): query (cache) 'evil.com/A/IN' denied") != null);
}

test "named-refused: REFUSED" {
    try testing.expect(firstMatchIn(&named_refused_patterns, "21-Apr-2026 12:00:00 client 1.2.3.4#53: REFUSED") != null);
    try testing.expect(firstMatchIn(&named_refused_patterns, "client 203.0.113.1#12345: REFUSED") != null);
}

test "named-refused: negative — successful query" {
    try testing.expect(firstMatchIn(&named_refused_patterns, "client 1.2.3.4#53: query (cache) 'example.com/A/IN' approved") == null);
}

test "named-refused: negative — zone transfer" {
    try testing.expect(firstMatchIn(&named_refused_patterns, "zone transfer completed for example.com") == null);
}

// ---------- recidive (fail2zig own log) ----------

test "recidive: matches fail2zig ban line" {
    // fail2zig's `lineCallback` in engine/main.zig calls
    //   std.log.info("ban: jail='{s}' ip={} duration={d}s ban_count={d}", ...)
    // which Zig's default handler renders as:
    //   info: ban: jail='sshd' ip=1.2.3.4 duration=3600s ban_count=1
    // We match on the `" ban: "` substring (with leading space) to avoid
    // the `unban:` line that also contains `ban:`.
    try testing.expect(firstMatchIn(&recidive_patterns, "info: ban: jail='sshd' ip=1.2.3.4 duration=3600s ban_count=1") != null);
    try testing.expect(firstMatchIn(&recidive_patterns, "2026-04-21T12:00:00Z info: ban: jail='nginx' ip=203.0.113.50 duration=7200s ban_count=2") != null);
    try testing.expect(firstMatchIn(&recidive_patterns, "[info] ban: jail='postfix' ip=8.8.8.8 duration=600s ban_count=5") != null);
}

test "recidive: negative — unban line" {
    try testing.expect(firstMatchIn(&recidive_patterns, "unban: jail='sshd' ip=1.2.3.4") == null);
}

test "recidive: negative — daemon startup line" {
    try testing.expect(firstMatchIn(&recidive_patterns, "fail2zig 0.1.0 running; backend=nftables") == null);
}

// ---------- vsftpd ----------

test "vsftpd: FAIL LOGIN" {
    try testing.expect(firstMatchIn(&vsftpd_patterns, "Apr 21 12:00:00 ftp vsftpd[1234]: [admin] FAIL LOGIN: Client \"1.2.3.4\"") != null);
    try testing.expect(firstMatchIn(&vsftpd_patterns, "Apr 21 12:00:01 ftp vsftpd[1234]: [root] FAIL LOGIN: Client \"203.0.113.1\"") != null);
    try testing.expect(firstMatchIn(&vsftpd_patterns, "vsftpd[5678]: [foo] FAIL LOGIN: Client \"10.0.0.1\"") != null);
}

test "vsftpd: authentication failed" {
    try testing.expect(firstMatchIn(&vsftpd_patterns, "Apr 21 12:00:00 ftp vsftpd[1234]: Authentication failed for user admin from 1.2.3.4") != null);
}

test "vsftpd: negative — OK LOGIN" {
    try testing.expect(firstMatchIn(&vsftpd_patterns, "Apr 21 12:00:00 ftp vsftpd[1234]: [admin] OK LOGIN: Client \"1.2.3.4\"") == null);
}

test "vsftpd: negative — startup" {
    try testing.expect(firstMatchIn(&vsftpd_patterns, "vsftpd: Starting up") == null);
}

// ---------- proftpd ----------

test "proftpd: no such user" {
    try testing.expect(firstMatchIn(&proftpd_patterns, "Apr 21 12:00:00 ftp proftpd[1234]: mod_auth.c(987): no such user 'admin' from 1.2.3.4") != null);
    try testing.expect(firstMatchIn(&proftpd_patterns, "proftpd[1234]: no such user 'foo' from 203.0.113.1") != null);
    try testing.expect(firstMatchIn(&proftpd_patterns, "proftpd[1234]: no such user 'bar' from 10.0.0.5") != null);
}

test "proftpd: login failed" {
    try testing.expect(firstMatchIn(&proftpd_patterns, "Apr 21 12:00:00 ftp proftpd[1234]: USER admin (Login failed): Incorrect password from 1.2.3.4") != null);
    try testing.expect(firstMatchIn(&proftpd_patterns, "proftpd[5678]: USER root (Login failed): Password incorrect from 8.8.8.8") != null);
}

test "proftpd: security violation" {
    try testing.expect(firstMatchIn(&proftpd_patterns, "Apr 21 12:00:00 ftp proftpd[1234]: SECURITY VIOLATION: root login attempted from 1.2.3.4") != null);
}

test "proftpd: negative — successful USER" {
    try testing.expect(firstMatchIn(&proftpd_patterns, "proftpd[1234]: USER admin: Login successful from 1.2.3.4") == null);
}

test "proftpd: negative — service msg" {
    try testing.expect(firstMatchIn(&proftpd_patterns, "proftpd[1234]: ProFTPD 1.3.7 standalone mode STARTUP") == null);
}

// ---------- mysqld-auth ----------

test "mysqld-auth: access denied from" {
    try testing.expect(firstMatchIn(&mysqld_auth_patterns, "2026-04-21 12:00:00 10 [Warning] Access denied for user 'root' from '1.2.3.4' (using password: YES)") != null);
    try testing.expect(firstMatchIn(&mysqld_auth_patterns, "2026-04-21 12:00:01 [Warning] Access denied for user 'admin' from '203.0.113.1' (using password: YES)") != null);
    try testing.expect(firstMatchIn(&mysqld_auth_patterns, "mysqld: Access denied for user 'foo' from '8.8.8.8'") != null);
}

test "mysqld-auth: access denied @" {
    try testing.expect(firstMatchIn(&mysqld_auth_patterns, "Access denied for user 'root'@'1.2.3.4' (using password: YES)") != null);
    try testing.expect(firstMatchIn(&mysqld_auth_patterns, "2026-04-21 12:00:00 [Warning] Access denied for user 'admin'@'203.0.113.1'") != null);
}

test "mysqld-auth: negative — user OK" {
    try testing.expect(firstMatchIn(&mysqld_auth_patterns, "2026-04-21 12:00:00 [Note] Access granted for user 'root'@'1.2.3.4'") == null);
}

test "mysqld-auth: negative — service info" {
    try testing.expect(firstMatchIn(&mysqld_auth_patterns, "2026-04-21 12:00:00 [Note] mysqld: ready for connections") == null);
}
