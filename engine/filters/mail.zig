// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Built-in mail-server filters.
//!
//! Three filter sets:
//!   * `postfix`  — SMTP abuse: reject RCPT, SASL auth failure, AUTH disconnect
//!   * `dovecot`  — IMAP/POP3 auth failures
//!   * `courier`  — Courier-IMAP login failures
//!
//! Postfix log shape (syslog):
//!   `Apr 21 12:00:00 host postfix/smtpd[PID]: NOQUEUE: reject: RCPT from host[<IP>]: ...`
//!
//! Dovecot log shape:
//!   `Apr 21 12:00:00 host dovecot: imap-login: Disconnected: ... rip=<IP>, lip=..., session=...`

const std = @import("std");
const types = @import("types.zig");
const parser = @import("../core/parser.zig");

pub const PatternDef = types.PatternDef;

/// `postfix` — SMTP-level abuse.
pub const postfix_patterns = [_]PatternDef{
    // RCPT reject: `NOQUEUE: reject: RCPT from host[1.2.3.4]: ...`
    .{
        .name = "rcpt-reject",
        .match = parser.compile("<*>NOQUEUE: reject: RCPT from <*>[<IP>]"),
    },
    // SASL auth failure: `warning: host[1.2.3.4]: SASL LOGIN authentication failed`
    .{
        .name = "sasl-auth-failed",
        .match = parser.compile("<*>warning: <*>[<IP>]: SASL <*>authentication failed"),
    },
    // Lost connection after AUTH: `lost connection after AUTH from host[1.2.3.4]`
    .{
        .name = "lost-connection-auth",
        .match = parser.compile("<*>lost connection after AUTH from <*>[<IP>]"),
    },
    // Disconnect after EHLO/HELO — DDoS-style hammer.
    .{
        .name = "disconnect-helo",
        .match = parser.compile("<*>disconnect from <*>[<IP>]<*>ehlo=<*>commands="),
    },
};

/// `dovecot` — IMAP/POP3 login failures.
pub const dovecot_patterns = [_]PatternDef{
    // imap-login: Disconnected (auth failed, 1 attempts): rip=1.2.3.4, lip=...
    .{
        .name = "imap-auth-failed",
        .match = parser.compile("<*>imap-login: <*>auth failed<*>rip=<IP>"),
    },
    // pop3-login equivalent.
    .{
        .name = "pop3-auth-failed",
        .match = parser.compile("<*>pop3-login: <*>auth failed<*>rip=<IP>"),
    },
    // auth-worker: pam(..., 1.2.3.4): pam_authenticate() failed
    .{
        .name = "pam-auth-failed",
        .match = parser.compile("<*>auth-worker<*>pam(<*>,<IP>)<*>pam_authenticate()"),
    },
    // "no auth attempts in N secs" — aborted connection after slow-probe.
    .{
        .name = "no-auth-attempts",
        .match = parser.compile("<*>imap-login: <*>no auth attempts<*>rip=<IP>"),
    },
};

/// `courier` — Courier IMAP login failures.
pub const courier_patterns = [_]PatternDef{
    // `LOGIN FAILED, user=x, ip=[::ffff:1.2.3.4]`
    .{
        .name = "login-failed",
        .match = parser.compile("<*>LOGIN FAILED<*>ip=[<IP>"),
    },
    // `FAILED, ip=[...]` — older format without LOGIN keyword.
    .{
        .name = "auth-failed",
        .match = parser.compile("<*>imaplogin: FAILED<*>ip=[<IP>"),
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

test "postfix: RCPT reject" {
    try testing.expect(firstMatchIn(&postfix_patterns, "Apr 21 12:00:00 mail postfix/smtpd[1234]: NOQUEUE: reject: RCPT from unknown[1.2.3.4]: 554 5.7.1 Relay access denied") != null);
    try testing.expect(firstMatchIn(&postfix_patterns, "Apr 21 12:00:01 mail postfix/smtpd[1234]: NOQUEUE: reject: RCPT from host.example.com[203.0.113.50]: 450 4.1.2 Domain not found") != null);
    try testing.expect(firstMatchIn(&postfix_patterns, "Apr 21 12:00:02 mail postfix/smtpd[1234]: NOQUEUE: reject: RCPT from mx.evil.com[10.0.0.1]: 554 Service unavailable") != null);
}

test "postfix: SASL auth failure" {
    try testing.expect(firstMatchIn(&postfix_patterns, "Apr 21 12:00:00 mail postfix/smtpd[1234]: warning: unknown[1.2.3.4]: SASL LOGIN authentication failed: authentication failure") != null);
    try testing.expect(firstMatchIn(&postfix_patterns, "Apr 21 12:00:00 mail postfix/smtpd[1234]: warning: host[9.9.9.9]: SASL PLAIN authentication failed: encryption needed") != null);
    try testing.expect(firstMatchIn(&postfix_patterns, "Apr 21 12:00:00 mail postfix/submission/smtpd[5678]: warning: evil[8.8.8.8]: SASL CRAM-MD5 authentication failed") != null);
}

test "postfix: lost connection after AUTH" {
    try testing.expect(firstMatchIn(&postfix_patterns, "Apr 21 12:00:00 mail postfix/smtpd[1234]: lost connection after AUTH from unknown[1.2.3.4]") != null);
    try testing.expect(firstMatchIn(&postfix_patterns, "Apr 21 12:00:01 mail postfix/smtpd[1234]: lost connection after AUTH from mx.spam[10.1.2.3]") != null);
    try testing.expect(firstMatchIn(&postfix_patterns, "Apr 21 12:00:02 mail postfix/smtpd[1234]: lost connection after AUTH from evil[203.0.113.55]") != null);
}

test "postfix: negative — successful delivery" {
    try testing.expect(firstMatchIn(&postfix_patterns, "Apr 21 12:00:00 mail postfix/smtp[1234]: A1B2C3: to=<user@example.com>, relay=mx.example.com[1.2.3.4]:25, delay=0.5, status=sent (250 OK)") == null);
}

test "postfix: negative — queue manager activity" {
    try testing.expect(firstMatchIn(&postfix_patterns, "Apr 21 12:00:00 mail postfix/qmgr[1234]: removed") == null);
}

test "dovecot: imap auth failed" {
    try testing.expect(firstMatchIn(&dovecot_patterns, "Apr 21 12:00:00 mail dovecot: imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<admin>, method=PLAIN, rip=1.2.3.4, lip=10.0.0.1") != null);
    try testing.expect(firstMatchIn(&dovecot_patterns, "Apr 21 12:00:00 mail dovecot: imap-login: Disconnected (auth failed, 3 attempts): user=<root>, rip=203.0.113.1, lip=10.0.0.1") != null);
    try testing.expect(firstMatchIn(&dovecot_patterns, "dovecot: imap-login: Aborted login (auth failed, 5 attempts): user=<foo>, rip=8.8.8.8, lip=..., session=ABCD") != null);
}

test "dovecot: pop3 auth failed" {
    try testing.expect(firstMatchIn(&dovecot_patterns, "dovecot: pop3-login: Disconnected (auth failed, 1 attempts): rip=1.2.3.4") != null);
}

test "dovecot: pam auth failure" {
    try testing.expect(firstMatchIn(&dovecot_patterns, "dovecot: auth-worker(1234): pam(admin,1.2.3.4): pam_authenticate() failed: Authentication failure") != null);
    try testing.expect(firstMatchIn(&dovecot_patterns, "dovecot: auth-worker(1): pam(root,203.0.113.1): pam_authenticate() failed: User unknown") != null);
}

test "dovecot: negative — successful login" {
    try testing.expect(firstMatchIn(&dovecot_patterns, "dovecot: imap-login: Login: user=<admin>, method=PLAIN, rip=1.2.3.4, lip=10.0.0.1, mpid=1234, session=XYZ") == null);
}

test "dovecot: negative — unrelated info" {
    try testing.expect(firstMatchIn(&dovecot_patterns, "dovecot: master: Dovecot v2.3.18 starting up") == null);
}

test "courier: login failed" {
    try testing.expect(firstMatchIn(&courier_patterns, "Apr 21 12:00:00 mail imapd: LOGIN FAILED, user=admin, ip=[::ffff:1.2.3.4]") != null);
    try testing.expect(firstMatchIn(&courier_patterns, "Apr 21 12:00:01 mail imapd-ssl: LOGIN FAILED, user=root, ip=[::ffff:203.0.113.1]") != null);
    try testing.expect(firstMatchIn(&courier_patterns, "Apr 21 12:00:02 mail pop3d: LOGIN FAILED, user=foo, ip=[::ffff:8.8.8.8]") != null);
}

test "courier: negative — successful LOGIN" {
    try testing.expect(firstMatchIn(&courier_patterns, "Apr 21 12:00:00 mail imapd: LOGIN, user=admin, ip=[::ffff:1.2.3.4]") == null);
}

test "courier: negative — service startup" {
    try testing.expect(firstMatchIn(&courier_patterns, "Apr 21 12:00:00 mail imapd: Connection, ip=[::ffff:1.2.3.4]") == null);
}
