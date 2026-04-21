---
title: Built-in filters
description: Reference for all 15 built-in fail2zig filters — what each one matches, which log file to point at, example matching log lines, and recommended jail settings.
sidebar_position: 2
category: Reference
audience: operator
last_verified: 2026-04-21
---

fail2zig ships 15 built-in filters compiled into the binary at build time.
There is no runtime regex engine — each filter is a set of specialized match
functions generated from a pattern DSL at compile time. This means the filters
cannot be modified at runtime, but they also cannot be made to allocate
unbounded memory or execute in unbounded time on attacker-controlled input.

Filter names accept both hyphenated and underscore forms interchangeably.
`"nginx-http-auth"` and `"nginx_http_auth"` are identical in a `filter =`
directive and in the registry.

---

## SSH

### `sshd`

**What it matches:** OpenSSH authentication failures across the full 7.x / 8.x /
9.x line. Covers password failures, invalid user attempts, PAM failures, protocol
version mismatches, and the maximum-auth-attempts message added in OpenSSH 8.

**Log file:**

| Distribution | Path |
|---|---|
| Debian, Ubuntu | `/var/log/auth.log` |
| RHEL, Fedora, CentOS, Rocky | `/var/log/secure` |
| systemd journal | Available via `journald` backend (Phase 2) |

**Example matching lines** (taken from filter test suite):

```text
Failed password for root from 192.168.1.100 port 43210 ssh2
Failed password for invalid user admin from 10.0.0.1 port 22 ssh2
Invalid user testuser from 203.0.113.50 port 54321
Connection closed by authenticating user root 45.227.253.98 port 11111 [preauth]
Disconnected from authenticating user root 45.227.253.98 port 11111 [preauth]
error: PAM: Authentication failure for root from 1.2.3.4
Received disconnect from 192.0.2.10 port 22:11: ...
Bad protocol version identification 'GET / HTTP/1.0' from 1.2.3.4 port 55678
maximum authentication attempts exceeded for root from 198.51.100.1 port 22 ssh2
```

**Recommended jail settings:**

```toml
[jails.sshd]
enabled  = true
filter   = "sshd"
logpath  = ["/var/log/auth.log", "/var/log/secure"]
maxretry = 3      # SSH is high-value; tighten the threshold
bantime  = 3600   # 1 hour first offense; pair with bantime_increment
```

When to tune: Lower `maxretry` to 2 on servers that see constant brute-force
volume. Enable bantime increment (see `[defaults]`) — SSH attackers typically
probe the same IP multiple times over days.

---

## Web

### `nginx-http-auth`

**What it matches:** nginx basic authentication failures from the nginx error log.
Covers: no credentials provided, user not found in htpasswd file, and password
mismatch.

**Log file:** `/var/log/nginx/error.log`

**Example matching lines:**

```text
2026/04/21 12:00:00 [error] 1234#0: *1 no user/password was provided for basic authentication, client: 1.2.3.4, server: example.com
[error] 1#0: *2 user "admin": was not found in "/etc/nginx/.htpasswd", client: 203.0.113.50, server: _
[error] user "foo": password mismatch, client: 9.9.9.9, server: app
```

**Recommended jail settings:**

```toml
[jails.nginx-http-auth]
enabled  = true
filter   = "nginx-http-auth"
logpath  = ["/var/log/nginx/error.log"]
maxretry = 5
bantime  = 600
```

---

### `nginx-limit-req`

**What it matches:** nginx request-rate-limit violations from `limit_req_zone`
and connection-rate violations from `limit_conn_zone`. Useful for banning clients
that repeatedly trigger rate limits, indicating automated abuse rather than
accidental misconfiguration.

**Log file:** `/var/log/nginx/error.log`

**Example matching lines:**

```text
[error] 1#0: *1 limiting requests, excess: 0.500 by zone "one", client: 1.2.3.4, server: _
[error] limiting requests, excess: 10 by zone "req_zone", client: 203.0.113.1
[error] 1#0: *1 limiting connections by zone "addr", client: 5.6.7.8
```

**Recommended jail settings:**

```toml
[jails.nginx-limit-req]
enabled  = true
filter   = "nginx-limit-req"
logpath  = ["/var/log/nginx/error.log"]
maxretry = 10     # rate-limit bursts are common; tune to your traffic baseline
findtime = 60
bantime  = 300
```

When to tune: If legitimate users behind NAT trigger rate limits,
increase `maxretry` or add their shared egress IP to `ignoreip`. Reduce
`findtime` to 60 seconds if you want to catch rapid bursts rather than
sustained traffic.

---

### `nginx-botsearch`

**What it matches:** Bots probing well-known attack paths in the nginx access
log. Covers: WordPress `wp-login.php`, `xmlrpc.php`, phpMyAdmin, `.env` files,
and `.git` directories.

**Log file:** `/var/log/nginx/access.log`

**Example matching lines:**

```text
1.2.3.4 - - [21/Apr/2026:12:00:00 +0000] "GET /wp-login.php HTTP/1.1" 404 162
203.0.113.50 - - [21/Apr/2026:12:00:00 +0000] "POST /wordpress/wp-login.php HTTP/1.1" 404 500
1.2.3.4 - - [21/Apr/2026] "POST /xmlrpc.php HTTP/1.1" 404 162
9.9.9.9 - - [21/Apr/2026] "GET /phpmyadmin/ HTTP/1.1" 404 0
5.6.7.8 - - [21/Apr/2026] "GET /.env HTTP/1.1" 404 0
1.2.3.4 - - [21/Apr/2026] "GET /.git/config HTTP/1.1" 404 0
```

**Recommended jail settings:**

```toml
[jails.nginx-botsearch]
enabled  = true
filter   = "nginx-botsearch"
logpath  = ["/var/log/nginx/access.log"]
maxretry = 2      # even one probe is suspicious; two is a pattern
findtime = 3600   # wide window — bots may space probes out
bantime  = 86400  # 1 day for confirmed scanner
```

---

### `apache-auth`

**What it matches:** Apache httpd basic authentication failures from the Apache
error log. Covers: authentication failure, user not found, and password mismatch
messages from `mod_auth_basic` and related modules.

**Log file:** `/var/log/apache2/error.log` (Debian/Ubuntu); `/var/log/httpd/error_log` (RHEL)

**Example matching lines:**

```text
[Tue Apr 21 12:00:00.000 2026] [auth_basic:error] [pid 1:tid 2] [client 1.2.3.4:12345] user admin: authentication failure
[error] [client 203.0.113.50:80] user foo: authentication failure for "/admin"
[error] [client 1.2.3.4:22] user doesntexist not found: /admin
[error] [client 1.2.3.4:22] AH01617: user admin: password mismatch: /secret
```

**Recommended jail settings:**

```toml
[jails.apache-auth]
enabled  = true
filter   = "apache-auth"
logpath  = [
    "/var/log/apache2/error.log",
    "/var/log/httpd/error_log",
]
maxretry = 5
bantime  = 600
```

---

### `apache-badbots`

**What it matches:** Well-known abusive user-agents in the Apache access log
(AhrefsBot, SemrushBot, MJ12bot, DotBot) and access-log 404s for WordPress
`wp-login.php` and `xmlrpc.php`.

**Log file:** `/var/log/apache2/access.log` (Debian/Ubuntu); `/var/log/httpd/access_log` (RHEL)

**Example matching lines:**

```text
1.2.3.4 - - [21/Apr/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 1024 "-" "Mozilla/5.0 (compatible; AhrefsBot/7.0)"
5.6.7.8 - - [21/Apr/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 512 "-" "SemrushBot/7~bl"
1.2.3.4 - - [21/Apr/2026] "GET /wp-login.php HTTP/1.1" 404 162 "-" "curl/7.0"
```

**Recommended jail settings:**

```toml
[jails.apache-badbots]
enabled  = true
filter   = "apache-badbots"
logpath  = [
    "/var/log/apache2/access.log",
    "/var/log/httpd/access_log",
]
maxretry = 2
bantime  = 86400
```

---

### `apache-overflows`

**What it matches:** Malformed or oversized HTTP requests from the Apache error
log. Covers: invalid URI, URI too long (414), and error reading headers — patterns
associated with buffer overflow probes and scanner tooling.

**Log file:** `/var/log/apache2/error.log` (Debian/Ubuntu); `/var/log/httpd/error_log` (RHEL)

**Example matching lines:**

```text
[error] [client 1.2.3.4:22] Invalid URI in request GET /<garbage> HTTP/1.0
[error] [client 203.0.113.1:80] request failed: URI too long (longer than 8190)
[error] [client 10.0.0.5:55678] request failed: error reading the headers
```

**Recommended jail settings:**

```toml
[jails.apache-overflows]
enabled  = true
filter   = "apache-overflows"
logpath  = [
    "/var/log/apache2/error.log",
    "/var/log/httpd/error_log",
]
maxretry = 2
bantime  = 3600
```

---

## Mail

### `postfix`

**What it matches:** Postfix SMTP-level abuse. Covers: RCPT address rejection
(`NOQUEUE: reject`), SASL authentication failures, and lost-connection-after-AUTH
patterns indicating credential stuffing.

**Log file:** `/var/log/mail.log` (Debian/Ubuntu); `/var/log/maillog` (RHEL)

**Example matching lines:**

```text
Apr 21 12:00:00 mail postfix/smtpd[1234]: NOQUEUE: reject: RCPT from unknown[1.2.3.4]: 554 5.7.1 Relay access denied
Apr 21 12:00:01 mail postfix/smtpd[1234]: NOQUEUE: reject: RCPT from host.example.com[203.0.113.50]: 450 4.1.2 Domain not found
Apr 21 12:00:00 mail postfix/smtpd[1234]: warning: unknown[1.2.3.4]: SASL LOGIN authentication failed: authentication failure
Apr 21 12:00:00 mail postfix/smtpd[1234]: lost connection after AUTH from mail.example.com[10.0.0.1]
```

**Recommended jail settings:**

```toml
[jails.postfix]
enabled  = true
filter   = "postfix"
logpath  = [
    "/var/log/mail.log",
    "/var/log/maillog",
]
maxretry = 5
findtime = 600
bantime  = 1800
```

When to tune: Mail servers legitimately see high reject rates from misconfigured
senders. Consider raising `maxretry` to 10 if you're seeing legitimate MTA IPs
getting banned. Add well-known transactional mail provider IP ranges to
`ignoreip` if needed.

---

### `dovecot`

**What it matches:** Dovecot IMAP and POP3 authentication failures. Covers:
`imap-login: Disconnected (auth failed)`, `pop3-login: Disconnected (auth failed)`,
PAM authentication failures, and connections dropped without any auth attempt
(slow-probe reconnaissance).

**Log file:** `/var/log/mail.log` (Dovecot typically writes to the same log as Postfix)

**Example matching lines:**

```text
Apr 21 12:00:00 mail dovecot: imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<foo>, method=PLAIN, rip=1.2.3.4, lip=10.0.0.1
Apr 21 12:00:00 mail dovecot: pop3-login: Disconnected (auth failed, 1 attempts): user=<bar>, rip=203.0.113.50
Apr 21 12:00:00 mail dovecot: auth-worker(1234): pam(username,1.2.3.4): pam_authenticate() failed
Apr 21 12:00:00 mail dovecot: imap-login: Disconnected (no auth attempts in 0 secs): rip=5.6.7.8
```

**Recommended jail settings:**

```toml
[jails.dovecot]
enabled  = true
filter   = "dovecot"
logpath  = ["/var/log/mail.log"]
maxretry = 5
bantime  = 1800
```

---

### `courier`

**What it matches:** Courier-IMAP authentication failures. Two patterns: the
`LOGIN FAILED` form used by current Courier builds and the older `imaplogin: FAILED`
form from legacy versions.

**Log file:** Courier writes to syslog; path depends on your syslog configuration.
Common paths: `/var/log/mail.log`, `/var/log/courier/errors`.

**Example matching lines:**

```text
Apr 21 12:00:00 mail authdaemond: LOGIN FAILED, user=foo, ip=[::ffff:1.2.3.4]
Apr 21 12:00:00 mail authdaemond: imaplogin: FAILED, ip=[::ffff:203.0.113.50]
```

**Recommended jail settings:**

```toml
[jails.courier]
enabled  = true
filter   = "courier"
logpath  = ["/var/log/mail.log"]
maxretry = 5
bantime  = 1800
```

Note: Courier wraps IPv4 addresses in IPv6 notation (`::ffff:1.2.3.4`). fail2zig
canonicalizes these to their IPv4 form at the parse boundary, so they will be
tracked and banned as IPv4 addresses and will match IPv4 CIDR entries in `ignoreip`.

---

## DNS

### `named-refused`

**What it matches:** BIND (named) queries that were denied or refused. Two
patterns cover the modern `denied` log message and the legacy `REFUSED` message
from older BIND versions.

**Log file:** `/var/log/named/default` or `/var/log/syslog` depending on BIND configuration.

**Example matching lines:**

```text
21-Apr-2026 12:00:00.000 client @0xabc 1.2.3.4#53 (example.com): query (cache) 'example.com/A/IN' denied
21-Apr-2026 12:00:00.000 client 203.0.113.50#53: REFUSED
```

**Recommended jail settings:**

```toml
[jails.named-refused]
enabled  = true
filter   = "named-refused"
logpath  = ["/var/log/named/default", "/var/log/syslog"]
maxretry = 10     # DNS resolvers have high query rates; tune carefully
findtime = 60
bantime  = 600
```

When to tune: Misconfigured resolvers and CDN nodes may legitimately query your
DNS server. Consider monitoring ban events before committing to low thresholds.

---

## FTP

### `vsftpd`

**What it matches:** vsftpd login failures. Two patterns: the current
`FAIL LOGIN: Client "<IP>"` format and the older
`Authentication failed for user x from <IP>` format.

**Log file:** `/var/log/vsftpd.log`

**Example matching lines:**

```text
[pid 1234] [user] FAIL LOGIN: Client "1.2.3.4"
[pid 5678] Authentication failed for nobody from 203.0.113.50
```

**Recommended jail settings:**

```toml
[jails.vsftpd]
enabled  = true
filter   = "vsftpd"
logpath  = ["/var/log/vsftpd.log"]
maxretry = 5
bantime  = 3600
```

---

### `proftpd`

**What it matches:** ProFTPD login failures. Three patterns: `no such user`,
`Login failed: Incorrect password`, and the `SECURITY VIOLATION` message from
ProFTPD's tilde-path protection.

**Log file:** `/var/log/proftpd/proftpd.log` or `/var/log/auth.log` depending on
ProFTPD's `SystemLog` directive.

**Example matching lines:**

```text
mod_auth.c(..): no such user 'admin' from 1.2.3.4
mod_auth.c(..): USER admin (Login failed): Incorrect password from 203.0.113.50
SECURITY VIOLATION: root login attempted from 10.0.0.5
```

**Recommended jail settings:**

```toml
[jails.proftpd]
enabled  = true
filter   = "proftpd"
logpath  = ["/var/log/proftpd/proftpd.log"]
maxretry = 5
bantime  = 3600
```

---

## Database

### `mysqld-auth`

**What it matches:** MySQL and MariaDB access-denied messages. Two patterns cover
the MySQL 5.x format (`Access denied for user 'x'@'1.2.3.4'`) and the alternative
form where the IP appears after `from '`.

**Log file:** `/var/log/mysql/error.log` (Debian/Ubuntu);
`/var/log/mysqld.log` (RHEL); MariaDB: `/var/log/mariadb/mariadb.log`

**Example matching lines:**

```text
[Warning] Access denied for user 'root'@'1.2.3.4' (using password: YES)
2026-04-21T12:00:00.000000Z 0 [Warning] Access denied for user 'admin'@'203.0.113.50'
```

**Recommended jail settings:**

```toml
[jails.mysqld-auth]
enabled  = true
filter   = "mysqld-auth"
logpath  = [
    "/var/log/mysql/error.log",
    "/var/log/mysqld.log",
    "/var/log/mariadb/mariadb.log",
]
maxretry = 5
bantime  = 3600
```

When to tune: MySQL access-denied messages are also emitted for
application-level credential errors (misconfigured app connecting with wrong
password). Confirm the IPs being banned are not your own application servers
before setting a tight `maxretry`.

---

## Meta

### `recidive`

**What it matches:** fail2zig's own ban log lines. The recidive jail watches
the fail2zig log file and escalates IPs that accumulate repeated bans — a
"jail-of-jails" pattern.

The matched line format is:

```text
info: ban: jail='sshd' ip=1.2.3.4 duration=3600s ban_count=3
```

**Phase 2 caveat:** For recidive to work, fail2zig must write its ban log to a
file that the recidive jail can watch. In v0.1.0, the daemon writes operational
logs to stderr / journald. If you run the daemon under systemd, you'll need to
redirect its output to a file (e.g., via `StandardOutput=file:/var/log/fail2zig.log`
in the unit file override) and point the recidive jail at that file.

Without this setup, recidive will be configured but will never match — the daemon
will start without error, but no escalation will occur.

**Log file:** Wherever you redirect fail2zig's stderr. Not a default system log path.

**Example matching line:**

```text
info: ban: jail='sshd' ip=45.227.253.98 duration=7200s ban_count=2
```

**Recommended jail settings:**

```toml
[jails.recidive]
enabled  = true
filter   = "recidive"
logpath  = ["/var/log/fail2zig.log"]   # requires systemd unit override
maxretry = 3          # 3 bans in any jail → recidive escalation
findtime = 86400      # within a 24-hour window
bantime  = 604800     # 1 week for persistent repeat offenders
```

---

## Summary table

| Filter | Category | Patterns | Typical log path |
|---|---|---|---|
| `sshd` | SSH | 9 | `/var/log/auth.log`, `/var/log/secure` |
| `nginx-http-auth` | Web | 3 | `/var/log/nginx/error.log` |
| `nginx-limit-req` | Web | 2 | `/var/log/nginx/error.log` |
| `nginx-botsearch` | Web | 5 | `/var/log/nginx/access.log` |
| `apache-auth` | Web | 3 | `/var/log/apache2/error.log` |
| `apache-badbots` | Web | 6 | `/var/log/apache2/access.log` |
| `apache-overflows` | Web | 3 | `/var/log/apache2/error.log` |
| `postfix` | Mail | 4 | `/var/log/mail.log` |
| `dovecot` | Mail | 4 | `/var/log/mail.log` |
| `courier` | Mail | 2 | `/var/log/mail.log` |
| `named-refused` | DNS | 2 | `/var/log/named/default` |
| `vsftpd` | FTP | 2 | `/var/log/vsftpd.log` |
| `proftpd` | FTP | 3 | `/var/log/proftpd/proftpd.log` |
| `mysqld-auth` | Database | 2 | `/var/log/mysql/error.log` |
| `recidive` | Meta | 1 | Configurable (see caveat above) |
