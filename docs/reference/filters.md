---
title: Filters and native rules
description: Built-in service matchers, PortSentry history input and bounded native JSON rules.
sidebar_position: 2
category: Reference
audience: operator
last_verified: 2026-11-15
---

fail2zig ships 16 compiled built-in filter names (15 external-service filters plus
internal `recidive`) and supports bounded custom
JSON rules through `rule_files`. Built-in names accept hyphen/underscore aliases.
A service name does not establish equivalence with a fail2ban filter of the same name.

The examples below are matcher-oriented starting points. Verify your actual log
format and time contract with `fail2zig rule-test`; file jails need an explicit
`timestamp`.

The timestamp contract decides what the filter sees. With `syslog` or `iso8601`
the daemon strips the line's prefix and matches the message body; with `undated`
it matches the whole line. The `sshd` patterns are anchored at the start of the
body, so an `auth.log` line with its syslog prefix does not match under `undated`.
`rule-test --service <name>` defaults to `syslog` for every filter except
`portsentry`, `apache-*` and `nginx-*`, so an example line shown here without a
prefix needs `--timestamp undated`. That default looks the name up exactly:
`--service nginx_http_auth` gets `syslog`, so pass `--timestamp` with an
underscore alias.

Addresses that can never be enforced are never banned: `0.0.0.0/8`,
`127.0.0.0/8`, `::` and `::1`. The file examples use `undated` deliberately, so select a dated contract
when your input provides appropriate event timestamps. Validation does not prove
live source readiness. Keep default loopback ignores in all enforcing examples.

---

## SSH

### `sshd`

**What it matches:** Supported OpenSSH failure-message forms, including password,
invalid-user, PAM, protocol and authentication-limit messages. This is a format
contract, not qualification of every OpenSSH version or distribution.

The banned address is taken only from the connection's own address field. An
address inside a user name or other client-supplied text never selects who is
banned.

**Log file:**

| Distribution                | Path                                                           |
| --------------------------- | -------------------------------------------------------------- |
| Debian, Ubuntu              | `/var/log/auth.log`                                            |
| RHEL, Fedora, CentOS, Rocky | `/var/log/secure`                                              |
| systemd journal             | `source = "journald"`; `auto` picks it when no configured `logpath` exists and `/usr/bin/journalctl` is present |

**Example matching lines** (taken from filter test suite):

```text
Failed password for root from 192.168.1.100 port 43210 ssh2
Failed password for invalid user admin from 10.0.0.1 port 22 ssh2
Invalid user testuser from 203.0.113.50 port 54321
Connection closed by authenticating user root 45.227.253.98 port 11111 [preauth]
Disconnected from authenticating user root 45.227.253.98 port 11111 [preauth]
error: PAM: Authentication failure for root from 1.2.3.4
Received disconnect from 192.0.2.10 port 22:11: Bye Bye [preauth]
Bad protocol version identification 'GET / HTTP/1.0' from 1.2.3.4 port 55678
maximum authentication attempts exceeded for root from 198.51.100.1 port 22 ssh2
```

**Recommended jail settings:**

```toml
[jails.sshd]
enabled  = true
filter   = "sshd"
source = "journald"
journal_executables = ["/usr/sbin/sshd", "/usr/lib/openssh/sshd-session"]
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
source = "file"
timestamp = "undated"
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
source = "file"
timestamp = "undated"
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
and `.git` directories. A request counts only when its status is 404 or 403 and
the path fragment is followed by the end of the path, `/`, `.` or `?`.

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
source = "file"
timestamp = "undated"
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
source = "file"
timestamp = "undated"
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
`wp-login.php` and `xmlrpc.php`. The user-agent is read from the combined log
format, so the common log format without it does not match.

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
source = "file"
timestamp = "undated"
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
source = "file"
timestamp = "undated"
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
source = "file"
timestamp = "undated"
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
and PAM authentication failures. A disconnect without authentication attempts is
not one of the built-in failure patterns.

**Log file:** `/var/log/mail.log` (Dovecot typically writes to the same log as Postfix)

**Example matching lines:**

```text
Apr 21 12:00:00 mail dovecot: imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<foo>, method=PLAIN, rip=1.2.3.4, lip=10.0.0.1
Apr 21 12:00:00 mail dovecot: pop3-login: Disconnected (auth failed, 1 attempts): user=<bar>, rip=203.0.113.50
Apr 21 12:00:00 mail dovecot: auth-worker(1234): pam(username,1.2.3.4): pam_authenticate() failed
```

**Recommended jail settings:**

```toml
[jails.dovecot]
enabled  = true
filter   = "dovecot"
source = "file"
timestamp = "undated"
logpath  = ["/var/log/mail.log"]
maxretry = 5
bantime  = 1800
```

---

### `courier`

**What it matches:** Courier authentication failures, including the
`LOGIN FAILED` form used by current Courier builds, the older `imaplogin: FAILED`
form from legacy versions, and the SMTP `error,relay=<IP>,…msg="535 Authentication
failed."` form.

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
source = "file"
timestamp = "undated"
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
source = "file"
timestamp = "undated"
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
source = "file"
timestamp = "undated"
logpath  = ["/var/log/vsftpd.log"]
maxretry = 5
bantime  = 3600
```

---

### `proftpd`

**What it matches:** ProFTPD login failures. Three patterns: `no such user`,
`USER … Login failed … from <IP>` with any reason text, and the `SECURITY VIOLATION` message from
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
source = "file"
timestamp = "undated"
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
source = "file"
timestamp = "undated"
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

## Scan detection

### `portsentry`

**What it matches:** Supported PortSentry v2.0.7 history records. The whole-record
matcher extracts the typed bracketed source address and preserves original event
time. Ignored, pre-threshold and sensor-blocked records are excluded: a record
matches only when it ends with `ignored: [false] triggered: [true] noblock:
[true] blocked: [false]`.

**Log source:** The PortSentry history file, conventionally `/var/log/portsentry.log`,
with `source = "file"` and `timestamp = "iso8601"`. Syslog, stdout and journal
envelopes are outside this integration.

**Qualified deployment:** PortSentry v2.0.7 on Debian 13 with IPv4/IPv6 nftables
bans, expiry and restored connectivity. `--connect` was qualified in 0.4.3;
`--stealth -m pcap -i <interface>` (TCP SYN, FIN, NULL and XMAS scans, and UDP)
in 0.4.7. Legacy 1.2 and other 2.x versions stay unqualified. Automatic bans
cover the source across host ports and protocols.

Follow the [PortSentry setup guide](../guides/portsentry.md) for the sensor settings,
enforcing jail and validation sequence. Sensor response actions must be disabled.
PortSentry recreates its history file at every start; choose the jail's
`on_truncation` policy deliberately.

---

## Meta

### `recidive`

**What it matches:** Repeat offenders. Every ban enforced in another jail is
recorded in-process as one attempt against `recidive` — no log file, no
`logpath`. `fail2zig jails` shows `SOURCE internal`,
`HEALTH ok`. Restores, unbans, failed bans, and log-only would-bans do not
count.

**Log file:** None. The shipped default config includes a `recidive` jail with
no `logpath`.

**Recommended jail settings** (the values of the shipped example, in seconds):

```toml
[jails.recidive]
enabled  = true
filter   = "recidive"
source   = "internal"
maxretry = 2          # 2 enforced bans in any jail → recidive escalation
findtime = 86400      # within a 24-hour window
bantime  = 604800     # 1 week for persistent repeat offenders
```

---

## Summary table

| Filter             | Category | Typical log path                           |
| ------------------ | -------- | ------------------------------------------ |
| `sshd`             | SSH      | `/var/log/auth.log`, `/var/log/secure`     |
| `nginx-http-auth`  | Web      | `/var/log/nginx/error.log`                 |
| `nginx-limit-req`  | Web      | `/var/log/nginx/error.log`                 |
| `nginx-botsearch`  | Web      | `/var/log/nginx/access.log`                |
| `apache-auth`      | Web      | `/var/log/apache2/error.log`               |
| `apache-badbots`   | Web      | `/var/log/apache2/access.log`              |
| `apache-overflows` | Web      | `/var/log/apache2/error.log`               |
| `postfix`          | Mail     | `/var/log/mail.log`                        |
| `dovecot`          | Mail     | `/var/log/mail.log`                        |
| `courier`          | Mail     | `/var/log/mail.log`                        |
| `named-refused`    | DNS      | `/var/log/named/default`                   |
| `vsftpd`           | FTP      | `/var/log/vsftpd.log`                      |
| `proftpd`          | FTP      | `/var/log/proftpd/proftpd.log`             |
| `mysqld-auth`      | Database | `/var/log/mysql/error.log`                 |
| `recidive`         | Meta     | None (in-process `internal` source)        |
| `portsentry`       | Scan detection | `/var/log/portsentry.log` (v2.0.7 history) |

## Custom native rules

A log the built-in filters do not cover can be matched with a custom rule file: a
bounded JSON description of a failing record, as a typed template or as structured
JSON, with predicates, exclusions and correlation. Rules are not regular
expressions, and fail2ban filters are not imported.

```json
{
  "id": "app-denied",
  "source": "application",
  "format": "template",
  "template": "Denied login for {user:word} from {peer:ip} port {port:uint}",
  "subject": "peer",
  "conditions": [{ "field": "port", "number": 2201 }],
  "exclude": [{ "field": "user", "text": "probe" }]
}
```

The [custom rule file reference](custom-rules.md) gives the complete format, its
limits, the file ownership requirements, a jail that uses a rule and how to test
one with `rule-test`. The [parser architecture](../architecture/parser-engine.md)
explains the boundary.
