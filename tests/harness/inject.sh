#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat >&2 <<EOF
Usage: $0 <jail> <source-ip> <count> [--delay-ms N]

Supported jails:
  sshd              -> logger -p auth.info (routes to /var/log/auth.log)
  nginx-http-auth   -> /var/log/nginx/error.log
  nginx-botsearch   -> /var/log/nginx/access.log
  postfix           -> /var/log/mail.log
  apache-auth       -> /var/log/apache2/error.log
  dovecot           -> /var/log/mail.log
EOF
    exit 2
}

[ $# -lt 3 ] && usage
jail="$1"; ip="$2"; count="$3"; shift 3
delay_ms=0
while [ $# -gt 0 ]; do
    case "$1" in
        --delay-ms) delay_ms="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; usage ;;
    esac
done

delay_s=$(awk -v ms="$delay_ms" 'BEGIN{printf "%.3f", ms/1000.0}')

emit() {
    local body="$1"
    case "$jail" in
        sshd)
            logger -t "sshd[$$]" -p auth.info "$body"
            ;;
        nginx-http-auth)
            echo "$body" | sudo tee -a /var/log/nginx/error.log >/dev/null
            ;;
        nginx-botsearch)
            echo "$body" | sudo tee -a /var/log/nginx/access.log >/dev/null
            ;;
        postfix|dovecot)
            echo "$body" | sudo tee -a /var/log/mail.log >/dev/null
            ;;
        apache-auth)
            echo "$body" | sudo tee -a /var/log/apache2/error.log >/dev/null
            ;;
        *)
            echo "inject.sh: unsupported jail '$jail'" >&2
            usage
            ;;
    esac
}

for i in $(seq 1 "$count"); do
    case "$jail" in
        sshd)
            emit "Invalid user probe$i from $ip port $((40000 + i))"
            ;;
        nginx-http-auth)
            emit "2026/04/21 12:00:0$((i % 10)) [error] 1#0: *$i no user/password was provided for basic authentication, client: $ip, server: example.com"
            ;;
        nginx-botsearch)
            emit "$ip - - [21/Apr/2026:12:00:0$((i % 10)) +0000] \"GET /wp-login.php HTTP/1.1\" 404 162 \"-\" \"InjectBot/$i\""
            ;;
        postfix)
            emit "Apr 21 12:00:0$((i % 10)) mail postfix/smtpd[1234]: warning: unknown[$ip]: SASL LOGIN authentication failed: authentication failure"
            ;;
        apache-auth)
            emit "[Tue Apr 21 12:00:0$((i % 10)).000 2026] [auth_basic:error] [pid 1:tid $i] [client $ip:12345] user admin: authentication failure"
            ;;
        dovecot)
            emit "Apr 21 12:00:0$((i % 10)) mail dovecot: imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<admin>, method=PLAIN, rip=$ip, lip=10.0.0.1"
            ;;
    esac
    if [ "$delay_ms" != "0" ] && [ "$i" != "$count" ]; then
        sleep "$delay_s"
    fi
done
