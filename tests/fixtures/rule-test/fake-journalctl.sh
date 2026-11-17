#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig maintainers
# Does:  Prints two fixed sshd journal records as JSON lines, standing in for journalctl.
# Holds: The output is fixed text: it reads no argument, journal or clock.

printf '%s\n' '{"__CURSOR":"s=1;i=1","__REALTIME_TIMESTAMP":"1776772800000000","MESSAGE":"Failed password for root from 203.0.113.200 port 22 ssh2","SYSLOG_IDENTIFIER":"sshd"}'
printf '%s\n' '{"__CURSOR":"s=1;i=2","__REALTIME_TIMESTAMP":"1776772801000000","MESSAGE":"Accepted publickey for ops from 198.51.100.9 port 22 ssh2","SYSLOG_IDENTIFIER":"sshd"}'
