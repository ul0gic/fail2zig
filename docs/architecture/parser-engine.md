---
title: 'Parser and native rules'
description: 'Compiled service matchers, bounded JSON rules, offline evaluation and typed detection results.'
sidebar_position: 4
category: Architecture
audience: engineer
last_verified: 2026-11-15
---

## Two supported matching paths

The 16 built-in filters, including internal recidive, compile to specialized matchers in the executable.
Custom jails can load bounded native JSON rules through `rule_files`. Neither path
runs arbitrary fail2ban regexes, Python extensions or shell action strings.

Built-in matcher allocation checks describe those components. They do not imply
zero allocation through SQLite, receipt ingestion, DNS, retries or administration.

## Built-in service matching

Built-ins recognize structural fields in supported service log formats and extract
addresses from those positions. They are not a promise to understand every version
or configuration of a named service. Hyphen/underscore aliases are supported for
built-in names, but a name match during migration is not semantic equivalence.

Changing a built-in matcher requires a new build. Test representative successes,
failures and malformed records with the release's offline evaluator before using
a service profile. See the [filter reference](../reference/filters.md).

## Bounded native JSON rules

Native rules support structured JSON records or typed template captures, predicates,
exclusions and bounded correlation. A rule declares its service/source, subject and
conditions. It emits typed addresses or hostnames, not executable commands.

The rule implementation limits configuration bytes, input record bytes, fields,
segments and work. The maximum rule document is 4 KiB, the custom rule record
limit is 2 KiB, and a jail takes at most eight rule files; the
[custom rule file reference](../reference/custom-rules.md) lists every limit. Oversized or invalid data is rejected; these limits
are specific to this rule path, not a universal line-size claim for every source.

Hostname subjects enter bounded native DNS/retry handling. Correlation state,
original event time and record identity have to survive retries consistently.

```bash
fail2zig rule-test --file /path/to/sample.log --service sshd --timestamp undated
fail2zig rule-test --file /path/to/sample.log --rule-file /path/to/rule.json
```

The evaluator reports matched, missed, ignored and rejected records without
starting a daemon or installing firewall rules. See [a native rule example](../reference/filters.md#custom-native-rules).

## Detection is not enforcement

A match enters ignore and ban policy. Repeated failures can produce finite,
permanent or escalating protection, with independently owned jail scopes.
Typed enforcement intent is persisted before backend dispatch. Kernel readback,
not a matching log line or subprocess exit alone, confirms installed protection.

Uncertain effects remain visible and recoverable. Keep that distinction when
consuming status, history, metrics or events. See [enforcement](netlink-interop.md).

## Performance scope

Older parser-only measurements do not describe the complete native runtime.
This release does not claim measured superiority over another product or a
whole-daemon zero-allocation path. Evaluate ingestion, durability and enforcement
together under your selected workload and backend.
