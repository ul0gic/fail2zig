---
title: 'Custom rule files'
description: 'The JSON rule-file format: template and JSON rules, predicates, exclusions, correlation, limits, file requirements and how to test a rule.'
sidebar_position: 3
category: Reference
audience: operator
last_verified: 2026-11-15
---

A custom rule file teaches a jail to detect failures in a log the built-in
filters do not cover. A rule is one JSON object in its own file. It is a bounded
description of what a failing record looks like, not a regular expression and not
a script: fail2ban filters are not imported, and nothing in a rule is executed.

## A first rule

This application logs `Denied login for alice from 203.0.113.100 port 2201`. The
rule bans the address, only for port 2201, and never for the user `probe`:

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

Test it against sample records before any jail uses it. The repository carries
this rule and a sample log as fixtures:

```bash
fail2zig rule-test --file tests/fixtures/rule-test/custom.log \
  --rule-file tests/fixtures/rule-test/custom-rule.json --timestamp undated --output table
```

```text
counts	matched=1	missed=2	ignored=1	rejected=1
line	outcome	reason	identity	event_time_us	time	pattern
1	match	matched	203.0.113.100	1794711595826245	time-eligible-receipt	-
2	miss	condition_failed	-	1794711595826245	time-eligible-receipt	-
3	ignore	exclusion_matched	203.0.113.102	1794711595826245	time-eligible-receipt	-
4	miss	template_mismatch	-	1794711595826245	time-eligible-receipt	-
5	reject	invalid_subject	-	1794711595826245	time-eligible-receipt	-
```

Line 2 is another port, line 3 is the excluded user, line 4 does not fit the
template, and line 5 carries an address that can never be banned.

## Use a rule in a jail

```toml
[jails.application]
filter = "application"
source = "file"
timestamp = "undated"
logpath = ["/var/log/application.log"]
rule_files = ["/etc/fail2zig/rules/application.json"]
enforce = false
```

- `rule_files` takes up to eight distinct absolute paths. Every rule file of one
  jail must carry the same `source` value, and each `id` must be unique in the jail.
- `filter` is the jail's service name: 1 to 64 characters from letters, digits,
  `.`, `_` and `-`. It does not have to equal the rule's `source`.
- The jail's source must be `file` or `journald`. A custom rule on the journal
  also needs an explicit `journal_executables` list.
- Exclusions for a rule jail live in its `ignore_file`. `ignoretime`, timed
  `ignoreip` entries and the `ignore` commands are refused for it.
- Start with `enforce = false`, watch `fail2zig jails` and `history`, then enable
  enforcement.

A rule file must be a regular file, not a symbolic link, owned by root or by the
daemon's user, and not writable by group or others. The daemon refuses anything
else with `UntrustedConsumerFile`. `rule-test` does not apply these ownership
checks, so a rule that tests clean can still be refused at start.

## Fields

| Field          | Type   | Required          | Rules                                                                                   |
| -------------- | ------ | ----------------- | --------------------------------------------------------------------------------------- |
| `id`           | string | yes               | 1 to 32 characters from letters, digits, `_` and `-`. Unique within the jail.           |
| `source`       | string | yes               | Same character rule. Shared by every rule file of the jail.                             |
| `format`       | string | yes               | `"template"` or `"json"`.                                                               |
| `template`     | string | `template` format | 1 to 512 bytes. Not allowed with `"json"`.                                              |
| `subject`      | string | yes               | The capture or field that holds the address to ban.                                     |
| `subject_kind` | string | no                | `"ip"` (default) or `"hostname"`.                                                       |
| `conditions`   | array  | yes               | At least one predicate. All must hold.                                                  |
| `exclude`      | array  | no                | Predicates; a record that satisfies one is ignored.                                     |
| `correlation`  | object | no                | `json` format only. See [correlation](#correlation).                                    |

`conditions` and `exclude` together hold at most eight predicates. A key that
appears twice makes the rule invalid.

### Predicates

A predicate compares one capture or field with a constant.

| Key      | Meaning                                                                              |
| -------- | ------------------------------------------------------------------------------------ |
| `field`  | The capture or field name.                                                           |
| `op`     | `"equal"` (default) or `"starts_with"`. `starts_with` needs `text`.                  |
| `text`   | A string of 1 to 256 bytes.                                                          |
| `number` | A non-negative integer.                                                              |

Give exactly one of `text` or `number`.

## Template rules

A template is the record written out literally, with `{name:kind}` where a value
varies. It must match the whole record from its first byte to its last.

| Kind       | Captures                                                                           |
| ---------- | ---------------------------------------------------------------------------------- |
| `word`     | Printable bytes up to the next space, tab or delimiter.                            |
| `ip`       | An IPv4 or IPv6 address, at most 45 characters.                                    |
| `uint`     | A decimal non-negative integer.                                                    |
| `quoted`   | A double-quoted string; `\"` and `\\` are the only escapes.                        |
| `hostname` | A host name, at most 253 characters, labels of letters, digits and hyphens.        |

- A template has at most 8 captures and 24 segments (literals and captures). Capture
  names are unique, 1 to 32 characters.
- A captured value is never empty and is at most 256 bytes.
- The byte after a capture must be the end of the template, a space, a tab, or one
  of `[ ] ( ) , ; : = | " '`. An `ip` capture cannot be followed by `:`, and a
  `quoted` capture cannot touch a literal `"`.
- There is no way to write a literal `{` or `}`.
- In a predicate, a `word` or `quoted` capture takes `text` and a `uint` capture
  takes `number`. An `ip` or `hostname` capture cannot be a predicate field.
- `subject` must name an `ip` capture, or a `hostname` capture when `subject_kind`
  is `"hostname"`.

The jail's `timestamp` setting decides how much of each line the template sees.
With `undated` the template must match the whole line. A rule has no time field;
the event time comes from the jail's timestamp contract.

## JSON rules

With `"format": "json"` each record is one JSON object, and predicates read its
fields directly:

```json
{
  "id": "api-denied",
  "source": "api",
  "format": "json",
  "subject": "client",
  "conditions": [{ "field": "event", "text": "login_failed" }]
}
```

```bash
fail2zig rule-test --record '{"event":"login_failed","client":"203.0.113.9","user":"alice"}' \
  --rule-file api-denied.json --timestamp undated --output table
```

```text
counts	matched=1	missed=0	ignored=0	rejected=0
line	outcome	reason	identity	event_time_us	time	pattern
1	match	matched	203.0.113.9	1794711595839230	time-eligible-receipt	-
```

A record must be an object of at most eight fields. Field names follow the name
rule above, and values are strings of at most 256 bytes or non-negative integers.
Nested objects, arrays, booleans, null and negative or fractional numbers make the
record invalid. `subject` names a string field.

## Correlation

Some services log the address in one record and the failure in a later one.
Correlation joins two JSON records that share a key.

| Key           | Meaning                                                                     |
| ------------- | --------------------------------------------------------------------------- |
| `key`         | The field whose value joins the two records.                                |
| `phase`       | The field that says which of the two records this is.                       |
| `start`       | The `phase` value of the first record, 1 to 64 bytes.                       |
| `finish`      | The `phase` value of the record that completes the match.                   |
| `ttl_seconds` | How long the first record waits for the second, 1 to 300.                   |

All five keys are required. `key`, `phase` and `subject` must be three different
names, and `start` and `finish` must differ. At most eight pending records are
held at a time. A first record waiting for its partner is reported by `rule-test`
as a miss.

## Host-name subjects

With `"subject_kind": "hostname"` the rule captures a host name and the daemon
resolves it before banning. The jail then needs a configured resolver
(`dns_server`); without one the daemon refuses with `HostnameResolutionRequired`.
In `rule-test`, pass `--identity dns --dns-server <ip:port>`.

## Limits

| Limit                          | Value         |
| ------------------------------ | ------------- |
| Rule document                  | 4,096 bytes   |
| Record                         | 2,048 bytes   |
| Predicates per rule            | 8             |
| Captures per template          | 8             |
| Segments per template          | 24            |
| Fields per JSON record         | 8             |
| Name length                    | 32 bytes      |
| Value length                   | 256 bytes     |
| Rule files per jail            | 8             |
| Correlation records held       | 8             |

Addresses that can never be enforced are rejected as `invalid_subject`:
`0.0.0.0/8`, `127.0.0.0/8`, `::` and `::1`.

## Outcomes and reasons

`rule-test` reports one outcome per record, with a reason:

| Outcome  | Meaning                                                                                  |
| -------- | ---------------------------------------------------------------------------------------- |
| `match`  | The record is a failure and its subject is a candidate for a ban. Reason `matched`.      |
| `miss`   | The rule does not apply, or a correlated record is still waiting for its partner.        |
| `ignore` | An `exclude` predicate matched. Reason `exclusion_matched`.                              |
| `reject` | The record or its subject is invalid.                                                    |

The reasons are `matched`, `source_mismatch`, `template_mismatch`,
`condition_failed`, `exclusion_matched`, `missing_field`, `wrong_type`,
`invalid_record`, `invalid_subject`, `incomplete_record`, `context_stored`,
`context_missing`, `context_expired`, `context_conflict` and `event_order`. The
four `context_` reasons and `event_order` arise only with correlation.

## Errors

| Error                                              | Cause                                                                        |
| -------------------------------------------------- | ---------------------------------------------------------------------------- |
| `InvalidRule`, `RuleFileInvalid`                   | The document breaks a rule on this page.                                     |
| `ConfigTooLarge`, `RuleFileTooLarge`               | The document is over 4,096 bytes.                                            |
| `RuleFileNotFound`, `InvalidNativePath`            | The path is missing or not absolute.                                         |
| `DuplicateRuleFile`, `DuplicateRuleId`             | The same file or the same `id` appears twice in a jail.                      |
| `ConsumerSourceMismatch`                           | Rule files of one jail carry different `source` values.                      |
| `ConsumerFileLimit`                                | More than eight rule files.                                                  |
| `UntrustedConsumerFile`                            | The file's type, owner or permissions are not accepted.                      |
| `HostnameResolutionRequired`                       | A host-name rule with no resolver configured.                                |
| `RecordTooLarge`                                   | A record is over 2,048 bytes.                                                |

Changing `rule_files` needs a restart; `reload` reports `restart_required`. See
the [configuration reference](config.md#what-a-reload-applies) and
[rule-test](cli-fail2zig.md#offline-rule-testing).
