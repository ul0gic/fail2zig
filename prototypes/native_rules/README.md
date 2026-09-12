# Native rules: isolated N1 prototype

This experiment evaluates whether constrained, operator-authored rules can cover useful
local workloads while keeping subject attribution and resource/error behavior explicit.
It is **not connected to the daemon, ban policy, firewall, importer or shipped builds**.
Its output is a candidate failure event, never a ban decision. Syntax is experimental.

Requires the project's Zig 0.14.1 toolchain. No Python or added library is used. The prototype
reuses the native `shared.IpAddress` parser/canonicalization and Zig's JSON parser. It does
not reuse or modify the production wildcard matcher or the existing HTTP access-log parser.

## Run and inspect

From the repository root:

```sh
cd prototypes/native_rules
zig build test -Doptimize=ReleaseSafe --summary all
zig build -Doptimize=ReleaseSafe
./zig-out/bin/native-rules-probe fixtures/auth.json auth-log fixtures/auth.jsonl
./zig-out/bin/native-rules-probe fixtures/auth-template.json auth-log fixtures/auth.txt
./zig-out/bin/native-rules-probe fixtures/http.json http-log fixtures/http.jsonl
./zig-out/bin/native-rules-probe fixtures/session.json auth-log fixtures/session.jsonl
zig build test-workloads -Doptimize=ReleaseSafe --summary all
./zig-out/bin/native-rules-probe fixtures/mail-delimited.json mail-log fixtures/mail-delimited.txt
./zig-out/bin/native-rules-probe fixtures/access-quoted.json access-log fixtures/access-quoted.txt
```

The runner reads local files only. The source ID is a separate collector argument; a
`source` property inside a record cannot change it. This is a binding, not authentication
of the file or caller. Real source provenance/permissions remain an integration requirement.
The CLI uses synthetic monotonic seconds advancing once per record; it is not live event time.
Each input record must end with a newline. An incomplete last record is rejected explicitly.
The fixture-file size cap is 1 MiB. Ordinary no-match, exclusion and awaiting-context outcomes
exit successfully. Rejected/exhausted records produce explanations and a nonzero exit status.

For example, the authentication input yields a candidate for the failure, no match for the
success and an exclusion for the health-check account. Output includes rule/source, outcome,
reason, relevant field/predicate, canonical subject when applicable and subject origin
(record or saved context). It does not echo raw records, accounts or session keys. The subject
address is still potentially sensitive operational data; protect diagnostic output accordingly.

## Rule shape

Rules bind an exact source ID and an explicit subject field. All `conditions` must match;
any matching `exclude` predicate suppresses the event. Predicates support exact string or
unsigned-number equality, plus explicit string prefix matching. There is no implicit coercion
between a JSON number and string. A required predicate/exclusion field missing on the evaluated
path causes rejection, not a candidate. A failed earlier condition short-circuits evaluation.

Two decoders are available:

- `json`: a flat object of strings and integer values from 0 through 9,223,372,036,854,775,807,
  with duplicate fields rejected.
  Nested structures, booleans, null and floating-point values are outside this experiment.
- `template`: full-record, exact literal matching with named `{field:word}`, `{field:ip}`,
  `{field:uint}` and `{field:quoted}` captures. Names cannot repeat. Words are nonempty
  printable ASCII without whitespace; unsigned numbers contain decimal digits only. The
  subject must be typed `ip`. Unknown fields/types and detectable predicate/capture type
  conflicts reject the rule at load time.

Unquoted captures end at space/tab, end of record, or the first occurrence of the next
literal's delimiter byte. Supported punctuation delimiters are `[ ] ( ) , ; : = | " '`.
The delimiter remains part of the following literal, which must match in full. There is no
search for a later delimiter if the suffix fails. Adjacent captures and alphanumeric
delimiters are rejected. IP captures cannot use `:` as a delimiter, because it belongs to
IPv6 addresses; use `peer[{peer:ip}]:{port:uint}` for an address followed by a port.
Dots, slashes and other punctuation outside the listed set are not capture delimiters.

`{field:quoted}` consumes its own opening and closing double quotes. Do not surround the
capture with additional quotes in the template. It accepts printable ASCII including spaces,
allows empty content, and decodes only `\"` and `\\`. Unknown escapes (including hex/Unicode
escapes), literal control bytes, non-ASCII bytes and unterminated quotes are rejected. The
first unescaped closing quote ends the field; later quotes are never reconsidered. The
decoded value is limited to 256 bytes within the existing fixed scratch buffer. Raw input
and per-byte scanning remain subject to the existing record/work limits. Quoted text cannot
be used as an untyped subject; a quoted IP can instead use literal quotes around `{peer:ip}`.

Braces remain reserved. Wildcard search, alternation, optional captures, regex and template
literal escaping are unsupported. This is the maintainer-approved narrow capture extension,
not a general parser framework. Literal/full-record shape mismatches return `no_match` with
`template_mismatch`; malformed typed fields/quoting remain `rejected`, and cap failures are
`exhausted`. An unrelated line may fail a typed capture before reaching a later mismatching
literal; no-match classification does not scan ahead or backtrack to override that error.

Text example: `login result={result:word} peer={client:ip} account={account:word}`.
Bracketed mail example: `warning: peer[{peer:ip}]: authentication {result:word}`.
Quoted access example: `{peer:ip} - - {request:quoted} {status:uint}`.
A field parser validates the complete captured address and applies existing native
canonicalization and unenforceable-address checks. It does not infer trust from any arbitrary
address in the record. Allowlists, proxy trust, client identity behind shared IPs, thresholds,
ban scope and expiry are outside the matcher and still required before actual enforcement.

The original HTTP fixture is structured JSON containing `remote`, `status` and `path`. The
new quoted-access fixture covers one explicitly shaped text format, not every combined-log
variant or URL normalization. Prefix predicates
mean literal prefix: the example deliberately includes a slash boundary in `/private/`.
Existing compiled detectors remain unchanged and available in the product.

## Two-record correlation

The JSON-only `correlation` experiment stores an explicitly named subject on a start record
and retrieves it on a finish record using an exact session key within the same program/source.
Eight slots are available. Start records never emit candidates. Finish records must pass the
rule conditions/exclusions. A supplied finish subject must agree with the saved subject.
Duplicate starts cannot extend lifetime or replace a different subject. A successful candidate
or exclusion consumes the context; rejection/no-match preserves it. A repeated finish has no
context. This is not general duplicate suppression of input records or exactly-once processing.

Expiry is at `now - started >= ttl_seconds`; TTL must be 1–300 seconds. Clock reversal is
rejected. Capacity exhaustion preserves live slots; expired slots can be reused. Context is
copied and staged before publication so processing errors cannot partly change it. The clock
watermark advances on complete, in-limit evaluated records even when they fail; callers must
supply monotonic processing time, not out-of-order log event time.

Context is memory-only. The rule/source binding does not make a log-provided session key
trustworthy. Proper session provenance/lifecycle, restart persistence, event-time handling,
reload-generation rules and integration with durable source acknowledgment remain unimplemented.
A `Session` borrows a heap-pinned `Program`; it must not outlive the program. The standalone
runner creates one program/session and does not implement hot reload. The invalid-replacement
unit test proves that a failed construction leaves an existing object usable, not daemon reload.

## Resource contract

Hard ceilings are intentionally small prototype choices, not final product defaults:

| Resource | Ceiling |
|---|---|
| Configuration | 4 KiB input, 32 KiB fixed parser storage plus fixed program metadata |
| Record | 2 KiB input, 32 KiB fixed decode scratch plus fixed evaluation metadata |
| Fields | 8; names up to 32 bytes; string/text captures up to 256 bytes |
| Conditions plus exclusions | 8 |
| Text template | 512 bytes, 24 compiled segments |
| Session context | 8 entries, keys up to 64 bytes, TTL up to 300 seconds |
| Evaluation work allowance | At most 16,384 charged units; configurable downward |

Evaluation uses fixed storage rather than the caller's heap. Program creation has one owning
allocation; configuration parsing is confined to that object's fixed buffer. Invalid rules
and allocation failures clean up the owner. Each call stages bounded context and owns a fixed
scratch arena; borrowed field values do not escape into saved context or explanations.

Work units charge input bytes and bounded comparison/lookup costs. They are a deterministic
admission/work allowance, **not measured instructions, elapsed-time deadlines or a complete
accounting of JSON parser operations**. Input, parser memory and structural caps independently
limit decoding. A long record rejected by a cap is not silently truncated into a candidate.
Per-daemon scheduling/fairness, stack/RSS qualification and multi-rule aggregate budgets remain
future work. `exhausted`, `rejected` and ordinary `no_match` are distinct observable outcomes.

## What the result can establish

The tests exercise original private-authentication and format-variation examples, structured
HTTP conditions, legitimate successes, exclusions, strict field attribution, malformed/type/
size/duplicate input handling, owned rule lifetime, allocation failure, explain output and
session expiry/conflict/capacity/isolation. These are bounded feasibility cases, not measured
customer-risk reduction, a usability study, complete service coverage or native N1 completion.

The approved delimiter/quoted-field correction now covers the three selected SSH, bracketed-mail
and quoted-access workload shapes. Source provenance, native checkpoints, aggregate resource
budgets and daemon integration remain separate work. Stop and discuss before broadening this
into a general pattern language, adding a dependency or changing the agreed product boundary.
The original prototype and workload receipts retain their historical hashes/results; this
revision has separate evidence. The checkpoint `e502479` remains available.
