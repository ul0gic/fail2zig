# Parity fixture and source-mode contract

Status: P0 inventory and harness input contract. This document does not certify
candidate behavior. Reference: fail2ban 1.1.1 commit
`f60978618a101427b06924fc932b44350fec2b63`.

The product harness is [mode_test_inventory.py](../../tests/parity/mode_test_inventory.py).
Its JSON joins the existing source inventory and fixture metadata to concrete
configuration inputs, requirement owners, reference configuration-stream hashes,
and deterministic record eligibility. It does not run upstream tests or log
records. Pattern matching and action dispatch belong to subsequent harness work.

## Source test definitions and generated families

Every one of the 444 syntactically discovered functions has a source anchor,
qualified name, body hash, individual assertion/call inventory and requirement
ownership. These are 444 definitions, not 444 runnable tests. The sample factory,
its nested generated test body and the fixture action method are classified
separately. Reference harness self-tests have harness applicability rather than
an invented product API requirement.

Behavior ownership starts from each source class's actual responsibility and
refines named behaviors such as rotation, journal selection, ignore commands,
multiline state and ban escalation. Assertion calls remain beside each mapping
so P1 reviewers can detect overbroad ownership. A mapped requirement means the
case must be carried into that requirement's acceptance work; it does not mean
the assertion already passes in fail2zig.

The generated families are explicit:

- File monitoring: each factory test for polling and pyinotify, with dependency
  availability recorded per profile.
- Journal monitoring: each factory test for the systemd profile.
- SMTP action mixin: each inherited method for the legacy and aiosmtpd adapters.
- Client/server base tests: each inherited method for client and server classes.
- Sample factory: one root per selected stock or test-only filter, with its full
  ordered record/option metadata in the fixture inventory.

Each loop inside a definition has an anchor, iterator-AST hash and literal arity
where statically available. An implementation must retain all members or supply
a documented generator for a runtime iterator. Source test bodies and possible
payload literals must not be automatically imported or replayed. Original benign
fixtures exercise their observable contracts in an isolated local harness.

## Concrete sample eligibility and cached options

The pinned metadata contains four expression spellings, all comparing the root
filter name or `opts.get('mode')` to a string. The resolver interprets only these
AST forms, accepting equality and inequality and rejecting other syntax. It
never uses Python `eval`, executes arbitrary expressions or imports the sample
loader.

All symbolic conjunctions and conditional defaults become explicit booleans.
Each execution choice records requested options, eligibility, first eligible
construction of the root-local cache key, and effective cached options. The
first cached construction wins even if a later option declaration requests a
different value under the same key. Ordered record associations remain intact;
a record is not an independent fresh filter test merely because it has its own
JSON entry.

The self-checks cover all four expression forms, compound guards, four
benign rejected forms, and the distinction between block gating before lazy
construction and a per-record constraint after construction. They verify this restricted metadata interpreter. They
do not claim the upstream expression language is limited to these forms.

## Effective declarations, selectors and open domains

Every catalog declaration has stock, explicit override and empty-value acceptance
specifications. Internal interpolation fragments are identified as configuration
declarations rather than automatically advertised as public parameters.

Nested selector tags are joined to their declared target keys. For example,
SSHD's mode and public-key branches form a Cartesian product, including inherited
log-type selectors from its common configuration. When several templates use the
same parameter, their declared domains are intersected; a key such as
`mdre-normal-other` does not accidentally advertise `normal-other` as an SSHD
mode when another required template has no matching branch. Include closures
are retained per combination.

Source-declared combinations, stock defaults, effective sample options, and
empty/unknown/case-changed selector boundaries are passed to the actual pinned
`FilterReader` or `ActionReader`. Only configuration streams are produced. No
stock detection pattern is compiled or matched, no command is executed, and no firewall
or provider is contacted. An audit hook rejects subprocess and socket attempts.
A fresh bytecode-cache prefix prevents stale source-adjacent bytecode from
becoming the oracle. Every configuration job runs twice and records equal stream
hashes or equal diagnosed error hashes. Imported reference source hashes are
included in the receipt.

Configuration-stream success is not proof that the eventual matcher or action
can run. Unknown selector values can survive as unresolved tags; action tags can
also legitimately await runtime information. The receipt preserves those tag
names. P1 must compare the correct stage's outcome rather than treating every
unresolved tag as either success or failure. A common helper requiring its
consumer's values may correctly fail standalone conversion.

Custom local declarations, regular expressions, paths, command templates and
other free-form values have open domains. No finite inventory can enumerate all
strings. Acceptance therefore combines every declared branch with boundary and
property contracts: precedence, empty versus absent, explicit unknown values,
valid and invalid type conversion, missing includes, cycles, conditional option
selection and deterministic error reporting. Layering and interpolation cases
remain owned by CFG-01/CFG-02; pattern semantics by FLT-02 through FLT-05; runtime
action expansion and lifecycle by ACT-03 through ACT-08.

## Positive, negative and boundary acceptance

Existing upstream records remain source hashes and metadata associations, not
replayed inputs. Each selected root also has an original neutral negative record
specification using a documentation address and a `status=healthy` event. Its
proposed outcome is no failure ticket and no action dispatch from a fresh state.
P1/P3 must validate that negative against each effective mode before adopting it
as an oracle. Filters with intentionally broad semantics require a different
original record; silently converting a surprising match into an accepted
negative is forbidden.

Stateful cases preserve record order, cache identity, multiline correlation,
ignore decisions and ticket timestamps. Each positive needs its expected
identity, event time and control-tag effects; negatives include neutral records,
ignore precedence, ignored identity, incomplete correlation and successful
session cleanup. Timestamp/threshold boundaries use the separate timing contract
and fixed time. Resource limits include explicit rejection and recovery outcomes,
not merely an elapsed-time observation.

## Phase handoff

P0 delivers provenance, mapped definitions, generated-family ownership,
resolved metadata choices, declared parameter contracts and configuration-only
reference oracles. P1 consumes these specifications to build differential
execution and semantic coverage accounting. P2–P7 implement and certify their
corresponding behavior. Neither a mapped definition, a selected branch, an
eligible record nor an equal repeated reference hash is a candidate pass.

Before a requirement becomes verified, its evidence must identify the exact
candidate/reference artifacts and profile, original fixture or approved corpus
provenance, all expected/actual outcomes, skips, and any normalization. Missing
oracle cases, unsupported profiles and unexpected errors stay visible as failed
or deferred work; they are not removed from the denominator.
