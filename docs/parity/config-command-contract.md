# Configuration and operator compatibility contract

This is the proposed D6/D7 implementation contract for fail2ban 1.1.1 at
`f60978618a101427b06924fc932b44350fec2b63`. It defines new architecture and a
named compatibility profile; it does not describe shipped fail2zig functionality.
The native daemon, importer, reload implementation and command adapter still need
implementation and phase acceptance. Existing correction work stays separate. D6/D7
design choices below are selected for P0; execution/certification remains phase-gated.

The contract preserves effective operator intent and source provenance while keeping
inspection free of imported code execution. It separates configuration publication
from effects that may already have happened. It follows the
[action contract](action-contract.md) for executable extensions and uncertain effects,
the finalized [runtime contract](runtime-contract.md) for process/ABI/durability/profile
decisions, and [fixture contract](fixture-contract.md) for symbolic mode expansion.

## D6: three connected representations

Use a versioned canonical configuration document with `schema_version=1`, an immutable
`config_generation`, a pinned `reference_profile`, and a content-addressed asset manifest.
The new schema is not an extension of the existing TOML struct by silent defaulting.
Old native configurations receive an explicit schema/profile conversion path.

| Representation | Required fields and meaning |
|---|---|
| Source graph | Ordered file/include occurrences; original path and spelling; resolved path; exact byte hash; section/option source spans; assignment order; raw token bytes; comments/format retention in original assets; include-before/include-after edges; local layering; previous-value links. A file included twice has two graph occurrences. |
| Resolved values | Consumer identity and phase; canonical type; presence; explicit raw value or unresolved expression; typed value when available; selected assignment/default; ordered provenance chain; interpolation/parameter dependencies; diagnostics; dependency/secret classification. |
| Effective generation | Immutable global/startup, jail, source, filter, ordered action-instance and policy objects; admitted compatibility assets; exact scope identities; runtime-overlay revision; per-object provenance references; selected profile limits. |

Original asset bytes are retained separately and referenced by hash. The graph preserves
semantics and edits without forcing every reader to hold duplicate whole-file strings.
Hashes identify content; filesystem permissions and trusted activation are separate
checks. A path change, symlink target change or content change invalidates the prepared
manifest even if a displayed effective scalar is unchanged.

Canonical paths distinguish closed typed fields from open namespaces. For example,
`jail.<id>.policy.maxretry`, `source.<id>.backend.parameters`,
`filter.<id>.compat.parameters`, and `action.<id>.compat.parameters` have distinct
consumers. Ordered action instances are an array with stable IDs, not a dictionary
keyed only by action filename. Port/protocol/network prefix and action target remain
explicit under D3. A property named `port` inside an administrator extension is not
silently interpreted as a daemon-wide port field.

## Presence, defaults and conversion

The value envelope uses `presence=absent|explicit|derived`, `raw` when supplied,
`resolution=unresolved|resolved|reference-fallback|invalid`, an explicit `type`, optional
`typed`, and an `origin` record. `typed=null` is permitted only when that consumer's
schema permits it; it is not an alternative spelling for absence. An explicit empty
string remains `presence=explicit, raw=""`. An explicit false, zero, empty list, the
literal string `None`, and a disabled/absent feature are not interchangeable.

Default identity includes reference release, reader, section, option and resolution
phase. In particular, reference early `logtarget` defaults to `/var/log/fail2ban.log`,
while the later global reader defaults to `STDERR`; an effective config assignment
or command-line override can supersede either. Collapsing both phases into one default
would change startup behavior. See `client/fail2banreader.py:42` and `:52`.

Resolution order is a graph operation with these boundaries:

1. Read exact ordered `.conf`, sorted `.d/*.conf`, `.local`, sorted `.d/*.local` inputs
   and before/after includes. Keep source and prior assignments, including `known/`
   previous-value references. See `client/configreader.py:206` and
   `client/configparserinc.py`.
2. Apply reference defaults, section inheritance and reader-specific static values.
   Resolve bracket parameters, Definition/Init values, conditionals and recursive
   interpolation using the selected consumer's precedence. Do not convert an integer
   or boolean before substitutions that depend on its original expression. See
   `client/configreader.py:337` and `:381`.
3. Convert at the reference consumer boundary. Missing optional values with no default
   may remain omitted. Some invalid integer/boolean values produce a warning and a
   default, including a null default. Preserve that result plus `reference-fallback`
   provenance; do not falsely describe universal rejection as reference behavior.
   Syntax/interpolation/required-section failures remain distinct. See
   `client/configreader.py:256` and `:376`.
4. Materialize effective source/filter/action/policy objects. Expressions requiring
   administrator Python, custom getters or external resolution remain typed deferred
   assets until the selected trusted activation phase. Inspect may identify them and
   their dependency profile; it must not evaluate them to manufacture a resolved value.

Native strict validation remains a named native-profile behavior. Import inspection
reports all reference fallbacks and deferred values. It blocks complete migration when
a consumed required value cannot be represented or activated under the chosen profile.
It does not replace an imported value with a convenient native default.

## Open namespaces and option accounting

The source inventory has typed reader/backend options, active stock assignments and
filter/action parameter definitions. All three sets remain represented:

| Inventory family | Canonical owner and treatment |
|---|---|
| Early/global logging, PID/socket and thread values | Startup/global objects, with phase-specific defaults and restart/reconfigure capability. Socket path is an endpoint selection, not a source-file mutation. |
| Jail enable/backend/filter/action/source selection | Jail graph edges and ordered definition instances; disabled definitions stay in the source graph and migration manifest. |
| Retry/time/history options | Typed policy objects with raw duration/expression provenance; D4 owns permanent duration, fractions, retry aggregation and history semantics. |
| File/journal/encoding/timezone options | Source instance and decoder/date context; retain backend-specific Init parameters and environment inputs. |
| Ignore addresses, commands and cache parameters | Ignore-policy objects; command/cache expressions are deferred assets with explicit execution capability. |
| Filter regex/prefix/ignore/maxlines/date/modes | Filter definition and parameter graph; D1 owns actual language/context semantics. |
| Action Definition/Init, family conditionals and custom options | Ordered action instances and compatibility parameter graph; D2/D3 own interpretation and effects. |
| Include, stock path and interpolation helpers | Ordered source-graph nodes and resolution inputs; platform-specific files remain profile-qualified, not deleted. |
| Unrecognized or custom namespace members | Retain exact name/value/provenance and consumed-by edges. Classify as typed, delegated, reference-ignored, or unresolved. No name-only whitelist may discard extension parameters. |

An assignment proven unused by the selected reference consumer may be reported as
`reference-ignored`, with the consumer/profile evidence. Merely failing to recognize
its name is insufficient. A consumed unknown option is an unresolved blocker.
Secret-bearing parameters retain semantic identity but diagnostics and ordinary exports
use redacted references; privileged migration export must explicitly include the required
secret material through its protected asset channel. Redaction cannot masquerade as
lossless secret migration.

The companion probe emits a row for every inventoried command, typed option, active
stock assignment, catalog option, client alias and diagnostic option. Rows retain source
anchors and existing requirement IDs. Their presence is accounting, not proof that every
dynamic option combination has been semantically expanded.

## Runtime overlay and reload transaction

Runtime changes form an append-only logical overlay with operation ID, actor, time,
base generation, target, typed set/add/remove operation, insertion order and origin.
They do not rewrite imported source files. Read APIs distinguish `source`, `effective`,
`runtime-overlay`, and `prepared` views. The migration snapshot binds all relevant
revisions; two machines with identical files but different runtime overlays differ.

Native `config.reload` requires an explicit overlay policy:
`preserve`, `discard-affected`, or `reference-1.1.1`. The first two are explicit native
modes. The adapter selects `reference-1.1.1`, defined by the table below and the probe's
machine-readable `reload_property_matrix`. Every typed inventoried property has a row,
including startup-only and indirect inputs. The table describes **effective stream
presence**, not merely whether a key appears in one file. Defaults and inheritance can
emit setters even when the local key is absent. Even a targeted CLI reload includes the
global stream (`client/configurator.py:78`–`:91`).

For native `preserve`, resolve the new source graph first, then replay the affected
ordered overlay operations against stable target identities. A removed/incompatible
target rejects preparation with a named target/type conflict; it is not silently
discarded or retargeted. `discard-affected` excludes those targets' old overlay entries
from the new effective revision while retaining their historical audit records;
unaffected targets retain their overlays. In `reference-1.1.1`, use the selected
reset/retain/merge/reconcile rules to derive the effective state and mark superseded
overlay entries in the new revision. All policies retain the old immutable generation
for provenance; none deletes historical mutations to pretend they never occurred.

| Property group | Same-instance reference reload and acceptance |
|---|---|
| `failregex`, `ignoreregex`, `ignoreip` | Begin clears exactly these lists; additions rebuild them in stream order. Omit all additions → empty, even with a runtime overlay. `server/filter.py:141`. |
| `maxretry`, `maxmatches`, `findtime`, `usedns`, `maxlines`, `prefregex`, `datepattern`, `logtimezone`, `logencoding`, `ignoreself`, `ignorecommand`, `ignorecache`, `bantime` | No generic scalar reset. Omitted effective setter retains the old value; supplied setter uses its consumer conversion and side effects. Empty is consumer-specific: empty date pattern creates an empty detector, whereas null disables it; empty ignore-cache disables the cache. `server/filter.py:148`, `:302`, `:441`; `server/server.py:359`–`:522`. |
| `bantime.*` | Per-key merge; omitted key retained. Empty becomes null/removes the key, except `increment` reinserts false. Formula/factor/multiplier changes recompute derived state; inspect never evaluates them. Unknown suffixes remain an open namespace. `server/jail.py:225`. |
| `logpath` | Begin records old paths; re-added path preserves its existing container/cursor even if tail changes; new paths apply head/tail/database seek; end removes unrepeated paths. Test two existing paths, one retained and one omitted, plus a new tail path. `server/filter.py:148`, `:1018`. |
| `journalmatch` | Generic reset does not clear it. Concrete systemd backend appends groups, including repeated groups, to its Python list; `+` denotes disjunction. Omission retains groups. Invalid additions restore prior groups or report restore failure. Backend library interpretation is a separate P3 check. `server/filtersystemd.py:211`, `:228`. |
| Ordered action instances | Existing instance with both `reload` and `clearAllParams` clears parameters and is marked for end reload. End retains only marked entries; unmarked instances are flushed/stopped/removed. Source also leaves newly created/replaced entries and custom reload-without-clear entries unmarked. Preserve these source branches in P4 recorder comparisons; do not invent universal instance preservation. `server/server.py:508`; `server/actions.py:105`, `:151`. |
| Enable/filter/backend/no-log controls | Reader determines emitted graph; same complete backend selector reuses jail, changed selector recreates it. Untouched affected jails are removed. Constructor Init/environment inputs are not reapplied to a reused source. `client/jailreader.py:257`; `server/server.py:237`, `:296`; `server/filtersystemd.py:111`. |
| Runtime `idle` | Reload begin sets idle; successful start resumes even if previously idle. Failed streams retain their actual partial terminal state for diagnosis. `server/server.py:263`, `:296`. |
| Logging, IPv6, thread, DB retention | Apply emitted setters in ordered global stream. Both full and targeted CLI reload may override runtime values. Disabled-DB retention setters log and return null without applying a change. Thread stack size concerns subsequent threads. `client/fail2banreader.py:79`; `server/transmitter.py:190`–`:213`. |
| `dbfile` | Same filename/already-disabled none is no-op; changing database while any jails exist raises. Otherwise opening/disabling is an explicit resource transition. Test same/different/none separately. `server/server.py:828`. |
| Socket/PID and indirect include/helper/cache inputs | Startup/client endpoint or consuming-field inputs, not invented independent reload setters. Preserve provenance and evaluate the actual consumer's row. A different client socket selects a different endpoint, not relocation of a running endpoint. `client/fail2banreader.py:42`; `client/configreader.py:206`, `:381`. |

Restart/backend replacement uses constructor state plus the newly emitted stream.
Continuity of failures, source positions and bans is governed by the runtime/migration
contract; it cannot be inferred from the scalar table. All matrix rows include concrete
acceptance predicates and source anchors. Only the harmless base-filter reset/scalar
case has been executed here; file/backend/action/restart branches are source-inspected.

The transaction boundary is:

1. `inspect` records assets, values, diagnostics and unresolved consumers without
   evaluating imported executable content. `prepare` resolves allowed static data and
   computes a per-object change plan against one immutable generation.
2. Validate capabilities, schema, source/asset hashes, dependency profile and required
   runtime-overlay policy. Prepare fallible local resources without transferring live
   ownership or issuing external actions. Any unavoidable external preparation is an
   explicitly marked effect, not part of a promise of side-effect-free inspection.
3. Acquire the coordinator barrier and the runtime contract's one ordered SQLite writer;
   recheck base generation, overlay revision and asset fingerprints. Use WAL,
   `synchronous=FULL` and foreign keys for the full profile. In **one SQL transaction**
   persist the new generation metadata, resolved graph/asset bindings, selected overlay
   revision, source/ticket barrier state, desired ownership changes and ordered pending
   action intents. Concurrent stale requests receive `E_STALE`, never an implicit rebase.
4. Publish/acknowledge the immutable generation only after that transaction commits.
   External start/reload/stop/unban work follows its ordered action barrier and journaled
   outcomes. Keep `publication=prepared|committed|rejected` separate from
   `effects=pending|converged|degraded|uncertain` in the response.
   Successful scalar publication is not proof that all protection effects converged.
5. Before publication/effects, validation failure leaves the old generation and ownership
   intact. After an effect starts, rollback is a new compensating plan with observed
   outcomes; it cannot promise to undo notifications or provider effects atomically.
   Effect dispatch follows its durable intent; receipt/outcome commits are subsequent
   transactions. A crash after dispatch can leave an uncertain outcome. Stale-generation
   receipts cannot overwrite newer desired ownership. Recovery requires idempotent
   readback or explicit manual resolution as specified in runtime contract section 5.

Reference reload is not itself an atomic rollback guarantee. The client validates the
new config before sending it, but transmitter reload calls begin, executes a stream and
calls end in `finally`. The server may remove untouched jails and execute requested
unban/restart effects. See `client/fail2banclient.py:309`,
`server/transmitter.py:102`, and `server/server.py:296`. Native stronger transactional
behavior is explicit; the legacy mode retains the observed successful command intent
and exposes any intentional failure-path difference as a named contract.

`multi-set` and `server-stream` map to ordered operations with per-step outcomes, not
to an invented all-or-nothing transaction. Their partial-failure/reload interaction is
a required compatibility fixture. No successful prefix of a failed stream is discarded
from the audit trail.

## D7: adapter identity and operation envelope

Select `fail2zig-fail2ban` as the optional adapter executable. Its initial documented
profile is `upstream-1.1.1`, selected by `--reference-profile`; packaged profile metadata
records the reference commit and target fail2zig build. No executable named
`fail2ban-client` is replaced automatically. Operators change automation to the explicit
adapter path or deliberately manage their own wrapper.

Default `--format legacy` preserves the pinned CLI command shapes and relevant textual
output. `--format json` provides the native versioned operation envelope. Adapter-only
options are recognized before delegating remaining arguments to the legacy grammar.
Their spelling is deliberately outside current upstream options; conflicts in later
reference versions require another profile. Interactive tokenization is a separately
tested legacy CLI workflow, not permission to invoke a shell.

The adapter speaks the versioned native IPC interface. It never exposes or promises
fail2ban pickle/socket wire compatibility. Existing native IPC remains versioned through
an explicit capability handshake; unsupported operation/schema versions return a typed
error before mutation. Current `shared/protocol.zig:14` has only seven native command
tags, and `engine/net/commands.zig` returns an unimplemented reload response. Adding the
adapter name alone cannot close the command ledger.

| Request field | Contract |
|---|---|
| `schema_version`, `reference_profile` | Versioned native envelope and compatibility semantics, independent of product release version. |
| `request_id`, `actor`, `intent` | Stable operation identity, authenticated local principal and declared inspect/read/mutate/trusted-extension intent. The daemon derives actual credentials; a supplied actor string is not authorization. |
| `base_generation`, `overlay_revision` | Preconditions for mutations and consistent snapshots; absent is allowed only where that operation explicitly permits it. |
| `operation`, `target`, `arguments` | Structured operation family, jail/action/source target and typed ordered arguments. No Python object or arbitrary executable callback in frames. |
| `deadline`, `capabilities` | Validated request deadline and admitted capability references. Client claims do not grant capabilities. |
| `legacy_context` | Parsed alias, flavor, separator, ordering and profile needed for formatting; never used to bypass native validation. |

Product identity is truthful: `version` returns the actual fail2zig daemon version,
and adapter version/help identifies fail2zig and the reference profile. It must not
report itself as a running fail2ban 1.1.1 process. Version-identifying output is an
explicit migration difference, covered by identity fixtures. Other formatting uses
the reference command's meaning and data shape, not substituted product claims.

## Operator operation families

| Legacy surface | Structured operation and required distinctions |
|---|---|
| Server start/restart/stop; jail add/start/restart/stop | Separate service and jail lifecycle operations. `stop --all` stops jails without terminating the daemon. Jail restart aliases reload/restart with preserved flags. Service-manager profile and foreground/background semantics remain required. |
| reload and flags | `config.reload` with target, restart/unban/if-exists flags, overlay policy and generation preconditions. Unknown jail and explicitly tolerated absence are distinct. |
| banned/unban across all jails; jail banip/unbanip/banned | Typed ban query/acquire/release operations preserving scope, history deletion intent, absent reporting, list/single-result shape, separator and time ordering. |
| attempt | `ticket.submit_manual` preserving identity and ordered failure metadata; not an implicit direct enforcement call. |
| status and stats/statistic/statistics | Generation-bound status/statistics snapshots. Basic/short/stats and Cymru flavors remain distinct. Cymru enrichment requires explicit external-resolution capability and later resolver fixtures; it cannot silently become basic status. |
| Logging/database/thread/global getters and setters | Typed config accessors with exact runtime/startup capability. `flushlogs` is a reopen operation. DB disable, purge/retention and restart restrictions are retained. |
| Jail scalar and collection getters/setters | Typed scalar writes and ordered add/remove/index operations. Preserve DNS/date/prefix/multiline/time/history fields and backend-specific journal/path behavior. |
| Action add/delete/list | Attach/detach admitted instances; list cached instance names. Attach/delete can change protection and invoke lifecycle effects. |
| Action property/method access and enumeration | Trusted extension operations described below. A lexical `get` is not proof of purity. |
| ping/echo/version/server-status | Local health, echoed tokens, truthful artifact identity and readiness; readiness is not protection convergence. |
| multi-set/server-stream/config-error/sleep | Typed internal ordered stream, diagnostic report and delay operations, retained with authenticated caller/admission constraints. Internal naming does not remove an inventoried requirement. |
| Client flags and diagnostic options | Local parsing/dump/validation, endpoint/process/deadline/verbosity/interactive workflows and `diagnostic.filter.evaluate`; each alias and combination retains its own source mapping. |

The probe's machine-readable command mapping covers every existing inventory row.
The probe additionally emits finite/open `dynamic_parameter_domains`, including eight
reload-flag subsets and their target/order acceptance matrix. These select argument,
output and error behavior; they are not claimed executed comparisons.

| Domain | Selected exact contract |
|---|---|
| `bantime.<EXTRA>` | Declared keys: increment, factor, formula, multipliers, maxtime, rndtime, overalljails. Arbitrary suffixes remain stored/open; derived evformula/evmultipliers are not silently excluded if explicitly accessed. Empty/removal and executable expression semantics follow the reload matrix and trusted policy profile. |
| Thread | One declared option, stacksize in KiB. Structured argument is an options dictionary. Unknown key raises legacy KeyError (`E_VALUE`); a preceding dictionary item may already have applied. OS size constraints are profile-qualified. Getter returns dictionary. |
| Status/statistics | basic, short, stats, cymru; unknown strings warn and follow non-short/non-stats fallback. Cymru requires admitted resolver. stats/statistic/statistics share server data, but only stats/statistics use the table beautifier; singular statistic retains raw rendering. Preserve alias before formatting and ASCII/Unicode encoding behavior. |
| Ban output | `--with-time` selects timed rows/newline rendering; another first extra token is an arbitrary separator, including empty. `banned` has list/one-ID scalar/multiple-ID ordered list shapes. `--report-absent` changes unban error policy; `--all` scope stays explicit. |
| Reload | Leading --restart/--unban/--if-exists before optional jail/--all. All eight subsets × all/present/absent target are acceptance cases; repeated flags are membership-idempotent, permutations preserve unban-before-restart, flags after a target with extra tokens fail parsing. |
| Booleans/DNS | usedns yes/warn/no/raw, case-folded; invalid string logs ERROR and succeeds with the `no` fallback. `_as_bool` true set is 1/on/true/yes; all other strings false. Config-reader boolean conversion has its own warning/default grammar. idle is strictly case-sensitive on/off. allowipv6 only exact auto selects automatic detection. |
| Logging/backend/numeric text | Reserved logging targets include SYSLOG, STDOUT/SYSOUT, STDERR, SYSTEMD-JOURNAL, INHERITED plus open file paths/options. Levels include standard/custom declared names plus consumer-resolved numeric/attribute domain. Backend finite selectors auto/pyinotify/polling/systemd plus open Init parameters; unavailable dependencies remain profile gates. Regex/date/codec/duration/identifier/path domains remain typed open languages, with no invented 128-retry ceiling. |
| Action member | All names accepted by actual getattr/setattr/dir, including explicit private access; enumeration filters underscore names and classifies callability after descriptors. Method args are JSON-object kwargs or omitted `{}`. Preserve per-instance identity, descriptor order, property readback and ordered batch partial outcomes under ABI1. No name whitelist converts a required method into an exclusion. |

The machine rows carry pinned paths, error/output predicates and open-domain rules.
Client aliases remain a complete 28-row parse inventory, with ordered occurrences
retained (last assignment, verbosity accumulation and action selection follow the
pinned parser); diagnostic flags remain 24 rows. P1/P6 must exercise accepted/rejected
combinations, not just individual switches. Filter/action mode selector expansion is
owned by the fixture contract and source-backed inventory: metadata guards are resolved;
resulting matcher/action behavior remains unexecuted until admitted comparison. Every
open parameter binds its selected consumer,
asset hash, profile and positive/negative/boundary tests; arbitrary possible strings
cannot be enumerated into a misleading finite whitelist.

## Trusted getter boundary

`server/transmitter.py:388` uses `getattr` to distinguish action methods from properties;
`:496` reads properties with `getattr`, and subsequent property/method enumeration also
calls descriptors. Set operations can therefore invoke getters before mutation as well.
These commands can execute administrator extension code even when named `get`.

Define two separate views:

- Static inspect/export reads only the admitted source graph and already materialized
  plain-data snapshot. It never instantiates an extension, calls `dir`/`getattr`/properties,
  evaluates formulas, performs DNS, or fetches remote status. Unknown dynamic values are
  `deferred-trusted-read`, not fabricated null/empty results.
- Trusted runtime property/method access uses an explicit admitted extension instance,
  capability, generation and request identity in the **trusted extension service**.
  This is distinct from the unprivileged matcher. Deadlines,
  effect uncertainty and output conversion follow D2. The adapter must reject with
  `E_TRUST_REQUIRED` when this capability is absent, and retain that command as an open
  full-profile blocker rather than silently downgrading the result.

The full compatibility profile is expected to provide this trusted path. The boundary
does not exclude required getters from parity. Migration runtime export that needs such
values is a separate authorized operation with uncertain/failed fields recorded; file
inspection alone cannot claim a complete live-state snapshot.

Use runtime contract section 3's ABI1: pinned ActionBase/CallingMap/ActionInfo,
per-jail process-local stable adapter graph, committed-state mirrors and typed bounded
callback RPC. Reentrancy requiring the held owner transaction is an explicit error;
never deadlock or silently substitute stale state. Private identity/monkeypatch needs
require extension-specific admitted fixtures and may require expanding the local graph.
The declared development semantic profile is CPython 3.13.5; distribution profiles pin
their actual interpreter/packages separately. Full-profile storage is SQLite; action
identity, uid/gid, capabilities, environment, filesystem/network/dependency hashes and
secret channels are per-instance activation metadata. Service/init integration remains
profile-qualified, not assumed portable from successful local Python probes.

For open getter/method results, the service returns plain typed values when losslessly
representable. Otherwise it performs bounded legacy rendering in the trusted process
and returns tagged `legacy-rendered` text plus original type identity; JSON clients see
that tag, never a fabricated native object. Rendering can execute custom repr/str and
therefore carries the same trust/deadline/effect disposition. No pickle crosses IPC.
Missing member maps AttributeError/`E_NOT_FOUND`; malformed kwargs or JSON maps
`E_VALUE`; extension exceptions retain class identity and redacted detail under
`E_INTERNAL`. A fixture requiring object identity across calls binds a service-local
handle only; exporting arbitrary callable objects is not a wire-compatibility claim.

## Outputs and errors

Native JSON emits one response envelope containing request ID, result/error, generation,
overlay revision, diagnostics and effect disposition. No log chatter enters JSON stdout.
List ordering, null, empty collection, missing field and scalar/list shapes are preserved.
Diagnostic entries have stable code, severity, source span, consumer and redacted detail.
The effective imported result may succeed with a reference fallback warning.

Legacy formatting uses the pinned beautifier contract and CLI stream behavior, with
documented target-version identity. Fail2ban transmitter acknowledgement is `(0, value)`
or `(1, exception)`; this native adapter uses typed data rather than serialized exceptions.
The reference ordinary CLI exits 0 for success and 255 for failure. Some server errors
are beautified to stdout while diagnostic logging uses stderr. Preserve this through
legacy integration fixtures rather than applying native stderr conventions silently.
See `server/transmitter.py:54`, `client/beautifier.py:59`,
`client/beautifier.py:263`, and `client/fail2banclient.py:509`.

| Native code | Meaning | Native JSON exit |
|---|---|---|
| `E_SYNTAX`, `E_VALUE` | Malformed command/arity or argument value | 2 |
| `E_CONFIG` | Required source/semantic configuration cannot resolve | 1 |
| `E_NOT_FOUND`, `E_EXISTS` | Missing or duplicate jail/action/resource | 1 |
| `E_STALE`, `E_BUSY` | Generation/hash changed or conflicting operation active | 1 |
| `E_AUTH`, `E_TRUST_REQUIRED` | Caller unauthorized or executable extension capability absent | 1 |
| `E_UNSUPPORTED`, `E_DEPENDENCY`, `E_LIMIT` | Required capability, dependency or validated capacity unavailable | 1 |
| `E_TRANSPORT` | Unable to establish/use a valid IPC exchange; request effect may be unknown | 3 |
| `E_DEADLINE`, `E_EFFECT_UNCERTAIN` | Operation deadline elapsed or completion/effect cannot be established | 1 |
| `E_INTERNAL` | Unexpected implementation failure | 1 |

Legacy format maps ordinary failure to 255 and formats the corresponding reference
error class where one exists. Unknown jail, duplicate jail and invalid arity have
specific reference texts. New capability/stale/uncertain errors have explicit fail2zig
messages and remain nonzero; they do not invent success or pretend to be reference
exceptions. Exit values are coarse categories; structured error/effect fields carry
the actionable distinction. Cancellation and broken-pipe behavior require dedicated
CLI integration fixtures before certification.

Transport loss or a deadline does not establish whether a mutation occurred. Query by
request ID and generation before retrying a non-idempotent command. A retry deduplicates
accepted delivery only within the durable operation contract; it does not guarantee
exactly-once external effects. Logging sensitive action parameters is prohibited in
ordinary diagnostics even when legacy repr formatting would expose them; this named
security difference must be documented in the adapter profile.

## Prototype and closure recommendation

Run the contract probe with a clean pinned reference checkout and the source audit:

```sh
timeout 60s unshare --user --map-root-user --net -- \
  python3 -I -B tests/parity/config_command_contract_probe.py \
  --reference /tmp/fail2ban-parity-reference-1.1.1 \
  --source-audit .project/parity/source-audit.json \
  --output /tmp/p0-config-command-contract.json
```

The probe uses original harmless config/response data. It tests reference missing/empty/
inherited/default-conversion behavior and selected beautifier values/errors. Separate
pure model checks exercise distinct value states, stale generation/assets, unresolved
consumers, preserved explicit overlay, pre-effect publication and static getter refusal.
Its corpus has eight reader cases, twelve successful-value formatter cases,
three error formatter cases, one base-filter reload case and ten model/accounting
controls (including two original in-memory SQLite transaction controls). These groups
are reported separately; model controls are not reference or candidate behavior evidence.
No daemon, transmitter, action, external getter or service executes. The base filter
case only sets original ordinary parameters and calls its in-memory reset methods.
The models do not prove runtime transactions; formatting values do not prove complete
CLI stdout/stderr/exit compatibility.

Recommend closing the **D6/D7 P0 design/inventory input gate** after independent review:
the reload matrix covers all typed properties; finite declarations and open consumer
domains are explicit; generation publication is bound to the selected SQLite transaction;
trusted getter ABI and dependency profiles are inherited from the finalized runtime
contract; adapter identity, output/error taxonomy and retained namespaces are selected.
The report retains all 112 commands, 60 typed options, 412 stock assignments, 1,215
catalog options, 28 client aliases and 24 diagnostic options without silently dropping
platforms or extensions. This recommendation does not close G1 or any parity row.

Arbitrary Python extensions and seamless handover from an uninstrumented source remain
real feasibility/admission risks in runtime contract sections 3 and 6. They are not
renamed as solved here. Required extension fixtures must prove its exact observable
ABI and admitted privilege/containment profile; an unrepresentable requirement blocks
that profile and full replacement claims. Runtime durability must pass crash-window
tests for generation/source/ticket/intents and stale receipts, not just this SQL model.

P1 must turn the selected domains into controlled traces, including formatter flavors,
aliases, conversion warnings, failed streams and property-getter outcomes. P2 implements
the lossless configuration model; P6 implements native runtime operations, reload and
adapter behavior, all eight reload flag subsets and partial-failure cases; P7 validates
live-overlay export and migration. Provider/getter effects
and real service/init behavior require their authorized integration environments.
No applicable inventoried row closes merely because this document assigns a family.
