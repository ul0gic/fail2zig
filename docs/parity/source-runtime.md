# Source foundations and native replacement obligations

Updated 2026-09-12. These are component findings and retained invariants. Legacy staged sessions
still use Python/dynamic libsystemd. Their native replacements now join an explicit
[log-only daemon preview](native-runtime.md) with embedded SQLite, durable retry decisions and
actual file/restart acceptance. The default daemon and full N2 obligations remain distinct.
See [component status](p2-components.md) and [runtime contract](runtime-contract.md).

## Occurrences, commit and retry

source_record.zig distinguishes data from a baseline checkpoint and carries source/occurrence
identity, cursor, raw hash, optional path and authoritative journal microseconds. Borrowed
record lifetime and checkpoint acknowledgment are separate from merely discovering a position.
A source cursor is acknowledged only after disposition, relevant state and intent commit.

record_pipeline stages processing, record_store checks revisions/commits, then the processor
publishes. Schema 2 supports named shared checkpoints alongside jail state: an expected
revision on a read is still a transaction dependency; null payload does not waive validation.
Revision zero depends on absence. Stale shared state invalidates readiness; retry reloads it.
Committed occurrence replay does not rewrite shared state. Preserve rollback/dedup/CAS tests.

Native receipt admission now explicitly activates schema 3: a bounded pending observation
commits before processor preparation, without advancing source progress or emitting an intent.
The outcome transaction saves signed receipt microseconds/generation and removes pending
state atomically. Restart reuses the saved time after validating the occurrence binding;
a first observation which never committed cannot be recovered. Native pipeline opt-in owns
capture and supplies `Record.receipt_time`. Ordinary schema-2 open does not activate the upgrade.
The coordinator still must enumerate every pending source and verify its recovery anchor.
File/pipeline/SQLite tests exercise this boundary with a time processor fixture; production
source processing, journal integration and daemon activation remain incomplete.

An additional native built-in detector and internal file configuration projection now exist.
They reuse the 14 external-service filters, retain exact admitted time/rule/address evidence,
validate explicit body/source settings and static ignores, and bind detector configuration to
source generations. The native file session now passes its actual decoded slice to this
consumer and commits typed failure evidence with time, checkpoint/cursor and receipt deletion.
Explicit schema 6 adds detached validated detector rows with binary IP family/address and
rule identity; schema-4/5 migration is atomic. The focused `test-native-detection` gate covers
all seven codecs, rollback/restart, corruption and process death around commit. Retry/correlation
state and daemon cutover remain incomplete; a candidate does not create a ban intent.
Recidive remains an internal confirmed-ban consumer. Journal detection uses the separate
origin-qualified consumer described below.

Backward wall-clock recovery now has an approved automatic policy. Explicit schema 7 stores
the greatest durable receipt time independently of detailed records; migration seeds it from
existing committed and pending receipts. Native admission pauses while the clock is behind
that boundary. A serialized recovery driver uses bounded monotonic retries and resumes only
after storage, state, ownership and source validation, checking time again between stages.
Original receipts and source positions are preserved; recovery does not extend ban deadlines.
Corruption remains an intervention condition. Unavailable persistence still refuses startup,
including when startup first waited for the clock. File continuity, pending identities and
empty journal start boundaries participate in validation. Each pending row is detached before
source IO, so journal commands cannot hold a SQLite read snapshot open; concurrent database
changes or a WAL reset conservatively restart validation. These are tested native components.
The active daemon, real firewall recovery and operator health wiring remain integration work.

The new native file session now consumes an actual native processor with a fixed versioned
checkpoint. It restores saved tail positions, verifies pending record bindings without
acknowledgment, and samples processing time after receipt durability. Explicit schema 4 adds
typed original/effective timestamp and outcome columns with detached validated reads. These
components are tested; the active daemon and legacy sessions have not selected this path.

Native syslog year inference is explicitly enabled per field with a fixed UTC offset. It
uses durable receipt, rejects equal-distance candidates and then applies existing time
admission without substituting another year. Explicit schema-5 activation preserves the
selected year in typed outcomes; ordinary schema-4 open/admission does not enable inference
storage. Old rows retain NULL inference provenance. Named zones/DST, automatic generation
migration and public source configuration mapping remain open.

Replace helper serialization/state with native versioned checkpoints. Preserve immutable
source/configuration generation bindings and reject stale prepared work. Embedded SQLite
retains the durable boundary. No Python ABI or exact timestamp bit identity is required to
retain correct source time/occurrence behavior.

## Files

Preserve per-file incarnation identity, discovery, hardlink alias handling, bounded fair polling,
explicit startup/live/head/tail semantics, partial records, rotation and truncation detection.
A candidate position must not be mistaken for a durable cursor. Permission, delayed-file,
size/capacity and read errors must remain visible source health, with defined retry behavior.

Framing must return complete supported character/code-unit boundaries and raw byte offsets,
including BOM and incremental decoding. Malformed/unsupported encodings need an explicit
outcome, not guessed cursor advancement. Keep valid partial tails for later data. State
restart/tail baseline reset behavior explicitly and reject unsupported checkpoint versions.

FileSource now offers setNativeFraming, binding its native framing version, encoding and
record limit to the caller's semantic configuration hash. This path uses the bounded
source_text module and no helper. It preserves raw byte cursors, waits for complete aligned
LF records and strips only the CR belonging to CRLF. Native decoder/file/SQLite fixtures
cover partial code units, invalid text, binding changes and failed commit/reopen. The legacy
FileSession still selects the Python-backed processor; the daemon has not switched paths.

Document limitations: polling/stat observations cannot detect every truncate-and-regrow event
that occurs entirely between observations. Do not market an absolute no-loss guarantee beyond
the source/filesystem contract. Actual source-to-native-decision/restart tests remain required.

## Journal

Keep meaningful selectors, occurrence/cursor identity, field/priority/time extraction,
rotation/reopen, cursor-not-found and permissions/error handling. Extraction/read/format/size
errors are distinct from a callback failing to commit. Identical journal text does not identify
the same occurrence. Preserve journal microseconds and explicit timezone/receipt provenance.

The current component Reader dynamically opens libsystemd; the active daemon starts
journalctl. Host journald/journalctl is the accepted OS integration. Retain that transport
and qualify invocation/output, complete records, time/fields, cursor semantics, permissions,
retry and durable acknowledgment across intended systems. Preserve useful component
invariants without adopting its dynamic reader implementation. Keep journal-only deployments
in scope; file input is not a substitute. No embedded journal reader or compression-library
build is required. A missing/unusable system tool must produce actionable source health.

The new native_journal_transport/native_journal_session components now implement bounded
journalctl reads, explicit durable tail/empty-time baselines, exact inclusive anchors and
pending-record verification. They feed the actual native processor and receipt pipeline,
preserving complete fields and integer journal timestamps. Positive-prefixed line counts
keep since/cursor queries oldest-first across qualified command versions. Child failures,
stderr diagnostics and incomplete/oversize output do not acknowledge input. No native
journal library or Python helper is introduced. Daemon selection, scheduling and full operational
qualification remain open.

Native journal detection now accepts an explicit local SSH syslog origin profile: a configured
machine ID and installed executable paths, unique journal-supplied origin fields, root UID and
direct syslog transport. Neither SYSLOG_IDENTIFIER nor message text authenticates the sender.
Stdout records are excluded because journal credentials can describe the stream's parent.
See the [systemd field definitions](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.journal-fields.xml).
This trusts the selected local journal/OS transport; it does not authenticate arbitrary imported
JSON or a compromised privileged host. Other transports/deployments need a qualified profile.

Missing, ambiguous and mismatched origins commit typed exclusions without a subject, allowing
later valid records to proceed. Explicit schema 8 preserves previous detection rows and clock
metadata transactionally. The journal configuration plan inherits effective findtime/ignore
settings and binds the qualified consumer to the source generation. Native tests cover failed
commits, reopen, allocation failure, capacity refusal and killed migration. An explicit captured
lab gate also classifies actual OpenSSH records; it is not part of ordinary tests and does not
contact a host. This path is not yet selected by the active daemon.

## Reviewed reference differences

Original file input consisting of Ċ followed by CR/LF, b/newline and a partial tail exposes
misaligned reference offsets in little-endian Unicode. In UTF-16 LE the reference position
is 5 after the first record, while the candidate preserves 6 then reads b to position 10.
For UTF-32 LE the reference leaves 9, while the candidate preserves 12 then reaches 20.
The reference misses the second valid record. Retain the candidate's code-unit alignment.

The original source comparison has 22 agreements and these two reviewed differences across
24 cases. Separate generic framing records 30 agreements/34 cases across 14 codecs; its
additional two differences concern BOM re-encoding offset calculation. For BOM-prefixed
first/newline/second/newline/partial, the candidate ends the second record at byte 28 for
UTF-16 and 56 for UTF-32; reference offsets 30/60 consume bytes from the partial record.
These are explicit correctness differences, not identical-result passes.

Preserve original receipts and separately test native expected outcomes. Wider encodings,
source lifecycle, daemon coordination and real standalone targets remain qualification work.
No old Python-backed comparison or static build proves the replacement ingestion path.
