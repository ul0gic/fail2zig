# Compatibility work and reference tests

Full fail2ban replacement and migration are under development. The reference is
fail2ban 1.1.1, commit `f60978618a101427b06924fc932b44350fec2b63`.
Current native filter names and successful configuration import do not establish
equivalent behavior for modified filters, action scope, state or automation.

The intended contract is equivalent effective configuration, detection, enforcement
scope, administration and migration continuity on explicitly certified Linux profiles.
Compatibility includes custom assets and retained state. Missing required behavior,
silently skipped settings or unavailable profile evidence prevent certification.

Native fast paths and a full compatibility profile may have different dependencies.
Their dependencies and whole-process performance must be reported separately. No
full-parity, lossless-migration or comparative speed claim follows from the probes below.

## Reproducible initial evidence

See [reference tests](../../tests/parity/README.md) for prerequisites and commands.

| Probe | What it establishes | What it does not establish |
|---|---|---|
| Configuration comparison | Actual values from both readers for six synthetic layering/include/interpolation cases | Complete configuration compatibility; four initial cases differ |
| Reference semantics | Pinned captures, raw identities, networks and worker outcome distinctions | Candidate filter parity or complete worker resource guarantees |
| SQLite snapshots | Read-only backup of synthetic durable history, including committed WAL data | Live export, transient ticket/queue transfer or safe cutover |
| Timing/ticket comparison | Seven actual component comparisons and 23 controlled reference cases | Candidate ingestion timing, scheduler/cleanup integration or enforcement |
| [Action lifecycle](action-contract.md) | Sixteen reference dispatcher cases with original in-memory recorders | Configured action execution, production privilege separation or candidate parity |
| Fixture inventory | Stock source metadata, option variants, record hashes and declared expectations | Condition execution, complete generated tests or detection accuracy |
| [Mode/source contracts](fixture-contract.md) | Mapped definitions/generated families, resolved metadata and repeated config-reader outcomes | Candidate detection or action execution; proposed negatives still need validation |
| [Configuration/operator contracts](config-command-contract.md) | Per-property reload/source domains and harmless reader/formatter observations | Implemented reload, CLI adapter or real effect transactions |
| [Runtime contracts](runtime-contract.md) | Selected IPC/state/migration architecture and original data/transaction controls | Real workers, arbitrary extension compatibility or live state capture |
| [Profile selection](profile-contract.md) | Exact selected userlands/source/package metadata and dependency contract | Installed full-profile recipes, booted kernels or certification |

Executed behavioral fixtures are original synthetic data. Source inventory tools retain
only upstream metadata/hashes and do not execute the upstream sample records or test bodies.
Reference code is read from a separately obtained
checkout; this repository does not vendor upstream source or logs. JSON reports identify
the tested source/artifact, inputs, expected/observed outcomes and environment. Expected
differences remain failures; reference-only passes never become candidate certification.

The current development environment is Debian 13 x86_64 with Zig 0.14.1, Python 3.13.5
and SQLite 3.46.1. Additional distribution/backend profiles require their own pinned
packages and acceptance evidence. Cross-compilation alone does not certify a platform.
