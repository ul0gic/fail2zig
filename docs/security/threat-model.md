# Threat model

This document names what fail2zig protects, where untrusted data enters it, and how each
threat is met. Every control below is described in the
[runtime architecture](../architecture.md), the [CLI manual](../man/fail2zig.1) or the
[configuration reference](../man/fail2zig.toml.5); each row says where. Report a
vulnerability through a private
[security advisory](https://github.com/ul0gic/fail2zig/security/advisories/new).

## Scope

fail2zig 0.4.8 runs as one daemon per host under a dedicated non-login service user. It
reads logs, decides bans and owns its own firewall rules in its own network namespace.
The administrative client talks to it over a local Unix socket. This model covers that
daemon, that client and the state file. It does not cover a host whose root account is
already compromised, the services fail2zig watches, or a metrics listener an operator
exposes beyond loopback.

Severity is the worst outcome if the control failed:

| Severity | Outcome |
|----------|---------|
| High | Protection is lost or turned against the host: an attacker is not banned, a legitimate address is banned at scale, or the operator is locked out |
| Medium | Protection degrades or a bounded resource is exhausted, with the cause visible in `status` |
| Low | Information is disclosed or an operator is misled, with no loss of protection |

## Assets

| Asset | Why it matters |
|-------|----------------|
| Firewall rules the daemon owns | They are the protection; a missing rule lets an attacker in, a wrong rule blocks a legitimate user |
| The state file | Source positions, receipts, retry state, ban owners and their origins, history; losing or corrupting it loses protection decisions |
| Operator access to the host | A ban of the operator's own address or the host's addresses locks the operator out |
| Configuration | It decides what is banned, ignored and enforced |
| Daemon availability | A stalled or exhausted daemon stops admitting new detections |
| Addresses in logs, bans and output | They are personal data of the people behind them |

## Trust boundaries

| Boundary | Untrusted side | What crosses it |
|----------|----------------|-----------------|
| Logs | Remote clients who write text into watched log files and the journal | Records that may be crafted, malformed, oversized, flooded, truncated, rotated or replaced |
| Configuration | Whoever can write the configuration file and custom rule files | Keys, address lists, durations, rule files |
| IPC peer | Local processes that can connect to the administration socket | Framed requests: queries and mutations |
| Kernel | Other administrators and tools that change the same firewall | Rules and set elements added, changed or removed outside fail2zig |
| State file | Anything that can write the file or its directory, and crashes or full disks | Rows the daemon reads back at start and during work |

## Threats and controls

### Logs

| Threat | Severity | Control | Established by | Described in |
|--------|----------|---------|----------------|--------------|
| A crafted line injects code or shell syntax into a ban action | High | Rules produce typed subjects, never command strings; log content is never evaluated; there is no runtime interpreter and no shell-script action | Untrusted input stays data | architecture.md, Sources and detection |
| A malformed or oversized record crashes the parser or matches a truncated prefix | High | Records and decoded text have explicit limits; overflow rejects the whole record; invalid encoding is replaced for matching and a damaged address cannot supply a ban target | Healthy admission; untrusted input stays data | architecture.md, Sources and detection; Resource boundaries |
| A forged journal entry claims to come from `sshd` | High | Journal sources check machine identity, root UID, transport and an exact list of root-owned executable paths; a journal tag alone authorizes nothing | Untrusted input stays data | architecture.md, Sources and detection; `journal_executables` in fail2zig.toml(5) |
| A forged line names the host or a trusted address, so fail2zig bans it | High | `ignoreip`, runtime ignore entries and `ignoreself` (on by default) exclude those addresses at admission; a detection of an ignored address creates no ban | Healthy admission | `ignoreip`, `ignoreself` in fail2zig.toml(5); architecture.md, Sources and detection |
| A flood of distinct addresses exhausts tracking and stalls the jail | Medium | Bounded shared pools; the oldest idle tracked subject is evicted inline so new attackers are still tracked; live bans are never evicted; evictions are counted and logged | Healthy admission; bounded resources | `maxretry` in fail2zig.toml(5); architecture.md, Resource boundaries |
| A flood of bans fills the live-ban pool or the state file | Medium | 65,536 live bans across all jails, refused beyond that as retryable backpressure with the cause in `status`; the state file is capped at 1 GiB, a full file pauses ingestion while rules stay in place | Durable receipts; firewall ownership | architecture.md, Resource boundaries; `state_file` in fail2zig.toml(5) |
| An attacker truncates, rotates or replaces a log to erase evidence or force a re-read | Medium | Lost continuity is refused, never reset silently: the source pauses until `repair-source` acknowledges the loss, or, under `on_truncation = "restart"`, resumes with a durable loss event | Source checkpoints | `on_truncation` in fail2zig.toml(5); REPAIR-SOURCE in fail2zig(1) |
| A crash mid-burst loses or double-counts records | Medium | A record is receipted before processing; a group of records is acknowledged only after its single `fsync` returns; a refused record is retried alone | Durable receipts; SQLite transaction ownership | architecture.md, Processing and durable state |
| A repeat offender waits out a long ban and returns as a first-time offender | Low | Escalation decay is measured from the ban's end, never during a live ban; an `unban` clears the failure window but keeps the escalation count | Healthy admission | `bantime_increment_decay` in fail2zig.toml(5); `unban` in fail2zig(1) |

### Configuration

| Threat | Severity | Control | Established by | Described in |
|--------|----------|---------|----------------|--------------|
| A typo or unknown key silently changes behavior | Medium | Unknown keys and sections are rejected with line and column; `--validate-config` checks without starting | Untrusted input stays data | fail2zig.toml(5), DESCRIPTION |
| An address is both banned and ignored, so the outcome depends on order | Medium | An address in both the effective `ignoreip` and `banip` of a jail is refused at start and rejected on reload | Firewall ownership | `banip` in fail2zig.toml(5) |
| A timed configuration entry never expires because the host reloads on a schedule | Medium | The first-applied time and deadline are stored per entry; reloads and restarts read the stored deadline and never restart it | Durable state is the one authority | TIMED ENTRIES in fail2zig.toml(5); architecture.md, Sources and detection |
| A writable custom rule file lets another user change detection | High | Rule files must be owned by root or the daemon user, not group or other writable, regular files opened without following a final symlink, at most 4096 bytes | Untrusted input stays data | `rule_files` in fail2zig.toml(5) |
| An invalid reload half-applies and leaves jails in a mixed state | Medium | The whole proposal is validated first; any failure rejects it and the running generation is untouched; removed jails go last | SQLite transaction ownership | `reload` in fail2zig(1); architecture.md, Administration and privileges |

### IPC peer

| Threat | Severity | Control | Established by | Described in |
|--------|----------|---------|----------------|--------------|
| An unprivileged local user bans, unbans or reloads | High | The socket is mode 0660; mutations require uid 0 or the daemon uid, checked from `SO_PEERCRED` peer credentials; the socket directory must not be group or other writable | Authorization at the owning component | COMMANDS and FILES in fail2zig(1); architecture.md, Administration and privileges |
| A monitoring user reads addresses and paths they should not see | Low | Group members get read-only queries; addresses and paths are printed as `<redacted>` for them | Authorization at the owning component | `ignore list`, `config` and `status` in fail2zig(1) |
| An operator bans their own SSH peer, loopback or the host | High | The client's lockout guard refuses those targets, and networks containing them, unless `--force`; the guard is a convenience, not an authorization boundary | Healthy admission | `ban` in fail2zig(1); `ignoreself` in fail2zig.toml(5) |
| A mutation leaves no trace of who made it | Low | Every mutation request writes one audit log line with command, target, jail, peer uid and outcome; `admin_requests` is the durable record | Authorization at the owning component | COMMANDS in fail2zig(1); architecture.md, Administration and privileges |
| A malformed or oversized frame crashes the daemon | Medium | Administrative frames have explicit limits | Untrusted input stays data | architecture.md, Resource boundaries |
| A retried `repair-source` repairs twice | Low | The token replays the committed outcome without a second repair; a different token after a repair is refused | SQLite transaction ownership | REPAIR-SOURCE in fail2zig(1) |

### Kernel

| Threat | Severity | Control | Established by | Described in |
|--------|----------|---------|----------------|--------------|
| Another tool flushes or deletes fail2zig's elements | High | Protection is confirmed only by readback of owned kernel state, re-read on a 5 s cadence; an owned element a readback finds missing is dispatched again; `status` reports the readback's age | Firewall ownership with kernel readback | architecture.md, Enforcement |
| fail2zig removes or changes rules it does not own | High | Only scoped rules that validate as the daemon's own are repaired or removed; anything else stays foreign | Firewall ownership with kernel readback | architecture.md, Enforcement |
| A ban is reported as installed when it is not | Medium | A policy decision is never reported as protection; uncertain outcomes stay visible until a readback settles them | Firewall ownership with kernel readback | architecture.md, Enforcement; `status` in fail2zig(1) |
| Rules land in the wrong network namespace | Medium | The daemon verifies its recorded namespace selector and never enters another namespace | Firewall ownership | `firewall_namespace` in fail2zig.toml(5) |
| A stop or restart opens a window with no rules | Medium | A stop leaves owned rules in the kernel with their timeouts; the next start reconciles them; withdrawal is an explicit command | Firewall ownership | DESCRIPTION and `firewall withdraw` in fail2zig(1); architecture.md, Enforcement |

### State file

| Threat | Severity | Control | Established by | Described in |
|--------|----------|---------|----------------|--------------|
| Corrupt or unsupported state is used as if valid | High | Corrupt state, an unsupported schema and unsafe generations refuse the start rather than reset; schema upgrades take a coherent backup first | Durable state is the one authority | architecture.md, Processing and durable state; SERVICE ACCOUNT AND UPGRADE in fail2zig(1) |
| Another user writes the state file | High | The state directory and database must belong to the daemon uid with no group or other write access; the file is created mode 0600 | Authorization at the owning component | FILES in fail2zig(1); `state_file` in fail2zig.toml(5) |
| A second daemon writes the same state | High | One daemon owns the state lock; one storage worker owns every transaction | SQLite transaction ownership | architecture.md, Processing and durable state |
| A full disk corrupts state or drops protection | Medium | A full file is a retryable storage failure: ingestion pauses, rules stay in place, `status` shows the storage phase | Durable receipts | architecture.md, Resource boundaries |

### Other surfaces

| Threat | Severity | Control | Established by | Described in |
|--------|----------|---------|----------------|--------------|
| The metrics listener exposes state to the network | Low | It binds to 127.0.0.1 by default and can be disabled with `metrics_enabled = false` | Least exposure | `metrics_bind`, `metrics_enabled` in fail2zig.toml(5) |
| A compromised daemon gains root | High | The service runs as a non-login user with only the capabilities enforcement and log access need, under systemd filesystem and syscall restrictions | Least privilege | architecture.md, Administration and privileges |
| A support bundle leaks addresses | Low | Addresses are replaced by per-bundle keyed hashes and paths other than log paths are hidden unless the operator opts in | Least exposure | SUPPORT-BUNDLE in fail2zig(1) |
| Daemon log lines leak raw attacker payloads or break a log pipeline | Low | Encoding warnings are rate-limited and never print raw payloads; in JSON mode every line is one object and a cut line stays valid | Untrusted input stays data | architecture.md, Sources and detection; `log_format` in fail2zig.toml(5) |

## Accepted risks

- The lockout guard runs in the client. A caller with `--force`, or one that speaks the socket protocol directly, is limited only by the socket's authorization.
- A host address assigned after the last start or reload is not `self` until the next reload.
- Under tracking-pool pressure an idle partial count is evicted, so a very slow attacker can reset its own count. Live bans are never evicted.
- A `banip` entry replaces an existing ban's expiry with its own, even when the replaced ban would have lasted longer.
- Host-name `ignoreip` entries trust the system resolver.
