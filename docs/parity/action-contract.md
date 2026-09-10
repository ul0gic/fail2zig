# Action compatibility contract

This is the proposed D2/D3 contract for implementing action compatibility. Its
reference is fail2ban 1.1.1 at
`f60978618a101427b06924fc932b44350fec2b63`. The accompanying probe establishes
16 small reference dispatch cases using original in-memory recorder actions.
It does not implement a privileged executor or certify fail2zig action parity.

The central requirement is to retain the reference action behavior while reporting
what actually happened to protection separately. A reference ticket being marked
banned is insufficient evidence that every action installed its intended effect.
An exception is insufficient evidence that an action installed nothing.

## Identity and context

One action instance belongs to a jail and has a stable instance identifier. Two
invocations of the same action definition with different parameters remain distinct.
A compatible realization can be shared only when its entire enforcement scope is
equivalent; the action name or address alone is insufficient.

The proposed native boundary uses versioned data messages. It does not transport
Python objects, executable callbacks, pickle, or imported code in request frames.
Administrator-owned executable assets are separately identified, hashed and admitted
by the selected compatibility profile at activation.

| Field | Required meaning |
|---|---|
| `schema_version` | Message schema version, initially `1`; unknown versions reject before dispatch. |
| `request_id` | Stable identifier for this operation, retained across delivery attempts. It identifies delivery; it does not guarantee effect deduplication. |
| `daemon_epoch`, `config_generation` | Identify the running owner and immutable effective configuration used to construct the request. |
| `jail_id`, `action_instance_id` | Separate jail and parameterized action identities. |
| `operation` | `start`, `check`, `repair`, `ban`, `prolong`, `reban`, `unban`, `flush`, `reload`, or `stop`; profile capabilities determine availability. |
| `scope` | Subject, address family, ports, protocols, direction, interface, chain/table/namespace, verdict and backend/provider target where applicable. No omitted port means “all ports” unless that is the effective action meaning. |
| `ticket` | Failure identity, optional separate enforcement address/network, effective event time, duration, attempt/retry counts, ban count, retained matches/captures, and restored status. |
| `desired_generation` | Monotonic generation within the owner's scope; distinguishes an old ban request from a newer unban or changed duration. |
| `parameters` | Immutable effective action parameters with source/asset fingerprints. Missing, empty and explicit values remain distinguishable. |
| `limits` | Selected profile's validated input/output/queue/memory/CPU/deadline budgets. Imported action timeout intent remains explicit. |

Failure identity is a tagged value: an address, a network with an explicit prefix,
or a raw identifier. A captured enforcement address is separate from that identity.
Rendering an IPv4 `/0` as `0.0.0.0` must not collapse it into an IPv4 `/32` subject.
D3 owns scope normalization; D4 owns timestamp, duration and ticket semantics.
Permanent duration is explicit, distinct from a finite zero duration and a legacy
unknown historical duration. An unknown historical value needs resolved migration
context before a new enforcement operation is issued.

The native context must provide an equivalent data view for these reference
`ActionInfo` families:

- Identity/time: `fid`, `ip`, `family`, `time`, `bantime`, `bancount`, `restored`.
- Failure data: `failures`, `matches`, and captured `F-*` data.
- Retained history: `ipmatches`, `ipjailmatches`, `ipfailures`, `ipjailfailures`.
- Jail counters: `jail.name`, `jail.banned`, `jail.banned_total`, `jail.found`,
  `jail.found_total`.
- Derived or diagnostic access: `ip-rev`, `ip-host`, `raw-ticket`, and action-specific
  hostname tags. Resolution, formatting, caching and dependency semantics require
  their own contracts; they are not all exercised by this probe.

Each action receives the original logical context. Mutation by one Python action
must not silently alter the next action's view. Pinned `CallingMap` implements
copy-on-write/reset behavior. The probe verifies direct mapping mutation isolation;
it does not establish behavior for mutations of nested objects or arbitrary action
access to the jail object.

A generic Python `ActionBase` extension may access more than these fields through
its jail object. The full compatibility adapter therefore needs an explicit supported
jail/context ABI and extension fixtures. Serializing this table alone does not make
arbitrary Python extensions compatible. Inspect/plan must never instantiate imported
actions, execute descriptors/getters, resolve secret-bearing callbacks, or evaluate
policy code. Trusted activation and trusted runtime export are separate operations.

## Lifecycle and ordering

The following is observed pinned behavior, not an assumption that all operations
share one success or retry rule.

| Operation | Reference behavior and contract |
|---|---|
| Start | Actions start in configured order; an exception is logged and later actions still receive start. No successful-start inference follows from loop completion. |
| Ban | Ticket is admitted to the ban manager before action calls. Actions run in configured order and exceptions do not stop later actions. The ticket's banned flag is set afterward even if an action failed. Python return values such as `False` are not inspected by this dispatcher. |
| Restored ban | An action with `norestored` is skipped. Other actions still receive the restored context. This is policy suppression, not an execution failure. |
| Prolong | Requires an identity currently in the ban manager and an action whose `_prolongable` is true. Restored suppression also applies; failures are caught per action. Duration selection and observer scheduling remain D4/P5 work. |
| Reban | `ActionBase.reban` defaults to `ban`. The Actions reban loop returns immediately on the first exception. It does not have the ordinary ban loop's continue-on-error behavior. Epoch/repair triggers need further fixtures. |
| Unban | Actions run in configured order; failures do not stop later actions. There is no `norestored` skip in this loop. Manual removal pops the reference ticket before action completion, so a remaining effect can outlive the visible ticket. |
| Flush | An action whose flush returns true handles its own flush; other actions fall back to individual unbans. Flush errors and consistency repair need additional fixtures. |
| Stop | Actions stop in reverse configured order and are removed from the reference action registry even when stop raises. |
| Reload/check/repair | Preserve their distinct action-specific semantics, removed-action handling and epochs. These are required contracts, but the probe does not verify them. |

The implementation must preserve ordering within each jail's relevant lifecycle and
scope. Independent work may run concurrently only when dependencies, ordering and
shared realization allow it. Start/reload/stop barriers cannot be overtaken by ordinary
queued operations. A configuration generation remains attached to work already admitted;
reload requires an explicit transfer/cancel/reconcile decision for that work.

These facts are anchored in reference `server/actions.py` at lines 301, 321, 480,
571, 600, 635 and 690; `server/action.py` at lines 181 and 261; and
`server/banmanager.py` at lines 268 and 378. `Ticket.banned` is the integer bitmask
`0x08` in `server/ticket.py:169`, not a boolean-valued property.

## Execution outcome and realized protection

A completion record carries `request_id`, owner/config/desired generations, operation,
execution outcome, action return metadata, observation identity/time, and bounded
diagnostics. It keeps these separate dimensions:

| Dimension | Values and meaning |
|---|---|
| Desired effect | `present`, `absent`, or the specific desired provider/lifecycle state, with exact scope and duration. |
| Execution | `not_dispatched`, `returned`, `raised`, `deadline`, or `transport_lost`. `not_dispatched` includes explicit restored-policy suppression or invalid admission with a reason. |
| Observed effect | `present`, `absent`, `unknown`, or `not_applicable`, with observation source and scope fingerprint. A delivery acknowledgment is not an observation. |
| Reconciliation | `in_sync`, `pending`, `uncertain`, or `blocked`, with the operation or operator decision required next. |
| Reference-facing ticket | The separate reference-compatible admission/count/flag state needed by legacy operations. It must not be advertised as verified protection. |

A native backend can report a checked desired effect as observed only through its
validated backend contract. A Python action returning normally is merely `returned`
when no observer can establish its effect. A normal return of `False` cannot be
silently reinterpreted as the reference dispatcher raising an error. Preserve the
return metadata and report the supported observation separately.

An action can change its target and then raise, time out, or lose its worker reply.
Until there is reliable observation, the result is uncertain. Notification delivery
and other provider side effects may have no safe readback. Retry eligibility then
depends on a declared idempotency/observation contract; it is not implied by an exception.

The recorder probe intentionally demonstrates both a failure before its fake effect
and a failure after that effect. The test can inspect its own in-memory sets. That
privileged test knowledge is not available to a production executor merely because
it knows the method raised.

## Reconciliation, restart and cancellation

Before dispatch, persist sufficient operation intent, owner/generation and previous
observation to reconcile an interrupted operation. Persist dispatch acknowledgment
and result separately. The eventual storage transaction and durability point belong
to the D4 schema; no such production journal exists in this probe.

After worker/daemon restart, enumerate unfinished operations and reconcile each exact
scope against the latest desired generation. Never apply a stale ban result over a
newer unban intent. Observation of another jail's shared effect does not establish
ownership for this jail. Removing one owner must preserve other still-required owners.

For observable idempotent enforcement, read back the scoped effect and converge to
the latest desired state. For an unobservable external effect, retain uncertainty
until an action-specific receipt or explicit operator decision resolves it. Record
why automatic retry is or is not permitted. Do not promise exactly-once arbitrary
shell/Python/provider side effects.

On deadline or cancellation, stop accepting result claims for obsolete generations,
terminate and reap the complete assigned execution process group where supported,
and reconcile effects independently. Worker termination cannot roll back an effect
already installed. Partial output, successful process exit and complete protected
scope are different observations.

The selected activation profile must define administrator identity, privileges,
allowed assets/dependencies, working directory/environment, secret handling,
filesystem/network access and concrete budgets. Reject an unsupported profile before
activation with a blocking diagnostic. A profile label cannot silently remove an
applicable action or alter its effective timeout. This document does not introduce
an unrestricted privileged shell endpoint or a production action worker.

## Reproducible probe

Run from the repository root with the separately verified reference checkout:

```sh
timeout 30s unshare --user --map-root-user --net -- \
  python3 -I -B tests/parity/action_contract_probe.py \
  --reference /tmp/fail2ban-parity-reference-1.1.1 \
  --output /tmp/f2z-p0-action-contract.json
```

The probe checks reference HEAD metadata and a pinned SHA-256 manifest of all 78
reference Python files before and after execution. It records exact source hashes,
Python/kernel, candidate branch/HEAD, script hash and namespace information. It avoids
preexisting bytecode and refuses a report path inside either source checkout.
Namespaces isolate identity and networking; they do not isolate the host filesystem.

Original recorder objects are inserted directly into the reference `_actions` map.
This bypasses extension loading. Private dispatch methods are pinned test seams;
`Actions.run` is called synchronously with its loop disabled to inspect start/stop.
No thread, daemon, database, subprocess command, DNS request, provider request or
firewall operation is started. Audit/helper guards reject attempted external calls.
The tests do not instantiate stock `CommandAction` objects.

Sixteen cases cover ordered start/stop, start failure, ordered ban, failures before
and after fake effect, false return, restored suppression versus unban, three prolong
variants, unban failure, base reban and reban failure, context reset, flush fallback,
and the strict past-expiry unban boundary. Each case also checks ERROR event count,
level and message prefix; the five intentional exception cases each emit one ERROR,
while the false-return case emits none. Full messages are retained as evidence;
complete formatting, tracebacks and other logging levels remain unverified.
JSON retains expected/observed values and records the initial bitmask expectation
correction and private-call limit adjustment.
Exit `0` means these reference cases agree; `1` means a comparison mismatch;
`2` means the probe could not complete.

Still unverified: a production context ABI, dynamic getters/history/DNS views,
start-on-demand families, CommandAction interpolation/check/repair/reload/flush-error
semantics, observer-driven prolong/epochs, privilege separation, process-tree cleanup,
resource exhaustion, durable queues, restart reconciliation, scoped kernel effects,
provider effects, arbitrary extensions and candidate parity. Those remain phase-gate
work, not capabilities established by these sixteen passes.
