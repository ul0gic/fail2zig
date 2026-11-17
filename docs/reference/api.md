---
title: 'Monitoring API'
description: 'The HTTP endpoints, every Prometheus metric, the health and status JSON, and the JSON contract of the administrative commands.'
sidebar_position: 5
category: Reference
audience: operator
last_verified: 2026-11-16
---

fail2zig exposes two read interfaces for monitoring. The HTTP listener serves
metrics, status and health to anything that can reach its address. The local
socket serves the administrative commands, whose `--output json` form is the
interface for scripts. Neither can change protection over HTTP; mutations go
through the socket as uid 0 or the daemon's uid.

## HTTP listener

The listener binds `127.0.0.1:9100` by default. `metrics_bind` takes an IPv4
address only, and a value that does not parse stops the daemon at start.
`metrics_enabled = false` removes the listener; see the
[configuration reference](config.md#metrics_enabled).

There is no authentication, no TLS and no peer check. Whoever can reach the
address can read every endpoint, so the bind address is the only access control.
The endpoints are read-only and carry no ban list.

| Endpoint      | Response                                                                                   |
| ------------- | ------------------------------------------------------------------------------------------ |
| `/metrics`    | 200, `text/plain; version=0.0.4`. Prometheus metrics, listed below.                         |
| `/api/status` | 200, `application/json`. The daemon status with paths and addresses redacted.              |
| `/api/health` | 200 when ready, 503 when not, `application/json`.                                          |
| `/api/bans`   | 403, `text/plain`. Ban details are served only through the socket to an administrator.     |
| anything else | 404 `not found`.                                                                           |

```bash
curl --fail http://127.0.0.1:9100/api/health
```

```json
{"schema_version":1,"ready":true,"components":{"config":"ok","storage":"ok","sources":"ok","clock":"ok","enforcement":"ok","admin":"ok"},"cause":null}
```

### Request rules

| Rule                | Value                                                                              |
| ------------------- | ---------------------------------------------------------------------------------- |
| Method              | `GET` only. Any other method, `HEAD` included, returns 405 `only GET`.             |
| Query string        | Ignored.                                                                           |
| Request size        | 8 KiB of headers. A larger request returns 413 `request too large`.                |
| Read deadline       | 5 seconds from accept.                                                             |
| Concurrent clients  | 16. A further connection is closed without a response.                             |
| Accept rate         | 100 connections per second. Excess connections are closed and logged.              |
| Response size       | 64 KiB. A larger body returns 500.                                                 |
| Connection          | One request per connection; every response carries `Connection: close`.            |

Every response, errors included, carries `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`
and `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`. No CORS
headers are sent, so a browser page on another origin cannot read the responses.

### `/api/health`

| Field            | Type           | Meaning                                                                  |
| ---------------- | -------------- | ------------------------------------------------------------------------ |
| `schema_version` | integer        | `1`.                                                                     |
| `ready`          | boolean        | True only when all six components are `ok`.                              |
| `components`     | object         | `config`, `storage`, `sources`, `clock`, `enforcement` and `admin`, each `ok`, `degraded`, `failed` or `unknown`. |
| `cause`          | string or null | The reason given by the first component that is not `ok`.                |

The status code is 200 when `ready` is true and 503 otherwise, so a `degraded` or
`unknown` component also answers 503. An open connection proves neither readiness
nor recent attack activity; read the body.

### `/api/status`

The same object `fail2zig status --output json` prints, in the redacted view that
members of the monitor group see. A field that does not apply is omitted, so test
for presence before reading a value.

| Group              | Fields                                                                                                                                         |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Identity           | `version`, `runtime` (`"native"`), `generation` (64 hex digits), `mutation_revision`, `schema_version` (`1`).                                   |
| Protection         | `state` and `protection` (the same value: `active`, `degraded`, `log-only` or `unknown`), `cause` (`"none"` when clear; an unhealthy, unpaused source's error when nothing else explains it), `protection_cause`. |
| Bans               | `active_bans` (omitted when kernel knowledge is `none`), `total_bans`, `decisions_total`.                                                       |
| Firewall knowledge | `knowledge` (`fresh`, `stale` or `none`), `confirmed_at_us`, `knowledge_age_ms`, `pending_bans`, `oldest_pending_ms`, `overdue_removals`, `oldest_overdue_ms`, `overdue_bookkeeping`, `dump_interrupted`. |
| Storage            | `storage` (the phase, `healthy` in normal operation), `sqlite_code`, `next_retry_ms`, `committed_records`.                                      |
| Sources            | `jails_active`, `unhealthy_sources`, `missing_sources`, `paused_sources`, and the `sources` array.                                             |
| Backend            | `backend`, `effect_backend`, `effect_stage`, `effect_cause`, `effect_mutation`, `effects_uncertain`, `overdue_effects`.                         |
| Worker and clock   | `worker_busy`, `worker_stalled`, `worker_busy_age_ms`, `worker_heartbeat_age_ms`, `clock_uncertain`, `expiry_overdue`, `expiry_uncertain`, `next_committed_expiry_us`. |
| Resources          | `memory_admission_bytes`, `uptime_seconds` (omitted while the clock is uncertain).                                                             |
| State file         | `state_file_bytes`, `state_file_pages` (allocated), `state_file_max_pages`, `state_file_used_pages` (allocated minus SQLite's free pages).       |
| Tracking pool      | `pool_sample_available`, `pool_sample_pending`, `pool_sample_as_of_us`; with a sample, `pool_tracked`, `pool_banned`, `pool_tracking_limit`, `pool_ban_limit`. |

Each entry of `sources` describes one log source: `jail`, `kind`, `state`,
`loss_events`, and when they apply `path`, `on_truncation`, `cause`, `inode`,
`committed_offset`, `observed_size`, `repair` and `last_loss`. `state` is `reading`,
`paused`, `missing`, `waiting` or `broken`; a `waiting` or `broken` entry has no
`path` and names the jail's source error in `cause`. The
[log file lifecycle](../guides/log-lifecycle.md) explains the states.

Fields ending in `_us` are microseconds since the Unix epoch; fields ending in
`_ms` are durations in milliseconds.

## Prometheus metrics

`/metrics` renders gauges and counters only; there are no histograms. Every
series has `HELP` and `TYPE` lines.

### Daemon-wide

These carry no labels and are all gauges.

| Metric                                    | Meaning                                                       |
| ----------------------------------------- | ------------------------------------------------------------- |
| `fail2zig_up`                             | Always `1` while the listener answers.                        |
| `fail2zig_native_storage_healthy`         | `1` when storage is healthy, `0` otherwise.                   |
| `fail2zig_native_committed_records`       | Records committed by the storage worker.                      |
| `fail2zig_native_worker_busy`             | `1` while the storage worker is working.                      |
| `fail2zig_native_worker_busy_age_ms`      | How long the worker has been busy, in milliseconds.           |
| `fail2zig_native_worker_stalled`          | `1` when the worker is considered stalled.                    |
| `fail2zig_native_worker_heartbeat_age_ms` | Milliseconds since the worker's last heartbeat.               |
| `fail2zig_native_clock_uncertain`         | `1` when the daemon cannot trust its clock.                   |
| `fail2zig_native_expiry_overdue`          | `1` when a ban expiry is overdue.                             |
| `fail2zig_native_expiry_uncertain`        | `1` when expiry state is uncertain.                           |
| `fail2zig_state_file_bytes`               | Size of the state file in bytes.                              |
| `fail2zig_state_file_pages`               | Size of the state file in pages; SQLite's limit is 278,528.   |
| `fail2zig_state_file_used_pages`          | Pages in use: the file's pages minus SQLite's free pages. New work waits near 262,144. |
| `fail2zig_pool_sample_available`          | `1` when a tracking-pool sample has been published.           |
| `fail2zig_pool_sample_pending`            | `1` while a new sample is being taken.                        |
| `fail2zig_pool_sample_as_of_seconds`      | Time of the sample, in seconds since the Unix epoch.          |
| `fail2zig_pool_tracked`                   | Addresses tracked in the shared pool.                         |
| `fail2zig_pool_banned`                    | Banned addresses in the shared pool.                          |
| `fail2zig_pool_tracking_limit`            | Tracking capacity, 65,536.                                    |
| `fail2zig_pool_ban_limit`                 | Ban capacity, 65,536.                                         |

The four pool occupancy and limit gauges and `fail2zig_pool_sample_as_of_seconds`
appear only once a sample is available. Alert on
`fail2zig_pool_sample_available` before relying on them.

### Per jail

These carry the label `jail="<name>"`. A jail's series appear when it starts or is
added by a reload and stop when it is removed.

| Metric                                   | Type    | Meaning                                                              |
| ---------------------------------------- | ------- | -------------------------------------------------------------------- |
| `fail2zig_jail_bans_active`              | gauge   | Live bans confirmed in the kernel.                                   |
| `fail2zig_jail_bans_total`               | counter | Bans issued.                                                         |
| `fail2zig_jail_failures_counted_total`   | counter | Failures counted toward a ban.                                       |
| `fail2zig_jail_ignored_detections_total` | counter | Detections skipped because the address is on the ignore list.        |
| `fail2zig_jail_pool_evictions_total`     | counter | Idle addresses evicted from the shared tracking pool.                |
| `fail2zig_jail_source_state`             | gauge   | `0` ok, `1` paused or unhealthy, `2` missing, `3` blocked.           |

### Useful alerts

```text
fail2zig_native_storage_healthy == 0
fail2zig_native_worker_stalled == 1
fail2zig_jail_source_state == 1
fail2zig_state_file_used_pages > 235929
fail2zig_pool_banned / fail2zig_pool_ban_limit > 0.9
```

The page threshold is 90 % of the 262,144-page capacity. Near the capacity new
work waits with `StorageCapacity` while installed rules stay in the kernel and
expiry, unban and cleanup continue; see
[state and resource limits](config.md#state_file).

## JSON from the administrative commands

Every administrative command accepts `--output json`. Use it for automation and
branch on the exit class, not on table text. The commands and their fields are in
the [administration reference](cli-fail2zig-client.md).

### Who may ask what

The socket is mode `0660` and identifies the caller by peer credentials.

| Caller                       | Queries answered                                                                 |
| ---------------------------- | -------------------------------------------------------------------------------- |
| uid 0 or the daemon's uid    | Everything, unredacted, and every mutation.                                      |
| Any other user in the group  | `status`, `config`, `stats`, `ignore list` and loss events, with paths and addresses redacted. |

A group member asking for ban lists, history or the firewall inventory gets code
403, `administrator required for ban, history and firewall details`.

### Pagination

`history` and `firewall show` return pages. `--limit` takes 1 to 256 and defaults
to 64. A response with more rows carries `next_cursor`; pass it back with
`--cursor` to continue.

- A `firewall show` cursor lives 60 seconds, must be used with the same
  `--limit`, and is void once the retained observation changes.
- A `history` cursor has no timer. It is void once the configuration generation
  or the set of owners changes.
- A void cursor returns code 409, `cursor expired or observation changed; restart
  pagination without a cursor`. Start again without `--cursor`.

A response is at most 1 MiB. A page that would exceed it returns code 413,
`response exceeds 1 MiB`; lower `--limit`.

### Errors

A refused or failed query prints one object and exits non-zero:

```json
{"error":{"code":403,"message":"administrator required for ban, history and firewall details"}}
```

| Code | Meaning                                                                                  |
| ---- | ---------------------------------------------------------------------------------------- |
| 400  | The request is malformed: an unknown kind, a bad `--limit`, a malformed cursor.          |
| 403  | The caller is not an administrator, or a mutation came from a uid that may not mutate.   |
| 404  | `unknown jail`.                                                                          |
| 409  | The cursor expired, or the configuration changed during the query.                       |
| 413  | The response would exceed 1 MiB.                                                         |
| 500  | `query source failed`: the daemon could not read what the query needs.                   |
| 503  | `query source is not available`: the daemon has not published that view yet.             |

The command's exit status follows the
[exit classes](cli-fail2zig-client.md#exit-classes): a mutation that was applied
without full confirmation exits 4, one whose outcome is unknown exits 5, and every
other refusal exits 1.

### `stats`

`fail2zig stats --output json` reads the worker's published snapshot. Its
counters accumulate from daemon start and reset on restart.

| Field                                                                                   | Meaning                                                       |
| --------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| `available`, `reason`                                                                   | Whether a snapshot exists; if not, `not_published`, `backend_unavailable` or `log_only`. |
| `backend`, `uptime_seconds`, `snapshot_age_ms`                                          | The firewall backend and the age of this snapshot.            |
| `knowledge`, `knowledge_age_ms`                                                         | How current the daemon's view of the kernel is.               |
| `view_ready`, `view_entries`, `last_observed_installed`                                 | The daemon's view of its installed bans.                      |
| `pending_live_dispatches`, `overdue_blocking_removals`, `overdue_bookkeeping`           | Work waiting on the kernel.                                   |
| `accepted_readbacks`, `dump_interruptions`, `acknowledged_batches`                      | Kernel readbacks and install batches since start.             |
| `events_applied`, `events_dropped`, `view_rebuilds`, `view_restarts`, `incremental_updates` | How the view was kept current.                             |
| `expiry_batches`, `expiries_prepared`                                                   | Ban expiry work.                                              |
| `retirement_batches`, `retry_subjects_retired`, `retry_subjects_examined`, `retirement_pinned_state`, `retirement_pinned_effect`, `retirement_refused` | Cleanup of tracked addresses whose bans ended. |
