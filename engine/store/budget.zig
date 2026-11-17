// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Bounds the state-file pages each kind of write can add and admits or refuses intake against the capacity line.
// Holds: Intake that would take used plus owed pages past 262,144 is refused, and after a refusal reopens only 1,024 pages lower.

const shared = @import("shared");
const store = @import("store.zig");
const effects = @import("../core/native_effect.zig");
const consumer = @import("../core/native_consumer.zig");
const retry = @import("../core/native_retry.zig");
const ignore = @import("../core/native_ignore.zig");
const Error = store.Error;

pub const Class = enum { intake, obligation, reclamation };

pub const capacity_pages: u64 = 262_144;
pub const limit_pages: u64 = capacity_pages + 16_384;
pub const reclamation_pages: u64 = 2_048;
pub const hysteresis_pages: u64 = 1_024;
pub const owed_work_schema: i64 = 29;

// Why: SQLITE_DEFAULT_PAGE_SIZE is 4096 (vendor/sqlite/sqlite3.c:14904) and the store never sets page_size.
const page_bytes: u64 = 4096;
// Why: A table leaf keeps at most the usable size less 35 bytes of payload before spilling to overflow pages (sqlite3.c:76668).
const max_local_bytes: u64 = page_bytes - 35;
// Why: Each overflow page carries the usable size less its 4-byte next-page pointer (sqlite3.c:74664).
const overflow_bytes: u64 = page_bytes - 4;
// Why: balance() leaves a page alone while at least a third of it is in use (sqlite3.c:82368).
const fill_divisor: u64 = 3;
// Why: SQLite limits cell size so at least four cells fit on a page (sqlite3.c:72278).
const min_fanout: u64 = 4;
// Why: balance_nonroot turns at most three siblings into five (sqlite3.c:81492); balance_deeper adds the root's page.
const pages_per_level: u64 = 2;
// Why: Schema version 29 creates 119 b-trees, the sqlite_schema rows with a root page.
const schema_trees: u64 = 119;
// Why: Covers the payload-size, rowid and header-size varints and the 2-byte cell pointer.
const cell_overhead: u64 = 20;
// Why: Serial types up to 2 x 16 MiB + 13 fit a 4-byte varint.
const column_header: u64 = 4;

const max_depth: u64 = blk: {
    var depth: u64 = 1;
    var reach: u64 = min_fanout;
    while (reach < limit_pages) : (depth += 1) reach *= min_fanout;
    break :blk depth;
};
const split_pages: u64 = pages_per_level * max_depth + 1;
const transaction_pages: u64 = schema_trees * split_pages;

pub const Cost = struct {
    cell_bytes: u64 = 0,
    overflow_pages: u64 = 0,

    fn plus(self: Cost, other: Cost) Cost {
        return .{ .cell_bytes = self.cell_bytes +| other.cell_bytes, .overflow_pages = self.overflow_pages +| other.overflow_pages };
    }
    fn times(self: Cost, count: u64) Cost {
        return .{ .cell_bytes = self.cell_bytes *| count, .overflow_pages = self.overflow_pages *| count };
    }
    fn pages(self: Cost) u64 {
        return ((self.cell_bytes *| fill_divisor) +| (page_bytes - 1)) / page_bytes +| self.overflow_pages;
    }
};

fn entry(columns: u64, value_bytes: u64) Cost {
    const payload = cell_overhead + columns * column_header + value_bytes;
    if (payload <= max_local_bytes) return .{ .cell_bytes = payload };
    return .{ .cell_bytes = max_local_bytes, .overflow_pages = (payload + overflow_bytes - 1) / overflow_bytes };
}
fn index(columns: u64, key_bytes: u64) Cost {
    return entry(columns + 1, key_bytes + int);
}

const hash: u64 = 32;
const int: u64 = 8;
const owner_jail: u64 = 64;
const subject: u64 = 16;
const effect_scope: u64 = 24;
const canonical_scope: u64 = 92;
const target_metadata: u64 = 512;
const evidence: u64 = retry.max_evidence_text_bytes;
const attempts: u64 = retry.max_attempts * retry.attempt_bytes;
const record_jail: u64 = 4096;
const source: u64 = store.Limits.source_bytes;
const occurrence: u64 = 16384;
const cursor: u64 = store.Limits.cursor_bytes;
const timestamp_text: u64 = 20;
const disposition: u64 = 64;
const shared_name: u64 = 4096;
const action_intent: u64 = 1024 * 1024;
const config_path: u64 = 4096;
const allowlist_snapshot: u64 = 65536;
const config_jails: u64 = 64;
const ignore_address: u64 = shared.types.IgnoreEntry.max_text_bytes;
const observations_per_intent: u64 = @intCast(store.load_repair.observations_per_intent);

const owner_revision = entry(9, 3 * hash + owner_jail + 5 * int).plus(index(3, hash + owner_jail + int));
const intent_row = entry(11, 4 * hash + 7 * int);
const intent = intent_row.plus(index(1, hash)).plus(index(2, hash + int)).plus(index(1, hash));
const observation = entry(8, 3 * hash + 5 * int).plus(index(1, hash)).plus(index(2, hash + int));

pub const live_owner = owner_revision.plus(intent).plus(observation.times(observations_per_intent)).plus(index(1, hash));
pub const unconfirmed_owner = entry(7, 3 * hash + owner_jail + 2 * int + canonical_scope)
    .plus(index(1, hash)).plus(index(3, 2 * hash + owner_jail)).plus(index(2, owner_jail + hash))
    .plus(index(3, owner_jail + int + hash)).plus(index(2, int + hash))
    .plus(entry(2, int + hash)).plus(index(1, hash))
    .plus(entry(11, hash + source + occurrence + evidence + subject + 6 * int))
    .plus(index(1, hash)).plus(index(2, 2 * int)).plus(index(3, 2 * int + subject)).plus(index(1, int)).plus(index(3, 2 * int + subject))
    .plus(entry(5, owner_jail + subject + 3 * int)).plus(index(3, owner_jail + int + subject))
    .plus(entry(8, subject + 7 * int)).plus(index(2, int + subject)).plus(index(1, int))
    .plus(entry(4, 3 * hash + owner_jail)).plus(index(2, hash + owner_jail));
pub const unsettled_intent = observation.times(observations_per_intent).plus(intent_row);

const ban = entry(9, 3 * hash + owner_jail + 5 * int).plus(index(2, hash + owner_jail)).plus(index(2, owner_jail + hash)).plus(index(2, owner_jail + hash))
    .plus(entry(7, 2 * hash + effect_scope + 3 * int + canonical_scope)).plus(index(1, hash))
    .plus(owner_revision).plus(intent)
    .plus(entry(11, 2 * hash + owner_jail + 7 * int + target_metadata)).plus(index(2, hash + int)).plus(index(1, hash))
    .plus(live_owner).plus(unconfirmed_owner);
const detection = ban
    .plus(entry(8, record_jail + subject + 5 * int + attempts)).plus(index(3, record_jail + int + subject))
    .plus(entry(9, record_jail + source + occurrence + 3 * int + subject + hash + evidence))
    .plus(index(5, record_jail + source + occurrence + int + subject)).plus(index(1, hash));
const record = entry(20, record_jail + source + occurrence + 4 * hash + cursor + 10 * int + timestamp_text + disposition)
    .plus(index(3, record_jail + source + occurrence)).plus(index(4, record_jail + source + hash + int))
    .plus(entry(5, record_jail + source + cursor + occurrence + source)).plus(index(2, record_jail + source))
    .plus(entry(7, record_jail + source + 2 * hash + occurrence + cursor + int)).plus(index(2, record_jail + source))
    .plus(entry(3, record_jail + store.Limits.checkpoint_bytes + int)).plus(index(1, record_jail))
    .plus(entry(3, shared_name + store.Limits.shared_bytes + int)).plus(index(1, shared_name))
    .plus(entry(5, record_jail + source + occurrence + action_intent + disposition)).plus(index(3, record_jail + source + occurrence))
    .plus(entry(9, 4 * int + record_jail + 2 * source + hash + consumer.max_payload).plus(index(5, int + record_jail + 2 * source + hash)).times(consumer.max_deltas))
    .plus(detection.times(store.max_native_detections));
const ignore_entry = entry(6, owner_jail + 4 * int + subject);
const reload = entry(6, 2 * hash + config_path + 3 * int)
    .plus(entry(4, hash + owner_jail + hash + allowlist_snapshot).times(config_jails))
    .plus(entry(6, int + owner_jail + ignore_address + 3 * int).times(config_jails * ignore.max_entries));

pub const record_pages: u64 = transaction_pages + record.pages();
pub const ban_pages: u64 = transaction_pages + ban.pages();
pub const ignore_pages: u64 = transaction_pages + ignore_entry.pages();
pub const reload_pages: u64 = transaction_pages + reload.pages();
pub fn activationPages(owners: u64) u64 {
    return transaction_pages +| ban.times(owners).pages();
}

comptime {
    if (capacity_pages + record_pages > limit_pages - reclamation_pages) @compileError("a record staged above the capacity line must fit below the reclamation reserve");
}

pub fn Methods(comptime Store: type) type {
    return struct {
        pub fn owedPages(self: *Store) Error!u64 {
            var row = try self.statement("SELECT l.live,w.markers,w.unsettled_intents,w.reconciled FROM effect_owner_live l JOIN effect_owed_work w ON w.id=1 WHERE l.id=1;");
            defer row.deinit();
            if (!try row.row()) return error.LiveOwnerCounterInvalid;
            const live = try row.signed(0);
            const markers = try row.signed(1);
            const unsettled = try row.signed(2);
            if (live < 0) return error.LiveOwnerCounterInvalid;
            // Why: Counters not marked reconciled are untrusted, so every live owner counts as unconfirmed and intents as the maximum.
            const trusted = try row.signed(3) == 1 and markers >= 0 and unsettled >= 0;
            const unconfirmed: u64 = @intCast(if (trusted) @max(0, live - markers) else live);
            const pending: u64 = if (trusted) @intCast(unsettled) else effects.max_intents;
            const owed = live_owner.times(@intCast(live)).plus(unconfirmed_owner.times(unconfirmed)).plus(unsettled_intent.times(pending));
            return owed.pages();
        }

        pub fn admitIntake(self: *Store, pages: u64) Error!void {
            if (!self.runtime_limits) return;
            const line = if (self.intake_closed) capacity_pages - hysteresis_pages else capacity_pages;
            if ((try self.usedPages()) +| (try self.owedPages()) +| pages > line) {
                self.intake_closed = true;
                return error.StorageCapacity;
            }
            self.intake_closed = false;
        }

        pub fn assertIntake(self: *Store) Error!void {
            if (!self.runtime_limits or self.admission != .intake) return;
            if ((try self.usedPages()) +| (try self.owedPages()) > capacity_pages) {
                self.intake_closed = true;
                return error.StorageCapacity;
            }
        }
    };
}
