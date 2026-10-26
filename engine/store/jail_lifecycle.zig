// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const effects = @import("../core/native_effect.zig");
const detection = @import("../core/native_detection_record.zig");
const store = @import("store.zig");
const Error = store.Error;

pub fn Methods(comptime Store: type) type {
    return struct {
        pub const JailRetirementIntent = struct { jail: detection.Name, keep_ignore_deadlines: bool };
        pub const JailRetirementPhase = enum { owners, retry_states, retry_retired, policy_summaries, source_cursors, pending_receipts, manifests, timed_entries, record_groups, finish, done };
        pub const JailRetirementCursor = struct { phase: JailRetirementPhase = .owners, owner_after: ?effects.Hash = null, timed_list: u8 = 1 };
        pub const JailRetirementFinishProof = struct {
            intent: JailRetirementIntent,
            verification: union(enum) {
                no_installation,
                observed: struct { installation: [16]u8, effect_revision: u64, publication_epoch: u64, fingerprint: effects.Hash, observed_us: i64 },
            },
        };
        pub const JailRetirementReconciliation = struct { jail: detection.Name, keep_ignore_deadlines: bool, owner_generation: effects.Hash, owner_revision: u64, token: effects.Token };
        pub const JailRetirementPage = struct { next: JailRetirementCursor, examined: u16 = 0, owners_released: u16 = 0, bans_lifted: u16 = 0, deleted_rows: u16 = 0, done: bool = false, yielded: bool = false, withdrawal_required: bool = false, reconcile: ?JailRetirementReconciliation = null };

        fn retirementIntent(row: *store.Stmt) Error!JailRetirementIntent {
            if (row.store.api.column_type(row.ptr, 0) != 3 or row.store.api.column_type(row.ptr, 1) != 1) return error.InvalidRecord;
            const name = detection.Name.init(try row.boundedBytes(0, 64)) catch return error.InvalidRecord;
            const keep = try row.signed(1);
            if (keep != 0 and keep != 1) return error.InvalidRecord;
            return .{ .jail = name, .keep_ignore_deadlines = keep == 1 };
        }
        pub fn jailRetirement(self: *Store, jail: []const u8) Error!?JailRetirementIntent {
            _ = detection.Name.init(jail) catch return error.InvalidRecord;
            var row = try self.statement("SELECT jail,keep_ignore_deadlines FROM jail_retirements WHERE jail=?1;");
            defer row.deinit();
            try row.text(1, jail);
            return if (try row.row()) try retirementIntent(&row) else null;
        }
        pub fn jailRetirements(self: *Store, out: []JailRetirementIntent) Error!usize {
            var rows = try self.statement("SELECT jail,keep_ignore_deadlines FROM jail_retirements ORDER BY jail LIMIT 65;");
            defer rows.deinit();
            var count: usize = 0;
            while (try rows.row()) {
                if (count == out.len or count == 64) return error.StorageLimit;
                out[count] = try retirementIntent(&rows);
                count += 1;
            }
            return count;
        }
        pub fn jailRetirementOwnerKeys(self: *Store, intent: JailRetirementIntent, after: ?effects.Hash, out: []effects.Hash) Error!usize {
            if (out.len == 0 or out.len > 64) return error.InvalidEffect;
            try self.beginRead();
            errdefer self.rollback();
            const current = try self.jailRetirement(intent.jail.slice()) orelse return error.StaleEffect;
            if (current.keep_ignore_deadlines != intent.keep_ignore_deadlines) return error.StaleEffect;
            var rows = try self.statement(if (after != null)
                "SELECT scope_key FROM effect_owners INDEXED BY effect_owners_jail WHERE jail=?1 AND scope_key>?2 ORDER BY scope_key LIMIT ?3;"
            else
                "SELECT scope_key FROM effect_owners INDEXED BY effect_owners_jail WHERE jail=?1 ORDER BY scope_key LIMIT ?3;");
            defer rows.deinit();
            try rows.text(1, intent.jail.slice());
            if (after) |*key| try rows.blob(2, key);
            try rows.int(3, @intCast(out.len));
            var count: usize = 0;
            while (try rows.row()) {
                out[count] = try Store.effectBlob(&rows, 0, 32);
                count += 1;
            }
            try self.commitTransaction();
            return count;
        }
        pub fn jailRetirementOwnerBefore(self: *Store, intent: JailRetirementIntent, key: effects.Hash) Error!?effects.Hash {
            try self.beginRead();
            errdefer self.rollback();
            const current = try self.jailRetirement(intent.jail.slice()) orelse return error.StaleEffect;
            if (current.keep_ignore_deadlines != intent.keep_ignore_deadlines) return error.StaleEffect;
            var row = try self.statement("SELECT scope_key FROM effect_owners INDEXED BY effect_owners_jail WHERE jail=?1 AND scope_key<?2 ORDER BY scope_key DESC LIMIT 1;");
            defer row.deinit();
            try row.text(1, intent.jail.slice());
            try row.blob(2, &key);
            const before = if (try row.row()) try Store.effectBlob(&row, 0, 32) else null;
            try self.commitTransaction();
            return before;
        }
        pub fn beginJailRetirementTx(self: *Store, jail: []const u8, keep_ignore_deadlines: bool) Error!void {
            if (self.api.get_autocommit(self.db) != 0) return error.DatabaseFailure;
            _ = detection.Name.init(jail) catch return error.InvalidRecord;
            if (try self.jailRetirement(jail) != null) return;
            // Bound the obligation set independently of the configured-name population.
            var intents: [64]JailRetirementIntent = undefined;
            if (try self.jailRetirements(&intents) == intents.len) return error.StorageLimit;
            var row = try self.statement("INSERT INTO jail_retirements VALUES(?1,?2);");
            defer row.deinit();
            try row.text(1, jail);
            try row.int(2, @intFromBool(keep_ignore_deadlines));
            try row.done();
        }
        pub fn beginJailRetirement(self: *Store, jail: []const u8, keep_ignore_deadlines: bool) Error!void {
            try self.beginWrite();
            errdefer self.rollback();
            try self.beginJailRetirementTx(jail, keep_ignore_deadlines);
            try self.commitTransaction();
        }
        pub fn retireJailPage(self: *Store, jail: []const u8, cursor: JailRetirementCursor, max_rows: u8, now_us: i64, clock: effects.Clock) Error!JailRetirementPage {
            _ = detection.Name.init(jail) catch return error.InvalidEffect;
            if (max_rows == 0 or max_rows > 64) return error.InvalidEffect;
            try self.beginWrite();
            errdefer self.rollback();
            return self.retireJailPageTx(jail, cursor, max_rows, now_us, clock) catch |failure| {
                if (failure != error.Interrupted) return failure;
                const prior_rollback = self.rollback_error_code;
                self.rollback_error_code = null;
                self.rollback();
                const clean = !self.reopen_required and self.rollback_error_code == null and self.api.get_autocommit(self.db) != 0;
                if (self.rollback_error_code == null) self.rollback_error_code = prior_rollback;
                if (!clean) return error.Interrupted;
                if (max_rows == 1) return error.MaintenanceWorkExhausted;
                return .{ .next = cursor, .yielded = true };
            };
        }
        fn retireJailPageTx(self: *Store, jail: []const u8, cursor: JailRetirementCursor, max_rows: u8, now_us: i64, clock: effects.Clock) Error!JailRetirementPage {
            try self.requireRetryProjectionMutationTx();
            const intent = try self.jailRetirement(jail) orelse return error.InvalidRecord;
            try self.effectSchema();
            const now = try self.effectClock(clock);
            if (now_us > now) return error.InvalidEffect;
            var page: JailRetirementPage = .{ .next = cursor };
            while (true) switch (page.next.phase) {
                .owners => {
                    const Held = struct { key: effects.Hash, generation: effects.Hash, revision: u64, absent: bool };
                    var held: [64]Held = undefined;
                    var count: usize = 0;
                    {
                        var rows = try self.statement(if (page.next.owner_after != null)
                            "SELECT scope_key,generation,revision,lease_kind,deadline_us FROM effect_owners INDEXED BY effect_owners_jail WHERE jail=?1 AND scope_key>?2 ORDER BY scope_key LIMIT ?3;"
                        else
                            "SELECT scope_key,generation,revision,lease_kind,deadline_us FROM effect_owners INDEXED BY effect_owners_jail WHERE jail=?1 ORDER BY scope_key LIMIT ?3;");
                        defer rows.deinit();
                        try rows.text(1, jail);
                        if (page.next.owner_after) |*key| try rows.blob(2, key);
                        try rows.int(3, max_rows);
                        while (try rows.row()) {
                            const revision = try rows.signed(2);
                            if (revision <= 0) return error.InvalidEffect;
                            held[count] = .{ .key = try Store.effectBlob(&rows, 0, 32), .generation = try Store.effectBlob(&rows, 1, 32), .revision = @intCast(revision), .absent = (try Store.effectLease(&rows, 3, 4)) == .absent };
                            count += 1;
                        }
                    }
                    var blocked = false;
                    for (held[0..count]) |owner| {
                        if (owner.absent) {
                            page.next.owner_after = owner.key;
                            continue;
                        }
                        const installation = try self.readInstallation() orelse return error.InstallationRequired;
                        const prior = try self.readEffect(owner.key, installation) orelse return error.InvalidEffect;
                        if (prior.status == .dispatched) {
                            page.reconcile = .{ .jail = intent.jail, .keep_ignore_deadlines = intent.keep_ignore_deadlines, .owner_generation = owner.generation, .owner_revision = owner.revision, .token = prior.token() };
                            blocked = true;
                            break;
                        }
                        var revision_bytes: [8]u8 = undefined;
                        std.mem.writeInt(u64, &revision_bytes, owner.revision, .little);
                        const id = effects.hashParts("fail2zig-jail-retire-v1", &.{ jail, &owner.key, &revision_bytes });
                        const result = try self.transitionOwnerTx(.{ .scope = prior.scope.canonical, .jail = jail, .current_generation = owner.generation, .next_generation = owner.generation, .expected_owner_revision = owner.revision, .transition_id = id, .mode = .release, .occurred_us = now_us }, now);
                        if (!result.changed) return error.InvalidEffect;
                        page.owners_released += 1;
                        page.bans_lifted += @intFromBool(result.entry.desired == .absent);
                        page.next.owner_after = owner.key;
                    }
                    if (!blocked and count < max_rows) page.next.phase = .retry_states;
                    page.examined = @intCast(count);
                    if (count != 0) break;
                },
                .retry_states, .retry_retired, .policy_summaries => {
                    const phase = page.next.phase;
                    const Child = struct { subject: detection.Subject };
                    var children: [64]Child = undefined;
                    var count: usize = 0;
                    var decisions: u64 = 0;
                    {
                        var rows = try self.statement(switch (phase) {
                            .retry_states => "SELECT family,subject,decisions FROM retry_states WHERE jail=?1 ORDER BY family,subject LIMIT ?2;",
                            .retry_retired => "SELECT family,subject,decisions FROM retry_retired WHERE jail=?1 ORDER BY family,subject LIMIT ?2;",
                            else => "SELECT family,subject,0 FROM confirmed_policy_summaries WHERE jail=?1 ORDER BY family,subject LIMIT ?2;",
                        });
                        defer rows.deinit();
                        try rows.text(1, jail);
                        try rows.int(2, max_rows);
                        while (try rows.row()) {
                            const value = try rows.signed(2);
                            if (value < 0) return error.InvalidRetryState;
                            children[count] = .{ .subject = try self.decodeRetrySubject(&rows, 0, 1) };
                            decisions = std.math.add(u64, decisions, @intCast(value)) catch return error.StorageLimit;
                            count += 1;
                        }
                    }
                    for (children[0..count]) |child| {
                        var row = try self.statement(switch (phase) {
                            .retry_states => "DELETE FROM retry_states WHERE jail=?1 AND family=?2 AND subject=?3;",
                            .retry_retired => "DELETE FROM retry_retired WHERE jail=?1 AND family=?2 AND subject=?3;",
                            else => "DELETE FROM confirmed_policy_summaries WHERE jail=?1 AND family=?2 AND subject=?3;",
                        });
                        defer row.deinit();
                        try row.text(1, jail);
                        try Store.bindSubject(&row, &child.subject);
                        try row.done();
                        if (self.api.changes(self.db) != 1) return error.InvalidRetryState;
                        page.deleted_rows += 1;
                        if (phase == .retry_states) try self.removeRetryProjectionRowTx(jail, &child.subject);
                    }
                    if (count != 0 and phase != .policy_summaries) {
                        if (phase == .retry_states) self.deletedRows(.retry_states) else try self.changeRetiredTotal(jail, decisions, false);
                        try self.changeRetryJailSummaryTx(jail, decisions, 0);
                    }
                    if (count < max_rows) page.next.phase = switch (phase) {
                        .retry_states => .retry_retired,
                        .retry_retired => .policy_summaries,
                        else => .source_cursors,
                    };
                    page.examined = @intCast(count);
                    if (count != 0) break;
                },
                .source_cursors, .pending_receipts => {
                    const phase = page.next.phase;
                    // Copy only bounded keys; bindings outlive each SQLITE_STATIC statement.
                    var arena = std.heap.ArenaAllocator.init(self.allocator);
                    defer arena.deinit();
                    var sources: [64][]const u8 = undefined;
                    var count: usize = 0;
                    {
                        var rows = try self.statement(if (phase == .source_cursors) "SELECT source FROM source_cursors WHERE jail=?1 ORDER BY source LIMIT ?2;" else "SELECT source FROM pending_receipts WHERE jail=?1 ORDER BY source LIMIT ?2;");
                        defer rows.deinit();
                        try rows.text(1, jail);
                        try rows.int(2, max_rows);
                        while (try rows.row()) {
                            sources[count] = try arena.allocator().dupe(u8, try rows.boundedBytes(0, store.Limits.source_bytes));
                            count += 1;
                        }
                    }
                    for (sources[0..count]) |source| {
                        var row = try self.statement(if (phase == .source_cursors) "DELETE FROM source_cursors WHERE jail=?1 AND source=?2;" else "DELETE FROM pending_receipts WHERE jail=?1 AND source=?2;");
                        defer row.deinit();
                        try row.text(1, jail);
                        try row.text(2, source);
                        try row.done();
                        if (self.api.changes(self.db) != 1) return error.InvalidRecord;
                        page.deleted_rows += 1;
                    }
                    if (count < max_rows) page.next.phase = if (phase == .source_cursors) .pending_receipts else .manifests;
                    page.examined = @intCast(count);
                    if (count != 0) break;
                },
                .manifests => {
                    const deleted = try self.retireJailManifestTx(jail);
                    if (deleted == 0) {
                        page.next.phase = .timed_entries;
                        continue;
                    }
                    page.examined = 1;
                    page.deleted_rows = deleted;
                    break;
                },
                .timed_entries => {
                    if (intent.keep_ignore_deadlines) page.next.timed_list = 2;
                    if (page.next.timed_list != 1 and page.next.timed_list != 2) return error.InvalidRecord;
                    const Key = struct { address: [64]u8, len: usize, duration: i64 };
                    var keys: [64]Key = undefined;
                    var count: usize = 0;
                    {
                        var rows = try self.statement("SELECT address,duration_s FROM config_timed_entries WHERE list=?1 AND jail=?2 ORDER BY address,duration_s LIMIT ?3;");
                        defer rows.deinit();
                        try rows.int(1, page.next.timed_list);
                        try rows.text(2, jail);
                        try rows.int(3, max_rows);
                        while (try rows.row()) {
                            const address = try rows.boundedBytes(0, 64);
                            keys[count] = .{ .address = undefined, .len = address.len, .duration = try rows.signed(1) };
                            @memcpy(keys[count].address[0..address.len], address);
                            count += 1;
                        }
                    }
                    for (keys[0..count]) |*key| {
                        var row = try self.statement("DELETE FROM config_timed_entries WHERE list=?1 AND jail=?2 AND address=?3 AND duration_s=?4;");
                        defer row.deinit();
                        try row.int(1, page.next.timed_list);
                        try row.text(2, jail);
                        try row.text(3, key.address[0..key.len]);
                        try row.int(4, key.duration);
                        try row.done();
                        if (self.api.changes(self.db) != 1) return error.InvalidRecord;
                        page.deleted_rows += 1;
                    }
                    if (count < max_rows) {
                        if (page.next.timed_list == 1) page.next.timed_list = 2 else page.next.phase = .record_groups;
                    }
                    page.examined = @intCast(count);
                    if (count != 0) break;
                },
                .record_groups => {
                    const progress = try self.retireRecordGroupsTx(intent, max_rows, clock);
                    page.examined = progress.examined;
                    page.deleted_rows = progress.deleted_rows;
                    if (progress.done) page.next.phase = .finish;
                    break;
                },
                .finish => {
                    page.withdrawal_required = true;
                    break;
                },
                .done => return error.InvalidRecord,
            };
            _ = try self.commitEffectClock(clock);
            try self.commitEffectTransaction(page.owners_released != 0);
            return page;
        }
        pub fn finishJailRetirement(self: *Store, proof: JailRetirementFinishProof, clock: effects.Clock) Error!JailRetirementPage {
            try self.beginWrite();
            errdefer self.rollback();
            try self.requireRetryProjectionMutationTx();
            const jail = proof.intent.jail.slice();
            const intent = try self.jailRetirement(jail) orelse return error.StaleEffect;
            if (intent.keep_ignore_deadlines != proof.intent.keep_ignore_deadlines) return error.StaleEffect;
            const installation = try self.readInstallation();
            const now = try self.effectClock(clock);
            switch (proof.verification) {
                .no_installation => {
                    if (installation != null) return error.StaleEffect;
                    if (try self.integer("SELECT EXISTS(SELECT 1 FROM native_effects LIMIT 1);") != 0) return error.InvalidEffect;
                },
                .observed => |verified| {
                    const saved = installation orelse return error.InstallationRequired;
                    if (!std.mem.eql(u8, &saved.id, &verified.installation) or verified.publication_epoch != self.effect_publication_epoch) return error.StaleEffect;
                    const revision = try self.integer("SELECT revision FROM effect_clock WHERE singleton=1;");
                    if (revision < 0) return error.InvalidEffect;
                    if (@as(u64, @intCast(revision)) != verified.effect_revision) return error.StaleEffect;
                    if (verified.observed_us > now) return error.InvalidEffect;
                },
            }
            inline for (.{ "retry_states", "retry_retired", "confirmed_policy_summaries", "source_cursors", "pending_receipts", "consumer_manifests", "records" }) |table| {
                var row = try self.statement("SELECT 1 FROM " ++ table ++ " WHERE jail=?1 LIMIT 1;");
                defer row.deinit();
                try row.text(1, jail);
                if (try row.row()) return error.StaleEffect;
            }
            {
                var row = try self.statement("SELECT 1 FROM consumer_requirements WHERE manifest_jail=?1 LIMIT 1;");
                defer row.deinit();
                try row.text(1, jail);
                if (try row.row()) return error.StaleEffect;
            }
            for ([_]u8{ 1, 2 }) |list| {
                if (list == 1 and intent.keep_ignore_deadlines) continue;
                var row = try self.statement("SELECT 1 FROM config_timed_entries WHERE list=?1 AND jail=?2 LIMIT 1;");
                defer row.deinit();
                try row.int(1, list);
                try row.text(2, jail);
                if (try row.row()) return error.StaleEffect;
            }
            var page: JailRetirementPage = .{ .next = .{ .phase = .done }, .done = true };
            if (try self.retiredTotal(jail) != 0) return error.InvalidRetryState;
            inline for (.{ "DELETE FROM retry_retired_totals WHERE jail=?1;", "DELETE FROM retry_escalation_policies WHERE jail=?1;", "DELETE FROM retry_policies WHERE jail=?1;", "DELETE FROM checkpoints WHERE jail=?1;" }) |sql| {
                try self.deleteRetirementParent(sql, jail);
                page.deleted_rows += @intCast(self.api.changes(self.db));
            }
            try self.retireRetryProjectionJailTx(jail);
            try self.deleteRetirementParent("DELETE FROM jail_retirements WHERE jail=?1;", jail);
            if (self.api.changes(self.db) != 1) return error.InvalidRecord;
            page.deleted_rows += 1;
            _ = try self.commitEffectClock(clock);
            try self.commitEffectTransaction(false);
            return page;
        }
        fn deleteRetirementParent(self: *Store, sql: [:0]const u8, jail: []const u8) Error!void {
            var row = try self.statement(sql);
            defer row.deinit();
            try row.text(1, jail);
            try row.done();
        }
        const DiscoveryJail = struct {
            bytes: [64]u8 = [_]u8{0} ** 64,
            len: usize = 0,

            fn init(value: []const u8) DiscoveryJail {
                var jail = DiscoveryJail{ .len = value.len };
                @memcpy(jail.bytes[0..value.len], value);
                return jail;
            }

            fn slice(self: *const DiscoveryJail) []const u8 {
                return self.bytes[0..self.len];
            }
        };
        const DiscoveryCandidates = struct { policy: ?DiscoveryJail = null, owner: ?DiscoveryJail = null };

        fn nextDiscoveryNames(self: *Store, after: ?DiscoveryJail) Error!DiscoveryCandidates {
            try self.beginRead();
            errdefer self.rollback();
            var candidates = DiscoveryCandidates{};
            {
                var row = try self.statement(if (after != null)
                    "SELECT jail FROM retry_policies WHERE jail>?1 ORDER BY jail LIMIT 1;"
                else
                    "SELECT jail FROM retry_policies ORDER BY jail LIMIT 1;");
                defer row.deinit();
                if (after) |*key| try row.text(1, key.slice());
                if (try row.row()) candidates.policy = DiscoveryJail.init(try row.boundedBytes(0, 64));
            }
            {
                var row = try self.statement(if (after != null)
                    "SELECT jail FROM effect_owners INDEXED BY effect_owners_jail WHERE jail>?1 ORDER BY jail LIMIT 1;"
                else
                    "SELECT jail FROM effect_owners INDEXED BY effect_owners_jail ORDER BY jail LIMIT 1;");
                defer row.deinit();
                if (after) |*key| try row.text(1, key.slice());
                if (try row.row()) candidates.owner = DiscoveryJail.init(try row.boundedBytes(0, 64));
            }
            try self.commitTransaction();
            return candidates;
        }

        fn discoveryOwnerHasLease(self: *Store, jail: *const DiscoveryJail) Error!bool {
            var after: ?effects.Hash = null;
            while (true) {
                var count: usize = 0;
                var last: effects.Hash = undefined;
                var live = false;
                {
                    // A separate read transaction for each page resets the SQLite work guard.
                    try self.beginRead();
                    errdefer self.rollback();
                    {
                        var row = try self.statement(if (after != null)
                            "SELECT scope_key,lease_kind FROM effect_owners INDEXED BY effect_owners_jail WHERE jail=?1 AND scope_key>?2 ORDER BY scope_key LIMIT 64;"
                        else
                            "SELECT scope_key,lease_kind FROM effect_owners INDEXED BY effect_owners_jail WHERE jail=?1 ORDER BY scope_key LIMIT 64;");
                        defer row.deinit();
                        try row.text(1, jail.slice());
                        if (after) |*key| try row.blob(2, key);
                        while (try row.row()) {
                            last = try Store.effectBlob(&row, 0, 32);
                            count += 1;
                            if (try row.signed(1) != 0) {
                                live = true;
                                break;
                            }
                        }
                    }
                    try self.commitTransaction();
                }
                if (live) return true;
                if (count < 64) return false;
                after = last;
            }
        }

        pub fn unconfiguredJails(self: *Store, configured: []const []const u8, out: [][64]u8) Error!usize {
            // Startup holds the state lock and has not started workers, so these read pages share stable ownership.
            var count: usize = 0;
            var after: ?DiscoveryJail = null;
            while (true) {
                const candidates = try self.nextDiscoveryNames(after);
                var jail = candidates.policy orelse candidates.owner orelse return count;
                if (candidates.owner) |owner| {
                    if (std.mem.order(u8, jail.slice(), owner.slice()) == .gt) jail = owner;
                }
                after = jail;
                for (configured) |name| {
                    if (std.mem.eql(u8, name, jail.slice())) break;
                } else {
                    const from_policy = if (candidates.policy) |policy| std.mem.eql(u8, policy.slice(), jail.slice()) else false;
                    if (!from_policy and !try self.discoveryOwnerHasLease(&jail)) continue;
                    if (count == out.len) return error.StorageLimit;
                    out[count] = jail.bytes;
                    count += 1;
                }
            }
        }
    };
}
