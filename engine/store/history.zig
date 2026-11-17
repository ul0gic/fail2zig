// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Pages, validates, resets and commits the confirmed effect history stream and reads the matches retained for its events.
// Holds: A history page is refused unless its sequences run contiguously from the requested position up to at most the stream head.

const std = @import("std");
const build_options = @import("build_options");
const diag_mod = @import("../diag/diag.zig");
const consumers = @import("../detect/consumer.zig");
const detection = @import("../detect/detection_record.zig");
const retry = @import("../detect/retry.zig");
const effects = @import("../effect/effect.zig");
const effect_history = @import("../effect/effect_history.zig");
const store = @import("store.zig");
const Error = store.Error;

pub fn Methods(comptime Store: type) type {
    return struct {
        const InternalSource = Store.InternalSource;
        const HistoryResetIntent = store.HistoryResetIntent;
        const HistoryResetResult = store.HistoryResetResult;
        fn historyHead(self: *Store, installation: effects.Installation, after: u64) Error!effect_history.PageToken {
            if (self.schema_version < 13) return error.ConsumerStorageRequired;
            try installation.validate();
            const admitted = try self.readInstallation() orelse return error.InstallationRequired;
            if (!std.meta.eql(admitted, installation)) return error.InstallationMismatch;
            var row = try self.statement("SELECT revision,head,retained_from FROM confirmed_history_stream WHERE id=1;");
            defer row.deinit();
            if (!try row.row()) return error.HistoryGap;
            const stream_revision = try row.signed(0);
            const head = try row.signed(1);
            const floor = try row.signed(2);
            if (stream_revision <= 0 or head < 0 or floor <= 0) return error.InvalidHistoryPage;
            const token = effect_history.PageToken{
                .installation = installation.id,
                .stream_revision = @intCast(stream_revision),
                .head_sequence = @intCast(head),
                .retained_from_sequence = @intCast(floor),
                .after_sequence = after,
                .last_sequence = after,
            };
            try token.validate();
            return token;
        }
        pub fn confirmedEffectPageTx(self: *Store, installation: effects.Installation, after: u64, expected_revision: ?u64, output: []effect_history.Event) Error!effect_history.Page {
            if (output.len == 0 or output.len > effect_history.max_page) return error.InvalidHistoryPage;
            var token = try self.historyHead(installation, after);
            if (expected_revision) |wanted_revision| if (wanted_revision != token.stream_revision) return error.StaleHistoryPage;
            var row = try self.statement(if (self.schema_version >= store.load_repair_schema)
                self.originSql(
                    "SELECT s.sequence,e.event_id,e.scope_key,e.canonical_scope,e.jail,e.decision_id,e.confirmed_us,",
                    "e.origin",
                    ",EXISTS(SELECT 1 FROM confirmed_event_details d WHERE d.event_id=e.event_id) FROM confirmed_history_sequence s JOIN confirmed_effect_events e ON e.event_id=s.event_id WHERE s.sequence>?1 ORDER BY s.sequence LIMIT ?2;",
                )
            else if (self.schema_version >= 19)
                self.originSql(
                    "SELECT s.sequence,e.event_id,e.scope_key,n.canonical_scope,e.jail,e.decision_id,e.confirmed_us,",
                    "e.origin",
                    ",EXISTS(SELECT 1 FROM confirmed_event_details d WHERE d.event_id=e.event_id) FROM confirmed_history_sequence s JOIN confirmed_effect_events e ON e.event_id=s.event_id JOIN native_effects n ON n.scope_key=e.scope_key WHERE s.sequence>?1 ORDER BY s.sequence LIMIT ?2;",
                )
            else if (self.schema_version >= 17)
                self.originSql(
                    "SELECT s.sequence,e.event_id,e.scope_key,n.scope,e.jail,e.decision_id,e.confirmed_us,",
                    "e.origin",
                    ",EXISTS(SELECT 1 FROM confirmed_event_details d WHERE d.event_id=e.event_id) FROM confirmed_history_sequence s JOIN confirmed_effect_events e ON e.event_id=s.event_id JOIN native_effects n ON n.scope_key=e.scope_key WHERE s.sequence>?1 ORDER BY s.sequence LIMIT ?2;",
                )
            else
                self.originSql("SELECT s.sequence,e.event_id,e.scope_key,n.scope,e.jail,e.decision_id,e.confirmed_us,", "e.origin", " FROM confirmed_history_sequence s JOIN confirmed_effect_events e ON e.event_id=s.event_id JOIN native_effects n ON n.scope_key=e.scope_key WHERE s.sequence>?1 ORDER BY s.sequence LIMIT ?2;"));
            defer row.deinit();
            try row.int(1, @intCast(after));
            try row.int(2, @intCast(output.len));
            var count: usize = 0;
            while (try row.row()) {
                const sequence = try row.signed(0);
                if (sequence <= 0 or sequence != after + count + 1 or sequence > token.head_sequence) return error.HistoryGap;
                const native_retry = if (self.schema_version >= 17) blk: {
                    const value = try row.signed(8);
                    if (value < 0 or value > 1) return error.InvalidHistoryEvent;
                    break :blk value == 1;
                } else false;
                const event = effect_history.Event{
                    .sequence = @intCast(sequence),
                    .event_id = try Store.effectBlob(&row, 1, 32),
                    .installation = installation,
                    .scope_key = try Store.effectBlob(&row, 2, 32),
                    .scope = try self.decodeStoredScope(&row, 3),
                    .jail = detection.Name.init(try row.boundedBytes(4, 64)) catch return error.InvalidHistoryEvent,
                    .decision_id = try Store.effectBlob(&row, 5, 32),
                    .confirmed_us = try row.signed(6),
                    .native_retry = native_retry,
                    .origin = std.meta.intToEnum(effects.Origin, try row.signed(7)) catch return error.InvalidHistoryEvent,
                };
                try event.validate();
                output[count] = event;
                count += 1;
            }
            if (count != @min(output.len, token.head_sequence - after)) return error.HistoryGap;
            token.last_sequence = after + count;
            const page = effect_history.Page{ .token = token, .count = count, .more = token.last_sequence < token.head_sequence };
            try page.validate();
            return page;
        }
        pub fn confirmedEffectPage(self: *Store, installation: effects.Installation, after_sequence: u64, expected_revision: ?u64, output: []effect_history.Event) Error!effect_history.Page {
            try self.beginRead();
            errdefer self.rollback();
            const page = try self.confirmedEffectPageTx(installation, after_sequence, expected_revision, output);
            try self.commitTransaction();
            return page;
        }

        // Holds: Refuses to run outside an open transaction; on success the caller owns and frees every returned line.
        pub fn retainedMatchesForEventsTx(self: *Store, allocator: std.mem.Allocator, installation: effects.Installation, events: []const effect_history.Event, output: []?[]u8) Error!void {
            if (output.len > effect_history.max_page) return error.InvalidApplicationHistoryQuery;
            @memset(output, null);
            if (events.len != output.len or events.len > effect_history.max_page or self.api.get_autocommit(self.db) != 0 or self.schema_version < store.load_repair_schema) return error.InvalidApplicationHistoryQuery;
            installation.validate() catch return error.InvalidApplicationHistoryQuery;
            errdefer clearRetainedMatches(allocator, output);
            for (events, output) |*event, *line| {
                try event.validate();
                if (!std.meta.eql(event.installation, installation)) return error.InvalidApplicationHistoryQuery;
                line.* = try self.retainedEventMatchTx(allocator, installation, event.scope_key, event.scope, event.jail.slice(), event.decision_id, event.confirmed_us);
            }
        }

        pub fn retainedMatchesForOwnersTx(self: *Store, allocator: std.mem.Allocator, installation: effects.Installation, now_us: i64, owners: []const Store.OperatorOwner, output: []?[]u8) Error!void {
            if (output.len > effect_history.max_page) return error.InvalidApplicationHistoryQuery;
            @memset(output, null);
            if (owners.len != output.len or owners.len > effects.max_page or self.api.get_autocommit(self.db) != 0 or self.schema_version < store.load_repair_schema) return error.InvalidApplicationHistoryQuery;
            installation.validate() catch return error.InvalidApplicationHistoryQuery;
            errdefer clearRetainedMatches(allocator, output);
            for (owners, output) |*owner, *line| {
                const key = try owner.scope.key(installation);
                if (owner.jail.len == 0 or owner.jail.len > owner.jail.bytes.len) return error.InvalidApplicationHistoryQuery;
                const jail = detection.Name.init(owner.jail.slice()) catch return error.InvalidApplicationHistoryQuery;
                if (!std.mem.eql(u8, &key, &owner.key) or !std.meta.eql(jail, owner.jail)) return error.InvalidApplicationHistoryQuery;
                var current = try self.statement("SELECT o.decision_id,o.lease_kind,o.deadline_us,n.canonical_scope FROM effect_owners o JOIN native_effects n USING(scope_key) WHERE o.scope_key=?1 AND o.jail=?2;");
                defer current.deinit();
                try current.blob(1, &owner.key);
                try current.text(2, owner.jail.slice());
                if (!try current.row()) continue;
                const scope = try self.decodeStoredScope(&current, 3);
                const stored_key = try scope.key(installation);
                if (!std.mem.eql(u8, &stored_key, &owner.key)) return error.InvalidApplicationHistoryRow;
                const decision_id = try Store.effectBlob(&current, 0, 32);
                const lease = try Store.effectLease(&current, 1, 2);
                if (!std.mem.eql(u8, &decision_id, &owner.decision_id) or !lease.live(now_us) or !std.meta.eql(lease, owner.lease)) continue;
                line.* = try self.retainedEventMatchTx(allocator, installation, owner.key, owner.scope, owner.jail.slice(), owner.decision_id, null);
            }
        }

        fn clearRetainedMatches(allocator: std.mem.Allocator, output: []?[]u8) void {
            for (output) |*line| {
                if (line.*) |value| allocator.free(value);
                line.* = null;
            }
        }

        fn retainedEventMatchTx(self: *Store, allocator: std.mem.Allocator, installation: effects.Installation, key: effects.Hash, scope: effects.Scope, jail: []const u8, decision_id: effects.Hash, confirmed_us: ?i64) Error!?[]u8 {
            var row = try self.statement("SELECT e.event_id,e.scope_key,e.canonical_scope,e.jail,e.decision_id,e.confirmed_us,d.event_id,d.evidence FROM confirmed_effect_events e LEFT JOIN confirmed_event_details d ON d.event_id=e.event_id WHERE e.scope_key=?1 AND e.jail=?2 AND e.decision_id=?3;");
            defer row.deinit();
            try row.blob(1, &key);
            try row.text(2, jail);
            try row.blob(3, &decision_id);
            if (!try row.row()) return null;
            const stored_scope = try self.decodeStoredScope(&row, 2);
            const stored_key = try stored_scope.key(installation);
            const expected_scope = try scope.encodeCanonical();
            const actual_scope = try stored_scope.encodeCanonical();
            const event_id = effects.hashParts("fail2zig-native-confirmed-owner-v1", &.{ &installation.id, &key, jail, &decision_id });
            if (!std.mem.eql(u8, &stored_key, &key) or !std.mem.eql(u8, &expected_scope, &actual_scope) or
                !std.mem.eql(u8, &event_id, &try Store.effectBlob(&row, 0, 32)) or
                !std.mem.eql(u8, &key, &try Store.effectBlob(&row, 1, 32)) or
                !std.mem.eql(u8, &decision_id, &try Store.effectBlob(&row, 4, 32))) return error.InvalidApplicationHistoryRow;
            if (self.api.column_type(row.ptr, 3) != 3 or !std.mem.eql(u8, jail, try row.boundedBytes(3, 64))) return error.InvalidApplicationHistoryRow;
            const stored_us = try row.signed(5);
            if (confirmed_us) |expected| if (stored_us != expected) return error.InvalidApplicationHistoryRow;
            if (self.api.column_type(row.ptr, 6) == 5) {
                if (self.api.column_type(row.ptr, 7) != 5) return error.InvalidApplicationHistoryRow;
                return null;
            }
            if (!std.mem.eql(u8, &event_id, &try Store.effectBlob(&row, 6, 32))) return error.InvalidApplicationHistoryRow;
            if (self.api.column_type(row.ptr, 7) == 5) return null;
            if (self.api.column_type(row.ptr, 7) != 3) return error.InvalidApplicationHistoryRow;
            const evidence = try row.boundedBytes(7, retry.max_evidence_text_bytes);
            if (evidence.len == 0 or !std.unicode.utf8ValidateSlice(evidence)) return error.InvalidApplicationHistoryRow;
            if (try self.effectiveHistoryLimitTx(jail) == 0) return null;
            return allocator.dupe(u8, evidence) catch error.OutOfMemory;
        }

        pub fn historyEventEligible(self: *Store, event: effect_history.Event) Error!bool {
            try event.validate();
            if (self.schema_version < 20) return true;
            if (event.scope.canonical.subject.kind != .host) return error.InvalidHistoryReset;
            const subject: detection.Subject = switch (event.scope.canonical.subject.family) {
                .v4 => .{ .v4 = event.scope.canonical.subject.address[0..4].* },
                .v6 => .{ .v6 = event.scope.canonical.subject.address },
            };
            try self.beginRead();
            errdefer self.rollback();
            var row = try self.statement("SELECT max(through_sequence) FROM history_reset_watermarks WHERE family=?1 AND subject=?2 AND ((scope=1 AND jail=?3) OR (scope=2 AND jail=''));");
            defer row.deinit();
            try Store.bindSubjectAt(&row, &subject, 1);
            try row.text(3, event.jail.slice());
            if (!try row.row()) return error.InvalidHistoryReset;
            const through = try row.optionalSigned(0);
            if (try row.row()) return error.InvalidHistoryReset;
            try self.commitTransaction();
            if (through) |value| {
                if (value < 0) return error.InvalidHistoryReset;
                return event.sequence > @as(u64, @intCast(value));
            }
            return true;
        }

        pub fn resetHistory(self: *Store, intent: HistoryResetIntent, clock: effects.Clock) Error!HistoryResetResult {
            intent.subject.validate() catch return error.InvalidHistoryReset;
            if (intent.subject.unenforceable() or intent.expected_revision > std.math.maxInt(i64) or std.mem.allEqual(u8, &intent.intent_id, 0)) return error.InvalidHistoryReset;
            const scope_value: i64 = switch (intent.scope) {
                .jail => |name| blk: {
                    _ = detection.Name.init(name) catch return error.InvalidHistoryReset;
                    break :blk 1;
                },
                .overall => 2,
            };
            const jail = switch (intent.scope) {
                .jail => |name| name,
                .overall => "",
            };
            try self.beginWrite();
            errdefer self.rollback();
            if (self.schema_version < 20) return error.HistoryResetStorageRequired;
            var existing = try self.statement("SELECT through_sequence,reset_us,revision,intent_id FROM history_reset_watermarks WHERE scope=?1 AND jail=?2 AND family=?3 AND subject=?4;");
            defer existing.deinit();
            try existing.int(1, scope_value);
            try existing.text(2, jail);
            try Store.bindSubjectAt(&existing, &intent.subject, 3);
            var prior_revision: u64 = 0;
            if (try existing.row()) {
                const through = try existing.signed(0);
                const reset_us = try existing.signed(1);
                const saved_revision = try existing.signed(2);
                const prior_intent = try Store.effectBlob(&existing, 3, 32);
                if (through < 0 or saved_revision <= 0 or try existing.row()) return error.InvalidHistoryReset;
                if (std.mem.eql(u8, &prior_intent, &intent.intent_id)) {
                    try self.commitTransaction();
                    return .{ .revision = @intCast(saved_revision), .through_sequence = @intCast(through), .reset_us = reset_us };
                }
                prior_revision = @intCast(saved_revision);
            }
            if (prior_revision != intent.expected_revision) return error.StaleHistoryReset;
            if (prior_revision == std.math.maxInt(i64)) return error.InvalidHistoryReset;
            if (prior_revision == 0 and try self.integer("SELECT count(*) FROM history_reset_watermarks;") >= effects.max_effects) return error.EffectCapacity;
            const now = try self.effectClock(clock);
            const head_value = try self.integer("SELECT head FROM confirmed_history_stream WHERE id=1;");
            if (head_value < 0) return error.InvalidHistoryReset;
            const head: u64 = @intCast(head_value);
            {
                var write = try self.statement("INSERT INTO history_reset_watermarks VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(scope,jail,family,subject) DO UPDATE SET through_sequence=excluded.through_sequence,reset_us=excluded.reset_us,revision=excluded.revision,intent_id=excluded.intent_id;");
                defer write.deinit();
                try write.int(1, scope_value);
                try write.text(2, jail);
                try Store.bindSubjectAt(&write, &intent.subject, 3);
                try write.int(5, @intCast(head));
                try write.int(6, now);
                try write.int(7, @intCast(prior_revision + 1));
                try write.blob(8, &intent.intent_id);
                try write.done();
                if (self.api.changes(self.db) != 1) return error.InvalidHistoryReset;
            }
            {
                var summaries = try self.statement(if (scope_value == 1)
                    "DELETE FROM confirmed_policy_summaries WHERE jail=?1 AND family=?2 AND subject=?3;"
                else
                    "DELETE FROM confirmed_policy_summaries WHERE family=?1 AND subject=?2;");
                defer summaries.deinit();
                if (scope_value == 1) {
                    try summaries.text(1, jail);
                    try Store.bindSubjectAt(&summaries, &intent.subject, 2);
                } else try Store.bindSubjectAt(&summaries, &intent.subject, 1);
                try summaries.done();
            }
            try self.fault(.after_history_reset);
            _ = try self.commitEffectClock(clock);
            try self.commitTransaction();
            return .{ .revision = prior_revision + 1, .through_sequence = head, .reset_us = now };
        }

        fn validateConfirmedEffectPageTx(self: *Store, token: effect_history.PageToken) Error!void {
            try token.validate();
            const installation = try self.readInstallation() orelse return error.InstallationRequired;
            const current = try self.historyHead(installation, token.after_sequence);
            if (!std.mem.eql(u8, &current.installation, &token.installation)) return error.InstallationMismatch;
            if (current.stream_revision != token.stream_revision or current.head_sequence != token.head_sequence or current.retained_from_sequence != token.retained_from_sequence) return error.StaleHistoryPage;
            var events: [effect_history.max_page]effect_history.Event = undefined;
            const size: usize = @intCast(token.last_sequence - token.after_sequence);
            const page = try self.confirmedEffectPageTx(installation, token.after_sequence, token.stream_revision, events[0..@max(1, size)]);
            if (page.token.last_sequence != token.last_sequence) return error.StaleHistoryPage;
        }
        pub fn validateConfirmedEffectPage(self: *Store, token: effect_history.PageToken) Error!void {
            try self.beginRead();
            errdefer self.rollback();
            try self.validateConfirmedEffectPageTx(token);
            try self.commitTransaction();
        }
        pub fn canonicalHistoryManifest(manifest: consumers.Manifest) bool {
            return std.mem.eql(u8, manifest.jail, "@history") and std.mem.eql(u8, manifest.source, "confirmed-effects") and manifest.required.len == 1 and
                manifest.required[0].format_version == effect_history.version and consumers.Key.eql(manifest.required[0].key, effect_history.key(manifest.source_generation));
        }
        fn checkHistoryBatch(manifest: consumers.Manifest, batch: consumers.Batch, installation: [16]u8) Error!effect_history.Checkpoint {
            try batch.validate();
            _ = try manifest.digest();
            if (!canonicalHistoryManifest(manifest) or batch.deltas.len != 1 or batch.dependencies.len != 0) return error.InvalidHistoryTransition;
            const delta = batch.deltas[0];
            if (!consumers.Key.eql(delta.key, manifest.required[0].key) or delta.format_version != effect_history.version or delta.valid_until_us != null) return error.InvalidHistoryTransition;
            const history_checkpoint = try effect_history.Checkpoint.decode(delta.payload);
            if (!std.mem.eql(
                u8,
                &history_checkpoint.generation,
                &manifest.source_generation,
            ) or !std.mem.eql(u8, &history_checkpoint.installation, &installation)) return error.HistoryGenerationMismatch;
            return history_checkpoint;
        }
        pub fn bootstrapConfirmedHistory(self: *Store, manifest: consumers.Manifest, batch: consumers.Batch, installation: effects.Installation) Error!void {
            const history_checkpoint = try checkHistoryBatch(manifest, batch, installation.id);
            if (history_checkpoint.last_sequence != 0 or batch.deltas[0].expected_revision != 0) return error.InvalidHistoryTransition;
            try self.beginAdmissionWrite();
            errdefer self.rollback();
            _ = try self.historyHead(installation, 0);
            try self.admitManifestTx(manifest);
            try self.checkManifestBatch(manifest, batch, true, true);
            try self.writeConsumerBatch(batch);
            try self.readyManifest(manifest);
            try self.fault(.before_consumer_input_commit);
            try self.commitConsumerClock(batch);
            try self.commitTransaction();
        }
        pub const max_history_commit_pages = 4;
        pub const HistoryCommit = struct { batch: consumers.Batch, token: effect_history.PageToken };

        pub fn commitConfirmedHistory(self: *Store, manifest: consumers.Manifest, batch: consumers.Batch, token: effect_history.PageToken) Error!void {
            if (!try self.commitConfirmedHistoryGroup(manifest, &.{.{ .batch = batch, .token = token }}, null)) return error.MaintenanceWorkExhausted;
        }

        pub fn commitConfirmedHistoryGroup(self: *Store, manifest: consumers.Manifest, pages: []const HistoryCommit, internal: ?InternalSource) Error!bool {
            if (pages.len == 0 or pages.len > max_history_commit_pages) return error.InvalidHistoryTransition;
            try self.beginWrite();
            errdefer self.rollback();
            self.commitHistoryPagesTx(manifest, pages, internal) catch |failure| {
                if (failure != error.Interrupted) return failure;
                const prior_rollback = self.rollback_error_code;
                self.rollback_error_code = null;
                self.rollback();
                const clean = !self.reopen_required and self.rollback_error_code == null and self.api.get_autocommit(self.db) != 0;
                if (self.rollback_error_code == null) self.rollback_error_code = prior_rollback;
                if (!clean) return error.Interrupted;
                if (pages.len == 1) return error.MaintenanceWorkExhausted;
                if (comptime build_options.diag) diag_mod.count(.history_yields, 1);
                return false;
            };
            if (comptime build_options.diag) {
                diag_mod.count(.history_groups, 1);
                diag_mod.count(.history_pages, pages.len);
            }
            return true;
        }

        fn commitHistoryPagesTx(self: *Store, manifest: consumers.Manifest, pages: []const HistoryCommit, internal: ?InternalSource) Error!void {
            for (pages) |page| try self.commitConfirmedHistoryTx(manifest, page.batch, page.token);
            if (internal) |source| try self.releaseHistoryRecords(source);
            try self.commitTransaction();
        }

        fn commitConfirmedHistoryTx(self: *Store, manifest: consumers.Manifest, batch: consumers.Batch, token: effect_history.PageToken) Error!void {
            const next = try checkHistoryBatch(manifest, batch, token.installation);
            try self.validateConfirmedEffectPageTx(token);
            try self.checkManifestBatch(manifest, batch, false, true);
            if (token.last_sequence == token.after_sequence) return error.HistoryCaughtUp;
            var row = try self.statement("SELECT payload FROM consumer_checkpoints WHERE kind=?1 AND jail=?2 AND source=?3 AND rule=?4 AND generation=?5;");
            defer row.deinit();
            const required_key = manifest.required[0].key;
            try Store.bindConsumerKey(&row, &required_key);
            if (!try row.row()) return error.MissingRequiredConsumer;
            const previous = try effect_history.Checkpoint.decode(try row.boundedBytes(0, effect_history.checkpoint_bytes));
            var events: [effect_history.max_page]effect_history.Event = undefined;
            const installation = try self.readInstallation() orelse return error.InstallationRequired;
            const size: usize = @intCast(token.last_sequence - token.after_sequence);
            const page = try self.confirmedEffectPageTx(installation, token.after_sequence, token.stream_revision, events[0..size]);
            for (events[0..page.count]) |event| if (event.confirmed_us > batch.prepared_us) return error.InvalidHistoryEvent;
            try effect_history.validateTransition(previous, next, page, events[0..page.count]);
            try self.writeConsumerBatch(batch);
            try self.fault(.before_consumer_input_commit);
            try self.commitConsumerClock(batch);
        }
    };
}
