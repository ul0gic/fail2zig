// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Marks effect intents dispatched and settles their outcomes, reconciles jail retirements, confirms owners and prepares expiries.
// Holds: A settlement applies only to a token whose installation, revision and intent id still match the stored effect.

const std = @import("std");
const effects = @import("../effect/effect.zig");
const detection = @import("../detect/detection_record.zig");
const store = @import("store.zig");
const Error = store.Error;
const origin_schema = @import("effects.zig").origin_schema;

pub fn Methods(comptime Store: type) type {
    return struct {
        const effectBlob = Store.effectBlob;
        const effectLease = Store.effectLease;
        const observations_per_intent = Store.observations_per_intent;
        fn checkedEffectToken(self: *Store, token: effects.Token) Error!effects.Entry {
            const installation = try self.readInstallation() orelse return error.InstallationRequired;
            if (!std.mem.eql(u8, &installation.id, &token.installation)) return error.InstallationMismatch;
            const entry = try self.readEffect(token.scope_key, installation) orelse return error.StaleEffect;
            if (entry.revision != token.revision or !std.mem.eql(u8, &entry.intent_id, &token.intent_id)) return error.StaleEffect;
            return entry;
        }
        fn markDispatchedTx(self: *Store, token: effects.Token, dispatch_us: i64) Error!void {
            var row = try self.statement("UPDATE effect_intents SET status=2,dispatch_us=?2,observed_us=NULL,fingerprint=NULL WHERE intent_id=?1 AND status=1;");
            defer row.deinit();
            try row.blob(1, &token.intent_id);
            try row.int(2, dispatch_us);
            try row.done();
            if (self.api.changes(self.db) != 1) return error.StaleEffect;
            try self.markActionTargetsTx(token.scope_key, dispatch_us);
        }
        fn markActionTargetsTx(self: *Store, scope_key: effects.Hash, dispatch_us: i64) Error!void {
            if (self.schema_version < 21) return;
            var targets = try self.statement("UPDATE action_targets SET status=2,dispatch_us=?2,settled_us=NULL WHERE scope_key=?1 AND status IN(1,5) AND action_id IN (SELECT decision_id FROM effect_owners WHERE scope_key=?1);");
            defer targets.deinit();
            try targets.blob(1, &scope_key);
            try targets.int(2, dispatch_us);
            try targets.done();
        }
        const SettledIntent = struct { entry: effects.Entry, status: effects.Status, settlement: effects.Settlement };
        pub fn effectObservationId(intent_id: effects.Hash, dispatch_us: i64, observed_us: i64, fingerprint: effects.Hash, state: ?effects.Lease, status: effects.Status) effects.Hash {
            var stamps: [16]u8 = undefined;
            std.mem.writeInt(i64, stamps[0..8], dispatch_us, .little);
            std.mem.writeInt(i64, stamps[8..16], observed_us, .little);
            var observed_state: [10]u8 = [_]u8{0} ** 10;
            observed_state[0] = if (state) |lease| @intFromEnum(lease) else 3;
            if (state) |lease| if (lease == .finite) {
                std.mem.writeInt(i64, observed_state[1..9], lease.finite, .little);
            };
            observed_state[9] = @intFromEnum(status);
            return effects.hashParts("fail2zig-native-effect-observation-v1", &.{ &intent_id, &stamps, &fingerprint, &observed_state });
        }
        fn settleTx(self: *Store, token: effects.Token, dispatch_us: i64, observation: effects.Observation, clock: effects.Clock) Error!SettledIntent {
            const entry = try self.checkedEffectToken(token);
            switch (entry.status) {
                .pending => {
                    if (dispatch_us < entry.intent_us) return error.InvalidEffect;
                    try self.markDispatchedTx(token, dispatch_us);
                    try self.fault(.before_effect_dispatch_commit);
                },
                .dispatched, .applied, .absent, .expired => {},
                .superseded => return error.StaleEffect,
            }
            self.noteEffectChange(token.scope_key);
            const now = try self.effectClock(clock);
            if (observation.observed_us > now) return error.InvalidEffect;
            var dispatch = try self.statement("SELECT dispatch_us,observed_us,fingerprint FROM effect_intents WHERE intent_id=?1;");
            defer dispatch.deinit();
            try dispatch.blob(1, &token.intent_id);
            if (!try dispatch.row()) return error.InvalidEffect;
            const dispatch_time = try dispatch.optionalSigned(0) orelse return error.InvalidEffect;
            if (observation.observed_us < dispatch_time) return error.InvalidEffect;
            const previous_observed = try dispatch.optionalSigned(1);
            if (previous_observed) |previous| {
                if (observation.observed_us < previous) return error.StaleEffect;
                if (observation.observed_us == previous and !std.mem.eql(u8, &observation.fingerprint, &try effectBlob(&dispatch, 2, 32))) return error.StaleEffect;
            }
            const expired = entry.desired == .finite and !entry.desired.live(now);
            const matches = if (observation.state) |state| effects.Lease.eql(entry.desired, state) else false;
            const status: effects.Status = if (expired) .expired else if (!matches) .pending else if (entry.desired == .absent) .absent else .applied;
            if (previous_observed != null and observation.observed_us == previous_observed.? and status != entry.status) return error.StaleEffect;
            const observation_id = effectObservationId(token.intent_id, dispatch_time, observation.observed_us, observation.fingerprint, observation.state, status);
            {
                var prior = try self.statement("SELECT 1 FROM effect_observations WHERE observation_id=?1;");
                defer prior.deinit();
                try prior.blob(1, &observation_id);
                if (!try prior.row()) {
                    if (try self.tableRows(.effect_observations) >= effects.max_observations) return error.EffectCapacity;
                    var receipt = try self.statement("INSERT INTO effect_observations VALUES(?1,?2,?3,?4,?5,?6,?7,?8);");
                    defer receipt.deinit();
                    try receipt.blob(1, &observation_id);
                    try receipt.blob(2, &token.intent_id);
                    try receipt.int(3, dispatch_time);
                    try receipt.int(4, observation.observed_us);
                    try receipt.blob(5, &observation.fingerprint);
                    try receipt.int(6, if (observation.state) |state| @intFromEnum(state) else 3);
                    if (observation.state) |state| if (state == .finite) {
                        try receipt.int(7, state.finite);
                    };
                    try receipt.int(8, @intFromEnum(status));
                    try receipt.done();
                    self.insertedRows(.effect_observations, 1);
                }
            }
            if (self.schema_version >= store.load_repair_schema) {
                var trim = try self.statement("DELETE FROM effect_observations WHERE intent_id=?1 AND rowid NOT IN (SELECT rowid FROM effect_observations INDEXED BY effect_observations_intent WHERE intent_id=?1 ORDER BY observed_us DESC,rowid DESC LIMIT ?2);");
                defer trim.deinit();
                try trim.blob(1, &token.intent_id);
                try trim.int(2, observations_per_intent);
                try trim.done();
                self.removedRows(.effect_observations, self.api.changes(self.db));
            }
            var row = try self.statement("UPDATE effect_intents SET status=?2,observed_us=?3,fingerprint=?4 WHERE intent_id=?1;");
            defer row.deinit();
            try row.blob(1, &token.intent_id);
            try row.int(2, @intFromEnum(status));
            try row.int(3, observation.observed_us);
            try row.blob(4, &observation.fingerprint);
            try row.done();
            if (entry.status != .pending) try self.markActionTargetsTx(token.scope_key, dispatch_time);
            if (status == .applied and self.schema_version >= store.load_repair_schema) {
                var owners: [effects.max_page]effects.Owner = undefined;
                const count = try self.readOwners(token.scope_key, &owners);
                var subjects: [effects.max_page]detection.Subject = undefined;
                var subject_count: usize = 0;
                for (owners[0..count]) |owner| if (owner.lease.live(now)) {
                    if (try self.confirmOwnerTx(token, owner, observation.observed_us)) |subject| {
                        var seen = false;
                        for (subjects[0..subject_count]) |previous| if (std.meta.eql(subject, previous)) {
                            seen = true;
                            break;
                        };
                        if (!seen) {
                            subjects[subject_count] = subject;
                            subject_count += 1;
                        }
                    }
                };
                for (subjects[0..subject_count]) |subject| try self.refreshRetainedSubjectTx(subject);
            } else if (status == .applied) {
                var owners: [effects.max_page]effects.Owner = undefined;
                const count = try self.readOwners(token.scope_key, &owners);
                for (owners[0..count]) |owner| if (owner.lease.live(now)) {
                    const event_id = effects.hashParts("fail2zig-native-confirmed-owner-v1", &.{ &token.installation, &token.scope_key, owner.jail.slice(), &owner.decision_id });
                    var existing = try self.statement("SELECT event_id FROM confirmed_effect_events WHERE scope_key=?1 AND jail=?2 AND decision_id=?3;");
                    defer existing.deinit();
                    try existing.blob(1, &token.scope_key);
                    try existing.text(2, owner.jail.slice());
                    try existing.blob(3, &owner.decision_id);
                    if (try existing.row()) {
                        if (!std.mem.eql(u8, &event_id, &try effectBlob(&existing, 0, 32))) return error.InvalidEffect;
                        continue;
                    }
                    if (try self.tableRows(.confirmed_effect_events) >= effects.max_confirmed_events) return error.EffectCapacity;
                    var event = try self.statement("INSERT INTO confirmed_effect_events VALUES(?1,?2,?3,?4,?5) ON CONFLICT(scope_key,jail,decision_id) DO NOTHING;");
                    defer event.deinit();
                    try event.blob(1, &event_id);
                    try event.blob(2, &token.scope_key);
                    try event.text(3, owner.jail.slice());
                    try event.blob(4, &owner.decision_id);
                    try event.int(5, observation.observed_us);
                    try event.done();
                    self.insertedRows(.confirmed_effect_events, self.api.changes(self.db));
                    if (self.schema_version >= 17) {
                        var detail_inserted = false;
                        var detail = try self.statement("INSERT INTO confirmed_event_details(event_id,source,occurrence,decided_us,ordinal,evidence) SELECT ?1,source,occurrence,decided_us,ordinal,evidence FROM retry_decision_details WHERE jail=?2 AND effect_decision_id=?3;");
                        defer detail.deinit();
                        try detail.blob(1, &event_id);
                        try detail.text(2, owner.jail.slice());
                        try detail.blob(3, &owner.decision_id);
                        try detail.done();
                        if (self.api.changes(self.db) > 1) return error.InvalidApplicationHistoryRow;
                        detail_inserted = self.api.changes(self.db) == 1;
                        self.insertedRows(.confirmed_event_details, self.api.changes(self.db));
                        if (self.schema_version >= 18 and detail_inserted) {
                            var summary = try self.statement("INSERT OR REPLACE INTO confirmed_policy_summaries(jail,family,subject,confirmed_count,latest_confirmed_us) SELECT d.jail,d.family,d.subject,coalesce(s.confirmed_count,0)+1,max(coalesce(s.latest_confirmed_us,?3),?3) FROM retry_decision_details d LEFT JOIN confirmed_policy_summaries s ON s.jail=d.jail AND s.family=d.family AND s.subject=d.subject WHERE d.jail=?1 AND d.effect_decision_id=?2;");
                            defer summary.deinit();
                            try summary.text(1, owner.jail.slice());
                            try summary.blob(2, &owner.decision_id);
                            try summary.int(3, observation.observed_us);
                            try summary.done();
                            if (self.api.changes(self.db) != 1) return error.InvalidRetryState;
                            _ = try self.evictMemoryRows(.summaries, observation.observed_us);
                        }
                    }
                    if (self.schema_version >= 13) {
                        var sequenced = try self.statement("SELECT s.event_id FROM confirmed_history_stream h JOIN confirmed_history_sequence s ON s.sequence=h.head WHERE h.id=1;");
                        defer sequenced.deinit();
                        if (!try sequenced.row() or !std.mem.eql(u8, &try effectBlob(&sequenced, 0, 32), &event_id)) return error.HistoryGap;
                    }
                };
            }
            if (status == .applied or status == .absent) _ = try self.settleActionTargetsTx(token.scope_key, now);
            if (entry.desired == .absent and status == .pending) if (self.effect_invalidation) |hook| if (hook.retirement_pending) |notify| {
                var pending_owners: [effects.max_page]effects.Owner = undefined;
                const owner_count = try self.readOwners(token.scope_key, &pending_owners);
                notify(hook.context, token.scope_key, pending_owners[0..owner_count], entry.desired);
            };
            return .{ .entry = entry, .status = status, .settlement = if (expired) .expired else if (matches) .verified else .retry_same_intent };
        }
        fn jailRetirementFenceTx(self: *Store, request: Store.JailRetirementReconciliation) Error!bool {
            const intent = try self.jailRetirement(request.jail.slice()) orelse return false;
            if (intent.keep_ignore_deadlines != request.keep_ignore_deadlines) return false;
            const installation = try self.readInstallation() orelse return error.InstallationRequired;
            if (!std.mem.eql(u8, &installation.id, &request.token.installation)) return false;
            const entry = try self.readEffect(request.token.scope_key, installation) orelse return false;
            if (entry.status != .dispatched or !std.meta.eql(entry.token(), request.token)) return false;
            var row = try self.statement("SELECT o.generation,o.revision,o.lease_kind,o.deadline_us,EXISTS(SELECT 1 FROM effect_owner_revisions h WHERE h.scope_key=o.scope_key AND h.jail=o.jail AND h.revision=o.revision AND h.generation=o.generation AND h.decision_id=o.decision_id AND h.lease_kind=o.lease_kind AND h.deadline_us IS o.deadline_us AND h.decided_us=o.decided_us) FROM effect_owners o WHERE o.scope_key=?1 AND o.jail=?2;");
            defer row.deinit();
            try row.blob(1, &request.token.scope_key);
            try row.text(2, request.jail.slice());
            if (!try row.row()) return false;
            const generation = try effectBlob(&row, 0, 32);
            const revision = try row.signed(1);
            if (revision <= 0 or try row.signed(4) != 1) return error.InvalidEffect;
            return (try effectLease(&row, 2, 3)) != .absent and @as(u64, @intCast(revision)) == request.owner_revision and std.mem.eql(u8, &generation, &request.owner_generation);
        }
        pub fn validateJailRetirementReconciliation(self: *Store, request: Store.JailRetirementReconciliation) Error!bool {
            try self.beginRead();
            errdefer self.rollback();
            const valid = try self.jailRetirementFenceTx(request);
            try self.commitTransaction();
            return valid;
        }
        pub fn settleJailRetirementReconciliation(self: *Store, request: Store.JailRetirementReconciliation, dispatch_us: i64, observation: effects.Observation, clock: effects.Clock) Error!?effects.Settlement {
            const token = request.token;
            if (observation.qualification != .complete_owned or !std.mem.eql(
                u8,
                &observation.installation,
                &token.installation,
            ) or !std.mem.eql(u8, &observation.scope_key, &token.scope_key)) return error.IncompleteEffectObservation;
            try self.beginWrite();
            errdefer self.rollback();
            if (!try self.jailRetirementFenceTx(request)) {
                try self.commitTransaction();
                return null;
            }
            const settled = try self.settleTx(token, dispatch_us, observation, clock);
            try self.advanceEffectSnapshot();
            try self.fault(.before_effect_receipt_commit);
            const final = try self.commitEffectClock(clock);
            if (settled.status == .applied and settled.entry.desired == .finite and !settled.entry.desired.live(final)) return error.EffectExpired;
            try self.commitEffectTransaction(true);
            return settled.settlement;
        }
        pub fn settleOutcome(self: *Store, token: effects.Token, dispatch_us: i64, observation: effects.Observation, clock: effects.Clock) Error!effects.Settlement {
            if (observation.qualification != .complete_owned or !std.mem.eql(
                u8,
                &observation.installation,
                &token.installation,
            ) or !std.mem.eql(u8, &observation.scope_key, &token.scope_key)) return error.IncompleteEffectObservation;
            try self.beginWrite();
            errdefer self.rollback();
            const settled = try self.settleTx(token, dispatch_us, observation, clock);
            try self.advanceEffectSnapshot();
            try self.fault(.before_effect_receipt_commit);
            const final = try self.commitEffectClock(clock);
            if (settled.status == .applied and settled.entry.desired == .finite and !settled.entry.desired.live(final)) return error.EffectExpired;
            try self.commitEffectTransaction(true);
            return settled.settlement;
        }
        pub fn settleExpired(self: *Store, tokens: []const effects.Token, fingerprint: effects.Hash, observed_us: i64, clock: effects.Clock) Error!usize {
            if (tokens.len == 0 or tokens.len > max_expiry_batch) return error.InvalidEffect;
            try self.beginWrite();
            errdefer self.rollback();
            for (tokens) |token| {
                const observation = effects.Observation{
                    .installation = token.installation,
                    .scope_key = token.scope_key,
                    .fingerprint = fingerprint,
                    .observed_us = observed_us,
                    .qualification = .complete_owned,
                    .state = .absent,
                };
                const settled = try self.settleTx(token, observed_us, observation, clock);
                if (settled.entry.desired != .absent or settled.settlement != .verified) return error.InvalidEffect;
            }
            try self.advanceEffectSnapshot();
            try self.fault(.before_effect_receipt_commit);
            _ = try self.commitEffectClock(clock);
            try self.commitEffectTransaction(true);
            return tokens.len;
        }
        pub const max_install_batch = 1024;
        pub const InstallItem = struct { token: effects.Token, state: ?effects.Lease };
        pub fn settleInstalled(self: *Store, items: []const InstallItem, dispatch_us: i64, fingerprint: effects.Hash, observed_us: i64, clock: effects.Clock) Error!usize {
            if (items.len == 0 or items.len > max_install_batch) return error.InvalidEffect;
            try self.beginWrite();
            errdefer self.rollback();
            for (items) |item| {
                const observation = effects.Observation{
                    .installation = item.token.installation,
                    .scope_key = item.token.scope_key,
                    .fingerprint = fingerprint,
                    .observed_us = observed_us,
                    .qualification = .complete_owned,
                    .state = item.state,
                };
                _ = try self.settleTx(item.token, dispatch_us, observation, clock);
            }
            try self.advanceEffectSnapshot();
            try self.fault(.before_effect_receipt_commit);
            _ = try self.commitEffectClock(clock);
            try self.commitEffectTransaction(true);
            return items.len;
        }
        fn confirmOwnerTx(self: *Store, token: effects.Token, owner: effects.Owner, observed_us: i64) Error!?detection.Subject {
            var retained_subject: ?detection.Subject = null;
            const jail = owner.jail.slice();
            // Why: Stored event ids are recomputed from this domain string and compared, so changing it fails every existing confirmation.
            const event_id = effects.hashParts("fail2zig-native-confirmed-owner-v1", &.{ &token.installation, &token.scope_key, jail, &owner.decision_id });
            {
                var marker = try self.statement("SELECT decision_id,event_id FROM confirmation_markers WHERE scope_key=?1 AND jail=?2;");
                defer marker.deinit();
                try marker.blob(1, &token.scope_key);
                try marker.text(2, jail);
                if (try marker.row()) {
                    if (!std.mem.eql(u8, &try effectBlob(&marker, 0, 32), &owner.decision_id) or !std.mem.eql(u8, &try effectBlob(&marker, 1, 32), &event_id)) return error.InvalidEffect;
                    try self.clearConfirmedRetryEvidenceTx(jail, owner.decision_id);
                    return null;
                }
            }
            var retained = try self.statement("SELECT event_id FROM confirmed_effect_events WHERE scope_key=?1 AND jail=?2 AND decision_id=?3;");
            defer retained.deinit();
            try retained.blob(1, &token.scope_key);
            try retained.text(2, jail);
            try retained.blob(3, &owner.decision_id);
            const already_confirmed = try retained.row();
            if (already_confirmed and !std.mem.eql(u8, &event_id, &try effectBlob(&retained, 0, 32))) return error.InvalidEffect;
            if (!already_confirmed) {
                if (try self.tableRows(.confirmed_effect_events) >= effects.max_confirmed_events) return error.EffectCapacity;
                {
                    var event = try self.statement(if (self.schema_version >= origin_schema)
                        "INSERT INTO confirmed_effect_events(event_id,scope_key,jail,decision_id,confirmed_us,canonical_scope,origin) SELECT ?1,scope_key,?3,?4,?5,canonical_scope,?6 FROM native_effects WHERE scope_key=?2;"
                    else
                        "INSERT INTO confirmed_effect_events(event_id,scope_key,jail,decision_id,confirmed_us,canonical_scope) SELECT ?1,scope_key,?3,?4,?5,canonical_scope FROM native_effects WHERE scope_key=?2;");
                    defer event.deinit();
                    try event.blob(1, &event_id);
                    try event.blob(2, &token.scope_key);
                    try event.text(3, jail);
                    try event.blob(4, &owner.decision_id);
                    try event.int(5, observed_us);
                    if (self.schema_version >= origin_schema) try event.int(6, @intFromEnum(owner.origin));
                    try event.done();
                    if (self.api.changes(self.db) != 1) return error.InvalidEffect;
                    self.insertedRows(.confirmed_effect_events, 1);
                }
                var sequence: i64 = undefined;
                {
                    // Why: The confirmed_history_append trigger gives the insert the head sequence, so any other event at head is a gap.
                    var head = try self.statement("SELECT h.head,s.event_id FROM confirmed_history_stream h JOIN confirmed_history_sequence s ON s.sequence=h.head WHERE h.id=1;");
                    defer head.deinit();
                    if (!try head.row() or !std.mem.eql(u8, &try effectBlob(&head, 1, 32), &event_id)) return error.HistoryGap;
                    sequence = try head.signed(0);
                }
                if (try self.effectiveHistoryLimitTx(jail) != 0) {
                    var detail = try self.statement("INSERT INTO confirmed_event_details(event_id,source,occurrence,decided_us,ordinal,evidence,family,subject,sequence,confirmed_us,evidence_bytes) SELECT ?1,source,occurrence,decided_us,ordinal,evidence,family,subject,?4,?5,CASE WHEN evidence IS NULL THEN NULL ELSE length(CAST(evidence AS BLOB)) END FROM retry_decision_details WHERE jail=?2 AND effect_decision_id=?3 RETURNING family,subject,evidence_bytes;");
                    defer detail.deinit();
                    try detail.blob(1, &event_id);
                    try detail.text(2, jail);
                    try detail.blob(3, &owner.decision_id);
                    try detail.int(4, sequence);
                    try detail.int(5, observed_us);
                    if (try detail.row()) {
                        var subject: [16]u8 = undefined;
                        const stored = try detail.boundedBytes(1, subject.len);
                        @memcpy(subject[0..stored.len], stored);
                        const family = try detail.signed(0);
                        const bytes = try detail.optionalSigned(2);
                        if (try detail.row()) return error.InvalidApplicationHistoryRow;
                        self.insertedRows(.confirmed_event_details, 1);
                        retained_subject = switch (family) {
                            4 => if (stored.len == 4) .{ .v4 = subject[0..4].* } else return error.InvalidApplicationHistoryRow,
                            6 => if (stored.len == 16) .{ .v6 = subject } else return error.InvalidApplicationHistoryRow,
                            else => return error.InvalidApplicationHistoryRow,
                        };
                        try self.retainDetailDeferredTx(family, subject[0..stored.len], bytes, sequence);
                    }
                }
                var summary = try self.statement("INSERT OR REPLACE INTO confirmed_policy_summaries(jail,family,subject,confirmed_count,latest_confirmed_us) SELECT d.jail,d.family,d.subject,coalesce(s.confirmed_count,0)+1,max(coalesce(s.latest_confirmed_us,?3),?3) FROM retry_decision_details d LEFT JOIN confirmed_policy_summaries s ON s.jail=d.jail AND s.family=d.family AND s.subject=d.subject WHERE d.jail=?1 AND d.effect_decision_id=?2;");
                defer summary.deinit();
                try summary.text(1, jail);
                try summary.blob(2, &owner.decision_id);
                try summary.int(3, observed_us);
                try summary.done();
                if (self.api.changes(self.db) > 1) return error.InvalidRetryState;
                if (self.api.changes(self.db) == 1) _ = try self.evictMemoryRows(.summaries, observed_us);
            }
            var marker = try self.statement("INSERT INTO confirmation_markers VALUES(?1,?2,?3,?4);");
            defer marker.deinit();
            try marker.blob(1, &token.scope_key);
            try marker.text(2, jail);
            try marker.blob(3, &owner.decision_id);
            try marker.blob(4, &event_id);
            try marker.done();
            try self.clearConfirmedRetryEvidenceTx(jail, owner.decision_id);
            return retained_subject;
        }
        pub const ExpiryItem = struct { key: effects.Hash, revision: u64 };
        pub const max_expiry_batch = store.Store.attribution_batch;
        pub fn prepareExpiry(self: *Store, key: effects.Hash, expected_revision: u64, clock: effects.Clock) Error!effects.Entry {
            try self.beginWrite();
            errdefer self.rollback();
            const installation = try self.readInstallation() orelse return error.InstallationRequired;
            const now = try self.effectClock(clock);
            const prepared = try self.prepareExpiryTx(installation, key, expected_revision, now);
            _ = try self.commitEffectClock(clock);
            try self.commitEffectTransaction(prepared.expired != 0);
            return prepared.entry;
        }
        pub fn prepareExpiries(self: *Store, items: []const ExpiryItem, clock: effects.Clock) Error!usize {
            if (items.len == 0 or items.len > max_expiry_batch) return error.InvalidEffect;
            try self.beginWrite();
            errdefer self.rollback();
            const installation = try self.readInstallation() orelse return error.InstallationRequired;
            const now = try self.effectClock(clock);
            var expired_scopes: usize = 0;
            for (items) |item| {
                if ((try self.prepareExpiryTx(installation, item.key, item.revision, now)).expired != 0) expired_scopes += 1;
            }
            _ = try self.commitEffectClock(clock);
            try self.commitEffectTransaction(expired_scopes != 0);
            return expired_scopes;
        }
        fn prepareExpiryTx(self: *Store, installation: effects.Installation, key: effects.Hash, expected_revision: u64, now: i64) Error!struct { entry: effects.Entry, expired: u64 } {
            const prior = try self.readEffect(key, installation) orelse return error.StaleEffect;
            if (prior.revision != expected_revision) return error.StaleEffect;
            if (prior.status == .dispatched) return error.EffectReconciliationRequired;
            self.noteEffectChange(key);
            var owners: [effects.max_page]effects.Owner = undefined;
            const count = try self.readOwners(key, &owners);
            var expired: u64 = 0;
            var expiring_count: u64 = 0;
            for (owners[0..count]) |owner| if (owner.lease == .finite and !owner.lease.live(now)) {
                expiring_count += 1;
            };
            if (try self.tableRows(.effect_owner_revisions) > effects.max_owner_revisions - expiring_count) return error.EffectCapacity;
            for (owners[0..count]) |owner| if (owner.lease == .finite and !owner.lease.live(now)) {
                if (owner.revision == std.math.maxInt(i64)) return error.EffectCapacity;
                try self.retireOwnerDecisionTx(key, owner.jail.slice(), null, now);
                var row = try self.statement("UPDATE effect_owners SET lease_kind=0,deadline_us=NULL,revision=revision+1 WHERE scope_key=?1 AND jail=?2;");
                defer row.deinit();
                try row.blob(1, &key);
                try row.text(2, owner.jail.slice());
                try row.done();
                self.insertedRows(.effect_owner_revisions, self.api.changes(self.db));
                expired += 1;
            };
            var entry = prior;
            if (expired != 0) {
                const effect_revision = std.math.add(u64, prior.revision, expired) catch return error.EffectCapacity;
                if (effect_revision > std.math.maxInt(i64)) return error.EffectCapacity;
                entry = try self.replaceEffectIntent(installation, prior.scope, key, effect_revision, prior.intent_id, now);
            }
            return .{ .entry = entry, .expired = expired };
        }
        pub fn confirmedEffectEvents(self: *Store) Error!u64 {
            const count = try self.integer("SELECT count(*) FROM confirmed_effect_events;");
            return std.math.cast(u64, count) orelse error.InvalidEffect;
        }
    };
}
