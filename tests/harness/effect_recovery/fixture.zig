// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Verifies effect recovery on an existing state file and the kernel firewall: owner refusals, stale evidence, drift and rollback.
// Holds: It refuses to run unless F2Z_NATIVE_PARENT_NETNS names a namespace other than the current network namespace.

const std = @import("std");
const engine = @import("engine_test");
const effects = engine.core.native_effect;
const Store = engine.core.record_store.Store;
const inspection = engine.firewall.inspection;

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len != 3) return error.InvalidArguments;
    const legacy = std.mem.eql(u8, args[1], "legacy");
    const drift = std.mem.eql(u8, args[1], "drift");
    const rollback = std.mem.eql(u8, args[1], "rollback");
    if (!legacy and !drift and !rollback and !std.mem.eql(u8, args[1], "reject")) return error.InvalidArguments;
    var ns: [std.fs.max_path_bytes]u8 = undefined;
    const parent_ns = std.posix.getenv("F2Z_NATIVE_PARENT_NETNS") orelse return error.NamespaceRequired;
    if (std.mem.eql(u8, try std.fs.readLinkAbsolute("/proc/self/ns/net", &ns), parent_ns)) return error.NamespaceRequired;
    var store = try Store.openExisting(allocator, args[2]);
    defer store.close();
    if (drift) return verifyDrift(&store);
    if (rollback) return verifyRepairRollback(&store);
    const installation = try store.readInstallation() orelse return error.MissingInstallation;
    var entries: [effects.max_page]effects.Entry = undefined;
    const page = try store.effectPage(null, null, &entries);
    if (page.count == 0) return error.EmptyFixture;
    var entry = for (entries[0..page.count]) |candidate| {
        if (candidate.desired != .absent) break candidate;
    } else return error.MissingLiveOwner;
    if (!legacy) try verifyOwnerRefusals(&store, entry);
    var inspector = try inspection.Inspector.open(allocator, .{ .id = installation.id, .transport = .nftables }, .{});
    defer inspector.close();
    var admitted = try inspector.admitInstallation(.{ .installation = inspector.installation, .intent_id = entry.intent_id, .revision = entry.revision });
    defer admitted.deinit();
    if (admitted != .installed or admitted.installed.snapshot.state != .owned or admitted.installed.snapshot.entries.len != 0) return error.ExpectedEmptyOwnedFirewall;
    const observed = std.time.microTimestamp();
    const fingerprint = admitted.installed.snapshot.fingerprint;
    // Why: The release intents must be created at a later microsecond than the observation, so the observation is stale when settled.
    std.Thread.sleep(std.time.ns_per_ms);
    var owners: [effects.max_page]effects.Owner = undefined;
    const count = try store.effectOwners(entry.scope_key, entry.revision, &owners);
    var released: usize = 0;
    for (owners[0..count]) |owner| {
        if (owner.lease == .absent) continue;
        const now = std.time.microTimestamp();
        entry = try store.transitionOwner(.{
            .scope = entry.scope.canonical,
            .jail = owner.jail.slice(),
            .current_generation = owner.generation,
            .next_generation = owner.generation,
            .expected_owner_revision = owner.revision,
            .transition_id = effects.hashParts("effect-recovery-verifier-release", &.{ &entry.intent_id, owner.jail.slice() }),
            .mode = .release,
            .occurred_us = now,
        }, .{ .prepared_us = now });
        released += 1;
    }
    if (entry.desired != .absent or entry.status != .pending or observed >= entry.intent_us) return error.ExpectedNewPendingAbsence;
    const outcome = store.settleOutcome(entry.token(), observed, .{
        .installation = installation.id,
        .scope_key = entry.scope_key,
        .fingerprint = fingerprint,
        .observed_us = observed,
        .qualification = .complete_owned,
        .state = .absent,
    }, .{ .prepared_us = std.time.microTimestamp() });
    if (legacy) {
        if (try outcome != .verified) return error.ExpectedLegacySettlement;
        if (store.readEffect(entry.scope_key, installation)) |_| return error.ExpectedInvalidStoredEvidence else |failure| {
            if (failure != error.InvalidEffect) return failure;
        }
    } else {
        if (outcome) |_| return error.StaleEvidenceWasCommitted else |failure| {
            if (failure != error.InvalidEffect) return failure;
        }
        const unchanged = try store.readEffect(entry.scope_key, installation) orelse return error.MissingEffect;
        if (!std.meta.eql(entry, unchanged)) return error.RollbackChangedEffect;
        var row = try store.statement("SELECT dispatch_us,observed_us,fingerprint,(SELECT count(*) FROM effect_observations WHERE intent_id=?1) FROM effect_intents WHERE intent_id=?1;");
        defer row.deinit();
        try row.blob(1, &entry.intent_id);
        if (!try row.row() or try row.optionalSigned(0) != null or try row.optionalSigned(1) != null or store.api.column_type(row.ptr, 2) != 5 or try row.signed(3) != 0) return error.RollbackLeftEvidence;
    }
    try std.json.stringify(.{ .mode = args[1], .released_owners = released, .scope_key = std.fmt.fmtSliceHexLower(&entry.scope_key), .intent_id = std.fmt.fmtSliceHexLower(&entry.intent_id), .observation_us = observed, .created_us = entry.intent_us, .result = if (legacy) "invalid evidence committed by legacy writer" else "writer rejected stale evidence transactionally" }, .{}, std.io.getStdOut().writer());
    try std.io.getStdOut().writer().writeByte('\n');
}

const HeldClock = struct {
    now: i64,
    fn read(context: ?*anyopaque) i64 {
        const self: *HeldClock = @ptrCast(@alignCast(context.?));
        return self.now;
    }
};

fn verifyDrift(store: *Store) !void {
    if (comptime @hasDecl(engine, "native_effect_runtime")) {
        const runtime = engine.native_effect_runtime;
        const Name = engine.core.native_detection_record.Name;
        var names: [64]Name = undefined;
        var bindings: [64]runtime.Binding = undefined;
        var count: usize = 0;
        {
            var row = try store.statement("SELECT jail,generation FROM retry_policies ORDER BY jail;");
            defer row.deinit();
            while (try row.row()) {
                if (count == bindings.len) return error.FixtureCapacity;
                names[count] = try Name.init(try row.boundedBytes(0, 64));
                bindings[count] = .{ .jail = names[count].slice(), .generation = try Store.effectBlob(&row, 1, 32) };
                count += 1;
            }
        }
        const installation = try store.readInstallation() orelse return error.MissingInstallation;
        var manager = try runtime.Manager.create(std.heap.page_allocator, store, installation);
        defer manager.destroy();
        try manager.inspector.subscribe();
        manager.events_subscribed = manager.inspector.subscribed();
        manager.verify_interval_ns = 60 * std.time.ns_per_s;
        try advance(manager, bindings[0..count]);
        if (!manager.events_subscribed or !manager.events_healthy) return error.EventSubscriptionRequired;
        const held = manager.inventory orelse return error.MissingInventory;
        const entry = for (manager.live[0..manager.count]) |candidate| {
            if (candidate.desired == .permanent) break candidate;
        } else return error.MissingPermanentOwner;
        var row = try store.statement("SELECT observed_us FROM effect_intents WHERE intent_id=?1;");
        defer row.deinit();
        try row.blob(1, &entry.intent_id);
        if (!try row.row()) return error.MissingEffect;
        const observed = try row.signed(0);
        try std.io.getStdOut().writer().print("cached_end_us={d} accepted_us={d} acknowledged_batches={d}\n", .{ held.end_us, observed, manager.counters.acknowledged_batches });
        if (held.end_us >= observed) return error.CachedEvidenceBranchNotReached;
        var inspector = try inspection.Inspector.open(std.heap.page_allocator, manager.inspector.installation, .{});
        defer inspector.close();
        var removed = try inspector.applyExact(.{ .installation = inspector.installation, .effect_id = entry.scope_key, .aggregate_revision = entry.revision, .scope = entry.scope.canonical, .operation = .ensure_absent }, .{ .wall_us = std.time.microTimestamp() });
        defer removed.deinit();
        if (removed != .verified or !removed.verified.changed) return error.ExpectedExternalRemoval;
        std.Thread.sleep(2 * std.time.ns_per_ms);
        try advance(manager, bindings[0..count]);
        if (!manager.appliedKey(entry.scope_key, std.time.microTimestamp())) return error.ProtectionNotRestored;
        var restored = try inspector.inspect();
        defer restored.deinit();
        if (try restored.find(entry.scope.canonical) == null) return error.KernelBanNotRestored;
        try std.io.getStdOut().writer().print("restored=true full_readbacks={d} events_applied={d}\n", .{ manager.counters.full_readbacks, manager.counters.events_applied });
        var clock = HeldClock{ .now = manager.last_wall_us - 1 };
        manager.wall = HeldClock.read;
        manager.wall_context = &clock;
        const slice = manager.runSlice(bindings[0..count], .{ .max_steps = 32 }, null);
        if (slice.outcome != .fatal or slice.outcome.fatal != error.EffectClockReversed) return error.ExpectedClockRegressionRefusal;
        try std.io.getStdOut().writer().writeAll("clock_regression_refused=true\n");
    } else return error.RuntimeApiUnavailable;
}

fn verifyOwnerRefusals(store: *Store, entry: effects.Entry) !void {
    var owners: [effects.max_page]effects.Owner = undefined;
    const count = try store.effectOwners(entry.scope_key, entry.revision, &owners);
    const owner = for (owners[0..count]) |candidate| {
        if (candidate.lease != .absent) break candidate;
    } else return error.MissingLiveOwner;
    const revision = try store.integer("SELECT revision FROM effect_clock;");
    var generation = owner.generation;
    generation[0] ^= 1;
    const now = std.time.microTimestamp();
    var change = effects.OwnerChange{ .scope = entry.scope, .jail = owner.jail.slice(), .generation = generation, .decision_id = effects.hashParts("effect-recovery-owner-refusal", &.{&entry.intent_id}), .expected_revision = owner.revision, .lease = owner.lease, .decided_us = now, .origin = .manual };
    if (store.setOwner(change, .{ .prepared_us = now })) |_| return error.LiveOwnerGenerationAccepted else |failure| {
        if (failure != error.EffectGenerationMismatch) return failure;
    }
    change.generation = owner.generation;
    change.expected_revision += 1;
    if (store.setOwner(change, .{ .prepared_us = now })) |_| return error.StaleOwnerRevisionAccepted else |failure| {
        if (failure != error.StaleEffect) return failure;
    }
    const after = try store.readEffect(entry.scope_key, entry.installation) orelse return error.MissingEffect;
    if (!std.meta.eql(entry, after) or revision != try store.integer("SELECT revision FROM effect_clock;")) return error.RefusalChangedEffect;
    var after_owners: [effects.max_page]effects.Owner = undefined;
    const after_count = try store.effectOwners(entry.scope_key, entry.revision, &after_owners);
    if (after_count != count) return error.RefusalChangedOwner;
    for (owners[0..count], after_owners[0..after_count]) |before, after_owner| if (!std.meta.eql(before, after_owner)) return error.RefusalChangedOwner;
    try std.io.getStdOut().writer().writeAll("live_generation_refused=true stale_revision_refused=true\n");
}

fn verifyRepairRollback(store: *Store) !void {
    if (comptime @hasDecl(Store, "effectEvidencePage")) {
        const before = try store.effectEvidencePage(null, false, .{ .prepared_us = std.time.microTimestamp() });
        if (before.eligible != 1 or !before.done) return error.ExpectedOneEligibleIntent;
        const observations = try store.integer("SELECT count(*) FROM effect_observations;");
        const revision = try store.integer("SELECT revision FROM effect_clock;");
        store.fail_at = .before_effect_receipt_commit;
        const result = store.effectEvidencePage(null, true, .{ .prepared_us = std.time.microTimestamp() });
        store.fail_at = null;
        if (result) |_| return error.ExpectedInjectedFailure else |failure| {
            if (failure != error.InjectedFailure) return failure;
        }
        const after = try store.effectEvidencePage(null, false, .{ .prepared_us = std.time.microTimestamp() });
        if (!std.meta.eql(before, after) or observations != try store.integer("SELECT count(*) FROM effect_observations;") or revision != try store.integer("SELECT revision FROM effect_clock;")) return error.RollbackChangedEvidence;
        try std.io.getStdOut().writer().writeAll("repair_precommit_rollback=true\n");
    } else return error.RepairApiUnavailable;
}

fn advance(manager: anytype, bindings: anytype) !void {
    var timer = try std.time.Timer.start();
    while (timer.read() < 10 * std.time.ns_per_s) {
        const slice = manager.runSlice(bindings, .{ .max_steps = 32 }, null);
        switch (slice.outcome) {
            .fatal => |failure| return failure,
            .stop => return error.UnexpectedStop,
            .wait => std.Thread.sleep(100 * std.time.ns_per_ms),
            .idle, .progress => {},
        }
        if (manager.status.ready) return;
    }
    return error.ReadinessTimeout;
}
