// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const durable = @import("../core/record_store.zig");
const plan = @import("../config/native_consumer_plan.zig");
const consumers = @import("../core/native_consumer.zig");
const bridge = @import("../core/native_consumer_coordinator.zig");
const rule = @import("../core/native_rule_consumer.zig");
const ignore = @import("../core/native_ignore.zig");
const retry = @import("../core/native_retry.zig");
const files = @import("../core/durable_file_source.zig");
const file_session = @import("../core/native_file_session.zig");
const journal_session = @import("../core/native_journal_session.zig");
const reload = @import("native_reload.zig");
const detection = @import("../core/native_detection_record.zig");
const Hash = std.crypto.hash.sha2.Sha256;

pub fn digest(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    Hash.hash(bytes, &result, .{});
    return result;
}
fn equal(a: [32]u8, b: [32]u8) bool {
    return std.mem.eql(u8, &a, &b);
}
fn part(hash: *Hash, bytes: []const u8) void {
    var size: [8]u8 = undefined;
    std.mem.writeInt(u64, &size, bytes.len, .little);
    hash.update(&size);
    hash.update(bytes);
}
fn number(hash: *Hash, value: u64) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .little);
    hash.update(&bytes);
}
pub fn transcript() Hash {
    var result = Hash.init(.{});
    result.update("fail2zig-custom-rebind-source-proof-v1\x00");
    return result;
}

pub const Progress = struct {
    context: ?*anyopaque,
    report: *const fn (?*anyopaque, u64) void,
    monotonic_ms: *const fn (?*anyopaque) u64,
};
fn unavailableSource(_: []const u8, _: [32]u8, _: ?*anyopaque) anyerror!void {
    return error.ConsumerRuntimeNotReady;
}
fn oldGeneration(allocator: std.mem.Allocator, jail: anytype, parent: [32]u8, initial: *const ignore.Snapshot, saved: retry.Admission, resolver: ?[32]u8, form: retry.HashForm, progress: Progress) ![32]u8 {
    const assets = jail.custom_plan.?;
    var settings = assets.settings;
    settings.journal_origin = switch (jail.plan) {
        .journal => |value| &value.profile,
        else => null,
    };
    settings.authority_revision = if (resolver != null) 1 else 0;
    settings.monotonic_ms = progress.monotonic_ms;
    settings.clock_context = progress.context;
    var registry = bridge.Registry.init(try assets.legacySemanticGeneration(parent, initial, settings, resolver));
    var scratch: [2048]u8 = undefined;
    return switch (jail.plan) {
        .file => |value| blk: {
            var options = try value.customSessionOptions(parent);
            options.retry = saved.policy;
            options.retry_hash = form;
            options.staged_detection = registry.consumer();
            options.consumer_sources = .{ .context = null, .admit = unavailableSource };
            const processor = try file_session.Session.prepareProcessor(allocator, options, value.specs, &scratch, .{ .us = 0 });
            break :blk processor.generation;
        },
        .journal => |value| blk: {
            var options = value.sessionOptions();
            options.processing.parent_generation = parent;
            options.retry = saved.policy;
            options.retry_hash = form;
            options.staged_detection = registry.consumer();
            options.consumer_sources = .{ .context = null, .admit = unavailableSource };
            const processor = try journal_session.Session.prepareProcessor(allocator, options, &scratch, .{ .us = 0 });
            break :blk processor.generation;
        },
        .internal => error.CustomLegacyIdentityMismatch,
    };
}
fn proves(allocator: std.mem.Allocator, jail: anytype, parent: [32]u8, payload: []const u8, saved: retry.Admission, resolver: ?[32]u8, progress: Progress) !bool {
    var options = jail.custom_plan.?.ignore_options;
    options.parent_generation = parent;
    const initial = ignore.Snapshot.restoreLegacy(allocator, options, payload) catch |failure| {
        if (failure == error.OutOfMemory) return failure;
        return false;
    };
    defer initial.destroy();
    if (equal(try oldGeneration(allocator, jail, parent, initial, saved, resolver, .identity, progress), saved.generation)) return true;
    return equal(try oldGeneration(allocator, jail, parent, initial, saved, resolver, .stored, progress), saved.generation);
}

// Called with the startup writer held, before generation-sensitive admission.
pub fn migrate(allocator: std.mem.Allocator, store: *durable.Store, jail: anytype, resolver: ?[32]u8, planned: [32]u8, reclaim_completed: *bool, progress: Progress) !bool {
    const assets = jail.custom_plan orelse return false;
    const saved = try store.readRetryPolicy(jail.name);
    const existing = try store.customIgnoreState(allocator, jail.name);
    defer if (existing) |value| value.deinit(allocator);
    if (existing) |value| {
        if (value.value.format_version == ignore.version) {
            if (!equal(value.parent, assets.parent_generation)) return error.CustomLegacyIdentityMismatch;
            return false;
        }
        if (value.value.format_version != 1 or value.value.valid_until_us != null) return error.CustomLegacyProofRequired;
    } else if (saved == null or equal(saved.?.generation, planned)) return false;
    const prior = saved orelse return error.CustomLegacyProofRequired;
    if (!try durable.Store.retryPoliciesEqual(prior.policy, jail.policy)) return error.CustomLegacyIdentityMismatch;
    var old_parent: [32]u8 = if (existing) |value| value.parent else undefined;
    var evidence: ?durable.Store.CustomEvidenceCursor = null;
    var evidence_hash = [_]u8{0} ** 32;
    var found = false;
    if (existing) |value| {
        var options = assets.ignore_options;
        options.parent_generation = value.parent;
        const live = try ignore.Snapshot.restoreLegacy(allocator, options, value.value.payload.?);
        live.destroy();
        found = try proves(allocator, jail, old_parent, value.value.payload.?, prior, resolver, progress);
    }
    var after_evidence: ?durable.Store.CustomEvidenceCursor = null;
    var examined: u64 = 0;
    while (!found) {
        const item = try store.customEvidenceNext(allocator, after_evidence) orelse return error.CustomLegacyProofRequired;
        defer item.deinit(allocator);
        after_evidence = item.cursor;
        examined += 1;
        progress.report(progress.context, examined);
        if (!std.mem.eql(u8, item.cursor.jail.slice(), jail.name)) continue;
        // The header only routes a candidate; typed restoration and the complete binding prove it.
        if (item.payload.len < 80 or !std.mem.eql(u8, item.payload[0..4], "F2NI") or std.mem.readInt(u16, item.payload[4..6], .little) != 1) continue;
        const candidate_parent = item.payload[8..40].*;
        if (existing != null and !equal(candidate_parent, old_parent)) continue;
        if (!equal(item.digest, try reload.jailDigest(jail.name, prior.policy, prior.generation))) continue;
        if (!try proves(allocator, jail, candidate_parent, item.payload, prior, resolver, progress)) continue;
        old_parent = candidate_parent;
        evidence = item.cursor;
        evidence_hash = digest(item.payload);
        found = true;
    }
    const cursors: durable.Store.CursorRekey = switch (jail.plan) {
        .file => |value| blk: {
            const options = value.sessionOptions().processing;
            break :blk .{ .file = .{
                .legacy = files.FileSource.framingBinding(options.encoding, prior.generation, options.max_record_bytes),
                .planned = files.FileSource.framingBinding(options.encoding, planned, options.max_record_bytes),
            } };
        },
        .journal => .journal,
        .internal => return error.CustomLegacyIdentityMismatch,
    };
    var target = durable.Store.CustomRebindTarget{
        .jail = try detection.Name.init(jail.name),
        .old_parent = old_parent,
        .new_parent = assets.parent_generation,
        .old_generation = prior.generation,
        .new_generation = planned,
        .cursors = cursors,
        .expected_consumer_revision = try store.consumerRevision(),
        .expected_checkpoint_revision = try store.revision(jail.name),
        .old_ignore_revision = if (existing) |value| value.value.revision else 0,
        .old_ignore_sha256 = if (existing) |value| digest(value.value.payload.?) else [_]u8{0} ** 32,
        .evidence = evidence,
        .evidence_sha256 = evidence_hash,
        .source_count = 0,
        .source_proof_sha256 = undefined,
    };
    if (existing == null) {
        try store.rebindUnopenedCustom(&target);
        return true;
    }
    var source_hash = transcript();
    target.source_count = try sources(allocator, store, assets, &target, resolver, &source_hash, false, progress, &examined);
    target.source_proof_sha256 = source_hash.finalResult();
    if (!reclaim_completed.*) {
        var cursor = durable.ReclaimCursor{ .phase = 1 };
        var window: u16 = 1024;
        while (cursor.phase < 3) {
            try store.reclaimCustomCompatibilityPage(&cursor, &window);
            examined += 1;
            progress.report(progress.context, examined);
        }
        reclaim_completed.* = true;
    }
    var revision = try store.stageCustomIgnoreRebind(&target, .{
        .old_key = .{ .kind = .ignore, .jail = jail.name, .source = "@shared", .rule = "allowlist", .generation = old_parent },
        .new_key = .{ .kind = .ignore, .jail = jail.name, .source = "@shared", .rule = "allowlist", .generation = assets.parent_generation },
        .old_format = 1,
        .new_format = ignore.version,
        .revision = target.old_ignore_revision,
        .old_payload_sha256 = target.old_ignore_sha256,
        .new_payload = assets.initial_ignore.payload,
        .valid_until_us = null,
    });
    var replay_hash = transcript();
    const count = try sources(allocator, store, assets, &target, resolver, &replay_hash, true, progress, &examined);
    revision = try store.consumerRevision();
    var cursor = durable.Store.CustomIdentityCursor{ .expected_consumer_revision = revision };
    var page_size: u8 = 64;
    while (cursor.phase != .done) {
        const result = store.customIdentityStep(&target, cursor, page_size) catch |failure| {
            if (failure != error.Interrupted or !store.startupAdmissionActive()) return failure;
            if (page_size == 1) return error.MaintenanceWorkExhausted;
            page_size = @max(1, page_size / 2);
            continue;
        };
        cursor = result.cursor;
        examined += 1;
        progress.report(progress.context, examined);
    }
    _ = try store.finishCustomRebind(&target, cursor.expected_consumer_revision, count, replay_hash.finalResult());
    return true;
}
fn sources(allocator: std.mem.Allocator, store: *durable.Store, assets: *const plan.Prepared, target: *const durable.Store.CustomRebindTarget, resolver: ?[32]u8, hash: *Hash, apply: bool, progress: Progress, examined: *u64) !u16 {
    var after: ?[]u8 = null;
    defer if (after) |value| allocator.free(value);
    var count: u16 = 0;
    var revision = try store.consumerRevision();
    while (true) {
        var keys: [1]durable.Store.ManifestKey = undefined;
        const page = try store.consumerManifestKeysPage(allocator, target.jail.slice(), after, revision, &keys);
        if (page.count == 0) break;
        const key = keys[0];
        defer key.deinit(allocator);
        if (count == 4096) return error.ConsumerCapacity;
        const prepared = try Source.prepare(allocator, store, assets, target, key, resolver);
        defer prepared.destroy();
        try prepared.include(hash);
        if (apply) revision = try store.rebindCustomSource(target, prepared.update);
        count += 1;
        examined.* += 1;
        progress.report(progress.context, examined.*);
        if (!page.more) break;
        const next = try allocator.dupe(u8, key.source);
        if (after) |value| allocator.free(value);
        after = next;
    }
    return count;
}

// One source owns its payloads; manifest/key strings borrow the caller's live target and source.
pub const Source = struct {
    allocator: std.mem.Allocator,
    saved: ?durable.Store.ManifestSnapshot = null,
    old_requirements: [bridge.max_rules + 2]consumers.Requirement = undefined,
    new_requirements: [bridge.max_rules + 2]consumers.Requirement = undefined,
    payloads: [bridge.max_rules][rule.checkpoint_bytes]u8 = undefined,
    changes: [bridge.max_rules]durable.Store.CustomCheckpointRebind = undefined,
    update: durable.Store.CustomSourceRebind = undefined,

    pub fn prepare(allocator: std.mem.Allocator, store: *durable.Store, assets: *const plan.Prepared, target: *const durable.Store.CustomRebindTarget, key: durable.Store.ManifestKey, resolver: ?[32]u8) !*Source {
        if (assets.count == 0 or assets.count > bridge.max_rules or key.status != .ready or !equal(key.generation, target.old_generation)) return error.CustomLegacyIdentityMismatch;
        const self = try allocator.create(Source);
        self.* = .{ .allocator = allocator };
        errdefer self.destroy();
        const jail = target.jail.slice();
        for (assets.programs, 0..) |program, i| {
            const old = try rule.Consumer.init(program, jail, key.source, target.old_parent, resolver != null);
            const next = try rule.Consumer.init(program, jail, key.source, target.new_parent, resolver != null);
            const kind: consumers.Kind = if (program.metadata().correlation != null) .correlation else .rule;
            self.old_requirements[i] = .{ .key = .{ .kind = kind, .jail = jail, .source = key.source, .rule = program.metadata().id, .generation = old.binding }, .format_version = rule.version };
            self.new_requirements[i] = .{ .key = .{ .kind = kind, .jail = jail, .source = key.source, .rule = program.metadata().id, .generation = next.binding }, .format_version = rule.version };
        }
        const n = assets.count;
        self.old_requirements[n] = .{ .key = .{ .kind = .ignore, .jail = jail, .source = "@shared", .rule = "allowlist", .generation = target.old_parent }, .format_version = 1 };
        self.new_requirements[n] = .{ .key = .{ .kind = .ignore, .jail = jail, .source = "@shared", .rule = "allowlist", .generation = target.new_parent }, .format_version = ignore.version };
        const required = n + 1 + @intFromBool(resolver != null);
        if (resolver) |generation| {
            self.old_requirements[n + 1] = .{ .key = bridge.resolverKey(generation), .format_version = 1 };
            self.new_requirements[n + 1] = self.old_requirements[n + 1];
        }
        const old_manifest = consumers.Manifest{ .jail = jail, .source = key.source, .source_generation = target.old_generation, .required = self.old_requirements[0..required] };
        const next_manifest = consumers.Manifest{ .jail = jail, .source = key.source, .source_generation = target.new_generation, .required = self.new_requirements[0..required] };
        if (!equal(try old_manifest.digest(), key.digest)) return error.CustomLegacyIdentityMismatch;
        self.saved = try store.consumerManifestSnapshot(allocator, old_manifest);
        const saved = &self.saved.?;
        if (saved.status != .ready or saved.count != required) return error.CustomLegacyIdentityMismatch;
        // Include decoder workspace and one retained historical payload, not just copied output bytes.
        var bytes: usize = @sizeOf(Source) + 2 * @sizeOf(rule.Consumer) + @sizeOf(ignore.Snapshot) + ignore.max_entries * @sizeOf(ignore.Entry) + ignore.max_checkpoint_bytes + key.source.len;
        for (saved.states[0..saved.count]) |state| {
            const payload = state.payload orelse return error.MissingRequiredConsumer;
            bytes = std.math.add(usize, bytes, payload.len) catch return error.ConsumerCapacity;
        }
        if (bytes > consumers.max_prepared_bytes) return error.ConsumerCapacity;
        for (assets.programs, 0..) |program, i| {
            const value = saved.states[i];
            if (value.revision == 0 or value.format_version != rule.version) return error.CustomLegacyIdentityMismatch;
            const payload = value.payload.?;
            try rule.Consumer.rebindCheckpoint(program, jail, key.source, target.old_parent, target.new_parent, resolver != null, payload, &self.payloads[i]);
            self.changes[i] = .{ .old_key = self.old_requirements[i].key, .new_key = self.new_requirements[i].key, .old_format = rule.version, .new_format = rule.version, .revision = value.revision, .old_payload_sha256 = digest(payload), .new_payload = &self.payloads[i], .valid_until_us = value.valid_until_us };
        }
        const policy = saved.states[n];
        if (policy.format_version != 1 or policy.revision != target.old_ignore_revision or policy.valid_until_us != null or !equal(digest(policy.payload.?), target.old_ignore_sha256)) return error.CustomLegacyIdentityMismatch;
        var options = assets.ignore_options;
        options.parent_generation = target.old_parent;
        const restored = try ignore.Snapshot.restoreLegacy(allocator, options, policy.payload.?);
        restored.destroy();
        if (resolver) |generation| {
            const authority = saved.states[n + 1];
            if (authority.format_version != 1 or authority.revision != 1 or authority.valid_until_us != null or !std.mem.eql(u8, authority.payload.?, &generation)) return error.CustomLegacyIdentityMismatch;
        }
        self.update = .{ .old_manifest = old_manifest, .new_manifest = next_manifest, .status = saved.status, .expected_consumer_revision = saved.revision, .checkpoints = self.changes[0..n] };
        return self;
    }
    pub fn include(self: *const Source, hash: *Hash) !void {
        part(hash, self.update.old_manifest.source);
        part(hash, &try self.update.old_manifest.digest());
        part(hash, &try self.update.new_manifest.digest());
        number(hash, @intFromEnum(self.update.status));
        for (self.update.old_manifest.required, self.saved.?.states[0..self.saved.?.count]) |requirement, value| {
            number(hash, @intFromEnum(requirement.key.kind));
            part(hash, requirement.key.jail);
            part(hash, requirement.key.source);
            part(hash, requirement.key.rule);
            part(hash, &requirement.key.generation);
            number(hash, value.format_version);
            number(hash, value.revision);
            part(hash, &digest(value.payload.?));
            number(hash, @intFromBool(value.valid_until_us != null));
            if (value.valid_until_us) |until| number(hash, @bitCast(until));
        }
    }
    pub fn destroy(self: *Source) void {
        if (self.saved) |*saved| saved.deinit(self.allocator);
        self.allocator.destroy(self);
    }
};
