// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Source-bound reversible bridge into the existing native record transaction.
//! All owners, configuration slices and programs outlive this stable coordinator.
//! DNS scheduling and SQL remain with the daemon; neither occurs during prepare.
const std = @import("std");
const rules = @import("native_rules.zig");
const rule = @import("native_rule_consumer.zig");
const state = @import("native_consumer.zig");
const detection = @import("native_detection_record.zig");
const records = @import("source_record.zig");
const dns = @import("native_dns.zig");
const ignore = @import("native_ignore.zig");
const origin = @import("native_journal_origin.zig");
pub const max_rules = 8;
pub const max_sources = 4096;
pub const Settings = struct {
    jail: []const u8,
    logical_source: []const u8,
    filter: detection.Name,
    parent_generation: [32]u8,
    /// Configured initial contents; construct against this immutable snapshot
    /// before publishing a coherent saved mutable allowlist into its owner.
    ignore_generation: [32]u8,
    /// Immutable resolver authority is durably admitted before source binding.
    authority_revision: u64 = 0,
    family: dns.Family = .both,
    journal: bool = false,
    journal_origin: ?*const origin.Profile = null,
    clock_context: ?*anyopaque = null,
    clock: *const fn (?*anyopaque) i64 = systemClock,
    monotonic_ms: ?*const fn (?*anyopaque) u64 = null,
    turn: ?*const fn (?*anyopaque) u64 = null,
};
fn systemClock(_: ?*anyopaque) i64 {
    return std.time.microTimestamp();
}
pub const Saved = struct { key: state.Key, format_version: u16, revision: u64, payload: []const u8, valid_until_us: ?i64 = null };
pub const StateStage = struct {
    manifest: state.Manifest,
    state: detection.StagedState,
    bootstrap: bool,
};
pub const Pending = struct { request: dns.Request, purpose: enum { subject, exclusion }, occurrence: [32]u8 };
/// Semantic identity deliberately excludes incarnation. The processor binds it
/// to codec/time policy before the exact incarnation is known at source attach.
pub fn generation(settings: Settings, programs: []const *const rules.Program, ignores: *const ignore.Owner, cache: ?*const dns.Cache) ![32]u8 {
    return generationFromInitial(settings, programs, ignores.live, cache);
}
fn generationFromInitial(settings: Settings, programs: []const *const rules.Program, initial: *const ignore.Snapshot, cache: ?*const dns.Cache) ![32]u8 {
    return generationFromPolicy(settings, programs, initial, if (cache) |owner| owner.generation else null);
}
/// Pure preflight of immutable policy; does not consult mutable resolver state
/// or invoke clocks. Runtime construction uses this same semantic identity.
pub fn generationFromPolicy(settings: Settings, programs: []const *const rules.Program, initial: *const ignore.Snapshot, resolver_generation: ?[32]u8) ![32]u8 {
    if (programs.len == 0 or programs.len > max_rules) return error.ConsumerCapacity;
    if (settings.filter.len == 0 or settings.filter.len > 64) return error.InvalidConsumer;
    try (state.Key{ .kind = .rule, .jail = settings.jail, .source = settings.logical_source, .rule = settings.filter.slice(), .generation = settings.parent_generation }).validate();
    if (settings.journal and settings.journal_origin == null) return error.JournalOriginRequired;
    if (!settings.journal and settings.journal_origin != null) return error.InvalidConsumer;
    if (initial.options.family != settings.family or std.mem.allEqual(u8, &settings.ignore_generation, 0) or
        !std.mem.eql(u8, &initial.generation, &settings.ignore_generation)) return error.IgnoreGenerationMismatch;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("fail2zig-native-coordinator-v1\x00");
    hash.update(&settings.parent_generation);
    hash.update(&settings.ignore_generation);
    hash.update(&initial.options.parent_generation);
    hash.update(&initial.options.resolver_generation);
    hash.update(&.{ @intFromEnum(settings.family), @intFromBool(settings.journal) });
    if (settings.journal_origin) |profile| hash.update(&profile.generation);
    if (resolver_generation) |resolver| {
        if (settings.authority_revision != 1) return error.DnsAuthorityRequired;
        if (!std.mem.eql(u8, &resolver, &initial.options.resolver_generation)) return error.DnsGenerationMismatch;
        hash.update(&resolver);
    }
    var hostname_rules: usize = 0;
    for (programs, 0..) |program, i| {
        const spec = program.metadata();
        if (!std.mem.eql(u8, spec.source, settings.logical_source)) return error.ConsumerSourceMismatch;
        _ = try detection.Name.init(spec.id);
        for (programs[0..i]) |prior| if (std.mem.eql(u8, prior.metadata().id, spec.id)) return error.InvalidConsumer;
        if (spec.subject_kind == .hostname) hostname_rules += 1;
        hash.update(&program.generation);
    }
    var hostname_ignores: usize = 0;
    for (initial.entries) |entry| if (entry == .hostname) {
        hostname_ignores += 1;
    };
    // Dependencies reserve immutable ignore and configured resolver authority revisions. Admission uses
    // a conservative union bound; never discovers an impossible batch at commit.
    if (hostname_rules + hostname_ignores > state.max_dependencies - 1 - @as(usize, @intFromBool(resolver_generation != null))) return error.ConsumerCapacity;
    if (hostname_rules + hostname_ignores != 0 and resolver_generation == null) return error.HostnameResolutionRequired;
    if (hostname_rules + hostname_ignores != 0 and settings.monotonic_ms == null) return error.DnsMonotonicClockRequired;
    for ([_][]const u8{ settings.jail, settings.logical_source, settings.filter.slice() }) |value| {
        var length: [8]u8 = undefined;
        std.mem.writeInt(u64, &length, value.len, .little);
        hash.update(&length);
        hash.update(value);
    }
    return hash.finalResult();
}
pub const Coordinator = struct {
    settings: Settings,
    incarnation: []const u8,
    generation: [32]u8,
    owners: []const *rule.Consumer,
    ignores: *ignore.Owner,
    cache: ?*dns.Cache,
    revisions: [max_rules]u64 = [_]u64{0} ** max_rules,
    ready: bool = false,
    busy: bool = false,
    published: bool = false,
    mode: enum { record, checkpoint, bootstrap, restore, dns_input, allowlist } = .record,
    ignore_stage: ?ignore.Owner.Stage = null,
    stages: [max_rules]?rule.Prepared = [_]?rule.Prepared{null} ** max_rules,
    restore_revisions: [max_rules]u64 = undefined,
    deltas: [state.max_deltas]state.Delta = undefined,
    delta_count: usize = 0,
    dependencies: [state.max_dependencies]state.Dependency = undefined,
    dependency_count: usize = 0,
    names: [state.max_dependencies]dns.Name = undefined,
    name_count: usize = 0,
    requirements: [max_rules + 2]state.Requirement = undefined,
    outcomes: [16]detection.Outcome = undefined,
    outcome_count: usize = 0,
    prepared_us: i64 = 0,
    deadline: ?i64 = null,
    ignore_reserved: bool = false,
    pending: ?Pending = null,
    waiting_occurrence: ?[32]u8 = null,
    next_request: u64 = 1,
    dns_stage: ?dns.Cache.Stage = null,
    immediate: ?dns.Result = null,
    request_deadline_ms: ?u64 = null,
    reservation_turn: ?u64 = null,
    processing_reserved: bool = false,
    active_turn: ?u64 = null,
    dns_name: dns.Name = undefined,
    dns_manifest_source: [260]u8 = undefined,
    dns_requirement: [1]state.Requirement = undefined,

    pub fn init(settings: Settings, incarnation: []const u8, owners: []const *rule.Consumer, ignores: *ignore.Owner, cache: ?*dns.Cache) !Coordinator {
        return initWithInitial(settings, incarnation, owners, ignores, ignores.live, cache);
    }
    /// New sources may bind after a saved mutable ignore snapshot was restored.
    /// Initial content identity remains immutable; live state must retain policy.
    pub fn initWithInitial(settings: Settings, incarnation: []const u8, owners: []const *rule.Consumer, ignores: *ignore.Owner, initial: *const ignore.Snapshot, cache: ?*dns.Cache) !Coordinator {
        if (!std.mem.eql(u8, &ignores.live.options.parent_generation, &initial.options.parent_generation) or
            !std.mem.eql(u8, &ignores.live.options.resolver_generation, &initial.options.resolver_generation) or
            ignores.live.options.family != initial.options.family or ignores.live.options.self_required != initial.options.self_required)
            return error.IgnoreGenerationMismatch;
        if (owners.len == 0 or owners.len > max_rules) return error.ConsumerCapacity;
        var programs: [max_rules]*const rules.Program = undefined;
        for (owners, 0..) |owner, i| {
            programs[i] = owner.program;
            const expected = try rule.Consumer.init(owner.program, settings.jail, incarnation, settings.parent_generation, cache != null);
            if (!std.mem.eql(u8, &expected.binding, &owner.binding) or owner.in_flight) return error.RuleGenerationMismatch;
        }
        return .{ .settings = settings, .incarnation = incarnation, .generation = try generationFromInitial(settings, programs[0..owners.len], initial, cache), .owners = owners, .ignores = ignores, .cache = cache };
    }
    fn ruleKey(self: *const Coordinator, index: usize) state.Key {
        const owner = self.owners[index];
        return .{ .kind = if (owner.contexts != null) .correlation else .rule, .jail = self.settings.jail, .source = self.incarnation, .rule = owner.program.metadata().id, .generation = owner.binding };
    }
    fn ignoreKey(self: *const Coordinator) state.Key {
        return .{ .kind = .ignore, .jail = self.settings.jail, .source = "@shared", .rule = "allowlist", .generation = self.ignores.live.options.parent_generation };
    }
    fn authorityKey(self: *const Coordinator) state.Key {
        return resolverKey(self.cache.?.generation);
    }
    fn requiredCount(self: *const Coordinator) usize {
        return self.owners.len + 1 + @intFromBool(self.cache != null);
    }
    pub fn manifest(self: *Coordinator, source_generation: [32]u8) !state.Manifest {
        for (self.owners, 0..) |_, i| self.requirements[i] = .{ .key = self.ruleKey(i), .format_version = rule.version };
        self.requirements[self.owners.len] = .{ .key = self.ignoreKey(), .format_version = ignore.version };
        if (self.cache != null) self.requirements[self.owners.len + 1] = .{ .key = self.authorityKey(), .format_version = 1 };
        const value = state.Manifest{ .jail = self.settings.jail, .source = self.incarnation, .source_generation = source_generation, .required = self.requirements[0..self.requiredCount()] };
        _ = try value.digest();
        return value;
    }
    fn begin(self: *Coordinator, now_us: i64) !void {
        if (self.busy or self.ignores.in_flight) return error.ConsumerBusy;
        self.busy = true;
        self.published = false;
        self.prepared_us = now_us;
        self.delta_count = 0;
        self.dependency_count = 0;
        self.name_count = 0;
        self.outcome_count = 0;
        self.deadline = null;
        self.request_deadline_ms = null;
        self.active_turn = null;
    }
    fn batch(self: *Coordinator) state.Batch {
        return .{ .deltas = self.deltas[0..self.delta_count], .dependencies = self.dependencies[0..self.dependency_count], .prepared_us = self.prepared_us, .commit_before_us = self.deadline, .clock_context = self, .clock = checkedClock, .admission = admission };
    }
    fn checkedClock(context: ?*anyopaque) i64 {
        const self: *Coordinator = @ptrCast(@alignCast(context.?));
        return self.settings.clock(self.settings.clock_context);
    }
    fn admission(context: ?*anyopaque) state.Error!void {
        const self: *Coordinator = @ptrCast(@alignCast(context.?));
        if (self.request_deadline_ms) |deadline| {
            const clock = self.settings.monotonic_ms orelse return error.InvalidConsumer;
            if (clock(self.settings.clock_context) >= deadline) return error.ConsumerExpired;
        }
        if (self.active_turn) |turn| {
            const current = self.settings.turn orelse return error.InvalidConsumer;
            if (current(self.settings.clock_context) != turn) return error.ConsumerExpired;
        }
    }
    fn stateStage(self: *Coordinator) detection.StagedState {
        return .{ .consumers = self.batch(), .context = self, .publish = publish, .release = release };
    }
    fn delta(self: *Coordinator, value: state.Delta) !void {
        if (self.delta_count == self.deltas.len) return error.ConsumerCapacity;
        self.deltas[self.delta_count] = value;
        self.delta_count += 1;
    }
    fn dependency(self: *Coordinator, value: state.Dependency) !void {
        for (self.dependencies[0..self.dependency_count]) |prior| if (state.Key.eql(prior.key, value.key)) {
            if (prior.expected_revision != value.expected_revision or prior.valid_until_us != value.valid_until_us) return error.ConsumerRevisionMismatch;
            return;
        };
        if (self.dependency_count == self.dependencies.len) return error.ConsumerCapacity;
        self.dependencies[self.dependency_count] = value;
        self.dependency_count += 1;
    }
    fn requiredReads(self: *Coordinator) !void {
        for (self.owners, 0..) |_, i| try self.dependency(.{ .key = self.ruleKey(i), .expected_revision = self.revisions[i] });
        try self.ignoreRead();
        try self.authorityRead();
    }
    fn authorityRead(self: *Coordinator) !void {
        if (self.cache != null) try self.dependency(.{ .key = self.authorityKey(), .expected_revision = self.settings.authority_revision });
    }
    fn ignoreRead(self: *Coordinator) !void {
        if (self.ignores.revision == 0) return error.ConsumerStateNotReady;
        try self.dependency(.{ .key = self.ignoreKey(), .expected_revision = self.ignores.revision });
    }
    pub fn prepareBootstrap(self: *Coordinator, source_generation: [32]u8, now_us: i64) !StateStage {
        if (self.ready) return error.ConsumerAlreadyReady;
        for (self.revisions[0..self.owners.len]) |revision| if (revision != 0) return error.ConsumerStateNotReady;
        try self.begin(now_us);
        errdefer release(self);
        self.mode = .bootstrap;
        for (self.owners) |owner| {
            if (!std.mem.allEqual(u64, &owner.counters, 0)) return error.ConsumerNotFirstUse;
            if (owner.contexts) |contexts| if (contexts.live.watermark_us != null) return error.ConsumerNotFirstUse;
        }
        for (self.owners, 0..) |owner, i| {
            self.stages[i] = try owner.prepareSnapshot();
            try self.delta(.{ .key = self.ruleKey(i), .format_version = rule.version, .expected_revision = 0, .payload = self.stages[i].?.checkpoint });
        }
        if (self.ignores.revision == 0) {
            self.ignores.in_flight = true;
            self.ignore_reserved = true;
            try self.delta(.{ .key = self.ignoreKey(), .format_version = ignore.version, .expected_revision = 0, .payload = self.ignores.live.payload });
        } else try self.ignoreRead();
        try self.authorityRead();
        try self.batch().validate();
        return .{ .manifest = try self.manifest(source_generation), .state = self.stateStage(), .bootstrap = true };
    }
    /// Caller supplies every row from one validated ready manifest snapshot. It
    /// rechecks that snapshot before publishing all source/shared restored owners.
    pub fn prepareRestore(self: *Coordinator, source_generation: [32]u8, saved: []const Saved, now_us: i64) !StateStage {
        if (self.ready or saved.len != self.requiredCount()) return error.ConsumerRestoreMismatch;
        try self.begin(now_us);
        errdefer release(self);
        self.mode = .restore;
        const required = (try self.manifest(source_generation)).required;
        for (required, 0..) |requirement, i| {
            var found: ?Saved = null;
            for (saved) |row| if (state.Key.eql(row.key, requirement.key)) {
                if (found != null) return error.ConsumerRestoreMismatch;
                found = row;
            };
            const row = found orelse return error.ConsumerRestoreMismatch;
            if (row.format_version != requirement.format_version or row.revision == 0 or row.revision > std.math.maxInt(i64) or row.valid_until_us != null) return error.ConsumerRestoreMismatch;
            if (i < self.owners.len) {
                self.stages[i] = try self.owners[i].prepareRestore(row.payload);
                self.restore_revisions[i] = row.revision;
            } else if (i == self.owners.len) {
                if (self.ignores.revision != row.revision or !std.mem.eql(u8, self.ignores.live.payload, row.payload)) return error.ConsumerRestoreMismatch;
            } else if (row.revision != 1 or !std.mem.eql(u8, row.payload, &self.cache.?.generation)) return error.ConsumerRestoreMismatch;
            try self.dependency(.{ .key = row.key, .expected_revision = row.revision });
        }
        return .{ .manifest = try self.manifest(source_generation), .state = self.stateStage(), .bootstrap = false };
    }
    fn identity(self: *const Coordinator, record: records.Record) ![32]u8 {
        if (!std.mem.eql(u8, record.source, self.incarnation)) return error.ConsumerSourceMismatch;
        if (record.occurrence.len == 0 or record.occurrence.len > 16384 or record.cursor.len > 16384) return error.InvalidConsumer;
        const receipt = record.receipt_time orelse return error.MissingReceiptTime;
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(&self.generation);
        hash.update(&record.raw_hash);
        var number: [8]u8 = undefined;
        std.mem.writeInt(i64, &number, receipt.us, .little);
        hash.update(&number);
        for ([_][]const u8{ record.source, record.occurrence, record.cursor }) |value| {
            std.mem.writeInt(u64, &number, value.len, .little);
            hash.update(&number);
            hash.update(value);
        }
        return hash.finalResult();
    }
    pub fn prepareCheckpoint(self: *Coordinator, record: records.Record, now_us: i64, _: u64) !detection.StagedState {
        if (!self.ready) return error.ConsumerStateNotReady;
        if (record.kind != .checkpoint or self.waiting_occurrence != null) return error.ConsumerPending;
        if (!std.mem.eql(u8, record.source, self.incarnation)) return error.ConsumerSourceMismatch;
        if (record.occurrence.len == 0 or record.occurrence.len > 16384 or record.cursor.len > 16384) return error.InvalidConsumer;
        try self.begin(now_us);
        errdefer release(self);
        self.mode = .checkpoint;
        try self.requiredReads();
        return self.stateStage();
    }
    fn fallback(self: *Coordinator, kind: detection.Kind) void {
        self.outcomes[0] = .{ .kind = kind, .generation = self.generation, .filter = self.settings.filter };
        self.outcome_count = 1;
    }
    pub fn prepare(self: *Coordinator, input: detection.StagedInput) !detection.StagedPrepared {
        if (!self.ready) return error.ConsumerStateNotReady;
        if (input.record.kind != .data or input.decoded.len > 2048) return error.InvalidConsumer;
        const occurrence = try self.identity(input.record);
        if (self.waiting_occurrence) |held| if (!std.mem.eql(u8, &held, &occurrence)) return error.ConsumerPending;
        if (input.processing_us < input.record.receipt_time.?.us) return error.ConsumerClockReversed;
        if (input.time == .eligible and input.time.eligible.receipt.us != input.record.receipt_time.?.us) return error.ConsumerReceiptMismatch;
        try self.begin(input.processing_us);
        errdefer release(self);
        self.mode = .record;
        defer {
            self.immediate = null;
            self.reservation_turn = null;
            self.processing_reserved = false;
        }
        if (input.time != .eligible) {
            try self.requiredReads();
            self.fallback(.time_excluded);
        } else if (if (self.settings.journal_origin) |profile| profile.rejection(input.record.journal_fields) else null) |rejection| {
            try self.requiredReads();
            self.fallback(rejection);
        } else {
            try self.ignoreRead();
            try self.authorityRead();
            var rejected = false;
            for (self.owners, 0..) |owner, i| {
                const stage = try owner.prepare(.{ .source = self.settings.logical_source, .record = input.decoded }, .{ .occurrence = occurrence, .event_us = input.time.eligible.timestamp.us, .receipt_us = input.record.receipt_time.?.us, .processing_us = input.processing_us });
                self.stages[i] = stage;
                if (stage.valid_until_us) |deadline| self.deadline = if (self.deadline) |prior| @min(prior, deadline) else deadline;
                try self.delta(.{ .key = self.ruleKey(i), .format_version = rule.version, .expected_revision = self.revisions[i], .payload = stage.checkpoint });
                const outcome = stage.outcome.?;
                if (outcome.kind == .rejected) rejected = true;
                if (outcome.kind != .candidate and outcome.kind != .excluded) continue;
                const subject = outcome.subject orelse continue;
                switch (subject) {
                    .address => |ip| try self.address(ip, outcome.kind == .excluded, i, occurrence, input.processing_us),
                    .hostname => |hostname| {
                        if (outcome.kind == .excluded) continue;
                        const request = dns.Request{ .name = hostname, .family = self.settings.family, .generation = self.cache.?.generation };
                        if (self.immediate) |result| {
                            if (std.mem.eql(u8, result.request.name.slice(), hostname.slice()) and result.request.family == request.family) {
                                try result.validateCompletion(result.request, input.monotonic_ms, input.processing_us);
                                self.active_turn = self.reservation_turn orelse return error.DnsResultExpired;
                                self.request_deadline_ms = result.deadline_ms;
                                for (result.answer.addresses[0..result.answer.count]) |ip| try self.address(ip, false, i, occurrence, input.processing_us);
                                continue;
                            }
                        }
                        const cached = (try self.cache.?.lookup(request, input.processing_us)) orelse return self.needDns(request, .subject, occurrence);
                        try self.dnsRead(request, cached.revision, cached.result.valid_until_us);
                        for (cached.result.answer.addresses[0..cached.result.answer.count]) |ip| try self.address(ip, false, i, occurrence, input.processing_us);
                    },
                }
            }
            if (self.outcome_count == 0) self.fallback(if (rejected) .malformed_body else .no_match);
        }
        try self.batch().validate();
        for (self.outcomes[0..self.outcome_count]) |*outcome| try outcome.validate(input.time);
        return .{ .outcomes = self.outcomes[0..self.outcome_count], .consumers = self.batch(), .context = self, .publish = publish, .release = release };
    }
    fn address(self: *Coordinator, ip: rules.Ip, excluded: bool, index: usize, occurrence: [32]u8, now_us: i64) !void {
        var subject: detection.Subject = undefined;
        switch (ip) {
            .ipv4 => |bits| {
                var bytes: [4]u8 = undefined;
                std.mem.writeInt(u32, &bytes, bits, .big);
                subject = .{ .v4 = bytes };
            },
            .ipv6 => |bits| {
                var bytes: [16]u8 = undefined;
                std.mem.writeInt(u128, &bytes, bits, .big);
                subject = .{ .v6 = bytes };
            },
        }
        var kind: detection.Kind = if (excluded) .ignored else .candidate;
        if (subject.unenforceable()) kind = .unenforceable else if (!excluded) {
            const decision = try self.ignores.live.check(ip, self.cache, now_us);
            if (decision.kind == .pending) return self.needDns(decision.request.?, .exclusion, occurrence);
            for (decision.dependencies[0..decision.count]) |dep| try self.dnsRead(dep.request, dep.revision, dep.valid_until_us);
            if (decision.kind == .ignored) kind = .ignored;
        }
        for (self.outcomes[0..self.outcome_count]) |*prior| if (std.meta.eql(prior.subject.?, subject)) {
            if (kind == .candidate and prior.kind != .candidate) prior.* = self.addressOutcome(subject, kind, index);
            return;
        };
        if (self.outcome_count == self.outcomes.len) return error.ConsumerCapacity;
        self.outcomes[self.outcome_count] = self.addressOutcome(subject, kind, index);
        self.outcome_count += 1;
    }
    fn addressOutcome(self: *const Coordinator, subject: detection.Subject, kind: detection.Kind, index: usize) detection.Outcome {
        return .{ .kind = kind, .subject = subject, .generation = self.generation, .filter = self.settings.filter, .pattern = detection.Name.init(self.owners[index].program.metadata().id) catch self.settings.filter, .pattern_index = @intCast(index) };
    }
    fn needDns(self: *Coordinator, request: dns.Request, purpose: @FieldType(Pending, "purpose"), occurrence: [32]u8) error{ ConsumerPending, DnsRequestOverflow } {
        self.waiting_occurrence = occurrence;
        if (self.pending == null) {
            if (self.next_request == std.math.maxInt(u64)) return error.DnsRequestOverflow;
            var value = request;
            value.id = self.next_request;
            self.next_request += 1;
            self.pending = .{ .request = value, .purpose = purpose, .occurrence = occurrence };
        }
        return error.ConsumerPending;
    }
    fn dnsRead(self: *Coordinator, request: dns.Request, revision: u64, expiry: i64) !void {
        const probe = dnsKey(request.name.slice(), request.family, request.generation);
        for (self.dependencies[0..self.dependency_count]) |prior| if (state.Key.eql(prior.key, probe)) return self.dependency(.{ .key = prior.key, .expected_revision = revision, .valid_until_us = expiry });
        if (self.name_count == self.names.len) return error.ConsumerCapacity;
        self.names[self.name_count] = request.name;
        const key = dnsKey(self.names[self.name_count].slice(), request.family, request.generation);
        self.name_count += 1;
        try self.dependency(.{ .key = key, .expected_revision = revision, .valid_until_us = expiry });
    }
    /// One completion-turn reservation for a subject only. Any prepare consumes
    /// it, including an aborted prepare; exclusion reads never see this answer.
    pub fn provideImmediate(self: *Coordinator, result: dns.Result, now_ms: u64, now_us: i64) !void {
        if (self.busy or self.immediate != null) return error.ConsumerBusy;
        const pending = self.pending orelse return error.DnsRequestMismatch;
        if (pending.purpose != .subject or self.settings.monotonic_ms == null or self.settings.turn == null) return error.ImmediateSubjectRequired;
        try result.validateCompletion(pending.request, now_ms, now_us);
        if (result.answer.kind != .positive or result.answer.ttl_seconds != 0 or result.completed_us != result.valid_until_us) return error.ImmediateSubjectRequired;
        self.immediate = result;
        self.processing_reserved = false;
        self.reservation_turn = self.settings.turn.?(self.settings.clock_context);
        self.pending = null;
    }
    pub fn processingTime(self: *Coordinator, record: records.Record, actual_us: i64) !i64 {
        const result = self.immediate orelse return actual_us;
        const occurrence = try self.identity(record);
        const held = self.waiting_occurrence orelse return error.DnsRequestMismatch;
        if (!std.mem.eql(u8, &occurrence, &held)) return error.ConsumerPending;
        if (actual_us < result.completed_us) return error.ConsumerClockReversed;
        if (self.processing_reserved) {
            self.immediate = null;
            self.reservation_turn = null;
            return error.ConsumerExpired;
        }
        const turn = self.settings.turn orelse return error.ImmediateSubjectRequired;
        const clock = self.settings.monotonic_ms orelse return error.ImmediateSubjectRequired;
        if (turn(self.settings.clock_context) != self.reservation_turn.? or clock(self.settings.clock_context) >= result.deadline_ms) {
            self.immediate = null;
            self.reservation_turn = null;
            return error.ConsumerExpired;
        }
        self.processing_reserved = true;
        return result.completed_us;
    }
    pub fn pendingRequest(self: *const Coordinator) ?Pending {
        return self.pending;
    }
    pub fn cancelRequest(self: *Coordinator, request_id: u64) !void {
        if (self.busy) return error.ConsumerBusy;
        if (self.pending == null or self.pending.?.request.id != request_id) return error.DnsRequestMismatch;
        self.pending = null;
    }
    /// Commit this shared input first, without touching the waiting source ack.
    /// Publish only after Store.bootstrapConsumerManifest/commitConsumerInput.
    pub fn prepareDnsResult(self: *Coordinator, result: dns.Result, now_ms: u64, now_us: i64) !StateStage {
        const pending = self.pending orelse return error.DnsRequestMismatch;
        try result.validateCompletion(pending.request, now_ms, now_us);
        try self.begin(now_us);
        errdefer release(self);
        self.mode = .dns_input;
        self.request_deadline_ms = result.deadline_ms;
        self.dns_stage = try self.cache.?.prepare(result, now_us);
        self.dns_name = result.request.name;
        const key = dnsKey(self.dns_name.slice(), result.request.family, result.request.generation);
        self.dns_requirement[0] = .{ .key = key, .format_version = dns.version };
        const source = try std.fmt.bufPrint(&self.dns_manifest_source, "{s}:{s}", .{ @tagName(result.request.family), self.dns_name.slice() });
        try self.delta(.{ .key = key, .format_version = dns.version, .expected_revision = self.dns_stage.?.expected_revision, .payload = self.dns_stage.?.checkpoint(), .valid_until_us = result.valid_until_us });
        return .{ .manifest = .{ .jail = "@shared", .source = source, .source_generation = result.request.generation, .required = &self.dns_requirement }, .state = self.stateStage(), .bootstrap = self.dns_stage.?.expected_revision == 0 };
    }
    /// Replace the shared allowlist as one consumer delta at the owner's current revision.
    /// The snapshot's parent generation is unchanged, so restore paths read the new payload
    /// through the same key; publish only after the store committed the delta.
    pub fn prepareAllowlistRefresh(self: *Coordinator, next: *ignore.Snapshot, source_generation: [32]u8, now_us: i64) !StateStage {
        if (!self.ready) return error.ConsumerStateNotReady;
        if (!std.mem.eql(u8, &next.options.parent_generation, &self.ignores.live.options.parent_generation) or !std.mem.eql(u8, &next.options.resolver_generation, &self.ignores.live.options.resolver_generation)) return error.IgnoreGenerationMismatch;
        try self.begin(now_us);
        errdefer release(self);
        self.mode = .allowlist;
        if (self.ignores.revision == 0) return error.ConsumerStateNotReady;
        for (self.owners, 0..) |_, i| try self.dependency(.{ .key = self.ruleKey(i), .expected_revision = self.revisions[i] });
        try self.authorityRead();
        self.ignore_stage = try self.ignores.prepare(next);
        try self.delta(.{ .key = self.ignoreKey(), .format_version = ignore.version, .expected_revision = self.ignores.revision, .payload = next.payload });
        try self.batch().validate();
        return .{ .manifest = try self.manifest(source_generation), .state = self.stateStage(), .bootstrap = false };
    }
    fn publish(context: ?*anyopaque) void {
        const self: *Coordinator = @ptrCast(@alignCast(context.?));
        if (!self.busy or self.published) return;
        for (self.stages[0..self.owners.len], 0..) |stage, i| if (stage) |value| {
            value.publish();
            self.revisions[i] = if (self.mode == .restore) self.restore_revisions[i] else self.revisions[i] + 1;
        };
        if (self.ignore_reserved) self.ignores.revision = 1;
        if (self.ignore_stage) |*stage| stage.publish();
        if (self.dns_stage) |*stage| {
            stage.publish();
            self.pending = null;
        }
        if (self.mode == .bootstrap or self.mode == .restore) self.ready = true;
        if (self.mode == .record) {
            self.waiting_occurrence = null;
            self.pending = null;
        }
        self.published = true;
    }
    fn release(context: ?*anyopaque) void {
        const self: *Coordinator = @ptrCast(@alignCast(context.?));
        for (self.stages[0..self.owners.len]) |*stage| {
            if (stage.*) |value| value.release();
            stage.* = null;
        }
        if (self.dns_stage) |*stage| stage.release();
        self.dns_stage = null;
        if (self.ignore_stage) |*stage| stage.release();
        self.ignore_stage = null;
        if (self.ignore_reserved) self.ignores.in_flight = false;
        self.ignore_reserved = false;
        self.busy = false;
    }
};
pub fn resolverKey(resolver_generation: [32]u8) state.Key {
    return .{ .kind = .dns, .jail = "@shared", .source = "@resolver", .rule = "authority", .generation = resolver_generation };
}
pub fn dnsKey(name: []const u8, family: dns.Family, resolver_generation: [32]u8) state.Key {
    return .{ .kind = .dns, .jail = "@shared", .source = name, .rule = @tagName(family), .generation = resolver_generation };
}
/// Borrowed bounded registry; source factories allocate/admit owners before
/// registering, after an actual file/journal incarnation has been established.
pub const Registry = struct {
    generation: [32]u8,
    sources: [max_sources]*Coordinator = undefined,
    count: usize = 0,
    pub fn init(value: [32]u8) Registry {
        return .{ .generation = value };
    }
    pub fn register(self: *Registry, owner: *Coordinator) !void {
        if (self.count == self.sources.len) return error.ConsumerCapacity;
        if (!std.mem.eql(u8, &owner.generation, &self.generation)) return error.ConsumerGenerationMismatch;
        for (self.sources[0..self.count]) |prior| if (std.mem.eql(u8, prior.incarnation, owner.incarnation)) return error.DuplicateConsumerSource;
        self.sources[self.count] = owner;
        self.count += 1;
    }
    pub fn source(self: *Registry, incarnation: []const u8) !*Coordinator {
        for (self.sources[0..self.count]) |owner| if (std.mem.eql(u8, owner.incarnation, incarnation)) return owner;
        return error.ConsumerSourceUnbound;
    }
    pub fn consumer(self: *Registry) detection.StagedConsumer {
        return .{ .generation = self.generation, .context = self, .prepare = prepare, .prepare_checkpoint = checkpoint, .manifest = manifest, .processing_time = processingTime };
    }
    fn prepare(input: detection.StagedInput, context: ?*anyopaque) anyerror!detection.StagedPrepared {
        const self: *Registry = @ptrCast(@alignCast(context.?));
        return (try self.source(input.record.source)).prepare(input);
    }
    pub fn processingTime(record: records.Record, actual_us: i64, context: ?*anyopaque) anyerror!i64 {
        const self: *Registry = @ptrCast(@alignCast(context.?));
        return (try self.source(record.source)).processingTime(record, actual_us);
    }
    fn checkpoint(record: records.Record, now_us: i64, now_ms: u64, context: ?*anyopaque) anyerror!detection.StagedState {
        const self: *Registry = @ptrCast(@alignCast(context.?));
        return (try self.source(record.source)).prepareCheckpoint(record, now_us, now_ms);
    }
    fn manifest(incarnation: []const u8, source_generation: [32]u8, context: ?*anyopaque) anyerror!state.Manifest {
        const self: *Registry = @ptrCast(@alignCast(context.?));
        return (try self.source(incarnation)).manifest(source_generation);
    }
};
