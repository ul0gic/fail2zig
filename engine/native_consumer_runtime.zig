// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Native owner/factory and one-request DNS scheduler. Store remains the only
//! persistence authority. Construct this fresh runtime behind the global recovery
//! gate; finish source/shared validation before making its generation usable.
const std = @import("std");
const durable = @import("core/record_store.zig");
const state = @import("core/native_consumer.zig");
const bridge = @import("core/native_consumer_coordinator.zig");
const rule = @import("core/native_rule_consumer.zig");
const rules = @import("core/native_rules.zig");
const dns = @import("core/native_dns.zig");
const ignore = @import("core/native_ignore.zig");
const detection = @import("core/native_detection_record.zig");
const files = @import("core/native_file_session.zig");
pub const Clock = struct {
    context: ?*anyopaque,
    read_us: *const fn (?*anyopaque) anyerror!i64,
    read_ms: *const fn (?*anyopaque) u64,
};
/// Nonoverlapping Zig allocation envelopes, not measured RSS. Config/programs,
/// SQLite/C and source-session memory are accounted by their respective owners.
pub const AllocationPlan = struct {
    fixed_live_bytes: usize,
    per_source_live_bytes: usize,
    source_capacity: usize,
    capacity_live_bytes: usize,
    workspace_bytes: usize,
    pub fn requiredBytes(self: AllocationPlan) !usize {
        return add(try add(self.fixed_live_bytes, try mul(self.per_source_live_bytes, self.source_capacity)), try add(self.capacity_live_bytes, self.workspace_bytes));
    }
};
pub const DnsOptions = struct {
    generation: [32]u8,
    server: ?std.net.Address = null,
    capacity: usize,
    max_sources: usize,
    max_owned_bytes: usize,
    clock: Clock,
};
pub const Poll = struct { kind: enum { idle, waiting, ready, unknown }, source: ?*bridge.Coordinator = null };
const Slot = struct { owner: *bridge.Coordinator, retry_after_ms: u64 = 0 };
const Scan = struct {
    after: [16384]u8 = undefined,
    length: usize = 0,
    revision: ?u64 = null,
    count: usize = 0,
    authority: bool = false,
    done: bool = false,
    fn cursor(self: *const Scan) ?[]const u8 {
        return if (self.length == 0) null else self.after[0..self.length];
    }
    fn advance(self: *Scan, source: []const u8) !void {
        if (source.len == 0 or source.len > self.after.len) return error.InvalidConsumer;
        @memcpy(self.after[0..source.len], source);
        self.length = source.len;
    }
};
pub const DnsRuntime = struct {
    allocator: std.mem.Allocator,
    store: *durable.Store,
    options: DnsOptions,
    cache: dns.Cache,
    client: ?dns.Client,
    slots: []Slot,
    count: usize = 0,
    next: usize = 0,
    active: ?usize = null,
    completion: ?dns.Result = null,
    turn: u64 = 1,
    authority_ready: bool = false,
    restored: bool = false,
    failed: bool = false,
    restore_scan: Scan = .{},
    validation: Scan = .{},
    reserved_bytes: usize,

    pub fn allocationPlan(options: DnsOptions) !AllocationPlan {
        if (options.max_sources == 0 or options.max_sources > bridge.max_sources or options.capacity == 0 or options.capacity > 1024) return error.InvalidConsumerRuntimeLimits;
        if (options.server != null and std.mem.allEqual(u8, &options.generation, 0)) return error.DnsGenerationMismatch;
        return .{ .fixed_live_bytes = @sizeOf(DnsRuntime), .per_source_live_bytes = @sizeOf(Slot), .source_capacity = options.max_sources, .capacity_live_bytes = try mul(options.capacity, @sizeOf(?[dns.cache_entry_bytes]u8)), .workspace_bytes = state.max_prepared_bytes };
    }
    pub fn requiredBytes(options: DnsOptions) !usize {
        return (try allocationPlan(options)).requiredBytes();
    }
    pub fn create(allocator: std.mem.Allocator, store: *durable.Store, options: DnsOptions) !*DnsRuntime {
        if (store.schema_version < 12) return error.InvalidConsumerRuntimeLimits;
        const reserved = try requiredBytes(options);
        if (reserved > options.max_owned_bytes) return error.ConsumerRuntimeBudget;
        const self = try allocator.create(DnsRuntime);
        errdefer allocator.destroy(self);
        var cache = try dns.Cache.init(allocator, options.generation, options.capacity);
        errdefer cache.deinit();
        const slots = try allocator.alloc(Slot, options.max_sources);
        errdefer allocator.free(slots);
        self.* = .{ .allocator = allocator, .store = store, .options = options, .cache = cache, .slots = slots, .client = if (options.server) |server| try dns.Client.init(server, options.generation) else null, .reserved_bytes = reserved };
        return self;
    }
    pub fn destroy(self: *DnsRuntime) void {
        if (self.client) |*client| client.deinit();
        self.cache.deinit();
        self.allocator.free(self.slots);
        const allocator = self.allocator;
        allocator.destroy(self);
    }
    pub fn cacheForConsumers(self: *DnsRuntime) ?*dns.Cache {
        return if (self.client != null) &self.cache else null;
    }
    fn now(self: *DnsRuntime) !i64 {
        return self.options.clock.read_us(self.options.clock.context);
    }
    pub fn commitClock(context: ?*anyopaque) i64 {
        const self: *DnsRuntime = @ptrCast(@alignCast(context.?));
        return self.now() catch std.math.minInt(i64);
    }
    pub fn monotonic(context: ?*anyopaque) u64 {
        const self: *DnsRuntime = @ptrCast(@alignCast(context.?));
        return self.options.clock.read_ms(self.options.clock.context);
    }
    pub fn turnToken(context: ?*anyopaque) u64 {
        const self: *DnsRuntime = @ptrCast(@alignCast(context.?));
        return self.turn;
    }
    pub fn advanceTurn(self: *DnsRuntime) !void {
        try self.idle();
        self.turn = std.math.add(u64, self.turn, 1) catch return error.DnsTurnOverflow;
    }
    fn idle(self: *const DnsRuntime) !void {
        if (self.store.api.get_autocommit(self.store.db) == 0) return error.ConsumerTransactionActive;
        try self.idleForRestore();
    }
    // Only unpublished state construction/validation may share the startup
    // admission transaction. Scheduling and DNS polling still require idle().
    fn idleForRestore(self: *const DnsRuntime) !void {
        if (self.failed) return error.ConsumerRuntimeFailed;
        if (self.store.api.get_autocommit(self.store.db) == 0 and !self.store.startupAdmissionActive()) return error.ConsumerTransactionActive;
        if (self.cache.in_flight) return error.ConsumerBusy;
        for (self.slots[0..self.count]) |slot| if (slot.owner.busy) return error.ConsumerBusy;
    }
    fn register(self: *DnsRuntime, owner: *bridge.Coordinator) !void {
        if (!self.restored or self.failed) return error.ConsumerRuntimeNotReady;
        if (self.count == self.slots.len) return error.ConsumerRuntimeBudget;
        self.slots[self.count] = .{ .owner = owner };
        self.count += 1;
    }
    fn unregister(self: *DnsRuntime, owner: *bridge.Coordinator) void {
        for (self.slots[0..self.count], 0..) |slot, i| if (slot.owner == owner) {
            if (self.active) |active| {
                if (active == i) {
                    if (self.client) |*client| client.deinit();
                    self.active = null;
                    self.completion = null;
                } else if (active > i) self.active = active - 1;
            }
            std.mem.copyForwards(Slot, self.slots[i .. self.count - 1], self.slots[i + 1 .. self.count]);
            self.count -= 1;
            if (self.next >= self.count) self.next = 0;
            return;
        };
    }
    fn authorityManifest(self: *DnsRuntime, requirements: *[1]state.Requirement) state.Manifest {
        requirements[0] = .{ .key = bridge.resolverKey(self.options.generation), .format_version = 1 };
        return .{ .jail = "@shared", .source = "@resolver", .source_generation = self.options.generation, .required = requirements };
    }
    fn validateAuthority(self: *DnsRuntime, snapshot: *const durable.Store.ManifestSnapshot) !void {
        if (snapshot.status != .ready or snapshot.count != 1) return error.DnsAuthorityRequired;
        const row = snapshot.states[0];
        if (row.revision != 1 or row.format_version != 1 or row.valid_until_us != null or row.payload == null or !std.mem.eql(u8, row.payload.?, &self.options.generation)) return error.DnsAuthorityRequired;
    }
    fn admitAuthority(self: *DnsRuntime) !void {
        var requirements: [1]state.Requirement = undefined;
        const manifest = self.authorityManifest(&requirements);
        var snapshot = self.store.consumerManifestSnapshot(self.allocator, manifest) catch |failure| {
            if (failure != error.ConsumerManifestMissing) return failure;
            const deltas = [_]state.Delta{.{ .key = requirements[0].key, .format_version = 1, .expected_revision = 0, .payload = &self.options.generation }};
            try self.store.bootstrapConsumerManifest(manifest, .{ .deltas = &deltas, .prepared_us = try self.now(), .clock_context = self, .clock = commitClock });
            self.authority_ready = true;
            return;
        };
        defer snapshot.deinit(self.allocator);
        try self.validateAuthority(&snapshot);
        try self.store.validateConsumerManifestSnapshot(manifest, &snapshot);
        self.authority_ready = true;
    }
    /// At most sixteen durable manifests per call, with exact snapshot recheck.
    /// Failure poisons this unpublished owner; rebuild instead of partial reset.
    pub fn restoreTurn(self: *DnsRuntime) !bool {
        try self.idleForRestore();
        if (self.restored) return true;
        if (self.count != 0) return error.ConsumerBusy;
        errdefer self.failed = true;
        if (self.client != null and !self.authority_ready) {
            try self.admitAuthority();
            return false;
        }
        const done = try self.scanDns(&self.restore_scan, true);
        if (done) self.restored = true;
        return done;
    }
    pub fn beginValidation(self: *DnsRuntime) !void {
        try self.idleForRestore();
        if (!self.restored) return error.ConsumerRuntimeNotReady;
        self.validation = .{};
    }
    pub fn validateTurn(self: *DnsRuntime) !bool {
        try self.idleForRestore();
        if (!self.restored) return error.ConsumerRuntimeNotReady;
        return self.scanDns(&self.validation, false);
    }
    /// Root calls this after all own bootstrap writes and every validation scan,
    /// immediately before opening its global generation gate. No write is allowed
    /// between this check and publication into the serialized scheduler.
    pub fn finishValidation(self: *DnsRuntime, jails: []const *JailRuntime) !void {
        try self.idleForRestore();
        if (!self.validation.done or jails.len > 128) return error.ConsumerRuntimeNotReady;
        const revision = self.validation.revision orelse return error.ConsumerRuntimeNotReady;
        var count: usize = 0;
        for (jails, 0..) |jail, i| {
            if (jail.dns_runtime != self or !jail.validation.done or jail.validation.revision != revision) return error.StaleConsumerCheckpoint;
            for (jails[0..i]) |prior| if (prior == jail) return error.InvalidConsumer;
            count = try add(count, jail.count);
        }
        if (count != self.count) return error.UnboundRequiredConsumer;
        var keys: [1]durable.Store.ManifestKey = undefined;
        const page = try self.store.consumerManifestKeysPage(self.allocator, "@shared", null, revision, &keys);
        defer for (keys[0..page.count]) |key| key.deinit(self.allocator);
    }
    fn scanDns(self: *DnsRuntime, scan: *Scan, restoring: bool) !bool {
        if (scan.done) return true;
        var keys: [16]durable.Store.ManifestKey = undefined;
        const page = try self.store.consumerManifestKeysPage(self.allocator, "@shared", scan.cursor(), scan.revision, &keys);
        defer for (keys[0..page.count]) |key| key.deinit(self.allocator);
        scan.revision = page.revision;
        for (keys[0..page.count]) |key| {
            if (self.client == null) return error.DnsConfigurationRequired;
            if (key.status != .ready or !std.mem.eql(u8, &key.generation, &self.options.generation)) return error.DnsGenerationMismatch;
            var requirements: [1]state.Requirement = undefined;
            if (std.mem.eql(u8, key.source, "@resolver")) {
                const manifest = self.authorityManifest(&requirements);
                var saved = try self.store.consumerManifestSnapshot(self.allocator, manifest);
                defer saved.deinit(self.allocator);
                if (saved.revision != page.revision) return error.StaleConsumerCheckpoint;
                try self.validateAuthority(&saved);
                try self.store.validateConsumerManifestSnapshot(manifest, &saved);
                scan.authority = true;
            } else {
                if (scan.count == self.options.capacity) return error.DnsCacheLimit;
                const request = try requestFromSource(key.source, key.generation);
                requirements[0] = .{ .key = bridge.dnsKey(request.name.slice(), request.family, request.generation), .format_version = dns.version };
                const manifest = state.Manifest{ .jail = "@shared", .source = key.source, .source_generation = key.generation, .required = &requirements };
                if (!std.mem.eql(u8, &key.digest, &try manifest.digest())) return error.ConsumerManifestMismatch;
                var saved = try self.store.consumerManifestSnapshot(self.allocator, manifest);
                defer saved.deinit(self.allocator);
                if (saved.revision != page.revision or saved.status != .ready or saved.count != 1) return error.StaleConsumerCheckpoint;
                const row = saved.states[0];
                const bytes = row.payload orelse return error.MissingRequiredConsumer;
                if (row.format_version != dns.version or row.revision == 0 or row.valid_until_us == null) return error.InvalidDnsCheckpoint;
                if (restoring) {
                    var stage = try self.cache.prepareRestore(bytes);
                    defer stage.release();
                    if (stage.entry.revision != row.revision or stage.entry.result.valid_until_us != row.valid_until_us.? or !sameRequest(stage.entry.result.request, request)) return error.InvalidDnsCheckpoint;
                    try self.store.validateConsumerManifestSnapshot(manifest, &saved);
                    stage.publish();
                } else {
                    if (try self.cache.revision(request) != row.revision) return error.StaleConsumerCheckpoint;
                    var found = false;
                    for (self.cache.entries) |entry| if (entry) |value| if (std.mem.eql(u8, &value, bytes)) {
                        found = true;
                        break;
                    };
                    if (!found) return error.StaleConsumerCheckpoint;
                    try self.store.validateConsumerManifestSnapshot(manifest, &saved);
                }
                scan.count += 1;
            }
            try scan.advance(key.source);
        }
        if (!page.more) {
            if ((self.client != null) != scan.authority) return error.DnsAuthorityRequired;
            var count: usize = 0;
            for (self.cache.entries) |entry| if (entry != null) {
                count += 1;
            };
            if (count != scan.count) return error.MissingRequiredConsumer;
            scan.done = true;
        }
        return scan.done;
    }
    /// Call once per scheduler turn, after releasing every record stage. On
    /// ready, retry exactly this source before the next advanceTurn/yield.
    pub fn pollDns(self: *DnsRuntime) !Poll {
        try self.advanceTurn();
        if (!self.restored) return error.ConsumerRuntimeNotReady;
        const client = if (self.client) |*value| value else return .{ .kind = .idle };
        const now_ms = monotonic(self);
        const now_us = try self.now();
        if (self.active == null) {
            for (0..self.count) |_| {
                const index = self.next;
                self.next = (self.next + 1) % self.count;
                const slot = &self.slots[index];
                if (slot.retry_after_ms > now_ms) continue;
                if (slot.owner.pendingRequest()) |pending| {
                    try client.begin(pending.request, now_ms);
                    self.active = index;
                    return .{ .kind = .waiting, .source = slot.owner };
                }
            }
            return .{ .kind = .idle };
        }
        const slot = &self.slots[self.active.?];
        const pending = slot.owner.pendingRequest() orelse {
            client.deinit();
            self.active = null;
            self.completion = null;
            return .{ .kind = .idle };
        };
        if (self.completion == null) self.completion = try client.poll(now_ms, now_us);
        const result = self.completion orelse return .{ .kind = .waiting, .source = slot.owner };
        result.validateCompletion(pending.request, now_ms, now_us) catch |failure| {
            if (failure == error.DnsResultExpired) return self.unknown(slot, now_ms);
            return failure;
        };
        if (result.answer.kind != .positive and result.answer.kind != .negative) return self.unknown(slot, now_ms);
        if (result.answer.ttl_seconds == 0) {
            if (result.answer.kind != .positive or pending.purpose != .subject) return self.unknown(slot, now_ms);
            try slot.owner.provideImmediate(result, now_ms, now_us);
        } else {
            const stage = try slot.owner.prepareDnsResult(result, now_ms, now_us);
            defer stage.state.release(stage.state.context);
            if (stage.bootstrap) try self.store.bootstrapConsumerManifest(stage.manifest, stage.state.consumers) else try self.store.commitConsumerInput(stage.manifest, stage.state.consumers);
            stage.state.publish(stage.state.context);
        }
        const owner = slot.owner;
        self.active = null;
        self.completion = null;
        return .{ .kind = .ready, .source = owner };
    }
    fn unknown(self: *DnsRuntime, slot: *Slot, now_ms: u64) !Poll {
        if (slot.owner.pendingRequest()) |pending| try slot.owner.cancelRequest(pending.request.id);
        slot.retry_after_ms = std.math.add(u64, now_ms, 1000) catch return error.DnsClockOverflow;
        self.active = null;
        self.completion = null;
        return .{ .kind = .unknown, .source = slot.owner };
    }
};
pub const JailOptions = struct {
    settings: bridge.Settings,
    programs: []const *const rules.Program,
    /// Borrowed immutable configured snapshot and exact current self policy.
    initial_ignore: *ignore.Snapshot,
    ignore_options: ignore.Options,
    max_sources: usize,
    max_owned_bytes: usize,
};
const Source = struct {
    allocator: std.mem.Allocator,
    identity: []u8,
    generation: [32]u8,
    rules: []rule.Consumer,
    pointers: [bridge.max_rules]*rule.Consumer = undefined,
    coordinator: bridge.Coordinator = undefined,
    fn destroy(self: *Source) void {
        self.allocator.free(self.rules);
        self.allocator.free(self.identity);
        const allocator = self.allocator;
        allocator.destroy(self);
    }
};
pub const JailRuntime = struct {
    allocator: std.mem.Allocator,
    store: *durable.Store,
    dns_runtime: *DnsRuntime,
    options: JailOptions,
    settings: bridge.Settings,
    ignores: ignore.Owner,
    registry: bridge.Registry,
    sources: []*Source,
    count: usize = 0,
    reserved_bytes: usize,
    validation: Scan = .{},

    pub fn allocationPlan(options: JailOptions) !AllocationPlan {
        return capacityPlan(options.programs.len, options.max_sources);
    }
    /// Counts suffice for admission before rule assets are allocated.
    pub fn capacityPlan(rule_count: usize, source_capacity: usize) !AllocationPlan {
        if (source_capacity == 0 or source_capacity > bridge.max_sources or rule_count == 0 or rule_count > bridge.max_rules) return error.InvalidConsumerRuntimeLimits;
        const source_bytes = try add(@sizeOf(Source), try add(16384, try mul(rule_count, @sizeOf(rule.Consumer))));
        const ignore_bytes = try add(@sizeOf(ignore.Snapshot), try add(try mul(ignore.max_entries, @sizeOf(ignore.Entry)), ignore.max_checkpoint_bytes));
        return .{ .fixed_live_bytes = try add(@sizeOf(JailRuntime), ignore_bytes), .per_source_live_bytes = try add(source_bytes, @sizeOf(*Source)), .source_capacity = source_capacity, .capacity_live_bytes = 0, .workspace_bytes = try add(state.max_prepared_bytes + 16 * 16384, ignore_bytes) };
    }
    pub fn requiredBytes(options: JailOptions) !usize {
        return (try allocationPlan(options)).requiredBytes();
    }
    pub fn create(allocator: std.mem.Allocator, store: *durable.Store, resolver: *DnsRuntime, options: JailOptions) !*JailRuntime {
        if (!resolver.restored or resolver.store != store) return error.ConsumerRuntimeNotReady;
        const reserved = try requiredBytes(options);
        if (reserved > options.max_owned_bytes) return error.ConsumerRuntimeBudget;
        var settings = options.settings;
        settings.clock_context = resolver;
        settings.clock = DnsRuntime.commitClock;
        settings.monotonic_ms = DnsRuntime.monotonic;
        settings.turn = DnsRuntime.turnToken;
        settings.authority_revision = if (resolver.authority_ready) 1 else 0;
        const initial = options.initial_ignore;
        var ignore_owner = ignore.Owner{ .live = initial, .revision = 0 };
        const semantic = try bridge.generation(settings, options.programs, &ignore_owner, resolver.cacheForConsumers());
        var live = try ignore.Snapshot.restore(allocator, options.ignore_options, initial.payload);
        errdefer live.destroy();
        if (!std.mem.eql(u8, &live.generation, &initial.generation)) return error.IgnoreGenerationMismatch;
        var saved = try store.consumerSnapshot(allocator, .{ .kind = .ignore, .jail = settings.jail, .source = "@shared", .rule = "allowlist", .generation = initial.options.parent_generation });
        defer saved.deinit(allocator);
        if (saved.revision != 0) {
            if (saved.format_version != ignore.version or saved.valid_until_us != null) return error.InvalidIgnoreCheckpoint;
            const restored = try ignore.Snapshot.restore(allocator, options.ignore_options, saved.payload orelse return error.MissingRequiredConsumer);
            live.destroy();
            live = restored;
        }
        const self = try allocator.create(JailRuntime);
        errdefer allocator.destroy(self);
        const sources = try allocator.alloc(*Source, options.max_sources);
        errdefer allocator.free(sources);
        self.* = .{ .allocator = allocator, .store = store, .dns_runtime = resolver, .options = options, .settings = settings, .ignores = .{ .live = live, .revision = saved.revision }, .registry = bridge.Registry.init(semantic), .sources = sources, .reserved_bytes = reserved };
        return self;
    }
    pub fn destroy(self: *JailRuntime) void {
        for (self.sources[0..self.count]) |source| {
            self.dns_runtime.unregister(&source.coordinator);
            source.destroy();
        }
        self.allocator.free(self.sources);
        self.ignores.deinit();
        const allocator = self.allocator;
        allocator.destroy(self);
    }
    pub const AllowlistRefresh = enum { unchanged, applied };
    /// Re-read a file-backed allowlist and commit it as the next shared revision. Any read,
    /// parse, capacity or commit failure leaves the last valid snapshot published.
    pub fn refreshAllowlist(self: *JailRuntime, path: []const u8, now_us: i64) !AllowlistRefresh {
        if (self.count == 0) return error.ConsumerRuntimeNotReady;
        const next = try ignore.Snapshot.fromFile(self.allocator, self.ignores.live.options, path);
        if (std.mem.eql(u8, next.payload, self.ignores.live.payload)) {
            next.destroy();
            return .unchanged;
        }
        const source = self.sources[0];
        const stage = source.coordinator.prepareAllowlistRefresh(next, source.generation, now_us) catch |err| {
            next.destroy();
            return err;
        };
        defer stage.state.release(stage.state.context);
        try self.store.commitConsumerInput(stage.manifest, stage.state.consumers);
        stage.state.publish(stage.state.context);
        return .applied;
    }
    pub fn stagedConsumer(self: *JailRuntime) detection.StagedConsumer {
        return self.registry.consumer();
    }
    pub fn consumerSources(self: *JailRuntime) files.ConsumerSources {
        return .{ .context = self, .admit = bindSource };
    }
    pub fn bindSource(identity: []const u8, generation: [32]u8, context: ?*anyopaque) anyerror!void {
        const self: *JailRuntime = @ptrCast(@alignCast(context.?));
        try self.admitSource(identity, generation);
    }
    pub fn admitSource(self: *JailRuntime, identity: []const u8, generation: [32]u8) !void {
        try self.dns_runtime.idleForRestore();
        if (identity.len == 0 or identity.len > 16384 or std.mem.indexOfScalar(u8, identity, 0) != null) return error.InvalidConsumer;
        for (self.sources[0..self.count]) |source| if (std.mem.eql(u8, source.identity, identity)) {
            if (!std.mem.eql(u8, &source.generation, &generation)) return error.ConsumerGenerationMismatch;
            try self.validateSource(source, null);
            return;
        };
        if (self.count == self.sources.len or self.dns_runtime.count == self.dns_runtime.slots.len) return error.ConsumerRuntimeBudget;
        const source = try self.allocator.create(Source);
        errdefer self.allocator.destroy(source);
        const held = try self.allocator.dupe(u8, identity);
        errdefer self.allocator.free(held);
        const owners = try self.allocator.alloc(rule.Consumer, self.options.programs.len);
        errdefer self.allocator.free(owners);
        source.* = .{ .allocator = self.allocator, .identity = held, .generation = generation, .rules = owners };
        for (owners, self.options.programs, 0..) |*owner, program, i| {
            owner.* = try rule.Consumer.init(program, self.settings.jail, held, self.settings.parent_generation, self.dns_runtime.client != null);
            source.pointers[i] = owner;
        }
        source.coordinator = try bridge.Coordinator.initWithInitial(self.settings, held, source.pointers[0..owners.len], &self.ignores, self.options.initial_ignore, self.dns_runtime.cacheForConsumers());
        const manifest = try source.coordinator.manifest(generation);
        var snapshot: ?durable.Store.ManifestSnapshot = self.store.consumerManifestSnapshot(self.allocator, manifest) catch |failure| blk: {
            if (failure != error.ConsumerManifestMissing) return failure;
            break :blk null;
        };
        defer if (snapshot) |*saved| saved.deinit(self.allocator);
        if (snapshot) |*saved| {
            if (saved.status != .ready) return error.MissingRequiredConsumer;
            var rows: [state.max_dependencies]bridge.Saved = undefined;
            for (manifest.required, saved.states[0..saved.count], 0..) |requirement, value, i| rows[i] = .{ .key = requirement.key, .format_version = value.format_version, .revision = value.revision, .valid_until_us = value.valid_until_us, .payload = value.payload orelse return error.MissingRequiredConsumer };
            const stage = try source.coordinator.prepareRestore(generation, rows[0..saved.count], try self.dns_runtime.now());
            defer stage.state.release(stage.state.context);
            try self.store.validateConsumerManifestSnapshot(manifest, saved);
            stage.state.publish(stage.state.context);
        } else {
            const stage = try source.coordinator.prepareBootstrap(generation, try self.dns_runtime.now());
            defer stage.state.release(stage.state.context);
            try self.store.bootstrapConsumerManifest(stage.manifest, stage.state.consumers);
            stage.state.publish(stage.state.context);
        }
        try self.dns_runtime.register(&source.coordinator);
        errdefer self.dns_runtime.unregister(&source.coordinator);
        try self.registry.register(&source.coordinator);
        self.sources[self.count] = source;
        self.count += 1;
    }
    pub fn beginValidation(self: *JailRuntime) !void {
        try self.dns_runtime.idleForRestore();
        self.validation = .{};
    }
    pub fn validateTurn(self: *JailRuntime) !bool {
        try self.dns_runtime.idleForRestore();
        if (self.validation.done) return true;
        var keys: [16]durable.Store.ManifestKey = undefined;
        const page = try self.store.consumerManifestKeysPage(self.allocator, self.settings.jail, self.validation.cursor(), self.validation.revision, &keys);
        defer for (keys[0..page.count]) |key| key.deinit(self.allocator);
        self.validation.revision = page.revision;
        for (keys[0..page.count]) |key| {
            if (self.validation.count == self.sources.len) return error.ConsumerRuntimeBudget;
            var found: ?*Source = null;
            for (self.sources[0..self.count]) |source| if (std.mem.eql(u8, source.identity, key.source)) {
                found = source;
                break;
            };
            const source = found orelse return error.UnboundRequiredConsumer;
            if (key.status != .ready or !std.mem.eql(u8, &key.generation, &source.generation)) return error.ConsumerGenerationMismatch;
            if (!std.mem.eql(u8, &key.digest, &try (try source.coordinator.manifest(source.generation)).digest())) return error.ConsumerManifestMismatch;
            try self.validateSource(source, page.revision);
            self.validation.count += 1;
            try self.validation.advance(key.source);
        }
        if (!page.more) {
            if (self.validation.count != self.count) return error.MissingRequiredConsumer;
            self.validation.done = true;
        }
        return self.validation.done;
    }
    fn validateSource(self: *JailRuntime, source: *Source, expected_revision: ?u64) !void {
        const manifest = try source.coordinator.manifest(source.generation);
        var saved = try self.store.consumerManifestSnapshot(self.allocator, manifest);
        defer saved.deinit(self.allocator);
        if (saved.status != .ready or (expected_revision != null and saved.revision != expected_revision.?)) return error.StaleConsumerCheckpoint;
        for (saved.states[0..saved.count], 0..) |row, i| {
            if (row.valid_until_us != null or row.payload == null) return error.InvalidConsumer;
            if (i < source.rules.len) {
                const snapshot = try source.rules[i].prepareSnapshot();
                defer snapshot.release();
                if (row.revision != source.coordinator.revisions[i] or row.format_version != rule.version or !std.mem.eql(u8, row.payload.?, snapshot.checkpoint)) return error.StaleConsumerCheckpoint;
            } else if (i == source.rules.len) {
                if (row.revision != self.ignores.revision or row.format_version != ignore.version or !std.mem.eql(u8, row.payload.?, self.ignores.live.payload)) return error.StaleConsumerCheckpoint;
            } else if (row.revision != 1 or row.format_version != 1 or !std.mem.eql(u8, row.payload.?, &self.dns_runtime.options.generation)) return error.DnsAuthorityRequired;
        }
        try self.store.validateConsumerManifestSnapshot(manifest, &saved);
    }
};
fn add(a: usize, b: usize) !usize {
    return std.math.add(usize, a, b) catch error.ConsumerRuntimeBudget;
}
fn mul(a: usize, b: usize) !usize {
    return std.math.mul(usize, a, b) catch error.ConsumerRuntimeBudget;
}
fn requestFromSource(source: []const u8, generation: [32]u8) !dns.Request {
    if (source.len > 260) return error.InvalidDnsCheckpoint;
    const at = std.mem.indexOfScalar(u8, source, ':') orelse return error.InvalidDnsCheckpoint;
    const family = std.meta.stringToEnum(dns.Family, source[0..at]) orelse return error.InvalidDnsCheckpoint;
    const name = try dns.Name.init(source[at + 1 ..]);
    if (!std.mem.eql(u8, name.slice(), source[at + 1 ..])) return error.InvalidDnsCheckpoint;
    return .{ .name = name, .family = family, .generation = generation };
}
fn sameRequest(a: dns.Request, b: dns.Request) bool {
    return a.family == b.family and std.mem.eql(u8, &a.generation, &b.generation) and std.mem.eql(u8, a.name.slice(), b.name.slice());
}
