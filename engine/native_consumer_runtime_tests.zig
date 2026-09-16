// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const t = std.testing;
const runtime = @import("native_consumer_runtime.zig");
const durable = @import("core/record_store.zig");
const rules = @import("core/native_rules.zig");
const ignore = @import("core/native_ignore.zig");
const dns = @import("core/native_dns.zig");
const state = @import("core/native_consumer.zig");
const bridge = @import("core/native_consumer_coordinator.zig");
const detection = @import("core/native_detection_record.zig");
const files = @import("core/native_file_session.zig");
const time = @import("core/native_time.zig");
const gen = [_]u8{7} ** 32;
const plain = "{\"id\":\"private-login\",\"source\":\"application\",\"format\":\"json\",\"subject\":\"peer\",\"conditions\":[{\"field\":\"result\",\"text\":\"denied\"}]}";
const hostname = "{\"id\":\"private-login\",\"source\":\"application\",\"format\":\"json\",\"subject\":\"peer\",\"subject_kind\":\"hostname\",\"conditions\":[{\"field\":\"result\",\"text\":\"denied\"}]}";
const failure = "{\"peer\":\"198.51.100.81\",\"result\":\"denied\"}\n";
const host_failure = "{\"peer\":\"client.example\",\"result\":\"denied\"}\n";
const Clock = struct {
    us: i64 = 1_000_000_000,
    ms: u64 = 0,
    fn epoch(context: ?*anyopaque) !i64 {
        const self: *Clock = @ptrCast(@alignCast(context.?));
        return self.us;
    }
    fn wall(context: ?*anyopaque) !time.Timestamp {
        return .{ .us = try epoch(context) };
    }
    fn mono(context: ?*anyopaque) u64 {
        const self: *Clock = @ptrCast(@alignCast(context.?));
        return self.ms;
    }
    fn bound(self: *Clock) runtime.Clock {
        return .{ .context = self, .read_us = epoch, .read_ms = mono };
    }
};
const Fixture = struct {
    tmp: t.TmpDir,
    path: []u8,
    database: []u8,
    store: durable.Store,
    clock: Clock = .{},
    fn init() !Fixture {
        var tmp = t.tmpDir(.{});
        errdefer tmp.cleanup();
        const root = try tmp.dir.realpathAlloc(t.allocator, ".");
        defer t.allocator.free(root);
        const path = try std.fs.path.join(t.allocator, &.{ root, "input.log" });
        errdefer t.allocator.free(path);
        const database = try std.fs.path.join(t.allocator, &.{ root, "state.sqlite" });
        errdefer t.allocator.free(database);
        var store = try durable.Store.open(t.allocator, database);
        errdefer store.close();
        try store.enableReceipts(16);
        try store.enableNativeTime();
        try store.enableYearInference();
        try store.enableDetection();
        try store.enableClockRecovery();
        try store.enableJournalDetection();
        try store.enableRetry();
        try store.enableConsumers();
        try store.enableEffects();
        try store.enableConsumerManifests();
        try tmp.dir.writeFile(.{ .sub_path = "input.log", .data = "" });
        return .{ .tmp = tmp, .path = path, .database = database, .store = store };
    }
    fn deinit(self: *Fixture) void {
        self.store.close();
        t.allocator.free(self.path);
        t.allocator.free(self.database);
        self.tmp.cleanup();
    }
    fn reopen(self: *Fixture) !void {
        self.store.close();
        self.store = try durable.Store.open(t.allocator, self.database);
        try self.store.enableReceipts(16);
    }
    fn append(self: *Fixture, bytes: []const u8) !void {
        const file = try self.tmp.dir.openFile("input.log", .{ .mode = .write_only });
        defer file.close();
        try file.seekFromEnd(0);
        try file.writeAll(bytes);
    }
};
const Run = struct {
    fixture: *Fixture,
    program: *rules.Program,
    programs: [1]*const rules.Program = undefined,
    initial: *ignore.Snapshot,
    resolver: *runtime.DnsRuntime,
    jail: ?*runtime.JailRuntime = null,
    session: ?*files.Session = null,
    fn init(fixture: *Fixture, config: []const u8, server: ?std.net.Address) !Run {
        const program = try rules.Program.create(t.allocator, config, .{});
        errdefer program.destroy();
        const initial = try ignore.Snapshot.create(t.allocator, .{ .parent_generation = gen, .resolver_generation = gen, .family = .v4 }, &.{});
        errdefer initial.destroy();
        const resolver = try runtime.DnsRuntime.create(t.allocator, &fixture.store, .{ .generation = gen, .server = server, .capacity = 32, .max_sources = 4, .max_owned_bytes = 8 * 1024 * 1024, .clock = fixture.clock.bound() });
        errdefer resolver.destroy();
        for (0..128) |_| {
            if (try resolver.restoreTurn()) break;
        } else return error.RestoreDidNotFinish;
        return .{ .fixture = fixture, .program = program, .initial = initial, .resolver = resolver };
    }
    fn createJail(self: *Run) !void {
        self.programs = .{self.program};
        self.jail = try runtime.JailRuntime.create(t.allocator, &self.fixture.store, self.resolver, .{ .settings = .{ .jail = "fixture", .logical_source = "application", .filter = try detection.Name.init("custom"), .parent_generation = gen, .ignore_generation = self.initial.generation, .family = .v4 }, .programs = &self.programs, .initial_ignore = self.initial, .ignore_options = self.initial.options, .max_sources = 4, .max_owned_bytes = 8 * 1024 * 1024 });
    }
    fn start(self: *Run) !void {
        try self.createJail();
        const f = self.fixture;
        const jail = self.jail.?;
        self.session = try files.Session.createDeferred(t.allocator, &f.store, .{ .processing = .{ .jail = "fixture", .parent_generation = gen, .timestamp = .undated }, .staged_detection = jail.stagedConsumer(), .consumer_sources = jail.consumerSources(), .max_sources = 4, .clock = Clock.wall, .clock_context = &f.clock, .monotonic_clock = .{ .context = &f.clock, .read = Clock.mono } }, &.{.{ .pattern = f.path }});
        for (0..128) |_| {
            if (try self.session.?.admissionTurn()) break;
        } else return error.AdmissionDidNotFinish;
        try self.validate();
    }
    fn validate(self: *Run) !void {
        try self.resolver.beginValidation();
        try self.jail.?.beginValidation();
        for (0..128) |_| {
            if (try self.resolver.validateTurn()) break;
        } else return error.ValidationDidNotFinish;
        for (0..128) |_| {
            if (try self.jail.?.validateTurn()) break;
        } else return error.ValidationDidNotFinish;
        try self.resolver.finishValidation(&.{self.jail.?});
    }
    fn deliver(self: *Run) !usize {
        for (0..32) |_| {
            const count = try self.session.?.pollTurn(1);
            if (count != 0) return count;
        }
        return 0;
    }
    fn destroy(self: *Run) void {
        if (self.session) |session| session.destroy();
        if (self.jail) |jail| jail.destroy();
        self.resolver.destroy();
        self.initial.destroy();
        self.program.destroy();
    }
};
const Peer = struct {
    fd: std.posix.socket_t,
    address: std.net.Address,
    fn init() !Peer {
        const fd = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM | std.posix.SOCK.NONBLOCK | std.posix.SOCK.CLOEXEC, 0);
        errdefer std.posix.close(fd);
        var address = try std.net.Address.parseIp("127.0.0.1", 0);
        try std.posix.bind(fd, &address.any, address.getOsSockLen());
        var length = address.getOsSockLen();
        try std.posix.getsockname(fd, &address.any, &length);
        return .{ .fd = fd, .address = address };
    }
    fn answer(self: Peer, ttl: u32) !void {
        var packet: [1024]u8 = undefined;
        var sender: std.net.Address = undefined;
        var length: std.posix.socklen_t = @sizeOf(std.net.Address);
        const count = try std.posix.recvfrom(self.fd, &packet, 0, &sender.any, &length);
        if (count < 12 or count > 512) return error.InvalidFixtureQuery;
        packet[2] = 0x81;
        packet[3] = 0x80;
        std.mem.writeInt(u16, packet[6..8], 2, .big);
        var at = count;
        for ([_][4]u8{ .{ 198, 51, 100, 81 }, .{ 198, 51, 100, 82 } }) |address| {
            @memcpy(packet[at..][0..6], &[6]u8{ 0xc0, 0x0c, 0, 1, 0, 1 });
            std.mem.writeInt(u32, packet[at + 6 ..][0..4], ttl, .big);
            std.mem.writeInt(u16, packet[at + 10 ..][0..2], 4, .big);
            @memcpy(packet[at + 12 ..][0..4], &address);
            at += 16;
        }
        if (try std.posix.sendto(self.fd, packet[0..at], 0, &sender.any, length) != at) return error.FixtureShortSend;
    }
};
fn complete(run: *Run, peer: Peer, ttl: u32) !runtime.Poll {
    try t.expectEqual(.waiting, (try run.resolver.pollDns()).kind);
    try t.expectEqual(.waiting, (try run.resolver.pollDns()).kind);
    try peer.answer(ttl);
    const result = try run.resolver.pollDns();
    try t.expectEqual(.ready, result.kind);
    return result;
}
fn sql(store: *durable.Store, statement: [:0]const u8) !void {
    const execute = @extern(*const fn (*anyopaque, [*:0]const u8, ?*anyopaque, ?*anyopaque, ?*?[*:0]u8) callconv(.c) c_int, .{ .name = "sqlite3_exec" });
    if (execute(@ptrCast(store.db), statement, null, null, null) != 0) return error.TestSqlFailed;
}

test "native consumer runtime: actual file baseline has no receipt and restart preserves custom counters" {
    var f = try Fixture.init();
    defer f.deinit();
    {
        var run = try Run.init(&f, plain, null);
        defer run.destroy();
        try run.start();
        _ = try run.deliver();
        try t.expectEqual(@as(usize, 0), try f.store.pendingReceiptCount());
        try f.append(failure);
        try t.expectEqual(@as(usize, 1), try run.deliver());
        const source = &run.session.?.sources.sources.items[0];
        try t.expectEqual(detection.Kind.candidate, (try f.store.nativeDetection("fixture", source.source_id, null)).?.kind);
        try t.expectEqual(@as(u64, 1), run.jail.?.sources[0].rules[0].counters[@intFromEnum(rules.Kind.candidate)]);
    }
    try f.reopen();
    var restarted = try Run.init(&f, plain, null);
    defer restarted.destroy();
    try restarted.start();
    try t.expectEqual(@as(u64, 1), restarted.jail.?.sources[0].rules[0].counters[@intFromEnum(rules.Kind.candidate)]);
    try t.expectEqual(@as(usize, 0), try restarted.deliver());
}

test "native consumer runtime: DNS yield then shared commit and two subjects acknowledge atomically" {
    var f = try Fixture.init();
    defer f.deinit();
    const peer = try Peer.init();
    defer std.posix.close(peer.fd);
    var run = try Run.init(&f, hostname, peer.address);
    defer run.destroy();
    try run.start();
    _ = try run.deliver();
    try f.append(host_failure);
    const before_revision = try f.store.revision("fixture");
    try t.expectError(error.ConsumerPending, run.deliver());
    try t.expectEqual(@as(usize, 1), try f.store.pendingReceiptCount());
    try t.expect(run.session.?.pipe.ready);
    try t.expectEqual(.pending, run.session.?.last_failure_domain.?);
    try t.expectEqual(@as(u64, 0), run.jail.?.sources[0].rules[0].counters[@intFromEnum(rules.Kind.candidate)]);
    _ = try complete(&run, peer, 30);
    try t.expectEqual(before_revision, try f.store.revision("fixture"));
    try t.expectEqual(@as(usize, 1), try f.store.pendingReceiptCount());
    try t.expectEqual(@as(usize, 1), try run.deliver());
    var outcomes: [16]detection.Outcome = undefined;
    const source = &run.session.?.sources.sources.items[0];
    try t.expectEqual(@as(usize, 2), try f.store.nativeDetections("fixture", source.source_id, null, &outcomes));
    try t.expectEqual(detection.Kind.candidate, outcomes[0].kind);
    try t.expectEqual(detection.Kind.candidate, outcomes[1].kind);
    try t.expectEqual(@as(usize, 0), try f.store.pendingReceiptCount());
    try run.validate();
}

test "native consumer runtime: restart after DNS input commit restores original expiry and pending receipt" {
    var f = try Fixture.init();
    defer f.deinit();
    const peer = try Peer.init();
    defer std.posix.close(peer.fd);
    {
        var run = try Run.init(&f, hostname, peer.address);
        defer run.destroy();
        try run.start();
        _ = try run.deliver();
        try f.append(host_failure);
        try t.expectError(error.ConsumerPending, run.deliver());
        _ = try complete(&run, peer, 30);
    }
    try f.reopen();
    f.clock.us += 5_000_000;
    f.clock.ms += 5000;
    var restarted = try Run.init(&f, hostname, peer.address);
    defer restarted.destroy();
    try restarted.start();
    try t.expectEqual(@as(usize, 1), try restarted.deliver());
    const request = dns.Request{ .name = try dns.Name.init("client.example"), .family = .v4, .generation = gen };
    const cached = (try restarted.resolver.cache.lookup(request, f.clock.us)).?;
    try t.expectEqual(@as(i64, 1_030_000_000), cached.result.valid_until_us);
    const source = &restarted.session.?.sources.sources.items[0];
    try t.expectEqual(@as(i64, 1_000_000_000), (try f.store.nativeTime("fixture", source.source_id, null)).?.eligible.receipt.us);
    try t.expectEqual(runtime.Poll{ .kind = .idle }, try restarted.resolver.pollDns());
}

test "native consumer runtime: required missing row refuses source restart without bootstrap reset" {
    var f = try Fixture.init();
    defer f.deinit();
    {
        var run = try Run.init(&f, plain, null);
        defer run.destroy();
        try run.createJail();
        try run.jail.?.admitSource("inode-a", gen);
    }
    try sql(&f.store, "DELETE FROM consumer_checkpoints WHERE kind=1;");
    try f.reopen();
    var restarted = try Run.init(&f, plain, null);
    defer restarted.destroy();
    try restarted.createJail();
    try t.expectError(error.MissingRequiredConsumer, restarted.jail.?.admitSource("inode-a", gen));
    try t.expectEqual(@as(usize, 0), restarted.jail.?.count);
}

test "native consumer runtime: final validation detects omitted source and cross-owner revision change" {
    var f = try Fixture.init();
    defer f.deinit();
    var run = try Run.init(&f, plain, null);
    defer run.destroy();
    try run.createJail();
    try run.jail.?.admitSource("inode-a", gen);
    try run.validate();
    try run.resolver.beginValidation();
    try t.expect(try run.resolver.validateTurn());
    try run.jail.?.admitSource("inode-b", gen);
    try run.jail.?.beginValidation();
    try t.expect(try run.jail.?.validateTurn());
    try t.expectError(error.StaleConsumerCheckpoint, run.resolver.finishValidation(&.{run.jail.?}));
    try run.validate();
}

test "native consumer runtime: memory admission refuses before owners and authority mutation" {
    var f = try Fixture.init();
    defer f.deinit();
    const peer = try Peer.init();
    defer std.posix.close(peer.fd);
    try t.expectError(error.ConsumerRuntimeBudget, runtime.DnsRuntime.create(t.allocator, &f.store, .{ .generation = gen, .server = peer.address, .capacity = 1024, .max_sources = 4096, .max_owned_bytes = 1, .clock = f.clock.bound() }));
    var keys: [1]durable.Store.ManifestKey = undefined;
    const page = try f.store.consumerManifestKeysPage(t.allocator, "@shared", null, null, &keys);
    try t.expectEqual(@as(usize, 0), page.count);
}

test "native consumer runtime: same-turn zero TTL resolves subject without cached exclusion" {
    var f = try Fixture.init();
    defer f.deinit();
    const peer = try Peer.init();
    defer std.posix.close(peer.fd);
    var run = try Run.init(&f, hostname, peer.address);
    defer run.destroy();
    try run.start();
    const health = @import("core/storage_health.zig");
    var gate = health.Gate.init(.{ .context = &f.clock, .read = Clock.mono });
    const recovery_generation = try gate.beginRecovery();
    inline for (.{ .storage, .state, .ownership, .sources }) |step| try gate.completed(recovery_generation, step);
    run.session.?.pipe.gate = &gate;
    run.session.?.pipe.recovery_generation = recovery_generation;
    _ = try run.deliver();
    try f.append(host_failure);
    try t.expectError(error.ConsumerPending, run.deliver());
    try t.expect(run.session.?.pipe.ready);
    try t.expectEqual(health.Phase.healthy, gate.snapshot().phase);
    const completion = try complete(&run, peer, 0);
    f.clock.us += 25;
    try t.expectEqual(@as(usize, 1), try run.session.?.resumeConsumerSource(completion.source.?.incarnation));
    const request = dns.Request{ .name = try dns.Name.init("client.example"), .family = .v4, .generation = gen };
    try t.expect((try run.resolver.cache.lookup(request, f.clock.us)) == null);
    try t.expectEqual(@as(usize, 0), try f.store.pendingReceiptCount());
}

fn allocateDns(allocator: std.mem.Allocator, store: *durable.Store, clock: *Clock) !void {
    const owner = try runtime.DnsRuntime.create(allocator, store, .{ .generation = gen, .capacity = 8, .max_sources = 4, .max_owned_bytes = 8 * 1024 * 1024, .clock = clock.bound() });
    owner.destroy();
}
fn allocateJail(allocator: std.mem.Allocator, run: *Run) !void {
    const jail = try runtime.JailRuntime.create(allocator, &run.fixture.store, run.resolver, .{ .settings = .{ .jail = "fixture", .logical_source = "application", .filter = try detection.Name.init("custom"), .parent_generation = gen, .ignore_generation = run.initial.generation, .family = .v4 }, .programs = &run.programs, .initial_ignore = run.initial, .ignore_options = run.initial.options, .max_sources = 4, .max_owned_bytes = 8 * 1024 * 1024 });
    jail.destroy();
}
test "native consumer runtime: every runtime owner allocation failure releases owned memory" {
    var f = try Fixture.init();
    defer f.deinit();
    try t.checkAllAllocationFailures(t.allocator, allocateDns, .{ &f.store, &f.clock });
    var run = try Run.init(&f, plain, null);
    defer run.destroy();
    run.programs = .{run.program};
    try t.checkAllAllocationFailures(t.allocator, allocateJail, .{&run});
}

test "native consumer runtime: shared DNS reads require pinned authority ownership expiry and CAS" {
    var f = try Fixture.init();
    defer f.deinit();
    const peer = try Peer.init();
    defer std.posix.close(peer.fd);
    var run = try Run.init(&f, hostname, peer.address);
    defer run.destroy();
    try run.start();
    _ = try run.deliver();
    try f.append(host_failure);
    try t.expectError(error.ConsumerPending, run.deliver());
    _ = try complete(&run, peer, 30);
    const owner = &run.jail.?.sources[0].coordinator;
    const pending = (try f.store.readPendingSource(t.allocator, "fixture", owner.incarnation)).?;
    defer pending.deinit(t.allocator);
    const receipt = time.Timestamp{ .us = pending.receipt_us };
    const prepared = try owner.prepare(.{ .record = .{ .source = pending.identity.source, .occurrence = pending.identity.occurrence, .cursor = pending.identity.cursor, .raw_hash = pending.identity.raw_hash, .message = host_failure[0 .. host_failure.len - 1], .receipt_time = receipt }, .decoded = host_failure[0 .. host_failure.len - 1], .time = .{ .eligible = .{ .timestamp = receipt, .receipt = receipt, .origin = .receipt, .original = null } }, .processing_us = f.clock.us, .monotonic_ms = f.clock.ms });
    defer prepared.release(prepared.context);
    const manifest = try owner.manifest(run.session.?.processor.generation);
    try t.expectEqual(@as(usize, 3), prepared.consumers.dependencies.len);
    var dependencies: [3]state.Dependency = undefined;
    @memcpy(&dependencies, prepared.consumers.dependencies);
    var authority_index: usize = 0;
    var dynamic_index: usize = 0;
    for (dependencies, 0..) |dependency, i| {
        if (std.mem.eql(u8, dependency.key.source, "@resolver")) authority_index = i;
        if (std.mem.eql(u8, dependency.key.source, "client.example")) dynamic_index = i;
    }
    var omitted: [2]state.Dependency = undefined;
    var at: usize = 0;
    for (dependencies, 0..) |dependency, i| if (i != authority_index) {
        omitted[at] = dependency;
        at += 1;
    };
    var batch = prepared.consumers;
    batch.dependencies = &omitted;
    try t.expectError(error.MissingRequiredConsumer, f.store.commitConsumerInput(manifest, batch));
    batch.dependencies = &dependencies;
    dependencies[dynamic_index].key.generation[0] ^= 1;
    try t.expectError(error.ConsumerManifestMismatch, f.store.commitConsumerInput(manifest, batch));
    dependencies[dynamic_index] = prepared.consumers.dependencies[dynamic_index];
    dependencies[dynamic_index].key.source = "unowned.example";
    try t.expectError(error.ConsumerManifestMissing, f.store.commitConsumerInput(manifest, batch));
    dependencies[dynamic_index] = prepared.consumers.dependencies[dynamic_index];
    try sql(&f.store, "UPDATE consumer_manifests SET ready=0 WHERE jail='@shared' AND source='v4:client.example';");
    try t.expectError(error.MissingRequiredConsumer, f.store.commitConsumerInput(manifest, batch));
    try sql(&f.store, "UPDATE consumer_manifests SET ready=1 WHERE jail='@shared' AND source='v4:client.example';");
    dependencies[dynamic_index].expected_revision += 1;
    try t.expectError(error.StaleConsumerCheckpoint, f.store.commitConsumerInput(manifest, batch));
    dependencies[dynamic_index] = prepared.consumers.dependencies[dynamic_index];
    f.clock.us += 30_000_000;
    try t.expectError(error.ConsumerExpired, f.store.commitConsumerInput(manifest, batch));
    try t.expectEqual(@as(usize, 1), try f.store.pendingReceiptCount());
    try t.expectEqual(@as(u64, 0), run.jail.?.sources[0].rules[0].counters[@intFromEnum(rules.Kind.candidate)]);
}

test "native consumer runtime: immutable resolver authority cannot be rewritten or silently recreated" {
    var f = try Fixture.init();
    defer f.deinit();
    const peer = try Peer.init();
    defer std.posix.close(peer.fd);
    {
        var run = try Run.init(&f, hostname, peer.address);
        defer run.destroy();
        const key = bridge.resolverKey(gen);
        const requirements = [_]state.Requirement{.{ .key = key, .format_version = 1 }};
        const manifest = state.Manifest{ .jail = "@shared", .source = "@resolver", .source_generation = gen, .required = &requirements };
        const deltas = [_]state.Delta{.{ .key = key, .format_version = 1, .expected_revision = 1, .payload = &gen }};
        try t.expectError(error.InvalidConsumer, f.store.commitConsumerInput(manifest, .{ .deltas = &deltas, .prepared_us = f.clock.us, .clock_context = run.resolver, .clock = runtime.DnsRuntime.commitClock }));
    }
    try sql(&f.store, "DELETE FROM consumer_checkpoints WHERE source='@resolver';");
    try t.expectError(error.MissingRequiredConsumer, Run.init(&f, hostname, peer.address));
}

test "native consumer runtime: DNS scheduler refuses held record stage and active SQL transaction" {
    var f = try Fixture.init();
    defer f.deinit();
    const peer = try Peer.init();
    defer std.posix.close(peer.fd);
    var run = try Run.init(&f, plain, peer.address);
    defer run.destroy();
    try run.createJail();
    try run.jail.?.admitSource("inode-a", gen);
    const owner = &run.jail.?.sources[0].coordinator;
    const stage = try owner.prepareCheckpoint(.{ .kind = .checkpoint, .source = "inode-a", .occurrence = "baseline", .cursor = "cursor", .message = "", .raw_hash = gen }, f.clock.us, f.clock.ms);
    try t.expectError(error.ConsumerBusy, run.resolver.pollDns());
    stage.release(stage.context);
    try sql(&f.store, "BEGIN;");
    try t.expectError(error.ConsumerTransactionActive, run.resolver.pollDns());
    try sql(&f.store, "ROLLBACK;");
    try t.expect(run.resolver.client.?.socket == null);
    try t.expectEqual(.idle, (try run.resolver.pollDns()).kind);
}

test "native consumer runtime: failed fanout transaction reopens with original receipt and no partial outcomes" {
    for ([_]durable.CommitStage{ .after_detection, .after_consumer_delta }) |fault| {
        var f = try Fixture.init();
        defer f.deinit();
        const peer = try Peer.init();
        defer std.posix.close(peer.fd);
        {
            var run = try Run.init(&f, hostname, peer.address);
            defer run.destroy();
            try run.start();
            _ = try run.deliver();
            const source = &run.session.?.sources.sources.items[0];
            const prior = (try f.store.sourceCursor(t.allocator, "fixture", source.source_id)).?;
            defer t.allocator.free(prior);
            try f.append(host_failure);
            try t.expectError(error.ConsumerPending, run.deliver());
            _ = try complete(&run, peer, 30);
            f.store.fail_at = fault;
            try t.expectError(error.InjectedFailure, run.deliver());
            f.store.fail_at = null;
            const current = (try f.store.sourceCursor(t.allocator, "fixture", source.source_id)).?;
            defer t.allocator.free(current);
            try t.expectEqualStrings(prior, current);
            var outcomes: [16]detection.Outcome = undefined;
            try t.expectEqual(@as(usize, 0), try f.store.nativeDetections("fixture", source.source_id, null, &outcomes));
            try t.expectEqual(@as(usize, 1), try f.store.pendingReceiptCount());
            try t.expectEqual(@as(u64, 0), run.jail.?.sources[0].rules[0].counters[@intFromEnum(rules.Kind.candidate)]);
        }
        try f.reopen();
        f.clock.us += 1_000_000;
        f.clock.ms += 1000;
        var restarted = try Run.init(&f, hostname, peer.address);
        defer restarted.destroy();
        try restarted.start();
        try t.expectEqual(@as(usize, 1), try restarted.deliver());
        var outcomes: [16]detection.Outcome = undefined;
        const source = &restarted.session.?.sources.sources.items[0];
        try t.expectEqual(@as(usize, 2), try f.store.nativeDetections("fixture", source.source_id, null, &outcomes));
        try t.expectEqual(@as(i64, 1_000_000_000), (try f.store.nativeTime("fixture", source.source_id, null)).?.eligible.receipt.us);
        try t.expectEqual(@as(u64, 1), restarted.jail.?.sources[0].rules[0].counters[@intFromEnum(rules.Kind.candidate)]);
        try t.expectEqual(@as(usize, 0), try f.store.pendingReceiptCount());
    }
}

test "native consumer runtime: authoritative preflight matches exact creation admission and validates size inputs" {
    var f = try Fixture.init();
    defer f.deinit();
    var run = try Run.init(&f, plain, null);
    defer run.destroy();
    try run.createJail();
    const dns_plan = try runtime.DnsRuntime.allocationPlan(run.resolver.options);
    try t.expectEqual(run.resolver.reserved_bytes, try dns_plan.requiredBytes());
    try t.expectEqual(run.resolver.reserved_bytes, try runtime.DnsRuntime.requiredBytes(run.resolver.options));
    const jail_plan = try runtime.JailRuntime.allocationPlan(run.jail.?.options);
    try t.expectEqual(run.jail.?.reserved_bytes, try jail_plan.requiredBytes());
    try t.expectEqual(run.jail.?.reserved_bytes, try runtime.JailRuntime.requiredBytes(run.jail.?.options));
    var dns_options = run.resolver.options;
    dns_options.max_owned_bytes = run.resolver.reserved_bytes - 1;
    try t.expectError(error.ConsumerRuntimeBudget, runtime.DnsRuntime.create(t.allocator, &f.store, dns_options));
    dns_options.max_owned_bytes += 1;
    const exact = try runtime.DnsRuntime.create(t.allocator, &f.store, dns_options);
    exact.destroy();
    dns_options.capacity = 0;
    try t.expectError(error.InvalidConsumerRuntimeLimits, runtime.DnsRuntime.requiredBytes(dns_options));
    var jail_options = run.jail.?.options;
    jail_options.max_sources = std.math.maxInt(usize);
    try t.expectError(error.InvalidConsumerRuntimeLimits, runtime.JailRuntime.requiredBytes(jail_options));
    jail_options = run.jail.?.options;
    jail_options.programs = &.{};
    try t.expectError(error.InvalidConsumerRuntimeLimits, runtime.JailRuntime.requiredBytes(jail_options));
    try t.expectError(error.ConsumerRuntimeBudget, (runtime.AllocationPlan{ .fixed_live_bytes = std.math.maxInt(usize), .per_source_live_bytes = 1, .source_capacity = 1, .capacity_live_bytes = 0, .workspace_bytes = 0 }).requiredBytes());
}

test "native consumer runtime: startup restore permits private state but refuses DNS dispatch" {
    var f = try Fixture.init();
    defer f.deinit();
    const peer = try Peer.init();
    defer std.posix.close(peer.fd);
    try f.store.beginStartupAdmission();
    defer f.store.abortStartupAdmission();
    var run = try Run.init(&f, hostname, peer.address);
    defer run.destroy();
    try run.createJail();
    try run.validate();
    try t.expectError(error.ConsumerTransactionActive, run.resolver.pollDns());
    try t.expectError(error.ConsumerTransactionActive, run.resolver.advanceTurn());
    try f.store.finishStartupAdmission();
    try t.expect((try run.resolver.pollDns()).kind == .idle);
}

test "native consumer runtime: file-backed allowlist refresh commits a new shared revision and survives restart, failures retain the last valid set" {
    var f = try Fixture.init();
    defer f.deinit();
    var run = try Run.init(&f, plain, null);
    var live = true;
    defer if (live) run.destroy();
    try run.start();
    _ = try run.deliver();
    const jail = run.jail.?;
    const before = jail.ignores.revision;
    try t.expectEqual(@as(u64, 1), before);
    const initial_payload = try t.allocator.dupe(u8, jail.ignores.live.payload);
    defer t.allocator.free(initial_payload);

    try writeAllowlist(&f, "192.0.2.0/24 # office\n198.51.100.7\n");
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const allow_path = try f.tmp.dir.realpath("allow.txt", &path_buf);
    const first = jail.refreshAllowlist(allow_path, f.clock.us) catch |err| {
        std.debug.print("allowlist refresh failed: {s}\n", .{@errorName(err)});
        return err;
    };
    try t.expectEqual(runtime.JailRuntime.AllowlistRefresh.applied, first);
    try t.expectEqual(before + 1, jail.ignores.revision);
    try t.expect(!std.mem.eql(u8, initial_payload, jail.ignores.live.payload));
    try t.expectEqual(@as(usize, 2), jail.ignores.live.entries.len);
    const refreshed = try t.allocator.dupe(u8, jail.ignores.live.payload);
    defer t.allocator.free(refreshed);
    try t.expectEqual(runtime.JailRuntime.AllowlistRefresh.unchanged, try jail.refreshAllowlist(allow_path, f.clock.us));
    try t.expectEqual(before + 1, jail.ignores.revision);

    try t.expectError(error.FileNotFound, jail.refreshAllowlist("/nonexistent/allow.txt", f.clock.us));
    try writeAllowlist(&f, "not an address here\n");
    try t.expectError(error.InvalidIgnoreEntry, jail.refreshAllowlist(allow_path, f.clock.us));
    try t.expectEqualSlices(u8, refreshed, jail.ignores.live.payload);
    try t.expectEqual(before + 1, jail.ignores.revision);

    run.destroy();
    live = false;
    try f.reopen();
    var restarted = try Run.init(&f, plain, null);
    defer restarted.destroy();
    try restarted.start();
    try t.expectEqual(before + 1, restarted.jail.?.ignores.revision);
    try t.expectEqualSlices(u8, refreshed, restarted.jail.?.ignores.live.payload);
}

fn writeAllowlist(f: *Fixture, data: []const u8) !void {
    const file = try f.tmp.dir.createFile("allow.txt", .{ .truncate = true, .mode = 0o600 });
    defer file.close();
    try file.chmod(0o600);
    try file.writeAll(data);
}
