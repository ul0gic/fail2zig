// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const t = std.testing;
const module = @import("core/native_consumer_coordinator.zig");
const rules = @import("core/native_rules.zig");
const rule = @import("core/native_rule_consumer.zig");
const ignores = @import("core/native_ignore.zig");
const dns = @import("core/native_dns.zig");
const detection = @import("core/native_detection_record.zig");
const state = @import("core/native_consumer.zig");
const gen = [_]u8{7} ** 32;
const plain = "{\"id\":\"private-login\",\"source\":\"application\",\"format\":\"json\",\"subject\":\"peer\",\"conditions\":[{\"field\":\"result\",\"text\":\"denied\"}]}";
const hostname = "{\"id\":\"private-login\",\"source\":\"application\",\"format\":\"json\",\"subject\":\"peer\",\"subject_kind\":\"hostname\",\"conditions\":[{\"field\":\"result\",\"text\":\"denied\"}]}";
const correlated = "{\"id\":\"private-login\",\"source\":\"application\",\"format\":\"json\",\"subject\":\"peer\",\"conditions\":[{\"field\":\"phase\",\"text\":\"failed\"}],\"correlation\":{\"key\":\"session\",\"phase\":\"phase\",\"start\":\"connected\",\"finish\":\"failed\",\"ttl_seconds\":30}}";
const failure = "{\"peer\":\"198.51.100.81\",\"result\":\"denied\"}";
const host_failure = "{\"peer\":\"client.example\",\"result\":\"denied\"}";
const Clock = struct {
    us: i64 = 10_000_000,
    ms: u64 = 10,
    turn: u64 = 1,
    fn now(context: ?*anyopaque) i64 {
        const self: *Clock = @ptrCast(@alignCast(context.?));
        return self.us;
    }
    fn token(context: ?*anyopaque) u64 {
        const self: *Clock = @ptrCast(@alignCast(context.?));
        return self.turn;
    }
    fn mono(context: ?*anyopaque) u64 {
        const self: *Clock = @ptrCast(@alignCast(context.?));
        return self.ms;
    }
};
const Fixture = struct {
    program: *rules.Program,
    owner: rule.Consumer,
    owner_ptrs: [1]*rule.Consumer = undefined,
    ignore_owner: ignores.Owner,
    cache: dns.Cache,
    clock: Clock = .{},
    coordinator: module.Coordinator = undefined,
    fn init(config: []const u8, allowlist: []const []const u8) !Fixture {
        const program = try rules.Program.create(t.allocator, config, .{});
        errdefer program.destroy();
        const snapshot = try ignores.Snapshot.create(t.allocator, .{ .parent_generation = gen, .resolver_generation = gen, .family = .both }, allowlist);
        errdefer snapshot.destroy();
        return .{ .program = program, .owner = try rule.Consumer.init(program, "application", "inode-a", gen, true), .ignore_owner = .{ .live = snapshot, .revision = 0 }, .cache = try dns.Cache.init(t.allocator, gen, 32) };
    }
    fn bind(self: *Fixture) !void {
        self.owner_ptrs = .{&self.owner};
        self.coordinator = try module.Coordinator.init(.{ .jail = "application", .logical_source = "application", .filter = try detection.Name.init("custom"), .parent_generation = gen, .ignore_generation = self.ignore_owner.live.generation, .authority_revision = 1, .clock_context = &self.clock, .clock = Clock.now, .monotonic_ms = Clock.mono, .turn = Clock.token }, "inode-a", &self.owner_ptrs, &self.ignore_owner, &self.cache);
    }
    fn ready(self: *Fixture) !void {
        const stage = try self.coordinator.prepareBootstrap(gen, self.clock.us);
        try stage.state.consumers.validate();
        stage.state.publish(stage.state.context);
        stage.state.release(stage.state.context);
    }
    fn deinit(self: *Fixture) void {
        self.cache.deinit();
        self.ignore_owner.deinit();
        self.program.destroy();
    }
    fn input(self: *Fixture, body: []const u8, occurrence: []const u8) detection.StagedInput {
        return .{ .record = .{ .source = "inode-a", .occurrence = occurrence, .cursor = occurrence, .message = body, .raw_hash = gen, .receipt_time = .{ .us = 10_000_000 } }, .decoded = body, .processing_us = self.clock.us, .monotonic_ms = self.clock.ms, .time = .{ .eligible = .{ .timestamp = .{ .us = 10_000_000 }, .origin = .event, .original = .{ .us = 10_000_000 }, .receipt = .{ .us = 10_000_000 } } } };
    }
    fn result(self: *Fixture, count: usize, ttl: u32) !dns.Result {
        const request = self.coordinator.pendingRequest().?.request;
        var answer = dns.Answer{ .kind = if (count == 0) .negative else .positive, .canonical = request.name, .ttl_seconds = ttl };
        for (0..count) |i| try answer.add(.{ .ipv4 = 0xc6336401 + @as(u32, @intCast(i)) });
        return .{ .request = request, .answer = answer, .completed_us = self.clock.us, .valid_until_us = self.clock.us + @as(i64, ttl) * 1_000_000, .deadline_ms = self.clock.ms + 4000 };
    }
    fn commitDns(self: *Fixture, completion: dns.Result) !void {
        const stage = try self.coordinator.prepareDnsResult(completion, self.clock.ms, self.clock.us);
        try stage.state.consumers.validate();
        _ = try stage.manifest.digest();
        stage.state.publish(stage.state.context);
        stage.state.release(stage.state.context);
    }
};
test "native coordinator: first-use rows precede observation and aborted bootstrap stays unavailable" {
    var f = try Fixture.init(plain, &.{});
    defer f.deinit();
    try f.bind();
    try t.expectError(error.ConsumerStateNotReady, f.coordinator.prepare(f.input(failure, "one")));
    const first = try f.coordinator.prepareBootstrap(gen, f.clock.us);
    try t.expectEqual(@as(usize, 2), first.state.consumers.deltas.len);
    try t.expectEqual(@as(usize, 3), first.manifest.required.len);
    try t.expect(!f.coordinator.ready);
    first.state.release(first.state.context);
    try t.expectEqual(@as(u64, 0), f.ignore_owner.revision);
    try t.expect(std.mem.allEqual(u64, &f.owner.counters, 0));
    try f.ready();
    try t.expect(f.coordinator.ready);
    try t.expectEqual(@as(u64, 1), f.ignore_owner.revision);
    try t.expect(std.mem.allEqual(u64, &f.owner.counters, 0));
    try t.expectError(error.ConsumerAlreadyReady, f.coordinator.prepareBootstrap(gen, f.clock.us));
}
test "native coordinator: literal candidate rollback and committed publication share exact revision" {
    var f = try Fixture.init(plain, &.{});
    defer f.deinit();
    try f.bind();
    try f.ready();
    const stage = try f.coordinator.prepare(f.input(failure, "one"));
    try t.expectEqual(detection.Kind.candidate, stage.outcomes[0].kind);
    try t.expectEqual(@as(usize, 1), stage.consumers.deltas.len);
    try t.expectEqual(@as(u64, 1), stage.consumers.deltas[0].expected_revision);
    try t.expect(f.coordinator.pendingRequest() == null);
    try t.expect(std.mem.allEqual(u64, &f.owner.counters, 0));
    stage.release(stage.context);
    const retry = try f.coordinator.prepare(f.input(failure, "one"));
    retry.publish(retry.context);
    retry.publish(retry.context);
    retry.release(retry.context);
    try t.expectEqual(@as(u64, 2), f.coordinator.revisions[0]);
    try t.expectEqual(@as(u64, 1), f.owner.counters[@intFromEnum(rules.Kind.candidate)]);
}
test "native coordinator: checkpoint and rejected time pin state without rule observations" {
    var f = try Fixture.init(plain, &.{});
    defer f.deinit();
    try f.bind();
    try f.ready();
    var input = f.input(failure, "one");
    input.record.kind = .checkpoint;
    input.record.receipt_time = null;
    const checkpoint = try f.coordinator.prepareCheckpoint(input.record, f.clock.us, f.clock.ms);
    try t.expectEqual(@as(usize, 0), checkpoint.consumers.deltas.len);
    try t.expectEqual(@as(usize, 3), checkpoint.consumers.dependencies.len);
    checkpoint.publish(checkpoint.context);
    checkpoint.release(checkpoint.context);
    input.record.kind = .data;
    input.record.receipt_time = .{ .us = 10_000_000 };
    input.time = .{ .rejected = .{ .reason = .malformed } };
    const rejected = try f.coordinator.prepare(input);
    try t.expectEqual(detection.Kind.time_excluded, rejected.outcomes[0].kind);
    rejected.publish(rejected.context);
    rejected.release(rejected.context);
    try t.expect(std.mem.allEqual(u64, &f.owner.counters, 0));
}
test "native coordinator: DNS yield releases rules and input commit retains pending occurrence" {
    var f = try Fixture.init(hostname, &.{});
    defer f.deinit();
    try f.bind();
    try f.ready();
    try t.expectError(error.ConsumerPending, f.coordinator.prepare(f.input(host_failure, "one")));
    try t.expect(!f.owner.in_flight and !f.coordinator.busy);
    try t.expect(std.mem.allEqual(u64, &f.owner.counters, 0));
    try t.expectError(error.ConsumerPending, f.coordinator.prepare(f.input(host_failure, "two")));
    const result = try f.result(16, 30);
    const stage = try f.coordinator.prepareDnsResult(result, f.clock.ms, f.clock.us);
    try t.expect(stage.bootstrap);
    try t.expectEqualStrings("both:client.example", stage.manifest.source);
    try t.expect((try f.cache.lookup(result.request, f.clock.us)) == null);
    stage.state.release(stage.state.context);
    try f.commitDns(result);
    try t.expect(f.coordinator.waiting_occurrence != null);
    const prepared = try f.coordinator.prepare(f.input(host_failure, "one"));
    try t.expectEqual(@as(usize, 16), prepared.outcomes.len);
    try t.expectEqual(@as(usize, 3), prepared.consumers.dependencies.len);
    prepared.publish(prepared.context);
    prepared.release(prepared.context);
    try t.expect(f.coordinator.waiting_occurrence == null);
    try t.expectEqual(@as(u64, 1), f.owner.counters[@intFromEnum(rules.Kind.candidate)]);
}
test "native coordinator: sequential subject and exclusion DNS commits make bounded progress" {
    var f = try Fixture.init(hostname, &.{"trusted.example"});
    defer f.deinit();
    try f.bind();
    try f.ready();
    try t.expectError(error.ConsumerPending, f.coordinator.prepare(f.input(host_failure, "one")));
    try f.commitDns(try f.result(2, 30));
    try t.expectError(error.ConsumerPending, f.coordinator.prepare(f.input(host_failure, "one")));
    try t.expectEqualStrings("trusted.example", f.coordinator.pendingRequest().?.request.name.slice());
    try t.expect(!f.owner.in_flight);
    try f.commitDns(try f.result(0, 20));
    const prepared = try f.coordinator.prepare(f.input(host_failure, "one"));
    try t.expectEqual(@as(usize, 2), prepared.outcomes.len);
    try t.expectEqual(@as(usize, 4), prepared.consumers.dependencies.len);
    for (prepared.outcomes) |outcome| try t.expectEqual(detection.Kind.candidate, outcome.kind);
    prepared.release(prepared.context);
}
test "native coordinator: stale completion and expiry during writer wait cannot publish" {
    var f = try Fixture.init(hostname, &.{});
    defer f.deinit();
    try f.bind();
    try f.ready();
    try t.expectError(error.ConsumerPending, f.coordinator.prepare(f.input(host_failure, "one")));
    var result = try f.result(1, 1);
    result.request.id += 1;
    try t.expectError(error.DnsRequestMismatch, f.coordinator.prepareDnsResult(result, f.clock.ms, f.clock.us));
    result.request.id -= 1;
    try f.commitDns(result);
    const prepared = try f.coordinator.prepare(f.input(host_failure, "one"));
    f.clock.us += 1_000_000;
    try t.expectError(error.ConsumerExpired, prepared.consumers.checkedTime(null));
    prepared.release(prepared.context);
    try t.expect(std.mem.allEqual(u64, &f.owner.counters, 0));
}
test "native coordinator: zero TTL subject is single immediate preparation and never a cache exclusion" {
    var f = try Fixture.init(hostname, &.{});
    defer f.deinit();
    try f.bind();
    try f.ready();
    try t.expectError(error.ConsumerPending, f.coordinator.prepare(f.input(host_failure, "one")));
    const result = try f.result(1, 0);
    try t.expectError(error.DnsCacheExpired, f.coordinator.prepareDnsResult(result, f.clock.ms, f.clock.us));
    try f.coordinator.provideImmediate(result, f.clock.ms, f.clock.us);
    const prepared = try f.coordinator.prepare(f.input(host_failure, "one"));
    try t.expectEqual(detection.Kind.candidate, prepared.outcomes[0].kind);
    try t.expectEqual(@as(usize, 2), prepared.consumers.dependencies.len);
    _ = try prepared.consumers.checkedTime(null);
    f.clock.us += 20;
    _ = try prepared.consumers.checkedTime(null);
    f.clock.turn += 1;
    try t.expectError(error.ConsumerExpired, prepared.consumers.checkedTime(null));
    prepared.release(prepared.context);
    try t.expect((try f.cache.lookup(result.request, f.clock.us)) == null);
    try t.expectError(error.ConsumerPending, f.coordinator.prepare(f.input(host_failure, "one")));
}
test "native coordinator: required zero TTL exclusion stays pending without contamination" {
    var f = try Fixture.init(plain, &.{"trusted.example"});
    defer f.deinit();
    try f.bind();
    try f.ready();
    try t.expectError(error.ConsumerPending, f.coordinator.prepare(f.input(failure, "one")));
    const result = try f.result(1, 0);
    try t.expectError(error.ImmediateSubjectRequired, f.coordinator.provideImmediate(result, f.clock.ms, f.clock.us));
    try t.expectError(error.DnsCacheExpired, f.coordinator.prepareDnsResult(result, f.clock.ms, f.clock.us));
    try t.expect(!f.owner.in_flight and !f.cache.in_flight);
}
test "native coordinator: literal allowlist avoids DNS even alongside missing hostname input" {
    var f = try Fixture.init(plain, &.{ "198.51.100.0/24", "trusted.example" });
    defer f.deinit();
    try f.bind();
    try f.ready();
    const stage = try f.coordinator.prepare(f.input(failure, "one"));
    try t.expectEqual(detection.Kind.ignored, stage.outcomes[0].kind);
    try t.expectEqual(@as(usize, 2), stage.consumers.dependencies.len);
    try t.expect(f.coordinator.pendingRequest() == null);
    stage.release(stage.context);
}
test "native coordinator: ready restore refuses missing rows and restores committed unpublished counters" {
    var before = try Fixture.init(plain, &.{});
    defer before.deinit();
    try before.bind();
    try before.ready();
    const prepared = try before.coordinator.prepare(before.input(failure, "one"));
    const bytes = try t.allocator.dupe(u8, prepared.consumers.deltas[0].payload);
    defer t.allocator.free(bytes);
    const key = prepared.consumers.deltas[0].key;
    prepared.release(prepared.context);
    var after = try Fixture.init(plain, &.{});
    defer after.deinit();
    try after.bind();
    after.ignore_owner.revision = 1;
    const manifest = try after.coordinator.manifest(gen);
    const rows = [_]module.Saved{ .{ .key = key, .format_version = rule.version, .revision = 2, .payload = bytes }, .{ .key = manifest.required[1].key, .format_version = ignores.version, .revision = 1, .payload = after.ignore_owner.live.payload }, .{ .key = manifest.required[2].key, .format_version = 1, .revision = 1, .payload = &gen } };
    try t.expectError(error.ConsumerRestoreMismatch, after.coordinator.prepareRestore(gen, rows[0..1], after.clock.us));
    const restored = try after.coordinator.prepareRestore(gen, &rows, after.clock.us);
    try t.expect(!after.coordinator.ready);
    restored.state.publish(restored.state.context);
    restored.state.release(restored.state.context);
    try t.expect(after.coordinator.ready);
    try t.expectEqual(@as(u64, 2), after.coordinator.revisions[0]);
    try t.expectEqual(@as(u64, 1), after.owner.counters[@intFromEnum(rules.Kind.candidate)]);
}
test "native coordinator: correlation finish deadline is transient and rollback retains context" {
    var f = try Fixture.init(correlated, &.{});
    defer f.deinit();
    try f.bind();
    try f.ready();
    const start = try f.coordinator.prepare(f.input("{\"phase\":\"connected\",\"session\":\"a\",\"peer\":\"198.51.100.81\"}", "one"));
    try t.expectEqual(detection.Kind.no_match, start.outcomes[0].kind);
    start.publish(start.context);
    start.release(start.context);
    f.clock.us = 11_000_000;
    var input = f.input("{\"phase\":\"failed\",\"session\":\"a\"}", "two");
    input.time.eligible.timestamp.us = 11_000_000;
    const finish = try f.coordinator.prepare(input);
    try t.expectEqual(detection.Kind.candidate, finish.outcomes[0].kind);
    try t.expectEqual(@as(i64, 40_000_000), finish.consumers.commit_before_us.?);
    try t.expect(finish.consumers.deltas[0].valid_until_us == null);
    f.clock.us = 40_000_000;
    try t.expectError(error.ConsumerExpired, finish.consumers.checkedTime(null));
    finish.release(finish.context);
    try t.expect(f.owner.contexts.?.live.entries[0] != null);
}
test "native coordinator: registry dispatches exact incarnation and pins shared callback lifetime" {
    var f = try Fixture.init(plain, &.{});
    defer f.deinit();
    try f.bind();
    try f.ready();
    var registry = module.Registry.init(f.coordinator.generation);
    try registry.register(&f.coordinator);
    try t.expectError(error.DuplicateConsumerSource, registry.register(&f.coordinator));
    try t.expectError(error.ConsumerSourceUnbound, registry.source("inode-b"));
    const consumer = registry.consumer();
    const manifest = try consumer.manifest("inode-a", gen, consumer.context);
    try t.expectEqualStrings("inode-a", manifest.source);
    const stage = try consumer.prepare(f.input(failure, "one"), consumer.context);
    try t.expectEqual(detection.Kind.candidate, stage.outcomes[0].kind);
    stage.release(stage.context);
    var input = f.input("", "checkpoint");
    input.record.kind = .checkpoint;
    const checkpoint = try consumer.prepare_checkpoint(input.record, f.clock.us, f.clock.ms, consumer.context);
    checkpoint.release(checkpoint.context);
}
test "native coordinator: journal gate precedes custom context and forbids missing profile" {
    var f = try Fixture.init(correlated, &.{});
    defer f.deinit();
    try f.bind();
    var settings = f.coordinator.settings;
    settings.journal = true;
    try t.expectError(error.JournalOriginRequired, module.Coordinator.init(settings, "inode-a", &f.owner_ptrs, &f.ignore_owner, &f.cache));
    const profile = try @import("core/native_journal_origin.zig").Profile.init("0123456789abcdef0123456789abcdef", &.{"/usr/sbin/sshd"});
    settings.journal_origin = &profile;
    f.coordinator = try module.Coordinator.init(settings, "inode-a", &f.owner_ptrs, &f.ignore_owner, &f.cache);
    try f.ready();
    const stage = try f.coordinator.prepare(f.input("{\"phase\":\"connected\",\"session\":\"a\",\"peer\":\"198.51.100.81\"}", "one"));
    try t.expectEqual(detection.Kind.origin_missing, stage.outcomes[0].kind);
    try t.expectEqual(@as(usize, 0), stage.consumers.deltas.len);
    stage.publish(stage.context);
    stage.release(stage.context);
    try t.expect(f.owner.contexts.?.live.watermark_us == null);
}
test "native coordinator: admission reserves dependency capacity before polling" {
    var f = try Fixture.init(hostname, &.{});
    defer f.deinit();
    try f.bind();
    const values = [_][]const u8{ "a.example", "b.example", "c.example", "d.example", "e.example", "f.example", "g.example", "h.example", "i.example", "j.example", "k.example", "l.example", "m.example", "n.example", "o.example" };
    const snapshot = try ignores.Snapshot.create(t.allocator, .{ .parent_generation = gen, .resolver_generation = gen, .family = .both }, &values);
    f.ignore_owner.live.destroy();
    f.ignore_owner.live = snapshot;
    try t.expectError(error.ConsumerCapacity, f.bind());
}

test "native coordinator: multi-rule 17-subject union refuses all staged observations" {
    var f = try Fixture.init(hostname, &.{});
    defer f.deinit();
    try f.bind();
    const extra_program = try rules.Program.create(t.allocator, "{\"id\":\"literal-extra\",\"source\":\"application\",\"format\":\"json\",\"subject\":\"other\",\"conditions\":[{\"field\":\"result\",\"text\":\"denied\"}]}", .{});
    defer extra_program.destroy();
    var extra_owner = try rule.Consumer.init(extra_program, "application", "inode-a", gen, true);
    const owners = [_]*rule.Consumer{ &f.owner, &extra_owner };
    f.coordinator = try module.Coordinator.init(f.coordinator.settings, "inode-a", &owners, &f.ignore_owner, &f.cache);
    try f.ready();
    const body = "{\"peer\":\"client.example\",\"other\":\"203.0.113.99\",\"result\":\"denied\"}";
    try t.expectError(error.ConsumerPending, f.coordinator.prepare(f.input(body, "one")));
    try f.commitDns(try f.result(16, 30));
    try t.expectError(error.ConsumerCapacity, f.coordinator.prepare(f.input(body, "one")));
    try t.expect(!f.owner.in_flight and !extra_owner.in_flight and !f.coordinator.busy);
    try t.expect(std.mem.allEqual(u64, &f.owner.counters, 0));
    try t.expect(std.mem.allEqual(u64, &extra_owner.counters, 0));
    try t.expectEqual(@as(u64, 1), f.coordinator.revisions[0]);
    try t.expectEqual(@as(u64, 1), f.coordinator.revisions[1]);
}

test "native coordinator: same subject across rules contributes one atomic outcome" {
    var f = try Fixture.init(plain, &.{});
    defer f.deinit();
    try f.bind();
    const extra_program = try rules.Program.create(t.allocator, "{\"id\":\"literal-extra\",\"source\":\"application\",\"format\":\"json\",\"subject\":\"peer\",\"conditions\":[{\"field\":\"result\",\"text\":\"denied\"}]}", .{});
    defer extra_program.destroy();
    var extra_owner = try rule.Consumer.init(extra_program, "application", "inode-a", gen, true);
    const owners = [_]*rule.Consumer{ &f.owner, &extra_owner };
    f.coordinator = try module.Coordinator.init(f.coordinator.settings, "inode-a", &owners, &f.ignore_owner, &f.cache);
    try f.ready();
    const stage = try f.coordinator.prepare(f.input(failure, "one"));
    try t.expectEqual(@as(usize, 1), stage.outcomes.len);
    try t.expectEqual(@as(usize, 2), stage.consumers.deltas.len);
    stage.publish(stage.context);
    stage.release(stage.context);
    try t.expectEqual(@as(u64, 1), f.owner.counters[@intFromEnum(rules.Kind.candidate)]);
    try t.expectEqual(@as(u64, 1), extra_owner.counters[@intFromEnum(rules.Kind.candidate)]);
}

test "native coordinator: malformed restore releases earlier rule reservation" {
    var f = try Fixture.init(plain, &.{});
    defer f.deinit();
    try f.bind();
    const bootstrap = try f.coordinator.prepareBootstrap(gen, f.clock.us);
    const saved = try t.allocator.dupe(u8, bootstrap.state.consumers.deltas[0].payload);
    defer t.allocator.free(saved);
    const requirements = bootstrap.manifest.required;
    const rows = [_]module.Saved{
        .{ .key = requirements[0].key, .format_version = rule.version, .revision = 1, .payload = saved },
        .{ .key = requirements[1].key, .format_version = ignores.version, .revision = 1, .payload = "invalid" },
        .{ .key = requirements[2].key, .format_version = 1, .revision = 1, .payload = &gen },
    };
    bootstrap.state.release(bootstrap.state.context);
    f.ignore_owner.revision = 1;
    try t.expectError(error.ConsumerRestoreMismatch, f.coordinator.prepareRestore(gen, &rows, f.clock.us));
    try t.expect(!f.owner.in_flight and !f.coordinator.busy and !f.coordinator.ready);
    try t.expect(std.mem.allEqual(u64, &f.owner.counters, 0));
}

test "native coordinator: completion clock belongs only to same receipt and scheduler turn" {
    var f = try Fixture.init(hostname, &.{});
    defer f.deinit();
    try f.bind();
    try f.ready();
    try t.expectError(error.ConsumerPending, f.coordinator.prepare(f.input(host_failure, "one")));
    const completion = try f.result(1, 0);
    try f.coordinator.provideImmediate(completion, f.clock.ms, f.clock.us);
    var registry = module.Registry.init(f.coordinator.generation);
    try registry.register(&f.coordinator);
    const consumer = registry.consumer();
    f.clock.us += 20;
    try t.expectEqual(completion.completed_us, try consumer.processing_time.?(f.input(host_failure, "one").record, f.clock.us, consumer.context));
    try t.expectError(error.ConsumerPending, consumer.processing_time.?(f.input(host_failure, "two").record, f.clock.us, consumer.context));
    var changed = f.input(host_failure, "one");
    changed.record.receipt_time.?.us += 1;
    try t.expectError(error.ConsumerPending, f.coordinator.processingTime(changed.record, f.clock.us));
    f.clock.turn += 1;
    try t.expectError(error.ConsumerExpired, f.coordinator.processingTime(f.input(host_failure, "one").record, f.clock.us));
    try t.expect(f.coordinator.immediate == null);
    try t.expectError(error.ConsumerPending, f.coordinator.prepare(f.input(host_failure, "one")));
}

test "native coordinator: shared DNS input expires at original monotonic request deadline" {
    var f = try Fixture.init(hostname, &.{});
    defer f.deinit();
    try f.bind();
    try f.ready();
    try t.expectError(error.ConsumerPending, f.coordinator.prepare(f.input(host_failure, "one")));
    const completion = try f.result(1, 30);
    const stage = try f.coordinator.prepareDnsResult(completion, f.clock.ms, f.clock.us);
    _ = try stage.state.consumers.checkedTime(null);
    f.clock.ms = completion.deadline_ms;
    try t.expectError(error.ConsumerExpired, stage.state.consumers.checkedTime(null));
    stage.state.release(stage.state.context);
    try t.expect((try f.cache.lookup(completion.request, f.clock.us)) == null);
    try t.expect(!f.cache.in_flight);
}

test "native coordinator: failed outer preparation cannot reuse completion clock in same turn" {
    var f = try Fixture.init(hostname, &.{});
    defer f.deinit();
    try f.bind();
    try f.ready();
    try t.expectError(error.ConsumerPending, f.coordinator.prepare(f.input(host_failure, "one")));
    const completion = try f.result(1, 0);
    try f.coordinator.provideImmediate(completion, f.clock.ms, f.clock.us);
    const record = f.input(host_failure, "one").record;
    _ = try f.coordinator.processingTime(record, f.clock.us);
    try t.expectError(error.ConsumerExpired, f.coordinator.processingTime(record, f.clock.us));
    try t.expect(f.coordinator.immediate == null);
}

test "native coordinator: initial ignore contents bind generation despite same parent identifier" {
    var first = try Fixture.init(plain, &.{});
    defer first.deinit();
    try first.bind();
    var changed = try Fixture.init(plain, &.{"198.51.100.0/24"});
    defer changed.deinit();
    try changed.bind();
    try t.expect(!std.mem.eql(u8, &first.coordinator.generation, &changed.coordinator.generation));
    var settings = changed.coordinator.settings;
    settings.ignore_generation = first.ignore_owner.live.generation;
    try t.expectError(error.IgnoreGenerationMismatch, module.Coordinator.init(settings, "inode-a", &changed.owner_ptrs, &changed.ignore_owner, &changed.cache));
    settings.ignore_generation = [_]u8{0} ** 32;
    try t.expectError(error.IgnoreGenerationMismatch, module.Coordinator.init(settings, "inode-a", &changed.owner_ptrs, &changed.ignore_owner, &changed.cache));
}

test "native coordinator: restored allowlist preserves configured initial identity for later sources" {
    var f = try Fixture.init(plain, &.{});
    defer f.deinit();
    try f.bind();
    const initial = f.ignore_owner.live;
    const changed = try ignores.Snapshot.create(t.allocator, initial.options, &.{"198.51.100.0/24"});
    f.ignore_owner.live = changed;
    defer initial.destroy();
    try t.expectError(error.IgnoreGenerationMismatch, module.Coordinator.init(f.coordinator.settings, "inode-a", &f.owner_ptrs, &f.ignore_owner, &f.cache));
    const restored = try module.Coordinator.initWithInitial(f.coordinator.settings, "inode-a", &f.owner_ptrs, &f.ignore_owner, initial, &f.cache);
    try t.expectEqual(f.coordinator.generation, restored.generation);
    var foreign = f.coordinator.settings;
    foreign.authority_revision = 0;
    try t.expectError(error.DnsAuthorityRequired, module.Coordinator.initWithInitial(foreign, "inode-a", &f.owner_ptrs, &f.ignore_owner, initial, &f.cache));
}

test "native coordinator: pure policy preflight matches runtime with and without resolver" {
    var f = try Fixture.init(plain, &.{});
    defer f.deinit();
    try f.bind();
    const programs = [_]*const rules.Program{f.program};
    const planned = try module.generationFromPolicy(f.coordinator.settings, &programs, f.ignore_owner.live, f.cache.generation);
    try t.expectEqualSlices(u8, &f.coordinator.generation, &planned);
    const direct = try module.generation(f.coordinator.settings, &programs, &f.ignore_owner, null);
    const no_resolver = try module.generationFromPolicy(f.coordinator.settings, &programs, f.ignore_owner.live, null);
    try t.expectEqualSlices(u8, &direct, &no_resolver);
    try t.expectError(error.DnsGenerationMismatch, module.generationFromPolicy(f.coordinator.settings, &programs, f.ignore_owner.live, [_]u8{8} ** 32));
}
