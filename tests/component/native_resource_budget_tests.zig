// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const t = std.testing;
const budget = @import("engine_test").runtime.native_resource_budget;
const files = @import("engine_test").core.native_file_session;
const durable = @import("engine_test").core.record_store;
const runtime = @import("engine_test").runtime.native_consumer_runtime;
const firewall_observation = @import("engine_test").runtime.native_firewall_observation;
const fd = budget.FdContext{ .soft_limit = 65536, .already_open = 3, .headroom = 32 };
fn samplePlan() !budget.Plan {
    var plan = budget.Plan{};
    try plan.include(try budget.fileCost(.{ .source_capacity = 8, .spec_count = 1, .max_record_bytes = 2048, .max_decoded_bytes = 2048 }));
    try plan.include(budget.storeWorkspace());
    try plan.include(try budget.controlCost(true, 1024 * 1024));
    try plan.include(try budget.configurationCost(1024 * 1024, 16 * budget.mib, 4 * budget.mib));
    try plan.includeDetached(try budget.publicationCost(4096, 65536));
    return plan;
}
test "native resource budget: complete selected plan admits exact limit and refuses one byte or descriptor below" {
    const plan = try samplePlan();
    const ample = try plan.finish(.{}, fd);
    try t.expect(ample.zig_bytes > ample.cost.bytes);
    const exact = budget.Limits{ .zig_bytes = ample.zig_bytes, .descriptors = ample.cost.fds + fd.already_open + fd.headroom };
    const admitted = try plan.finish(exact, fd);
    try t.expectEqual(ample.cost.fds, admitted.descriptor_capacity);
    try t.expectError(error.NativeMemoryAdmission, plan.finish(.{ .zig_bytes = exact.zig_bytes - 1, .descriptors = exact.descriptors }, fd));
    try t.expectError(error.NativeFdAdmission, plan.finish(.{ .zig_bytes = exact.zig_bytes, .descriptors = exact.descriptors - 1 }, fd));
    try t.expectEqual(@as(usize, 64 * budget.mib), ample.sqlite_bytes);
    std.debug.print("selected plan admission charge={d}, requested capacities={d}, fd reservation={d}; excludes C/helper RSS\n", .{ ample.zig_bytes, ample.cost.bytes, ample.cost.fds });
}
test "native resource budget: source consumer and SQL work coexist while same-layer jail work is serialized" {
    var plan = budget.Plan{};
    const initial = plan.live.bytes;
    try plan.include(.{ .workspace = .{ .bytes = 100 }, .workspace_kind = .source });
    try plan.include(.{ .workspace = .{ .bytes = 80 }, .workspace_kind = .source });
    try plan.include(.{ .workspace = .{ .bytes = 300 }, .workspace_kind = .consumer });
    try plan.include(.{ .workspace = .{ .bytes = 500 }, .workspace_kind = .storage });
    const result = try plan.finish(.{}, fd);
    try t.expectEqual(initial + 900, result.cost.bytes);
}
test "native resource budget: firewall observation accounts retained and transient objects with allocator overhead" {
    const cost = try budget.firewallObservationCost(firewall_observation.Cache, firewall_observation.Page);
    try t.expectEqual(@sizeOf(firewall_observation.Cache) + @sizeOf(firewall_observation.Page), cost.bytes);
    try t.expectEqual(@as(usize, 2), cost.allocations);
    try t.expectEqual(cost.bytes + cost.bytes / 4 + 2 * budget.allocation_allowance, try cost.chargedBytes());
    try t.expectError(error.InvalidResourceLimit, budget.firewallObservationCost(struct { bytes: [50 * 1024 + 1]u8 }, firewall_observation.Page));
    try t.expectError(error.InvalidResourceLimit, budget.firewallObservationCost(firewall_observation.Cache, struct { bytes: [50 * 1024 + 1]u8 }));
    std.debug.print("firewall observation cache={d}, page={d}, admitted={d}, charged={d}\n", .{ @sizeOf(firewall_observation.Cache), @sizeOf(firewall_observation.Page), cost.bytes, try cost.chargedBytes() });
}
test "native resource budget: optional observation refusal preserves the admitted baseline" {
    var plan = budget.Plan{};
    try plan.includeDetached(.{ .bytes = 4096, .allocations = 1 });
    const baseline = try plan.finish(.{}, fd);
    const optional = try budget.firewallObservationCost(firewall_observation.Cache, firewall_observation.Page);
    const exact = try budget.finishWithOptional(plan, optional, .{}, fd);
    try t.expect(exact.admitted);
    try t.expectEqual(try (try baseline.cost.plus(optional)).chargedBytes(), exact.requirements.zig_bytes);

    const refused = try budget.finishWithOptional(plan, optional, .{ .zig_bytes = baseline.zig_bytes, .descriptors = 2048 }, fd);
    try t.expect(!refused.admitted);
    try t.expectEqualDeep(baseline, refused.requirements);

    try t.expectError(error.NativeMemoryAdmission, budget.finishWithOptional(plan, optional, .{ .zig_bytes = baseline.zig_bytes - 1, .descriptors = 2048 }, fd));
}
test "native resource budget: overflow and malformed configured capacities refuse without changing plan" {
    var plan = budget.Plan{};
    const original = plan.live;
    try t.expectError(error.ResourceOverflow, plan.include(.{ .live = .{ .bytes = std.math.maxInt(usize) } }));
    try t.expectEqualDeep(original, plan.live);
    try t.expectError(error.ResourceOverflow, (budget.Cost{ .bytes = std.math.maxInt(usize) }).chargedBytes());
    try t.expectError(error.InvalidResourceLimit, budget.fileCost(.{ .source_capacity = 0, .spec_count = 1, .max_record_bytes = 2048, .max_decoded_bytes = 2048 }));
    try t.expectError(error.InvalidResourceLimit, budget.journalCost(.{ .max_record_bytes = 65537, .max_decoded_bytes = 2048, .batch_records = 1, .environment = .{ .entries = 0, .bytes = 0 } }));
    try t.expectError(error.InvalidResourceLimit, budget.configurationCost(0, 33 * budget.mib, 0));
    try t.expectError(error.InvalidResourceLimit, budget.programCost(1025));
    try t.expectError(error.InvalidResourceLimit, budget.timezoneCost(129));
}
test "native resource budget: OS soft descriptor limit and existing holdings constrain configured ceiling" {
    try t.expectEqual(@as(usize, 65), try (budget.FdContext{ .soft_limit = 100, .already_open = 3, .headroom = 32 }).available(2048));
    try t.expectError(error.NativeFdAdmission, (budget.FdContext{ .soft_limit = 35, .already_open = 3, .headroom = 32 }).available(2048));
    const current = try budget.FdContext.observe(2048, 16);
    try t.expect(current.already_open >= 3);
    try t.expect(try current.available(2048) <= 2032);
}
test "native resource budget: inherited environment and helper argv have bounded aggregate admission" {
    const values = [_][*:0]const u8{ "PATH=/usr/bin", "LANG=C" };
    const measured = try budget.measureEnvironment(&values);
    try t.expectEqual(@as(usize, 2), measured.entries);
    try t.expectEqual(@as(usize, 21), measured.bytes);
    const spawn = try measured.spawnCost(8, 1024);
    try t.expect(spawn.bytes > 3 * 1024);
    try t.expectEqual(@as(usize, 7), spawn.fds);
    const too_many = [_][*:0]const u8{"A=B"} ** 257;
    try t.expectError(error.EnvironmentLimit, budget.measureEnvironment(&too_many));
    var long: [16385:0]u8 = [_:0]u8{'x'} ** 16385;
    try t.expectError(error.EnvironmentLimit, budget.measureEnvironment(&[_][*:0]const u8{&long}));
    const per = [_:0]u8{'x'} ** 16000;
    try t.expectError(error.EnvironmentLimit, budget.measureEnvironment(&[_][*:0]const u8{ &per, &per, &per, &per, &per }));
    try t.expectError(error.EnvironmentLimit, measured.spawnCost(257, 1));
    _ = try budget.currentEnvironment();
}
test "native resource budget: authoritative consumer and effect envelopes include restore and helper memory" {
    const clock = struct {
        fn us(_: ?*anyopaque) !i64 {
            return 1;
        }
        fn ms(_: ?*anyopaque) u64 {
            return 1;
        }
    };
    const options = runtime.DnsOptions{ .generation = [_]u8{1} ** 32, .capacity = 8, .max_sources = 8, .max_owned_bytes = 16 * budget.mib, .clock = .{ .context = null, .read_us = clock.us, .read_ms = clock.ms } };
    const authoritative = try runtime.DnsRuntime.allocationPlan(options);
    const component = try budget.consumerCost(authoritative, 32);
    try t.expectEqual(try runtime.DnsRuntime.requiredBytes(options), component.live.bytes + component.workspace.bytes);
    try t.expectEqual(component.live.bytes, component.restore_overlap.bytes);
    const effects = try budget.effectCost(.{ .entries = 2, .bytes = 32 });
    try t.expect(effects.workspace.bytes > 16 * budget.mib);
    try t.expectEqual(@as(usize, 7), effects.workspace.fds);
    try t.expectEqual(effects.live.bytes, effects.restore_overlap.bytes);
}
test "native resource budget: active leases refuse exhaustion without evicting protected owners" {
    var plan = budget.Plan{};
    const cost = budget.Cost{ .bytes = 1024, .allocations = 1, .fds = 2 };
    try plan.include(.{ .live = cost });
    const requirements = try plan.finish(.{}, fd);
    var ledger = budget.Ledger.init(requirements);
    const owner = try ledger.reserve(.effect, cost);
    const protected = ledger.snapshot();
    try t.expectError(error.NativeFdAdmission, ledger.reserve(.source, .{ .fds = 1 }));
    try t.expectError(error.NativeMemoryAdmission, ledger.reserve(.workspace, .{ .bytes = requirements.zig_bytes }));
    try t.expectEqualDeep(protected, ledger.snapshot());
    try ledger.release(owner);
    const replacement = try ledger.reserve(.effect, cost);
    try t.expectError(error.StaleReservation, ledger.release(owner));
    try t.expectEqual(protected.used_bytes, ledger.snapshot().used_bytes);
    try ledger.release(replacement);
    try t.expectEqual(@as(usize, 0), ledger.snapshot().used_bytes);
    try t.expectEqual(protected.peak_bytes, ledger.snapshot().peak_bytes);
    try t.expectError(error.StaleReservation, ledger.release(replacement));
}
test "native resource budget: finite reservation registry never reuses active or exhausted tokens" {
    var plan = budget.Plan{};
    try plan.include(.{ .live = .{ .bytes = budget.max_reservations * 128 } });
    var ledger = budget.Ledger.init(try plan.finish(.{}, fd));
    var tokens: [budget.max_reservations]budget.Token = undefined;
    for (&tokens) |*token| token.* = try ledger.reserve(.other, .{});
    try t.expectError(error.ResourceReservationLimit, ledger.reserve(.other, .{}));
    for (tokens) |token| try ledger.release(token);
    ledger.slots[0].serial = std.math.maxInt(u64);
    const next = try ledger.reserve(.source, .{});
    try t.expectEqual(@as(u16, 1), next.slot);
    try ledger.release(next);
}
const Counting = struct {
    parent: std.mem.Allocator,
    current: usize = 0,
    peak: usize = 0,
    fn allocator(self: *Counting) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn changed(self: *Counting, before: usize, after: usize) void {
        self.current = self.current - before + after;
        self.peak = @max(self.peak, self.current);
    }
    fn alloc(ctx: *anyopaque, n: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *Counting = @ptrCast(@alignCast(ctx));
        const result = self.parent.rawAlloc(n, alignment, ra) orelse return null;
        self.changed(0, n);
        return result;
    }
    fn resize(ctx: *anyopaque, mem: []u8, alignment: std.mem.Alignment, n: usize, ra: usize) bool {
        const self: *Counting = @ptrCast(@alignCast(ctx));
        if (!self.parent.rawResize(mem, alignment, n, ra)) return false;
        self.changed(mem.len, n);
        return true;
    }
    fn remap(ctx: *anyopaque, mem: []u8, alignment: std.mem.Alignment, n: usize, ra: usize) ?[*]u8 {
        const self: *Counting = @ptrCast(@alignCast(ctx));
        const result = self.parent.rawRemap(mem, alignment, n, ra) orelse return null;
        self.changed(mem.len, n);
        return result;
    }
    fn free(ctx: *anyopaque, mem: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *Counting = @ptrCast(@alignCast(ctx));
        self.parent.rawFree(mem, alignment, ra);
        self.changed(mem.len, 0);
    }
};
test "native resource budget: selected real file owners and recovery overlap fit measured requested-capacity envelope" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(t.allocator, ".");
    defer t.allocator.free(root);
    const dbpath = try std.fs.path.join(t.allocator, &.{ root, "state.sqlite" });
    defer t.allocator.free(dbpath);
    const pattern = try std.fs.path.join(t.allocator, &.{ root, "*.log" });
    defer t.allocator.free(pattern);
    for (0..4) |i| {
        var name: [32]u8 = undefined;
        try tmp.dir.writeFile(.{ .sub_path = try std.fmt.bufPrint(&name, "fixture-{d}.log", .{i}), .data = "ordinary event\n" });
    }
    var store = try durable.Store.open(t.allocator, dbpath);
    defer store.close();
    try store.enableReceipts(4);
    try store.enableNativeTime();
    var observed = Counting{ .parent = t.allocator };
    const options = files.Options{ .processing = .{ .jail = "fixture", .parent_generation = [_]u8{1} ** 32, .timestamp = .undated, .max_record_bytes = 2048, .max_decoded_bytes = 2048 }, .max_sources = 4 };
    const component = try budget.fileCost(.{ .source_capacity = 4, .spec_count = 1, .max_record_bytes = 2048, .max_decoded_bytes = 2048 });
    {
        const old = try files.Session.createDeferred(observed.allocator(), &store, options, &.{.{ .pattern = pattern }});
        defer old.destroy();
        for (0..128) |_| if (try old.admissionTurn()) break;
        try t.expectEqual(@as(usize, 4), old.sources.sources.items.len);
        try t.expect(observed.current <= component.live.bytes);
        const replacement = try files.Session.createDeferred(observed.allocator(), &store, options, &.{.{ .pattern = pattern }});
        defer replacement.destroy();
        try replacement.copyRepairStateFrom(old);
        try replacement.retainSourcesFrom(old);
        for (0..128) |_| if (try replacement.admissionTurn()) break;
        _ = try replacement.pollTurn(1);
        const envelope = try (try component.live.plus(component.restore_overlap)).plus(component.workspace);
        try t.expect(observed.peak <= envelope.bytes);
        std.debug.print("selected four-source allocation peak={d}, reserved requested capacities={d}; excludes SQLite/C and allocator RSS\n", .{ observed.peak, envelope.bytes });
    }
    try t.expectEqual(@as(usize, 0), observed.current);
}

test "native resource budget: a reservation from another ledger cannot release the same numbered slot" {
    const requirements = try (budget.Plan{}).finish(.{}, fd);
    var first = budget.Ledger.init(requirements);
    var second = budget.Ledger.init(requirements);
    const old = try first.reserve(.source, .{});
    const current = try second.reserve(.source, .{});
    try t.expectEqual(old.slot, current.slot);
    try t.expectEqual(old.serial, current.serial);
    try t.expectError(error.StaleReservation, second.release(old));
    try second.release(current);
    try first.release(old);
}

test "native resource budget: old and replacement recovery snapshots are included without relying on session lifetime" {
    const component = try budget.fileCost(.{ .source_capacity = 8, .spec_count = 1, .max_record_bytes = 2048, .max_decoded_bytes = 2048 });
    const snapshot = try files.RecoverySnapshot.reservation(8);
    try t.expect(component.live.bytes > snapshot.bytes);
    try t.expect(component.restore_overlap.bytes > snapshot.bytes);
    try t.expect(component.live.fds >= 8 + snapshot.descriptors);
    const journal_component = try budget.journalCost(.{ .max_record_bytes = 2048, .max_decoded_bytes = 2048, .batch_records = 1, .environment = .{ .entries = 0, .bytes = 0 } });
    const journal_snapshot = try @import("engine_test").core.native_journal_session.RecoverySnapshot.reservation(1);
    try t.expect(journal_component.live.bytes > journal_snapshot.bytes);
    try t.expectEqual(journal_component.live.bytes, journal_component.restore_overlap.bytes);
}

test "native resource budget: maximum journal argv arena coexists with child spawn clone allowance" {
    const transport = @import("engine_test").core.native_journal_transport;
    var path: [4096]u8 = [_]u8{'x'} ** 4096;
    path[0] = '/';
    var selector: [4096]u8 = [_]u8{'v'} ** 4096;
    @memcpy(selector[0..8], "MESSAGE=");
    const paths = [_][]const u8{&path} ** 64;
    const matches = [_][]const u8{&selector} ** 64;
    var observed = Counting{ .parent = t.allocator };
    {
        var arena = std.heap.ArenaAllocator.init(observed.allocator());
        defer arena.deinit();
        const args = try transport.argv(arena.allocator(), .{ .target = .{ .files = &paths }, .matches = &matches, .batch_records = 1 }, .{ .cursor = "original-anchor" }, 2);
        var bytes: usize = 0;
        for (args) |arg| bytes += arg.len + 1;
        try t.expect(bytes > 512 * 1024);
        const child = try (budget.Environment{ .entries = 256, .bytes = 64 * 1024 }).spawnCost(args.len, bytes);
        const component = try budget.journalCost(.{ .max_record_bytes = 2048, .max_decoded_bytes = 2048, .batch_records = 1, .environment = .{ .entries = 256, .bytes = 64 * 1024 } });
        try t.expect(component.workspace.bytes >= observed.peak + child.bytes);
    }
    try t.expectEqual(@as(usize, 0), observed.current);
}

// Refuse allocator growth in place so arena/ArrayList replacement buffers are
// charged simultaneously; a roomy backing allocator must not hide their peak.
const QueryPeakAllocator = struct {
    live: usize = 0,
    peak: usize = 0,

    fn allocator(self: *QueryPeakAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(context: *anyopaque, len: usize, alignment: std.mem.Alignment, return_address: usize) ?[*]u8 {
        const self: *QueryPeakAllocator = @ptrCast(@alignCast(context));
        const memory = t.allocator.rawAlloc(len, alignment, return_address) orelse return null;
        self.live += len;
        self.peak = @max(self.peak, self.live);
        return memory;
    }
    fn resize(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) bool {
        return false;
    }
    fn remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }
    fn free(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, return_address: usize) void {
        const self: *QueryPeakAllocator = @ptrCast(@alignCast(context));
        self.live -= memory.len;
        t.allocator.rawFree(memory, alignment, return_address);
    }
};

test "native resource budget: exact aggregate scope projection and real query fit control scratch without in-place growth" {
    const query = @import("engine_test").net.query_v1;
    const effect = @import("engine_test").core.native_effect;
    const scope = @import("engine_test").firewall.scope;
    const shared = @import("shared");
    const jail_count = 64;
    // Conservative aggregate bound: all owner slots plus all detection slots,
    // even though mixed jail configurations cannot fill both simultaneously.
    const row_count = effect.max_owners + 4096;
    var measured = QueryPeakAllocator{};
    {
        const a = measured.allocator();
        var metadata = std.heap.ArenaAllocator.init(a);
        defer metadata.deinit();
        const arena = metadata.allocator();
        var body: [shared.protocol.max_request_body]u8 = undefined;
        @memset(&body, ' ');
        const request = "{\"schema_version\":1,\"kind\":\"scopes\",\"limit\":256}";
        @memcpy(body[0..request.len], request);
        try t.expectEqual(query.Kind.scopes, query.requestedKind(arena, &body).?);
        _ = try arena.alloc(query.JailConfig, jail_count);
        const jails = try arena.alloc(query.JailScopes, jail_count);
        // Match queryResponse's single exact owner, separate from its arena.
        const rows = try a.alloc(query.ScopeItem, row_count);
        defer a.free(rows);
        var ports: [scope.max_port_ranges]scope.PortRange = undefined;
        for (&ports, 0..) |*port, index| port.* = scope.PortRange.one(@intCast(65000 + index * 2));
        const projected = try query.projectScope(.{
            .subject = try scope.Subject.parseHost("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            .protocols = try scope.Protocols.list(&.{ .tcp, .udp }),
            .ports = try scope.Ports.list(&ports),
        });
        for (rows) |*row| row.* = .{
            .scope = projected,
            .lease = .finite,
            .deadline_us = std.math.maxInt(i64),
            .decision_id = [_]u8{0xff} ** 32,
            .confirmed = true,
        };
        // Maximum escaped name width is conservative for the JSON producer.
        const name = [_]u8{1} ** query.max_jail_bytes;
        for (jails, 0..) |*jail, index| {
            const start = index * row_count / jail_count;
            const end = (index + 1) * row_count / jail_count;
            jail.* = .{ .name = &name, .items = rows[start..end] };
        }
        const projection_bytes = measured.live;
        const result = try query.handle(a, &body, .monitor, [_]u8{0xff} ** 32, .{ .scopes = .{ .jails = jails } });
        defer result.deinit(a);
        try t.expect(result == .payload);
        // Reserve three full response ceilings beyond the measured projection:
        // more than ArrayList's <1.5x growth plus toOwnedSlice's 1x overlap,
        // with the remainder covering the small valid request parser workspace.
        try t.expect(projection_bytes + 3 * query.max_response_bytes <= 8 * budget.mib);
        try t.expect(measured.peak <= 8 * budget.mib);
        const parsed = try std.json.parseFromSlice(std.json.Value, t.allocator, result.payload, .{});
        defer parsed.deinit();
        try t.expectEqual(@as(usize, 256), parsed.value.object.get("items").?.array.items.len);
        std.debug.print("exact scope projection rows={d} bytes={d}, query peak={d}, response={d}, control scratch={d}\n", .{ row_count, projection_bytes, measured.peak, result.payload.len, 8 * budget.mib });
    }
    try t.expectEqual(@as(usize, 0), measured.live);
}
