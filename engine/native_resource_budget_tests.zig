// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const t = std.testing;
const budget = @import("native_resource_budget.zig");
const files = @import("core/native_file_session.zig");
const durable = @import("core/record_store.zig");
const runtime = @import("native_consumer_runtime.zig");
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
    const journal_snapshot = try @import("core/native_journal_session.zig").RecoverySnapshot.reservation(1);
    try t.expect(journal_component.live.bytes > journal_snapshot.bytes);
    try t.expectEqual(journal_component.live.bytes, journal_component.restore_overlap.bytes);
}

test "native resource budget: maximum journal argv arena coexists with child spawn clone allowance" {
    const transport = @import("core/native_journal_transport.zig");
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
