// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const store = @import("core/record_store.zig");
const file = @import("core/durable_file_source.zig");
const file_session = @import("core/native_file_session.zig");
const journal = @import("core/native_journal_transport.zig");
const journal_session = @import("core/native_journal_session.zig");
const repair = @import("core/source_repair.zig");
const consumer = @import("core/native_consumer.zig");
const runtime = @import("native_consumer_runtime.zig");
const effect = @import("core/native_effect.zig");
const effect_runtime = @import("native_effect_runtime.zig");
const inspection = @import("firewall/inspection.zig");
const timezone = @import("core/native_timezone.zig");
const rules = @import("core/native_rules.zig");
const ipc = @import("net/ipc.zig");
const http = @import("net/http.zig");
const shared = @import("shared");
pub const mib = 1024 * 1024;
pub const sqlite_heap_bytes = 64 * mib;
pub const sqlite_page_bytes = 256 * mib;
pub const sqlite_advisory_cache_bytes = 2 * mib;
pub const wal_trigger_bytes = 16 * mib;
pub const allocation_allowance = 64;
pub const max_reservations = 512;
pub const firewall_observation_object_bytes = 50 * 1024;
pub const Error = error{ ResourceOverflow, InvalidResourceLimit, NativeMemoryAdmission, NativeFdAdmission, ResourceReservationLimit, StaleReservation, EnvironmentLimit };
fn add(a: usize, b: usize) Error!usize {
    return std.math.add(usize, a, b) catch error.ResourceOverflow;
}
fn mul(a: usize, b: usize) Error!usize {
    return std.math.mul(usize, a, b) catch error.ResourceOverflow;
}
fn capacity(count: usize) Error!usize {
    return if (count == 0) 0 else add(try mul(count, 2), 8);
}
pub const Cost = struct {
    bytes: usize = 0,
    allocations: usize = 0,
    fds: usize = 0,
    pub fn plus(a: Cost, b: Cost) Error!Cost {
        return .{ .bytes = try add(a.bytes, b.bytes), .allocations = try add(a.allocations, b.allocations), .fds = try add(a.fds, b.fds) };
    }
    pub fn times(self: Cost, count: usize) Error!Cost {
        return .{ .bytes = try mul(self.bytes, count), .allocations = try mul(self.allocations, count), .fds = try mul(self.fds, count) };
    }
    pub fn maximum(a: Cost, b: Cost) Cost {
        return .{ .bytes = @max(a.bytes, b.bytes), .allocations = @max(a.allocations, b.allocations), .fds = @max(a.fds, b.fds) };
    }
    pub fn chargedBytes(self: Cost) Error!usize {
        return add(try add(self.bytes, self.bytes / 4), try mul(self.allocations, allocation_allowance));
    }
};
pub const Workspace = enum { source, consumer, storage, effect, configuration, other };
pub const Component = struct { live: Cost = .{}, restore_overlap: Cost = .{}, workspace: Cost = .{}, workspace_kind: Workspace = .other };
pub const Limits = struct {
    zig_bytes: usize = 256 * mib,
    descriptors: usize = 2048,
    pub fn validate(self: Limits) Error!void {
        if (self.zig_bytes == 0 or self.descriptors == 0) return error.InvalidResourceLimit;
    }
};
pub const FdContext = struct {
    soft_limit: usize,
    already_open: usize,
    headroom: usize = 32,
    pub fn available(self: FdContext, configured: usize) Error!usize {
        const unavailable = try add(self.already_open, self.headroom);
        if (configured == 0 or unavailable >= self.soft_limit or unavailable >= configured) return error.NativeFdAdmission;
        return @min(self.soft_limit, configured) - unavailable;
    }
    pub fn observe(configured: usize, headroom: usize) !FdContext {
        if (configured == 0) return error.InvalidResourceLimit;
        const limits = try std.posix.getrlimit(.NOFILE);
        const soft = std.math.cast(usize, limits.cur) orelse std.math.maxInt(usize);
        var directory = try std.fs.openDirAbsolute("/proc/self/fd", .{ .iterate = true });
        defer directory.close();
        var iterator = directory.iterate();
        var count: usize = 0;
        while (try iterator.next()) |entry| {
            const fd = std.fmt.parseInt(std.posix.fd_t, entry.name, 10) catch return error.NativeFdAdmission;
            if (fd == directory.fd) continue;
            count = try add(count, 1);
            if (count >= configured or count >= 65536) return error.NativeFdAdmission;
        }
        const result = FdContext{ .soft_limit = soft, .already_open = count, .headroom = headroom };
        _ = try result.available(configured);
        return result;
    }
};
pub const Environment = struct {
    entries: usize,
    bytes: usize,
    pub fn spawnCost(self: Environment, argv_entries: usize, argv_bytes: usize) Error!Cost {
        if (self.entries > 256 or self.bytes > 64 * 1024 or argv_entries > 256 or argv_bytes > 1024 * 1024) return error.EnvironmentLimit;
        const pointers = try mul(try add(try add(self.entries, argv_entries), 2), @sizeOf(?[*:0]u8));
        return .{ .bytes = try mul(try add(try add(self.bytes, argv_bytes), pointers), 3), .allocations = try add(try add(self.entries, argv_entries), 8), .fds = 7 };
    }
};
pub fn measureEnvironment(values: anytype) Error!Environment {
    if (values.len > 256) return error.EnvironmentLimit;
    var bytes: usize = 0;
    for (values) |pointer| {
        var length: usize = 0;
        while (length < 16 * 1024 and pointer[length] != 0) : (length += 1) {}
        if (length == 16 * 1024) return error.EnvironmentLimit;
        bytes = try add(bytes, length + 1);
        if (bytes > 64 * 1024) return error.EnvironmentLimit;
    }
    return .{ .entries = values.len, .bytes = bytes };
}
pub fn currentEnvironment() Error!Environment {
    if (@import("builtin").link_libc) {
        var values: [256][*:0]const u8 = undefined;
        var count: usize = 0;
        while (std.c.environ[count]) |value| {
            if (count == values.len) return error.EnvironmentLimit;
            values[count] = value;
            count += 1;
        }
        return measureEnvironment(values[0..count]);
    }
    return measureEnvironment(std.os.environ);
}

pub const Plan = struct {
    live: Cost = .{ .bytes = @sizeOf(Ledger), .allocations = 1 },
    restore_overlap: Cost = .{},
    workspaces: [6]Cost = [_]Cost{.{}} ** 6,
    detached: Cost = .{},
    helper_os_allowance_bytes: usize = 0,
    pub fn include(self: *Plan, component: Component) Error!void {
        const live = try self.live.plus(component.live);
        const overlap = try self.restore_overlap.plus(component.restore_overlap);
        self.live = live;
        self.restore_overlap = overlap;
        const index = @intFromEnum(component.workspace_kind);
        self.workspaces[index] = self.workspaces[index].maximum(component.workspace);
    }
    pub fn includeDetached(self: *Plan, cost: Cost) Error!void {
        self.detached = try self.detached.plus(cost);
    }
    pub fn finish(self: Plan, limits: Limits, fd: FdContext) Error!Requirements {
        try limits.validate();
        var workspace: Cost = .{};
        for (self.workspaces) |cost| workspace = try workspace.plus(cost);
        const total = try (try (try self.live.plus(self.restore_overlap)).plus(workspace)).plus(self.detached);
        const charged = try total.chargedBytes();
        if (charged > limits.zig_bytes) return error.NativeMemoryAdmission;
        const available = try fd.available(limits.descriptors);
        if (total.fds > available) return error.NativeFdAdmission;
        return .{ .cost = total, .zig_bytes = charged, .allocator_allowance_bytes = charged - total.bytes, .descriptor_capacity = available, .sqlite_bytes = sqlite_heap_bytes, .helper_os_allowance_bytes = self.helper_os_allowance_bytes };
    }
};
pub const Requirements = struct { cost: Cost, zig_bytes: usize, allocator_allowance_bytes: usize, descriptor_capacity: usize, sqlite_bytes: usize, helper_os_allowance_bytes: usize };

pub const OptionalRequirements = struct {
    requirements: Requirements,
    admitted: bool,
};

pub fn firewallObservationCost(comptime Cache: type, comptime Page: type) Error!Cost {
    if (@sizeOf(Cache) > firewall_observation_object_bytes or @sizeOf(Page) > firewall_observation_object_bytes)
        return error.InvalidResourceLimit;
    return .{ .bytes = try add(@sizeOf(Cache), @sizeOf(Page)), .allocations = 2 };
}

pub fn finishWithOptional(base: Plan, optional: Cost, limits: Limits, fd: FdContext) Error!OptionalRequirements {
    const baseline = try base.finish(limits, fd);
    var expanded = base;
    expanded.includeDetached(optional) catch |err| return switch (err) {
        error.ResourceOverflow => .{ .requirements = baseline, .admitted = false },
        else => err,
    };
    const admitted = expanded.finish(limits, fd) catch |err| return switch (err) {
        error.NativeMemoryAdmission, error.NativeFdAdmission, error.ResourceOverflow => .{ .requirements = baseline, .admitted = false },
        else => err,
    };
    return .{ .requirements = admitted, .admitted = true };
}

pub const FileOptions = struct { source_capacity: usize, spec_count: usize, max_record_bytes: usize, max_decoded_bytes: usize };
pub fn fileCost(options: FileOptions) !Component {
    if (options.source_capacity == 0 or options.source_capacity > store.Limits.pending_receipts or options.spec_count == 0 or options.spec_count > options.source_capacity or options.max_record_bytes == 0 or options.max_record_bytes > @import("core/source_text.zig").max_record_bytes or options.max_decoded_bytes == 0 or options.max_decoded_bytes > @import("core/source_text.zig").max_record_bytes) return error.InvalidResourceLimit;
    const Retained = std.meta.Child(@TypeOf(@as(file_session.Session, undefined).retained.items));
    const Spec = std.meta.Child(@TypeOf(@as(file.FileSet, undefined).specs.items));
    const pending_bytes = 64 + store.Limits.source_bytes * 2 + store.Limits.cursor_bytes;
    const arrays = try add(try mul(try capacity(options.source_capacity), @sizeOf(file.FileSource) + @sizeOf(Retained)), try mul(options.source_capacity, @sizeOf(repair.Repair) + @sizeOf(?store.Store.PendingSource)));
    const per_source = 4 * store.Limits.source_bytes + pending_bytes;
    const specs = try add(try mul(try capacity(options.spec_count), @sizeOf(Spec)), try mul(options.spec_count, store.Limits.source_bytes));
    const discovery = try add(file.discovery_max_depth * store.Limits.source_bytes, try add(try mul(options.source_capacity, store.Limits.source_bytes), try mul(try capacity(options.source_capacity), @sizeOf([]u8))));
    const live = Cost{ .bytes = try add(try add(@sizeOf(file_session.Session) + 64, options.max_decoded_bytes), try add(try add(arrays, specs), try add(discovery, try mul(options.source_capacity, per_source)))), .allocations = try add(32, try mul(options.source_capacity, 16)), .fds = try add(try mul(options.source_capacity, 2), file.discovery_max_depth) };
    const overlap = try live.plus(.{ .fds = try add(options.source_capacity, 1) });
    const workspace = Cost{ .bytes = try add(try mul(options.max_record_bytes, 4), pending_bytes + store.Limits.cursor_bytes * 2), .allocations = 32 };
    const snapshot = try file_session.RecoverySnapshot.reservation(options.source_capacity);
    const snapshot_cost = Cost{ .bytes = snapshot.bytes, .allocations = snapshot.allocations, .fds = snapshot.descriptors };
    return .{ .live = try live.plus(snapshot_cost), .restore_overlap = try overlap.plus(snapshot_cost), .workspace = workspace, .workspace_kind = .source };
}
pub const JournalOptions = struct { max_record_bytes: usize, max_decoded_bytes: usize, batch_records: usize, environment: Environment };
pub fn journalCost(options: JournalOptions) !Component {
    if (options.max_record_bytes == 0 or options.max_record_bytes > journal.max_line_bytes or options.max_decoded_bytes == 0 or options.max_decoded_bytes > journal.max_line_bytes or options.batch_records == 0 or options.batch_records > 128) return error.InvalidResourceLimit;
    const output = try mul(try add(options.batch_records, 1), journal.max_line_bytes + 1);
    const pending_bytes = 64 + store.Limits.source_bytes * 2 + store.Limits.cursor_bytes;
    const live = Cost{ .bytes = try add(@sizeOf(journal_session.Session) + journal.parse_bytes + pending_bytes, try add(options.max_decoded_bytes, output)), .allocations = 9 };
    const maximum_argv_bytes = 160 * 4160;
    const spawn = try options.environment.spawnCost(160, maximum_argv_bytes);
    const query_argv = Cost{ .bytes = 3 * (maximum_argv_bytes + 160 * @sizeOf([]const u8)), .allocations = 168 };
    const snapshot = try journal_session.RecoverySnapshot.reservation(1);
    const combined = try live.plus(.{ .bytes = snapshot.bytes, .allocations = snapshot.allocations, .fds = snapshot.descriptors });
    return .{ .live = combined, .restore_overlap = combined, .workspace = try (try spawn.plus(query_argv)).plus(.{ .bytes = pending_bytes + 65536, .allocations = 16 }), .workspace_kind = .source };
}
pub fn consumerCost(plan: runtime.AllocationPlan, allocation_count: usize) Error!Component {
    const live = Cost{ .bytes = try add(try add(plan.fixed_live_bytes, try mul(plan.per_source_live_bytes, plan.source_capacity)), plan.capacity_live_bytes), .allocations = allocation_count };
    return .{ .live = live, .restore_overlap = live, .workspace = .{ .bytes = plan.workspace_bytes, .allocations = 64 }, .workspace_kind = .consumer };
}
pub fn dnsCost(options: runtime.DnsOptions) !Component {
    var result = try consumerCost(try runtime.DnsRuntime.allocationPlan(options), try add(16, try mul(options.capacity, 4)));
    result.live.fds = @intFromBool(options.server != null);
    result.restore_overlap.fds = result.live.fds;
    return result;
}
pub fn jailConsumerCost(options: runtime.JailOptions) !Component {
    return consumerCost(try runtime.JailRuntime.allocationPlan(options), try add(64, try mul(options.max_sources, try add(8, try mul(options.programs.len, 2)))));
}
pub fn programCost(count: usize) Error!Component {
    if (count > 128 * 8) return error.InvalidResourceLimit;
    const live = Cost{ .bytes = try mul(count, @sizeOf(rules.Program)), .allocations = count };
    return .{ .live = live, .restore_overlap = live };
}
pub fn timezoneCost(count: usize) Error!Component {
    if (count > 128) return error.InvalidResourceLimit;
    const bytes = @sizeOf(timezone.Zone) + 255 + timezone.max_transitions * @sizeOf(timezone.Transition) + timezone.max_types * @sizeOf(timezone.TimeType);
    const live = try (Cost{ .bytes = bytes, .allocations = 4 }).times(count);
    return .{ .live = live, .restore_overlap = live, .workspace = if (count == 0) .{} else .{ .bytes = timezone.max_file_bytes, .allocations = 1, .fds = 2 }, .workspace_kind = .configuration };
}
pub fn configurationCost(retained_capacity: usize, prepared_arena: usize, projection_arena: usize) Error!Component {
    if (prepared_arena > 32 * mib or projection_arena > 4 * mib) return error.InvalidResourceLimit;
    const live = Cost{ .bytes = try add(retained_capacity, try add(prepared_arena, projection_arena)), .allocations = 8 };
    return .{ .live = live, .restore_overlap = live };
}
pub fn storeWorkspace() Component {
    return .{ .live = .{ .fds = 4 }, .workspace = .{ .bytes = store.Limits.checkpoint_bytes + store.Limits.shared_bytes + consumer.max_prepared_bytes + store.Limits.sqlite_row_bytes, .allocations = 128 }, .workspace_kind = .storage };
}
pub fn effectCost(environment: Environment) Error!Component {
    const limits = inspection.Limits{};
    const live = Cost{ .bytes = @sizeOf(effect_runtime.Manager) + effect.max_effects * (2 * @sizeOf(effect.Entry) + @sizeOf(bool)), .allocations = 4 };
    const vector = try mul(try mul(try add(limits.max_messages, 8), 3), @sizeOf([]u8));
    const spawn = try environment.spawnCost(64, 8192);
    const work = try spawn.plus(.{ .bytes = try add(limits.max_bytes, vector), .allocations = try add(limits.max_messages, 64) });
    return .{ .live = live, .restore_overlap = live, .workspace = work, .workspace_kind = .effect };
}
pub fn publicationCost(subjects: usize, coordinator_capacity: usize) Error!Cost {
    if (subjects > 4096) return error.InvalidResourceLimit;
    return .{ .bytes = try add(coordinator_capacity, try mul(subjects, 2 * (@sizeOf(store.Store.ActiveDecision) + @sizeOf(bool)))), .allocations = 4 * 128 };
}
pub fn controlCost(metrics: bool, response_capacity: usize) Error!Component {
    if (response_capacity == 0 or response_capacity > 2 * shared.protocol.max_payload_size) return error.InvalidResourceLimit;
    const EventLoop = @import("core/event_loop.zig").EventLoop;
    const Map = @TypeOf(@as(EventLoop, undefined).registrations);
    const registrations = ipc.max_clients + (if (metrics) http.max_clients else @as(usize, 0)) + 8;
    const loop_bytes = @sizeOf(EventLoop) + (4 * registrations + 16) * (@sizeOf(Map.KV) + 2);
    var live = Cost{ .bytes = loop_bytes + @sizeOf(ipc.IpcServer) + ipc.max_clients * (ipc.client_buffer_size + ipc.max_response_bytes), .allocations = 2 + 2 * ipc.max_clients, .fds = ipc.max_clients + 2 + 8 };
    if (metrics) {
        const Client = @typeInfo(@typeInfo(@TypeOf(@as(http.HttpServer, undefined).clients[0])).optional.child).pointer.child;
        live = try live.plus(.{ .bytes = @sizeOf(http.HttpServer) + http.max_clients * @sizeOf(Client), .allocations = http.max_clients + 1, .fds = http.max_clients + 1 });
    }
    return .{ .live = try live.plus(.{ .bytes = try mul(response_capacity, 4), .allocations = 64 }) };
}

pub const Category = enum { configuration, source, consumer, effect, control, detached, workspace, other };
pub const Token = struct { owner: *const Ledger, slot: u16, serial: u64 };
const Slot = struct { serial: u64 = 0, active: bool = false, category: Category = .other, cost: Cost = .{} };
pub const Ledger = struct {
    mutex: std.Thread.Mutex = .{},
    slots: [max_reservations]Slot = [_]Slot{.{}} ** max_reservations,
    limit_bytes: usize,
    limit_fds: usize,
    used_bytes: usize = 0,
    used_fds: usize = 0,
    peak_bytes: usize = 0,
    peak_fds: usize = 0,
    pub fn init(requirements: Requirements) Ledger {
        return .{ .limit_bytes = requirements.zig_bytes, .limit_fds = requirements.cost.fds };
    }
    pub fn reserve(self: *Ledger, category: Category, cost: Cost) Error!Token {
        self.mutex.lock();
        defer self.mutex.unlock();
        const bytes = try cost.chargedBytes();
        const next_bytes = try add(self.used_bytes, bytes);
        const next_fds = try add(self.used_fds, cost.fds);
        if (next_bytes > self.limit_bytes) return error.NativeMemoryAdmission;
        if (next_fds > self.limit_fds) return error.NativeFdAdmission;
        for (&self.slots, 0..) |*slot, index| if (!slot.active and slot.serial != std.math.maxInt(u64)) {
            const serial = slot.serial + 1;
            slot.* = .{ .serial = serial, .active = true, .category = category, .cost = cost };
            self.used_bytes = next_bytes;
            self.used_fds = next_fds;
            self.peak_bytes = @max(self.peak_bytes, next_bytes);
            self.peak_fds = @max(self.peak_fds, next_fds);
            return .{ .owner = self, .slot = @intCast(index), .serial = serial };
        };
        return error.ResourceReservationLimit;
    }
    pub fn release(self: *Ledger, token: Token) Error!void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (token.owner != self or token.slot >= self.slots.len) return error.StaleReservation;
        const slot = &self.slots[token.slot];
        if (!slot.active or slot.serial != token.serial) return error.StaleReservation;
        const bytes = try slot.cost.chargedBytes();
        if (bytes > self.used_bytes or slot.cost.fds > self.used_fds) return error.StaleReservation;
        self.used_bytes -= bytes;
        self.used_fds -= slot.cost.fds;
        slot.active = false;
    }
    pub fn snapshot(self: *Ledger) Snapshot {
        self.mutex.lock();
        defer self.mutex.unlock();
        return .{ .used_bytes = self.used_bytes, .used_fds = self.used_fds, .peak_bytes = self.peak_bytes, .peak_fds = self.peak_fds };
    }
};
pub const Snapshot = struct { used_bytes: usize, used_fds: usize, peak_bytes: usize, peak_fds: usize };
