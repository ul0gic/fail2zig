// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const db = @import("fail2ban_db.zig");
const plan = @import("plan.zig");
const scope = @import("../firewall/scope.zig");
const lease = @import("../core/native_lease.zig");

pub const Error = db.Error || error{ PlanInvalid, TimeOverflow };

pub const Backend = enum {
    nftables,
    ipset,
    iptables,
    fn supportsNetworks(self: Backend) bool {
        return self != .iptables;
    }
};

pub const Options = struct {
    snapshot_path: []const u8,
    document: *const plan.Document,
    backend: Backend,
    now_us: i64,
};

pub const LeaseKind = enum(u8) { finite = 1, permanent = 2 };
pub const EventKind = enum(u8) { restored_ban = 1 };

pub const StagedOwner = struct {
    jail: []const u8,
    scope: scope.Scope,
    encoded: [scope.encoded_bytes]u8,
    lease_kind: LeaseKind,
    deadline_us: ?i64,
    source_event_us: i64,
    bancount: i64,
    source_row: u64,
};

pub const StagedHistory = struct {
    jail: []const u8,
    scope: scope.Scope,
    encoded: [scope.encoded_bytes]u8,
    event_kind: EventKind = .restored_ban,
    event_us: i64,
    bancount: i64,
    source_row: u64,
};

pub const Skipped = struct { group: []const u8, reason: []const u8 };

pub const Report = struct {
    imported_owners: u64 = 0,
    imported_history: u64 = 0,
    skipped_expired: u64 = 0,
    skipped_unsupported: []const Skipped = &.{},
    blockers: []const plan.Blocker = &.{},
    double_count_avoided: u64 = 0,
    kernel_state: []const u8 = "unknown",
    assumptions: []const []const u8 = &.{},

    pub fn blocked(self: Report) bool {
        return self.blockers.len != 0;
    }
};

pub const Staging = struct {
    arena: std.heap.ArenaAllocator,
    owners: []const StagedOwner,
    history: []const StagedHistory,
    report: Report,

    pub fn deinit(self: *Staging) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub const StagedOwnerRow = @import("../core/record_store.zig").Store.StagedOwnerRow;
pub const StagedHistoryRow = @import("../core/record_store.zig").Store.StagedHistoryRow;

pub const staging_sql = struct {
    pub const delete_owners: [:0]const u8 = "DELETE FROM migration_staged_owners WHERE run_id=?1;";
    pub const delete_history: [:0]const u8 = "DELETE FROM migration_staged_history WHERE run_id=?1;";
    pub const insert_owner: [:0]const u8 = "INSERT INTO migration_staged_owners(run_id,seq,jail,scope,lease_kind,deadline_us,source_event_us,source_row) VALUES(?1,?2,?3,?4,?5,?6,?7,?8);";
    pub const insert_history: [:0]const u8 = "INSERT INTO migration_staged_history(run_id,seq,jail,scope,event_kind,event_us,bancount,source_row) VALUES(?1,?2,?3,?4,?5,?6,?7,?8);";
};

pub fn ownerRows(allocator: std.mem.Allocator, staging: *const Staging) error{OutOfMemory}![]StagedOwnerRow {
    const rows = try allocator.alloc(StagedOwnerRow, staging.owners.len);
    for (staging.owners, 0..) |owner, i| rows[i] = .{
        .jail = owner.jail,
        .scope = owner.encoded,
        .lease_kind = @intFromEnum(owner.lease_kind),
        .deadline_us = owner.deadline_us,
        .source_event_us = owner.source_event_us,
        .source_row = owner.source_row,
    };
    return rows;
}

pub fn historyRows(allocator: std.mem.Allocator, staging: *const Staging) error{OutOfMemory}![]StagedHistoryRow {
    const rows = try allocator.alloc(StagedHistoryRow, staging.history.len);
    for (staging.history, 0..) |event, i| rows[i] = .{
        .jail = event.jail,
        .scope = event.encoded,
        .event_kind = @intFromEnum(event.event_kind),
        .event_us = event.event_us,
        .bancount = event.bancount,
        .source_row = event.source_row,
    };
    return rows;
}

pub fn stage(store: anytype, run_id: [32]u8, staging: *const Staging) !void {
    if (staging.report.blocked()) return error.MigrationBlocked;
    const allocator = staging.arena.child_allocator;
    const owners = try ownerRows(allocator, staging);
    defer allocator.free(owners);
    const history = try historyRows(allocator, staging);
    defer allocator.free(history);
    try store.stageMigrationRows(run_id, owners, history);
}

const Group = struct {
    name: []const u8,
    enabled: bool,
    supported: bool,
    selected: bool,
    scope_mapping: []const u8,
};

const Converter = struct {
    a: std.mem.Allocator,
    options: Options,
    groups: []const Group,
    owners: std.ArrayListUnmanaged(StagedOwner) = .{},
    index: std.HashMapUnmanaged(OwnerKey, usize, OwnerKey.Context, std.hash_map.default_max_load_percentage) = .{},
    history: std.ArrayListUnmanaged(StagedHistory) = .{},
    skipped: std.ArrayListUnmanaged(Skipped) = .{},
    blockers: std.ArrayListUnmanaged(plan.Blocker) = .{},
    assumptions: std.ArrayListUnmanaged([]const u8) = .{},
    report: Report = .{},

    fn group(self: *Converter, name: []const u8) ?*const Group {
        for (self.groups) |*g| if (std.mem.eql(u8, g.name, name)) return g;
        return null;
    }

    fn addBlocker(self: *Converter, group_name: []const u8, kind: []const u8, comptime fmt: []const u8, args: anytype) Error!void {
        const reason = std.fmt.allocPrint(self.a, fmt, args) catch return error.OutOfMemory;
        for (self.blockers.items) |b| if (std.mem.eql(u8, b.group, group_name) and std.mem.eql(u8, b.reason, reason)) return;
        self.blockers.append(self.a, .{ .group = self.a.dupe(u8, group_name) catch return error.OutOfMemory, .kind = kind, .reason = reason }) catch return error.OutOfMemory;
    }

    fn addSkipped(self: *Converter, group_name: []const u8, reason: []const u8) Error!void {
        self.skipped.append(self.a, .{ .group = self.a.dupe(u8, group_name) catch return error.OutOfMemory, .reason = reason }) catch return error.OutOfMemory;
    }

    fn classifyJails(self: *Converter, reader: *db.Reader) Error!void {
        var it = try reader.jails();
        defer it.deinit();
        while (try it.next()) |row_const| {
            var row = row_const;
            defer row.deinit(self.a);
            const enabled = switch (row.enabled) {
                .present => |v| v != 0,
                .absent => false,
            };
            if (!enabled) {
                if (!self.importable(row.name)) try self.addSkipped(row.name, "jail-disabled-in-snapshot");
                continue;
            }
            const g = self.group(row.name) orelse {
                try self.addBlocker(row.name, "import", "group-not-in-plan", .{});
                continue;
            };
            if (!g.supported) {
                try self.addBlocker(row.name, "import", "group-unsupported-in-plan", .{});
            } else if (!g.selected) {
                try self.addSkipped(row.name, "group-not-selected");
            } else if (!g.enabled) {
                try self.addBlocker(row.name, "import", "group-disabled-in-plan-but-enabled-in-snapshot", .{});
            }
        }
    }

    fn importable(self: *Converter, jail: []const u8) bool {
        const g = self.group(jail) orelse return false;
        return g.enabled and g.supported and g.selected;
    }

    fn subjectFor(self: *Converter, jail: []const u8, ip: []const u8, source_row: u64) Error!?scope.Subject {
        const g = self.group(jail).?;
        if (!std.mem.eql(u8, g.scope_mapping, "host") and !std.mem.eql(u8, g.scope_mapping, "net") and !std.mem.eql(u8, g.scope_mapping, "port")) {
            try self.addBlocker(jail, "import", "scope-mapping-unknown:{s}", .{g.scope_mapping});
            return null;
        }
        if (std.mem.indexOfScalar(u8, ip, '/') != null) {
            if (!self.options.backend.supportsNetworks()) {
                try self.addBlocker(jail, "import", "network-scope-unsupported-by-backend:{s}:row:{d}", .{ @tagName(self.options.backend), source_row });
                return null;
            }
            return scope.Subject.parseNetwork(ip) catch {
                try self.addBlocker(jail, "import", "network-invalid:row:{d}", .{source_row});
                return null;
            };
        }
        return scope.Subject.parseHost(ip) catch {
            try self.addBlocker(jail, "import", "ip-invalid:row:{d}", .{source_row});
            return null;
        };
    }

    fn scopeFor(self: *Converter, jail: []const u8, ip: db.Optional([]u8), source_row: u64) Error!?struct { scope: scope.Scope, encoded: [scope.encoded_bytes]u8 } {
        const text = switch (ip) {
            .present => |v| v,
            .absent => {
                try self.addBlocker(jail, "import", "ip-absent:row:{d}", .{source_row});
                return null;
            },
        };
        const subject = (try self.subjectFor(jail, text, source_row)) orelse return null;
        const value = scope.Scope{ .subject = subject };
        const encoded = value.encode() catch {
            try self.addBlocker(jail, "import", "scope-unencodable:row:{d}", .{source_row});
            return null;
        };
        return .{ .scope = value, .encoded = encoded };
    }

    fn seconds(self: *Converter, jail: []const u8, value: i64, source_row: u64) Error!?i64 {
        return std.math.mul(i64, value, std.time.us_per_s) catch {
            try self.addBlocker(jail, "import", "time-overflow:row:{d}", .{source_row});
            return null;
        };
    }

    fn convertBans(self: *Converter, reader: *db.Reader) Error!void {
        var it = try reader.bans();
        defer it.deinit();
        var source_row: u64 = 0;
        while (try it.next()) |row_const| {
            var row = row_const;
            defer row.deinit(self.a);
            source_row += 1;
            if (!self.importable(row.jail)) continue;
            const jail = self.a.dupe(u8, row.jail) catch return error.OutOfMemory;
            const resolved = (try self.scopeFor(jail, row.ip, source_row)) orelse continue;
            const event_us = (try self.seconds(jail, row.timeofban, source_row)) orelse continue;
            if (event_us > self.options.now_us) {
                try self.addBlocker(jail, "import", "timeofban-in-future:row:{d}", .{source_row});
                continue;
            }
            const duration = lease.ImportedDuration.fromSeconds(row.bantime) catch {
                try self.addBlocker(jail, "import", "bantime-invalid:{d}:row:{d}", .{ row.bantime, source_row });
                continue;
            };
            var kind: LeaseKind = .permanent;
            var deadline: ?i64 = null;
            switch (duration) {
                .permanent => {},
                .imported_unknown => {
                    try self.addBlocker(jail, "import", "bantime-unknown-sentinel:row:{d}", .{source_row});
                    continue;
                },
                .finite => |value| {
                    const until = std.math.add(i64, event_us, value.finite_us) catch {
                        try self.addBlocker(jail, "import", "time-overflow:row:{d}", .{source_row});
                        continue;
                    };
                    if (until <= self.options.now_us) {
                        self.report.skipped_expired += 1;
                        continue;
                    }
                    kind = .finite;
                    deadline = until;
                },
            }
            const candidate = StagedOwner{
                .jail = jail,
                .scope = resolved.scope,
                .encoded = resolved.encoded,
                .lease_kind = kind,
                .deadline_us = deadline,
                .source_event_us = event_us,
                .bancount = row.bancount,
                .source_row = source_row,
            };
            try self.mergeOwner(candidate);
        }
    }

    fn mergeOwner(self: *Converter, candidate: StagedOwner) Error!void {
        const key = OwnerKey{ .jail = candidate.jail, .encoded = candidate.encoded };
        const slot = self.index.getOrPut(self.a, key) catch return error.OutOfMemory;
        if (!slot.found_existing) {
            slot.value_ptr.* = self.owners.items.len;
            self.owners.append(self.a, candidate) catch {
                self.index.removeByPtr(slot.key_ptr);
                return error.OutOfMemory;
            };
            return;
        }
        const existing = &self.owners.items[slot.value_ptr.*];
        self.report.double_count_avoided += 1;
        const bancount = @max(existing.bancount, candidate.bancount);
        const newer = candidate.source_event_us > existing.source_event_us;
        if (existing.lease_kind == .permanent) {
            existing.source_event_us = @max(existing.source_event_us, candidate.source_event_us);
        } else if (newer or candidate.lease_kind == .permanent) {
            existing.* = candidate;
        }
        existing.bancount = bancount;
    }

    fn convertBips(self: *Converter, reader: *db.Reader) Error!void {
        var it = try reader.bips();
        defer it.deinit();
        var source_row: u64 = 0;
        while (try it.next()) |row_const| {
            var row = row_const;
            defer row.deinit(self.a);
            source_row += 1;
            if (!self.importable(row.jail)) continue;
            const jail = self.a.dupe(u8, row.jail) catch return error.OutOfMemory;
            const resolved = (try self.scopeFor(jail, row.ip, source_row)) orelse continue;
            const event_us = (try self.seconds(jail, row.timeofban, source_row)) orelse continue;
            if (row.bancount < 0) {
                try self.addBlocker(jail, "import", "bancount-negative:row:{d}", .{source_row});
                continue;
            }
            if (self.hasOwner(jail, resolved.encoded)) {
                self.report.double_count_avoided += 1;
                continue;
            }
            self.history.append(self.a, .{
                .jail = jail,
                .scope = resolved.scope,
                .encoded = resolved.encoded,
                .event_us = event_us,
                .bancount = row.bancount,
                .source_row = source_row,
            }) catch return error.OutOfMemory;
        }
    }

    fn hasOwner(self: *Converter, jail: []const u8, encoded: [scope.encoded_bytes]u8) bool {
        return self.index.contains(.{ .jail = jail, .encoded = encoded });
    }
};

const OwnerKey = struct {
    jail: []const u8,
    encoded: [scope.encoded_bytes]u8,

    const Context = struct {
        pub fn hash(_: Context, key: OwnerKey) u64 {
            var hasher = std.hash.Wyhash.init(0);
            hasher.update(key.jail);
            hasher.update(&[_]u8{0});
            hasher.update(&key.encoded);
            return hasher.final();
        }
        pub fn eql(_: Context, x: OwnerKey, y: OwnerKey) bool {
            return std.mem.eql(u8, x.jail, y.jail) and std.mem.eql(u8, &x.encoded, &y.encoded);
        }
    };
};

fn readGroups(a: std.mem.Allocator, document: *const plan.Document) Error![]const Group {
    if (document.manifest != .object) return error.PlanInvalid;
    const groups_value = document.manifest.object.get("groups") orelse return error.PlanInvalid;
    if (groups_value != .array) return error.PlanInvalid;
    var out = std.ArrayListUnmanaged(Group){};
    for (groups_value.array.items) |item| {
        if (item != .object) return error.PlanInvalid;
        const object = item.object;
        const name = stringField(object, "name") orelse return error.PlanInvalid;
        const enabled = object.get("enabled") orelse return error.PlanInvalid;
        if (enabled != .bool) return error.PlanInvalid;
        const disposition = object.get("disposition") orelse return error.PlanInvalid;
        if (disposition != .object) return error.PlanInvalid;
        const kind = stringField(disposition.object, "kind") orelse return error.PlanInvalid;
        const mapping = object.get("mapping") orelse return error.PlanInvalid;
        if (mapping != .object) return error.PlanInvalid;
        const scope_mapping = stringField(mapping.object, "scope") orelse return error.PlanInvalid;
        var selected = false;
        for (document.selection) |s| if (std.mem.eql(u8, s, name)) {
            selected = true;
        };
        out.append(a, .{
            .name = a.dupe(u8, name) catch return error.OutOfMemory,
            .enabled = enabled.bool,
            .supported = std.mem.eql(u8, kind, "supported"),
            .selected = selected,
            .scope_mapping = a.dupe(u8, scope_mapping) catch return error.OutOfMemory,
        }) catch return error.OutOfMemory;
    }
    return out.toOwnedSlice(a) catch return error.OutOfMemory;
}

fn stringField(object: std.json.ObjectMap, name: []const u8) ?[]const u8 {
    const value = object.get(name) orelse return null;
    return switch (value) {
        .string => |s| s,
        else => null,
    };
}

pub fn import(allocator: std.mem.Allocator, options: Options) Error!Staging {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    errdefer arena_state.deinit();
    const a = arena_state.allocator();

    if (options.document.blockers.len != 0) return error.PlanInvalid;
    const groups = try readGroups(a, options.document);
    var converter = Converter{ .a = a, .options = options, .groups = groups };

    var reader = try db.Reader.open(a, options.snapshot_path);
    defer reader.close();
    try converter.classifyJails(&reader);
    try converter.convertBans(&reader);
    try converter.convertBips(&reader);

    converter.assumptions.append(a, "kernel_state:unknown") catch return error.OutOfMemory;
    converter.assumptions.append(a, "bans-rows-deduplicated-per-jail-scope:latest-decision-wins") catch return error.OutOfMemory;
    converter.assumptions.append(a, "bips-rows-with-a-live-owner-are-not-restored-as-history") catch return error.OutOfMemory;

    var report = converter.report;
    report.imported_owners = converter.owners.items.len;
    report.imported_history = converter.history.items.len;
    report.skipped_unsupported = converter.skipped.toOwnedSlice(a) catch return error.OutOfMemory;
    report.blockers = converter.blockers.toOwnedSlice(a) catch return error.OutOfMemory;
    report.assumptions = converter.assumptions.toOwnedSlice(a) catch return error.OutOfMemory;
    return .{
        .arena = arena_state,
        .owners = converter.owners.toOwnedSlice(a) catch return error.OutOfMemory,
        .history = converter.history.toOwnedSlice(a) catch return error.OutOfMemory,
        .report = report,
    };
}
