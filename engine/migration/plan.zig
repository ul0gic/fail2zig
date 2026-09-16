// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const inspect = @import("inspect.zig");
const fail2ban = @import("../config/fail2ban.zig");
const snapshot = @import("sqlite_snapshot.zig");
const db = @import("fail2ban_db.zig");

pub const schema_version: u32 = 1;
pub const validity_us: i64 = 24 * 60 * 60 * 1_000_000;
pub const max_plan_bytes: usize = 16 * 1024 * 1024;
pub const default_runtime_socket = "/var/run/fail2ban/fail2ban.sock";

pub const Error = inspect.Error || snapshot.Error || error{
    PlanTooLarge,
    PlanUnreadable,
    PlanInvalid,
    PlanTampered,
    PlanWriteFailed,
};

pub const Continuity = enum { lossless, reset_replay };

pub const PlanOptions = struct {
    source_dir: []const u8,
    source_db: ?[]const u8 = null,
    snapshot: ?*const snapshot.Snapshot = null,
    continuity: Continuity = .reset_replay,
    replay_window_s: ?u32 = null,
    now_us: i64,
    host_id: [32]u8,
    tool_version: []const u8 = "unknown",
    runtime_socket: ?[]const u8 = null,
    limits: inspect.Limits = .{},
};

pub const SnapshotRecord = struct {
    path: []const u8,
    recorded_sha256: []const u8,
    version: i64,
    captured_us: i64,
    jails: u64,
    logs: u64,
    bans: u64,
    bips: u64,
};

pub const Change = struct { group: []const u8, change: []const u8 };
pub const Blocker = struct { group: []const u8, kind: []const u8, reason: []const u8 };
pub const FileFingerprint = struct { path: []const u8, sha256: []const u8 };
pub const Drift = struct { files: []const FileFingerprint, runtime_socket: []const u8, runtime_state: []const u8 };

pub const Document = struct {
    schema_version: u32 = schema_version,
    tool_version: []const u8,
    host_id_hex: []const u8,
    created_us: i64,
    valid_until_us: i64,
    continuity: []const u8,
    replay_window_s: ?u32,
    source_dir: []const u8,
    source_db: ?[]const u8,
    snapshot: ?SnapshotRecord,
    snapshot_fp: ?[]const u8,
    manifest: std.json.Value,
    assumptions: []const []const u8,
    semantic_changes: []const Change,
    blockers: []const Blocker,
    secret_boundaries: []const []const u8,
    selection: []const []const u8,
    drift: Drift,
    digest: []const u8,
};

pub const Plan = struct {
    arena: std.heap.ArenaAllocator,
    doc: Document,
    plan_fp: ?[32]u8,

    pub fn deinit(self: *Plan) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub fn plan(allocator: std.mem.Allocator, options: PlanOptions) Error!Plan {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    errdefer arena_state.deinit();
    const a = arena_state.allocator();

    var manifest = try inspect.inspect(allocator, .{ .source_dir = options.source_dir, .tool_version = options.tool_version, .limits = options.limits });
    defer manifest.deinit();

    var builder = Builder{ .a = a, .options = options, .manifest = &manifest };
    try builder.collectGroupFindings();
    try builder.collectSecretBoundaries();
    try builder.collectSnapshot();
    try builder.collectContinuity();

    std.mem.sort([]const u8, builder.assumptions.items, {}, stringLessThan);
    std.mem.sort(Change, builder.changes.items, {}, changeLessThan);
    std.mem.sort(Blocker, builder.blockers.items, {}, blockerLessThan);
    std.mem.sort([]const u8, builder.secrets.items, {}, stringLessThan);
    std.mem.sort([]const u8, builder.selection.items, {}, stringLessThan);

    var files = std.ArrayListUnmanaged(FileFingerprint){};
    for (manifest.files) |f| try files.append(a, .{ .path = try a.dupe(u8, f.path), .sha256 = try hex(a, f.sha256) });
    const socket_path = options.runtime_socket orelse default_runtime_socket;

    var doc = Document{
        .tool_version = try a.dupe(u8, options.tool_version),
        .host_id_hex = try hex(a, options.host_id),
        .created_us = options.now_us,
        .valid_until_us = options.now_us +| validity_us,
        .continuity = @tagName(options.continuity),
        .replay_window_s = options.replay_window_s,
        .source_dir = try a.dupe(u8, options.source_dir),
        .source_db = if (options.source_db) |p| try a.dupe(u8, p) else null,
        .snapshot = builder.snapshot_record,
        .snapshot_fp = builder.snapshot_fp,
        .manifest = try manifestValue(a, &manifest),
        .assumptions = try builder.assumptions.toOwnedSlice(a),
        .semantic_changes = try builder.changes.toOwnedSlice(a),
        .blockers = try builder.blockers.toOwnedSlice(a),
        .secret_boundaries = try builder.secrets.toOwnedSlice(a),
        .selection = try builder.selection.toOwnedSlice(a),
        .drift = .{
            .files = try files.toOwnedSlice(a),
            .runtime_socket = try a.dupe(u8, socket_path),
            .runtime_state = runtimeState(socket_path),
        },
        .digest = "",
    };
    doc.digest = try computeDigest(a, &doc);
    var counting = std.io.countingWriter(std.io.null_writer);
    std.json.stringify(doc, .{}, counting.writer()) catch return error.OutOfMemory;
    if (counting.bytes_written > max_plan_bytes) return error.PlanTooLarge;
    return .{ .arena = arena_state, .doc = doc, .plan_fp = null };
}

const Builder = struct {
    a: std.mem.Allocator,
    options: PlanOptions,
    manifest: *const inspect.Manifest,
    assumptions: std.ArrayListUnmanaged([]const u8) = .{},
    changes: std.ArrayListUnmanaged(Change) = .{},
    blockers: std.ArrayListUnmanaged(Blocker) = .{},
    secrets: std.ArrayListUnmanaged([]const u8) = .{},
    selection: std.ArrayListUnmanaged([]const u8) = .{},
    snapshot_record: ?SnapshotRecord = null,
    snapshot_fp: ?[]const u8 = null,
    snapshot_usable: bool = false,

    fn addBlocker(self: *Builder, group: []const u8, kind: []const u8, reason: []const u8) Error!void {
        for (self.blockers.items) |b| if (std.mem.eql(u8, b.group, group) and std.mem.eql(u8, b.reason, reason)) return;
        try self.blockers.append(self.a, .{ .group = try self.a.dupe(u8, group), .kind = kind, .reason = try self.a.dupe(u8, reason) });
    }

    fn addChange(self: *Builder, group: []const u8, change: []const u8) Error!void {
        try self.changes.append(self.a, .{ .group = try self.a.dupe(u8, group), .change = change });
    }

    fn collectGroupFindings(self: *Builder) Error!void {
        for (self.manifest.groups) |g| {
            if (!g.enabled) continue;
            switch (g.disposition.kind) {
                .supported => try self.selection.append(self.a, try self.a.dupe(u8, g.name)),
                .operator_change, .blocker => for (g.disposition.reasons) |r| try self.addBlocker(g.name, @tagName(g.disposition.kind), r),
                .not_enabled => {},
            }
            if (std.mem.eql(u8, g.mapping.scope, "port")) try self.addChange(g.name, "port-scope-widened-to-host");
            if (std.mem.startsWith(u8, g.backend, "systemd")) {
                try self.addChange(g.name, "backend-substitution:systemd->journalctl");
                if (g.journalmatch != null) try self.addChange(g.name, "journalmatch-replacement:native-origin-qualification");
            } else if (!std.mem.eql(u8, g.backend, "auto")) {
                try self.addChange(g.name, try std.fmt.allocPrint(self.a, "backend-substitution:{s}->file", .{g.backend}));
            }
            if (std.mem.eql(u8, g.mapping.duration, "permanent")) try self.addChange(g.name, "permanent-ban-retained-without-increment");
        }
    }

    fn collectSecretBoundaries(self: *Builder) Error!void {
        const ini = fail2ban.loadJailConfig(self.a, self.options.source_dir) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return,
        };
        for (self.manifest.groups) |g| {
            for ([_][]const u8{ "destemail", "sender", "mta" }) |key| {
                const value = fail2ban.resolve(self.a, &ini, g.name, key) catch null;
                if (value != null) try self.secrets.append(self.a, try std.fmt.allocPrint(self.a, "{s}/{s}", .{ g.name, key }));
            }
            const action = (fail2ban.resolve(self.a, &ini, g.name, "action") catch null) orelse continue;
            const selectors = fail2ban.splitSelectors(self.a, action) catch continue;
            for (selectors) |selector| {
                const sel = fail2ban.parseSelector(self.a, selector) catch continue;
                var it = sel.parameters.iterator();
                while (it.next()) |kv| {
                    if (!isSecretParameter(kv.key_ptr.*)) continue;
                    try self.secrets.append(self.a, try std.fmt.allocPrint(self.a, "{s}/action/{s}/{s}", .{ g.name, sel.name, kv.key_ptr.* }));
                }
            }
        }
    }

    fn collectSnapshot(self: *Builder) Error!void {
        const snap = self.options.snapshot orelse {
            if (self.options.source_db != null) try self.addBlocker("*", "snapshot", "snapshot-missing");
            return;
        };
        const recorded = try hex(self.a, snap.destination_sha256);
        self.snapshot_record = .{
            .path = try self.a.dupe(u8, snap.destination_path),
            .recorded_sha256 = recorded,
            .version = snap.version,
            .captured_us = snap.captured_us,
            .jails = snap.row_counts.jails,
            .logs = snap.row_counts.logs,
            .bans = snap.row_counts.bans,
            .bips = snap.row_counts.bips,
        };
        const actual = snapshot.sha256File(snap.destination_path) catch {
            try self.addBlocker("*", "snapshot", "snapshot-unreadable");
            return;
        };
        self.snapshot_fp = try hex(self.a, actual);
        if (!std.mem.eql(u8, &actual, &snap.destination_sha256)) {
            try self.addBlocker("*", "snapshot", "snapshot-fingerprint-mismatch");
            return;
        }
        if (snap.version != db.expected_version) {
            try self.addBlocker("*", "snapshot", try std.fmt.allocPrint(self.a, "snapshot-version:{d}", .{snap.version}));
            return;
        }
        self.snapshot_usable = true;
    }

    fn collectContinuity(self: *Builder) Error!void {
        switch (self.options.continuity) {
            .reset_replay => {
                try self.assumptions.append(self.a, "non_lossless:true");
                if (self.options.replay_window_s) |w| {
                    try self.assumptions.append(self.a, try std.fmt.allocPrint(self.a, "replay_window_s:{d}", .{w}));
                } else try self.addBlocker("*", "continuity", "replay-window-missing");
            },
            .lossless => {
                var logs = std.ArrayListUnmanaged(LogRow){};
                if (self.snapshot_usable) try self.readLogs(&logs);
                for (self.manifest.groups) |g| {
                    if (!g.enabled) continue;
                    const usable = !std.mem.startsWith(u8, g.backend, "systemd") and self.snapshot_usable and hasUsableLog(logs.items, g);
                    if (!usable) try self.addBlocker(g.name, "continuity", try std.fmt.allocPrint(self.a, "continuity-unavailable:{s}", .{g.name}));
                }
            },
        }
    }

    const LogRow = struct { jail: []const u8, path: []const u8 };

    fn readLogs(self: *Builder, out: *std.ArrayListUnmanaged(LogRow)) Error!void {
        const path = self.snapshot_record.?.path;
        var reader = db.Reader.open(self.a, path) catch {
            try self.addBlocker("*", "snapshot", "snapshot-unreadable");
            self.snapshot_usable = false;
            return;
        };
        defer reader.close();
        var it = try reader.logs();
        defer it.deinit();
        while (try it.next()) |row| {
            const p = switch (row.path) {
                .present => |v| v,
                else => continue,
            };
            const md5_present = row.firstlinemd5 == .present;
            if (!md5_present) continue;
            try out.append(self.a, .{ .jail = row.jail, .path = p });
        }
    }

    fn hasUsableLog(logs: []const LogRow, g: inspect.Group) bool {
        for (g.logpaths) |lp| {
            for (logs) |row| if (std.mem.eql(u8, row.jail, g.name) and std.mem.eql(u8, row.path, lp)) return true;
        }
        return false;
    }
};

fn isSecretParameter(name: []const u8) bool {
    var lower_buf: [128]u8 = undefined;
    if (name.len > lower_buf.len) return true;
    const lower = std.ascii.lowerString(&lower_buf, name);
    if (std.mem.startsWith(u8, lower, "smtp")) return true;
    for ([_][]const u8{ "pass", "token", "key", "secret" }) |needle| if (std.mem.indexOf(u8, lower, needle) != null) return true;
    return false;
}

fn runtimeState(socket_path: []const u8) []const u8 {
    std.fs.cwd().access(socket_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return "absent",
        else => return "unknown",
    };
    return "unknown";
}

fn manifestValue(a: std.mem.Allocator, manifest: *const inspect.Manifest) Error!std.json.Value {
    var buf = std.ArrayListUnmanaged(u8){};
    inspect.renderJson(manifest, buf.writer(a)) catch return error.OutOfMemory;
    return std.json.parseFromSliceLeaky(std.json.Value, a, std.mem.trimRight(u8, buf.items, "\n"), .{}) catch return error.OutOfMemory;
}

fn computeDigest(a: std.mem.Allocator, doc: *const Document) Error![]const u8 {
    var copy = doc.*;
    copy.digest = "";
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buf = std.ArrayListUnmanaged(u8){};
    std.json.stringify(copy, .{}, buf.writer(a)) catch return error.OutOfMemory;
    hasher.update(buf.items);
    return try hex(a, hasher.finalResult());
}

fn hex(a: std.mem.Allocator, digest: [32]u8) Error![]const u8 {
    return std.fmt.allocPrint(a, "{s}", .{std.fmt.fmtSliceHexLower(&digest)});
}

fn stringLessThan(_: void, x: []const u8, y: []const u8) bool {
    return std.mem.order(u8, x, y) == .lt;
}
fn changeLessThan(_: void, x: Change, y: Change) bool {
    const g = std.mem.order(u8, x.group, y.group);
    if (g != .eq) return g == .lt;
    return std.mem.order(u8, x.change, y.change) == .lt;
}
fn blockerLessThan(_: void, x: Blocker, y: Blocker) bool {
    const g = std.mem.order(u8, x.group, y.group);
    if (g != .eq) return g == .lt;
    return std.mem.order(u8, x.reason, y.reason) == .lt;
}

pub fn renderJson(p: *const Plan, writer: anytype) !void {
    try std.json.stringify(p.doc, .{}, writer);
    try writer.writeByte('\n');
}

pub fn renderTable(p: *const Plan, writer: anytype) !void {
    const d = &p.doc;
    try writer.print("plan: source {s}, created {d}, valid until {d}, continuity {s}\n", .{ d.source_dir, d.created_us, d.valid_until_us, d.continuity });
    if (d.snapshot) |s| try writer.print("snapshot: {s} (version {d}, {d} bans, {d} logs)\n", .{ s.path, s.version, s.bans, s.logs });
    try writer.print("runtime state: {s} ({s})\n", .{ d.drift.runtime_state, d.drift.runtime_socket });
    try writer.writeAll("selection:");
    for (d.selection) |s| try writer.print(" {s}", .{s});
    try writer.writeAll("\nassumptions:");
    for (d.assumptions) |s| try writer.print(" {s}", .{s});
    try writer.writeAll("\n");
    if (d.semantic_changes.len > 0) {
        try writer.writeAll("semantic changes:\n");
        for (d.semantic_changes) |c| try writer.print("  {s}: {s}\n", .{ c.group, c.change });
    }
    if (d.blockers.len > 0) {
        try writer.writeAll("blockers:\n");
        for (d.blockers) |b| try writer.print("  {s} [{s}] {s}\n", .{ b.group, b.kind, b.reason });
    }
    if (d.secret_boundaries.len > 0) {
        try writer.writeAll("secret boundaries (values withheld):\n");
        for (d.secret_boundaries) |s| try writer.print("  {s}\n", .{s});
    }
    try writer.print("digest: {s}\n", .{d.digest});
}

pub fn writePlanFile(p: *const Plan, path: []const u8) Error!void {
    var buf = std.ArrayListUnmanaged(u8){};
    defer buf.deinit(p.arena.child_allocator);
    renderJson(p, buf.writer(p.arena.child_allocator)) catch return error.OutOfMemory;
    if (buf.items.len > max_plan_bytes) return error.PlanTooLarge;
    const dir_path = std.fs.path.dirname(path) orelse ".";
    const base = std.fs.path.basename(path);
    var dir = std.fs.cwd().openDir(dir_path, .{}) catch return error.PlanWriteFailed;
    defer dir.close();
    var tmp_name_buf: [std.fs.max_name_bytes]u8 = undefined;
    const tmp_name = std.fmt.bufPrint(&tmp_name_buf, ".{s}.tmp", .{base}) catch return error.PlanWriteFailed;
    const file = dir.createFile(tmp_name, .{ .exclusive = true, .mode = 0o600 }) catch return error.PlanWriteFailed;
    var committed = false;
    defer if (!committed) dir.deleteFile(tmp_name) catch {};
    {
        defer file.close();
        file.writeAll(buf.items) catch return error.PlanWriteFailed;
        file.sync() catch return error.PlanWriteFailed;
    }
    dir.rename(tmp_name, base) catch return error.PlanWriteFailed;
    committed = true;
}

pub fn readPlanFile(allocator: std.mem.Allocator, path: []const u8) Error!Plan {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    errdefer arena_state.deinit();
    const a = arena_state.allocator();
    const bytes = std.fs.cwd().readFileAlloc(a, path, max_plan_bytes) catch |err| switch (err) {
        error.FileTooBig => return error.PlanTooLarge,
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.PlanUnreadable,
    };
    var fp: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &fp, .{});
    const doc = std.json.parseFromSliceLeaky(Document, a, bytes, .{ .ignore_unknown_fields = false }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.PlanInvalid,
    };
    if (doc.schema_version != schema_version) return error.PlanInvalid;
    const expected = try computeDigest(a, &doc);
    if (!std.mem.eql(u8, expected, doc.digest)) return error.PlanTampered;
    return .{ .arena = arena_state, .doc = doc, .plan_fp = fp };
}

pub const Outcome = enum { valid, stale, drifted, blocked };

pub const ValidateOptions = struct {
    now_us: i64,
    source_dir: ?[]const u8 = null,
    snapshot_path: ?[]const u8 = null,
    runtime_socket: ?[]const u8 = null,
};

pub const Validation = struct {
    outcome: Outcome,
    reasons: []const []const u8,
    arena: std.heap.ArenaAllocator,

    pub fn deinit(self: *Validation) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub fn validate(allocator: std.mem.Allocator, p: *const Plan, options: ValidateOptions) Error!Validation {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    errdefer arena_state.deinit();
    const a = arena_state.allocator();
    const d = &p.doc;
    var reasons = std.ArrayListUnmanaged([]const u8){};
    var stale = false;
    var drifted = false;

    if (options.now_us > d.valid_until_us) {
        stale = true;
        try reasons.append(a, "stale:valid_until_exceeded");
    }

    const source_dir = options.source_dir orelse d.source_dir;
    for (d.drift.files) |f| {
        const full = if (std.fs.path.isAbsolute(f.path)) f.path else try std.fs.path.join(a, &.{ source_dir, f.path });
        const actual = snapshot.sha256File(full) catch {
            drifted = true;
            try reasons.append(a, try std.fmt.allocPrint(a, "file-removed:{s}", .{f.path}));
            continue;
        };
        const actual_hex = try hex(a, actual);
        if (!std.mem.eql(u8, actual_hex, f.sha256)) {
            drifted = true;
            try reasons.append(a, try std.fmt.allocPrint(a, "file-changed:{s}", .{f.path}));
        }
    }
    if (fail2ban.loadJailConfig(a, source_dir)) |ini| {
        const root = std.fs.path.resolve(a, &.{source_dir}) catch return error.OutOfMemory;
        for (ini.sources.items) |occ| {
            const rel = if (std.mem.startsWith(u8, occ.path, root) and occ.path.len > root.len and occ.path[root.len] == '/') occ.path[root.len + 1 ..] else occ.path;
            var known = false;
            for (d.drift.files) |f| if (std.mem.eql(u8, f.path, rel)) {
                known = true;
            };
            if (!known) {
                drifted = true;
                try reasons.append(a, try std.fmt.allocPrint(a, "file-added:{s}", .{rel}));
            }
        }
    } else |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            drifted = true;
            try reasons.append(a, try std.fmt.allocPrint(a, "source-unreadable:{s}", .{@errorName(err)}));
        },
    }

    if (d.snapshot_fp) |recorded| {
        const path = options.snapshot_path orelse (if (d.snapshot) |s| s.path else null);
        if (path) |sp| {
            if (snapshot.sha256File(sp)) |actual| {
                if (!std.mem.eql(u8, try hex(a, actual), recorded)) {
                    drifted = true;
                    try reasons.append(a, "snapshot-changed");
                }
            } else |_| {
                drifted = true;
                try reasons.append(a, "snapshot-missing");
            }
        }
    }

    const socket_path = options.runtime_socket orelse d.drift.runtime_socket;
    const state = runtimeState(socket_path);
    if (!std.mem.eql(u8, state, d.drift.runtime_state)) {
        drifted = true;
        try reasons.append(a, try std.fmt.allocPrint(a, "runtime-state-changed:{s}->{s}", .{ d.drift.runtime_state, state }));
    }

    for (d.blockers) |b| try reasons.append(a, try std.fmt.allocPrint(a, "blocked:{s}:{s}", .{ b.group, b.reason }));

    const outcome: Outcome = if (stale) .stale else if (drifted) .drifted else if (d.blockers.len > 0) .blocked else .valid;
    return .{ .outcome = outcome, .reasons = try reasons.toOwnedSlice(a), .arena = arena_state };
}
