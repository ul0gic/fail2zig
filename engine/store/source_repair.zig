// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const builtin = @import("builtin");
const store_mod = @import("store.zig");
const files = @import("../core/durable_file_source.zig");
const Store = store_mod.Store;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Repair rows whose outcome a replay returns, newest first.
pub const retained_repairs: i64 = 256;
/// Older rows keep only their token as a tombstone so an evicted token can never commit a
/// second repair. Beyond this many tombstones every new repair is refused.
pub const retained_tombstones: i64 = 4096;
pub const max_token_bytes = 128;
const max_path_rows = 64;
const outcome_truncation_acknowledged: i64 = 1;
const outcome_evicted: i64 = 2;

pub const Error = store_mod.Error || error{
    InvalidRepairRequest,
    LoadRepairMigrationRequired,
    SourceNotRecorded,
    SourceAmbiguous,
    SourceUnreadable,
    UnsupportedCheckpoint,
    UnsupportedDiscontinuity,
    TokenUnknownStateMismatch,
    PendingReceipt,
    ConsumerWorkPending,
    StaleGeneration,
    SourceChanged,
    RepairTokenMismatch,
    RepairTokenEvicted,
    RepairHistoryFull,
};

/// Observed relation between the recorded checkpoint and the file at the source path.
pub const Shape = enum { truncated, continuous, prefix_changed, replaced, missing };

pub const Request = struct {
    jail: []const u8,
    path: []const u8,
    /// Caller-chosen operation token; the same token and arguments replay the committed outcome.
    token: []const u8,
};

pub const FileIdentity = struct { device: u64, inode: u64, size: u64, prefix_sha256: [32]u8 };

pub const Outcome = struct {
    replayed: bool,
    /// Owned by the allocator passed to `repair`.
    source: []u8,
    generation: [32]u8,
    prior_checkpoint_revision: u64,
    prior_cursor_sha256: [32]u8,
    /// Only known when this call committed; a replay has the row, not the prior cursor.
    prior_offset: ?u64,
    prior_incarnation: ?[16]u8,
    new_incarnation: [16]u8,
    file: FileIdentity,
    committed_us: i64,

    pub fn deinit(self: Outcome, allocator: std.mem.Allocator) void {
        allocator.free(self.source);
    }
};

pub const Diagnostic = struct { shape: ?Shape = null };

pub const Fault = enum { before_commit, after_commit };
pub const Hooks = if (builtin.is_test) struct {
    context: ?*anyopaque = null,
    after_observe: ?*const fn (?*anyopaque) void = null,
    fail_at: ?Fault = null,
} else struct {};

pub fn tokenKey(token: []const u8) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update("fail2zig-source-repair-token-v1\x00");
    hash.update(token);
    return hash.finalResult();
}

fn validRequest(request: Request) bool {
    if (request.jail.len == 0 or request.jail.len > 64 or std.mem.indexOfScalar(u8, request.jail, 0) != null) return false;
    if (request.path.len == 0 or request.path.len > store_mod.Limits.source_bytes or request.path[0] != '/' or std.mem.indexOfScalar(u8, request.path, 0) != null) return false;
    if (request.token.len == 0 or request.token.len > max_token_bytes) return false;
    for (request.token) |c| if (!(std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == ':')) return false;
    return true;
}

// The file source identifier the daemon assigns to a discovered path.
fn sourceId(buffer: []u8, jail: []const u8, path: []const u8, device: u64, inode: u64) Error![]const u8 {
    return std.fmt.bufPrint(buffer, "{s}:{s}:{d}:{d}", .{ jail, path, device, inode }) catch error.InvalidRepairRequest;
}

const Plan = struct {
    source: []u8,
    prior_cursor: []u8,
    prior: files.Resume,
    next: files.Resume,
    generation: [32]u8,
    revision: u64,
    size: u64,

    fn deinit(self: Plan, allocator: std.mem.Allocator) void {
        allocator.free(self.source);
        allocator.free(self.prior_cursor);
    }
};

/// Acknowledges a same-inode truncation of one stopped file source. The caller holds the
/// state authority lock for the whole call and has opened `store` without creating it.
/// Only the selected source cursor and its jail checkpoint revision change; receipts,
/// owners, deadlines and consumer checkpoints are left exactly as they are.
pub fn repair(store: *Store, allocator: std.mem.Allocator, request: Request, now_us: i64, hooks: Hooks, diagnostic: *Diagnostic) Error!Outcome {
    diagnostic.* = .{};
    if (!validRequest(request) or now_us < 0) return error.InvalidRepairRequest;
    const key = tokenKey(request.token);
    try requireMigratedSchema(store);
    // A committed outcome is checked before any old-state precondition, which it has changed.
    if (try replay(store, allocator, request, key)) |prior| return prior;

    const fd = std.posix.open(request.path, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true }, 0) catch |failure| {
        if (failure != error.FileNotFound) return error.SourceUnreadable;
        diagnostic.shape = .missing;
        return if (try recordedRows(store, request) == 0) error.SourceNotRecorded else error.UnsupportedDiscontinuity;
    };
    const file = std.fs.File{ .handle = fd };
    defer file.close();
    const plan = try observe(store, allocator, request, file, diagnostic);
    defer plan.deinit(allocator);
    if (builtin.is_test) if (hooks.after_observe) |hook| hook(hooks.context);
    return commit(store, allocator, request, key, file, plan, now_us, hooks);
}

fn requireMigratedSchema(store: *Store) Error!void {
    if (try store.integer("PRAGMA user_version;") != store_mod.load_repair_schema) return error.LoadRepairMigrationRequired;
    switch (try store.loadRepairStatus()) {
        .complete => {},
        .incomplete => return error.LoadRepairMigrationIncomplete,
        .earlier_schema, .ready => return error.LoadRepairMigrationRequired,
    }
}

fn replay(store: *Store, allocator: std.mem.Allocator, request: Request, key: [32]u8) Error!?Outcome {
    try store.beginRead();
    errdefer store.rollback();
    const found = try readRow(store, allocator, request, key);
    try store.commitTransaction();
    return found;
}

fn readRow(store: *Store, allocator: std.mem.Allocator, request: Request, key: [32]u8) Error!?Outcome {
    var row = try store.statement("SELECT jail,source,generation,prior_cursor_sha256,prior_checkpoint_revision,file_device,file_inode,file_size,file_prefix_sha256,new_incarnation,committed_us,outcome FROM source_repairs WHERE token=?1;");
    defer row.deinit();
    try row.blob(1, &key);
    if (!try row.row()) return null;
    if (try row.signed(11) == outcome_evicted) return error.RepairTokenEvicted;
    const device = try unsigned(try row.signed(5));
    const inode = try unsigned(try row.signed(6));
    var buffer: [store_mod.Limits.source_bytes + 128]u8 = undefined;
    const expected = try sourceId(&buffer, request.jail, request.path, device, inode);
    if (!std.mem.eql(u8, try row.boundedBytes(0, 64), request.jail) or !std.mem.eql(u8, try row.boundedBytes(1, store_mod.Limits.source_bytes), expected))
        return error.RepairTokenMismatch;
    return .{
        .replayed = true,
        .source = try allocator.dupe(u8, expected),
        .generation = try fixed(32, &row, 2),
        .prior_cursor_sha256 = try fixed(32, &row, 3),
        .prior_checkpoint_revision = try unsigned(try row.signed(4)),
        .prior_offset = null,
        .prior_incarnation = null,
        .new_incarnation = try fixed(16, &row, 9),
        .file = .{ .device = device, .inode = inode, .size = try unsigned(try row.signed(7)), .prefix_sha256 = try fixed(32, &row, 8) },
        .committed_us = try row.signed(10),
    };
}

fn fixed(comptime n: usize, row: *store_mod.Stmt, column: c_int) Error![n]u8 {
    const value = try row.bytes(column);
    if (value.len != n) return error.InvalidRecord;
    return value[0..n].*;
}

fn unsigned(value: i64) Error!u64 {
    return std.math.cast(u64, value) orelse error.InvalidRecord;
}

fn recordedRows(store: *Store, request: Request) Error!i64 {
    try store.beginRead();
    errdefer store.rollback();
    var row = try store.statement("SELECT count(*) FROM source_cursors WHERE jail=?1 AND path=?2;");
    defer row.deinit();
    try row.text(1, request.jail);
    try row.text(2, request.path);
    if (!try row.row()) return error.DatabaseFailure;
    const count = try row.signed(0);
    try store.commitTransaction();
    return count;
}

fn observe(store: *Store, allocator: std.mem.Allocator, request: Request, file: std.fs.File, diagnostic: *Diagnostic) Error!Plan {
    const stat = std.posix.fstat(file.handle) catch return error.SourceUnreadable;
    if (!std.posix.S.ISREG(stat.mode)) return error.SourceUnreadable;
    const device: u64 = @intCast(stat.dev);
    const inode: u64 = @intCast(stat.ino);
    const size = std.math.cast(u64, stat.size) orelse return error.SourceUnreadable;

    try store.beginRead();
    errdefer store.rollback();
    var rows = try store.statement("SELECT source,cursor FROM source_cursors WHERE jail=?1 AND path=?2 ORDER BY source;");
    defer rows.deinit();
    try rows.text(1, request.jail);
    try rows.text(2, request.path);
    var count: usize = 0;
    var selected: ?Plan = null;
    errdefer if (selected) |value| value.deinit(allocator);
    while (try rows.row()) {
        count += 1;
        if (count > max_path_rows) return error.SourceAmbiguous;
        const cursor = try rows.boundedBytes(1, store_mod.Limits.cursor_bytes);
        const parsed = std.json.parseFromSlice(files.Resume, allocator, cursor, .{}) catch return error.InvalidRecord;
        defer parsed.deinit();
        const prior = parsed.value;
        if (prior.version != 2 or prior.prefix_len > 64) return error.InvalidRecord;
        if (prior.device != device or prior.inode != inode) continue;
        if (selected != null) return error.SourceAmbiguous;
        const source = try allocator.dupe(u8, try rows.boundedBytes(0, store_mod.Limits.source_bytes));
        errdefer allocator.free(source);
        const prior_cursor = try allocator.dupe(u8, cursor);
        selected = .{ .source = source, .prior_cursor = prior_cursor, .prior = prior, .next = undefined, .generation = undefined, .revision = undefined, .size = size };
    }
    if (count == 0) return error.SourceNotRecorded;
    var plan = selected orelse {
        diagnostic.shape = .replaced;
        return error.UnsupportedDiscontinuity;
    };
    var buffer: [store_mod.Limits.source_bytes + 128]u8 = undefined;
    if (!std.mem.eql(u8, plan.source, try sourceId(&buffer, request.jail, request.path, device, inode))) return error.SourceNotRecorded;

    const shape: Shape = if (files.truncatedInPlace(plan.prior, device, inode, size))
        .truncated
    else if (std.mem.eql(u8, &(files.prefixDigest(file, plan.prior.prefix_len) catch return error.SourceUnreadable), &plan.prior.prefix_hash))
        .continuous
    else
        .prefix_changed;
    diagnostic.shape = shape;
    switch (shape) {
        .truncated => {},
        .continuous => return error.TokenUnknownStateMismatch,
        else => return error.UnsupportedDiscontinuity,
    }
    const checkpoint = try readCheckpoint(store, request.jail);
    plan.generation = checkpoint.generation;
    plan.revision = checkpoint.revision;
    plan.next = files.restartedIncarnation(file, plan.prior) catch return error.SourceUnreadable;
    try store.commitTransaction();
    selected = null;
    return plan;
}

const Checkpoint = struct { generation: [32]u8, revision: u64 };

// The jail checkpoint of a file source is the native processor's `F2NT` payload, whose
// bytes 8..40 hold the configuration generation that every source receipt is bound to.
// The repair binds this stored generation and its consumer manifest rather than one
// recomputed from the configuration, which would need the daemon's resolver and consumer
// plans; a configuration changed since the stop is reconciled by the next start.
fn readCheckpoint(store: *Store, jail: []const u8) Error!Checkpoint {
    var row = try store.statement("SELECT payload,revision FROM checkpoints WHERE jail=?1;");
    defer row.deinit();
    try row.text(1, jail);
    if (!try row.row()) return error.InvalidRecord;
    const payload = try row.boundedBytes(0, store_mod.Limits.checkpoint_bytes);
    if ((payload.len != 96 and payload.len != 104) or !std.mem.eql(u8, payload[0..4], "F2NT")) return error.UnsupportedCheckpoint;
    const revision = try row.signed(1);
    if (revision <= 0) return error.InvalidRecord;
    return .{ .generation = payload[8..40].*, .revision = @intCast(revision) };
}

fn requireNoPendingWork(store: *Store, request: Request, plan: Plan) Error!void {
    {
        var row = try store.statement("SELECT 1 FROM pending_receipts WHERE jail=?1 AND source=?2;");
        defer row.deinit();
        try row.text(1, request.jail);
        try row.text(2, plan.source);
        if (try row.row()) return error.PendingReceipt;
    }
    var row = try store.statement("SELECT generation,ready FROM consumer_manifests WHERE jail=?1 AND source=?2;");
    defer row.deinit();
    try row.text(1, request.jail);
    try row.text(2, plan.source);
    if (!try row.row()) return;
    if (try row.signed(1) != 1) return error.ConsumerWorkPending;
    if (!std.mem.eql(u8, &try fixed(32, &row, 0), &plan.generation)) return error.StaleGeneration;
}

// Restat by path and descriptor. This detects, but cannot prevent, a producer writing or
// replacing the file during the repair; the next start still verifies continuity.
fn requireUnchangedFile(request: Request, file: std.fs.File, plan: Plan) Error!void {
    const held = std.posix.fstat(file.handle) catch return error.SourceChanged;
    const named = std.posix.fstatat(std.posix.AT.FDCWD, request.path, 0) catch return error.SourceChanged;
    if (held.dev != named.dev or held.ino != named.ino) return error.SourceChanged;
    if (@as(u64, @intCast(held.dev)) != plan.next.device or @as(u64, @intCast(held.ino)) != plan.next.inode) return error.SourceChanged;
    if (std.math.cast(u64, held.size) != plan.size) return error.SourceChanged;
    const digest = files.prefixDigest(file, plan.next.prefix_len) catch return error.SourceChanged;
    if (!std.mem.eql(u8, &digest, &plan.next.prefix_hash)) return error.SourceChanged;
}

fn commit(store: *Store, allocator: std.mem.Allocator, request: Request, key: [32]u8, file: std.fs.File, plan: Plan, now_us: i64, hooks: Hooks) Error!Outcome {
    const next_cursor = std.json.stringifyAlloc(allocator, plan.next, .{}) catch return error.OutOfMemory;
    defer allocator.free(next_cursor);
    if (next_cursor.len > store_mod.Limits.cursor_bytes) return error.StorageLimit;
    var prior_cursor_sha256: [32]u8 = undefined;
    Sha256.hash(plan.prior_cursor, &prior_cursor_sha256, .{});

    try store.beginWrite();
    var committed = false;
    errdefer if (!committed) store.rollback();
    if (try readRow(store, allocator, request, key)) |prior| {
        errdefer prior.deinit(allocator);
        try store.commitTransaction();
        committed = true;
        return prior;
    }
    if (try store.integer("SELECT count(*) FROM source_repairs;") >= retained_repairs + retained_tombstones) return error.RepairHistoryFull;
    const checkpoint = try readCheckpoint(store, request.jail);
    if (checkpoint.revision != plan.revision) return error.StaleCheckpoint;
    if (!std.mem.eql(u8, &checkpoint.generation, &plan.generation)) return error.StaleGeneration;
    try requireNoPendingWork(store, request, plan);
    try requireUnchangedFile(request, file, plan);
    {
        var row = try store.statement("UPDATE source_cursors SET cursor=?3 WHERE jail=?1 AND source=?2 AND cursor=?4;");
        defer row.deinit();
        try row.text(1, request.jail);
        try row.text(2, plan.source);
        try row.blob(3, next_cursor);
        try row.blob(4, plan.prior_cursor);
        try row.done();
        if (store.api.changes(store.db) != 1) return error.StaleCheckpoint;
    }
    {
        var row = try store.statement("UPDATE checkpoints SET revision=revision+1 WHERE jail=?1 AND revision=?2;");
        defer row.deinit();
        try row.text(1, request.jail);
        try row.int(2, @intCast(plan.revision));
        try row.done();
        if (store.api.changes(store.db) != 1) return error.StaleCheckpoint;
    }
    // Retention orders by this time, so it never moves backwards across repairs.
    const committed_us = blk: {
        var row = try store.statement("SELECT max(?1,coalesce(max(committed_us)+1,?1)) FROM source_repairs;");
        defer row.deinit();
        try row.int(1, now_us);
        if (!try row.row()) return error.DatabaseFailure;
        break :blk try row.signed(0);
    };
    const size = std.math.cast(i64, plan.size) orelse return error.StorageLimit;
    const device = std.math.cast(i64, plan.next.device) orelse return error.StorageLimit;
    const inode = std.math.cast(i64, plan.next.inode) orelse return error.StorageLimit;
    {
        var row = try store.statement("INSERT INTO source_repairs VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13);");
        defer row.deinit();
        try row.blob(1, &key);
        try row.text(2, request.jail);
        try row.text(3, plan.source);
        try row.blob(4, &plan.generation);
        try row.blob(5, &prior_cursor_sha256);
        try row.int(6, @intCast(plan.revision));
        try row.int(7, device);
        try row.int(8, inode);
        try row.int(9, size);
        try row.blob(10, &plan.next.prefix_hash);
        try row.blob(11, &plan.next.incarnation);
        try row.int(12, outcome_truncation_acknowledged);
        try row.int(13, committed_us);
        try row.done();
    }
    {
        var row = try store.statement("UPDATE source_repairs SET outcome=?2,source='-' WHERE outcome<>?2 AND token NOT IN (SELECT token FROM source_repairs WHERE outcome<>?2 ORDER BY committed_us DESC,token DESC LIMIT ?1);");
        defer row.deinit();
        try row.int(1, retained_repairs);
        try row.int(2, outcome_evicted);
        try row.done();
    }
    if (builtin.is_test) if (hooks.fail_at == .before_commit) return error.InjectedFailure;
    try store.commitTransaction();
    committed = true;
    if (builtin.is_test) if (hooks.fail_at == .after_commit) return error.InjectedFailure;
    return .{
        .replayed = false,
        .source = try allocator.dupe(u8, plan.source),
        .generation = plan.generation,
        .prior_checkpoint_revision = plan.revision,
        .prior_cursor_sha256 = prior_cursor_sha256,
        .prior_offset = plan.prior.offset,
        .prior_incarnation = plan.prior.incarnation,
        .new_incarnation = plan.next.incarnation,
        .file = .{ .device = plan.next.device, .inode = plan.next.inode, .size = plan.size, .prefix_sha256 = plan.next.prefix_hash },
        .committed_us = committed_us,
    };
}
