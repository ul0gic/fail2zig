// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Explicit native daemon activation for constant-duration log-only file and
//! qualified SSH journal jails. Unsupported protection is refused before state IO.
//! A single worker owns SQLite and sources; IPC/HTTP read detached snapshots.
const std = @import("std");
const shared = @import("shared");
const config = @import("config/native.zig");
const projection = @import("config/native_file_detection.zig");
const retry_config = @import("config/native_retry_policy.zig");
const retry = @import("core/native_retry.zig");
const durable = @import("core/record_store.zig");
const sessions = @import("core/native_file_session.zig");
const journal_projection = @import("config/native_journal_detection.zig");
const journal_sessions = @import("core/native_journal_session.zig");
const pipeline = @import("core/record_pipeline.zig");
const health = @import("core/storage_health.zig");
const recovery = @import("core/native_recovery.zig");
const loop_mod = @import("core/event_loop.zig");
const ipc = @import("net/ipc.zig");
const http = @import("net/http.zig");
const version = @import("build_options").version;
const max_jails = 64;
const max_sources_per_jail = 8;
const max_subjects_total = 4096;

const Plan = union(enum) {
    file: projection.Plan,
    journal: *journal_projection.Plan,
    fn deinit(self: *Plan, a: std.mem.Allocator) void {
        switch (self.*) {
            .file => |*plan| plan.deinit(a),
            .journal => |plan| plan.destroy(),
        }
    }
};
const Source = union(enum) {
    file: *sessions.Session,
    journal: *journal_sessions.Session,
    fn destroy(self: Source) void {
        switch (self) {
            .file => |source| source.destroy(),
            .journal => |source| source.destroy(),
        }
    }
    fn pipe(self: Source) *pipeline.Pipeline {
        return switch (self) {
            .file => |source| &source.pipe,
            .journal => |source| &source.pipe,
        };
    }
    fn poll(self: Source) !void {
        switch (self) {
            .file => |source| {
                _ = try source.poll(max_sources_per_jail);
            },
            .journal => |source| {
                _ = try source.poll(1);
            },
        }
    }
    fn verify(self: Source) !void {
        switch (self) {
            .file => |source| try source.verifyRecoverySources(),
            .journal => |source| try source.verifyRecoverySources(),
        }
    }
    fn healthy(self: Source) bool {
        return switch (self) {
            .file => |source| source.sources.sources.items.len > 0,
            .journal => |source| source.source_health == .healthy,
        };
    }
};
const Jail = struct {
    name: []const u8,
    plan: Plan,
    policy: retry.Policy,
    session: ?Source = null,
    /// Worker builds a full detached snapshot before locking its published copy.
    scratch: []durable.Store.ActiveDecision,
    active: []durable.Store.ActiveDecision,
    summary: durable.Store.RetrySummary = .{},
    revision: u64 = 0,
    healthy: bool = false,
    source_error: ?anyerror = null,
};

pub const Coordinator = struct {
    allocator: std.mem.Allocator,
    cfg: *const config.Config,
    jails: []Jail,
    store: durable.Store,
    store_open: bool = false,
    timer: std.time.Timer,
    gate: health.Gate,
    published_health: health.Snapshot,
    mutex: std.Thread.Mutex = .{},
    stop_mutex: std.Thread.Mutex = .{},
    wake: std.Thread.Condition = .{},
    stopping: bool = false,
    thread: ?std.Thread = null,
    start_us: i64,
    last_notice: u64 = 0,

    fn monotonic(ctx: ?*anyopaque) u64 {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        return self.timer.read() / std.time.ns_per_ms;
    }

    /// Immutable config must outlive this stable owner. All plans and aggregate
    /// allowances are validated before the database is opened or upgraded.
    pub fn create(a: std.mem.Allocator, cfg: *const config.Config) !*Coordinator {
        if (cfg.global.compatibility_pending) return error.CompatibilityNotAdmitted;
        var count: usize = 0;
        for (cfg.jails) |jail| if (jail.enabled) {
            count += 1;
        };
        if (count == 0 or count > max_jails) return error.NativeJailLimit;
        const per_jail: u32 = @intCast(max_subjects_total / count);
        const self = try a.create(Coordinator);
        errdefer a.destroy(self);
        const timer = try std.time.Timer.start();
        self.* = .{ .allocator = a, .cfg = cfg, .jails = try a.alloc(Jail, count), .store = undefined, .timer = timer, .gate = undefined, .published_health = undefined, .start_us = std.time.microTimestamp() };
        errdefer a.free(self.jails);
        self.gate = health.Gate.init(.{ .context = self, .read = monotonic });
        self.published_health = self.gate.snapshot();
        var prepared: usize = 0;
        errdefer for (self.jails[0..prepared]) |*jail| {
            jail.plan.deinit(a);
            a.free(jail.scratch);
            a.free(jail.active);
        };
        var reserved_bytes: usize = max_subjects_total * @sizeOf(durable.Store.ActiveDecision) * 2;
        for (cfg.jails) |*jail_cfg| {
            if (!jail_cfg.enabled) continue;
            const policy = try retry_config.fromJail(jail_cfg, cfg.defaults, per_jail);
            if (policy.enforce) return error.NativeEnforcementNotIntegrated;
            var selected = jail_cfg.*;
            if (selected.source == .auto) selected.source = cfg.defaults.source;
            if (selected.source == .auto) selected.source = if (config.anyLogpathExists(selected.logpath)) .file else if (config.filterSupportsJournald(selected.filter) and config.journalctlPresent()) .journald else .file;
            var selected_cfg = cfg.*;
            selected_cfg.jails = @constCast((&selected)[0..1]);
            var plan: Plan = switch (selected.source) {
                .file => blk: {
                    if (selected.journal_executables.len != 0) return error.UnusedJournalProfile;
                    const timestamp = selected.timestamp orelse return error.NativeTimestampRequired;
                    if (timestamp != .syslog and selected.timezone_offset_minutes != null) return error.UnusedTimezoneOffset;
                    var settings = projection.Settings{ .timestamp = undefined, .body = if (timestamp == .undated) .whole else .syslog, .start = .head, .max_sources = max_sources_per_jail, .ignore_capacity = 128 };
                    settings.timestamp = switch (timestamp) {
                        .undated => .undated,
                        .iso8601 => .{ .field = .{ .format = .iso8601, .boundary = .{ .delimiter = ' ' } } },
                        .syslog => .{ .field = .{ .format = .syslog, .boundary = .{ .length = 15 }, .infer_year = true, .context = .{ .offset_seconds = @as(i32, selected.timezone_offset_minutes orelse return error.NativeTimezoneRequired) * 60 } } },
                    };
                    reserved_bytes += 1024 * 1024;
                    break :blk .{ .file = try projection.Plan.init(a, &selected_cfg, 0, [_]u8{0} ** 32, settings) };
                },
                .journald => blk: {
                    if (selected.timestamp != null or selected.timezone_offset_minutes != null) return error.UnusedFileTimestamp;
                    if (selected.journal_executables.len == 0 or selected.journal_executables.len > 8) return error.InvalidJournalExecutables;
                    for (selected.journal_executables) |executable| {
                        var file = try std.fs.openFileAbsolute(executable, .{});
                        defer file.close();
                        const stat = try std.posix.fstat(file.handle);
                        if (!std.posix.S.ISREG(stat.mode) or stat.uid != 0 or stat.mode & 0o022 != 0 or stat.mode & 0o111 == 0) return error.UnqualifiedJournalExecutable;
                    }
                    const machine = try std.fs.cwd().readFileAlloc(a, "/etc/machine-id", 33);
                    defer a.free(machine);
                    reserved_bytes += 2 * 1024 * 1024;
                    break :blk .{ .journal = try journal_projection.Plan.create(a, &selected_cfg, 0, [_]u8{0} ** 32, .{ .machine_id = std.mem.trim(u8, machine, "\n"), .executables = selected.journal_executables, .ignore_capacity = 128, .journal = .{ .batch_records = 1, .matches = &.{ "SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session", "+", "_COMM=sshd", "_COMM=sshd-session" } } }) };
                },
                .auto => unreachable,
                .internal => return error.NativeInternalEventsRequired,
            };
            errdefer plan.deinit(a);
            if (reserved_bytes > 64 * 1024 * 1024) return error.NativeMemoryAdmission;
            const scratch = try a.alloc(durable.Store.ActiveDecision, per_jail);
            errdefer a.free(scratch);
            const active = try a.alloc(durable.Store.ActiveDecision, per_jail);
            self.jails[prepared] = .{ .name = selected.name, .plan = plan, .policy = policy, .scratch = scratch, .active = active };
            prepared += 1;
        }
        self.store = try durable.Store.open(a, cfg.global.state_file);
        self.store_open = true;
        errdefer self.store.close();
        try self.admitStore();
        errdefer for (self.jails) |jail| if (jail.session) |session| session.destroy();
        var recovery_driver = self.driver();
        _ = try recovery_driver.poll();
        self.publishHealth();
        return self;
    }

    fn admitStore(self: *Coordinator) !void {
        try self.store.configureRuntimeLimits();
        try self.store.enableReceipts(self.jails.len * max_sources_per_jail);
        try self.store.enableNativeTime();
        try self.store.enableDetection();
        try self.store.enableClockRecovery();
        try self.store.enableJournalDetection();
        try self.store.enableRetry();
        self.store.runtime_path = self.cfg.global.state_file;
        var names: [max_jails][]const u8 = undefined;
        for (self.jails, 0..) |jail, i| names[i] = jail.name;
        try self.store.validateRuntimeOwners(names[0..self.jails.len]);
    }
    fn driver(self: *Coordinator) recovery.Driver {
        return .{ .store = &self.store, .gate = &self.gate, .clock = .{ .generation = [_]u8{0} ** 32 }, .hooks = .{ .context = self, .storage = recoverStorage, .state = recoverState, .ownership = recoverOwnership, .sources = recoverSources } };
    }
    fn recoverStorage(ctx: ?*anyopaque) !void {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        if (self.gate.snapshot().has_been_healthy) {
            if (self.store_open) {
                self.store.close();
                self.store_open = false;
                // The recovery driver reads diagnostics even if reopen fails.
                self.store.last_error_code = null;
                self.store.rollback_error_code = null;
                self.store.reopen_required = true;
            }
            self.store = try durable.Store.open(self.allocator, self.cfg.global.state_file);
            self.store_open = true;
            try self.admitStore();
        }
    }
    fn recoverState(ctx: ?*anyopaque) !void {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        for (self.jails) |*jail| {
            const next: Source = switch (jail.plan) {
                .file => |*plan| blk: {
                    var options = plan.sessionOptions();
                    options.retry = jail.policy;
                    options.gate = &self.gate;
                    break :blk .{ .file = try sessions.Session.create(self.allocator, &self.store, options, plan.specs) };
                },
                .journal => |plan| blk: {
                    var options = plan.sessionOptions();
                    options.retry = jail.policy;
                    options.gate = &self.gate;
                    break :blk .{ .journal = try journal_sessions.Session.create(self.allocator, &self.store, options) };
                },
            };
            if (jail.session) |old| {
                // An observation whose first receipt write failed still owns its
                // original in-memory receipt time throughout runtime recovery.
                next.pipe().candidate_receipt = old.pipe().candidate_receipt;
                if (old == .file and next == .file and old.pipe().candidate_receipt != null) {
                    const failed = old.file.sources.sources.items[old.file.next_source].source_id;
                    for (next.file.sources.sources.items, 0..) |source, index| {
                        if (std.mem.eql(u8, source.source_id, failed)) {
                            next.file.next_source = index;
                            break;
                        }
                    } else {
                        next.destroy();
                        return error.PendingSourceMissing;
                    }
                }
                old.destroy();
            }
            jail.session = next;
        }
    }
    fn recoverOwnership(ctx: ?*anyopaque) !void {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        for (self.jails) |*jail| {
            if (jail.policy.enforce) return error.NativeEnforcementNotIntegrated;
            try self.publishJail(jail);
        }
    }
    fn recoverSources(ctx: ?*anyopaque) !void {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        for (self.jails) |*jail| try jail.session.?.verify();
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.jails) |*jail| jail.source_error = null;
    }
    fn publishJail(self: *Coordinator, jail: *Jail) !void {
        const summary = try self.store.retrySummary(jail.name, std.time.microTimestamp(), jail.scratch);
        const session = jail.session.?;
        self.mutex.lock();
        defer self.mutex.unlock();
        @memcpy(jail.active[0..summary.active], jail.scratch[0..summary.active]);
        jail.summary = summary;
        jail.revision = session.pipe().revision;
        jail.healthy = session.healthy();
    }
    fn publishHealth(self: *Coordinator) void {
        const snapshot = self.gate.snapshot();
        self.mutex.lock();
        self.published_health = snapshot;
        self.mutex.unlock();
        if (snapshot.notice_sequence != self.last_notice) {
            self.last_notice = snapshot.notice_sequence;
            std.log.info("native ingestion: {s}; cause={s}; committed={d}", .{ @tagName(snapshot.phase), if (snapshot.last_failure) |failure| @errorName(failure.cause) else "none", snapshot.committed_records });
        }
    }
    pub fn start(self: *Coordinator) !void {
        self.thread = try std.Thread.spawn(.{}, work, .{self});
    }
    fn work(self: *Coordinator) void {
        while (true) {
            self.stop_mutex.lock();
            if (self.stopping) {
                self.stop_mutex.unlock();
                return;
            }
            self.stop_mutex.unlock();
            self.tick() catch |failure| {
                if (!self.gate.snapshot().has_been_healthy and failure != error.ReceiptClockReversed) {
                    std.log.err("native: startup recovery failed: {s}; refusing to start", .{@errorName(failure)});
                    std.process.exit(1);
                }
                if (self.gate.snapshot().phase == .healthy) self.gate.failed(failure, .{ .sqlite_code = if (self.store_open) self.store.last_error_code else null, .reopen_required = !self.store_open or self.store.reopen_required });
            };
            self.publishHealth();
            self.stop_mutex.lock();
            if (!self.stopping) self.wake.timedWait(&self.stop_mutex, 100 * std.time.ns_per_ms) catch {};
            const stopped = self.stopping;
            self.stop_mutex.unlock();
            if (stopped) return;
        }
    }
    fn tick(self: *Coordinator) !void {
        if (self.gate.snapshot().phase != .healthy) {
            var recovery_driver = self.driver();
            _ = try recovery_driver.poll();
            return;
        }
        for (self.jails) |*jail| {
            if (jail.source_error != null) continue;
            try self.store.maintainWal(self.cfg.global.state_file);
            jail.session.?.poll() catch |failure| {
                // SQL failures have already closed the shared gate. Decode or
                // continuity failures belong to this jail and must not stop
                // independent owners of the same healthy store.
                if (self.gate.snapshot().phase != .healthy) return failure;
                self.mutex.lock();
                jail.source_error = failure;
                jail.healthy = false;
                self.mutex.unlock();
                std.log.err("native jail {s}: {s}; source paused pending repair", .{ jail.name, @errorName(failure) });
                continue;
            };
            try self.publishJail(jail);
        }
    }
    pub fn destroy(self: *Coordinator) void {
        self.stop_mutex.lock();
        self.stopping = true;
        self.wake.signal();
        self.stop_mutex.unlock();
        if (self.thread) |thread| thread.join();
        for (self.jails) |*jail| {
            if (jail.session) |session| session.destroy();
            jail.plan.deinit(self.allocator);
            self.allocator.free(jail.scratch);
            self.allocator.free(jail.active);
        }
        if (self.store_open) self.store.close();
        self.allocator.free(self.jails);
        self.allocator.destroy(self);
    }
    fn status(ctx: ?*anyopaque, out: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator) !void {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        self.mutex.lock();
        defer self.mutex.unlock();
        const gate = self.published_health;
        var healthy = gate.phase == .healthy;
        var decisions: u64 = 0;
        for (self.jails) |jail| {
            healthy = healthy and jail.healthy;
            decisions +|= jail.summary.decisions;
        }
        try std.json.stringify(.{ .version = version, .runtime = "native", .state = if (healthy) "log-only" else "degraded", .protection = if (healthy) "log-only" else "degraded", .active_bans = @as(u32, 0), .total_bans = @as(u64, 0), .storage = @tagName(gate.phase), .cause = if (gate.last_failure) |failure| @errorName(failure.cause) else "none", .sqlite_code = if (gate.last_failure) |failure| failure.diagnostics.sqlite_code else null, .next_retry_ms = gate.next_retry_ms, .committed_records = gate.committed_records, .decisions_total = decisions, .jails_active = self.jails.len, .backend = "none", .uptime_seconds = @as(u64, @intCast(@max(0, @divTrunc(std.time.microTimestamp() -| self.start_us, 1_000_000)))) }, .{}, out.writer(a));
    }
    fn bans(ctx: ?*anyopaque, out: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator) !void {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        try self.writeBans(out, a, null);
    }
    fn writeBans(self: *Coordinator, out: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator, selected: ?shared.JailId) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const w = out.writer(a);
        try w.writeAll("[");
        var first = true;
        for (self.jails) |jail| {
            if (selected) |name| if (!std.mem.eql(u8, name.slice(), jail.name)) continue;
            for (jail.active[0..jail.summary.active]) |decision| {
                if (decision.expiry_us <= std.time.microTimestamp()) continue;
                if (!first) try w.writeByte(',');
                first = false;
                const address: shared.IpAddress = switch (decision.subject) {
                    .v4 => |v| .{ .ipv4 = std.mem.readInt(u32, &v, .big) },
                    .v6 => |v| .{ .ipv6 = std.mem.readInt(u128, &v, .big) },
                };
                var buffer: [64]u8 = undefined;
                const formatted = try std.fmt.bufPrint(&buffer, "{}", .{address});
                try std.json.stringify(.{ .ip = formatted, .jail = jail.name, .expiry_us = decision.expiry_us, .ban_expiry = @divFloor(decision.expiry_us, 1_000_000), .ban_count = decision.ordinal, .enforced = false, .confirmed = false }, .{}, w);
            }
        }
        try w.writeAll("]");
        if (out.items.len > shared.protocol.max_payload_size - 16) return error.SnapshotLimit;
    }
    fn metrics(ctx: ?*anyopaque, out: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator) !void {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        self.mutex.lock();
        defer self.mutex.unlock();
        try out.writer(a).print("fail2zig_up 1\nfail2zig_native_storage_healthy {d}\nfail2zig_native_committed_records {d}\n", .{ @intFromBool(self.published_health.phase == .healthy), self.published_health.committed_records });
    }
    fn command(ctx: ?*anyopaque, cmd: shared.Command, a: std.mem.Allocator) !shared.Response {
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        var output: std.ArrayListUnmanaged(u8) = .{};
        defer output.deinit(a);
        switch (cmd) {
            .status => try status(self, &output, a),
            .version => try std.json.stringify(.{ .daemon_version = version }, .{}, output.writer(a)),
            .list => |selected| try self.writeBans(&output, a, selected.jail),
            .list_jails => {
                self.mutex.lock();
                defer self.mutex.unlock();
                const w = output.writer(a);
                try w.writeAll("[");
                for (self.jails, 0..) |jail, index| {
                    if (index > 0) try w.writeByte(',');
                    try std.json.stringify(.{ .name = jail.name, .healthy = jail.healthy and self.published_health.phase == .healthy, .enabled = true, .active_bans = @as(u32, 0), .maxretry = jail.policy.maxretry, .findtime = @divTrunc(jail.policy.window_us, 1_000_000), .bantime = @divTrunc(jail.policy.bantime_us, 1_000_000), .action = "log-only", .enforcing = false, .log_source = @tagName(jail.plan), .source_healthy = jail.healthy and self.published_health.phase == .healthy, .source = @tagName(jail.plan), .revision = jail.revision, .decisions = jail.summary.decisions, .cause = if (jail.source_error) |cause| @errorName(cause) else "none" }, .{}, w);
                }
                try w.writeAll("]");
            },
            .ban, .unban, .reload => return .{ .err = .{ .code = 503, .message = try a.dupe(u8, "Native administrative mutation is not integrated; no state was changed") } },
        }
        return .{ .ok = .{ .payload = try output.toOwnedSlice(a) } };
    }
};

fn terminate(_: *const std.os.linux.signalfd_siginfo, ctx: ?*anyopaque) void {
    const loop: *loop_mod.EventLoop = @ptrCast(@alignCast(ctx.?));
    loop.stop();
}
fn reload(_: *const std.os.linux.signalfd_siginfo, _: ?*anyopaque) void {
    std.log.warn("native reload is not integrated; current configuration retained", .{});
}
pub fn run(a: std.mem.Allocator, cfg: *const config.Config) !void {
    const coordinator = try Coordinator.create(a, cfg);
    defer coordinator.destroy();
    var loop = try loop_mod.EventLoop.init(a);
    defer loop.deinit();
    // Block signals before starting the worker so it inherits the signal mask.
    try loop.addSignalHandler(std.os.linux.SIG.TERM, terminate, &loop);
    try loop.addSignalHandler(std.os.linux.SIG.INT, terminate, &loop);
    try loop.addSignalHandler(std.os.linux.SIG.HUP, reload, &loop);
    var server = try ipc.IpcServer.init(a, &loop, cfg.global.socket_path);
    defer server.deinit();
    server.setCommandHandler(.{ .ctx = coordinator, .dispatch = Coordinator.command });
    try server.start();
    var web: ?http.HttpServer = null;
    defer if (web) |*value| value.deinit();
    if (cfg.global.metrics_enabled) {
        web = try http.HttpServer.init(a, &loop, cfg.global.metrics_port, cfg.global.metrics_bind);
        web.?.setStatusSource(.{ .ctx = coordinator, .write = Coordinator.status });
        web.?.setBansSource(.{ .ctx = coordinator, .write = Coordinator.bans });
        web.?.setMetricsSource(.{ .ctx = coordinator, .write = Coordinator.metrics });
        try web.?.start();
    }
    try coordinator.start();
    std.log.info("fail2zig {s} running; native SQLite ingestion; log-only; ipc={s}", .{ version, cfg.global.socket_path });
    try loop.run();
}
