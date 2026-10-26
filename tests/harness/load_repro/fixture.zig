// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const engine = @import("engine_test");
const durable = engine.core.record_store;
const effects = engine.core.native_effect;
const history = engine.core.native_effect_history;
const detection = engine.core.native_detection_record;
const retry = engine.core.native_retry;
const action = engine.core.native_action_outcome;
const time_policy = engine.core.source_time_policy;

const usage =
    \\usage: f2z-load-fixture <churn|hot|pinned|reuse|oracle-cases> <out-dir> [key=value...]
    \\       f2z-load-fixture attach <state-dir> jail=NAME[,NAME...] count=N [address_start=N normalize=1|0 seed=N evidence=N sync=full|off]
    \\       f2z-load-fixture pool-contract <out-dir> [resource=1]
    \\       f2z-load-fixture history-attach <state-dir> jail=NAME [rounds=1..64]
    \\keys: seed count interval_ms bantime_s gap_ms evidence jails churn retention_s max_matches retention=shipped|skip sync=full|off profile=1 (per-statement SQLite VM steps on stderr) audit=full|skip (skip the final-state audit)
    \\attach appends count bans to the daemon state fail2zig.sqlite in state-dir, round-robin over up to 16 existing jails under each jail's own generation and policy (bantime_s is ignored),
    \\with addresses 198.19.0.0/16 from address_start (address_start + count <= 65536); normalize=1 runs the history consumer and retention to the head, normalize=0 leaves the backlog declared
    \\
;
const second_us: i64 = 1_000_000;
// 2026-01-01T00:00:00Z; every state starts here so identical arguments give identical rows.
const epoch_us: i64 = 1_767_225_600 * second_us;
const source_name = "fixture";
const max_maintenance_steps = 100_000;
const max_attach_jails = 16;
// 198.19.0.0/16; the rig's first 65,536 generated addresses occupy 198.18.0.0/16.
const attach_addresses = 1 << 16;
// Receipt, effect and maintenance floors reject only a smaller value, so 1 µs keeps receipts distinct and monotonic.
const attach_step_us: i64 = 1;
const attach_sample_bans = 1024;
const batch_records = durable.Store.attribution_batch;
const Timestamp = @FieldType(durable.Receipt, "time");
// The daemon binds its history consumer to this constant policy generation.
fn historyPolicyGeneration() [32]u8 {
    return effects.hashParts("fail2zig-native-confirmed-history-v1", &.{});
}
const key_tables = [_][]const u8{ "native_effects", "effect_owners", "effect_owner_revisions", "effect_intents", "effect_observations", "action_targets", "confirmed_effect_events", "confirmed_event_details", "confirmed_history_sequence", "retry_decision_details", "retry_decisions", "retry_states", "records" };

const Shape = enum { churn, hot, pinned, reuse, @"oracle-cases", attach };
const RetentionMode = enum { shipped, skip };
const SyncMode = enum { full, off };
const AuditMode = enum { full, skip };

// SQLITE_TRACE_PROFILE: the callback receives the finished statement and a pointer to its elapsed nanoseconds.
const sqlite_trace_profile: c_uint = 0x02;
const sqlite3_trace_v2 = @extern(*const fn (*anyopaque, c_uint, ?*const fn (c_uint, ?*anyopaque, ?*anyopaque, ?*anyopaque) callconv(.c) c_int, ?*anyopaque) callconv(.c) c_int, .{ .name = "sqlite3_trace_v2" });
const sqlite3_sql = @extern(*const fn (?*anyopaque) callconv(.c) ?[*:0]const u8, .{ .name = "sqlite3_sql" });
const sqlite3_stmt_status = @extern(*const fn (?*anyopaque, c_int, c_int) callconv(.c) c_int, .{ .name = "sqlite3_stmt_status" });
const sqlite_stmtstatus_fullscan_step: c_int = 1;
const sqlite_stmtstatus_vm_step: c_int = 4;
const sqlite3_db_status64 = @extern(*const fn (*anyopaque, c_int, *i64, *i64, c_int) callconv(.c) c_int, .{ .name = "sqlite3_db_status64" });
const sqlite_dbstatus_cache_hit: c_int = 7;
const sqlite_dbstatus_cache_miss: c_int = 8;

const Profile = struct {
    const Stat = struct { ns: u64 = 0, calls: u64 = 0, steps: u64 = 0, fullscan: u64 = 0 };
    var allocator: std.mem.Allocator = undefined;
    var map: ?std.StringHashMap(Stat) = null;
    var total_ns: u64 = 0;
    var dropped: u64 = 0;

    fn install(db: *anyopaque, alloc: std.mem.Allocator) void {
        if (map == null) {
            allocator = alloc;
            map = std.StringHashMap(Stat).init(alloc);
        }
        _ = sqlite3_trace_v2(db, sqlite_trace_profile, callback, null);
    }
    fn callback(kind: c_uint, _: ?*anyopaque, statement: ?*anyopaque, elapsed: ?*anyopaque) callconv(.c) c_int {
        if (kind != sqlite_trace_profile or statement == null or elapsed == null) return 0;
        const ns: u64 = @intCast(@max(0, @as(*const i64, @ptrCast(@alignCast(elapsed.?))).*));
        total_ns += ns;
        const text = sqlite3_sql(statement) orelse return 0;
        const m = &(map orelse return 0);
        const entry = m.getOrPut(std.mem.span(text)) catch {
            dropped += 1;
            return 0;
        };
        if (!entry.found_existing) {
            entry.key_ptr.* = allocator.dupe(u8, std.mem.span(text)) catch {
                _ = m.remove(std.mem.span(text));
                dropped += 1;
                return 0;
            };
            entry.value_ptr.* = .{};
        }
        entry.value_ptr.ns += ns;
        entry.value_ptr.calls += 1;
        entry.value_ptr.steps += @intCast(@max(0, sqlite3_stmt_status(statement, sqlite_stmtstatus_vm_step, 1)));
        entry.value_ptr.fullscan += @intCast(@max(0, sqlite3_stmt_status(statement, sqlite_stmtstatus_fullscan_step, 1)));
        return 0;
    }
    fn printRow(writer: anytype, sql: []const u8, stat: Stat, total: u64) !void {
        const share = @as(f64, @floatFromInt(stat.ns)) * 100 / @as(f64, @floatFromInt(@max(total, 1)));
        try writer.print("{d:6.1}% {d:8.1} ms {d:8} calls {d:12} steps {d:10} steps/call {d:9} fullscan  {s}\n", .{ share, @as(f64, @floatFromInt(stat.ns)) / 1e6, stat.calls, stat.steps, stat.steps / @max(stat.calls, 1), stat.fullscan, sql[0..@min(sql.len, 160)] });
    }
    fn capacityCount(sql: []const u8) bool {
        const prefix = "SELECT count(*) FROM ";
        if (!std.mem.startsWith(u8, sql, prefix) or !std.mem.endsWith(u8, sql, ";")) return false;
        const table = sql[prefix.len .. sql.len - 1];
        if (table.len == 0) return false;
        for (table) |c| if (!std.ascii.isAlphanumeric(c) and c != '_') return false;
        return true;
    }
    fn report(writer: anytype, bans: u64) !void {
        const m = &(map orelse return);
        const Row = struct { sql: []const u8, stat: Stat };
        var rows = std.ArrayList(Row).init(allocator);
        defer rows.deinit();
        var it = m.iterator();
        var steps_total: u64 = 0;
        while (it.next()) |kv| {
            try rows.append(.{ .sql = kv.key_ptr.*, .stat = kv.value_ptr.* });
            steps_total += kv.value_ptr.steps;
        }
        std.mem.sort(Row, rows.items, {}, struct {
            fn less(_: void, a: Row, b: Row) bool {
                return a.stat.ns > b.stat.ns;
            }
        }.less);
        try writer.print("sqlite profile: {d} statements, {d} VM steps total ({d} per ban over {d} bans), {d:.1} ms total at millisecond resolution, {d} dropped; ranked by elapsed time\n", .{ rows.items.len, steps_total, if (bans == 0) 0 else steps_total / bans, bans, @as(f64, @floatFromInt(total_ns)) / 1e6, dropped });
        for (rows.items[0..@min(rows.items.len, 40)]) |row| try printRow(writer, row.sql, row.stat, total_ns);
        try writer.writeAll("capacity counts:\n");
        for (rows.items) |row| if (capacityCount(row.sql)) try printRow(writer, row.sql, row.stat, total_ns);
        var keys = m.keyIterator();
        while (keys.next()) |key| allocator.free(key.*);
        m.deinit();
        map = null;
    }
};

// Times the Store's statement lifecycle; the trace profile sees only execution, never preparation.
const SqliteApi = struct {
    const Api = @FieldType(durable.Store, "api");
    const Stat = struct { calls: u64 = 0, ns: u64 = 0 };
    var original: Api = undefined;
    var totals: struct { prepare: Stat = .{}, step: Stat = .{}, finalize: Stat = .{}, exec: Stat = .{} } = .{};
    var timer: std.time.Timer = undefined;
    var installed = false;

    fn install(api: *Api) !void {
        if (!installed) {
            timer = try std.time.Timer.start();
            original = api.*;
            installed = true;
        }
        api.prepare = timedPrepare;
        api.step = timedStep;
        api.finalize = timedFinalize;
        api.exec = timedExec;
    }
    fn Arg(comptime field: []const u8, comptime index: usize) type {
        return @typeInfo(@typeInfo(@FieldType(Api, field)).pointer.child).@"fn".params[index].type.?;
    }
    fn note(stat: *Stat, started: u64) void {
        stat.calls += 1;
        stat.ns += timer.read() - started;
    }
    fn timedPrepare(db: Arg("prepare", 0), sql: Arg("prepare", 1), bytes: Arg("prepare", 2), statement: Arg("prepare", 3), tail: Arg("prepare", 4)) callconv(.c) c_int {
        const started = timer.read();
        defer note(&totals.prepare, started);
        return original.prepare(db, sql, bytes, statement, tail);
    }
    fn timedStep(statement: Arg("step", 0)) callconv(.c) c_int {
        const started = timer.read();
        defer note(&totals.step, started);
        return original.step(statement);
    }
    fn timedFinalize(statement: Arg("finalize", 0)) callconv(.c) c_int {
        const started = timer.read();
        defer note(&totals.finalize, started);
        return original.finalize(statement);
    }
    fn timedExec(db: Arg("exec", 0), sql: Arg("exec", 1), callback: Arg("exec", 2), context: Arg("exec", 3), message: Arg("exec", 4)) callconv(.c) c_int {
        const started = timer.read();
        defer note(&totals.exec, started);
        return original.exec(db, sql, callback, context, message);
    }
};

const Options = struct {
    seed: u64 = 1,
    count: u64 = 0,
    interval_ms: u64 = 1000,
    bantime_s: u64 = 60,
    gap_ms: u64 = 1000,
    evidence: usize = 198,
    jails: u8 = 1,
    churn: u64 = 150,
    retention_s: i64 = 86_400,
    max_matches: u16 = 10,
    retention: RetentionMode = .shipped,
    sync: SyncMode = .full,
    jail: []const u8 = "portsentry",
    profile: bool = false,
    audit: AuditMode = .full,
    cache_kib: u64 = 0,
    normalize: bool = true,
    address_start: u32 = 0,

    fn defaults(shape: Shape) Options {
        return switch (shape) {
            .churn => .{ .count = 5000, .interval_ms = 200, .bantime_s = 60 },
            .hot => .{ .count = 40_000, .bantime_s = 1, .gap_ms = 1000 },
            .pinned => .{ .churn = 150, .interval_ms = 1000, .bantime_s = 60 },
            .reuse => .{ .count = 300, .bantime_s = 600, .gap_ms = 100_000 },
            .@"oracle-cases" => .{ .bantime_s = 10 },
            .attach => .{ .count = 65_536, .bantime_s = 86_400 * 7 },
        };
    }
    fn set(self: *Options, key: []const u8, value: []const u8) !void {
        if (std.mem.eql(u8, key, "jail")) {
            var seen: [max_attach_jails][]const u8 = undefined;
            var count: usize = 0;
            var names = std.mem.splitScalar(u8, value, ',');
            while (names.next()) |name| {
                if (name.len == 0 or name.len > 64 or count == max_attach_jails) return error.InvalidOption;
                for (seen[0..count]) |prior| if (std.mem.eql(u8, prior, name)) return error.InvalidOption;
                seen[count] = name;
                count += 1;
            }
            self.jail = value;
            return;
        }
        if (std.mem.eql(u8, key, "normalize")) {
            if (value.len != 1 or (value[0] != '0' and value[0] != '1')) return error.InvalidOption;
            self.normalize = value[0] == '1';
            return;
        }
        if (std.mem.eql(u8, key, "retention")) {
            self.retention = std.meta.stringToEnum(RetentionMode, value) orelse return error.InvalidOption;
            return;
        }
        if (std.mem.eql(u8, key, "profile")) {
            if (!std.mem.eql(u8, value, "1")) return error.InvalidOption;
            self.profile = true;
            return;
        }
        if (std.mem.eql(u8, key, "audit")) {
            self.audit = std.meta.stringToEnum(AuditMode, value) orelse return error.InvalidOption;
            return;
        }
        if (std.mem.eql(u8, key, "sync")) {
            self.sync = std.meta.stringToEnum(SyncMode, value) orelse return error.InvalidOption;
            return;
        }
        inline for (.{ "seed", "count", "interval_ms", "bantime_s", "gap_ms", "evidence", "jails", "churn", "retention_s", "max_matches", "cache_kib", "address_start" }) |name| {
            if (std.mem.eql(u8, key, name)) {
                @field(self, name) = try std.fmt.parseInt(@TypeOf(@field(self, name)), value, 10);
                return;
            }
        }
        return error.InvalidOption;
    }
    fn validate(self: Options, shape: Shape) !void {
        if (shape == .attach and self.address_start + self.count > attach_addresses) return error.InvalidOption;
        if (self.bantime_s == 0 or self.bantime_s > 86_400 * 365 or self.interval_ms == 0 or self.jails == 0 or self.jails > 16 or
            self.evidence > retry.max_evidence_text_bytes or self.retention_s < 0 or self.retention_s > 86_400 * 3650 or
            self.max_matches > 1024 or self.count > 1_000_000 or self.churn > 100_000 or self.gap_ms > 86_400_000) return error.InvalidOption;
    }
};

const Clock = struct {
    now: i64 = epoch_us,
    fn read(ctx: ?*anyopaque) i64 {
        const self: *Clock = @ptrCast(@alignCast(ctx.?));
        return self.now;
    }
    fn value(self: *Clock) effects.Clock {
        return .{ .prepared_us = self.now, .context = self, .read = read };
    }
    fn advanceMs(self: *Clock, ms: u64) void {
        self.now += @as(i64, @intCast(ms)) * 1000;
    }
};

const Jail = struct { name: []const u8, generation: [32]u8, policy: retry.Policy, checkpoint: ?[]u8 = null, records: u64 = 0, appended: u64 = 0 };
const Chunk = struct { cycle: u64, elapsed_ns: u64, cache_hits: i64, cache_misses: i64 };
const Timings = struct { open: u64 = 0, restore: u64 = 0, base_catchup: u64 = 0, append: u64 = 0, final_normalize: u64 = 0, close: u64 = 0, audit: u64 = 0 };
const Schedule = struct { receipt_floor_us: ?i64 = null, admission_floor_us: ?i64 = null, start_us: i64 = 0, end_us: i64 = 0, wall_end_us: i64 = 0, step_us: i64 = attach_step_us, future_dated: bool = false };
const HistoryProgress = struct { restored_sequence: u64 = 0, base_backlog: u64 = 0, head: u64 = 0, checkpoint: u64 = 0, backlog: u64 = 0 };
const AttachReport = struct {
    schedule: Schedule = .{},
    history: HistoryProgress = .{},
    timings: Timings = .{},
    base_live_native_effects: i64 = 0,
    base_live_effect_owners: i64 = 0,
    chunks: std.ArrayListUnmanaged(Chunk) = .{},
};
const Lease = struct { key: effects.Hash, deadline: i64 };
const Refusal = struct { cycle: u64, operation: []const u8, error_name: []const u8 };
const StoreFailure = struct { operation: []const u8, failure: anyerror };
const Phase = struct { label: []const u8, cycle: u64, clock_us: i64, counts: [key_tables.len]i64, retained_from: i64, head: i64 };
const Stats = struct {
    bans: u64 = 0,
    kept_existing: u64 = 0,
    expired: u64 = 0,
    history_pages: u64 = 0,
    retention_deleted: u64 = 0,
    retention_calls: u64 = 0,
    retry_details_pruned: u64 = 0,
    spent_scope_batches: u64 = 0,
    max_active_leases: usize = 0,
    ban_loop_ms: u64 = 0,
};

// Heap-owned: the store's progress handler and the effect clock keep pointers into it.
const Gen = struct {
    allocator: std.mem.Allocator,
    path: []const u8,
    store: durable.Store = undefined,
    store_open: bool = false,
    options: Options,
    installation: effects.Installation,
    clock: Clock = .{},
    consumer: history.Consumer,
    jails: std.ArrayList(Jail),
    leases: std.ArrayList(Lease),
    phases: std.ArrayList(Phase),
    records: u64 = 0,
    cycle: u64 = 0,
    store_failure: ?StoreFailure = null,
    stats: Stats = .{},
    refusal: ?Refusal = null,
    maintenance: bool,
    evidence_buffer: [retry.max_evidence_text_bytes]u8 = undefined,
    report: AttachReport = .{},

    fn create(allocator: std.mem.Allocator, dir: []const u8, name: []const u8, options: Options, maintenance: bool) !*Gen {
        const path = try std.fmt.allocPrint(allocator, "{s}/{s}.sqlite", .{ dir, name });
        errdefer allocator.free(path);
        if (std.fs.cwd().access(path, .{})) |_| return error.FixtureOutputExists else |failure| if (failure != error.FileNotFound) return failure;
        var seed_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &seed_bytes, options.seed, .little);
        const id_hash = effects.hashParts("fail2zig-load-fixture-installation-v1", &.{&seed_bytes});
        const installation = try effects.Installation.init(id_hash[0..16].*, .nftables, "load-fixture");
        const self = try allocator.create(Gen);
        self.* = .{ .allocator = allocator, .path = path, .options = options, .installation = installation, .consumer = try history.Consumer.init(installation, historyPolicyGeneration()), .jails = std.ArrayList(Jail).init(allocator), .leases = std.ArrayList(Lease).init(allocator), .phases = std.ArrayList(Phase).init(allocator), .maintenance = maintenance };
        return self;
    }
    fn attach(allocator: std.mem.Allocator, dir: []const u8, options: Options) !*Gen {
        const path = try std.fmt.allocPrint(allocator, "{s}/fail2zig.sqlite", .{dir});
        errdefer allocator.free(path);
        try std.fs.cwd().access(path, .{});
        const placeholder = try effects.Installation.init([_]u8{1} ** 16, .nftables, "attach");
        const self = try allocator.create(Gen);
        self.* = .{ .allocator = allocator, .path = path, .options = options, .installation = placeholder, .consumer = try history.Consumer.init(placeholder, historyPolicyGeneration()), .jails = std.ArrayList(Jail).init(allocator), .leases = std.ArrayList(Lease).init(allocator), .phases = std.ArrayList(Phase).init(allocator), .maintenance = options.normalize };
        return self;
    }
    fn destroy(self: *Gen) void {
        self.closeStore();
        for (self.jails.items) |jail| {
            self.allocator.free(jail.name);
            if (jail.checkpoint) |checkpoint| self.allocator.free(checkpoint);
        }
        self.jails.deinit();
        self.report.chunks.deinit(self.allocator);
        self.leases.deinit();
        self.phases.deinit();
        self.allocator.free(self.path);
        self.allocator.destroy(self);
    }
    // Records which production Store operation returned an error, so only its own
    // refusals are reported as results; every other error is a harness failure.
    fn stored(self: *Gen, operation: []const u8, result: anytype) @TypeOf(result) {
        return result catch |failure| {
            self.store_failure = .{ .operation = operation, .failure = failure };
            return failure;
        };
    }
    fn closeStore(self: *Gen) void {
        if (!self.store_open) return;
        self.store.close();
        self.store_open = false;
    }

    // Mirrors the daemon's runtime open and schema ladder, including the
    // per-transaction work guard, so construction hits the same refusals.
    fn openStore(self: *Gen) !void {
        self.store = try self.stored("Store.openRuntime", durable.Store.openRuntime(self.allocator, self.path));
        self.store_open = true;
        if (self.options.profile) {
            Profile.install(@ptrCast(self.store.db), self.allocator);
            try SqliteApi.install(&self.store.api);
        }
        self.store.runtime_path = self.path;
        try self.stored("Store.configureRuntimeLimits", self.store.configureRuntimeLimits());
        // Durability of intermediate commits only; row contents and VM work are unchanged.
        if (self.options.sync == .off) try self.stored("Store.exec", self.store.exec("PRAGMA synchronous=OFF;"));
        if (self.options.cache_kib != 0) {
            var pragma_buffer: [64]u8 = undefined;
            const pragma = try std.fmt.bufPrintZ(&pragma_buffer, "PRAGMA cache_size=-{d};", .{self.options.cache_kib});
            try self.stored("Store.exec", self.store.exec(pragma));
        }
        try self.stored("Store.prepareCurrentSchema", self.store.prepareCurrentSchema(.{
            .maximum_pending = 64,
            .migration = .{ .state_path = self.path, .now_us = self.clock.now, .history_max_matches = self.options.max_matches },
        }));
        if (try self.store.readRetryClock()) |floor| self.clock.now = @max(self.clock.now, floor);
        try self.prepareRetryView();
    }
    fn prepareRetryView(self: *Gen) !void {
        var owned: [64]detection.Name = undefined;
        var names: [64][]const u8 = undefined;
        var count: usize = 0;
        {
            var rows = try self.store.statement("SELECT jail FROM retry_policies ORDER BY jail LIMIT 65;");
            defer rows.deinit();
            while (try rows.row()) {
                if (count == names.len) return error.FixtureUnexpectedValue;
                owned[count] = try detection.Name.init(try rows.boundedBytes(0, 64));
                names[count] = owned[count].slice();
                count += 1;
            }
        }
        // Fresh shapes admit their first jail before runtime owner validation.
        if (count == 0) return;
        try self.stored("Store.validateRuntimeOwnerNames", self.store.validateRuntimeOwnerNames(names[0..count]));
        var validation = durable.Store.MaintenanceValidation{};
        while (!try self.stored("Store.validateMaintenanceTurn", self.store.validateMaintenanceTurn(&validation))) {}
        try self.stored("Store.finishMaintenanceValidation", self.store.finishMaintenanceValidation(&validation));
        try self.stored("Store.prepareRetryAdmissionView", self.store.prepareRetryAdmissionView(names[0..count], self.clock.now));
        while (try self.stored("Store.retryAdmissionStep", self.store.retryAdmissionStep(256)) == .progressed) {}
    }
    fn prepareRetryTime(self: *Gen, now: i64) !void {
        while ((try self.stored("Store.retryPoolOccupancy", self.store.retryPoolOccupancy(now))) == null) {
            while (try self.stored("Store.retryAdmissionStep", self.store.retryAdmissionStep(256)) == .progressed) {}
        }
    }
    fn setup(self: *Gen) !void {
        try self.openStore();
        _ = try self.stored("Store.setRetentionPolicy", self.store.setRetentionPolicy(self.options.max_matches));
        if (try self.store.integer("PRAGMA user_version;") != durable.latest_schema) return error.FixtureSchemaIncomplete;
        try self.stored("Store.admitInstallation", self.store.admitInstallation(self.installation, .{ .selector = self.installation.selector(), .disposition = .verified_absent }));
        const initial = try self.consumer.prepareInitial();
        defer initial.release();
        try self.stored("Store.bootstrapConfirmedHistory", self.store.bootstrapConfirmedHistory(self.consumer.manifest(), try initial.batch(self.clock.value()), self.installation));
        initial.publish();
    }
    fn addJail(self: *Gen, name: []const u8, duration: retry.Duration) !usize {
        var seed_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &seed_bytes, self.options.seed, .little);
        const owned = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned);
        const jail = Jail{ .name = owned, .generation = effects.hashParts("fail2zig-load-fixture-jail-v1", &.{ name, &seed_bytes }), .policy = .{ .maxretry = 1, .window_us = 60 * second_us, .duration = duration, .max_subjects = 65536, .enforce = true } };
        try self.stored("Store.admitRetry", self.store.admitRetry(jail.name, jail.generation, jail.policy));
        try self.jails.append(jail);
        if (!self.store.retry_projection_initialized) try self.prepareRetryView();
        return self.jails.items.len - 1;
    }
    fn finite(self: *Gen) retry.Duration {
        return .{ .finite_us = @as(i64, @intCast(self.options.bantime_s)) * second_us };
    }
    fn evidenceText(self: *Gen, record: u64, length: usize) ?[]const u8 {
        if (length == 0) return null;
        const prefix = std.fmt.bufPrint(&self.evidence_buffer, "fixture evidence seed={d} record={d} ", .{ self.options.seed, record }) catch self.evidence_buffer[0..0];
        @memset(self.evidence_buffer[prefix.len..], 'x');
        return self.evidence_buffer[0..length];
    }
    fn observation(self: *Gen, entry: effects.Entry) effects.Observation {
        return .{ .installation = entry.installation.id, .scope_key = entry.scope_key, .fingerprint = effects.hashParts("fail2zig-load-fixture-observation-v1", &.{&entry.intent_id}), .observed_us = self.clock.now, .qualification = .complete_owned, .state = entry.desired };
    }

    // One detection through receipt and record commit, then the effect runtime's
    // dispatch, verified settlement and action-target reconciliation.
    fn ban(self: *Gen, jail_index: usize, subject: detection.Subject, evidence_bytes: usize) !void {
        try self.prepareRetryTime(self.clock.now);
        const jail = self.jails.items[jail_index];
        self.records += 1;
        var occurrence_buffer: [32]u8 = undefined;
        const occurrence = try std.fmt.bufPrint(&occurrence_buffer, "fx-{d}", .{self.records});
        var raw_hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(occurrence, &raw_hash, .{});
        const identity = durable.ReceiptIdentity{ .jail = jail.name, .source = source_name, .occurrence = occurrence, .cursor = occurrence, .raw_hash = raw_hash, .generation = jail.generation };
        const revision = try self.stored("Store.revision", self.store.revision(jail.name));
        const receipt = try self.stored("Store.beginReceipt", self.store.beginReceipt(identity, .{ .us = self.clock.now }, revision));
        const record = try self.detectionRecord(jail, identity, receipt, subject, self.records, evidence_bytes, revision);
        while (true) {
            _ = self.store.commitRecord(record) catch |failure| {
                if (failure == error.RetryEligibilityPending) {
                    try self.prepareRetryTime(self.clock.now);
                    continue;
                }
                return self.stored("Store.commitRecord", @as(durable.Error!void, failure));
            };
            break;
        }
        self.stats.bans += 1;
        const key = try (try effects.Scope.host(subject)).key(self.installation);
        const entry = try self.stored("Store.readEffect", self.store.readEffect(key, self.installation)) orelse return error.FixtureMissingEffect;
        if (entry.status != .pending) {
            self.stats.kept_existing += 1;
            return;
        }
        _ = try self.stored("Store.settleOutcome", self.store.settleOutcome(entry.token(), self.clock.now, self.observation(entry), self.clock.value()));
        try self.settleActionTargets(key, jail.name);
        if (entry.desired == .finite) {
            try self.leases.append(.{ .key = key, .deadline = entry.desired.finite });
            self.stats.max_active_leases = @max(self.stats.max_active_leases, self.leases.items.len);
        }
    }
    fn detectionRecord(self: *Gen, jail: Jail, identity: durable.ReceiptIdentity, receipt: Timestamp, subject: detection.Subject, record: u64, evidence_bytes: usize, revision: u64) !durable.Record {
        const outcome = try time_policy.evaluate(.timestamped, .{ .parsed = receipt }, receipt, receipt, 1_000);
        return .{
            .jail = jail.name,
            .source = source_name,
            .occurrence = identity.occurrence,
            .cursor = identity.cursor,
            .raw_hash = identity.raw_hash,
            .receipt = .{ .time = receipt, .generation = jail.generation },
            .native_time_outcome = outcome,
            .native_detection = .{ .kind = .candidate, .generation = jail.generation, .filter = try detection.Name.init("fixture"), .pattern = try detection.Name.init("failure"), .pattern_index = 0, .subject = subject },
            .native_retry = .{ .generation = jail.generation, .policy = jail.policy, .processing_us = @max(self.clock.now, receipt.us) },
            .retry_evidence = .{ .text = self.evidenceText(record, evidence_bytes) },
            .effects_clock = self.clock.value(),
            .expected_revision = revision,
            .disposition = outcome.disposition(),
            .checkpoint = jail.checkpoint orelse "load-fixture",
        };
    }
    // One record of a group-commit frame, in the pipeline's stageInFrame order.
    fn stageBan(self: *Gen, frame: anytype, jail_index: usize, subject: detection.Subject) !effects.Hash {
        const key = try (try effects.Scope.host(subject)).key(self.installation);
        const jail = &self.jails.items[jail_index];
        self.cycle += 1;
        jail.records += 1;
        errdefer jail.records -= 1;
        var occurrence_buffer: [32]u8 = undefined;
        const occurrence = try std.fmt.bufPrint(&occurrence_buffer, "fx-{d}", .{jail.records});
        var raw_hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(occurrence, &raw_hash, .{});
        const identity = durable.ReceiptIdentity{ .jail = jail.name, .source = source_name, .occurrence = occurrence, .cursor = occurrence, .raw_hash = raw_hash, .generation = jail.generation };
        self.clock.now += attach_step_us;
        try self.stored("Store.openBatchRecord", self.store.openBatchRecord(frame));
        errdefer self.store.dropBatchRecord(frame);
        const revision = try self.stored("Store.revision", self.store.revision(jail.name));
        const reserved = try self.stored("Store.reserveReceiptStep", self.store.reserveReceiptStep(identity, .{ .us = self.clock.now }, revision));
        const result = try self.stored("Store.closeBatchRecord", self.store.closeBatchRecord(frame, try self.detectionRecord(jail.*, identity, reserved.time, subject, jail.records, self.options.evidence, revision)));
        if (result == .already_committed) return error.FixtureRecordAlreadyCommitted;
        jail.appended += 1;
        self.stats.bans += 1;
        return key;
    }
    // A refusal inside a frame keeps the records staged before it, as the pipeline does.
    fn appendChunk(self: *Gen, size: usize) !void {
        try self.prepareRetryTime(self.clock.now);
        var frame = try self.stored("Store.beginBatch", self.store.beginBatch());
        var keys: [batch_records]effects.Hash = undefined;
        var jail_indices: [batch_records]usize = undefined;
        var staged: usize = 0;
        const refusal: ?anyerror = for (0..size) |_| {
            const jail_index: usize = @intCast(self.cycle % self.jails.items.len);
            keys[staged] = self.stageBan(&frame, jail_index, attachSubject(self.options.address_start + self.cycle)) catch |cause| break cause;
            jail_indices[staged] = jail_index;
            staged += 1;
        } else null;
        const pending = if (refusal) |failure| failure == error.RetryEligibilityPending else false;
        if (pending) self.cycle -= 1;
        if (staged == 0 or frame.broken) {
            self.store.rollback();
            if (staged != 0) return error.FixtureBatchBroken;
            if (pending) {
                try self.prepareRetryTime(self.clock.now);
                self.store_failure = null;
                return;
            }
            if (refusal) |cause| return cause;
            return;
        }
        {
            errdefer self.store.rollback();
            for (self.jails.items) |jail| {
                var cursor = try self.store.statement("DELETE FROM source_cursors WHERE jail=?1 AND source=?2;");
                defer cursor.deinit();
                try cursor.text(1, jail.name);
                try cursor.text(2, source_name);
                try cursor.done();
            }
            try self.stored("Store.commitBatch", self.store.commitBatch(&frame));
        }
        try self.settleChunk(keys[0..staged], jail_indices[0..staged]);
        if (pending) {
            try self.prepareRetryTime(self.clock.now);
            self.store_failure = null;
        } else if (refusal) |cause| return cause;
    }
    // One readback per chunk: a single fingerprint and observation time, as the daemon's batched settlement.
    fn settleChunk(self: *Gen, keys: []const effects.Hash, jail_indices: []const usize) !void {
        var items: [batch_records]durable.Store.InstallItem = undefined;
        var count: usize = 0;
        var sampled: usize = 0;
        for (keys, 0..) |key, i| {
            const entry = try self.stored("Store.readEffect", self.store.readEffect(key, self.installation)) orelse return error.FixtureMissingEffect;
            if (entry.status != .pending) {
                self.stats.kept_existing += 1;
                continue;
            }
            items[count] = .{ .token = entry.token(), .state = entry.desired };
            count += 1;
            sampled = i;
        }
        if (count == 0) return;
        self.clock.now += attach_step_us;
        var cycle_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &cycle_bytes, self.cycle, .little);
        const fingerprint = effects.hashParts("fail2zig-load-fixture-readback-v1", &.{&cycle_bytes});
        _ = try self.stored("Store.settleInstalled", self.store.settleInstalled(items[0..count], self.clock.now, fingerprint, self.clock.now, self.clock.value()));
        try self.expectConfirmedTargets(keys[sampled], self.jails.items[jail_indices[sampled]].name);
    }
    fn expectConfirmedTargets(self: *Gen, key: effects.Hash, jail: []const u8) !void {
        var owners: [effects.max_page]effects.Owner = undefined;
        const count = try self.stored("Store.readOwners", self.store.readOwners(key, &owners));
        for (owners[0..count]) |owner| {
            if (!std.mem.eql(u8, owner.jail.slice(), jail)) continue;
            var targets: [action.max_targets_per_action]action.Target = undefined;
            const found = try self.stored("Store.actionTargets", self.store.actionTargets(owner.decision_id, &targets));
            for ([_]action.Kind{ .enforcement, .notification }) |kind| {
                for (targets[0..found]) |target| {
                    if (target.kind == kind and target.status == .confirmed) break;
                } else return error.FixtureUnconfirmedActionTarget;
            }
            return;
        }
        return error.FixtureMissingOwner;
    }
    fn settleActionTargets(self: *Gen, key: effects.Hash, jail: []const u8) !void {
        var owners: [effects.max_page]effects.Owner = undefined;
        const count = try self.stored("Store.readOwners", self.store.readOwners(key, &owners));
        for (owners[0..count]) |owner| {
            if (!std.mem.eql(u8, owner.jail.slice(), jail)) continue;
            var targets: [action.max_targets_per_action]action.Target = undefined;
            if (try self.stored("Store.actionTargets", self.store.actionTargets(owner.decision_id, &targets)) == 0) return;
            for ([_]action.Kind{ .enforcement, .notification }) |kind| {
                try self.stored("Store.markActionTargetDispatched", self.store.markActionTargetDispatched(owner.decision_id, kind, self.clock.value()));
                try self.stored("Store.settleActionTarget", self.store.settleActionTarget(owner.decision_id, kind, .confirmed, self.clock.value()));
            }
            return;
        }
        return error.FixtureMissingOwner;
    }
    fn expireDue(self: *Gen) !void {
        var index: usize = 0;
        while (index < self.leases.items.len) {
            const lease = self.leases.items[index];
            if (lease.deadline > self.clock.now) {
                index += 1;
                continue;
            }
            _ = self.leases.orderedRemove(index);
            const entry = try self.stored("Store.readEffect", self.store.readEffect(lease.key, self.installation)) orelse return error.FixtureMissingEffect;
            const next = try self.stored("Store.prepareExpiry", self.store.prepareExpiry(lease.key, entry.revision, self.clock.value()));
            if (next.status != .pending) continue;
            _ = try self.stored("Store.settleOutcome", self.store.settleOutcome(next.token(), self.clock.now, self.observation(next), self.clock.value()));
            self.stats.expired += 1;
        }
    }
    fn consume(self: *Gen, through: ?u64) !void {
        var events: [history.max_page]history.Event = undefined;
        for (0..1 << 20) |_| {
            var size: usize = history.max_page;
            if (through) |last| {
                if (self.consumer.live.last_sequence >= last) return;
                size = @intCast(@min(size, last - self.consumer.live.last_sequence));
            }
            const page = try self.stored("Store.confirmedEffectPage", self.store.confirmedEffectPage(self.installation, self.consumer.live.last_sequence, null, events[0..size]));
            if (page.count == 0) return;
            const stage = try self.consumer.prepare(page, events[0..page.count], self.clock.now);
            defer stage.release();
            try self.stored("Store.commitConfirmedHistory", self.store.commitConfirmedHistory(self.consumer.manifest(), try stage.batch(self.clock.value()), page.token));
            stage.publish();
            self.stats.history_pages += 1;
        }
        return error.FixtureUnboundedHistory;
    }
    fn maintain(self: *Gen) !void {
        for (0..max_maintenance_steps) |_| {
            if (self.options.retention == .shipped) self.stats.retention_calls += 1;
            switch (try self.stored("Store.maintenanceStep", self.store.maintenanceStep(.{
                .retention = .{ .age_us = self.options.retention_s * second_us, .max_matches = self.options.max_matches },
                .now_us = self.clock.now,
                .history_caught_up = self.options.retention == .shipped,
                .spent_scopes = true,
            }))) {
                .progress => |operation| switch (operation) {
                    .history_rebuild, .history_details, .history_prefix => self.stats.retention_deleted += 1,
                    .retry_details => self.stats.retry_details_pruned += 1,
                    .spent_scopes => self.stats.spent_scope_batches += 1,
                    .obsolete_rows => {},
                },
                .wait => {},
                .idle => return,
            }
        }
        return error.FixtureUnboundedMaintenance;
    }
    fn turn(self: *Gen) !void {
        try self.consume(null);
        if (self.maintenance) try self.maintain();
    }
    // The daemon's restoreHistory sequence; a base without a saved consumer is not a daemon state.
    fn restoreHistory(self: *Gen) !void {
        const manifest = self.consumer.manifest();
        var saved = try self.stored("Store.consumerManifestSnapshot", self.store.consumerManifestSnapshot(self.allocator, manifest));
        defer saved.deinit(self.allocator);
        if (saved.status != .ready or saved.count != 1) return error.FixtureMissingHistoryConsumer;
        const row = saved.states[0];
        if (row.format_version != history.version or row.valid_until_us != null) return error.FixtureInvalidHistoryCheckpoint;
        const stage = try self.consumer.prepareRestore(row.revision, row.payload orelse return error.FixtureMissingHistoryConsumer);
        defer stage.release();
        var probe: [1]history.Event = undefined;
        _ = try self.stored("Store.confirmedEffectPage", self.store.confirmedEffectPage(self.installation, self.consumer.staged.last_sequence, null, &probe));
        try self.stored("Store.validateConsumerManifestSnapshot", self.store.validateConsumerManifestSnapshot(manifest, &saved));
        stage.publish();
        self.report.history.restored_sequence = self.consumer.live.last_sequence;
    }
    fn addAttachJail(self: *Gen, name: []const u8) !void {
        var generation: [32]u8 = undefined;
        var policy: retry.Policy = undefined;
        {
            var row = try self.store.statement("SELECT generation,policy FROM retry_policies WHERE jail=?1;");
            defer row.deinit();
            try row.text(1, name);
            if (!try row.row()) return error.FixtureUnknownJail;
            generation = (try row.boundedBytes(0, 32))[0..32].*;
            policy = try retry.Policy.decode(try row.boundedBytes(1, 4096));
        }
        const owned = try self.allocator.dupe(u8, name);
        self.jails.append(.{ .name = owned, .generation = generation, .policy = policy }) catch |failure| {
            self.allocator.free(owned);
            return failure;
        };
        const jail = &self.jails.items[self.jails.items.len - 1];
        {
            var existing = try self.store.statement("SELECT count(*) FROM records WHERE jail=?1 AND source=?2;");
            defer existing.deinit();
            try existing.text(1, name);
            try existing.text(2, source_name);
            if (!try existing.row()) return error.FixtureMissingInstallation;
            jail.records = @intCast(try existing.signed(0));
        }
        // The jail's pipeline restores from the latest record's checkpoint, so every appended record carries the one the daemon wrote.
        jail.checkpoint = try self.stored("Store.checkpoint", self.store.checkpoint(self.allocator, name)) orelse return error.FixtureMissingCheckpoint;
    }
    // Starts at or above every persisted floor and never lowers one; a floor past wall time is reported, not repaired.
    fn scheduleClock(self: *Gen) !void {
        const schedule = &self.report.schedule;
        const wall = std.time.microTimestamp();
        if (try self.stored("Store.receiptClock", self.store.receiptClock())) |floor| schedule.receipt_floor_us = floor.us;
        if (try self.stored("Store.admissionClock", self.store.admissionClock())) |floor| schedule.admission_floor_us = floor.us;
        const floor = @max(schedule.receipt_floor_us orelse wall, schedule.admission_floor_us orelse wall);
        schedule.future_dated = floor > wall;
        schedule.start_us = @max(wall, floor);
        self.clock.now = schedule.start_us;
    }
    fn appendBans(self: *Gen) !void {
        var sample = try std.time.Timer.start();
        _ = try self.cacheSample();
        while (self.cycle < self.options.count) {
            self.syncClock();
            try self.appendChunk(@intCast(@min(batch_records, self.options.count - self.cycle)));
            if (self.options.normalize) try self.turn();
            if (self.cycle % attach_sample_bans == 0 or self.cycle == self.options.count) try self.sampleChunk(&sample);
            if (self.cycle % 4096 == 0) try self.phase("progress");
        }
    }
    fn recordEnd(self: *Gen) !void {
        const report = &self.report;
        report.history.head = std.math.cast(u64, try self.store.integer("SELECT head FROM confirmed_history_stream WHERE id=1;")) orelse return error.FixtureUnexpectedValue;
        report.history.checkpoint = self.consumer.live.last_sequence;
        report.history.backlog = report.history.head -| report.history.checkpoint;
        report.schedule.end_us = self.clock.now;
        report.schedule.wall_end_us = std.time.microTimestamp();
    }
    fn syncClock(self: *Gen) void {
        self.clock.now = @max(self.clock.now, std.time.microTimestamp());
    }
    fn cacheSample(self: *Gen) !struct { hits: i64, misses: i64 } {
        var hits: i64 = 0;
        var misses: i64 = 0;
        var highwater: i64 = 0;
        if (sqlite3_db_status64(@ptrCast(self.store.db), sqlite_dbstatus_cache_hit, &hits, &highwater, 1) != 0) return error.FixtureCacheStatus;
        if (sqlite3_db_status64(@ptrCast(self.store.db), sqlite_dbstatus_cache_miss, &misses, &highwater, 1) != 0) return error.FixtureCacheStatus;
        return .{ .hits = hits, .misses = misses };
    }
    fn sampleChunk(self: *Gen, timer: *std.time.Timer) !void {
        const cache = try self.cacheSample();
        try self.report.chunks.append(self.allocator, .{ .cycle = self.cycle, .elapsed_ns = timer.lap(), .cache_hits = cache.hits, .cache_misses = cache.misses });
    }
    fn phase(self: *Gen, label: []const u8) !void {
        var item = Phase{ .label = label, .cycle = self.cycle, .clock_us = self.clock.now, .counts = undefined, .retained_from = 0, .head = 0 };
        for (key_tables, 0..) |table, i| {
            var buffer: [96]u8 = undefined;
            item.counts[i] = try self.store.integer(try std.fmt.bufPrintZ(&buffer, "SELECT count(*) AS n FROM {s};", .{table}));
        }
        item.retained_from = try self.store.integer("SELECT retained_from FROM confirmed_history_stream WHERE id=1;");
        item.head = try self.store.integer("SELECT head FROM confirmed_history_stream WHERE id=1;");
        try self.phases.append(item);
    }
    // A closed store leaves no WAL, so the main file is a complete copy.
    fn snapshot(self: *Gen, dir: []const u8, name: []const u8) ![]u8 {
        self.closeStore();
        var wal_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const wal = try std.fmt.bufPrint(&wal_buffer, "{s}-wal", .{self.path});
        if (std.fs.cwd().statFile(wal)) |stat| {
            if (stat.size != 0) return error.FixtureWalRemains;
        } else |failure| if (failure != error.FileNotFound) return failure;
        const target = try std.fmt.allocPrint(self.allocator, "{s}/{s}.sqlite", .{ dir, name });
        errdefer self.allocator.free(target);
        if (std.fs.cwd().access(target, .{})) |_| return error.FixtureOutputExists else |failure| if (failure != error.FileNotFound) return failure;
        try std.fs.cwd().copyFile(self.path, std.fs.cwd(), target, .{});
        try self.openStore();
        return target;
    }
};

fn churnSubject(seed: u64, index: u64) detection.Subject {
    const base: u32 = (198 << 24) | (18 << 16);
    const offset: u32 = @intCast((seed *% 7919 +% index) % 131_070 + 1);
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, base + offset, .big);
    return .{ .v4 = bytes };
}
fn attachSubject(index: u64) detection.Subject {
    return .{ .v4 = .{ 198, 19, @intCast(index >> 8 & 0xff), @intCast(index & 0xff) } };
}
fn host(a: u8, b: u8, c: u8, d: u8) detection.Subject {
    return .{ .v4 = .{ a, b, c, d } };
}

fn runChurn(gen: *Gen) !void {
    try gen.setup();
    const jail = try gen.addJail("churn", gen.finite());
    while (gen.cycle < gen.options.count) {
        gen.cycle += 1;
        gen.clock.advanceMs(gen.options.interval_ms);
        try gen.expireDue();
        try gen.ban(jail, churnSubject(gen.options.seed, gen.cycle), gen.options.evidence);
        try gen.turn();
        if (gen.cycle == 1 or gen.cycle % 1024 == 0) try gen.phase("progress");
    }
}
fn runHot(gen: *Gen) !void {
    try gen.setup();
    var names: [16][16]u8 = undefined;
    for (0..gen.options.jails) |i| _ = try gen.addJail(try std.fmt.bufPrint(&names[i], "hot-{d}", .{i}), gen.finite());
    const subject = host(203, 0, 113, 7);
    while (gen.cycle < gen.options.count) {
        gen.cycle += 1;
        try gen.expireDue();
        try gen.ban(@intCast((gen.cycle - 1) % gen.options.jails), subject, gen.options.evidence);
        try gen.turn();
        if (gen.cycle <= 2) try gen.phase("per-cycle");
        if (gen.cycle % 4096 == 0) try gen.phase("progress");
        gen.clock.advanceMs(gen.options.bantime_s * 1000 + gen.options.gap_ms);
    }
}
fn runPinned(gen: *Gen) !void {
    try gen.setup();
    const pinned = try gen.addJail("pinned", .permanent);
    const churn = try gen.addJail("churn", gen.finite());
    gen.clock.advanceMs(1000);
    try gen.ban(pinned, host(203, 0, 113, 200), gen.options.evidence);
    try gen.turn();
    while (gen.cycle < gen.options.churn) {
        gen.cycle += 1;
        gen.clock.advanceMs(gen.options.interval_ms);
        try gen.expireDue();
        try gen.ban(churn, churnSubject(gen.options.seed, gen.cycle), gen.options.evidence);
        try gen.turn();
    }
    gen.clock.advanceMs(gen.options.bantime_s * 1000 + 1000);
    try gen.expireDue();
    try gen.turn();
    try gen.phase("before-retention-age");
    gen.clock.now += (gen.options.retention_s + 3600) * second_us;
    try gen.turn();
    try gen.phase("after-retention-age");
}
fn runAttach(gen: *Gen) !void {
    const report = &gen.report;
    var timer = try std.time.Timer.start();
    try gen.openStore();
    gen.installation = try gen.stored("Store.readInstallation", gen.store.readInstallation()) orelse return error.FixtureMissingInstallation;
    gen.consumer = try history.Consumer.init(gen.installation, historyPolicyGeneration());
    report.timings.open = timer.lap();
    try gen.restoreHistory();
    report.timings.restore = timer.lap();
    var names = std.mem.splitScalar(u8, gen.options.jail, ',');
    while (names.next()) |name| try gen.addAttachJail(name);
    try gen.scheduleClock();
    report.base_live_native_effects = try gen.store.integer("SELECT count(*) FROM native_effects WHERE lease_kind<>0;");
    report.base_live_effect_owners = try gen.store.integer("SELECT count(*) FROM effect_owners WHERE lease_kind<>0;");
    report.timings.open += timer.lap();
    if (gen.options.normalize) {
        try gen.consume(null);
        report.history.base_backlog = gen.consumer.live.last_sequence - report.history.restored_sequence;
    }
    report.timings.base_catchup = timer.lap();
    gen.appendBans() catch |failure| {
        report.timings.append = timer.lap();
        try gen.recordEnd();
        return failure;
    };
    report.timings.append = timer.lap();
    gen.stats.ban_loop_ms = report.timings.append / std.time.ns_per_ms;
    if (gen.options.normalize) {
        gen.syncClock();
        try gen.turn();
    }
    report.timings.final_normalize = timer.lap();
    try gen.recordEnd();
    try gen.phase("final");
}
fn runReuse(gen: *Gen) !void {
    try gen.setup();
    const jail = try gen.addJail("reuse", gen.finite());
    const subject = host(203, 0, 113, 9);
    while (gen.cycle < gen.options.count) {
        gen.cycle += 1;
        try gen.expireDue();
        try gen.ban(jail, subject, gen.options.evidence);
        try gen.turn();
        if (gen.cycle % 50 == 0) try gen.phase("progress");
        gen.clock.advanceMs(gen.options.bantime_s * 1000 + gen.options.gap_ms);
    }
    try gen.expireDue();
    try gen.turn();
    try gen.phase("final");
}

// Oracle states are built without retention maintenance: it is the operation
// under test, and the daemon skips it while the history consumer lags.
const OracleCase = struct {
    name: []const u8,
    build: *const fn (*Gen, []const u8, *std.ArrayList(Snapshot)) anyerror!void,
};
const Snapshot = struct { label: []const u8, path: []u8 };

fn rest(gen: *Gen) !void {
    gen.clock.advanceMs(gen.options.bantime_s * 1000 + 1000);
    try gen.expireDue();
}
fn step(gen: *Gen, jail: usize, subject: detection.Subject, evidence: usize) !void {
    gen.clock.advanceMs(1000);
    gen.cycle += 1;
    try gen.ban(jail, subject, evidence);
}
fn buildCompeting(gen: *Gen, _: []const u8, _: *std.ArrayList(Snapshot)) !void {
    const jail = try gen.addJail("oracle", gen.finite());
    try step(gen, jail, host(192, 0, 2, 1), 16);
    try step(gen, jail, host(192, 0, 2, 2), 16);
    gen.clock.advanceMs(100_000);
    for (0..12) |round| {
        try step(gen, jail, host(192, 0, 2, 40), 16);
        if (round < 9) try step(gen, jail, host(192, 0, 2, 50), retry.max_evidence_text_bytes);
        try rest(gen);
    }
    try gen.consume(null);
}
fn buildLag(gen: *Gen, _: []const u8, _: *std.ArrayList(Snapshot)) !void {
    const jail = try gen.addJail("oracle", gen.finite());
    for (0..100) |i| try step(gen, jail, host(198, 51, 100, @intCast(i + 1)), 16);
    try gen.consume(100);
    try step(gen, jail, host(192, 0, 2, 101), 16);
    try rest(gen);
    try step(gen, jail, host(192, 0, 2, 101), 16);
}
fn buildRebuild(gen: *Gen, _: []const u8, _: *std.ArrayList(Snapshot)) !void {
    const jail = try gen.addJail("oracle", gen.finite());
    try step(gen, jail, host(192, 0, 2, 11), 16);
    try step(gen, jail, host(192, 0, 2, 10), 16);
    try rest(gen);
    try step(gen, jail, host(192, 0, 2, 11), 16);
    try step(gen, jail, host(192, 0, 2, 10), 16);
    try gen.consume(null);
}
fn buildEvidence(gen: *Gen, dir: []const u8, snapshots: *std.ArrayList(Snapshot)) !void {
    const jail = try gen.addJail("oracle", gen.finite());
    const subject = host(192, 0, 2, 60);
    try step(gen, jail, subject, 0);
    try rest(gen);
    for (0..8) |_| {
        try step(gen, jail, subject, retry.max_evidence_text_bytes);
        try rest(gen);
    }
    try gen.consume(null);
    try snapshots.append(.{ .label = "at-limit", .path = try gen.snapshot(dir, "or6-at-limit") });
    try step(gen, jail, subject, 1);
    try gen.consume(null);
}
fn buildAdvancing(gen: *Gen, _: []const u8, _: *std.ArrayList(Snapshot)) !void {
    const jail = try gen.addJail("oracle", gen.finite());
    for (1..5) |i| try step(gen, jail, host(192, 0, 2, @intCast(20 + i)), 16);
    gen.clock.advanceMs(100_000);
    for (0..3) |_| {
        try step(gen, jail, host(192, 0, 2, 30), 16);
        try rest(gen);
    }
    try gen.consume(null);
}
fn buildLiveInsert(gen: *Gen, dir: []const u8, snapshots: *std.ArrayList(Snapshot)) !void {
    const jail = try gen.addJail("oracle", gen.finite());
    const p = host(192, 0, 2, 70);
    const q = host(192, 0, 2, 71);
    try step(gen, jail, p, 16);
    try step(gen, jail, q, 16);
    try rest(gen);
    try step(gen, jail, q, 16);
    try gen.consume(null);
    try snapshots.append(.{ .label = "before-insert", .path = try gen.snapshot(dir, "or9-before-insert") });
    try rest(gen);
    try step(gen, jail, p, 16);
    try gen.consume(null);
}
const oracle_cases = [_]OracleCase{
    .{ .name = "or1-competing", .build = buildCompeting },
    .{ .name = "or2-consumer-lag", .build = buildLag },
    .{ .name = "or3-partial-rebuild", .build = buildRebuild },
    .{ .name = "or6-over-limit", .build = buildEvidence },
    .{ .name = "or8-advancing-cutoff", .build = buildAdvancing },
    .{ .name = "or9-after-insert", .build = buildLiveInsert },
};

// Inspection uses a separate read-only connection without the runtime guard,
// so whole-database checks are not limited by the per-transaction allowance.
const Inspection = struct {
    fn tables(store: *durable.Store, allocator: std.mem.Allocator) !std.ArrayList([]u8) {
        var names = std.ArrayList([]u8).init(allocator);
        errdefer freeNames(&names, allocator);
        var rows = try store.statement("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;");
        defer rows.deinit();
        while (try rows.row()) try names.append(try allocator.dupe(u8, try rows.boundedBytes(0, 256)));
        return names;
    }
    fn freeNames(names: *std.ArrayList([]u8), allocator: std.mem.Allocator) void {
        for (names.items) |name| allocator.free(name);
        names.deinit();
    }
    fn count(store: *durable.Store, table: []const u8) !i64 {
        var buffer: [320]u8 = undefined;
        for (table) |c| if (c == '"') return error.FixtureUnexpectedTable;
        return store.integer(try std.fmt.bufPrintZ(&buffer, "SELECT count(*) FROM \"{s}\";", .{table}));
    }
};

fn writeCounts(ws: anytype, store: *durable.Store, allocator: std.mem.Allocator) !void {
    var names = try Inspection.tables(store, allocator);
    defer Inspection.freeNames(&names, allocator);
    try ws.objectField("table_counts");
    try ws.beginObject();
    for (names.items) |name| {
        try ws.objectField(name);
        try ws.write(try Inspection.count(store, name));
    }
    try ws.endObject();
}
fn writeQuery(ws: anytype, store: *durable.Store, field: []const u8, sql: [:0]const u8) !void {
    try ws.objectField(field);
    try ws.write(try store.integer(sql));
}
fn writeHex(ws: anytype, bytes: []const u8) !void {
    var buffer: [128]u8 = undefined;
    if (bytes.len > 64) return error.FixtureUnexpectedValue;
    try ws.write(try std.fmt.bufPrint(&buffer, "{}", .{std.fmt.fmtSliceHexLower(bytes)}));
}

fn writeState(ws: anytype, gen: *Gen, label: []const u8, path: []const u8) !void {
    var store = try durable.Store.openReadOnly(gen.allocator, path);
    if (gen.options.profile) Profile.install(@ptrCast(store.db), gen.allocator);
    defer store.close();
    try ws.beginObject();
    try ws.objectField("label");
    try ws.write(label);
    try ws.objectField("path");
    try ws.write(path);
    try ws.objectField("schema_version");
    try ws.write(try store.integer("PRAGMA user_version;"));
    try writeCounts(ws, &store, gen.allocator);

    try ws.objectField("integrity_check");
    try ws.beginArray();
    {
        var rows = try store.statement("PRAGMA integrity_check(20);");
        defer rows.deinit();
        while (try rows.row()) try ws.write(try rows.boundedBytes(0, 4096));
    }
    try ws.endArray();
    try ws.objectField("foreign_key_violations");
    {
        var rows = try store.statement("PRAGMA foreign_key_check;");
        defer rows.deinit();
        var violations: u64 = 0;
        while (try rows.row()) violations += 1;
        try ws.write(violations);
    }

    try ws.objectField("history_stream");
    try ws.beginObject();
    try writeQuery(ws, &store, "revision", "SELECT revision FROM confirmed_history_stream WHERE id=1;");
    try writeQuery(ws, &store, "head", "SELECT head FROM confirmed_history_stream WHERE id=1;");
    try writeQuery(ws, &store, "retained_from", "SELECT retained_from FROM confirmed_history_stream WHERE id=1;");
    try writeQuery(ws, &store, "min_sequence", "SELECT coalesce(min(sequence),0) FROM confirmed_history_sequence;");
    try writeQuery(ws, &store, "max_sequence", "SELECT coalesce(max(sequence),0) FROM confirmed_history_sequence;");
    try ws.endObject();

    try ws.objectField("consumer_checkpoints");
    try ws.beginArray();
    {
        var rows = try store.statement("SELECT kind,jail,source,rule,generation,payload FROM consumer_checkpoints ORDER BY kind,jail,source,rule;");
        defer rows.deinit();
        while (try rows.row()) {
            try ws.beginObject();
            try ws.objectField("kind");
            try ws.write(try rows.signed(0));
            try ws.objectField("jail");
            try ws.write(try rows.boundedBytes(1, 64));
            try ws.objectField("source");
            try ws.write(try rows.boundedBytes(2, 256));
            try ws.objectField("rule");
            try ws.write(try rows.boundedBytes(3, 256));
            try ws.objectField("generation");
            try writeHex(ws, try rows.boundedBytes(4, 32));
            const payload = try rows.boundedBytes(5, 1 << 20);
            if (history.Checkpoint.decode(payload)) |checkpoint| {
                try ws.objectField("history_last_sequence");
                try ws.write(checkpoint.last_sequence);
                try ws.objectField("history_watermark_us");
                try ws.write(checkpoint.confirmed_watermark_us);
            } else |_| {}
            try ws.endObject();
        }
    }
    try ws.endArray();
    try ws.objectField("retry_policy_generations");
    try ws.beginObject();
    {
        var rows = try store.statement("SELECT jail,generation FROM retry_policies ORDER BY jail;");
        defer rows.deinit();
        while (try rows.row()) {
            try ws.objectField(try rows.boundedBytes(0, 64));
            try writeHex(ws, try rows.boundedBytes(1, 32));
        }
    }
    try ws.endObject();
    try ws.objectField("installation");
    {
        var rows = try store.statement("SELECT identity FROM effect_installation;");
        defer rows.deinit();
        if (try rows.row()) try writeHex(ws, try rows.boundedBytes(0, 16)) else try ws.write(null);
    }

    try ws.objectField("detail_provenance");
    try ws.beginObject();
    try writeQuery(ws, &store, "retry_linked", "SELECT count(*) FROM confirmed_event_details d JOIN confirmed_effect_events e USING(event_id) JOIN retry_decision_details r ON r.jail=e.jail AND r.effect_decision_id=e.decision_id;");
    try writeQuery(ws, &store, "unlinked", "SELECT count(*) FROM confirmed_event_details d JOIN confirmed_effect_events e USING(event_id) LEFT JOIN retry_decision_details r ON r.jail=e.jail AND r.effect_decision_id=e.decision_id WHERE r.jail IS NULL;");
    try writeQuery(ws, &store, "null_evidence", "SELECT count(*) FROM confirmed_event_details WHERE evidence IS NULL;");
    try writeQuery(ws, &store, "retained_subjects", "SELECT count(*) FROM (SELECT DISTINCT r.family,r.subject FROM confirmed_event_details d JOIN confirmed_effect_events e USING(event_id) JOIN retry_decision_details r ON r.jail=e.jail AND r.effect_decision_id=e.decision_id);");
    try ws.endObject();

    try ws.objectField("lifecycle");
    try ws.beginObject();
    try writeQuery(ws, &store, "live_or_pending_scopes", "SELECT count(*) FROM native_effects WHERE lease_kind<>0;");
    try writeQuery(ws, &store, "spent_scopes", "SELECT count(*) FROM native_effects WHERE lease_kind=0;");
    try writeQuery(ws, &store, "spent_scopes_referenced_by_history", "SELECT count(*) FROM native_effects n WHERE n.lease_kind=0 AND EXISTS(SELECT 1 FROM confirmed_effect_events e WHERE e.scope_key=n.scope_key);");
    try writeQuery(ws, &store, "obsolete_owner_revisions", "SELECT count(*) FROM effect_owner_revisions h WHERE NOT EXISTS(SELECT 1 FROM effect_owners o WHERE o.scope_key=h.scope_key AND o.jail=h.jail AND o.revision=h.revision);");
    // native_effects has no index on intent_id; NOT IN materializes the referenced ids once instead of scanning per row.
    try writeQuery(ws, &store, "obsolete_intents", "SELECT count(*) FROM effect_intents WHERE intent_id NOT IN (SELECT intent_id FROM native_effects WHERE intent_id IS NOT NULL);");
    try writeQuery(ws, &store, "obsolete_observations", "SELECT count(*) FROM effect_observations WHERE intent_id NOT IN (SELECT intent_id FROM native_effects WHERE intent_id IS NOT NULL);");
    try writeQuery(ws, &store, "action_targets_without_retained_event", "SELECT count(*) FROM action_targets a WHERE NOT EXISTS(SELECT 1 FROM confirmed_effect_events e WHERE e.scope_key=a.scope_key AND e.jail=a.jail AND e.decision_id=a.action_id);");
    try writeQuery(ws, &store, "unsettled_intents", "SELECT count(*) FROM effect_intents WHERE status IN(1,2);");
    try writeQuery(ws, &store, "unsettled_action_targets", "SELECT count(*) FROM action_targets WHERE status IN(1,2,5);");
    try writeQuery(ws, &store, "oldest_retained_confirmed_us", "SELECT coalesce(min(confirmed_us),0) FROM confirmed_effect_events;");
    try ws.endObject();

    try ws.objectField("invariants");
    try ws.beginObject();
    try writeQuery(ws, &store, "stream_contiguous", "SELECT (SELECT count(*) FROM confirmed_history_sequence)=(SELECT head-retained_from+1 FROM confirmed_history_stream WHERE id=1) AND (SELECT coalesce(min(sequence),(SELECT retained_from FROM confirmed_history_stream)) FROM confirmed_history_sequence)=(SELECT retained_from FROM confirmed_history_stream);");
    try writeQuery(ws, &store, "every_event_sequenced", "SELECT NOT EXISTS(SELECT 1 FROM confirmed_effect_events e WHERE NOT EXISTS(SELECT 1 FROM confirmed_history_sequence s WHERE s.event_id=e.event_id));");
    try writeQuery(ws, &store, "every_detail_retry_linked", "SELECT NOT EXISTS(SELECT 1 FROM confirmed_event_details d JOIN confirmed_effect_events e USING(event_id) LEFT JOIN retry_decision_details r ON r.jail=e.jail AND r.effect_decision_id=e.decision_id WHERE r.jail IS NULL);");
    try writeQuery(ws, &store, "one_current_intent_per_scope", "SELECT NOT EXISTS(SELECT 1 FROM native_effects n WHERE n.intent_id IS NULL OR NOT EXISTS(SELECT 1 FROM effect_intents i WHERE i.intent_id=n.intent_id AND i.scope_key=n.scope_key));");
    try writeQuery(ws, &store, "current_owner_revision_recorded", "SELECT NOT EXISTS(SELECT 1 FROM effect_owners o WHERE NOT EXISTS(SELECT 1 FROM effect_owner_revisions h WHERE h.scope_key=o.scope_key AND h.jail=o.jail AND h.revision=o.revision));");
    try ws.endObject();

    if (try store.integer("SELECT count(*) FROM confirmed_history_sequence;") <= 256) {
        try ws.objectField("events");
        try ws.beginArray();
        var rows = try store.statement("SELECT s.sequence,e.confirmed_us,e.jail,r.subject,CASE WHEN d.event_id IS NULL THEN -1 WHEN d.evidence IS NULL THEN NULL ELSE length(CAST(d.evidence AS BLOB)) END,e.event_id FROM confirmed_history_sequence s JOIN confirmed_effect_events e USING(event_id) LEFT JOIN confirmed_event_details d USING(event_id) LEFT JOIN retry_decision_details r ON r.jail=e.jail AND r.effect_decision_id=e.decision_id ORDER BY s.sequence;");
        defer rows.deinit();
        while (try rows.row()) {
            try ws.beginObject();
            try ws.objectField("sequence");
            try ws.write(try rows.signed(0));
            try ws.objectField("confirmed_us");
            try ws.write(try rows.signed(1));
            try ws.objectField("jail");
            try ws.write(try rows.boundedBytes(2, 64));
            try ws.objectField("subject");
            try writeHex(ws, try rows.boundedBytes(3, 16));
            try ws.objectField("evidence_bytes");
            try ws.write(try rows.optionalSigned(4));
            try ws.objectField("event_id");
            try writeHex(ws, try rows.boundedBytes(5, 32));
            try ws.endObject();
        }
        try ws.endArray();
    }
    try ws.endObject();
}

fn writeGen(ws: anytype, gen: *Gen) !void {
    try ws.objectField("clock_start_us");
    try ws.write(epoch_us);
    try ws.objectField("clock_end_us");
    try ws.write(gen.clock.now);
    try ws.objectField("cycles");
    try ws.write(gen.cycle);
    try ws.objectField("stats");
    try ws.write(gen.stats);
    try ws.objectField("active_leases_at_end");
    try ws.write(gen.leases.items.len);
    try ws.objectField("first_refusal");
    if (gen.refusal) |refusal| try ws.write(refusal) else try ws.write(null);
    try ws.objectField("phases");
    try ws.beginArray();
    for (gen.phases.items) |item| {
        try ws.beginObject();
        try ws.objectField("label");
        try ws.write(item.label);
        try ws.objectField("cycle");
        try ws.write(item.cycle);
        try ws.objectField("clock_us");
        try ws.write(item.clock_us);
        try ws.objectField("retained_from");
        try ws.write(item.retained_from);
        try ws.objectField("head");
        try ws.write(item.head);
        for (key_tables, item.counts) |table, value| {
            try ws.objectField(table);
            try ws.write(value);
        }
        try ws.endObject();
    }
    try ws.endArray();
}

fn fileSha256(path: []const u8, out: *[64]u8) !void {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    while (true) {
        const read = try file.read(&buffer);
        if (read == 0) break;
        hash.update(buffer[0..read]);
    }
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    _ = try std.fmt.bufPrint(out, "{}", .{std.fmt.fmtSliceHexLower(&digest)});
}

const Outcome = struct { harness_failure: ?[]const u8 = null };

fn runCase(gen: *Gen, body: anytype, args: anytype) !Outcome {
    var outcome = Outcome{};
    @call(.auto, body, args) catch |failure| {
        const from_store = if (gen.store_failure) |recorded| recorded.failure == failure else false;
        if (from_store and failure != error.OutOfMemory and gen.jails.items.len != 0) {
            gen.refusal = .{ .cycle = gen.cycle, .operation = gen.store_failure.?.operation, .error_name = @errorName(failure) };
        } else outcome.harness_failure = @errorName(failure);
    };
    var timer = try std.time.Timer.start();
    gen.closeStore();
    gen.report.timings.close = timer.read();
    return outcome;
}

const Publication = struct {
    claimed: bool,
    failures: std.BoundedArray([]const u8, 16) = .{},
    fn ok(self: *const Publication) bool {
        return self.claimed and self.failures.len == 0;
    }
};
fn checkPublication(gen: *Gen, harness_failure: ?[]const u8) !Publication {
    var result = Publication{ .claimed = gen.options.normalize };
    if (!result.claimed) return result;
    if (harness_failure != null) try result.failures.append("harness_failure");
    if (gen.refusal != null) try result.failures.append("first_refusal");
    if (gen.report.schedule.future_dated) try result.failures.append("clock_future_dated");
    if (gen.stats.kept_existing != 0) try result.failures.append("kept_existing");
    if (harness_failure != null) return result;
    var store = try durable.Store.openReadOnly(gen.allocator, gen.path);
    defer store.close();
    const count: i64 = @intCast(gen.options.count);
    if (try store.integer("SELECT head FROM confirmed_history_stream WHERE id=1;") != gen.consumer.live.last_sequence) try result.failures.append("history_head_not_at_checkpoint");
    if (try store.integer("SELECT count(*) FROM pending_receipts;") != 0) try result.failures.append("pending_receipts");
    // Spent-scope pruning removes only scopes and owners whose lease is spent, and attach runs no expiry, so live rows change only by the appended bans.
    if (try store.integer("SELECT count(*) FROM native_effects WHERE lease_kind<>0;") - gen.report.base_live_native_effects != count) try result.failures.append("live_native_effects_delta");
    if (try store.integer("SELECT count(*) FROM effect_owners WHERE lease_kind<>0;") - gen.report.base_live_effect_owners != count) try result.failures.append("live_effect_owners_delta");
    if (try store.integer("SELECT count(*) FROM action_targets WHERE status<>3;") != 0) try result.failures.append("unconfirmed_action_targets");
    return result;
}

fn writeAttach(ws: anytype, gen: *Gen, publication: *const Publication) !void {
    const report = &gen.report;
    try ws.objectField("attach");
    try ws.beginObject();
    try ws.objectField("attempted");
    try ws.write(gen.cycle);
    try ws.objectField("committed");
    try ws.write(gen.stats.bans);
    try ws.objectField("batch_records");
    try ws.write(batch_records);
    try ws.objectField("jails");
    try ws.beginArray();
    for (gen.jails.items) |jail| {
        try ws.beginObject();
        try ws.objectField("name");
        try ws.write(jail.name);
        try ws.objectField("generation");
        try writeHex(ws, &jail.generation);
        try ws.objectField("policy");
        try ws.write(jail.policy);
        try ws.objectField("records_after");
        try ws.write(jail.records);
        try ws.objectField("appended");
        try ws.write(jail.appended);
        try ws.endObject();
    }
    try ws.endArray();
    try ws.objectField("addresses");
    try ws.beginObject();
    try ws.objectField("first");
    try writeAddress(ws, gen.options.address_start);
    try ws.objectField("last");
    if (gen.stats.bans == 0) try ws.write(null) else try writeAddress(ws, gen.options.address_start + gen.stats.bans - 1);
    try ws.endObject();
    try ws.objectField("clock");
    try ws.write(report.schedule);
    try ws.objectField("history");
    try ws.beginObject();
    try ws.objectField("normalize");
    try ws.write(gen.options.normalize);
    try ws.objectField("restored_sequence");
    try ws.write(report.history.restored_sequence);
    try ws.objectField("base_backlog");
    try ws.write(report.history.base_backlog);
    try ws.objectField("head");
    try ws.write(report.history.head);
    try ws.objectField("checkpoint");
    try ws.write(report.history.checkpoint);
    try ws.objectField("backlog");
    try ws.write(report.history.backlog);
    try ws.endObject();
    try ws.objectField("base_counts");
    try ws.beginObject();
    try ws.objectField("live_native_effects");
    try ws.write(report.base_live_native_effects);
    try ws.objectField("live_effect_owners");
    try ws.write(report.base_live_effect_owners);
    try ws.endObject();
    try ws.objectField("chunks");
    try ws.write(report.chunks.items);
    try ws.objectField("publication");
    try ws.beginObject();
    try ws.objectField("claimed");
    try ws.write(publication.claimed);
    try ws.objectField("ok");
    try ws.write(publication.ok());
    try ws.objectField("failures");
    try ws.write(publication.failures.constSlice());
    try ws.endObject();
    try ws.endObject();
}
fn writeAddress(ws: anytype, index: u64) !void {
    var buffer: [16]u8 = undefined;
    const subject = attachSubject(index);
    try ws.write(try std.fmt.bufPrint(&buffer, "{d}.{d}.{d}.{d}", .{ subject.v4[0], subject.v4[1], subject.v4[2], subject.v4[3] }));
}

// Standalone Store observations; the verifier, not this producer, decides acceptance.
const PoolLog = struct {
    file: std.fs.File,
    timer: std.time.Timer,
    overall_peak: i64 = 0,
    const memoryUsed = @extern(*const fn () callconv(.c) i64, .{ .name = "sqlite3_memory_used" });
    const memoryHighwater = @extern(*const fn (c_int) callconv(.c) i64, .{ .name = "sqlite3_memory_highwater" });
    const hardHeap = @extern(*const fn (i64) callconv(.c) i64, .{ .name = "sqlite3_hard_heap_limit64" });
    const columnCount = @extern(*const fn (?*anyopaque) callconv(.c) c_int, .{ .name = "sqlite3_column_count" });

    fn emit(self: *PoolLog, value: anytype) !void {
        try std.json.stringify(value, .{}, self.file.writer());
        try self.file.writeAll("\n");
        try self.file.sync();
    }
    fn memory(self: *PoolLog, gen: ?*Gen, label: []const u8) !void {
        const peak = memoryHighwater(1);
        self.overall_peak = @max(self.overall_peak, peak);
        var values = [_]i64{0} ** 5;
        if (gen) |g| {
            for ([_]c_int{ 1, 2, 3, 7, 8 }, &values) |op, *value| {
                var unused: i64 = 0;
                if (sqlite3_db_status64(@ptrCast(g.store.db), op, value, &unused, 0) != 0) return error.FixtureCacheStatus;
            }
        }
        try self.emit(.{ .event = "memory", .label = label, .elapsed_ns = self.timer.read(), .sqlite_current = memoryUsed(), .phase_highwater = peak, .overall_highwater = self.overall_peak, .hard_limit = hardHeap(-1), .cache_bytes = values[0], .schema_bytes = values[1], .statement_bytes = values[2], .cache_hits = values[3], .cache_misses = values[4] });
    }
    fn api(self: *PoolLog, gen: *Gen, operation: []const u8, outcome: []const u8, serial: ?u64) !void {
        try self.emit(.{ .event = "api", .database = gen.path, .operation = operation, .outcome = outcome, .serial = serial, .clock_us = gen.clock.now, .autocommit = gen.store.api.get_autocommit(gen.store.db), .inline_work_left = gen.store.retry_admission_work_left, .target_hint = gen.store.retry_admission_target_hint, .reopen_required = gen.store.reopen_required, .rollback_error_code = gen.store.rollback_error_code });
    }
};

const PoolInput = struct {
    jail: usize,
    serial: u64,
    subject: detection.Subject,
    occurrence: [32]u8 = undefined,
    len: usize = 0,
    raw_hash: [32]u8 = undefined,
    receipt: ?Timestamp = null,
    revision: u64 = 0,
    operation: []const u8 = "input",

    fn init(jail: usize, serial: u64, subject: detection.Subject) !PoolInput {
        var input = PoolInput{ .jail = jail, .serial = serial, .subject = subject };
        const text = try std.fmt.bufPrint(&input.occurrence, "pool-{d}", .{serial});
        input.len = text.len;
        std.crypto.hash.sha2.Sha256.hash(text, &input.raw_hash, .{});
        return input;
    }
    fn identity(self: *const PoolInput, gen: *Gen) durable.ReceiptIdentity {
        const jail = gen.jails.items[self.jail];
        return .{ .jail = jail.name, .source = source_name, .occurrence = self.occurrence[0..self.len], .cursor = self.occurrence[0..self.len], .raw_hash = self.raw_hash, .generation = jail.generation };
    }
    fn reserve(self: *PoolInput, gen: *Gen) !void {
        self.operation = "revision";
        self.revision = try gen.store.revision(gen.jails.items[self.jail].name);
        self.operation = "beginReceipt";
        self.receipt = try gen.store.beginReceipt(self.identity(gen), .{ .us = gen.clock.now }, self.revision);
    }
    fn record(self: *const PoolInput, gen: *Gen) !durable.Record {
        return gen.detectionRecord(gen.jails.items[self.jail], self.identity(gen), self.receipt orelse return error.FixtureUnexpectedValue, self.subject, self.serial, gen.options.evidence, self.revision);
    }
    fn commit(self: *PoolInput, gen: *Gen) !durable.CommitResult {
        if (self.receipt == null) try self.reserve(gen);
        self.operation = "constructRecord";
        const value = try self.record(gen);
        self.operation = "commitRecord";
        return gen.store.commitRecord(value);
    }
    fn stage(self: *PoolInput, gen: *Gen, frame: anytype) !durable.CommitResult {
        self.operation = "openBatchRecord";
        try gen.store.openBatchRecord(frame);
        errdefer gen.store.dropBatchRecord(frame);
        self.revision = try gen.store.revision(gen.jails.items[self.jail].name);
        self.operation = "reserveReceiptStep";
        const step_result = try gen.store.reserveReceiptStep(self.identity(gen), .{ .us = gen.clock.now }, self.revision);
        self.receipt = step_result.time;
        self.operation = "constructRecord";
        const value = try self.record(gen);
        self.operation = "closeBatchRecord";
        return gen.store.closeBatchRecord(frame, value);
    }
};

fn poolJail(gen: *Gen, name: []const u8, policy: retry.Policy) !usize {
    const owned = try gen.allocator.dupe(u8, name);
    errdefer gen.allocator.free(owned);
    var seed: [8]u8 = undefined;
    std.mem.writeInt(u64, &seed, gen.options.seed, .little);
    const jail = Jail{ .name = owned, .generation = effects.hashParts("fail2zig-load-fixture-jail-v1", &.{ name, &seed }), .policy = policy };
    try gen.store.admitRetry(jail.name, jail.generation, jail.policy);
    try gen.jails.append(jail);
    return gen.jails.items.len - 1;
}
fn poolPrepare(gen: *Gen) !void {
    var names: [64][]const u8 = undefined;
    for (gen.jails.items, 0..) |jail, i| names[i] = jail.name;
    try gen.store.validateRuntimeOwnerNames(names[0..gen.jails.items.len]);
    var validation = durable.Store.MaintenanceValidation{};
    while (!try gen.store.validateMaintenanceTurn(&validation)) {}
    try gen.store.finishMaintenanceValidation(&validation);
    try gen.store.prepareRetryAdmissionView(names[0..gen.jails.items.len], gen.clock.now);
    while (try gen.store.retryAdmissionStep(256) == .progressed) {}
}
fn poolNew(allocator: std.mem.Allocator, dir: []const u8, name: []const u8) !*Gen {
    const gen = try Gen.create(allocator, dir, name, .{ .evidence = 198, .normalize = false }, false);
    errdefer gen.destroy();
    try gen.setup();
    return gen;
}
fn poolPolicy(maxretry: u16, limit: u32, permanent: bool, enforce: bool) retry.Policy {
    return .{ .maxretry = maxretry, .window_us = 3600 * second_us, .duration = if (permanent) .permanent else .{ .finite_us = 60 * second_us }, .max_subjects = limit, .enforce = enforce };
}
fn poolSubject(index: u64, ipv6: bool) detection.Subject {
    if (!ipv6) return host(198, 19, @truncate(index >> 8), @truncate(index));
    var address = [_]u8{0} ** 16;
    address[0..4].* = .{ 0x20, 0x01, 0x0d, 0xb8 };
    std.mem.writeInt(u64, address[8..16], index, .big);
    return .{ .v6 = address };
}
fn poolCommitObserved(log: *PoolLog, gen: *Gen, input: *PoolInput) !void {
    const result = input.commit(gen) catch |failure| {
        try log.api(gen, input.operation, @errorName(failure), input.serial);
        return;
    };
    try log.api(gen, "commitRecord", @tagName(result), input.serial);
}
fn poolStageObserved(log: *PoolLog, gen: *Gen, frame: anytype, input: *PoolInput) !void {
    const result = input.stage(gen, frame) catch |failure| {
        try log.api(gen, input.operation, @errorName(failure), input.serial);
        return;
    };
    try log.api(gen, "closeBatchRecord", @tagName(result), input.serial);
}
fn poolHashRow(hash: *std.crypto.hash.sha2.Sha256, row: *durable.Stmt) !void {
    const columns = PoolLog.columnCount(@ptrCast(row.ptr));
    for (0..@as(usize, @intCast(columns))) |i| {
        const column: c_int = @intCast(i);
        const kind = row.store.api.column_type(row.ptr, column);
        hash.update(&.{@intCast(kind)});
        var size: [8]u8 = undefined;
        if (kind == 1) {
            std.mem.writeInt(i64, &size, try row.signed(column), .little);
            hash.update(&size);
        } else if (kind == 3 or kind == 4) {
            const bytes = try row.bytes(column);
            std.mem.writeInt(u64, &size, bytes.len, .little);
            hash.update(&size);
            hash.update(bytes);
        } else if (kind != 5) return error.FixtureUnexpectedValue;
    }
    hash.update(&.{0xff});
}
fn poolHash(store: *durable.Store, sql: [:0]const u8) ![64]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var row = try store.statement(sql);
    defer row.deinit();
    while (try row.row()) try poolHashRow(&hash, &row);
    return std.fmt.bytesToHex(hash.finalResult(), .lower);
}
fn poolViewHash(store: *durable.Store) ![64]u8 {
    const Cursor = struct { jail: i64, family: i64, subject: [16]u8, len: usize };
    var cursor: ?Cursor = null;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    while (true) {
        const previous = cursor;
        var row = try store.statement(if (previous != null) "SELECT * FROM temp.retry_admission_rows WHERE (jail_id,family,subject)>(?1,?2,?3) ORDER BY jail_id,family,subject LIMIT 256;" else "SELECT * FROM temp.retry_admission_rows ORDER BY jail_id,family,subject LIMIT 256;");
        defer row.deinit();
        if (previous) |*last| {
            try row.int(1, last.jail);
            try row.int(2, last.family);
            try row.blob(3, last.subject[0..last.len]);
        }
        var count: usize = 0;
        while (try row.row()) {
            try poolHashRow(&hash, &row);
            const subject = try row.boundedBytes(2, 16);
            var next = Cursor{ .jail = try row.signed(0), .family = try row.signed(1), .subject = undefined, .len = subject.len };
            @memcpy(next.subject[0..subject.len], subject);
            cursor = next;
            count += 1;
        }
        if (count == 0) break;
    }
    return std.fmt.bytesToHex(hash.finalResult(), .lower);
}
fn poolProbeHeader(writer: anytype, value: anytype) !void {
    var buffer: [2048]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    try std.json.stringify(value, .{}, stream.writer());
    const bytes = stream.getWritten();
    try writer.writeAll(bytes[0 .. bytes.len - 1]);
}
// Preserve SELECT * column order and SQLite type tags used by poolHashRow.
fn poolTypedRow(writer: anytype, row: *durable.Stmt) !void {
    if (!try row.row()) return writer.writeAll("null");
    try poolTypedColumns(writer, row);
}
fn poolTypedColumns(writer: anytype, row: *durable.Stmt) !void {
    try writer.writeByte('[');
    const columns: usize = @intCast(PoolLog.columnCount(@ptrCast(row.ptr)));
    for (0..columns) |i| {
        if (i != 0) try writer.writeByte(',');
        const column: c_int = @intCast(i);
        const kind = row.store.api.column_type(row.ptr, column);
        try writer.print("[{d},", .{kind});
        switch (kind) {
            1 => try std.json.stringify(try row.signed(column), .{}, writer),
            3 => try std.json.stringify(try row.bytes(column), .{}, writer),
            4 => try writer.print("\"{}\"", .{std.fmt.fmtSliceHexLower(try row.bytes(column))}),
            5 => try writer.writeAll("null"),
            else => return error.FixtureUnexpectedValue,
        }
        try writer.writeByte(']');
    }
    try writer.writeByte(']');
}
fn poolTypedRows(writer: anytype, row: *durable.Stmt) !void {
    try writer.writeByte('[');
    var separator = false;
    while (try row.row()) {
        if (separator) try writer.writeByte(',');
        try poolTypedColumns(writer, row);
        separator = true;
    }
    try writer.writeByte(']');
}
fn poolProbe(log: *PoolLog, gen: *Gen, label: []const u8, input: *const PoolInput, include_subject: bool) !void {
    const jail = gen.jails.items[input.jail].name;
    const family: u8 = if (input.subject == .v4) 4 else 6;
    const bytes: []const u8 = switch (input.subject) {
        .v4 => |*value| value[0..],
        .v6 => |*value| value[0..],
    };
    var encoded: [32]u8 = undefined;
    const subject = try std.fmt.bufPrint(&encoded, "{}", .{std.fmt.fmtSliceHexLower(bytes)});
    var buffered = std.io.bufferedWriter(log.file.writer());
    const writer = buffered.writer();
    if (include_subject) {
        try poolProbeHeader(writer, .{ .event = "probe", .label = label, .jail = jail, .family = family, .subject_hex = subject });
        inline for (.{
            .{ "working", "SELECT * FROM retry_states WHERE jail=?1 AND family=?2 AND subject=?3;", 3 },
            .{ "projected", "SELECT * FROM temp.retry_admission_rows WHERE jail_id=(SELECT jail_id FROM temp.retry_publication_jails WHERE jail=?1) AND family=?2 AND subject=?3;", 3 },
            .{ "retired", "SELECT * FROM retry_retired WHERE jail=?1 AND family=?2 AND subject=?3;", 3 },
            .{ "retired_total", "SELECT * FROM retry_retired_totals WHERE jail=?1;", 1 },
        }) |entry| {
            try writer.writeAll(",\"" ++ entry[0] ++ "\":");
            var row = try gen.store.statement(entry[1]);
            defer row.deinit();
            try row.text(1, jail);
            if (entry[2] == 3) {
                try row.int(2, family);
                try row.blob(3, bytes);
            }
            try poolTypedRow(writer, &row);
        }
        try writer.writeAll("}\n");
    }
    try poolProbeHeader(writer, .{ .event = "input_probe", .label = label, .jail = jail, .serial = input.serial });
    inline for (.{
        .{ "record", "SELECT * FROM records WHERE jail=?1 AND source=?2 AND occurrence=?3;", 3 },
        .{ "pending_receipt", "SELECT * FROM pending_receipts WHERE jail=?1 AND source=?2;", 2 },
        .{ "checkpoint", "SELECT * FROM checkpoints WHERE jail=?1;", 1 },
        .{ "source_cursor", "SELECT * FROM source_cursors WHERE jail=?1 AND source=?2;", 2 },
    }) |entry| {
        try writer.writeAll(",\"" ++ entry[0] ++ "\":");
        var row = try gen.store.statement(entry[1]);
        defer row.deinit();
        try row.text(1, jail);
        if (entry[2] >= 2) try row.text(2, source_name);
        if (entry[2] == 3) try row.text(3, input.occurrence[0..input.len]);
        try poolTypedRow(writer, &row);
    }
    inline for (.{
        .{ "decisions", "SELECT * FROM retry_decisions WHERE jail=?1 AND source=?2 AND occurrence=?3 ORDER BY family,subject;" },
        .{ "details", "SELECT * FROM retry_decision_details WHERE jail=?1 AND source=?2 AND occurrence=?3 ORDER BY family,subject;" },
    }) |entry| {
        try writer.writeAll(",\"" ++ entry[0] ++ "\":");
        var row = try gen.store.statement(entry[1]);
        defer row.deinit();
        try row.text(1, jail);
        try row.text(2, source_name);
        try row.text(3, input.occurrence[0..input.len]);
        try poolTypedRows(writer, &row);
    }
    try writer.writeAll("}\n");
    try buffered.flush();
    try log.file.sync();
}
fn poolOwnerProbe(log: *PoolLog, gen: *Gen, label: []const u8, subject: detection.Subject) !void {
    const jail = gen.jails.items[0].name;
    const scope = try effects.Scope.host(subject);
    const key = try scope.key(gen.installation);
    const entry = try gen.store.readEffect(key, gen.installation);
    var owners: [effects.max_page]effects.Owner = undefined;
    const count = try gen.store.readOwners(key, &owners);
    var lease: ?[]const u8 = null;
    var revision: ?u64 = null;
    for (owners[0..count]) |owner| if (std.mem.eql(u8, owner.jail.slice(), jail)) {
        lease = @tagName(owner.lease);
        revision = owner.revision;
    };
    const bytes: []const u8 = switch (subject) {
        .v4 => |*value| value[0..],
        .v6 => |*value| value[0..],
    };
    var encoded: [32]u8 = undefined;
    const text = try std.fmt.bufPrint(&encoded, "{}", .{std.fmt.fmtSliceHexLower(bytes)});
    try log.emit(.{ .event = "owner_probe", .label = label, .jail = jail, .family = if (subject == .v4) @as(u8, 4) else 6, .subject_hex = text, .desired = if (entry) |value| @as(?[]const u8, @tagName(value.desired)) else null, .status = if (entry) |value| @as(?[]const u8, @tagName(value.status)) else null, .owner_lease = lease, .owner_revision = revision });
}
fn poolProbes(log: *PoolLog, gen: *Gen, label: []const u8) !void {
    if (std.mem.endsWith(u8, gen.path, "/pool-order.sqlite")) {
        for (0..17) |i| {
            const subject = poolSubject(i + 1, i % 2 == 1 or i == 16);
            const input = try PoolInput.init(63 - i / 2, i + 1, subject);
            try poolProbe(log, gen, label, &input, true);
            if (i < 16 and std.mem.eql(u8, label, "all-sixteen-pinned")) try poolOwnerProbe(log, gen, label, subject);
        }
        const held = try PoolInput.init(54, 1000, poolSubject(200, false));
        try poolProbe(log, gen, label, &held, true);
    } else if (std.mem.endsWith(u8, gen.path, "/pool-fault.sqlite")) {
        for (0..4) |i| {
            const input = try PoolInput.init(if (i == 1) 1 else 0, i + 1, poolSubject(if (i == 3) 1 else i + 1, i == 1 or i == 2));
            try poolProbe(log, gen, label, &input, i != 3);
        }
    } else if (std.mem.endsWith(u8, gen.path, "/pool-time.sqlite")) {
        for ([_]u64{ 1, 257, 258, 1000 }) |serial| {
            const input = try PoolInput.init(if (serial == 1000) 2 else if (serial == 258) 1 else 0, serial, poolSubject(serial, true));
            try poolProbe(log, gen, label, &input, true);
        }
    } else if (std.mem.endsWith(u8, gen.path, "/pool-resource.sqlite")) {
        for (0..64) |i| {
            const original = try PoolInput.init(31, 32 * (i + 1), poolSubject(32 * (i + 1), true));
            try poolProbe(log, gen, label, &original, true);
            const staged = try PoolInput.init(i % 32, 200000 + i, poolSubject(200000 + i, true));
            try poolProbe(log, gen, label, &staged, true);
            if (i < 32) {
                const prefix = try PoolInput.init(i % 32, 300000 + i, poolSubject(300000 + i, true));
                try poolProbe(log, gen, label, &prefix, true);
            }
        }
        const failed = try PoolInput.init(0, 400000, poolSubject(400000, true));
        try poolProbe(log, gen, label, &failed, true);
    }
}
fn poolFacts(log: *PoolLog, gen: *Gen, label: []const u8, full: bool) !void {
    try log.memory(gen, label);
    const total = try gen.store.integer("SELECT count(*) FROM retry_states;");
    const records = try gen.store.integer("SELECT count(*) FROM records;");
    const pending = try gen.store.integer("SELECT count(*) FROM pending_receipts;");
    var meta = try gen.store.statement("SELECT total,live,as_of_us,target_us,ready FROM temp.retry_admission_meta WHERE id=1;");
    const present = try meta.row();
    const total_view = if (present) try meta.signed(0) else null;
    const live_view = if (present) try meta.signed(1) else null;
    const as_of = if (present) try meta.signed(2) else null;
    const target = if (present) try meta.optionalSigned(3) else null;
    const ready = if (present) try meta.signed(4) else null;
    meta.deinit();
    try log.emit(.{ .event = "facts", .label = label, .database = gen.path, .clock_us = gen.clock.now, .rows = total, .records = records, .pending_receipts = pending, .view_total = total_view, .view_live = live_view, .as_of_us = as_of, .target_us = target, .ready = ready, .retry_floor = try gen.store.readRetryClock(), .receipt_floor = try gen.store.readReceiptClock(), .autocommit = gen.store.api.get_autocommit(gen.store.db) });
    if (!full) return;
    try log.emit(.{ .event = "settings", .label = label, .main_pages = try gen.store.integer("PRAGMA main.page_count;"), .temp_pages = try gen.store.integer("PRAGMA temp.page_count;"), .page_size = try gen.store.integer("PRAGMA page_size;"), .cache_size = try gen.store.integer("PRAGMA cache_size;"), .temp_store = try gen.store.integer("PRAGMA temp_store;"), .synchronous = try gen.store.integer("PRAGMA synchronous;") });
    const row_digest = try poolViewHash(&gen.store);
    const dictionary_digest = try poolHash(&gen.store, "SELECT * FROM temp.retry_publication_jails ORDER BY jail_id;");
    const meta_digest = try poolHash(&gen.store, "SELECT * FROM temp.retry_admission_meta ORDER BY id;");
    try log.emit(.{ .event = "view_fingerprints", .label = label, .rows = row_digest[0..], .dictionary = dictionary_digest[0..], .meta = meta_digest[0..] });
    {
        var pages = try gen.store.statement("SELECT name,count(*),sum(pgsize),sum(payload),sum(unused) FROM dbstat('temp') GROUP BY name ORDER BY name;");
        defer pages.deinit();
        while (try pages.row()) try log.emit(.{ .event = "temp_object", .label = label, .name = try pages.bytes(0), .pages = try pages.signed(1), .bytes = try pages.signed(2), .payload_bytes = try pages.signed(3), .unused_bytes = try pages.signed(4) });
    }
    var reader: ?durable.Store = null;
    if (gen.store.api.get_autocommit(gen.store.db) != 0) reader = try durable.Store.openReadOnly(gen.allocator, gen.path);
    defer if (reader) |*value| value.close();
    const oracle = if (reader) |*value| value else &gen.store;
    inline for (.{
        .{ "retry_states", "SELECT * FROM retry_states ORDER BY jail,family,subject;" },
        .{ "retry_retired", "SELECT * FROM retry_retired ORDER BY jail,family,subject;" },
        .{ "retry_retired_totals", "SELECT * FROM retry_retired_totals ORDER BY jail;" },
        .{ "records", "SELECT * FROM records ORDER BY jail,source,occurrence;" },
        .{ "pending_receipts", "SELECT * FROM pending_receipts ORDER BY jail,source;" },
        .{ "checkpoints", "SELECT * FROM checkpoints ORDER BY jail;" },
        .{ "source_cursors", "SELECT * FROM source_cursors ORDER BY jail,source;" },
        .{ "retry_decisions", "SELECT * FROM retry_decisions ORDER BY jail,source,occurrence,ordinal;" },
        .{ "retry_decision_details", "SELECT * FROM retry_decision_details ORDER BY jail,source,occurrence;" },
    }) |entry| {
        const digest = try poolHash(oracle, entry[1]);
        try log.emit(.{ .event = "main_fingerprint", .label = label, .table = entry[0], .sha256 = digest[0..] });
    }
    for (gen.jails.items) |jail| {
        var sum: u128 = try oracle.retiredTotal(jail.name);
        var working = try oracle.statement("SELECT decisions FROM retry_states WHERE jail=?1;");
        try working.text(1, jail.name);
        while (try working.row()) {
            const value = try working.signed(0);
            if (value < 0) return error.FixtureUnexpectedValue;
            sum += @as(u64, @intCast(value));
        }
        working.deinit();
        if (gen.store.api.get_autocommit(gen.store.db) != 0 and ready == 1) {
            const summary = try gen.store.retryJailSummary(jail.name);
            try log.emit(.{ .event = "summary", .label = label, .jail = jail.name, .main_u128 = sum, .provider_u64 = summary.decisions, .revision = summary.revision });
        } else {
            var buffered = std.io.bufferedWriter(log.file.writer());
            const writer = buffered.writer();
            try poolProbeHeader(writer, .{ .event = "summary_staged", .label = label, .jail = jail.name, .main_u128 = sum });
            try writer.writeAll(",\"projected\":");
            var row = try gen.store.statement("SELECT * FROM temp.retry_publication_jails WHERE jail=?1;");
            defer row.deinit();
            try row.text(1, jail.name);
            try poolTypedRow(writer, &row);
            try writer.writeAll("}\n");
            try buffered.flush();
            try log.file.sync();
        }
    }
    try poolProbes(log, gen, label);
    var buffer: [128]u8 = undefined;
    try log.memory(gen, try std.fmt.bufPrint(&buffer, "{s}-oracle-overhead", .{label}));
}
fn poolVictims(log: *PoolLog, gen: *Gen, label: []const u8) !void {
    try gen.store.beginWrite();
    errdefer gen.store.rollback();
    var victims: [16]durable.Store.RetryAdmissionVictim = undefined;
    const count = try gen.store.retryAdmissionVictimsTx(gen.clock.now, &victims);
    for (victims[0..count], 0..) |victim, i| {
        var bytes: [16]u8 = undefined;
        const length: usize = switch (victim.subject) {
            .v4 => |value| blk: {
                bytes[0..4].* = value;
                break :blk 4;
            },
            .v6 => |value| blk: {
                bytes = value;
                break :blk 16;
            },
        };
        var encoded: [32]u8 = undefined;
        const subject = try std.fmt.bufPrint(&encoded, "{}", .{std.fmt.fmtSliceHexLower(bytes[0..length])});
        try log.emit(.{ .event = "victim", .label = label, .index = i, .jail = victim.jail.slice(), .last_processed_us = victim.last_processed_us, .family = if (victim.subject == .v4) @as(u8, 4) else 6, .subject_hex = subject });
    }
    gen.store.rollback();
    var rows = try gen.store.statement("SELECT jail,family,subject,last_processed_us FROM retry_states WHERE lease_kind=0 OR (lease_kind=1 AND deadline_us<=?1) ORDER BY last_processed_us,jail,family,subject LIMIT 16;");
    defer rows.deinit();
    try rows.int(1, gen.clock.now);
    var i: usize = 0;
    while (try rows.row()) : (i += 1) {
        var encoded: [32]u8 = undefined;
        const text = try std.fmt.bufPrint(&encoded, "{}", .{std.fmt.fmtSliceHexLower(try rows.bytes(2))});
        try log.emit(.{ .event = "main_victim", .label = label, .index = i, .jail = try rows.bytes(0), .family = try rows.signed(1), .subject_hex = text, .last_processed_us = try rows.signed(3) });
    }
}
fn poolOwner(gen: *Gen, subject: detection.Subject, release: bool, serial: u64) !effects.Entry {
    const jail = gen.jails.items[0];
    const scope = try effects.Scope.host(subject);
    const key = try scope.key(gen.installation);
    var owners: [effects.max_page]effects.Owner = undefined;
    const count = try gen.store.readOwners(key, &owners);
    var revision: u64 = 0;
    for (owners[0..count]) |owner| if (std.mem.eql(u8, owner.jail.slice(), jail.name)) {
        revision = owner.revision;
    };
    var identity: [8]u8 = undefined;
    std.mem.writeInt(u64, &identity, serial, .little);
    return gen.store.setOwner(.{ .scope = scope, .jail = jail.name, .generation = jail.generation, .decision_id = effects.hashParts("pool-owner", &.{&identity}), .expected_revision = revision, .lease = if (release) .absent else .permanent, .decided_us = gen.clock.now, .origin = .manual }, gen.clock.value());
}
fn poolOrder(log: *PoolLog, allocator: std.mem.Allocator, dir: []const u8) !void {
    const gen = try poolNew(allocator, dir, "pool-order");
    defer gen.destroy();
    for (0..64) |i| {
        var name = [_]u8{'x'} ** 64;
        _ = try std.fmt.bufPrint(name[0..8], "pool-{d:0>2}-", .{63 - i});
        _ = try poolJail(gen, &name, poolPolicy(2, 17, false, false));
    }
    try poolPrepare(gen);
    var subjects: [17]detection.Subject = undefined;
    for (&subjects, 0..) |*subject, i| {
        subject.* = poolSubject(i + 1, i % 2 == 1 or i == 16);
        var input = try PoolInput.init(63 - i / 2, i + 1, subject.*);
        _ = try input.commit(gen);
    }
    try poolFacts(log, gen, "seventeen", true);
    try poolVictims(log, gen, "equal-time");
    for (subjects[0..7], 0..) |subject, i| _ = try poolOwner(gen, subject, false, i + 1);
    try poolFacts(log, gen, "prefix-probe-before", true);
    try gen.store.beginWrite();
    const eviction = gen.store.evictIdleSubject(gen.jails.items[0].name, gen.clock.now) catch |failure| {
        gen.store.rollback();
        return failure;
    };
    try log.emit(.{ .event = "prefix_pin_eviction", .report = eviction });
    try poolFacts(log, gen, "prefix-probe-staged", true);
    gen.store.rollback();
    try poolFacts(log, gen, "prefix-probe-rolled-back", true);
    for (subjects[7..16], 7..) |subject, i| _ = try poolOwner(gen, subject, false, i + 1);
    var held = try PoolInput.init(54, 1000, poolSubject(200, false));
    try held.reserve(gen);
    try poolCommitObserved(log, gen, &held);
    try poolFacts(log, gen, "all-sixteen-pinned", true);
    const entry = try poolOwner(gen, subjects[7], true, 1001);
    try log.emit(.{ .event = "released-owner", .status = @tagName(entry.status), .lease = @tagName(entry.desired) });
    try log.memory(gen, "release-pending");
    try poolOwnerProbe(log, gen, "release-pending", subjects[7]);
    try log.memory(gen, "release-pending-oracle-overhead");
    _ = try gen.store.settleOutcome(entry.token(), gen.clock.now, gen.observation(entry), gen.clock.value());
    try log.memory(gen, "release-settled");
    try poolOwnerProbe(log, gen, "release-settled", subjects[7]);
    try log.memory(gen, "release-settled-oracle-overhead");
    try poolCommitObserved(log, gen, &held);
    try poolFacts(log, gen, "held-retry", true);
    gen.closeStore();
    try gen.openStore();
    try poolFacts(log, gen, "order-reopened", true);
}
fn poolFault(log: *PoolLog, allocator: std.mem.Allocator, dir: []const u8) !void {
    const gen = try poolNew(allocator, dir, "pool-fault");
    defer gen.destroy();
    _ = try poolJail(gen, "prefix", poolPolicy(1, 65536, false, false));
    _ = try poolJail(gen, "fault", poolPolicy(1, 65536, false, false));
    try poolPrepare(gen);
    var prefix = try PoolInput.init(0, 1, poolSubject(1, false));
    var held = try PoolInput.init(1, 2, poolSubject(2, true));
    try held.reserve(gen);
    try poolFacts(log, gen, "outside-receipt", true);
    var frame = try gen.store.beginBatch();
    _ = try prefix.stage(gen, &frame);
    gen.store.fail_at = .after_retry_state;
    try poolStageObserved(log, gen, &frame, &held);
    gen.store.fail_at = null;
    try poolFacts(log, gen, "fault-prefix-staged", true);
    try gen.store.commitBatch(&frame);
    try poolFacts(log, gen, "fault-prefix-committed", true);
    try poolCommitObserved(log, gen, &held);
    try poolFacts(log, gen, "fault-held-retry", true);
    var outer = try PoolInput.init(0, 3, poolSubject(3, true));
    frame = try gen.store.beginBatch();
    _ = try outer.stage(gen, &frame);
    try poolFacts(log, gen, "outer-staged", true);
    gen.store.rollback();
    try poolFacts(log, gen, "outer-rollback", true);
    gen.clock.now += 3601 * second_us;
    const candidate = try gen.store.retryRetirementCandidate(gen.jails.items[0].name, null);
    if (candidate) |value| {
        const fence = durable.Store.CleanupFence{ .jail = gen.jails.items[0].name, .source = source_name, .generation = gen.jails.items[0].generation, .jail_revision = try gen.store.revision(gen.jails.items[0].name), .consumer_revision = try gen.store.consumerRevision(), .effect_revision = try gen.store.maintenanceEffectRevision(), .clock = gen.clock.value() };
        gen.store.fail_at = .after_retry_retire;
        if (gen.store.retireRetrySubject(fence, value)) |retired| {
            try log.emit(.{ .event = "retire-result", .retired = retired });
        } else |failure| try log.api(gen, "retireRetrySubject", @errorName(failure), null);
        gen.store.fail_at = null;
        try poolFacts(log, gen, "retire-rollback", true);
        const retired = try gen.store.retireRetrySubject(fence, value);
        try log.emit(.{ .event = "retire-retry", .retired = retired });
        try poolFacts(log, gen, "retire-success", true);
        var resurrect = try PoolInput.init(0, 4, prefix.subject);
        try poolCommitObserved(log, gen, &resurrect);
    }
    try poolFacts(log, gen, "retire-resurrect", true);
    gen.closeStore();
    try gen.openStore();
    try poolFacts(log, gen, "fault-reopened", true);
}
fn poolSample(log: *PoolLog, gen: *Gen, label: []const u8, now: i64) !void {
    const sample = gen.store.retryPoolOccupancy(now) catch |failure| {
        try log.api(gen, "retryPoolOccupancy", @errorName(failure), null);
        return;
    };
    try log.emit(.{ .event = "sample", .label = label, .requested_us = now, .value = sample });
}
fn poolTime(log: *PoolLog, allocator: std.mem.Allocator, dir: []const u8) !void {
    const gen = try poolNew(allocator, dir, "pool-time");
    defer gen.destroy();
    _ = try poolJail(gen, "finite", poolPolicy(1, 65536, false, false));
    _ = try poolJail(gen, "permanent", poolPolicy(1, 65536, true, false));
    _ = try poolJail(gen, "tracking", poolPolicy(2, 1, false, false));
    try poolPrepare(gen);
    for (0..258) |i| {
        var input = try PoolInput.init(if (i == 257) 1 else 0, i + 1, poolSubject(i + 1, true));
        _ = try input.commit(gen);
    }
    const deadline = gen.clock.now + 60 * second_us;
    try poolSample(log, gen, "deadline-minus-one", deadline - 1);
    try poolFacts(log, gen, "before-time-crossing", true);
    gen.clock.now = deadline;
    var input = try PoolInput.init(2, 1000, poolSubject(1000, true));
    var frame = try gen.store.beginBatch();
    try poolStageObserved(log, gen, &frame, &input);
    try poolFacts(log, gen, "time-first-pending", true);
    try poolStageObserved(log, gen, &frame, &input);
    try poolFacts(log, gen, "time-second-pending", true);
    gen.store.rollback();
    try poolFacts(log, gen, "time-frame-rollback", true);
    var turns: usize = 0;
    while (turns < 8) : (turns += 1) {
        const progress = try gen.store.retryAdmissionStep(256);
        try log.api(gen, "retryAdmissionStep", @tagName(progress), null);
        try poolSample(log, gen, "catchup", deadline);
        if (progress == .ready) break;
    }
    try poolFacts(log, gen, "time-ready", true);
    input.receipt = null;
    try poolCommitObserved(log, gen, &input);
    try poolSample(log, gen, "deadline-equality", deadline);
    try poolSample(log, gen, "deadline-plus-one", deadline + 1);
    try poolSample(log, gen, "old-time-request", deadline - 1);
    gen.closeStore();
    try gen.openStore();
    try poolFacts(log, gen, "time-reopened", true);
}
fn poolWarmMain(gen: *Gen) !void {
    inline for (.{
        "SELECT rowid,raw_hash FROM records WHERE rowid>?1 ORDER BY rowid LIMIT 256;",
        "SELECT rowid,evidence FROM retry_decision_details WHERE rowid>?1 ORDER BY rowid LIMIT 256;",
    }) |sql| {
        var after: i64 = 0;
        while (true) {
            const previous = after;
            var row = try gen.store.statement(sql);
            defer row.deinit();
            try row.int(1, previous);
            var count: usize = 0;
            while (try row.row()) {
                after = try row.signed(0);
                _ = try row.bytes(1);
                count += 1;
            }
            if (count == 0) break;
        }
    }
}
fn poolStageControl(log: *PoolLog, gen: *Gen, label: []const u8, point: []const u8) !void {
    try log.emit(.{ .event = "stage_control", .label = label, .point = point, .runtime_limits = gen.store.runtime_limits, .work_remaining = gen.store.work_remaining, .inline_work_left = gen.store.retry_admission_work_left, .row_tallies = gen.store.row_tallies, .autocommit = gen.store.api.get_autocommit(gen.store.db), .reopen_required = gen.store.reopen_required, .rollback_error_code = gen.store.rollback_error_code });
}
fn poolStageKeyProbe(log: *PoolLog, gen: *Gen, label: []const u8, input: *const PoolInput) !void {
    const jail = gen.jails.items[input.jail].name;
    const family: u8 = if (input.subject == .v4) 4 else 6;
    const bytes: []const u8 = switch (input.subject) {
        .v4 => |*value| value[0..],
        .v6 => |*value| value[0..],
    };
    var encoded: [32]u8 = undefined;
    const subject = try std.fmt.bufPrint(&encoded, "{}", .{std.fmt.fmtSliceHexLower(bytes)});
    var buffered = std.io.bufferedWriter(log.file.writer());
    const writer = buffered.writer();
    try poolProbeHeader(writer, .{ .event = "probe", .label = label, .jail = jail, .family = family, .subject_hex = subject });
    inline for (.{
        .{ "working", "SELECT * FROM retry_states WHERE jail=?1 AND family=?2 AND subject=?3;", 3 },
        .{ "projected", "SELECT * FROM temp.retry_admission_rows WHERE jail_id=(SELECT jail_id FROM temp.retry_publication_jails WHERE jail=?1) AND family=?2 AND subject=?3;", 3 },
        .{ "retired", "SELECT * FROM retry_retired WHERE jail=?1 AND family=?2 AND subject=?3;", 3 },
        .{ "retired_total", "SELECT * FROM retry_retired_totals WHERE jail=?1;", 1 },
    }) |entry| {
        try writer.writeAll(",\"" ++ entry[0] ++ "\":");
        var row = try gen.store.statement(entry[1]);
        defer row.deinit();
        try row.text(1, jail);
        if (entry[2] == 3) {
            try row.int(2, family);
            try row.blob(3, bytes);
        }
        try poolTypedRow(writer, &row);
    }
    try writer.writeAll("}\n");
    try buffered.flush();
    try log.file.sync();
}
fn poolStageProjection(log: *PoolLog, gen: *Gen, label: []const u8) !void {
    var buffered = std.io.bufferedWriter(log.file.writer());
    const writer = buffered.writer();
    try poolProbeHeader(writer, .{ .event = "stage_projection", .label = label });
    try writer.writeAll(",\"meta\":");
    {
        var row = try gen.store.statement("SELECT * FROM temp.retry_admission_meta WHERE id=1;");
        defer row.deinit();
        try poolTypedRow(writer, &row);
    }
    try writer.writeAll(",\"dictionary\":");
    {
        var row = try gen.store.statement("SELECT * FROM temp.retry_publication_jails ORDER BY jail_id LIMIT 64;");
        defer row.deinit();
        try poolTypedRows(writer, &row);
    }
    try writer.writeAll("}\n");
    try buffered.flush();
    try log.file.sync();
}
const PoolStage = enum { frame64, failed_record };
fn poolStageFacts(log: *PoolLog, gen: *Gen, stage: PoolStage) !void {
    const label = if (stage == .frame64) "resource-frame64" else "resource-failed-record";
    try log.memory(gen, label);
    try poolStageControl(log, gen, label, "before_observer");
    const total = try gen.store.integer("SELECT count(*) FROM retry_states;");
    const records = try gen.store.integer("SELECT count(*) FROM records;");
    const pending = try gen.store.integer("SELECT count(*) FROM pending_receipts;");
    var meta = try gen.store.statement("SELECT total,live,as_of_us,target_us,ready FROM temp.retry_admission_meta WHERE id=1;");
    const present = try meta.row();
    const total_view = if (present) try meta.signed(0) else null;
    const live_view = if (present) try meta.signed(1) else null;
    const as_of = if (present) try meta.signed(2) else null;
    const target = if (present) try meta.optionalSigned(3) else null;
    const ready = if (present) try meta.signed(4) else null;
    meta.deinit();
    try log.emit(.{ .event = "facts", .label = label, .database = gen.path, .clock_us = gen.clock.now, .rows = total, .records = records, .pending_receipts = pending, .view_total = total_view, .view_live = live_view, .as_of_us = as_of, .target_us = target, .ready = ready, .retry_floor = try gen.store.readRetryClock(), .receipt_floor = try gen.store.readReceiptClock(), .autocommit = gen.store.api.get_autocommit(gen.store.db) });
    try log.emit(.{ .event = "settings", .label = label, .main_pages = try gen.store.integer("PRAGMA main.page_count;"), .temp_pages = try gen.store.integer("PRAGMA temp.page_count;"), .page_size = try gen.store.integer("PRAGMA page_size;"), .cache_size = try gen.store.integer("PRAGMA cache_size;"), .temp_store = try gen.store.integer("PRAGMA temp_store;"), .synchronous = try gen.store.integer("PRAGMA synchronous;") });
    try poolStageProjection(log, gen, label);
    const old_count: usize = if (stage == .frame64) 65 else 33;
    for (0..old_count) |i| {
        const original = try PoolInput.init(31, 32 * (i + 1), poolSubject(32 * (i + 1), true));
        try poolStageKeyProbe(log, gen, label, &original);
    }
    const new_count: usize = if (stage == .frame64) 64 else 32;
    const first_serial: u64 = if (stage == .frame64) 200000 else 300000;
    for (0..new_count) |i| {
        const input = try PoolInput.init(i % 32, first_serial + i, poolSubject(first_serial + i, true));
        try poolStageKeyProbe(log, gen, label, &input);
        try poolProbe(log, gen, label, &input, false);
    }
    if (stage == .failed_record) {
        const failed = try PoolInput.init(0, 400000, poolSubject(400000, true));
        try poolStageKeyProbe(log, gen, label, &failed);
        try poolProbe(log, gen, label, &failed, false);
    }
    try poolStageControl(log, gen, label, "after_observer");
    var buffer: [128]u8 = undefined;
    try log.memory(gen, try std.fmt.bufPrint(&buffer, "{s}-oracle-overhead", .{label}));
}
fn poolResource(log: *PoolLog, allocator: std.mem.Allocator, dir: []const u8) !void {
    const gen = try poolNew(allocator, dir, "pool-resource");
    defer gen.destroy();
    for (0..64) |i| {
        var name = [_]u8{'x'} ** 64;
        _ = try std.fmt.bufPrint(name[0..8], "pool-{d:0>2}-", .{63 - i});
        _ = try poolJail(gen, &name, poolPolicy(if (i < 32) 2 else 1, 65536, false, i >= 32));
    }
    try poolPrepare(gen);
    try log.memory(gen, "resource-setup");
    for (0..2048) |chunk| {
        var frame = try gen.store.beginBatch();
        errdefer gen.store.rollback();
        for (0..64) |offset| {
            const serial = chunk * 64 + offset;
            const jail = (if (serial < 65536) @as(usize, 0) else 32) + serial % 32;
            var input = try PoolInput.init(jail, serial + 1, poolSubject(serial + 1, true));
            _ = input.stage(gen, &frame) catch |failure| {
                try log.api(gen, input.operation, @errorName(failure), input.serial);
                try log.memory(gen, "resource-refusal");
                return failure;
            };
        }
        try gen.store.commitBatch(&frame);
        if (chunk % 256 == 255) try log.memory(gen, "resource-progress");
    }
    try poolFacts(log, gen, "resource-full", true);
    try log.memory(gen, "resource-oracle-overhead");
    try poolWarmMain(gen);
    try log.memory(gen, "resource-after-main-reads");
    var frame = try gen.store.beginBatch();
    for (0..64) |i| {
        var input = try PoolInput.init(i % 32, 200000 + i, poolSubject(200000 + i, true));
        _ = input.stage(gen, &frame) catch |failure| {
            try log.api(gen, input.operation, @errorName(failure), input.serial);
            try log.memory(gen, "resource-refusal");
            return failure;
        };
    }
    try poolStageFacts(log, gen, .frame64);
    gen.store.rollback();
    try poolFacts(log, gen, "resource-outer-rollback", true);
    frame = try gen.store.beginBatch();
    for (0..32) |i| {
        var input = try PoolInput.init(i % 32, 300000 + i, poolSubject(300000 + i, true));
        _ = input.stage(gen, &frame) catch |failure| {
            try log.api(gen, input.operation, @errorName(failure), input.serial);
            try log.memory(gen, "resource-refusal");
            return failure;
        };
    }
    var failed = try PoolInput.init(0, 400000, poolSubject(400000, true));
    gen.store.fail_at = .after_retry_state;
    try poolStageObserved(log, gen, &frame, &failed);
    gen.store.fail_at = null;
    try poolStageFacts(log, gen, .failed_record);
    gen.store.rollback();
    try poolFacts(log, gen, "resource-failed-outer-rollback", true);
    gen.closeStore();
    try log.memory(null, "resource-closed");
    try gen.openStore();
    try poolFacts(log, gen, "resource-reopened", true);
}
fn runPoolContract(allocator: std.mem.Allocator, dir: []const u8, options: []const []const u8) !u8 {
    const resource = options.len == 1 and std.mem.eql(u8, options[0], "resource=1");
    if (options.len != 0 and !resource) return error.InvalidOption;
    _ = std.c.umask(0o077);
    try std.fs.cwd().makePath(dir);
    try std.posix.fchmodat(std.posix.AT.FDCWD, dir, 0o700, 0);
    const path = try std.fmt.allocPrint(allocator, "{s}/pool-contract.jsonl", .{dir});
    defer allocator.free(path);
    const file = try std.fs.cwd().createFile(path, .{ .exclusive = true, .mode = 0o600 });
    defer file.close();
    var log = PoolLog{ .file = file, .timer = try std.time.Timer.start() };
    const exe = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(exe);
    var exe_hash: [64]u8 = undefined;
    try fileSha256(exe, &exe_hash);
    try log.emit(.{ .event = "start", .schema_version = 1, .mode = "pool-contract", .resource = resource, .binary_sha256 = exe_hash[0..], .build_mode = @tagName(@import("builtin").mode), .claim = "standalone production Store APIs; independent verifier required; no daemon/kernel/source-ACK/upgrade claim" });
    const result = if (resource) poolResource(&log, allocator, dir) else blk: {
        poolOrder(&log, allocator, dir) catch |failure| break :blk @as(anyerror!void, failure);
        poolFault(&log, allocator, dir) catch |failure| break :blk @as(anyerror!void, failure);
        break :blk poolTime(&log, allocator, dir);
    };
    result catch |failure| {
        try log.emit(.{ .event = "stopped", .failure = @errorName(failure), .elapsed_ns = log.timer.read(), .sqlite_current = PoolLog.memoryUsed(), .sqlite_highwater = PoolLog.memoryHighwater(0), .hard_limit = PoolLog.hardHeap(-1) });
        return 1;
    };
    try log.memory(null, "closed");
    try log.emit(.{ .event = "complete", .elapsed_ns = log.timer.read(), .acceptance_claimed = false });
    return 0;
}

const HistoryAttach = struct {
    gen: *Gen,
    log: *PoolLog,
    rounds: u8,
    completed_rounds: u8 = 0,
    records: u64 = 0,
    round: u8 = 0,
    chunk: usize = 0,
    const Floors = struct { receipt_us: ?i64, retry_us: ?i64, effect_us: ?i64, admission_us: ?i64 };

    fn deadline(self: *HistoryAttach) !void {
        if (self.log.timer.read() >= 1800 * std.time.ns_per_s) return error.FixturePreparationDeadline;
    }
    fn floors(self: *HistoryAttach) !Floors {
        const receipt = try self.gen.store.readReceiptClock();
        const admission = try self.gen.store.readAdmissionClock(self.gen.store.schema_version);
        var row = try self.gen.store.statement("SELECT floor_us FROM effect_clock WHERE singleton=1;");
        defer row.deinit();
        if (!try row.row()) return error.FixtureUnexpectedValue;
        return .{ .receipt_us = if (receipt) |value| value.us else null, .retry_us = try self.gen.store.readRetryClock(), .effect_us = try row.optionalSigned(0), .admission_us = if (admission) |value| value.us else null };
    }
    fn progress(self: *HistoryAttach, label: []const u8) !void {
        const gen = self.gen;
        var stream = try gen.store.statement("SELECT revision,head,retained_from FROM confirmed_history_stream WHERE id=1;");
        defer stream.deinit();
        if (!try stream.row()) return error.FixtureUnexpectedValue;
        try self.log.emit(.{ .event = "history_progress", .label = label, .round = self.round, .chunk = self.chunk, .requested_rounds = self.rounds, .completed_rounds = self.completed_rounds, .committed_fixture_records = self.records, .stream_revision = try stream.signed(0), .head = try stream.signed(1), .retained_from = try stream.signed(2), .saved_checkpoint = gen.consumer.live.last_sequence, .saved_checkpoint_revision = gen.consumer.revision, .backlog = @as(u64, @intCast(try stream.signed(1))) -| gen.consumer.live.last_sequence, .pending_receipts = try gen.store.integer("SELECT count(*) FROM pending_receipts;"), .clock_us = gen.clock.now, .wall_us = std.time.microTimestamp(), .floors = try self.floors(), .elapsed_ns = self.log.timer.read(), .autocommit = gen.store.api.get_autocommit(gen.store.db), .inline_work_left = gen.store.retry_admission_work_left, .target_hint = gen.store.retry_admission_target_hint, .reopen_required = gen.store.reopen_required, .rollback_error_code = gen.store.rollback_error_code });
    }
    fn facts(self: *HistoryAttach, label: []const u8) !void {
        const gen = self.gen;
        try self.log.memory(gen, label);
        try self.progress(label);
        var counts: [key_tables.len]i64 = undefined;
        inline for (key_tables, 0..) |table, i| counts[i] = try gen.store.integer("SELECT count(*) FROM " ++ table ++ ";");
        const cursors = try poolHash(&gen.store, "SELECT * FROM source_cursors WHERE source<>'fixture' ORDER BY jail,source;");
        const checkpoints = try poolHash(&gen.store, "SELECT jail,payload FROM checkpoints ORDER BY jail;");
        var retention = try gen.store.statement("SELECT generation,max_matches,state,sweep_cursor,retry_evidence_sweep_cursor,history_subject_sweep_cursor FROM retention_policy WHERE id=1;");
        defer retention.deinit();
        if (!try retention.row()) return error.FixtureUnexpectedValue;
        const wall = std.time.microTimestamp();
        const observed_floors = try self.floors();
        try self.log.emit(.{ .event = "history_facts", .label = label, .round = self.round, .completed_rounds = self.completed_rounds, .table_names = key_tables, .counts = counts, .record_detections = try gen.store.integer("SELECT count(*) FROM record_detections;"), .original_source_cursors_sha256 = cursors[0..], .checkpoint_payloads_sha256 = checkpoints[0..], .retention_generation = try retention.signed(0), .retention_max_matches = try retention.signed(1), .retention_state = try retention.signed(2), .retention_sweep = try retention.signed(3), .retry_evidence_sweep = try retention.optionalSigned(4), .history_subject_sweep = try retention.optionalSigned(5), .main_pages = try gen.store.integer("PRAGMA page_count;"), .free_pages = try gen.store.integer("PRAGMA freelist_count;"), .page_size = try gen.store.integer("PRAGMA page_size;"), .cache_size = try gen.store.integer("PRAGMA cache_size;"), .synchronous = try gen.store.integer("PRAGMA synchronous;"), .clock_us = gen.clock.now, .wall_us = wall, .floors = observed_floors, .future_dated = gen.clock.now > wall or (observed_floors.admission_us orelse gen.clock.now) > wall });
        var buffer: [128]u8 = undefined;
        try self.log.memory(gen, try std.fmt.bufPrint(&buffer, "{s}-oracle-overhead", .{label}));
    }
    fn stage(self: *HistoryAttach, frame: anytype, serial: u64, first: usize, keys: []effects.Hash) !void {
        const gen = self.gen;
        const jail = gen.jails.items[0];
        var occurrence_buffer: [32]u8 = undefined;
        const occurrence = try std.fmt.bufPrint(&occurrence_buffer, "fx-{d}", .{serial});
        var raw_hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(occurrence, &raw_hash, .{});
        const identity = durable.ReceiptIdentity{ .jail = jail.name, .source = source_name, .occurrence = occurrence, .cursor = occurrence, .raw_hash = raw_hash, .generation = jail.generation };
        var outcomes: [16]detection.Outcome = undefined;
        for (&outcomes, keys, 0..) |*outcome, *key, i| {
            const subject = attachSubject(@intCast(first + i));
            key.* = try (try effects.Scope.host(subject)).key(gen.installation);
            outcome.* = .{ .kind = .candidate, .generation = jail.generation, .filter = try detection.Name.init("fixture"), .pattern = try detection.Name.init("failure"), .pattern_index = @intCast(i), .subject = subject };
        }
        gen.clock.now += attach_step_us;
        try gen.stored("Store.openBatchRecord", gen.store.openBatchRecord(frame));
        errdefer gen.store.dropBatchRecord(frame);
        const revision = try gen.stored("Store.revision", gen.store.revision(jail.name));
        const reserved = try gen.stored("Store.reserveReceiptStep", gen.store.reserveReceiptStep(identity, .{ .us = gen.clock.now }, revision));
        var record = try gen.detectionRecord(jail, identity, reserved.time, outcomes[0].subject.?, serial, 198, revision);
        record.native_detection = null;
        record.native_detections = &outcomes;
        const result = try gen.stored("Store.closeBatchRecord", gen.store.closeBatchRecord(frame, record));
        if (result == .already_committed) return error.FixtureRecordAlreadyCommitted;
    }
    fn append(self: *HistoryAttach, first: usize) !void {
        const gen = self.gen;
        try self.deadline();
        try gen.prepareRetryTime(gen.clock.now);
        var keys: [64]effects.Hash = undefined;
        {
            var frame = try gen.stored("Store.beginBatch", gen.store.beginBatch());
            errdefer gen.store.rollback();
            for (0..4) |i| try self.stage(&frame, self.records + @as(u64, @intCast(i)) + 1, first + i * 16, keys[i * 16 ..][0..16]);
            var cursor = try gen.store.statement("DELETE FROM source_cursors WHERE jail=?1 AND source=?2;");
            defer cursor.deinit();
            try cursor.text(1, gen.jails.items[0].name);
            try cursor.text(2, source_name);
            try cursor.done();
            try gen.stored("Store.commitBatch", gen.store.commitBatch(&frame));
        }
        self.records += 4;
        gen.cycle = self.records;
        const indices = [_]usize{0} ** 64;
        try gen.settleChunk(&keys, &indices);
        try self.log.memory(gen, "history-chunk");
        try self.progress("chunk");
        try self.log.memory(gen, "history-chunk-oracle-overhead");
    }
    fn expire(self: *HistoryAttach) !void {
        const gen = self.gen;
        gen.clock.now += second_us;
        for (0..64) |chunk| {
            try self.deadline();
            var items: [64]durable.Store.ExpiryItem = undefined;
            for (&items, 0..) |*item, i| {
                const key = try (try effects.Scope.host(attachSubject(@intCast(chunk * 64 + i)))).key(gen.installation);
                const entry = try gen.stored("Store.readEffect", gen.store.readEffect(key, gen.installation)) orelse return error.FixtureMissingEffect;
                item.* = .{ .key = key, .revision = entry.revision };
            }
            const prepared = try gen.stored("Store.prepareExpiries", gen.store.prepareExpiries(&items, gen.clock.value()));
            var tokens: [64]effects.Token = undefined;
            for (items, &tokens) |item, *token| {
                const entry = try gen.stored("Store.readEffect", gen.store.readEffect(item.key, gen.installation)) orelse return error.FixtureMissingEffect;
                if (entry.desired != .absent) return error.FixtureExpiryNotAbsent;
                token.* = entry.token();
            }
            var identity: [16]u8 = undefined;
            std.mem.writeInt(i64, identity[0..8], gen.clock.now, .little);
            std.mem.writeInt(u64, identity[8..16], chunk, .little);
            const fingerprint = effects.hashParts("fail2zig-history-fixture-expiry-v1", &.{&identity});
            const settled = try gen.stored("Store.settleExpired", gen.store.settleExpired(&tokens, fingerprint, gen.clock.now, gen.clock.value()));
            try self.log.emit(.{ .event = "history_expiry", .round = self.round, .chunk = chunk + 1, .prepared = prepared, .settled = settled, .clock_us = gen.clock.now, .elapsed_ns = self.log.timer.read() });
        }
    }
    fn reclaim(self: *HistoryAttach) !void {
        const gen = self.gen;
        try self.log.memory(gen, "before-reclaim");
        for (0..8192) |turn| {
            try self.deadline();
            const rested = gen.store.reclaim.rest != 0;
            const outcome = try gen.stored("Store.reclaimObsoleteOne", gen.store.reclaimObsoleteOne());
            if (turn % 64 == 0 or (outcome == .idle and !rested)) try self.log.emit(.{ .event = "history_reclaim", .round = self.round, .turn = turn + 1, .outcome = @tagName(outcome), .rested = rested, .elapsed_ns = self.log.timer.read() });
            if (outcome == .idle and !rested) return;
        }
        return error.FixtureUnboundedMaintenance;
    }
    fn run(self: *HistoryAttach) !void {
        const gen = self.gen;
        try gen.openStore();
        gen.installation = try gen.stored("Store.readInstallation", gen.store.readInstallation()) orelse return error.FixtureMissingInstallation;
        gen.consumer = try history.Consumer.init(gen.installation, historyPolicyGeneration());
        try gen.restoreHistory();
        try gen.addAttachJail(gen.options.jail);
        try gen.scheduleClock();
        const jail = gen.jails.items[0];
        if (jail.policy.maxretry != 1 or !jail.policy.enforce or jail.policy.duration != .finite_us or jail.policy.duration.finite_us != second_us or jail.policy.escalation.enabled or jail.policy.max_subjects < 4096) return error.FixtureHistoryPolicyMismatch;
        {
            var policy = try gen.store.statement("SELECT p.max_matches,l.max_matches FROM retention_policy p LEFT JOIN history_jail_limits l ON l.jail=?1 WHERE p.id=1;");
            defer policy.deinit();
            try policy.text(1, jail.name);
            if (!try policy.row()) return error.FixtureUnexpectedValue;
            const global = try policy.signed(0);
            if (@min(global, (try policy.optionalSigned(1)) orelse global) != 64) return error.FixtureHistoryPolicyMismatch;
        }
        if (gen.consumer.live.last_sequence != 0 or gen.consumer.live.total_confirmed != 0 or try gen.store.integer("SELECT head FROM confirmed_history_stream WHERE id=1;") != 0 or try gen.store.integer("SELECT count(*) FROM confirmed_effect_events;") != 0 or try gen.store.integer("SELECT count(*) FROM confirmed_event_details;") != 0 or try gen.store.integer("SELECT count(*) FROM retry_states;") != 0 or try gen.store.integer("SELECT count(*) FROM native_effects;") != 0 or try gen.store.integer("SELECT count(*) FROM pending_receipts;") != 0 or jail.records != 0) return error.FixtureHistoryBaseNotEmpty;
        const installation = std.fmt.bytesToHex(gen.installation.id, .lower);
        const generation = std.fmt.bytesToHex(jail.generation, .lower);
        try self.log.emit(.{ .event = "history_base", .schema = try gen.store.integer("PRAGMA user_version;"), .jail = jail.name, .installation_hex = installation[0..], .generation_hex = generation[0..], .maxretry = jail.policy.maxretry, .window_us = jail.policy.window_us, .duration_us = jail.policy.duration.finite_us, .max_subjects = jail.policy.max_subjects, .enforce = jail.policy.enforce, .history_limit = 64, .schedule = gen.report.schedule, .checkpoint = gen.consumer.live.last_sequence });
        try self.facts("base");
        for (0..self.rounds) |round| {
            self.round = @intCast(round + 1);
            for (0..64) |chunk| {
                self.chunk = chunk + 1;
                try self.append(chunk * 64);
            }
            try self.expire();
            self.completed_rounds += 1;
            if (self.completed_rounds % 16 == 0) try self.reclaim();
            try self.facts("round");
        }
        try self.facts("final");
        const wall = std.time.microTimestamp();
        const observed_floors = try self.floors();
        try self.log.emit(.{ .event = "complete", .requested_rounds = self.rounds, .completed_rounds = self.completed_rounds, .committed_fixture_records = self.records, .ceiling_requested = self.rounds == 64, .qualification_only = self.rounds < 64, .clock_us = gen.clock.now, .wall_us = wall, .floors = observed_floors, .daemon_startable_clock = gen.clock.now <= wall and (observed_floors.admission_us orelse gen.clock.now) <= wall, .elapsed_ns = self.log.timer.read(), .acceptance_claimed = false });
    }
};

fn runHistoryAttach(allocator: std.mem.Allocator, dir: []const u8, arguments: []const []const u8) !u8 {
    var jail: ?[]const u8 = null;
    var rounds: u8 = 64;
    var seen_rounds = false;
    for (arguments) |argument| {
        const split = std.mem.indexOfScalar(u8, argument, '=') orelse return error.InvalidOption;
        const key = argument[0..split];
        const value = argument[split + 1 ..];
        if (std.mem.eql(u8, key, "jail") and jail == null) {
            _ = try detection.Name.init(value);
            jail = value;
        } else if (std.mem.eql(u8, key, "rounds") and !seen_rounds) {
            rounds = try std.fmt.parseInt(u8, value, 10);
            if (rounds == 0 or rounds > 64) return error.InvalidOption;
            seen_rounds = true;
        } else return error.InvalidOption;
    }
    const name = jail orelse return error.InvalidOption;
    _ = std.c.umask(0o077);
    const path = try std.fmt.allocPrint(allocator, "{s}/history-attach.jsonl", .{dir});
    defer allocator.free(path);
    const file = try std.fs.cwd().createFile(path, .{ .exclusive = true, .mode = 0o600 });
    defer file.close();
    var log = PoolLog{ .file = file, .timer = try std.time.Timer.start() };
    const exe = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(exe);
    var binary: [64]u8 = undefined;
    try fileSha256(exe, &binary);
    try log.emit(.{ .event = "start", .schema_version = 1, .mode = "history-attach", .binary_sha256 = binary[0..], .build_mode = @tagName(@import("builtin").mode), .jail = name, .requested_rounds = rounds, .subjects = 4096, .outcomes_per_record = 16, .records_per_frame = 4, .decisions_per_chunk = 64, .evidence_bytes = 198, .deadline_seconds = 1800, .claim = "supplied production Store input and complete-owned observations; genuine saved history backlog; no parser/kernel/source-ACK/acceptance claim" });
    const gen = try Gen.attach(allocator, dir, .{ .jail = name, .normalize = false, .max_matches = 64, .evidence = 198 });
    defer gen.destroy();
    var run = HistoryAttach{ .gen = gen, .log = &log, .rounds = rounds };
    const result = blk: {
        var reader = durable.Store.openReadOnly(allocator, gen.path) catch |failure| break :blk @as(anyerror!void, failure);
        const version = reader.integer("PRAGMA user_version;") catch |failure| {
            reader.close();
            break :blk @as(anyerror!void, failure);
        };
        reader.close();
        if (version != durable.latest_schema) break :blk @as(anyerror!void, error.FixtureSchemaIncomplete);
        break :blk run.run();
    };
    result catch |failure| {
        if (gen.store_open) {
            try log.api(gen, if (gen.store_failure) |stored| stored.operation else "history-attach", @errorName(failure), run.records);
            if (!gen.store.reopen_required and gen.store.api.get_autocommit(gen.store.db) != 0) run.facts("failure") catch |observer| {
                try log.emit(.{ .event = "observer_failure", .failure = @errorName(observer) });
            };
        }
        try log.emit(.{ .event = "stopped", .failure = @errorName(failure), .round = run.round, .chunk = run.chunk, .completed_rounds = run.completed_rounds, .committed_fixture_records = run.records, .elapsed_ns = log.timer.read(), .sqlite_current = PoolLog.memoryUsed(), .sqlite_highwater = PoolLog.memoryHighwater(0), .acceptance_claimed = false });
        return 1;
    };
    return 0;
}

pub fn main() !u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const argv = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, argv);
    const stderr = std.io.getStdErr().writer();
    if (argv.len < 3) {
        try stderr.writeAll(usage);
        return 2;
    }
    if (std.mem.eql(u8, argv[1], "pool-contract")) return runPoolContract(allocator, argv[2], argv[3..]);
    if (std.mem.eql(u8, argv[1], "history-attach")) return runHistoryAttach(allocator, argv[2], argv[3..]);
    const shape = std.meta.stringToEnum(Shape, argv[1]) orelse {
        try stderr.writeAll(usage);
        return 2;
    };
    var options = Options.defaults(shape);
    for (argv[3..]) |argument| {
        const split = std.mem.indexOfScalar(u8, argument, '=') orelse {
            try stderr.print("invalid option '{s}'\n{s}", .{ argument, usage });
            return 2;
        };
        options.set(argument[0..split], argument[split + 1 ..]) catch {
            try stderr.print("invalid option '{s}'\n{s}", .{ argument, usage });
            return 2;
        };
    }
    options.validate(shape) catch {
        try stderr.writeAll("option out of range\n");
        return 2;
    };
    _ = std.c.umask(0o077);
    const dir = argv[2];
    if (shape != .attach) {
        try std.fs.cwd().makePath(dir);
        try std.posix.fchmodat(std.posix.AT.FDCWD, dir, 0o700, 0);
    }
    const manifest_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir, if (shape == .attach) "fixture-attach.json" else "manifest.json" });
    defer allocator.free(manifest_path);
    if (std.fs.cwd().access(manifest_path, .{})) |_| {
        try stderr.print("refusing to overwrite {s}\n", .{manifest_path});
        return 2;
    } else |failure| if (failure != error.FileNotFound) return failure;

    const exe = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(exe);
    var exe_hash: [64]u8 = undefined;
    try fileSha256(exe, &exe_hash);

    var output = std.ArrayList(u8).init(allocator);
    defer output.deinit();
    var ws = std.json.writeStream(output.writer(), .{ .whitespace = .indent_2 });
    try ws.beginObject();
    try ws.objectField("shape");
    try ws.write(@tagName(shape));
    try ws.objectField("generator");
    try ws.write("tests/harness/load_repro/fixture.zig");
    try ws.objectField("generator_sha256");
    try ws.write(exe_hash[0..]);
    try ws.objectField("build_mode");
    try ws.write(@tagName(@import("builtin").mode));
    try ws.objectField("arguments");
    try ws.write(argv[1..]);
    try ws.objectField("options");
    try ws.write(options);
    try ws.objectField("construction");
    try ws.write(if (shape == .attach and options.normalize)
        "attach: production Store APIs in group-commit frames with batched settlement; history consumer restored, run with retention after every frame and left at the head; recurrence not processed (fresh distinct subjects)"
    else if (shape == .attach)
        "attach: production Store APIs in group-commit frames with batched settlement; history consumer restored but not run, so the appended backlog is declared in attach.history.backlog; recurrence not processed"
    else if (shape == .@"oracle-cases")
        "production Store APIs; retention maintenance not run during construction"
    else if (options.retention == .skip)
        "diagnostic: production Store APIs with the shipped retention step skipped; not an untouched daemon baseline"
    else
        "production Store APIs in the daemon's runtime order, including the shipped retention step");
    try ws.objectField("connection_synchronous");
    try ws.write(if (options.sync == .off) "OFF on the generator connection (construction speed only; not a durability or timing result)" else "FULL (runtime default)");

    var failed = false;
    var timer = try std.time.Timer.start();
    if (shape == .@"oracle-cases") {
        try ws.objectField("states");
        try ws.beginArray();
        for (oracle_cases) |case| {
            const gen = try Gen.create(allocator, dir, case.name, options, false);
            defer gen.destroy();
            var snapshots = std.ArrayList(Snapshot).init(allocator);
            defer {
                for (snapshots.items) |item| allocator.free(item.path);
                snapshots.deinit();
            }
            const outcome = try runCase(gen, struct {
                fn body(g: *Gen, d: []const u8, s: *std.ArrayList(Snapshot), c: OracleCase) !void {
                    try g.setup();
                    try c.build(g, d, s);
                }
            }.body, .{ gen, dir, &snapshots, case });
            // Oracle states are small by design; any refusal means the state is wrong.
            if (gen.refusal != null or outcome.harness_failure != null) failed = true;
            try ws.beginObject();
            try ws.objectField("case");
            try ws.write(case.name);
            try ws.objectField("harness_failure");
            try ws.write(outcome.harness_failure);
            try writeGen(&ws, gen);
            try ws.objectField("snapshots");
            try ws.beginArray();
            for (snapshots.items) |item| try writeState(&ws, gen, item.label, item.path);
            try ws.endArray();
            try ws.objectField("state");
            if (options.audit == .full) try writeState(&ws, gen, "final", gen.path) else try ws.write(null);
            try ws.endObject();
        }
        try ws.endArray();
    } else {
        const gen = if (shape == .attach) try Gen.attach(allocator, dir, options) else try Gen.create(allocator, dir, @tagName(shape), options, true);
        defer gen.destroy();
        const outcome = switch (shape) {
            .churn => try runCase(gen, runChurn, .{gen}),
            .hot => try runCase(gen, runHot, .{gen}),
            .pinned => try runCase(gen, runPinned, .{gen}),
            .reuse => try runCase(gen, runReuse, .{gen}),
            .attach => try runCase(gen, runAttach, .{gen}),
            .@"oracle-cases" => unreachable,
        };
        if (gen.refusal != null or outcome.harness_failure != null) failed = true;
        try ws.objectField("harness_failure");
        try ws.write(outcome.harness_failure);
        try writeGen(&ws, gen);
        if (shape == .attach) {
            const publication = try checkPublication(gen, outcome.harness_failure);
            try writeAttach(&ws, gen, &publication);
            if (publication.claimed and !publication.ok()) failed = true;
        }
        var audit_timer = try std.time.Timer.start();
        try ws.objectField("state");
        if (options.audit == .full) try writeState(&ws, gen, "final", gen.path) else try ws.write(null);
        gen.report.timings.audit = audit_timer.read();
        if (shape == .attach) {
            try ws.objectField("timing_ns");
            try ws.write(gen.report.timings);
        }
    }
    if (options.profile) {
        try ws.objectField("sqlite_api");
        try ws.write(SqliteApi.totals);
    }
    try ws.objectField("runtime_ms");
    try ws.write(timer.read() / std.time.ns_per_ms);
    try ws.endObject();
    try output.append('\n');
    try std.fs.cwd().writeFile(.{ .sub_path = manifest_path, .data = output.items, .flags = .{ .mode = 0o600, .exclusive = true } });
    if (options.profile) try Profile.report(stderr, options.count);
    if (failed) {
        try stderr.writeAll("fixture failure; see manifest harness_failure, first_refusal and attach.publication\n");
        return 1;
    }
    return 0;
}
