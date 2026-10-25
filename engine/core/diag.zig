// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const build_options = @import("build_options");
const posix = std.posix;
const tracy = @import("tracy.zig");

pub const banner = "DIAGNOSTIC BUILD — not for production";

pub const Section = enum { journal, file, dump, compare, expiry, commit, wal, publish, fsync, readback, dispatch, reload, select, owners, history, maintenance, events };
pub const Counter = enum { wakes, spawns, dump_messages, dump_elements, readbacks, journal_records, file_records, ingest_full_bursts, write_commits, commit_rows, consistency_checks, consistency_skipped, events_received, events_applied, events_dropped, acknowledged_batches, statement_prepares, statement_cache_bypasses };
pub const Gauge = enum { readback_late_ms, wal_bytes, rss_bytes, startup_ready_ms, ingest_backlog_bytes, commit_rows_last };
pub const Limit = enum { live_bans, banned_subjects, retry_rows, effect_owners, effects, owner_revisions, intents, observations, action_targets, confirmed_events, event_details, pending_receipts, state_pages, sqlite_heap, kernel_elements, memory_plan, fds };
pub const Event = enum { commit_refused, source_paused, readback_stale, readback_deferred, storage_failed, continuity_loss, slow_startup, headroom_low, consistency_mismatch, events_overflowed };
pub const EventDetail = struct {
    subject: []const u8 = "",
    cause: []const u8 = "",
    detail: []const u8 = "",
    value: ?u64 = null,
};

const section_count = @typeInfo(Section).@"enum".fields.len;
const counter_count = @typeInfo(Counter).@"enum".fields.len;
const gauge_count = @typeInfo(Gauge).@"enum".fields.len;
const event_count = @typeInfo(Event).@"enum".fields.len;
const limit_count = @typeInfo(Limit).@"enum".fields.len;
const summary_interval_ns = 10 * std.time.ns_per_s;
const publish_interval_ns = std.time.ns_per_s;
const headroom_alert_percent = 95;
const headroom_rearm_percent = 80;
// The restart target: full protection within 60 s while holding 65,536 bans.
const slow_startup_ms = 60 * std.time.ms_per_s;
const event_lines_per_window = 8;
const max_subject_bytes = 128;
const journal_name = "fail2zig-diag.jsonl";

const bucket_bounds_ns = [_]u64{
    10 * std.time.ns_per_us,  50 * std.time.ns_per_us,  100 * std.time.ns_per_us,  250 * std.time.ns_per_us,
    500 * std.time.ns_per_us, std.time.ns_per_ms,       2500 * std.time.ns_per_us, 5 * std.time.ns_per_ms,
    10 * std.time.ns_per_ms,  25 * std.time.ns_per_ms,  50 * std.time.ns_per_ms,   100 * std.time.ns_per_ms,
    250 * std.time.ns_per_ms, 500 * std.time.ns_per_ms, std.time.ns_per_s,         2500 * std.time.ns_per_ms,
    5 * std.time.ns_per_s,    10 * std.time.ns_per_s,
};
const bucket_labels = [_][]const u8{ "0.00001", "0.00005", "0.0001", "0.00025", "0.0005", "0.001", "0.0025", "0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1", "2.5", "5", "10" };
const bucket_count = bucket_bounds_ns.len + 1;

const Totals = struct {
    entries: u64 = 0,
    wall_ns: u64 = 0,
    cpu_ns: u64 = 0,
    sum_ns: u64 = 0,
    buckets: [bucket_count]u64 = [_]u64{0} ** bucket_count,
};

const Snapshot = struct {
    sections: [section_count]Totals = [_]Totals{.{}} ** section_count,
    max_ns: [section_count]u64 = [_]u64{0} ** section_count,
    counters: [counter_count]u64 = [_]u64{0} ** counter_count,
    gauges: [gauge_count]u64 = [_]u64{0} ** gauge_count,
    limit_used: [limit_count]u64 = [_]u64{0} ** limit_count,
    limit_max: [limit_count]u64 = [_]u64{0} ** limit_count,
    limit_peak: [limit_count]u64 = [_]u64{0} ** limit_count,
    events: [event_count]u64 = [_]u64{0} ** event_count,
    events_suppressed: u64 = 0,
    clock_failures: u64 = 0,
    write_failures: u64 = 0,
    process_cpu_ns: u64 = 0,
    worker_cpu_ns: u64 = 0,
};

const State = struct {
    timer: std.time.Timer = undefined,
    journal: ?posix.fd_t = null,
    child_wall_ns: u64 = 0,
    child_cpu_ns: u64 = 0,
    total: Snapshot = .{},
    at_summary: Snapshot = .{},
    window_max_ns: [section_count]u64 = [_]u64{0} ** section_count,
    window_event_lines: [event_count]u8 = [_]u8{0} ** event_count,
    headroom_alerted: [limit_count]bool = [_]bool{false} ** limit_count,
    last_backlog_ns: ?u64 = null,
    started_wall_ns: u64 = 0,
    last_summary_ns: u64 = 0,
    last_publish_ns: u64 = 0,
    last_coord_stime_us: u64 = 0,
};

threadlocal var attached: bool = false;
var state: State = .{};
var published_mutex: std.Thread.Mutex = .{};
var published: ?Snapshot = null;

pub const Span = struct {
    section: Section,
    active: bool,
    counted: bool = false,
    wall_start_ns: u64 = 0,
    cpu_start_ns: u64 = 0,
    outer_child_wall_ns: u64 = 0,
    outer_child_cpu_ns: u64 = 0,
    tracy_zone: tracy.Zone = .{},
};

const tracy_locations = tracyLocations();

fn tracyLocations() [section_count]tracy.SourceLocation {
    const src = @src();
    var locations: [section_count]tracy.SourceLocation = undefined;
    for (&locations, @typeInfo(Section).@"enum".fields) |*location, field| location.* = .{ .name = field.name, .function = src.fn_name, .file = src.file, .line = src.line };
    return locations;
}

comptime {
    if (build_options.diag) @export(&timedFsync, .{ .name = "f2z_diag_fsync" });
}

fn timedFsync(fd: c_int) callconv(.c) c_int {
    const span = enter(.fsync);
    const rc = std.c.fsync(fd);
    const saved_errno = std.c._errno().*;
    leave(span);
    std.c._errno().* = saved_errno;
    return rc;
}

fn clockNs(id: posix.clockid_t) u64 {
    const ts = posix.clock_gettime(id) catch {
        state.total.clock_failures += 1;
        return 0;
    };
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

fn threadStimeUs() u64 {
    const usage = posix.getrusage(posix.rusage.THREAD);
    return @as(u64, @intCast(usage.stime.sec)) * std.time.us_per_s + @as(u64, @intCast(usage.stime.usec));
}

pub fn attach() void {
    state.timer = std.time.Timer.start() catch |err| {
        std.log.err("diag: timer unavailable: {s}", .{@errorName(err)});
        return;
    };
    if (comptime build_options.tracy) tracy.startup();
    attached = true;
    state.started_wall_ns = state.timer.read();
    state.last_summary_ns = state.started_wall_ns;
    state.last_publish_ns = state.started_wall_ns;
    state.total.process_cpu_ns = clockNs(.PROCESS_CPUTIME_ID);
    state.total.worker_cpu_ns = clockNs(.THREAD_CPUTIME_ID);
    state.last_coord_stime_us = threadStimeUs();
    state.at_summary = state.total;
    openJournal();
    publish();
}

fn openJournal() void {
    const dir = posix.getenv("FAIL2ZIG_DIAG_DIR") orelse return;
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buffer, "{s}/" ++ journal_name, .{dir}) catch {
        std.log.err("diag: FAIL2ZIG_DIAG_DIR is too long; no event journal", .{});
        return;
    };
    state.journal = posix.openZ(path, .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true, .CLOEXEC = true, .NOFOLLOW = true }, 0o600) catch |err| {
        std.log.err("diag: cannot open {s}: {s}; no event journal", .{ path, @errorName(err) });
        return;
    };
    std.log.info("diag: event journal {s}", .{path});
    var line: [512]u8 = undefined;
    var stream = std.io.fixedBufferStream(&line);
    stream.writer().print("{{\"ts_ms\":{d},\"type\":\"start\",\"version\":\"{s}\",\"pid\":{d}}}\n", .{ std.time.milliTimestamp(), build_options.version, std.os.linux.getpid() }) catch return;
    writeLine(stream.getWritten());
}

pub fn count(counter: Counter, amount: u64) void {
    if (attached) state.total.counters[@intFromEnum(counter)] +|= amount;
}

pub fn gauge(which: Gauge, value: u64) void {
    if (attached) state.total.gauges[@intFromEnum(which)] = value;
}

pub fn readback(start_ns: ?u64, last_verified_ns: ?u64, verify_interval_ns: u64, wake_interval_ns: u64) void {
    if (!attached) return;
    count(.readbacks, 1);
    const start = start_ns orelse return;
    const last = last_verified_ns orelse return;
    const late_ns = start -| (last +| verify_interval_ns);
    gauge(.readback_late_ms, late_ns / std.time.ns_per_ms);
    if (late_ns > wake_interval_ns) event(.readback_stale, .{ .value = late_ns / std.time.ns_per_ms });
}

pub fn limit(which: Limit, used: u64, max: u64) void {
    if (!attached) return;
    const index = @intFromEnum(which);
    state.total.limit_used[index] = used;
    state.total.limit_max[index] = max;
    state.total.limit_peak[index] = @max(state.total.limit_peak[index], used);
    if (max == 0) return;
    if (used *| 100 >= max *| headroom_alert_percent) {
        if (state.headroom_alerted[index]) return;
        state.headroom_alerted[index] = true;
        event(.headroom_low, .{ .cause = @tagName(which), .value = used });
    } else if (used *| 100 < max *| headroom_rearm_percent) state.headroom_alerted[index] = false;
}

pub fn startupReady() void {
    if (!attached) return;
    const ready_ms = processAgeMs() orelse return;
    gauge(.startup_ready_ms, ready_ms);
    if (ready_ms > slow_startup_ms) event(.slow_startup, .{ .value = ready_ms });
}

fn processAgeMs() ?u64 {
    var buffer: [1024]u8 = undefined;
    const stat = readProc("/proc/self/stat", &buffer) orelse return null;
    const close = std.mem.lastIndexOfScalar(u8, stat, ')') orelse return null;
    var fields = std.mem.tokenizeScalar(u8, stat[close + 1 ..], ' ');
    // starttime is field 22 of proc_pid_stat(5); the fields after the command start at field 3.
    var field: usize = 3;
    while (field < 22) : (field += 1) _ = fields.next() orelse return null;
    const start_ticks = std.fmt.parseInt(u64, fields.next() orelse return null, 10) catch return null;
    const ticks_per_s: u64 = std.c.getauxval(std.elf.AT_CLKTCK);
    if (ticks_per_s == 0) return null;
    const boot_ns = clockNs(.BOOTTIME);
    if (boot_ns == 0) return null;
    return (boot_ns -| start_ticks *| (std.time.ns_per_s / ticks_per_s)) / std.time.ns_per_ms;
}

pub fn ingestBacklog(jails: anytype) void {
    if (!attached) return;
    const now_ns = state.timer.read();
    if (state.last_backlog_ns) |last| if (now_ns -| last < publish_interval_ns) return;
    state.last_backlog_ns = now_ns;
    var bytes: u64 = 0;
    for (jails) |jail| {
        const session = jail.session orelse continue;
        if (session != .file) continue;
        for (session.file.sources.sources.items) |source| {
            const file = source.file orelse continue;
            const saved = source.committed orelse continue;
            const stat = posix.fstat(file.handle) catch continue;
            if (stat.ino != saved.inode) continue;
            bytes +|= (std.math.cast(u64, stat.size) orelse 0) -| saved.offset;
        }
    }
    gauge(.ingest_backlog_bytes, bytes);
}

pub fn enter(section: Section) Span {
    return open(section, true);
}

pub fn enterContinued(section: Section) Span {
    return open(section, false);
}

fn open(section: Section, counted: bool) Span {
    if (!attached) return .{ .section = section, .active = false };
    if (counted) state.total.sections[@intFromEnum(section)].entries += 1;
    const span: Span = .{
        .section = section,
        .active = true,
        .counted = counted,
        .tracy_zone = if (comptime build_options.tracy) tracy.zoneBegin(&tracy_locations[@intFromEnum(section)]) else .{},
        .wall_start_ns = state.timer.read(),
        .cpu_start_ns = clockNs(.THREAD_CPUTIME_ID),
        .outer_child_wall_ns = state.child_wall_ns,
        .outer_child_cpu_ns = state.child_cpu_ns,
    };
    state.child_wall_ns = 0;
    state.child_cpu_ns = 0;
    return span;
}

// Saturating subtraction: a failed clock read returns 0 and must not trap in ReleaseSafe.
pub fn leave(span: Span) void {
    if (!span.active) return;
    const wall_ns = state.timer.read() -| span.wall_start_ns;
    const cpu_ns = clockNs(.THREAD_CPUTIME_ID) -| span.cpu_start_ns;
    const index = @intFromEnum(span.section);
    const totals = &state.total.sections[index];
    totals.wall_ns += wall_ns -| state.child_wall_ns;
    totals.cpu_ns += cpu_ns -| state.child_cpu_ns;
    if (span.counted) {
        totals.buckets[bucketIndex(wall_ns)] += 1;
        totals.sum_ns +|= wall_ns;
        state.total.max_ns[index] = @max(state.total.max_ns[index], wall_ns);
        state.window_max_ns[index] = @max(state.window_max_ns[index], wall_ns);
    }
    state.child_wall_ns = span.outer_child_wall_ns + wall_ns;
    state.child_cpu_ns = span.outer_child_cpu_ns + cpu_ns;
    if (comptime build_options.tracy) tracy.zoneEnd(span.tracy_zone);
}

fn bucketIndex(ns: u64) usize {
    for (bucket_bounds_ns, 0..) |bound, i| if (ns <= bound) return i;
    return bucket_bounds_ns.len;
}

pub fn event(kind: Event, detail: EventDetail) void {
    if (!attached) return;
    const index = @intFromEnum(kind);
    state.total.events[index] += 1;
    @import("diag_events.zig").report(@tagName(kind), detail.subject, detail.cause, detail.detail, detail.value);
    if (state.journal == null) return;
    if (state.window_event_lines[index] >= event_lines_per_window) {
        state.total.events_suppressed += 1;
        return;
    }
    state.window_event_lines[index] += 1;
    var line: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&line);
    const w = stream.writer();
    const subject = detail.subject[0..@min(detail.subject.len, max_subject_bytes)];
    w.print("{{\"ts_ms\":{d},\"t_s\":{d},\"type\":\"event\",\"kind\":\"{s}\",\"subject\":", .{ std.time.milliTimestamp(), elapsedS(), @tagName(kind) }) catch return writeFailed();
    std.json.encodeJsonString(subject, .{}, w) catch return writeFailed();
    if (detail.cause.len != 0) {
        w.writeAll(",\"cause\":") catch return writeFailed();
        std.json.encodeJsonString(detail.cause, .{}, w) catch return writeFailed();
    }
    if (detail.detail.len != 0) {
        w.writeAll(",\"detail\":") catch return writeFailed();
        std.json.encodeJsonString(detail.detail[0..@min(detail.detail.len, max_subject_bytes)], .{}, w) catch return writeFailed();
    }
    if (detail.value) |value| w.print(",\"value\":{d}", .{value}) catch return writeFailed();
    w.writeAll("}\n") catch return writeFailed();
    writeLine(stream.getWritten());
}

fn elapsedS() u64 {
    return (state.timer.read() -| state.started_wall_ns) / std.time.ns_per_s;
}

fn writeFailed() void {
    state.total.write_failures += 1;
}

fn writeLine(bytes: []const u8) void {
    const fd = state.journal orelse return;
    var written: usize = 0;
    while (written < bytes.len) {
        const n = posix.write(fd, bytes[written..]) catch return writeFailed();
        if (n == 0) return writeFailed();
        written += n;
    }
}

pub fn emitIfDue() void {
    if (!attached) return;
    if (comptime build_options.tracy) tracy.frameMark();
    const now_ns = state.timer.read();
    if (now_ns -| state.last_publish_ns >= publish_interval_ns) {
        state.last_publish_ns = now_ns;
        publish();
    }
    if (now_ns -| state.last_summary_ns < summary_interval_ns) return;
    summarize(now_ns);
}

fn publish() void {
    state.total.process_cpu_ns = clockNs(.PROCESS_CPUTIME_ID);
    state.total.worker_cpu_ns = clockNs(.THREAD_CPUTIME_ID);
    if (residentBytes()) |bytes| state.total.gauges[@intFromEnum(Gauge.rss_bytes)] = bytes;
    sampleDescriptors();
    published_mutex.lock();
    defer published_mutex.unlock();
    published = state.total;
}

fn readProc(path: [:0]const u8, buffer: []u8) ?[]const u8 {
    var file = std.fs.openFileAbsoluteZ(path, .{}) catch return null;
    defer file.close();
    const len = file.read(buffer) catch return null;
    return buffer[0..len];
}

fn residentBytes() ?u64 {
    var buffer: [128]u8 = undefined;
    var fields = std.mem.tokenizeAny(u8, readProc("/proc/self/statm", &buffer) orelse return null, " \n");
    _ = fields.next() orelse return null;
    const pages = std.fmt.parseInt(u64, fields.next() orelse return null, 10) catch return null;
    return pages *| std.heap.pageSize();
}

fn sampleDescriptors() void {
    const soft = (posix.getrlimit(.NOFILE) catch return).cur;
    var directory = std.fs.openDirAbsoluteZ("/proc/self/fd", .{ .iterate = true }) catch return;
    defer directory.close();
    var descriptors: u64 = 0;
    var entries = directory.iterate();
    while (entries.next() catch return) |entry| {
        const fd = std.fmt.parseInt(posix.fd_t, entry.name, 10) catch continue;
        if (fd != directory.fd) descriptors += 1;
    }
    limit(.fds, descriptors, soft);
}

fn ms(ns: u64) u64 {
    return ns / std.time.ns_per_ms;
}

fn percentileUs(buckets: [bucket_count]u64, entries: u64, max_ns: u64, numerator: u64) u64 {
    if (entries == 0) return 0;
    const rank = (entries * numerator + 99) / 100;
    var seen: u64 = 0;
    for (buckets, 0..) |n, i| {
        seen += n;
        if (seen >= rank) return @min(if (i < bucket_bounds_ns.len) bucket_bounds_ns[i] else max_ns, max_ns) / std.time.ns_per_us;
    }
    return max_ns / std.time.ns_per_us;
}

fn summarize(now_ns: u64) void {
    defer {
        state.last_summary_ns = now_ns;
        state.at_summary = state.total;
        state.window_max_ns = [_]u64{0} ** section_count;
        state.window_event_lines = [_]u8{0} ** event_count;
    }
    if (state.journal == null) return;
    const total = &state.total;
    const prior = &state.at_summary;
    const coord_stime_us = threadStimeUs();
    defer state.last_coord_stime_us = coord_stime_us;
    total.process_cpu_ns = clockNs(.PROCESS_CPUTIME_ID);
    total.worker_cpu_ns = clockNs(.THREAD_CPUTIME_ID);
    const proc_ns = total.process_cpu_ns -| prior.process_cpu_ns;
    const coord_ns = total.worker_cpu_ns -| prior.worker_cpu_ns;
    var attributed_ns: u64 = 0;
    for (total.sections, prior.sections) |now, before| attributed_ns += now.cpu_ns -| before.cpu_ns;
    var line: [16 * 1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&line);
    const w = stream.writer();
    writeSummary(w, now_ns, proc_ns, coord_ns, attributed_ns, (coord_stime_us -| state.last_coord_stime_us) / std.time.us_per_ms) catch return writeFailed();
    writeLine(stream.getWritten());
}

fn writeSummary(w: anytype, now_ns: u64, proc_ns: u64, coord_ns: u64, attributed_ns: u64, stime_ms: u64) !void {
    const total = &state.total;
    const prior = &state.at_summary;
    try w.print("{{\"ts_ms\":{d},\"t_s\":{d},\"type\":\"summary\",\"window_ms\":{d},\"proc_cpu_ms\":{d},\"coord_cpu_ms\":{d},\"coord_stime_ms\":{d},\"other_thr_cpu_ms\":{d},\"unattributed_coord_cpu_ms\":{d}", .{
        std.time.milliTimestamp(),
        (now_ns -| state.started_wall_ns) / std.time.ns_per_s,
        ms(now_ns -| state.last_summary_ns),
        ms(proc_ns),
        ms(coord_ns),
        stime_ms,
        ms(proc_ns -| coord_ns),
        @as(i64, @intCast(ms(coord_ns))) - @as(i64, @intCast(ms(attributed_ns))),
    });
    try w.writeAll(",\"sections\":{");
    var first = true;
    for (total.sections, prior.sections, 0..) |now, before, i| {
        const entries = now.entries -| before.entries;
        const wall_ns = now.wall_ns -| before.wall_ns;
        if (entries == 0 and wall_ns == 0) continue;
        var window: [bucket_count]u64 = undefined;
        for (&window, now.buckets, before.buckets) |*slot, a, b| slot.* = a -| b;
        var observed: u64 = 0;
        for (window) |n| observed += n;
        const max_ns = state.window_max_ns[i];
        try w.print("{s}\"{s}\":{{\"n\":{d},\"wall_ms\":{d},\"cpu_ms\":{d},\"p50_us\":{d},\"p95_us\":{d},\"max_us\":{d}}}", .{
            if (first) "" else ",",
            @tagName(@as(Section, @enumFromInt(i))),
            entries,
            ms(wall_ns),
            ms(now.cpu_ns -| before.cpu_ns),
            percentileUs(window, observed, max_ns, 50),
            percentileUs(window, observed, max_ns, 95),
            max_ns / std.time.ns_per_us,
        });
        first = false;
    }
    try w.writeAll("},\"counters\":{");
    for (total.counters, prior.counters, 0..) |now, before, i| try w.print("{s}\"{s}\":{d}", .{ if (i == 0) "" else ",", @tagName(@as(Counter, @enumFromInt(i))), now -| before });
    try w.writeAll("},\"gauges\":{");
    for (total.gauges, 0..) |value, i| try w.print("{s}\"{s}\":{d}", .{ if (i == 0) "" else ",", @tagName(@as(Gauge, @enumFromInt(i))), value });
    try w.writeAll("},\"limits\":{");
    var first_limit = true;
    for (total.limit_used, total.limit_max, 0..) |used, max, i| {
        if (max == 0) continue;
        try w.print("{s}\"{s}\":[{d},{d}]", .{ if (first_limit) "" else ",", @tagName(@as(Limit, @enumFromInt(i))), used, max });
        first_limit = false;
    }
    try w.writeAll("},\"events\":{");
    for (total.events, prior.events, 0..) |now, before, i| try w.print("{s}\"{s}\":{d}", .{ if (i == 0) "" else ",", @tagName(@as(Event, @enumFromInt(i))), now -| before });
    try w.print("}},\"events_suppressed\":{d},\"clock_failures\":{d},\"write_failures\":{d}}}\n", .{ total.events_suppressed -| prior.events_suppressed, total.clock_failures, total.write_failures });
}

pub fn writeMetrics(w: anytype) !void {
    const snapshot = snap: {
        published_mutex.lock();
        defer published_mutex.unlock();
        break :snap published orelse return;
    };
    try w.print("f2z_diag_build_info{{version=\"{s}\"}} 1\n", .{build_options.version});
    try w.writeAll("# TYPE f2z_diag_section_seconds histogram\n");
    for (snapshot.sections, 0..) |totals, i| {
        const name = @tagName(@as(Section, @enumFromInt(i)));
        var cumulative: u64 = 0;
        for (bucket_labels, 0..) |label, b| {
            cumulative += totals.buckets[b];
            try w.print("f2z_diag_section_seconds_bucket{{section=\"{s}\",le=\"{s}\"}} {d}\n", .{ name, label, cumulative });
        }
        cumulative += totals.buckets[bucket_labels.len];
        try w.print("f2z_diag_section_seconds_bucket{{section=\"{s}\",le=\"+Inf\"}} {d}\nf2z_diag_section_seconds_sum{{section=\"{s}\"}} {d}\nf2z_diag_section_seconds_count{{section=\"{s}\"}} {d}\n", .{ name, cumulative, name, seconds(totals.sum_ns), name, cumulative });
    }
    for (snapshot.sections, snapshot.max_ns, 0..) |totals, max_ns, i| {
        const name = @tagName(@as(Section, @enumFromInt(i)));
        try w.print("f2z_diag_section_entries_total{{section=\"{s}\"}} {d}\nf2z_diag_section_self_wall_seconds_total{{section=\"{s}\"}} {d}\nf2z_diag_section_self_cpu_seconds_total{{section=\"{s}\"}} {d}\nf2z_diag_section_max_seconds{{section=\"{s}\"}} {d}\n", .{ name, totals.entries, name, seconds(totals.wall_ns), name, seconds(totals.cpu_ns), name, seconds(max_ns) });
    }
    for (snapshot.counters, 0..) |value, i| try w.print("f2z_diag_{s}_total {d}\n", .{ @tagName(@as(Counter, @enumFromInt(i))), value });
    for (snapshot.gauges, 0..) |value, i| try w.print("f2z_diag_{s} {d}\n", .{ @tagName(@as(Gauge, @enumFromInt(i))), value });
    for (snapshot.limit_used, snapshot.limit_max, snapshot.limit_peak, 0..) |used, max, peak, i| {
        if (max == 0) continue;
        const name = @tagName(@as(Limit, @enumFromInt(i)));
        try w.print("f2z_diag_limit_used{{limit=\"{s}\"}} {d}\nf2z_diag_limit_max{{limit=\"{s}\"}} {d}\nf2z_diag_limit_peak{{limit=\"{s}\"}} {d}\n", .{ name, used, name, max, name, peak });
    }
    for (snapshot.events, 0..) |value, i| try w.print("f2z_diag_events_total{{kind=\"{s}\"}} {d}\n", .{ @tagName(@as(Event, @enumFromInt(i))), value });
    try w.print("f2z_diag_events_suppressed_total {d}\nf2z_diag_clock_failures_total {d}\nf2z_diag_journal_write_failures_total {d}\nf2z_diag_process_cpu_seconds_total {d}\nf2z_diag_worker_cpu_seconds_total {d}\n", .{ snapshot.events_suppressed, snapshot.clock_failures, snapshot.write_failures, seconds(snapshot.process_cpu_ns), seconds(snapshot.worker_cpu_ns) });
}

fn seconds(ns: u64) f64 {
    return @as(f64, @floatFromInt(ns)) / std.time.ns_per_s;
}
