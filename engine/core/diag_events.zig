// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const posix = std.posix;

const queue_capacity = 64;
const text_bytes = 128;
const message_bytes = 1024;
const trace_bytes = 12 * 1024;
const body_bytes = 48 * 1024;
const io_timeout_s = 3;
const panic_wait_ns = 5 * std.time.ns_per_s;
const build_tag = @tagName(builtin.cpu.arch) ++ "-" ++ @tagName(builtin.os.tag) ++ "-" ++ @tagName(builtin.abi) ++ " " ++ @tagName(builtin.mode);
const client_name = "fail2zig-diag/" ++ build_options.version;

const Text = struct {
    bytes: [text_bytes]u8 = undefined,
    len: usize = 0,

    fn init(value: []const u8) Text {
        var text: Text = .{};
        const kept = utf8Prefix(value, text_bytes);
        @memcpy(text.bytes[0..kept.len], kept);
        text.len = kept.len;
        return text;
    }

    fn slice(text: *const Text) []const u8 {
        return text.bytes[0..text.len];
    }
};

const Anomaly = struct {
    kind: []const u8,
    subject: Text,
    cause: Text,
    detail: Text,
    value: ?u64,
    ts_ms: u64,
};

const Crash = struct {
    message: [message_bytes]u8 = undefined,
    message_len: usize = 0,
    trace: [trace_bytes]u8 = undefined,
    trace_len: usize = 0,
    ts_ms: u64 = 0,
};

const Endpoint = struct {
    dsn_buffer: [512]u8 = undefined,
    dsn_len: usize = 0,
    url_buffer: [512]u8 = undefined,
    uri: std.Uri = undefined,
    auth_buffer: [256]u8 = undefined,
    auth_len: usize = 0,

    fn dsn(e: *const Endpoint) []const u8 {
        return e.dsn_buffer[0..e.dsn_len];
    }

    fn auth(e: *const Endpoint) []const u8 {
        return e.auth_buffer[0..e.auth_len];
    }
};

var setup = std.once(start);
var running = false;
var endpoint: Endpoint = .{};
var mutex: std.Thread.Mutex = .{};
var ready: std.Thread.Condition = .{};
var queue: [queue_capacity]Anomaly = undefined;
var queue_head: usize = 0;
var queue_len: usize = 0;
var crash: Crash = .{};
var crash_pending = false;
var crash_sent: std.Thread.ResetEvent = .{};
var dropped = std.atomic.Value(u64).init(0);
var send_failures: u64 = 0;
var panicking = std.atomic.Value(bool).init(false);
threadlocal var is_sender = false;

pub fn report(kind: []const u8, subject: []const u8, cause: []const u8, detail: []const u8, value: ?u64) void {
    setup.call();
    if (!running) return;
    if (!mutex.tryLock()) {
        _ = dropped.fetchAdd(1, .monotonic);
        return;
    }
    defer mutex.unlock();
    if (queue_len == queue_capacity) {
        _ = dropped.fetchAdd(1, .monotonic);
        return;
    }
    queue[(queue_head + queue_len) % queue_capacity] = .{
        .kind = kind,
        .subject = Text.init(subject),
        .cause = Text.init(cause),
        .detail = Text.init(detail),
        .value = value,
        .ts_ms = nowMs(),
    };
    queue_len += 1;
    ready.signal();
}

pub fn panic(msg: []const u8, first_trace_addr: ?usize) noreturn {
    @branchHint(.cold);
    const trace_start = first_trace_addr orelse @returnAddress();
    if (!is_sender and !panicking.swap(true, .acq_rel)) reportCrash(msg, trace_start);
    std.debug.defaultPanic(msg, trace_start);
}

fn reportCrash(msg: []const u8, trace_start: usize) void {
    setup.call();
    if (!running) return;
    const message = utf8Prefix(msg, message_bytes);
    @memcpy(crash.message[0..message.len], message);
    crash.message_len = message.len;
    crash.ts_ms = nowMs();
    var stream = std.io.fixedBufferStream(&crash.trace);
    writeTrace(stream.writer(), trace_start) catch |err| switch (err) {
        error.NoSpaceLeft => {},
    };
    crash.trace_len = stream.pos;

    mutex.lock();
    crash_pending = true;
    ready.signal();
    mutex.unlock();
    crash_sent.timedWait(panic_wait_ns) catch |err| switch (err) {
        error.Timeout => {},
    };
}

fn writeTrace(w: anytype, trace_start: usize) !void {
    const info = std.debug.getSelfDebugInfo() catch |err| return w.print("debug info unavailable: {s}\n", .{@errorName(err)});
    std.debug.writeCurrentStackTrace(w, info, .no_color, trace_start) catch |err| switch (err) {
        error.NoSpaceLeft => return error.NoSpaceLeft,
        else => try w.print("\nstack trace incomplete: {s}\n", .{@errorName(err)}),
    };
}

fn start() void {
    const dsn = posix.getenv("FAIL2ZIG_DIAG_DSN") orelse return;
    parseDsn(&endpoint, dsn) catch |err| {
        std.log.warn("diag: FAIL2ZIG_DIAG_DSN ignored: {s}", .{@errorName(err)});
        return;
    };
    const thread = std.Thread.spawn(.{}, run, .{}) catch |err| {
        std.log.warn("diag: event sender not started: {s}", .{@errorName(err)});
        return;
    };
    thread.detach();
    running = true;
}

fn parseDsn(e: *Endpoint, dsn: []const u8) !void {
    if (dsn.len > e.dsn_buffer.len) return error.DsnTooLong;
    const uri = std.Uri.parse(dsn) catch return error.DsnInvalid;
    if (!std.mem.eql(u8, uri.scheme, "http") and !std.mem.eql(u8, uri.scheme, "https")) return error.DsnScheme;
    const key = componentText(uri.user orelse return error.DsnMissingKey);
    const host = componentText(uri.host orelse return error.DsnMissingHost);
    const project = std.mem.trimLeft(u8, componentText(uri.path), "/");
    if (key.len == 0 or !allBytes(key, std.ascii.isAlphanumeric)) return error.DsnKey;
    if (project.len == 0 or !allBytes(project, std.ascii.isDigit)) return error.DsnProject;
    if (host.len == 0 or !allBytes(host, isHostByte)) return error.DsnHost;

    var url = std.io.fixedBufferStream(&e.url_buffer);
    try url.writer().print("{s}://{s}", .{ uri.scheme, host });
    if (uri.port) |port| try url.writer().print(":{d}", .{port});
    try url.writer().print("/api/{s}/envelope/", .{project});
    e.uri = std.Uri.parse(url.getWritten()) catch return error.DsnInvalid;

    const auth = try std.fmt.bufPrint(&e.auth_buffer, "Sentry sentry_version=7, sentry_key={s}, sentry_client=" ++ client_name, .{key});
    e.auth_len = auth.len;
    @memcpy(e.dsn_buffer[0..dsn.len], dsn);
    e.dsn_len = dsn.len;
}

fn componentText(component: std.Uri.Component) []const u8 {
    return switch (component) {
        .raw, .percent_encoded => |text| text,
    };
}

fn allBytes(text: []const u8, comptime accept: fn (u8) bool) bool {
    for (text) |byte| if (!accept(byte)) return false;
    return true;
}

fn isHostByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '.' or byte == '-';
}

fn run() void {
    is_sender = true;
    var client: std.http.Client = .{ .allocator = std.heap.smp_allocator };
    var body: [body_bytes]u8 = undefined;
    while (true) {
        mutex.lock();
        while (queue_len == 0 and !crash_pending) ready.wait(&mutex);
        if (crash_pending) {
            crash_pending = false;
            mutex.unlock();
            deliver(&client, crashEnvelope(&body));
            crash_sent.set();
            continue;
        }
        const anomaly = queue[queue_head];
        queue_head = (queue_head + 1) % queue_capacity;
        queue_len -= 1;
        mutex.unlock();
        deliver(&client, anomalyEnvelope(&body, &anomaly));
    }
}

fn deliver(client: *std.http.Client, envelope: anyerror![]const u8) void {
    const body = envelope catch |err| return noteFailure(err);
    post(client, body) catch |err| noteFailure(err);
}

fn noteFailure(err: anyerror) void {
    send_failures += 1;
    if (send_failures == 1) std.log.warn("diag: GlitchTip send failed: {s}", .{@errorName(err)});
}

fn post(client: *std.http.Client, body: []const u8) !void {
    var header_buffer: [4096]u8 = undefined;
    var request = try client.open(.POST, endpoint.uri, .{
        .server_header_buffer = &header_buffer,
        .keep_alive = false,
        .headers = .{ .content_type = .{ .override = "application/x-sentry-envelope" } },
        .extra_headers = &.{.{ .name = "X-Sentry-Auth", .value = endpoint.auth() }},
    });
    defer request.deinit();
    const connection = request.connection orelse return error.NoConnection;
    const timeout = posix.timeval{ .sec = io_timeout_s, .usec = 0 };
    try posix.setsockopt(connection.stream.handle, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));
    try posix.setsockopt(connection.stream.handle, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&timeout));
    request.transfer_encoding = .{ .content_length = body.len };
    try request.send();
    try request.writeAll(body);
    try request.finish();
    try request.wait();
    if (request.response.status.class() != .success) return error.EnvelopeRejected;
}

fn anomalyEnvelope(buffer: []u8, anomaly: *const Anomaly) ![]const u8 {
    var stream = std.io.fixedBufferStream(buffer);
    const w = stream.writer();
    const id = eventId();
    try writeHeaders(w, &id, anomaly.ts_ms, "error");
    var message_buffer: [2 * text_bytes + 64]u8 = undefined;
    const message = try std.fmt.bufPrint(&message_buffer, "{s}: {s} {s}", .{ anomaly.kind, anomaly.subject.slice(), anomaly.cause.slice() });
    try w.writeAll(",\"message\":");
    try std.json.encodeJsonString(message, .{}, w);
    try w.print(",\"fingerprint\":[\"{s}\",", .{anomaly.kind});
    try std.json.encodeJsonString(anomaly.cause.slice(), .{}, w);
    try w.print("],\"tags\":{{\"kind\":\"{s}\"", .{anomaly.kind});
    if (anomaly.subject.len != 0) {
        try w.writeAll(",\"jail\":");
        try std.json.encodeJsonString(anomaly.subject.slice(), .{}, w);
    }
    if (anomaly.cause.len != 0) {
        try w.writeAll(",\"cause\":");
        try std.json.encodeJsonString(anomaly.cause.slice(), .{}, w);
    }
    try writeBuildTags(w);
    try w.writeAll("},\"extra\":{");
    if (anomaly.value) |value| try w.print("\"value\":{d},", .{value});
    if (anomaly.detail.len != 0) {
        try w.writeAll("\"detail\":");
        try std.json.encodeJsonString(anomaly.detail.slice(), .{}, w);
        try w.writeAll(",");
    }
    try writeSenderExtra(w);
    try w.writeAll("}}\n");
    return stream.getWritten();
}

fn crashEnvelope(buffer: []u8) ![]const u8 {
    var stream = std.io.fixedBufferStream(buffer);
    const w = stream.writer();
    const id = eventId();
    const message = crash.message[0..crash.message_len];
    try writeHeaders(w, &id, crash.ts_ms, "fatal");
    try w.writeAll(",\"message\":");
    try std.json.encodeJsonString(message, .{}, w);
    try w.writeAll(",\"exception\":{\"values\":[{\"type\":\"panic\",\"value\":");
    try std.json.encodeJsonString(message, .{}, w);
    try w.writeAll("}]},\"tags\":{\"kind\":\"panic\"");
    try writeBuildTags(w);
    try w.writeAll("},\"extra\":{\"stack_trace\":");
    try std.json.encodeJsonString(crash.trace[0..crash.trace_len], .{}, w);
    try w.writeAll(",");
    try writeSenderExtra(w);
    try w.writeAll("}}\n");
    return stream.getWritten();
}

fn writeHeaders(w: anytype, id: *const [32]u8, ts_ms: u64, level: []const u8) !void {
    try w.print("{{\"event_id\":\"{s}\",\"dsn\":", .{id});
    try std.json.encodeJsonString(endpoint.dsn(), .{}, w);
    try w.writeAll("}\n{\"type\":\"event\"}\n");
    try w.print("{{\"event_id\":\"{s}\",\"timestamp\":{d}.{d:0>3},\"platform\":\"other\",\"level\":\"{s}\",\"logger\":\"fail2zig.diag\",\"release\":\"fail2zig@" ++ build_options.version ++ "\",\"environment\":\"diag\"", .{ id, ts_ms / std.time.ms_per_s, ts_ms % std.time.ms_per_s, level });
}

fn writeBuildTags(w: anytype) !void {
    try w.writeAll(",\"version\":\"" ++ build_options.version ++ "\",\"build\":\"" ++ build_tag ++ "\"");
}

fn writeSenderExtra(w: anytype) !void {
    try w.print("\"events_dropped\":{d},\"send_failures\":{d}", .{ dropped.load(.monotonic), send_failures });
}

fn eventId() [32]u8 {
    var bytes: [16]u8 = undefined;
    std.crypto.random.bytes(&bytes);
    return std.fmt.bytesToHex(bytes, .lower);
}

fn nowMs() u64 {
    return std.math.lossyCast(u64, std.time.milliTimestamp());
}

fn utf8Prefix(text: []const u8, limit: usize) []const u8 {
    if (text.len <= limit) return text;
    var end = limit;
    while (end > 0 and text[end] & 0xC0 == 0x80) end -= 1;
    return text[0..end];
}
