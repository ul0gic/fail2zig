// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Version-1 structured read-only queries over daemon-supplied views.
//! Pure: no storage access, no locks. The caller (IPC thread) hands in
//! detached or mutex-held views and receives one bounded JSON payload.
const std = @import("std");
const shared = @import("shared");

pub const schema_version: u32 = 1;
pub const max_response_bytes: usize = 1 << 20;
pub const max_items_per_page: u32 = 256;
pub const default_limit: u32 = 64;
pub const max_jail_bytes: usize = 64;
pub const max_cursor_bytes: usize = 128;

pub const Kind = enum { status, config, health, scopes, history };
pub const PeerClass = enum { admin, monitor };

/// Numeric fields stay `Value` so a quoted number ("5") is rejected rather
/// than coerced by the std.json integer parser.
pub const Request = struct {
    schema_version: ?std.json.Value = null,
    kind: ?[]const u8 = null,
    jail: ?[]const u8 = null,
    cursor: ?[]const u8 = null,
    limit: ?std.json.Value = null,
};

pub const Failure = struct { code: u16, message: []const u8 };

/// `payload` is owned by the caller's allocator; failure messages are static.
pub const Result = union(enum) {
    payload: []u8,
    failure: Failure,

    pub fn deinit(self: Result, allocator: std.mem.Allocator) void {
        switch (self) {
            .payload => |bytes| allocator.free(bytes),
            .failure => {},
        }
    }
};

/// Writes a complete JSON object (status or readiness) into `out`.
pub const Callback = struct {
    ctx: ?*anyopaque,
    func: *const fn (ctx: ?*anyopaque, allocator: std.mem.Allocator, out: *std.ArrayList(u8)) anyerror!void,
};

pub const JailConfig = struct {
    name: []const u8,
    enabled: bool,
    filter: []const u8,
    source: []const u8,
    logpath: []const []const u8,
    maxretry: u32,
    findtime: u64,
    bantime: u64,
    bantime_permanent: bool,
    banaction: []const u8,
    ignoreip: []const []const u8,
};

pub const GlobalConfig = struct {
    log_level: []const u8,
    firewall: []const u8,
    metrics_enabled: bool,
    metrics_bind: []const u8,
    metrics_port: u16,
    socket_path: []const u8,
    state_file: []const u8,
    dns_server: ?[]const u8,
    timezone_root: ?[]const u8,
};

pub const ConfigView = struct {
    jails: []const JailConfig,
    global: GlobalConfig,
};

pub const Family = enum { v4, v6 };
pub const LeaseKind = enum { finite, permanent };

/// Kernel-facing scope of one owner, already reduced to plain values by the daemon.
pub const ScopeFields = struct {
    family: Family,
    /// Network byte order; IPv4 uses the first four bytes.
    address: [16]u8,
    prefix: u8,
    protocol: ?[]const u8 = null,
    port: ?u16 = null,
    direction: ?[]const u8 = null,
    target: ?[]const u8 = null,
};

pub const ScopeItem = struct {
    scope: ScopeFields,
    lease: LeaseKind,
    deadline_us: ?i64,
    /// Null when the published owner view carries no decision identity.
    decision_id: ?[32]u8,
    confirmed: bool,
};

pub const JailScopes = struct {
    name: []const u8,
    items: []const ScopeItem,
};

pub const ScopesView = struct {
    jails: []const JailScopes,
};

pub const HistoryEvent = struct {
    sequence: u64,
    event_id: [32]u8,
    jail: []const u8,
    decision_id: [32]u8,
    confirmed_us: i64,
    scope: ScopeFields,
    native_retry: bool,
};

/// Result of one bounded scan. `resume_after` is the last sequence the
/// source examined (never below the requested `after_sequence`), so a page
/// that scanned its budget without a match still moves the cursor forward.
pub const HistoryRead = struct { more: bool, resume_after: u64 };

/// Fills `out` with at most `limit` confirmed events whose sequence is greater
/// than `after_sequence`, ascending, restricted to `jail` when given, scanning
/// at most a source-defined budget. Must read a detached copy, never the live store.
pub const HistorySource = struct {
    ctx: ?*anyopaque,
    read: *const fn (ctx: ?*anyopaque, jail: ?[]const u8, after_sequence: u64, limit: u16, out: *std.ArrayList(HistoryEvent)) anyerror!HistoryRead,
};

pub const Sources = struct {
    status: ?Callback = null,
    config: ?ConfigView = null,
    health: ?Callback = null,
    scopes: ?ScopesView = null,
    history: ?HistorySource = null,
};

pub const Error = error{OutOfMemory};

/// Parses `body`, dispatches on kind, and renders one bounded JSON response.
/// Malformed input is a 400 failure; an oversized result is 413; a view the
/// daemon has not supplied is 503. Nothing here can fail except allocation.
pub fn handle(allocator: std.mem.Allocator, body: []const u8, peer_class: PeerClass, generation: [32]u8, sources: Sources) Error!Result {
    if (body.len > shared.protocol.max_request_body) return fail(400, "request body exceeds 16 KiB");
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const parsed = std.json.parseFromSliceLeaky(Request, arena, body, .{ .ignore_unknown_fields = false }) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => fail(400, "malformed query request"),
    };
    const version = parsed.schema_version orelse return fail(400, "schema_version is required");
    if (version != .integer or version.integer != schema_version) return fail(400, "unsupported schema_version");
    const kind_text = parsed.kind orelse return fail(400, "kind is required");
    const kind = std.meta.stringToEnum(Kind, kind_text) orelse return fail(400, "unknown query kind");
    if (parsed.jail) |jail| {
        if (jail.len == 0 or jail.len > max_jail_bytes) return fail(400, "jail must be 1..64 bytes");
    }
    var limit: u32 = default_limit;
    if (parsed.limit) |value| {
        if (value != .integer or value.integer < 1 or value.integer > max_items_per_page) return fail(400, "limit must be 1..256");
        limit = @intCast(value.integer);
    }
    if (parsed.cursor) |cursor| {
        if (cursor.len == 0 or cursor.len > max_cursor_bytes) return fail(400, "cursor is malformed");
    }

    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    var sink = BoundedSink{ .list = &out };
    const writer = sink.writer();
    const generation_hex = std.fmt.bytesToHex(generation, .lower);

    const outcome: RenderError!void = switch (kind) {
        .status => renderPassthrough(arena, writer, sources.status, &generation_hex),
        .health => renderHealth(arena, writer, sources.health, &generation_hex),
        .config => renderConfig(writer, sources.config, peer_class, &generation_hex),
        .scopes => renderScopes(writer, sources.scopes, parsed.jail, parsed.cursor, limit, &generation_hex),
        .history => renderHistory(arena, writer, sources.history, parsed.jail, parsed.cursor, @intCast(limit), &generation_hex),
    };
    outcome catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.ResponseTooLarge => fail(413, "response exceeds 1 MiB"),
        error.SourceUnavailable => fail(503, "query source is not available"),
        error.UnknownJail => fail(404, "unknown jail"),
        error.BadCursor => fail(400, "cursor is malformed"),
        error.SourceFailed => fail(500, "query source failed"),
    };
    return .{ .payload = try out.toOwnedSlice() };
}

/// Opaque page cursor: base64url of `s:<jail>:<item>` or `h:<sequence>`.
pub const Cursor = union(enum) {
    scopes: struct { jail: u32, item: u32 },
    history: struct { after_sequence: u64 },

    pub fn encode(self: Cursor, buffer: *[max_cursor_bytes]u8) []const u8 {
        // Longest text is "s:4294967295:4294967295" (23 bytes), so 64 never overflows.
        var raw: [64]u8 = undefined;
        const text = switch (self) {
            .scopes => |s| std.fmt.bufPrint(&raw, "s:{d}:{d}", .{ s.jail, s.item }) catch return "",
            .history => |h| std.fmt.bufPrint(&raw, "h:{d}", .{h.after_sequence}) catch return "",
        };
        return std.base64.url_safe_no_pad.Encoder.encode(buffer, text);
    }

    pub fn decode(text: []const u8) error{BadCursor}!Cursor {
        if (text.len == 0 or text.len > max_cursor_bytes) return error.BadCursor;
        var raw: [max_cursor_bytes]u8 = undefined;
        const len = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(text) catch return error.BadCursor;
        if (len > raw.len) return error.BadCursor;
        std.base64.url_safe_no_pad.Decoder.decode(raw[0..len], text) catch return error.BadCursor;
        const decoded = raw[0..len];
        if (decoded.len < 3 or decoded[1] != ':') return error.BadCursor;
        switch (decoded[0]) {
            's' => {
                const rest = decoded[2..];
                const split = std.mem.indexOfScalar(u8, rest, ':') orelse return error.BadCursor;
                const jail = std.fmt.parseInt(u32, rest[0..split], 10) catch return error.BadCursor;
                const item = std.fmt.parseInt(u32, rest[split + 1 ..], 10) catch return error.BadCursor;
                return .{ .scopes = .{ .jail = jail, .item = item } };
            },
            'h' => {
                const after = std.fmt.parseInt(u64, decoded[2..], 10) catch return error.BadCursor;
                return .{ .history = .{ .after_sequence = after } };
            },
            else => return error.BadCursor,
        }
    }
};

fn fail(code: u16, message: []const u8) Result {
    return .{ .failure = .{ .code = code, .message = message } };
}

const RenderError = error{ OutOfMemory, ResponseTooLarge, SourceUnavailable, UnknownJail, BadCursor, SourceFailed };

/// ArrayList writer that refuses growth past `max_response_bytes` instead of
/// allocating an unbounded response for a small request.
const BoundedSink = struct {
    list: *std.ArrayList(u8),
    const WriteError = error{ OutOfMemory, ResponseTooLarge };
    const Writer = std.io.GenericWriter(*BoundedSink, WriteError, write);
    fn write(self: *BoundedSink, bytes: []const u8) WriteError!usize {
        if (self.list.items.len + bytes.len > max_response_bytes) return error.ResponseTooLarge;
        try self.list.appendSlice(bytes);
        return bytes.len;
    }
    fn writer(self: *BoundedSink) Writer {
        return .{ .context = self };
    }
};

fn runCallback(arena: std.mem.Allocator, callback: Callback) RenderError!std.json.Value {
    var raw = std.ArrayList(u8).init(arena);
    callback.func(callback.ctx, arena, &raw) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.SourceFailed,
    };
    if (raw.items.len > max_response_bytes) return error.ResponseTooLarge;
    const value = std.json.parseFromSliceLeaky(std.json.Value, arena, raw.items, .{}) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.SourceFailed,
    };
    if (value != .object) return error.SourceFailed;
    return value;
}

/// Re-emits a daemon-produced object with the envelope fields forced, so a
/// pass-through source can neither omit nor override them.
fn renderPassthrough(arena: std.mem.Allocator, writer: anytype, callback: ?Callback, generation_hex: []const u8) RenderError!void {
    const source = callback orelse return error.SourceUnavailable;
    var value = try runCallback(arena, source);
    try stampEnvelope(arena, &value.object, generation_hex);
    std.json.stringify(value, .{}, writer) catch |err| return mapWrite(err);
}

fn renderHealth(arena: std.mem.Allocator, writer: anytype, callback: ?Callback, generation_hex: []const u8) RenderError!void {
    const source = callback orelse {
        std.json.stringify(.{ .schema_version = schema_version, .generation = generation_hex, .ready = null, .components = null }, .{}, writer) catch |err| return mapWrite(err);
        return;
    };
    var value = try runCallback(arena, source);
    try stampEnvelope(arena, &value.object, generation_hex);
    std.json.stringify(value, .{}, writer) catch |err| return mapWrite(err);
}

fn stampEnvelope(arena: std.mem.Allocator, object: *std.json.ObjectMap, generation_hex: []const u8) RenderError!void {
    object.put("schema_version", .{ .integer = schema_version }) catch return error.OutOfMemory;
    const owned = arena.dupe(u8, generation_hex) catch return error.OutOfMemory;
    object.put("generation", .{ .string = owned }) catch return error.OutOfMemory;
}

fn mapWrite(err: anyerror) RenderError {
    return switch (err) {
        error.ResponseTooLarge => error.ResponseTooLarge,
        else => error.OutOfMemory,
    };
}

const redacted = "<redacted>";

fn renderConfig(writer: anytype, view: ?ConfigView, peer_class: PeerClass, generation_hex: []const u8) RenderError!void {
    const config = view orelse return error.SourceUnavailable;
    const redact = peer_class == .monitor;
    var out = std.json.writeStream(writer, .{});
    out.beginObject() catch |err| return mapWrite(err);
    envelope(&out, generation_hex) catch |err| return mapWrite(err);
    field(&out, "redacted", redact) catch |err| return mapWrite(err);
    out.objectField("jails") catch |err| return mapWrite(err);
    out.beginArray() catch |err| return mapWrite(err);
    for (config.jails) |jail| {
        out.beginObject() catch |err| return mapWrite(err);
        field(&out, "name", jail.name) catch |err| return mapWrite(err);
        field(&out, "enabled", jail.enabled) catch |err| return mapWrite(err);
        field(&out, "filter", jail.filter) catch |err| return mapWrite(err);
        field(&out, "source", jail.source) catch |err| return mapWrite(err);
        stringList(&out, "logpath", jail.logpath, redact) catch |err| return mapWrite(err);
        field(&out, "maxretry", jail.maxretry) catch |err| return mapWrite(err);
        field(&out, "findtime", jail.findtime) catch |err| return mapWrite(err);
        field(&out, "bantime", jail.bantime) catch |err| return mapWrite(err);
        field(&out, "bantime_permanent", jail.bantime_permanent) catch |err| return mapWrite(err);
        field(&out, "banaction", jail.banaction) catch |err| return mapWrite(err);
        stringList(&out, "ignoreip", jail.ignoreip, redact) catch |err| return mapWrite(err);
        out.endObject() catch |err| return mapWrite(err);
    }
    out.endArray() catch |err| return mapWrite(err);
    out.objectField("global") catch |err| return mapWrite(err);
    out.beginObject() catch |err| return mapWrite(err);
    const g = config.global;
    field(&out, "log_level", g.log_level) catch |err| return mapWrite(err);
    field(&out, "firewall", g.firewall) catch |err| return mapWrite(err);
    field(&out, "metrics_enabled", g.metrics_enabled) catch |err| return mapWrite(err);
    field(&out, "metrics_bind", g.metrics_bind) catch |err| return mapWrite(err);
    field(&out, "metrics_port", g.metrics_port) catch |err| return mapWrite(err);
    field(&out, "socket_path", if (redact) redacted else g.socket_path) catch |err| return mapWrite(err);
    field(&out, "state_file", if (redact) redacted else g.state_file) catch |err| return mapWrite(err);
    optionalString(&out, "dns_server", if (redact) redacted else g.dns_server) catch |err| return mapWrite(err);
    optionalString(&out, "timezone_root", if (redact) redacted else g.timezone_root) catch |err| return mapWrite(err);
    out.endObject() catch |err| return mapWrite(err);
    out.endObject() catch |err| return mapWrite(err);
}

fn envelope(out: anytype, generation_hex: []const u8) !void {
    try field(out, "schema_version", schema_version);
    try field(out, "generation", generation_hex);
}

fn field(out: anytype, name: []const u8, value: anytype) !void {
    try out.objectField(name);
    try out.write(value);
}

fn optionalString(out: anytype, name: []const u8, value: ?[]const u8) !void {
    try out.objectField(name);
    if (value) |text| try out.write(text) else try out.write(null);
}

/// A redacted list keeps its array type so renderers stay schema-stable.
fn stringList(out: anytype, name: []const u8, values: []const []const u8, redact: bool) !void {
    try out.objectField(name);
    try out.beginArray();
    if (redact) {
        try out.write(redacted);
    } else {
        for (values) |value| try out.write(value);
    }
    try out.endArray();
}

fn renderScopes(writer: anytype, view: ?ScopesView, jail_filter: ?[]const u8, cursor_text: ?[]const u8, limit: u32, generation_hex: []const u8) RenderError!void {
    const scopes = view orelse return error.SourceUnavailable;
    var first_jail: u32 = 0;
    var last_jail: u32 = @intCast(scopes.jails.len);
    if (jail_filter) |name| {
        const index = findJail(scopes, name) orelse return error.UnknownJail;
        first_jail = index;
        last_jail = index + 1;
    }
    var jail_index = first_jail;
    var item_index: u32 = 0;
    if (cursor_text) |text| {
        const cursor = try Cursor.decode(text);
        if (cursor != .scopes) return error.BadCursor;
        if (cursor.scopes.jail < first_jail or cursor.scopes.jail >= last_jail) return error.BadCursor;
        if (cursor.scopes.item > scopes.jails[cursor.scopes.jail].items.len) return error.BadCursor;
        jail_index = cursor.scopes.jail;
        item_index = cursor.scopes.item;
    }

    var out = std.json.writeStream(writer, .{});
    out.beginObject() catch |err| return mapWrite(err);
    envelope(&out, generation_hex) catch |err| return mapWrite(err);
    out.objectField("items") catch |err| return mapWrite(err);
    out.beginArray() catch |err| return mapWrite(err);
    var emitted: u32 = 0;
    while (jail_index < last_jail and emitted < limit) {
        const jail = scopes.jails[jail_index];
        while (item_index < jail.items.len and emitted < limit) : (item_index += 1) {
            writeScopeItem(&out, jail.name, jail.items[item_index]) catch |err| return mapWrite(err);
            emitted += 1;
        }
        if (item_index >= jail.items.len) {
            jail_index += 1;
            item_index = 0;
        }
    }
    out.endArray() catch |err| return mapWrite(err);
    // Skip trailing empty jails so an exhausted page reports null, not a dead cursor.
    while (jail_index < last_jail and item_index >= scopes.jails[jail_index].items.len) {
        jail_index += 1;
        item_index = 0;
    }
    out.objectField("next_cursor") catch |err| return mapWrite(err);
    if (jail_index < last_jail) {
        var buffer: [max_cursor_bytes]u8 = undefined;
        const next = (Cursor{ .scopes = .{ .jail = jail_index, .item = item_index } }).encode(&buffer);
        out.write(next) catch |err| return mapWrite(err);
    } else {
        out.write(null) catch |err| return mapWrite(err);
    }
    out.endObject() catch |err| return mapWrite(err);
}

fn findJail(scopes: ScopesView, name: []const u8) ?u32 {
    for (scopes.jails, 0..) |jail, i| {
        if (std.mem.eql(u8, jail.name, name)) return @intCast(i);
    }
    return null;
}

fn writeScopeItem(out: anytype, jail: []const u8, item: ScopeItem) !void {
    try out.beginObject();
    try field(out, "jail", jail);
    try out.objectField("scope");
    try writeScope(out, item.scope);
    try field(out, "lease", @tagName(item.lease));
    try out.objectField("deadline_us");
    if (item.deadline_us) |deadline| try out.write(deadline) else try out.write(null);
    try out.objectField("decision_id_hex");
    if (item.decision_id) |id| {
        const hex = std.fmt.bytesToHex(id, .lower);
        try out.write(&hex);
    } else try out.write(null);
    try field(out, "confirmed", item.confirmed);
    try out.endObject();
}

fn writeScope(out: anytype, scope: ScopeFields) !void {
    try out.beginObject();
    try field(out, "family", @tagName(scope.family));
    var address_buffer: [48]u8 = undefined;
    try field(out, "address", formatAddress(scope, &address_buffer));
    try field(out, "prefix", scope.prefix);
    if (scope.protocol) |protocol| try field(out, "protocol", protocol);
    if (scope.port) |port| try field(out, "port", port);
    if (scope.direction) |direction| try field(out, "direction", direction);
    if (scope.target) |target| try field(out, "target", target);
    try out.endObject();
}

fn formatAddress(scope: ScopeFields, buffer: *[48]u8) []const u8 {
    const address: shared.IpAddress = switch (scope.family) {
        .v4 => .{ .ipv4 = std.mem.readInt(u32, scope.address[0..4], .big) },
        .v6 => .{ .ipv6 = std.mem.readInt(u128, &scope.address, .big) },
    };
    return std.fmt.bufPrint(buffer, "{}", .{address}) catch "?";
}

fn renderHistory(arena: std.mem.Allocator, writer: anytype, source: ?HistorySource, jail_filter: ?[]const u8, cursor_text: ?[]const u8, limit: u16, generation_hex: []const u8) RenderError!void {
    const history = source orelse return error.SourceUnavailable;
    var after_sequence: u64 = 0;
    if (cursor_text) |text| {
        const cursor = try Cursor.decode(text);
        if (cursor != .history) return error.BadCursor;
        after_sequence = cursor.history.after_sequence;
    }
    var events = std.ArrayList(HistoryEvent).init(arena);
    events.ensureTotalCapacity(limit) catch return error.OutOfMemory;
    const scanned = history.read(history.ctx, jail_filter, after_sequence, limit, &events) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.SourceFailed,
    };
    // A cursor that does not advance would let a client loop forever on one page.
    if (scanned.more and scanned.resume_after <= after_sequence) return error.SourceFailed;
    // The source is trusted but bounded anyway: never emit more than asked.
    const items = events.items[0..@min(events.items.len, limit)];

    var out = std.json.writeStream(writer, .{});
    out.beginObject() catch |err| return mapWrite(err);
    envelope(&out, generation_hex) catch |err| return mapWrite(err);
    out.objectField("items") catch |err| return mapWrite(err);
    out.beginArray() catch |err| return mapWrite(err);
    for (items) |event| {
        if (event.sequence > scanned.resume_after) return error.SourceFailed;
        writeHistoryEvent(&out, event) catch |err| return mapWrite(err);
    }
    out.endArray() catch |err| return mapWrite(err);
    out.objectField("next_cursor") catch |err| return mapWrite(err);
    if (scanned.more) {
        var buffer: [max_cursor_bytes]u8 = undefined;
        const next = (Cursor{ .history = .{ .after_sequence = scanned.resume_after } }).encode(&buffer);
        out.write(next) catch |err| return mapWrite(err);
    } else {
        out.write(null) catch |err| return mapWrite(err);
    }
    out.endObject() catch |err| return mapWrite(err);
}

fn writeHistoryEvent(out: anytype, event: HistoryEvent) !void {
    try out.beginObject();
    try field(out, "sequence", event.sequence);
    const event_hex = std.fmt.bytesToHex(event.event_id, .lower);
    try field(out, "event_id_hex", &event_hex);
    try field(out, "jail", event.jail);
    const decision_hex = std.fmt.bytesToHex(event.decision_id, .lower);
    try field(out, "decision_id_hex", &decision_hex);
    try field(out, "confirmed_us", event.confirmed_us);
    try out.objectField("scope");
    try writeScope(out, event.scope);
    try field(out, "native_retry", event.native_retry);
    try out.endObject();
}
