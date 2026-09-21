// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const shared = @import("shared");
const canonical_scope = @import("../firewall/scope.zig");
const inspection = @import("../firewall/inspection.zig");
const firewall_observation = @import("../native_firewall_observation.zig");

pub const schema_version: u32 = 1;
pub const max_response_bytes: usize = 1 << 20;
pub const max_items_per_page: u32 = 256;
pub const default_limit: u32 = 64;
pub const max_jail_bytes: usize = 64;
pub const max_cursor_bytes: usize = 128;

pub const Kind = enum { status, config, health, scopes, history, firewall };
pub const PeerClass = enum { admin, monitor };

pub const Request = struct {
    schema_version: ?std.json.Value = null,
    kind: ?[]const u8 = null,
    jail: ?[]const u8 = null,
    cursor: ?[]const u8 = null,
    limit: ?std.json.Value = null,
};

pub const Failure = struct { code: u16, message: []const u8 };

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
pub const SubjectKind = enum { host, network };
pub const Protocol = enum { all, tcp, udp, icmp_v4, icmp_v6 };
pub const ProtocolSet = struct {
    values: [5]Protocol = [_]Protocol{.all} ** 5,
    len: u8 = 1,

    pub fn slice(self: *const ProtocolSet) []const Protocol {
        return self.values[0..self.len];
    }
};
pub const PortRange = struct { first: u16, last: u16 };
pub const PortRanges = struct {
    values: [canonical_scope.max_port_ranges]PortRange = [_]PortRange{.{ .first = 0, .last = 0 }} ** canonical_scope.max_port_ranges,
    len: u8 = 0,

    pub fn slice(self: *const PortRanges) []const PortRange {
        return self.values[0..self.len];
    }
};
pub const LeaseKind = enum { finite, permanent };

pub const ScopeFields = struct {
    family: Family,
    address: [16]u8,
    prefix: u8,
    subject_kind: SubjectKind = .host,
    protocols: ProtocolSet = .{},
    port_ranges: PortRanges = .{},
    legacy_exact: bool = true,
    protocol: ?[]const u8 = null,
    port: ?u16 = null,
    direction: ?[]const u8 = null,
    target: ?[]const u8 = null,
};

pub const ScopeProjectionError = error{InvalidScope};

pub fn projectScope(scope: canonical_scope.Scope) ScopeProjectionError!ScopeFields {
    scope.validate() catch return error.InvalidScope;
    var protocols = ProtocolSet{ .len = 0 };
    inline for (.{
        canonical_scope.Protocol.all,
        canonical_scope.Protocol.tcp,
        canonical_scope.Protocol.udp,
        canonical_scope.Protocol.icmp_v4,
        canonical_scope.Protocol.icmp_v6,
    }) |protocol| {
        if (scope.protocols.contains(protocol)) {
            protocols.values[protocols.len] = @enumFromInt(@intFromEnum(protocol));
            protocols.len += 1;
        }
    }
    if (protocols.len == 0) return error.InvalidScope;

    var port_ranges = PortRanges{ .len = scope.ports.len };
    for (scope.ports.slice(), 0..) |range, index| {
        port_ranges.values[index] = .{ .first = range.first, .last = range.last };
    }
    const singular_protocol: ?[]const u8 = if (protocols.len == 1 and protocols.values[0] != .all)
        @tagName(protocols.values[0])
    else
        null;
    const singular_port: ?u16 = if (port_ranges.len == 1 and port_ranges.values[0].first == port_ranges.values[0].last)
        port_ranges.values[0].first
    else
        null;
    const legacy_exact = protocols.len == 1 and (port_ranges.len == 0 or singular_port != null);
    return .{
        .family = switch (scope.subject.family) {
            .v4 => .v4,
            .v6 => .v6,
        },
        .address = scope.subject.address,
        .prefix = scope.subject.prefix,
        .subject_kind = switch (scope.subject.kind) {
            .host => .host,
            .network => .network,
        },
        .protocols = protocols,
        .port_ranges = port_ranges,
        .legacy_exact = legacy_exact,
        .protocol = singular_protocol,
        .port = singular_port,
        .direction = @tagName(scope.topology.hook),
        .target = @tagName(scope.verdict),
    };
}

pub const ScopeItem = struct {
    scope: ScopeFields,
    lease: LeaseKind,
    deadline_us: ?i64,
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

pub const HistoryRead = struct { more: bool, resume_after: u64 };

pub const HistorySource = struct {
    ctx: ?*anyopaque,
    read: *const fn (ctx: ?*anyopaque, jail: ?[]const u8, after_sequence: u64, limit: u16, out: *std.ArrayList(HistoryEvent)) anyerror!HistoryRead,
};

pub const FirewallUnavailableReason = enum { no_manager, memory_budget, allocation_failed, not_observed, clock_unavailable };
pub const FirewallReader = struct {
    ctx: ?*anyopaque,
    read: *const fn (ctx: ?*anyopaque, request: firewall_observation.PageRequest, out: *firewall_observation.Page) anyerror!void,
};
pub const FirewallSource = union(enum) {
    unavailable: FirewallUnavailableReason,
    cache: FirewallReader,
};

pub const Sources = struct {
    status: ?Callback = null,
    config: ?ConfigView = null,
    health: ?Callback = null,
    scopes: ?ScopesView = null,
    history: ?HistorySource = null,
    firewall: ?FirewallSource = null,
};

pub const Error = error{OutOfMemory};

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
    if (kind == .firewall and parsed.jail != null) return fail(400, "firewall query does not accept a jail filter");

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
        .firewall => renderFirewall(allocator, writer, sources.firewall, parsed.cursor, @intCast(limit), &generation_hex),
    };
    outcome catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ResponseTooLarge => {
            out.deinit();
            return fail(413, "response exceeds 1 MiB");
        },
        error.SourceUnavailable => {
            out.deinit();
            return fail(503, "query source is not available");
        },
        error.UnknownJail => {
            out.deinit();
            return fail(404, "unknown jail");
        },
        error.BadCursor => {
            out.deinit();
            return fail(400, "cursor is malformed");
        },
        error.InvalidatedCursor => {
            out.deinit();
            return fail(409, "cursor expired or observation changed; restart pagination without a cursor");
        },
        error.SourceFailed => {
            out.deinit();
            return fail(500, "query source failed");
        },
    };
    return .{ .payload = try out.toOwnedSlice() };
}

pub const Cursor = union(enum) {
    scopes: struct { jail: u32, item: u32 },
    history: struct { after_sequence: u64 },

    pub fn encode(self: Cursor, buffer: *[max_cursor_bytes]u8) []const u8 {
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

pub fn requestedKind(arena: std.mem.Allocator, body: []const u8) ?Kind {
    if (body.len > shared.protocol.max_request_body) return null;
    const parsed = std.json.parseFromSliceLeaky(Request, arena, body, .{ .ignore_unknown_fields = false }) catch return null;
    const version = parsed.schema_version orelse return null;
    if (version != .integer or version.integer != schema_version) return null;
    return std.meta.stringToEnum(Kind, parsed.kind orelse return null);
}

fn fail(code: u16, message: []const u8) Result {
    return .{ .failure = .{ .code = code, .message = message } };
}

const RenderError = error{ OutOfMemory, ResponseTooLarge, SourceUnavailable, UnknownJail, BadCursor, InvalidatedCursor, SourceFailed };

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
    try field(out, "subject_kind", @tagName(scope.subject_kind));
    try out.objectField("protocols");
    try out.beginArray();
    for (scope.protocols.slice()) |protocol| try out.write(@tagName(protocol));
    try out.endArray();
    try out.objectField("port_ranges");
    try out.beginArray();
    for (scope.port_ranges.slice()) |range| {
        try out.beginObject();
        try field(out, "first", range.first);
        try field(out, "last", range.last);
        try out.endObject();
    }
    try out.endArray();
    try field(out, "legacy_exact", scope.legacy_exact);
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

fn renderFirewall(allocator: std.mem.Allocator, writer: anytype, source: ?FirewallSource, cursor: ?[]const u8, limit: u16, generation_hex: []const u8) RenderError!void {
    const selected = source orelse return error.SourceUnavailable;
    switch (selected) {
        .unavailable => |reason| {
            if (cursor != null) return error.InvalidatedCursor;
            return writeUnavailableFirewall(writer, generation_hex, reason);
        },
        .cache => |reader| {
            const page = allocator.create(firewall_observation.Page) catch return error.OutOfMemory;
            defer allocator.destroy(page);
            const now_ms = firewall_observation.monotonicMs();
            reader.read(reader.ctx, .{ .limit = limit, .cursor = cursor, .now_ms = now_ms }, page) catch |err| return switch (err) {
                error.BadCursor => error.BadCursor,
                error.InvalidatedCursor => error.InvalidatedCursor,
                error.OutOfMemory => error.OutOfMemory,
                else => error.SourceFailed,
            };
            return writeFirewallPage(writer, generation_hex, page, now_ms);
        },
    }
}

fn writeUnavailableFirewall(writer: anytype, generation_hex: []const u8, reason: FirewallUnavailableReason) RenderError!void {
    var out = std.json.writeStream(writer, .{});
    out.beginObject() catch |err| return mapWrite(err);
    envelope(&out, generation_hex) catch |err| return mapWrite(err);
    field(&out, "kind", "firewall") catch |err| return mapWrite(err);
    field(&out, "available", false) catch |err| return mapWrite(err);
    field(&out, "unavailable_reason", @tagName(reason)) catch |err| return mapWrite(err);
    out.objectField("installation") catch |err| return mapWrite(err);
    out.write(null) catch |err| return mapWrite(err);
    out.objectField("observation") catch |err| return mapWrite(err);
    out.write(null) catch |err| return mapWrite(err);
    writeNoAttempt(&out) catch |err| return mapWrite(err);
    field(&out, "structure", null) catch |err| return mapWrite(err);
    out.objectField("items") catch |err| return mapWrite(err);
    out.beginArray() catch |err| return mapWrite(err);
    out.endArray() catch |err| return mapWrite(err);
    out.objectField("next_cursor") catch |err| return mapWrite(err);
    out.write(null) catch |err| return mapWrite(err);
    out.endObject() catch |err| return mapWrite(err);
}

fn writeFirewallPage(writer: anytype, generation_hex: []const u8, page: *const firewall_observation.Page, now_ms: ?u64) RenderError!void {
    const metadata = page.metadata;
    const available = metadata.state != .unavailable;
    var out = std.json.writeStream(writer, .{});
    out.beginObject() catch |err| return mapWrite(err);
    envelope(&out, generation_hex) catch |err| return mapWrite(err);
    field(&out, "kind", "firewall") catch |err| return mapWrite(err);
    field(&out, "available", available) catch |err| return mapWrite(err);
    out.objectField("unavailable_reason") catch |err| return mapWrite(err);
    if (available) out.write(null) catch |err| return mapWrite(err) else out.write(@tagName(FirewallUnavailableReason.not_observed)) catch |err| return mapWrite(err);
    out.objectField("installation") catch |err| return mapWrite(err);
    out.beginObject() catch |err| return mapWrite(err);
    const installation_hex = std.fmt.bytesToHex(metadata.installation_id, .lower);
    field(&out, "id_hex", &installation_hex) catch |err| return mapWrite(err);
    field(&out, "backend", @tagName(metadata.backend)) catch |err| return mapWrite(err);
    field(&out, "namespace", "daemon-current") catch |err| return mapWrite(err);
    out.endObject() catch |err| return mapWrite(err);
    out.objectField("observation") catch |err| return mapWrite(err);
    if (available) {
        out.beginObject() catch |err| return mapWrite(err);
        const nonce_hex = std.fmt.bytesToHex(metadata.process_nonce, .lower);
        var id_buffer: [53]u8 = undefined;
        const id = std.fmt.bufPrint(&id_buffer, "{s}:{d}", .{ nonce_hex, metadata.sequence }) catch return error.SourceFailed;
        field(&out, "id", id) catch |err| return mapWrite(err);
        field(&out, "state", @tagName(metadata.state)) catch |err| return mapWrite(err);
        optionalInteger(&out, "observed_wall_us", metadata.observed_wall_us) catch |err| return mapWrite(err);
        optionalInteger(&out, "age_ms", page.age_ms) catch |err| return mapWrite(err);
        field(&out, "observation_complete", true) catch |err| return mapWrite(err);
        field(&out, "observed_total", metadata.observed_total) catch |err| return mapWrite(err);
        field(&out, "sample_count", metadata.retained_count) catch |err| return mapWrite(err);
        field(&out, "sample_truncated", metadata.retained_count < metadata.observed_total) catch |err| return mapWrite(err);
        field(&out, "inventory", @tagName(metadata.inventory)) catch |err| return mapWrite(err);
        field(&out, "origin", @tagName(metadata.origin)) catch |err| return mapWrite(err);
        field(&out, "comparison", "unavailable") catch |err| return mapWrite(err);
        field(&out, "comparison_reason", "intent_revision_not_aligned") catch |err| return mapWrite(err);
        out.endObject() catch |err| return mapWrite(err);
    } else {
        out.write(null) catch |err| return mapWrite(err);
    }
    writeAttempt(&out, metadata, now_ms) catch |err| return mapWrite(err);
    writeFirewallStructure(&out, metadata) catch |err| return mapWrite(err);
    out.objectField("items") catch |err| return mapWrite(err);
    out.beginArray() catch |err| return mapWrite(err);
    for (page.entries[0..page.count]) |entry| writeFirewallItem(&out, entry, metadata) catch |err| return switch (err) {
        error.InvalidScope => error.SourceFailed,
        else => mapWrite(err),
    };
    out.endArray() catch |err| return mapWrite(err);
    out.objectField("next_cursor") catch |err| return mapWrite(err);
    var cursor_buffer: [max_cursor_bytes]u8 = undefined;
    if (page.nextCursor(&cursor_buffer)) |next| out.write(next) catch |err| return mapWrite(err) else out.write(null) catch |err| return mapWrite(err);
    out.endObject() catch |err| return mapWrite(err);
}

const StructureTable = struct { family: []const u8, name: []const u8 };
const StructureChain = struct {
    family: []const u8,
    table: []const u8,
    name: []const u8,
    type: []const u8,
    hook: ?[]const u8 = null,
    priority: ?i32 = null,
    policy: ?[]const u8 = null,
};
const StructureSet = struct { family: []const u8, table: ?[]const u8, name: []const u8, key_type: []const u8 };
const StructureRule = struct {
    family: []const u8,
    table: []const u8,
    chain: []const u8,
    match: []const u8,
    verdict: []const u8,
    position: ?u8 = null,
};

fn hasFirewallStructure(metadata: firewall_observation.Metadata) bool {
    return metadata.state == .owned and metadata.structure_proof == .exact_v1;
}

// exact_v1 is established by the inspector, not inferred from installation intent.
// These fixed shapes are the scaffold that its complete readback validates.
// Dynamic rules/elements remain in the bounded page with exact canonical scopes.
fn writeFirewallStructure(out: anytype, metadata: firewall_observation.Metadata) !void {
    try out.objectField("structure");
    if (!hasFirewallStructure(metadata)) return out.write(null);
    const installation = inspection.Installation{ .id = metadata.installation_id, .transport = metadata.backend };
    var name_buffer: [28]u8 = undefined;
    const name = installation.name(&name_buffer);
    var set_buffers: [2][31]u8 = undefined;
    const sets = [2][]const u8{
        try inspection.setName(name, false, &set_buffers[0]),
        try inspection.setName(name, true, &set_buffers[1]),
    };
    try out.beginObject();
    try field(out, "proof", "exact_v1");
    try out.objectField("tables");
    if (metadata.backend == .nftables) {
        try out.write([_]StructureTable{.{ .family = "inet", .name = name }});
    } else {
        try out.write([_]StructureTable{ .{ .family = "v4", .name = "filter" }, .{ .family = "v6", .name = "filter" } });
    }
    try out.objectField("chains");
    if (metadata.backend == .nftables) {
        try out.write([_]StructureChain{.{ .family = "inet", .table = name, .name = "input", .type = "filter", .hook = "input", .priority = -1, .policy = "accept" }});
    } else {
        try out.write([_]StructureChain{ .{ .family = "v4", .table = "filter", .name = name, .type = "regular" }, .{ .family = "v6", .table = "filter", .name = name, .type = "regular" } });
    }
    try out.objectField("sets");
    try out.beginArray();
    if (metadata.backend == .nftables) {
        try out.write(StructureSet{ .family = "inet", .table = name, .name = "banned_ipv4", .key_type = "ipv4_addr" });
        try out.write(StructureSet{ .family = "inet", .table = name, .name = "banned_ipv6", .key_type = "ipv6_addr" });
    } else if (metadata.backend == .ipset) {
        try out.write(StructureSet{ .family = "v4", .table = null, .name = sets[0], .key_type = "hash:ip" });
        try out.write(StructureSet{ .family = "v6", .table = null, .name = sets[1], .key_type = "hash:ip" });
    }
    try out.endArray();
    try out.objectField("rules");
    try out.beginArray();
    if (metadata.backend == .nftables) {
        try out.write(StructureRule{ .family = "inet", .table = name, .chain = "input", .match = "ip saddr @banned_ipv4", .verdict = "drop" });
        try out.write(StructureRule{ .family = "inet", .table = name, .chain = "input", .match = "ip6 saddr @banned_ipv6", .verdict = "drop" });
    } else {
        for ([_][]const u8{ "v4", "v6" }, 0..) |family, index| {
            try out.write(StructureRule{ .family = family, .table = "filter", .chain = "INPUT", .match = "all", .verdict = name, .position = 1 });
            if (metadata.backend == .ipset) {
                var match_buffer: [48]u8 = undefined;
                const match = try std.fmt.bufPrint(&match_buffer, "source in {s}", .{sets[index]});
                try out.write(StructureRule{ .family = family, .table = "filter", .chain = name, .match = match, .verdict = "drop" });
            }
            try out.write(StructureRule{ .family = family, .table = "filter", .chain = name, .match = "all (ownership marker)", .verdict = "return" });
        }
    }
    try out.endArray();
    try out.endObject();
}

fn writeFirewallPlacement(out: anytype, entry: inspection.Entry, metadata: firewall_observation.Metadata) !void {
    try out.objectField("placement");
    if (!hasFirewallStructure(metadata)) return out.write(null);
    const installation = inspection.Installation{ .id = metadata.installation_id, .transport = metadata.backend };
    var name_buffer: [28]u8 = undefined;
    const name = installation.name(&name_buffer);
    const v6 = if (entry.scope) |scope| scope.subject.family == .v6 else entry.address == .ipv6;
    const in_set = entry.scope == null and metadata.backend != .iptables;
    var set_buffer: [31]u8 = undefined;
    const set: ?[]const u8 = if (!in_set) null else if (metadata.backend == .nftables)
        (if (v6) "banned_ipv6" else "banned_ipv4")
    else
        try inspection.setName(name, v6, &set_buffer);
    try out.write(.{
        .kind = @as([]const u8, if (entry.scope != null) "scoped_rule" else if (in_set) "set_element" else "address_rule"),
        .family = @as([]const u8, if (metadata.backend == .nftables) "inet" else if (v6) "v6" else "v4"),
        .table = if (metadata.backend == .nftables) name else "filter",
        .chain = if (metadata.backend == .nftables) "input" else name,
        .set = set,
        .verdict = @as([]const u8, "drop"),
    });
}

fn writeNoAttempt(out: anytype) !void {
    try out.objectField("last_attempt");
    try out.beginObject();
    try field(out, "outcome", "none");
    try out.objectField("cause");
    try out.write(null);
    try out.objectField("stage");
    try out.write(null);
    try out.objectField("age_ms");
    try out.write(null);
    try out.endObject();
}

fn writeAttempt(out: anytype, metadata: firewall_observation.Metadata, now_ms: ?u64) !void {
    if (metadata.sequence == 0 and metadata.attempt_failure == null) return writeNoAttempt(out);
    try out.objectField("last_attempt");
    try out.beginObject();
    try field(out, "outcome", if (metadata.attempt_failure == null) "success" else "failed");
    try out.objectField("cause");
    if (metadata.attempt_failure) |cause| try out.write(@errorName(cause)) else try out.write(null);
    try out.objectField("stage");
    if (metadata.attempt_stage) |stage| try out.write(@tagName(stage)) else try out.write(null);
    try out.objectField("age_ms");
    if (attemptAge(now_ms, metadata.attempt_mono_ms)) |age| try out.write(age) else try out.write(null);
    try out.endObject();
}

fn attemptAge(now_ms: ?u64, attempt_ms: ?u64) ?u64 {
    const now = now_ms orelse return null;
    const attempted = attempt_ms orelse return null;
    if (attempted > now) return null;
    return now - attempted;
}

fn optionalInteger(out: anytype, name: []const u8, value: anytype) !void {
    try out.objectField(name);
    if (value) |number| try out.write(number) else try out.write(null);
}

fn writeFirewallItem(out: anytype, entry: inspection.Entry, metadata: firewall_observation.Metadata) !void {
    const canonical = entry.scope orelse canonical_scope.Scope{ .subject = canonical_scope.Subject.host(entry.address) };
    const scope = try projectScope(canonical);
    try out.beginObject();
    try out.objectField("scope");
    try writeScope(out, scope);
    try out.objectField("effect_id_hex");
    if (entry.effect_id) |id| {
        const hex = std.fmt.bytesToHex(id, .lower);
        try out.write(&hex);
    } else try out.write(null);
    try optionalInteger(out, "remaining_ms_at_observation", entry.remaining_ms);
    try optionalInteger(out, "deadline_us", entry.deadline_us);
    try writeFirewallPlacement(out, entry, metadata);
    try out.endObject();
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
    if (scanned.more and scanned.resume_after <= after_sequence) return error.SourceFailed;
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
