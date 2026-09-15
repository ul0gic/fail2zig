// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Bounded typed query rendering over daemon-supplied views.
const std = @import("std");
const query = @import("net/query_v1.zig");

const t = std.testing;
const a = t.allocator;
const generation: [32]u8 = [_]u8{0xab} ** 32;
const generation_hex = "abababababababababababababababababababababababababababababababab";

fn statusCallback(_: ?*anyopaque, _: std.mem.Allocator, out: *std.ArrayList(u8)) anyerror!void {
    try out.appendSlice("{\"version\":\"0.3.1\",\"generation\":\"stale\",\"active_bans\":2}");
}

fn healthCallback(_: ?*anyopaque, _: std.mem.Allocator, out: *std.ArrayList(u8)) anyerror!void {
    try out.appendSlice("{\"ready\":true,\"components\":{\"storage\":\"ok\"}}");
}

fn hugeCallback(_: ?*anyopaque, allocator: std.mem.Allocator, out: *std.ArrayList(u8)) anyerror!void {
    _ = allocator;
    try out.appendSlice("{\"pad\":\"");
    try out.appendNTimes('x', query.max_response_bytes);
    try out.appendSlice("\"}");
}

fn brokenCallback(_: ?*anyopaque, _: std.mem.Allocator, out: *std.ArrayList(u8)) anyerror!void {
    try out.appendSlice("not json");
}

const config_view = query.ConfigView{
    .jails = &.{
        .{ .name = "sshd", .enabled = true, .filter = "sshd", .source = "journal", .logpath = &.{"/var/log/auth.log"}, .maxretry = 5, .findtime = 600, .bantime = 3600, .bantime_permanent = false, .banaction = "nftables", .ignoreip = &.{ "127.0.0.1/8", "192.0.2.0/24" } },
        .{ .name = "nginx", .enabled = false, .filter = "nginx-http-auth", .source = "file", .logpath = &.{}, .maxretry = 3, .findtime = 60, .bantime = 0, .bantime_permanent = true, .banaction = "nftables", .ignoreip = &.{} },
    },
    .global = .{ .log_level = "info", .firewall = "nftables", .metrics_enabled = true, .metrics_bind = "127.0.0.1", .metrics_port = 9101, .socket_path = "/run/fail2zig/fail2zig.sock", .state_file = "/var/lib/fail2zig/state.sqlite", .dns_server = "192.0.2.53", .timezone_root = null },
};

fn v4(last: u8) query.ScopeFields {
    return .{ .family = .v4, .address = [_]u8{ 192, 0, 2, last } ++ [_]u8{0} ** 12, .prefix = 32 };
}

fn item(last: u8, confirmed: bool) query.ScopeItem {
    return .{ .scope = v4(last), .lease = .finite, .deadline_us = 1_700_000_000_000_000 + @as(i64, last), .decision_id = [_]u8{last} ** 32, .confirmed = confirmed };
}

const sshd_items = [_]query.ScopeItem{ item(1, true), item(2, true), item(3, false) };
const v6_item = query.ScopeItem{ .scope = .{ .family = .v6, .address = [_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 11 ++ [_]u8{1}, .prefix = 128, .protocol = "tcp", .port = 22, .direction = "input", .target = "firewall" }, .lease = .permanent, .deadline_us = null, .decision_id = null, .confirmed = true };
const nginx_items = [_]query.ScopeItem{v6_item};
const scopes_view = query.ScopesView{ .jails = &.{
    .{ .name = "sshd", .items = &sshd_items },
    .{ .name = "empty", .items = &.{} },
    .{ .name = "nginx", .items = &nginx_items },
} };

const History = struct {
    events: []const query.HistoryEvent,
    calls: u32 = 0,
    /// Rows examined per call, mirroring the daemon's page cap; 0 = unbounded.
    scan_budget: u32 = 0,
    stuck: bool = false,
    last_after: u64 = 0,
    fn read(ctx: ?*anyopaque, jail: ?[]const u8, after: u64, limit: u16, out: *std.ArrayList(query.HistoryEvent)) anyerror!query.HistoryRead {
        const self: *History = @ptrCast(@alignCast(ctx.?));
        self.calls += 1;
        self.last_after = after;
        if (self.stuck) return .{ .more = true, .resume_after = after };
        var scanned: u32 = 0;
        var resume_after = after;
        for (self.events) |entry| {
            if (entry.sequence <= after) continue;
            if (self.scan_budget != 0 and scanned == self.scan_budget) return .{ .more = true, .resume_after = resume_after };
            if (out.items.len == limit) return .{ .more = true, .resume_after = resume_after };
            scanned += 1;
            resume_after = entry.sequence;
            if (jail) |name| if (!std.mem.eql(u8, name, entry.jail)) continue;
            try out.append(entry);
        }
        return .{ .more = false, .resume_after = resume_after };
    }
};

fn event(sequence: u64, jail: []const u8) query.HistoryEvent {
    return .{ .sequence = sequence, .event_id = [_]u8{@intCast(sequence)} ** 32, .jail = jail, .decision_id = [_]u8{0x11} ** 32, .confirmed_us = 1_000 + @as(i64, @intCast(sequence)), .scope = v4(@intCast(sequence)), .native_retry = sequence % 2 == 0 };
}

const history_events = [_]query.HistoryEvent{ event(1, "sshd"), event(2, "sshd"), event(3, "nginx"), event(4, "sshd"), event(5, "sshd") };

fn sources(history: *History) query.Sources {
    return .{
        .status = .{ .ctx = null, .func = statusCallback },
        .health = .{ .ctx = null, .func = healthCallback },
        .config = config_view,
        .scopes = scopes_view,
        .history = .{ .ctx = history, .read = History.read },
    };
}

fn run(body: []const u8, peer: query.PeerClass, src: query.Sources) !query.Result {
    return query.handle(a, body, peer, generation, src);
}

fn parse(payload: []const u8) !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, a, payload, .{});
}

fn expectFailure(result: query.Result, code: u16) !void {
    try t.expect(result == .failure);
    try t.expectEqual(code, result.failure.code);
}

test "native query: status passes the daemon object through with the envelope forced" {
    var history = History{ .events = &history_events };
    const result = try run("{\"schema_version\":1,\"kind\":\"status\"}", .monitor, sources(&history));
    defer result.deinit(a);
    const doc = try parse(result.payload);
    defer doc.deinit();
    try t.expectEqual(@as(i64, 1), doc.value.object.get("schema_version").?.integer);
    try t.expectEqualStrings(generation_hex, doc.value.object.get("generation").?.string);
    try t.expectEqualStrings("0.3.1", doc.value.object.get("version").?.string);
    try t.expectEqual(@as(i64, 2), doc.value.object.get("active_bans").?.integer);
}

test "native query: health is null-shaped until a readiness source is wired" {
    const result = try run("{\"schema_version\":1,\"kind\":\"health\"}", .admin, .{});
    defer result.deinit(a);
    const doc = try parse(result.payload);
    defer doc.deinit();
    try t.expect(doc.value.object.get("ready").? == .null);
    try t.expect(doc.value.object.get("components").? == .null);
    try t.expectEqualStrings(generation_hex, doc.value.object.get("generation").?.string);

    var history = History{ .events = &history_events };
    const wired = try run("{\"schema_version\":1,\"kind\":\"health\"}", .admin, sources(&history));
    defer wired.deinit(a);
    const wired_doc = try parse(wired.payload);
    defer wired_doc.deinit();
    try t.expect(wired_doc.value.object.get("ready").?.bool);
    try t.expectEqualStrings("ok", wired_doc.value.object.get("components").?.object.get("storage").?.string);
}

test "native query: config is complete for admin and redacted for monitor peers" {
    var history = History{ .events = &history_events };
    const admin = try run("{\"schema_version\":1,\"kind\":\"config\"}", .admin, sources(&history));
    defer admin.deinit(a);
    const admin_doc = try parse(admin.payload);
    defer admin_doc.deinit();
    const admin_root = admin_doc.value.object;
    try t.expect(!admin_root.get("redacted").?.bool);
    try t.expectEqualStrings("/run/fail2zig/fail2zig.sock", admin_root.get("global").?.object.get("socket_path").?.string);
    try t.expectEqualStrings("192.0.2.53", admin_root.get("global").?.object.get("dns_server").?.string);
    try t.expect(admin_root.get("global").?.object.get("timezone_root").? == .null);
    const admin_jails = admin_root.get("jails").?.array;
    try t.expectEqual(@as(usize, 2), admin_jails.items.len);
    try t.expectEqualStrings("192.0.2.0/24", admin_jails.items[0].object.get("ignoreip").?.array.items[1].string);
    try t.expectEqualStrings("/var/log/auth.log", admin_jails.items[0].object.get("logpath").?.array.items[0].string);
    try t.expect(admin_jails.items[1].object.get("bantime_permanent").?.bool);

    const monitor = try run("{\"schema_version\":1,\"kind\":\"config\"}", .monitor, sources(&history));
    defer monitor.deinit(a);
    const monitor_doc = try parse(monitor.payload);
    defer monitor_doc.deinit();
    const root = monitor_doc.value.object;
    try t.expect(root.get("redacted").?.bool);
    const global = root.get("global").?.object;
    inline for (.{ "socket_path", "state_file", "dns_server", "timezone_root" }) |name| {
        try t.expectEqualStrings("<redacted>", global.get(name).?.string);
    }
    try t.expectEqualStrings("info", global.get("log_level").?.string);
    try t.expectEqual(@as(i64, 9101), global.get("metrics_port").?.integer);
    const jail = root.get("jails").?.array.items[0].object;
    try t.expectEqualStrings("<redacted>", jail.get("ignoreip").?.array.items[0].string);
    try t.expectEqualStrings("<redacted>", jail.get("logpath").?.array.items[0].string);
    try t.expectEqualStrings("sshd", jail.get("name").?.string);
    try t.expect(std.mem.indexOf(u8, monitor.payload, "192.0.2") == null);
    try t.expect(std.mem.indexOf(u8, monitor.payload, "/var/") == null);
}

test "native query: scopes page walks jails in order and encodes optional scope fields" {
    var history = History{ .events = &history_events };
    const result = try run("{\"schema_version\":1,\"kind\":\"scopes\"}", .monitor, sources(&history));
    defer result.deinit(a);
    const doc = try parse(result.payload);
    defer doc.deinit();
    const items = doc.value.object.get("items").?.array.items;
    try t.expectEqual(@as(usize, 4), items.len);
    try t.expect(doc.value.object.get("next_cursor").? == .null);
    const first = items[0].object;
    try t.expectEqualStrings("sshd", first.get("jail").?.string);
    try t.expectEqualStrings("192.0.2.1", first.get("scope").?.object.get("address").?.string);
    try t.expectEqualStrings("v4", first.get("scope").?.object.get("family").?.string);
    try t.expectEqual(@as(i64, 32), first.get("scope").?.object.get("prefix").?.integer);
    try t.expect(first.get("scope").?.object.get("protocol") == null);
    try t.expectEqualStrings("finite", first.get("lease").?.string);
    try t.expectEqual(@as(i64, 1_700_000_000_000_001), first.get("deadline_us").?.integer);
    try t.expectEqualStrings("01" ** 32, first.get("decision_id_hex").?.string);
    try t.expect(first.get("confirmed").?.bool);
    try t.expect(!items[2].object.get("confirmed").?.bool);
    const last = items[3].object;
    try t.expectEqualStrings("nginx", last.get("jail").?.string);
    try t.expectEqualStrings("2001:db8::1", last.get("scope").?.object.get("address").?.string);
    try t.expectEqualStrings("tcp", last.get("scope").?.object.get("protocol").?.string);
    try t.expectEqual(@as(i64, 22), last.get("scope").?.object.get("port").?.integer);
    try t.expectEqualStrings("input", last.get("scope").?.object.get("direction").?.string);
    try t.expectEqualStrings("firewall", last.get("scope").?.object.get("target").?.string);
    try t.expectEqualStrings("permanent", last.get("lease").?.string);
    try t.expect(last.get("deadline_us").? == .null);
    try t.expect(last.get("decision_id_hex").? == .null);
}

test "native query: scopes cursor round-trips across pages and exhausts to null" {
    var history = History{ .events = &history_events };
    var cursor: ?[]u8 = null;
    defer if (cursor) |c| a.free(c);
    var seen = std.ArrayList([]u8).init(a);
    defer {
        for (seen.items) |s| a.free(s);
        seen.deinit();
    }
    var pages: usize = 0;
    while (true) {
        const body = if (cursor) |c| try std.fmt.allocPrint(a, "{{\"schema_version\":1,\"kind\":\"scopes\",\"limit\":3,\"cursor\":\"{s}\"}}", .{c}) else try a.dupe(u8, "{\"schema_version\":1,\"kind\":\"scopes\",\"limit\":3}");
        defer a.free(body);
        const result = try run(body, .admin, sources(&history));
        defer result.deinit(a);
        const doc = try parse(result.payload);
        defer doc.deinit();
        pages += 1;
        for (doc.value.object.get("items").?.array.items) |entry| {
            try seen.append(try a.dupe(u8, entry.object.get("scope").?.object.get("address").?.string));
        }
        const next = doc.value.object.get("next_cursor").?;
        if (cursor) |c| a.free(c);
        cursor = null;
        if (next == .null) break;
        cursor = try a.dupe(u8, next.string);
        try t.expect(pages < 10);
    }
    try t.expectEqual(@as(usize, 2), pages);
    try t.expectEqual(@as(usize, 4), seen.items.len);
    try t.expectEqualStrings("192.0.2.1", seen.items[0]);
    try t.expectEqualStrings("192.0.2.3", seen.items[2]);
    try t.expectEqualStrings("2001:db8::1", seen.items[3]);
}

test "native query: scopes exact-fit page reports null instead of a dead cursor" {
    var history = History{ .events = &history_events };
    const result = try run("{\"schema_version\":1,\"kind\":\"scopes\",\"limit\":4}", .admin, sources(&history));
    defer result.deinit(a);
    const doc = try parse(result.payload);
    defer doc.deinit();
    try t.expectEqual(@as(usize, 4), doc.value.object.get("items").?.array.items.len);
    try t.expect(doc.value.object.get("next_cursor").? == .null);
}

test "native query: scopes jail filter, empty jail and unknown jail" {
    var history = History{ .events = &history_events };
    const filtered = try run("{\"schema_version\":1,\"kind\":\"scopes\",\"jail\":\"nginx\"}", .admin, sources(&history));
    defer filtered.deinit(a);
    const doc = try parse(filtered.payload);
    defer doc.deinit();
    try t.expectEqual(@as(usize, 1), doc.value.object.get("items").?.array.items.len);

    const empty = try run("{\"schema_version\":1,\"kind\":\"scopes\",\"jail\":\"empty\"}", .admin, sources(&history));
    defer empty.deinit(a);
    const empty_doc = try parse(empty.payload);
    defer empty_doc.deinit();
    try t.expectEqual(@as(usize, 0), empty_doc.value.object.get("items").?.array.items.len);
    try t.expect(empty_doc.value.object.get("next_cursor").? == .null);

    const unknown = try run("{\"schema_version\":1,\"kind\":\"scopes\",\"jail\":\"nope\"}", .admin, sources(&history));
    try expectFailure(unknown, 404);

    const no_view = try run("{\"schema_version\":1,\"kind\":\"scopes\"}", .admin, .{});
    try expectFailure(no_view, 503);
}

test "native query: history pages through the detached source with a sequence cursor" {
    var history = History{ .events = &history_events };
    const first = try run("{\"schema_version\":1,\"kind\":\"history\",\"limit\":2}", .monitor, sources(&history));
    defer first.deinit(a);
    const doc = try parse(first.payload);
    defer doc.deinit();
    const items = doc.value.object.get("items").?.array.items;
    try t.expectEqual(@as(usize, 2), items.len);
    try t.expectEqual(@as(i64, 1), items[0].object.get("sequence").?.integer);
    try t.expectEqualStrings("01" ** 32, items[0].object.get("event_id_hex").?.string);
    try t.expectEqualStrings("11" ** 32, items[0].object.get("decision_id_hex").?.string);
    try t.expectEqual(@as(i64, 1001), items[0].object.get("confirmed_us").?.integer);
    try t.expect(!items[0].object.get("native_retry").?.bool);
    try t.expect(items[1].object.get("native_retry").?.bool);
    try t.expectEqualStrings("192.0.2.2", items[1].object.get("scope").?.object.get("address").?.string);
    const next = doc.value.object.get("next_cursor").?.string;
    try t.expectEqual(query.Cursor{ .history = .{ .after_sequence = 2 } }, try query.Cursor.decode(next));

    const body = try std.fmt.allocPrint(a, "{{\"schema_version\":1,\"kind\":\"history\",\"limit\":2,\"cursor\":\"{s}\",\"jail\":\"sshd\"}}", .{next});
    defer a.free(body);
    const second = try run(body, .monitor, sources(&history));
    defer second.deinit(a);
    const second_doc = try parse(second.payload);
    defer second_doc.deinit();
    const second_items = second_doc.value.object.get("items").?.array.items;
    try t.expectEqual(@as(usize, 2), second_items.len);
    try t.expectEqual(@as(i64, 4), second_items[0].object.get("sequence").?.integer);
    try t.expectEqual(@as(i64, 5), second_items[1].object.get("sequence").?.integer);
    try t.expect(second_doc.value.object.get("next_cursor").? == .null);
    try t.expectEqual(@as(u32, 2), history.calls);
}

test "native query: a filtered scan that exhausts its budget returns an empty page with an advancing cursor" {
    // Only sequence 3 belongs to nginx; with a 2-row budget the first call scans 1..2 and finds nothing.
    var history = History{ .events = &history_events, .scan_budget = 2 };
    const first = try run("{\"schema_version\":1,\"kind\":\"history\",\"jail\":\"nginx\",\"limit\":10}", .admin, sources(&history));
    defer first.deinit(a);
    const doc = try parse(first.payload);
    defer doc.deinit();
    try t.expectEqual(@as(usize, 0), doc.value.object.get("items").?.array.items.len);
    const next = doc.value.object.get("next_cursor").?.string;
    try t.expectEqual(query.Cursor{ .history = .{ .after_sequence = 2 } }, try query.Cursor.decode(next));

    const body = try std.fmt.allocPrint(a, "{{\"schema_version\":1,\"kind\":\"history\",\"jail\":\"nginx\",\"limit\":10,\"cursor\":\"{s}\"}}", .{next});
    defer a.free(body);
    const second = try run(body, .admin, sources(&history));
    defer second.deinit(a);
    const second_doc = try parse(second.payload);
    defer second_doc.deinit();
    const items = second_doc.value.object.get("items").?.array.items;
    try t.expectEqual(@as(usize, 1), items.len);
    try t.expectEqual(@as(i64, 3), items[0].object.get("sequence").?.integer);
    try t.expectEqual(@as(u64, 2), history.last_after);
    try t.expectEqual(@as(u32, 2), history.calls);
    try t.expectEqual(query.Cursor{ .history = .{ .after_sequence = 4 } }, try query.Cursor.decode(second_doc.value.object.get("next_cursor").?.string));

    // A source that reports more without advancing is refused rather than looped on.
    var stuck = History{ .events = &history_events, .stuck = true };
    try expectFailure(try run("{\"schema_version\":1,\"kind\":\"history\"}", .admin, sources(&stuck)), 500);
}

test "native query: history empty page and missing source" {
    var history = History{ .events = &.{} };
    const result = try run("{\"schema_version\":1,\"kind\":\"history\"}", .admin, sources(&history));
    defer result.deinit(a);
    const doc = try parse(result.payload);
    defer doc.deinit();
    try t.expectEqual(@as(usize, 0), doc.value.object.get("items").?.array.items.len);
    try t.expect(doc.value.object.get("next_cursor").? == .null);
    try expectFailure(try run("{\"schema_version\":1,\"kind\":\"history\"}", .admin, .{}), 503);
}

test "native query: malformed, unknown-kind, version and limit bounds are 400" {
    var history = History{ .events = &history_events };
    const bad = [_][]const u8{
        "",
        "{",
        "[]",
        "{\"kind\":\"status\"}",
        "{\"schema_version\":2,\"kind\":\"status\"}",
        "{\"schema_version\":1}",
        "{\"schema_version\":1,\"kind\":\"bans\"}",
        "{\"schema_version\":1,\"kind\":\"status\",\"extra\":1}",
        "{\"schema_version\":1,\"kind\":\"scopes\",\"limit\":0}",
        "{\"schema_version\":1,\"kind\":\"scopes\",\"limit\":257}",
        "{\"schema_version\":1,\"kind\":\"scopes\",\"limit\":-1}",
        "{\"schema_version\":1,\"kind\":\"scopes\",\"limit\":\"5\"}",
        "{\"schema_version\":1,\"kind\":\"scopes\",\"jail\":\"\"}",
        "{\"schema_version\":1,\"kind\":\"scopes\",\"cursor\":\"\"}",
        "{\"schema_version\":1,\"kind\":\"scopes\",\"cursor\":\"!!!\"}",
        "{\"schema_version\":1,\"kind\":\"scopes\",\"cursor\":\"aDox\"}",
        "{\"schema_version\":1,\"kind\":\"history\",\"cursor\":\"czowOjA\"}",
        "{\"schema_version\":1,\"kind\":\"scopes\",\"cursor\":\"czo5OTk6MA\"}",
    };
    for (bad) |body| {
        const result = try run(body, .admin, sources(&history));
        expectFailure(result, 400) catch |err| {
            std.debug.print("body accepted: {s}\n", .{body});
            return err;
        };
    }
    var long_jail: [65]u8 = undefined;
    @memset(&long_jail, 'j');
    const long = try std.fmt.allocPrint(a, "{{\"schema_version\":1,\"kind\":\"scopes\",\"jail\":\"{s}\"}}", .{long_jail});
    defer a.free(long);
    try expectFailure(try run(long, .admin, sources(&history)), 400);
    const oversized = try a.alloc(u8, 16 * 1024 + 1);
    defer a.free(oversized);
    @memset(oversized, ' ');
    try expectFailure(try run(oversized, .admin, sources(&history)), 400);
}

test "native query: limit 256 is accepted and default limit applies" {
    var history = History{ .events = &history_events };
    const max = try run("{\"schema_version\":1,\"kind\":\"scopes\",\"limit\":256}", .admin, sources(&history));
    defer max.deinit(a);
    try t.expect(max == .payload);
}

test "native query: pass-through responses above 1 MiB are refused as 413" {
    const result = try run("{\"schema_version\":1,\"kind\":\"status\"}", .admin, .{ .status = .{ .ctx = null, .func = hugeCallback } });
    try expectFailure(result, 413);
    const broken = try run("{\"schema_version\":1,\"kind\":\"health\"}", .admin, .{ .health = .{ .ctx = null, .func = brokenCallback } });
    try expectFailure(broken, 500);
    try expectFailure(try run("{\"schema_version\":1,\"kind\":\"status\"}", .admin, .{}), 503);
}

test "native query: cursor encoding is opaque base64url and strict on decode" {
    var buffer: [query.max_cursor_bytes]u8 = undefined;
    const encoded = (query.Cursor{ .scopes = .{ .jail = 7, .item = 42 } }).encode(&buffer);
    for (encoded) |c| try t.expect(std.ascii.isAlphanumeric(c) or c == '-' or c == '_');
    try t.expectEqual(query.Cursor{ .scopes = .{ .jail = 7, .item = 42 } }, try query.Cursor.decode(encoded));
    const history = (query.Cursor{ .history = .{ .after_sequence = std.math.maxInt(u64) } }).encode(&buffer);
    try t.expectEqual(query.Cursor{ .history = .{ .after_sequence = std.math.maxInt(u64) } }, try query.Cursor.decode(history));
    try t.expectError(error.BadCursor, query.Cursor.decode(""));
    try t.expectError(error.BadCursor, query.Cursor.decode("czo=")); // padded
    try t.expectError(error.BadCursor, query.Cursor.decode("eDoxOjI")); // x:1:2
    try t.expectError(error.BadCursor, query.Cursor.decode("czoxOg")); // s:1:
}
