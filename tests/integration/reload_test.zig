// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const harness = @import("harness.zig");

const t = std.testing;
const exe = "zig-out/bin/fail2zig";
const failure = "Failed password for root from 203.0.113.7 port 22 ssh2";

const Run = struct {
    code: u8,
    stdout: []u8,
    stderr: []u8,
    fn deinit(self: Run, a: std.mem.Allocator) void {
        a.free(self.stdout);
        a.free(self.stderr);
    }
};

fn run(a: std.mem.Allocator, argv: []const []const u8) !Run {
    const r = try std.process.Child.run(.{ .allocator = a, .argv = argv, .max_output_bytes = 1 << 20 });
    return .{ .code = switch (r.term) {
        .Exited => |c| c,
        else => 255,
    }, .stdout = r.stdout, .stderr = r.stderr };
}

fn writeConfig(h: *harness.Harness, maxretry: u32, bantime: u32, extra: []const u8) !void {
    var file = try std.fs.cwd().createFile(h.config_path, .{ .mode = 0o600 });
    defer file.close();
    try file.writer().print(
        \\[global]
        \\native_ingestion = true
        \\state_file = "{s}"
        \\socket_path = "{s}"
        \\metrics_enabled = false
        \\{s}
        \\[defaults]
        \\banaction = "log-only"
        \\maxretry = {d}
        \\findtime = 600
        \\bantime = {d}
        \\[jails.sshd]
        \\filter = "sshd"
        \\source = "file"
        \\timestamp = "undated"
        \\logpath = ["{s}"]
        \\
    , .{ h.state_path, h.socket_path, extra, maxretry, bantime, h.log_path });
}

fn client(a: std.mem.Allocator, h: *harness.Harness, cmd: []const u8) !Run {
    return run(a, &.{ exe, "--socket", h.socket_path, "--timeout", "4000", "--output", "json", cmd });
}

fn jsonString(a: std.mem.Allocator, json: []const u8, key: []const u8) ![]u8 {
    const needle = try std.fmt.allocPrint(a, "\"{s}\":\"", .{key});
    defer a.free(needle);
    const start = (std.mem.indexOf(u8, json, needle) orelse return error.MissingField) + needle.len;
    const end = std.mem.indexOfScalarPos(u8, json, start, '"') orelse return error.MissingField;
    return a.dupe(u8, json[start..end]);
}

fn generation(a: std.mem.Allocator, h: *harness.Harness) ![]u8 {
    const r = try client(a, h, "status");
    defer r.deinit(a);
    try t.expectEqual(@as(u8, 0), r.code);
    return jsonString(a, r.stdout, "generation");
}

fn waitHealthy(h: *harness.Harness) !void {
    var timer = try std.time.Timer.start();
    while (timer.read() < 10 * std.time.ns_per_s) {
        const s = try h.queryStatus();
        defer t.allocator.free(s);
        if (std.mem.indexOf(u8, s, "\"storage\":\"healthy\"") != null) return;
        std.time.sleep(25 * std.time.ns_per_ms);
    }
    return error.TimedOut;
}

fn waitListContains(h: *harness.Harness, needle: []const u8) !void {
    var timer = try std.time.Timer.start();
    while (timer.read() < 10 * std.time.ns_per_s) {
        const listing = try h.queryList();
        defer t.allocator.free(listing);
        if (std.mem.indexOf(u8, listing, needle) != null) return;
        std.time.sleep(50 * std.time.ns_per_ms);
    }
    return error.TimedOut;
}

fn waitJailsContains(a: std.mem.Allocator, h: *harness.Harness, needle: []const u8) !void {
    var timer = try std.time.Timer.start();
    while (timer.read() < 10 * std.time.ns_per_s) {
        const r = try client(a, h, "jails");
        defer r.deinit(a);
        if (r.code == 0 and std.mem.indexOf(u8, r.stdout, needle) != null) return;
        std.time.sleep(50 * std.time.ns_per_ms);
    }
    return error.TimedOut;
}

test "reload: no-op, invalid, restart-only and live policy proposals return exact outcomes without disturbing protection" {
    const a = t.allocator;
    std.fs.cwd().access(exe, .{}) catch return error.SkipZigTest;
    var h = try harness.Harness.init(a, .{ .spawn_daemon = false });
    defer h.deinit();
    try writeConfig(&h, 3, 60, "");
    try h.startDaemon();
    defer _ = h.stopDaemon() catch {};
    try waitHealthy(&h);
    const g0 = try generation(a, &h);
    defer a.free(g0);
    try t.expectEqual(@as(usize, 64), g0.len);

    const noop = try client(a, &h, "reload");
    defer noop.deinit(a);
    try t.expectEqual(@as(u8, 0), noop.code);
    try t.expect(std.mem.indexOf(u8, noop.stdout, "\"schema_version\":1") != null);
    try t.expect(std.mem.indexOf(u8, noop.stdout, "\"outcome\":\"noop\"") != null);
    try t.expect(std.mem.indexOf(u8, noop.stdout, g0) != null);

    try writeConfig(&h, 3, 60, "bogus_key = 1");
    const invalid = try client(a, &h, "reload");
    defer invalid.deinit(a);
    try t.expectEqual(@as(u8, 1), invalid.code);
    try t.expect(std.mem.indexOf(u8, invalid.stdout, "\"outcome\":\"rejected\"") != null);
    try t.expect(std.mem.indexOf(u8, invalid.stdout, "UnknownKey") != null);

    try writeConfig(&h, 3, 60, "metrics_port = 9199");
    const restart = try client(a, &h, "reload");
    defer restart.deinit(a);
    try t.expectEqual(@as(u8, 1), restart.code);
    try t.expect(std.mem.indexOf(u8, restart.stdout, "\"outcome\":\"restart_required\"") != null);
    try t.expect(std.mem.indexOf(u8, restart.stdout, "global.metrics_port") != null);
    const still = try generation(a, &h);
    defer a.free(still);
    try t.expectEqualStrings(g0, still);

    try t.expectError(error.UnexpectedResponse, h.sendCommand(.{ .reload = {} }));

    try writeConfig(&h, 2, 60, "");
    const applied = try client(a, &h, "reload");
    defer applied.deinit(a);
    try t.expectEqual(@as(u8, 0), applied.code);
    try t.expect(std.mem.indexOf(u8, applied.stdout, "\"outcome\":\"applied\"") != null);
    const g1 = try generation(a, &h);
    defer a.free(g1);
    try t.expect(!std.mem.eql(u8, g0, g1));
    try waitJailsContains(a, &h, "\"maxretry\":2");
    try waitHealthy(&h);

    try h.writeLine(failure);
    try h.writeLine(failure);
    try waitListContains(&h, "203.0.113.7");

    const plain = try run(a, &.{ exe, "--socket", h.socket_path, "--output", "plain", "reload" });
    defer plain.deinit(a);
    try t.expectEqual(@as(u8, 0), plain.code);
    try t.expect(std.mem.startsWith(u8, plain.stdout, "outcome\tnoop\ngeneration\t"));

    const before_rejected = try h.queryList();
    defer a.free(before_rejected);
    try writeConfig(&h, 2, 60, "dns_server = \"invalid-address\"");
    const semantic = try client(a, &h, "reload");
    defer semantic.deinit(a);
    try t.expectEqual(@as(u8, 1), semantic.code);
    try t.expect(std.mem.indexOf(u8, semantic.stdout, "\"outcome\":\"rejected\"") != null);
    try t.expect(std.mem.indexOf(u8, semantic.stdout, "InvalidNativeDns") != null);
    try t.expect(std.mem.indexOf(u8, semantic.stdout, "[global].dns_server") != null);
    const after_generation = try generation(a, &h);
    defer a.free(after_generation);
    try t.expectEqualStrings(g1, after_generation);
    const after_rejected = try h.queryList();
    defer a.free(after_rejected);
    try t.expectEqualStrings(before_rejected, after_rejected);
}

test "reload: SIGHUP applies a live bantime change and the generation survives restart while a stopped-time edit still refuses" {
    const a = t.allocator;
    std.fs.cwd().access(exe, .{}) catch return error.SkipZigTest;
    var h = try harness.Harness.init(a, .{ .spawn_daemon = false });
    defer h.deinit();
    try writeConfig(&h, 3, 60, "");
    try h.startDaemon();
    try waitHealthy(&h);
    try writeConfig(&h, 3, 120, "");
    try std.posix.kill(h.child.?.id, std.posix.SIG.HUP);
    try waitJailsContains(a, &h, "\"bantime\":120");
    try waitHealthy(&h);
    const g1 = try generation(a, &h);
    defer a.free(g1);
    try t.expectEqual(std.process.Child.Term{ .Exited = 0 }, try h.stopDaemon());

    try h.startDaemon();
    try waitHealthy(&h);
    const g2 = try generation(a, &h);
    defer a.free(g2);
    try t.expectEqualStrings(g1, g2);
    try waitJailsContains(a, &h, "\"bantime\":120");
    try t.expectEqual(std.process.Child.Term{ .Exited = 0 }, try h.stopDaemon());

    try writeConfig(&h, 5, 120, "");
    try t.expectError(error.DaemonUnavailable, h.startDaemon());
    try writeConfig(&h, 3, 120, "");
    try h.startDaemon();
    defer _ = h.stopDaemon() catch {};
    try waitHealthy(&h);
    const g3 = try generation(a, &h);
    defer a.free(g3);
    try t.expectEqualStrings(g1, g3);
}
