// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

const shared = @import("shared");
const engine = @import("engine");

const EventLoop = engine.event_loop_mod.EventLoop;
const journald = engine.journald_source_mod;
const ipc = engine.ipc_mod;
const commands = engine.commands_mod;
const config_mod = engine.config_mod;
const tracker_map_mod = engine.tracker_map_mod;
const firewall = engine.firewall;

const testing = std.testing;

const iterations: u32 = 500;
const pace_ms: u64 = 10;
const target_ns: u64 = 50 * std.time.ns_per_ms;
const check_interval_ms: u64 = 5;
const deadline_ms: i64 = 30_000;

const fake_journalctl =
    \\#!/bin/sh
    \\sleep 1
    \\printf '{"MESSAGE":"Invalid user a from 1.1.1.1 port 1","__CURSOR":"s=b1"}\n'
    \\printf '{"MESSAGE":"Invalid user b from 2.2.2.2 port 2","__CURSOR":"s=b2"}\n'
    \\printf '{"MESSAGE":"Invalid user c from 3.3.3.3 port 3","__CURSOR":"s=b3"}\n'
    \\
;

const LineCounter = struct {
    lines: u64 = 0,

    fn onLine(_: []const u8, _: shared.JailId, _: bool, ud: ?*anyopaque) void {
        const self: *LineCounter = @ptrCast(@alignCast(ud.?));
        self.lines += 1;
    }
};

const Driver = struct {
    loop: *EventLoop,
    done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    start_ms: i64,

    fn onCheck(_: u64, ud: ?*anyopaque) void {
        const d: *Driver = @ptrCast(@alignCast(ud.?));
        const timed_out = std.time.milliTimestamp() - d.start_ms > deadline_ms;
        if (d.done.load(.acquire) or timed_out) d.loop.stop();
    }
};

const Client = struct {
    socket_path: []const u8,
    samples: []u64,
    completed: u32 = 0,
    failures: u32 = 0,
    driver: *Driver,

    fn run(self: *Client) void {
        defer self.driver.done.store(true, .release);
        var timer = std.time.Timer.start() catch return;
        var i: u32 = 0;
        while (i < iterations) : (i += 1) {
            const t0 = timer.read();
            if (statusRoundTrip(self.socket_path)) {
                self.samples[self.completed] = timer.read() - t0;
                self.completed += 1;
            } else |_| {
                self.failures += 1;
            }
            std.time.sleep(pace_ms * std.time.ns_per_ms);
        }
    }
};

fn statusRoundTrip(socket_path: []const u8) !void {
    const stream = try std.net.connectUnixSocket(socket_path);
    defer stream.close();
    try shared.serializeCommand(.{ .status = {} }, stream.writer());
    const resp = try shared.deserializeResponse(stream.reader(), std.heap.page_allocator);
    defer resp.deinit(std.heap.page_allocator);
    switch (resp) {
        .ok => |o| if (std.mem.indexOf(u8, o.payload, "\"protection\"") == null) return error.UnexpectedPayload,
        .err => return error.ErrResponse,
    }
}

test "benchmark: IPC status round-trip latency while a slow journalctl is polled (PRF-001)" {
    if (!benchmarkEnabled()) return error.SkipZigTest;
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const a = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "journalctl", .data = fake_journalctl, .flags = .{ .mode = 0o755 } });
    var abs_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = try tmp.dir.realpath(".", &abs_buf);
    const script = try std.fmt.allocPrint(a, "{s}/journalctl", .{root});
    defer a.free(script);
    const state_file = try std.fmt.allocPrint(a, "{s}/state.bin", .{root});
    defer a.free(state_file);
    const socket_path = try std.fmt.allocPrint(a, "{s}/bench.sock", .{root});
    defer a.free(socket_path);
    if (socket_path.len >= 108) return error.SkipZigTest;

    var loop = try EventLoop.init(a);
    defer loop.deinit();

    var counter = LineCounter{};
    var src = try journald.JournaldSource.init(a, &loop, state_file, .{ .journalctl_path = script });
    defer src.deinit();
    try src.addJail(try shared.JailId.fromSlice("sshd"), "sshd", LineCounter.onLine, &counter);
    src.seedCursor("sshd", "s=seed");
    try src.attach();

    var trackers = tracker_map_mod.TrackerMap.init(a);
    defer trackers.deinit();
    var jails = [_]config_mod.JailConfig{
        .{ .name = "sshd", .enabled = true, .banaction = .@"log-only" },
    };
    var cfg = config_mod.Config{
        .global = .{},
        .defaults = .{},
        .jails = &jails,
        .diag = .{},
    };
    var backend = firewall.Backend{ .nftables = firewall.nftables.NftablesBackend{} };
    var ctx = commands.Context{
        .trackers = &trackers,
        .config = &cfg,
        .backend = &backend,
        .start_time = std.time.timestamp(),
    };

    var server = try ipc.IpcServer.init(a, &loop, socket_path);
    defer server.deinit();
    server.setAllowAnyPeer(true);
    server.setCommandHandler(ctx.asHandler());
    try server.start();

    var driver = Driver{ .loop = &loop, .start_ms = std.time.milliTimestamp() };
    _ = try loop.addTimer(check_interval_ms, Driver.onCheck, &driver, false);

    const samples = try a.alloc(u64, iterations);
    defer a.free(samples);
    var client = Client{ .socket_path = socket_path, .samples = samples, .driver = &driver };
    const thread = try std.Thread.spawn(.{}, Client.run, .{&client});

    try loop.run();
    thread.join();

    const elapsed_ms = std.time.milliTimestamp() - driver.start_ms;
    const polls_consumed = counter.lines / 3;

    try testing.expectEqual(@as(u32, 0), client.failures);
    try testing.expectEqual(iterations, client.completed);
    try testing.expect(polls_consumed >= 2);

    const got = samples[0..client.completed];
    std.sort.pdq(u64, got, {}, std.sort.asc(u64));
    const p50 = got[got.len / 2];
    const p99 = got[(got.len * 99) / 100];
    const max = got[got.len - 1];
    var sum: u64 = 0;
    for (got) |x| sum += x;
    const mean = sum / got.len;

    const stdout = std.io.getStdOut().writer();
    stdout.print(
        \\{{"bench":"loop_latency","iterations":{d},"p50_ns":{d},"p99_ns":{d},"max_ns":{d},"mean_ns":{d},"polls_consumed":{d},"elapsed_ms":{d},"target_ns":{d}}}
        \\
    ,
        .{ got.len, p50, p99, max, mean, polls_consumed, elapsed_ms, target_ns },
    ) catch {};

    if (p99 > target_ns) {
        std.log.err("loop-latency regression: p99={d}ns > target {d}ns (max={d}ns)", .{ p99, target_ns, max });
        return error.TestBelowTarget;
    }
}

fn benchmarkEnabled() bool {
    const val = std.process.getEnvVarOwned(std.heap.page_allocator, "FAIL2ZIG_RUN_BENCH") catch return false;
    defer std.heap.page_allocator.free(val);
    return std.mem.eql(u8, val, "1") or std.mem.eql(u8, val, "true");
}
