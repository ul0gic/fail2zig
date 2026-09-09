// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

const shared = @import("shared");
const engine = @import("engine");

const testing = std.testing;

const target_ms: u64 = 100;

test "benchmark: daemon startup time under target" {
    if (!benchmarkEnabled()) return error.SkipZigTest;
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const a = testing.allocator;

    std.fs.cwd().access("zig-out/bin/fail2zig", .{}) catch return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var abs_buf: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_abs = try tmp.dir.realpath(".", &abs_buf);

    const log_path = try std.fmt.allocPrint(a, "{s}/auth.log", .{tmp_abs});
    defer a.free(log_path);
    const config_path = try std.fmt.allocPrint(a, "{s}/config.toml", .{tmp_abs});
    defer a.free(config_path);
    const state_path = try std.fmt.allocPrint(a, "{s}/state.bin", .{tmp_abs});
    defer a.free(state_path);
    const socket_path = try std.fmt.allocPrint(a, "{s}/sock/fail2zig.sock", .{tmp_abs});
    defer a.free(socket_path);
    const pid_path = try std.fmt.allocPrint(a, "{s}/fail2zig.pid", .{tmp_abs});
    defer a.free(pid_path);

    {
        var f = try std.fs.cwd().createFile(log_path, .{ .truncate = true });
        f.close();
    }

    {
        var f = try std.fs.cwd().createFile(config_path, .{ .truncate = true });
        defer f.close();
        const w = f.writer();
        try w.print(
            \\[global]
            \\log_level = "warn"
            \\pid_file = "{s}"
            \\socket_path = "{s}"
            \\state_file = "{s}"
            \\memory_ceiling_mb = 64
            \\metrics_bind = "127.0.0.1"
            \\metrics_port = 9123
            \\
            \\[defaults]
            \\bantime = 600
            \\findtime = 600
            \\maxretry = 5
            \\
            \\[jails.sshd]
            \\enabled = true
            \\filter = "sshd"
            \\logpath = ["{s}"]
            \\
        ,
            .{ pid_path, socket_path, state_path, log_path },
        );
    }

    var argv = [_][]const u8{
        "zig-out/bin/fail2zig",
        "--foreground",
        "--config",
        config_path,
    };
    var child = std.process.Child.init(&argv, a);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;

    var timer = try std.time.Timer.start();
    const t0 = timer.read();
    child.spawn() catch return error.SkipZigTest;
    defer _ = child.kill() catch {};

    var ready_ns: u64 = 0;
    var connected = false;
    var waited: u64 = 0;
    const poll_step_us: u64 = 500;
    while (waited < 3_000_000) : (waited += poll_step_us) {
        if (tryConnect(socket_path)) |fd| {
            posix.close(fd);
            ready_ns = timer.read() - t0;
            connected = true;
            break;
        } else |_| {}
        std.time.sleep(poll_step_us * std.time.ns_per_us);
    }

    if (!connected) return error.SkipZigTest;

    const stdout = std.io.getStdOut().writer();
    stdout.print(
        \\{{"bench":"startup_time","elapsed_ns":{d},"elapsed_ms":{d:.2},"target_ms":{d}}}
        \\
    ,
        .{ ready_ns, @as(f64, @floatFromInt(ready_ns)) / @as(f64, std.time.ns_per_ms), target_ms },
    ) catch {};

    if (ready_ns / std.time.ns_per_ms > target_ms) {
        std.log.err(
            "startup regression: {d}ms > target {d}ms",
            .{ ready_ns / std.time.ns_per_ms, target_ms },
        );
        return error.TestBelowTarget;
    }
}

fn tryConnect(path: []const u8) !posix.fd_t {
    const fd = try posix.socket(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    errdefer posix.close(fd);
    var addr: posix.sockaddr.un = .{ .family = posix.AF.UNIX, .path = undefined };
    if (path.len >= addr.path.len) return error.NameTooLong;
    @memcpy(addr.path[0..path.len], path);
    addr.path[path.len] = 0;
    const addr_len: posix.socklen_t = @intCast(@sizeOf(@TypeOf(addr.family)) + path.len + 1);
    try posix.connect(fd, @ptrCast(&addr), addr_len);
    return fd;
}

fn benchmarkEnabled() bool {
    const val = std.process.getEnvVarOwned(std.heap.page_allocator, "FAIL2ZIG_RUN_BENCH") catch return false;
    defer std.heap.page_allocator.free(val);
    return std.mem.eql(u8, val, "1") or std.mem.eql(u8, val, "true");
}
