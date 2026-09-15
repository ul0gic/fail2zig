// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Component root: readiness derivation, systemd notification and the bounded log sink.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;
const testing = std.testing;

const readiness = @import("core/readiness.zig");
const sd_notify = @import("core/sd_notify.zig");
const log_target = @import("core/log_target.zig");
const storage_health = @import("core/storage_health.zig");

extern "c" fn mkfifo(path: [*:0]const u8, mode: c_uint) c_int;

// ---------------------------------------------------------------------------
// Readiness
// ---------------------------------------------------------------------------

const healthy_worker: storage_health.WorkerStatus = .{
    .busy = false,
    .stalled = false,
    .clock_uncertain = false,
    .expiry_overdue = false,
    .expiry_uncertain = false,
    .busy_age_ms = 0,
    .heartbeat_age_ms = 0,
    .next_committed_expiry_us = null,
};

const enforcing_jail: readiness.Jail = .{ .healthy = true, .source_error = false, .enforce = true };
const log_only_jail: readiness.Jail = .{ .healthy = true, .source_error = false, .enforce = false };

fn allGood() readiness.Inputs {
    return .{
        .config_loaded = true,
        .storage_phase = .healthy,
        .worker = healthy_worker,
        .jails = &.{enforcing_jail},
        .effects = .{ .ready = true, .uncertain = false, .overdue = false },
        .admin_generation_admitted = true,
    };
}

fn expectComponent(report: readiness.Report, c: readiness.Component, s: readiness.State) !void {
    try testing.expectEqual(s, report.state(c));
}

test "native readiness: every component ok yields ready with null cause" {
    const r = readiness.derive(allGood());
    try testing.expect(r.ready);
    try testing.expectEqual(@as(?[]const u8, null), r.cause);
    for (r.components) |s| try testing.expectEqual(readiness.State.ok, s);
}

test "native readiness: config not loaded fails config and names the cause" {
    var in = allGood();
    in.config_loaded = false;
    const r = readiness.derive(in);
    try testing.expect(!r.ready);
    try expectComponent(r, .config, .failed);
    try testing.expectEqualStrings("configuration not admitted", r.cause.?);
}

test "native readiness: storage phases map to unknown, ok, degraded and failed" {
    var in = allGood();
    in.storage_phase = null;
    try expectComponent(readiness.derive(in), .storage, .unknown);
    in.storage_phase = .starting;
    try expectComponent(readiness.derive(in), .storage, .unknown);
    in.storage_phase = .healthy;
    try expectComponent(readiness.derive(in), .storage, .ok);
    in.storage_phase = .paused;
    try expectComponent(readiness.derive(in), .storage, .degraded);
    in.storage_phase = .recovering;
    try expectComponent(readiness.derive(in), .storage, .degraded);
    in.storage_phase = .intervention;
    const r = readiness.derive(in);
    try expectComponent(r, .storage, .failed);
    try testing.expect(!r.ready);
    try testing.expectEqualStrings("storage requires intervention", r.cause.?);
}

test "native readiness: stalled worker degrades storage while healthy" {
    var in = allGood();
    var w = healthy_worker;
    w.stalled = true;
    in.worker = w;
    const r = readiness.derive(in);
    try expectComponent(r, .storage, .degraded);
    try expectComponent(r, .clock, .ok);
    try testing.expect(!r.ready);
}

test "native readiness: sources unknown without jails, degraded while waiting, failed on continuity loss" {
    var in = allGood();
    in.jails = &.{};
    try expectComponent(readiness.derive(in), .sources, .unknown);
    in.jails = &.{ enforcing_jail, .{ .healthy = false, .source_error = false, .enforce = true } };
    try expectComponent(readiness.derive(in), .sources, .degraded);
    in.jails = &.{ enforcing_jail, .{ .healthy = false, .source_error = true, .enforce = true } };
    const r = readiness.derive(in);
    try expectComponent(r, .sources, .failed);
    try testing.expectEqualStrings("source continuity lost", r.cause.?);
}

test "native readiness: clock unknown without worker and failed when uncertain" {
    var in = allGood();
    in.worker = null;
    var r = readiness.derive(in);
    try expectComponent(r, .clock, .unknown);
    try expectComponent(r, .storage, .ok);
    try testing.expect(!r.ready);
    var w = healthy_worker;
    w.clock_uncertain = true;
    in.worker = w;
    r = readiness.derive(in);
    try expectComponent(r, .clock, .failed);
    try testing.expectEqualStrings("clock uncertain", r.cause.?);
}

test "native readiness: enforcement is not applicable for log-only jails" {
    var in = allGood();
    in.jails = &.{log_only_jail};
    in.effects = null;
    const r = readiness.derive(in);
    try expectComponent(r, .enforcement, .ok);
    try testing.expect(r.ready);
    in.effects = .{ .ready = false, .uncertain = true, .overdue = true };
    try testing.expect(readiness.derive(in).ready);
}

test "native readiness: enforcement unknown, failed, degraded for enforcing jails" {
    var in = allGood();
    in.effects = null;
    try expectComponent(readiness.derive(in), .enforcement, .unknown);
    in.effects = .{ .ready = false, .uncertain = false, .overdue = false };
    var r = readiness.derive(in);
    try expectComponent(r, .enforcement, .failed);
    try testing.expectEqualStrings("enforcement backend unavailable", r.cause.?);
    in.effects = .{ .ready = true, .uncertain = true, .overdue = false };
    try expectComponent(readiness.derive(in), .enforcement, .degraded);
    in.effects = .{ .ready = true, .uncertain = false, .overdue = true };
    r = readiness.derive(in);
    try expectComponent(r, .enforcement, .degraded);
    try testing.expectEqualStrings("enforcement expiries overdue", r.cause.?);
}

test "native readiness: admin failed without admitted generation, degraded when not serving" {
    var in = allGood();
    in.admin_generation_admitted = false;
    try expectComponent(readiness.derive(in), .admin, .failed);
    in.admin_generation_admitted = true;
    in.admin_serving = false;
    const r = readiness.derive(in);
    try expectComponent(r, .admin, .degraded);
    try testing.expect(!r.ready);
    try testing.expectEqualStrings("administrative socket refusing new connections", r.cause.?);
}

test "native readiness: cause names the first non-ok component in declared order" {
    var in = allGood();
    in.storage_phase = .paused;
    in.admin_serving = false;
    try testing.expectEqualStrings("storage paused", readiness.derive(in).cause.?);
    in.config_loaded = false;
    try testing.expectEqualStrings("configuration not admitted", readiness.derive(in).cause.?);
}

test "native readiness: json shape for ready and for a failed component" {
    var buf: [512]u8 = undefined;
    var s = std.io.fixedBufferStream(&buf);
    try readiness.writeJson(readiness.derive(allGood()), s.writer());
    try testing.expectEqualStrings(
        "{\"schema_version\":1,\"ready\":true,\"components\":{\"config\":\"ok\",\"storage\":\"ok\",\"sources\":\"ok\",\"clock\":\"ok\",\"enforcement\":\"ok\",\"admin\":\"ok\"},\"cause\":null}",
        s.getWritten(),
    );

    var in = allGood();
    in.storage_phase = .intervention;
    in.effects = null;
    s.reset();
    try readiness.writeJson(readiness.derive(in), s.writer());
    try testing.expectEqualStrings(
        "{\"schema_version\":1,\"ready\":false,\"components\":{\"config\":\"ok\",\"storage\":\"failed\",\"sources\":\"ok\",\"clock\":\"ok\",\"enforcement\":\"unknown\",\"admin\":\"ok\"},\"cause\":\"storage requires intervention\"}",
        s.getWritten(),
    );

    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, s.getWritten(), .{});
    defer parsed.deinit();
    try testing.expect(parsed.value.object.get("ready").?.bool == false);
}

// ---------------------------------------------------------------------------
// sd_notify
// ---------------------------------------------------------------------------

const TmpPath = struct {
    tmp: testing.TmpDir,
    abs: []u8,

    fn init(a: std.mem.Allocator) !TmpPath {
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const abs = try a.dupe(u8, try tmp.dir.realpath(".", &buf));
        return .{ .tmp = tmp, .abs = abs };
    }

    fn join(self: *TmpPath, a: std.mem.Allocator, name: []const u8) ![]u8 {
        return std.fmt.allocPrint(a, "{s}/{s}", .{ self.abs, name });
    }

    fn deinit(self: *TmpPath, a: std.mem.Allocator) void {
        a.free(self.abs);
        self.tmp.cleanup();
    }
};

const Receiver = struct {
    fd: posix.fd_t,

    fn bindPath(path: []const u8) !Receiver {
        if (path.len >= 108) return error.SkipZigTest;
        const fd = try posix.socket(posix.AF.UNIX, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK, 0);
        errdefer posix.close(fd);
        var addr: linux.sockaddr.un = .{ .path = [_]u8{0} ** 108 };
        @memcpy(addr.path[0..path.len], path);
        const abstract = path[0] == '@';
        if (abstract) addr.path[0] = 0;
        const len: posix.socklen_t = @intCast(@offsetOf(linux.sockaddr.un, "path") + path.len + @as(usize, if (abstract) 0 else 1));
        try posix.bind(fd, @ptrCast(&addr), len);
        return .{ .fd = fd };
    }

    fn recv(self: Receiver, buf: []u8) ![]const u8 {
        var tries: u32 = 0;
        while (tries < 100) : (tries += 1) {
            const n = posix.recvfrom(self.fd, buf, 0, null, null) catch |err| switch (err) {
                error.WouldBlock => {
                    std.time.sleep(2 * std.time.ns_per_ms);
                    continue;
                },
                else => return err,
            };
            return buf[0..n];
        }
        return error.Timeout;
    }

    fn expectNothing(self: Receiver) !void {
        var buf: [16]u8 = undefined;
        const n = posix.recvfrom(self.fd, &buf, 0, null, null) catch |err| switch (err) {
            error.WouldBlock => return,
            else => return err,
        };
        _ = n;
        return error.UnexpectedDatagram;
    }

    fn deinit(self: Receiver) void {
        posix.close(self.fd);
    }
};

test "native readiness: sd_notify sends READY, RELOADING, STOPPING and STATUS to a path socket" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var dir = try TmpPath.init(a);
    defer dir.deinit(a);
    const path = try dir.join(a, "notify");
    defer a.free(path);
    const rx = try Receiver.bindPath(path);
    defer rx.deinit();

    var n = try sd_notify.Notifier.initWithPath(path);
    defer n.deinit();
    try testing.expect(n.enabled());

    var buf: [600]u8 = undefined;
    try testing.expectEqual(sd_notify.Result.sent, try n.ready());
    try testing.expectEqualStrings("READY=1\n", try rx.recv(&buf));
    try testing.expectEqual(sd_notify.Result.sent, try n.reloadingAt(1234567));
    try testing.expectEqualStrings("RELOADING=1\nMONOTONIC_USEC=1234567\n", try rx.recv(&buf));
    try testing.expectEqual(sd_notify.Result.sent, try n.reloading());
    const reload = try rx.recv(&buf);
    try testing.expect(std.mem.startsWith(u8, reload, "RELOADING=1\nMONOTONIC_USEC="));
    try testing.expect(std.mem.endsWith(u8, reload, "\n"));
    try testing.expectEqual(sd_notify.Result.sent, try n.stopping());
    try testing.expectEqualStrings("STOPPING=1\n", try rx.recv(&buf));
    try testing.expectEqual(sd_notify.Result.sent, try n.status("ready; 3 jails"));
    try testing.expectEqualStrings("STATUS=ready; 3 jails\n", try rx.recv(&buf));

    const flags = try posix.fcntl(n.fd, posix.F.GETFD, 0);
    try testing.expect((flags & posix.FD_CLOEXEC) != 0);
}

test "native readiness: sd_notify abstract namespace socket" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var name_buf: [64]u8 = undefined;
    const name = try std.fmt.bufPrint(&name_buf, "@fail2zig-notify-test-{d}", .{linux.getpid()});
    const rx = try Receiver.bindPath(name);
    defer rx.deinit();
    var n = try sd_notify.Notifier.initWithPath(name);
    defer n.deinit();
    var buf: [64]u8 = undefined;
    try testing.expectEqual(sd_notify.Result.sent, try n.ready());
    try testing.expectEqualStrings("READY=1\n", try rx.recv(&buf));
}

test "native readiness: sd_notify absent environment is a disabled no-op" {
    if (posix.getenv("NOTIFY_SOCKET") != null) return error.SkipZigTest;
    var n = try sd_notify.Notifier.fromEnvironment();
    defer n.deinit();
    try testing.expect(!n.enabled());
    try testing.expectEqual(sd_notify.Result.disabled, try n.ready());
    try testing.expectEqual(sd_notify.Result.disabled, try n.status("x"));
}

test "native readiness: sd_notify rejects oversized or multi-line status and empty or long paths" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var dir = try TmpPath.init(a);
    defer dir.deinit(a);
    const path = try dir.join(a, "notify");
    defer a.free(path);
    const rx = try Receiver.bindPath(path);
    defer rx.deinit();
    var n = try sd_notify.Notifier.initWithPath(path);
    defer n.deinit();

    const too_long = [_]u8{'s'} ** (sd_notify.max_status_bytes + 1);
    try testing.expectError(error.MessageTooLong, n.status(&too_long));
    const exact = [_]u8{'s'} ** sd_notify.max_status_bytes;
    try testing.expectEqual(sd_notify.Result.sent, try n.status(&exact));
    try testing.expectError(error.MessageTooLong, n.status("a\nREADY=1"));
    const huge = [_]u8{'m'} ** (sd_notify.max_message_bytes + 1);
    try testing.expectError(error.MessageTooLong, n.send(&huge));
    var buf: [600]u8 = undefined;
    _ = try rx.recv(&buf);
    try rx.expectNothing();

    try testing.expectError(error.PathTooLong, sd_notify.Notifier.initWithPath(""));
    const long_path = [_]u8{'p'} ** 108;
    try testing.expectError(error.PathTooLong, sd_notify.Notifier.initWithPath(&long_path));
}

test "native readiness: sd_notify unreachable socket returns SendFailed and stays usable" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var dir = try TmpPath.init(a);
    defer dir.deinit(a);
    const path = try dir.join(a, "nobody-listens");
    defer a.free(path);
    var n = try sd_notify.Notifier.initWithPath(path);
    defer n.deinit();
    try testing.expectError(error.SendFailed, n.ready());
    try testing.expectError(error.SendFailed, n.stopping());

    const rx = try Receiver.bindPath(path);
    defer rx.deinit();
    var buf: [64]u8 = undefined;
    try testing.expectEqual(sd_notify.Result.sent, try n.ready());
    try testing.expectEqualStrings("READY=1\n", try rx.recv(&buf));
}

// ---------------------------------------------------------------------------
// Log target
// ---------------------------------------------------------------------------

fn readFile(a: std.mem.Allocator, path: []const u8) ![]u8 {
    const f = try std.fs.cwd().openFile(path, .{});
    defer f.close();
    return f.readToEndAlloc(a, 1 << 24);
}

test "native readiness: log file append, mode 0640 and reopen after rename" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var dir = try TmpPath.init(a);
    defer dir.deinit(a);
    const path = try dir.join(a, "daemon.log");
    defer a.free(path);
    const rotated = try dir.join(a, "daemon.log.1");
    defer a.free(rotated);

    var sink = try log_target.Sink.init(a, .{ .file = path });
    defer sink.deinit();
    const st = try posix.fstat(sink.fd);
    try testing.expectEqual(@as(u32, 0o640), st.mode & 0o777);
    const fl = try posix.fcntl(sink.fd, posix.F.GETFL, 0);
    const o_append: usize = 0o2000;
    const o_nonblock: usize = 0o4000;
    try testing.expect((fl & o_append) != 0);
    try testing.expect((fl & o_nonblock) != 0);

    try testing.expectEqual(log_target.PushResult.queued, sink.push("first\n"));
    sink.drain();
    try std.fs.cwd().rename(path, rotated);
    try testing.expectEqual(log_target.PushResult.queued, sink.push("still-old\n"));
    sink.drain();
    try sink.reopen();
    try testing.expectEqual(log_target.PushResult.queued, sink.push("fresh\n"));
    sink.drain();

    const old = try readFile(a, rotated);
    defer a.free(old);
    try testing.expectEqualStrings("first\nstill-old\n", old);
    const new = try readFile(a, path);
    defer a.free(new);
    try testing.expectEqualStrings("fresh\n", new);
    try testing.expect(!sink.stats().degraded);
    try testing.expectEqual(@as(u64, 0), sink.stats().failed_total);
}

test "native readiness: log target refuses symlink, FIFO, device, relative path and missing parent" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var dir = try TmpPath.init(a);
    defer dir.deinit(a);

    const target = try dir.join(a, "real.log");
    defer a.free(target);
    const link = try dir.join(a, "link.log");
    defer a.free(link);
    try std.fs.cwd().symLink(target, link, .{});
    try testing.expectError(error.SymlinkRefused, log_target.Sink.init(a, .{ .file = link }));
    try testing.expectError(error.FileNotFound, std.fs.cwd().access(target, .{}));

    const fifo = try dir.join(a, "pipe.log");
    defer a.free(fifo);
    const fifo_z = try a.dupeZ(u8, fifo);
    defer a.free(fifo_z);
    try testing.expectEqual(@as(c_int, 0), mkfifo(fifo_z.ptr, 0o600));
    try testing.expectError(error.NotRegularFile, log_target.Sink.init(a, .{ .file = fifo }));

    try testing.expectError(error.NotRegularFile, log_target.Sink.init(a, .{ .file = "/dev/null" }));
    try testing.expectError(error.PathNotAbsolute, log_target.Sink.init(a, .{ .file = "relative.log" }));
    const missing = try dir.join(a, "absent/daemon.log");
    defer a.free(missing);
    try testing.expectError(error.ParentMissing, log_target.Sink.init(a, .{ .file = missing }));
}

test "native readiness: failed reopen keeps the previous descriptor" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var dir = try TmpPath.init(a);
    defer dir.deinit(a);
    const path = try dir.join(a, "daemon.log");
    defer a.free(path);
    var sink = try log_target.Sink.init(a, .{ .file = path });
    defer sink.deinit();
    const before = sink.fd;
    try std.fs.cwd().deleteFile(path);
    try std.fs.cwd().symLink("/nonexistent", path, .{});
    try testing.expectError(error.SymlinkRefused, sink.reopen());
    try testing.expectEqual(before, sink.fd);
    _ = sink.push("survives\n");
    sink.drain();
    try testing.expect(!sink.stats().degraded);
}

test "native readiness: ring overflow drops beyond capacity and drain preserves order" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var dir = try TmpPath.init(a);
    defer dir.deinit(a);
    const path = try dir.join(a, "daemon.log");
    defer a.free(path);
    var sink = try log_target.Sink.init(a, .{ .file = path });
    defer sink.deinit();

    var expected = std.ArrayList(u8).init(a);
    defer expected.deinit();
    var i: usize = 0;
    var queued: usize = 0;
    while (i < 300) : (i += 1) {
        var line: [32]u8 = undefined;
        const text = try std.fmt.bufPrint(&line, "line {d}\n", .{i});
        if (sink.push(text) == .queued) {
            queued += 1;
            try expected.appendSlice(text);
        }
    }
    try testing.expectEqual(@as(usize, 256), queued);
    var s = sink.stats();
    try testing.expectEqual(@as(usize, 256), s.queued);
    try testing.expectEqual(@as(u64, 44), s.dropped_total);

    sink.drain();
    s = sink.stats();
    try testing.expectEqual(@as(usize, 0), s.queued);
    const written = try readFile(a, path);
    defer a.free(written);
    try testing.expectEqualStrings(expected.items, written);

    // Slots are reusable after drain; the ring wraps without corrupting order.
    _ = sink.push("after\n");
    sink.drain();
    const again = try readFile(a, path);
    defer a.free(again);
    try testing.expect(std.mem.endsWith(u8, again, "line 255\nafter\n"));
}

test "native readiness: lines longer than a slot are truncated with a marker" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var dir = try TmpPath.init(a);
    defer dir.deinit(a);
    const path = try dir.join(a, "daemon.log");
    defer a.free(path);
    var sink = try log_target.Sink.init(a, .{ .file = path });
    defer sink.deinit();
    const long = [_]u8{'L'} ** (log_target.max_line_bytes + 100);
    try testing.expectEqual(log_target.PushResult.queued, sink.push(&long));
    sink.drain();
    const out = try readFile(a, path);
    defer a.free(out);
    try testing.expectEqual(log_target.max_line_bytes, out.len);
    try testing.expect(std.mem.endsWith(u8, out, log_target.truncation_marker));
}

test "native readiness: ENOSPC destination marks degraded and a later success clears it" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var dir = try TmpPath.init(a);
    defer dir.deinit(a);
    const path = try dir.join(a, "daemon.log");
    defer a.free(path);
    var sink = try log_target.Sink.init(a, .{ .file = path });
    defer sink.deinit();

    const full = posix.openat(posix.AT.FDCWD, "/dev/full", .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0) catch return error.SkipZigTest;
    const good = sink.fd;
    sink.fd = full;
    _ = sink.push("one\n");
    _ = sink.push("two\n");
    sink.drain();
    var s = sink.stats();
    try testing.expectEqual(@as(u64, 2), s.failed_total);
    try testing.expect(s.degraded);
    try testing.expectEqual(@as(usize, 0), s.queued);

    sink.fd = good;
    posix.close(full);
    _ = sink.push("three\n");
    sink.drain();
    s = sink.stats();
    try testing.expect(!s.degraded);
    try testing.expectEqual(@as(u64, 2), s.failed_total);
    const out = try readFile(a, path);
    defer a.free(out);
    try testing.expectEqualStrings("three\n", out);
}

test "native readiness: EAGAIN on a full non-blocking pipe counts as failed without blocking" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var sink = try log_target.Sink.init(a, .stderr);
    defer sink.deinit();

    const fds = try posix.pipe2(.{ .NONBLOCK = true, .CLOEXEC = true });
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);
    var filler: [4096]u8 = undefined;
    @memset(&filler, 'f');
    while (true) {
        _ = posix.write(fds[1], &filler) catch |err| switch (err) {
            error.WouldBlock => break,
            else => return err,
        };
    }
    sink.fd = fds[1];
    sink.owns_fd = false;
    _ = sink.push("blocked\n");
    sink.drain();
    const s = sink.stats();
    try testing.expectEqual(@as(u64, 1), s.failed_total);
    try testing.expect(s.degraded);
}

test "native readiness: std.log sink formats level, scope and truncates oversized messages" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = testing.allocator;
    var dir = try TmpPath.init(a);
    defer dir.deinit(a);
    const path = try dir.join(a, "daemon.log");
    defer a.free(path);
    var sink = try log_target.Sink.init(a, .{ .file = path });
    defer sink.deinit();

    log_target.install(&sink);
    defer log_target.install(null);
    log_target.logFn(.warn, .default, "ipc: peer uid={d}", .{@as(u32, 7)});
    log_target.logFn(.info, .storage, "committed {d}", .{@as(u32, 3)});
    const big = [_]u8{'b'} ** (log_target.max_line_bytes * 2);
    log_target.logFn(.err, .default, "{s}", .{&big});
    try testing.expectEqual(@as(usize, 3), sink.stats().queued);
    sink.drain();

    const out = try readFile(a, path);
    defer a.free(out);
    try testing.expect(std.mem.startsWith(u8, out, "warning: ipc: peer uid=7\ninfo(storage): committed 3\nerror: bbbb"));
    try testing.expect(std.mem.endsWith(u8, out, log_target.truncation_marker));
    try testing.expectEqual(@as(usize, "warning: ipc: peer uid=7\ninfo(storage): committed 3\n".len + log_target.max_line_bytes), out.len);
}
