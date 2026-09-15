// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! systemd readiness protocol over an AF_UNIX datagram to `$NOTIFY_SOCKET`, without
//! libsystemd. Absent environment disables the notifier; send failures are reported,
//! never fatal, because service-manager visibility must not stop protection.

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

pub const max_message_bytes: usize = 512;
pub const max_status_bytes: usize = 256;

pub const Result = enum { sent, disabled };

pub const Error = error{
    MessageTooLong,
    SendFailed,
};

pub const InitError = error{
    PathTooLong,
    SocketCreateFailed,
};

const sun_path_len: usize = 108;

pub const Notifier = struct {
    fd: posix.fd_t = -1,
    addr: linux.sockaddr.un = .{ .path = [_]u8{0} ** sun_path_len },
    addr_len: posix.socklen_t = 0,

    pub fn fromEnvironment() InitError!Notifier {
        const path = posix.getenv("NOTIFY_SOCKET") orelse return .{};
        if (path.len == 0) return .{};
        return initWithPath(path);
    }

    /// A leading `@` selects the abstract namespace, as systemd does.
    pub fn initWithPath(path: []const u8) InitError!Notifier {
        if (path.len == 0 or path.len >= sun_path_len) return error.PathTooLong;
        var self: Notifier = .{};
        @memcpy(self.addr.path[0..path.len], path);
        if (path[0] == '@') self.addr.path[0] = 0;
        self.addr_len = @intCast(@offsetOf(linux.sockaddr.un, "path") + path.len + @as(usize, if (path[0] == '@') 0 else 1));
        const stype: u32 = posix.SOCK.DGRAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK;
        self.fd = posix.socket(posix.AF.UNIX, stype, 0) catch return error.SocketCreateFailed;
        return self;
    }

    pub fn enabled(self: *const Notifier) bool {
        return self.fd != -1;
    }

    pub fn deinit(self: *Notifier) void {
        if (self.fd != -1) posix.close(self.fd);
        self.* = .{};
    }

    pub fn ready(self: *const Notifier) Error!Result {
        return self.send("READY=1\n");
    }

    pub fn stopping(self: *const Notifier) Error!Result {
        return self.send("STOPPING=1\n");
    }

    pub fn reloading(self: *const Notifier) Error!Result {
        return self.reloadingAt(monotonicUsec());
    }

    /// systemd rejects RELOADING without the monotonic timestamp of the reload start.
    pub fn reloadingAt(self: *const Notifier, monotonic_usec: u64) Error!Result {
        var buf: [64]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "RELOADING=1\nMONOTONIC_USEC={d}\n", .{monotonic_usec}) catch return error.MessageTooLong;
        return self.send(msg);
    }

    /// Newlines terminate a field, so a status containing one is rejected rather than
    /// letting the remainder be parsed as further assignments.
    pub fn status(self: *const Notifier, text: []const u8) Error!Result {
        if (text.len > max_status_bytes) return error.MessageTooLong;
        if (std.mem.indexOfScalar(u8, text, '\n') != null) return error.MessageTooLong;
        var buf: [max_message_bytes]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "STATUS={s}\n", .{text}) catch return error.MessageTooLong;
        return self.send(msg);
    }

    pub fn send(self: *const Notifier, message: []const u8) Error!Result {
        if (self.fd == -1) return .disabled;
        if (message.len > max_message_bytes) return error.MessageTooLong;
        const rc = linux.sendto(self.fd, message.ptr, message.len, linux.MSG.NOSIGNAL, @ptrCast(&self.addr), self.addr_len);
        switch (linux.E.init(rc)) {
            .SUCCESS => {
                if (rc != message.len) return error.SendFailed;
                return .sent;
            },
            else => return error.SendFailed,
        }
    }
};

fn monotonicUsec() u64 {
    const ts = posix.clock_gettime(.MONOTONIC) catch return 0;
    const sec: u64 = @intCast(ts.sec);
    const nsec: u64 = @intCast(ts.nsec);
    return sec * std.time.us_per_s + nsec / std.time.ns_per_us;
}
