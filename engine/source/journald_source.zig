// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");

const config_mod = @import("../config/config.zig");

pub const Error = error{
    NotLinux,
    OutOfMemory,
    EventLoopError,
    TooManyJails,
    PathTooLong,
    UnsupportedJournaldFilter,
};

pub const max_jails: usize = 64;

pub const max_output_bytes: usize = 16 * 1024 * 1024;

pub const default_child_timeout_ms: u64 = 60_000;

pub const default_baseline_timeout_ms: u64 = 5_000;

const cursor_file_basename = "journald-cursors.bin";

pub const SidecarError = error{
    OutOfMemory,
    WriteFailed,
    ReadFailed,
    OpenFailed,
    FsyncFailed,
    RenameFailed,
    ChmodFailed,
    PathTooLong,
};

pub fn cursorPath(state_file: []const u8, buf: []u8) SidecarError![]const u8 {
    const dir = std.fs.path.dirname(state_file) orelse ".";
    const need = dir.len + 1 + cursor_file_basename.len;
    if (need > buf.len) return error.PathTooLong;
    @memcpy(buf[0..dir.len], dir);
    buf[dir.len] = '/';
    @memcpy(buf[dir.len + 1 ..][0..cursor_file_basename.len], cursor_file_basename);
    return buf[0..need];
}

pub const Options = struct {
    journalctl_path: []const u8 = config_mod.journalctl_path,
    child_timeout_ms: u64 = default_child_timeout_ms,
    baseline_timeout_ms: u64 = default_baseline_timeout_ms,
};
