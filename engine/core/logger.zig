// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

pub const Level = enum(u2) {
    debug = 0,
    info = 1,
    warn = 2,
    err = 3,

    pub fn tag(self: Level) []const u8 {
        return switch (self) {
            .debug => "debug",
            .info => "info",
            .warn => "warn",
            .err => "err",
        };
    }
};

pub const Field = struct {
    key: []const u8,
    value: Value,

    pub const Value = union(enum) {
        string: []const u8,
        int: i64,
        uint: u64,
        boolean: bool,
        float: f64,
    };

    pub fn str(key: []const u8, value: []const u8) Field {
        return .{ .key = key, .value = .{ .string = value } };
    }
    pub fn int(key: []const u8, value: i64) Field {
        return .{ .key = key, .value = .{ .int = value } };
    }
    pub fn uint(key: []const u8, value: u64) Field {
        return .{ .key = key, .value = .{ .uint = value } };
    }
    pub fn boolean(key: []const u8, value: bool) Field {
        return .{ .key = key, .value = .{ .boolean = value } };
    }
    pub fn float(key: []const u8, value: f64) Field {
        return .{ .key = key, .value = .{ .float = value } };
    }
};

pub const max_line_bytes: usize = 4096;
