// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

const std = @import("std");

// Fixed seconds, matching the compatibility importer; months and years are not calendar intervals.
pub fn parse(text: []const u8) error{InvalidValue}!u64 {
    var pos: usize = 0;
    var total: u64 = 0;
    var has_term = false;
    while (true) {
        while (pos < text.len and std.ascii.isWhitespace(text[pos])) : (pos += 1) {}
        if (pos == text.len) break;
        const number_start = pos;
        while (pos < text.len and std.ascii.isDigit(text[pos])) : (pos += 1) {}
        if (number_start == pos) return error.InvalidValue;
        const number = std.fmt.parseInt(u64, text[number_start..pos], 10) catch return error.InvalidValue;
        const unit_start = pos;
        while (pos < text.len and std.ascii.isAlphabetic(text[pos])) : (pos += 1) {}
        const unit = text[unit_start..pos];
        const scale: u64 = if (std.mem.eql(u8, unit, "s")) 1 else if (std.mem.eql(u8, unit, "m") or std.mem.eql(u8, unit, "mm") or std.mem.eql(u8, unit, "min")) 60 else if (std.mem.eql(u8, unit, "h")) 3600 else if (std.mem.eql(u8, unit, "d")) 86_400 else if (std.mem.eql(u8, unit, "w")) 604_800 else if (std.mem.eql(u8, unit, "mo")) 2_629_800 else if (std.mem.eql(u8, unit, "y")) 31_557_600 else return error.InvalidValue;
        const seconds = std.math.mul(u64, number, scale) catch return error.InvalidValue;
        total = std.math.add(u64, total, seconds) catch return error.InvalidValue;
        has_term = true;
    }
    if (!has_term) return error.InvalidValue;
    return total;
}
