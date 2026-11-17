// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Provides the colour, terminal width, table cell, escaping, number and time text, query and plain-line helpers formatters share.
// Holds: Text passed through renderDiagnostic or writeEscaped carries no C0, DEL, C1 or bidirectional control codepoint to the terminal.

const std = @import("std");
const args = @import("../args.zig");

pub const OutputFormat = args.OutputFormat;

pub const Color = struct {
    enabled: bool,

    const reset = "\x1b[0m";
    pub const bold = "\x1b[1m";
    pub const red = "\x1b[31m";
    pub const green = "\x1b[32m";
    pub const yellow = "\x1b[33m";
    pub const cyan = "\x1b[36m";

    pub fn on(self: Color, writer: anytype, code: []const u8) !void {
        if (self.enabled) try writer.writeAll(code);
    }

    pub fn off(self: Color, writer: anytype) !void {
        if (self.enabled) try writer.writeAll(reset);
    }
};

pub fn shouldColor(allow_color: bool) bool {
    if (!allow_color) return false;
    const fd = std.io.getStdOut().handle;
    return std.posix.isatty(fd);
}

pub fn terminalColumns() usize {
    const fd = std.io.getStdOut().handle;
    if (!std.posix.isatty(fd)) return 80;
    var winsize: std.posix.winsize = .{ .row = 0, .col = 0, .xpixel = 0, .ypixel = 0 };
    const result = std.posix.system.ioctl(fd, std.posix.T.IOCGWINSZ, @intFromPtr(&winsize));
    if (std.posix.errno(result) != .SUCCESS or winsize.col == 0) return 80;
    return winsize.col;
}

pub fn writeStatusNarrowRow(writer: anytype, label: []const u8, value: []const u8, columns: usize) !void {
    try writer.writeAll(label);
    try writeCell(writer, value, @max(@as(usize, 4), columns -| label.len));
    try writer.writeAll("\n");
}

pub fn rowUsed(value: []const u8) usize {
    return 2 + label_col + value.len;
}

pub const label_col: usize = 13;

pub fn boolValue(value: bool) []const u8 {
    return if (value) "true" else "false";
}

pub const diagnostic_max_bytes: usize = 96;

const DiagnosticUnit = struct {
    input_len: usize,
    output_len: usize,
    kind: enum { raw, slash, newline, carriage_return, tab, hex },
};

fn diagnosticUnit(input: []const u8) DiagnosticUnit {
    const byte = input[0];
    if (byte == '\\') return .{ .input_len = 1, .output_len = 2, .kind = .slash };
    if (byte == '\n') return .{ .input_len = 1, .output_len = 2, .kind = .newline };
    if (byte == '\r') return .{ .input_len = 1, .output_len = 2, .kind = .carriage_return };
    if (byte == '\t') return .{ .input_len = 1, .output_len = 2, .kind = .tab };
    if (byte < 0x20 or byte == 0x7f) return .{ .input_len = 1, .output_len = 4, .kind = .hex };
    if (byte < 0x7f) return .{ .input_len = 1, .output_len = 1, .kind = .raw };
    const sequence_len: usize = std.unicode.utf8ByteSequenceLength(byte) catch return .{ .input_len = 1, .output_len = 4, .kind = .hex };
    if (sequence_len > input.len) return .{ .input_len = 1, .output_len = 4, .kind = .hex };
    const codepoint = std.unicode.utf8Decode(input[0..sequence_len]) catch return .{ .input_len = 1, .output_len = 4, .kind = .hex };
    if (isUnsafeUnicodeControl(codepoint)) return .{ .input_len = sequence_len, .output_len = sequence_len * 4, .kind = .hex };
    return .{ .input_len = sequence_len, .output_len = sequence_len, .kind = .raw };
}

// Why: C1 controls and the bidirectional marks, embeddings and isolates (Unicode UAX #9) can reorder or hide what the terminal shows.
fn isUnsafeUnicodeControl(codepoint: u21) bool {
    return (codepoint >= 0x80 and codepoint <= 0x9f) or
        codepoint == 0x061c or
        (codepoint >= 0x200e and codepoint <= 0x200f) or
        (codepoint >= 0x202a and codepoint <= 0x202e) or
        (codepoint >= 0x2066 and codepoint <= 0x2069);
}

fn emitUnit(out: []u8, input: []const u8, unit: DiagnosticUnit) void {
    switch (unit.kind) {
        .raw => @memcpy(out, input),
        .slash => @memcpy(out, "\\\\"),
        .newline => @memcpy(out, "\\n"),
        .carriage_return => @memcpy(out, "\\r"),
        .tab => @memcpy(out, "\\t"),
        .hex => {
            const hex = "0123456789ABCDEF";
            for (input, 0..) |hex_byte, index| {
                const offset = index * 4;
                out[offset] = '\\';
                out[offset + 1] = 'x';
                out[offset + 2] = hex[hex_byte >> 4];
                out[offset + 3] = hex[hex_byte & 0x0f];
            }
        },
    }
}

pub fn escapedLen(input: []const u8) usize {
    var index: usize = 0;
    var total: usize = 0;
    while (index < input.len) {
        const unit = diagnosticUnit(input[index..]);
        total += unit.output_len;
        index += unit.input_len;
    }
    return total;
}

pub fn writeEscaped(writer: anytype, input: []const u8) !void {
    var unit_buffer: [16]u8 = undefined;
    var index: usize = 0;
    while (index < input.len) {
        const unit = diagnosticUnit(input[index..]);
        emitUnit(unit_buffer[0..unit.output_len], input[index..][0..unit.input_len], unit);
        try writer.writeAll(unit_buffer[0..unit.output_len]);
        index += unit.input_len;
    }
}

// Holds: The result fits both the buffer and 96 bytes, never splits an escape, and marks a cut input with trailing dots.
pub fn renderDiagnostic(buffer: []u8, input: []const u8) []const u8 {
    const capacity = @min(buffer.len, diagnostic_max_bytes);
    if (capacity == 0) return buffer[0..0];
    var input_index: usize = 0;
    var escaped_len: usize = 0;
    while (input_index < input.len and escaped_len <= capacity) {
        const unit = diagnosticUnit(input[input_index..]);
        escaped_len +|= unit.output_len;
        input_index += unit.input_len;
    }
    const truncated = input_index < input.len or escaped_len > capacity;
    const suffix_len = if (truncated) @min(capacity, 3) else 0;
    const limit = capacity - suffix_len;
    input_index = 0;
    var output_index: usize = 0;
    while (input_index < input.len) {
        const unit = diagnosticUnit(input[input_index..]);
        if (unit.output_len > limit - output_index) break;
        emitUnit(buffer[output_index..][0..unit.output_len], input[input_index..][0..unit.input_len], unit);
        output_index += unit.output_len;
        input_index += unit.input_len;
    }
    if (truncated) {
        @memset(buffer[output_index..][0..suffix_len], '.');
        output_index += suffix_len;
    }
    return buffer[0..output_index];
}

pub fn rowLabel(writer: anytype, label: []const u8, value: []const u8, width: usize) !void {
    return rowLabelStyled(writer, .{ .enabled = false }, "", label, value, width, false);
}

pub fn rowLabelStyled(writer: anytype, color: Color, style: []const u8, label: []const u8, value: []const u8, width: usize, comptime escape: bool) !void {
    try writer.writeAll("| ");
    try writer.writeAll(label);
    if (label.len < label_col) {
        try writeSpaces(writer, label_col - label.len);
    }
    try color.on(writer, style);
    if (escape) try writeEscaped(writer, value) else try writer.writeAll(value);
    try color.off(writer);
    const value_len = if (escape) escapedLen(value) else value.len;
    const used = 1 + 1 + @max(label.len, label_col) + value_len;
    if (used < width - 1) {
        try writeSpaces(writer, width - 1 - used);
    }
    try writer.writeAll("|\n");
}

pub fn repeatChar(writer: anytype, ch: u8, n: usize) !void {
    var i: usize = 0;
    while (i < n) : (i += 1) try writer.writeByte(ch);
}

pub fn writeSpaces(writer: anytype, n: usize) !void {
    try repeatChar(writer, ' ', n);
}

// Holds: A result the formatters below return from scratch is overwritten by the next such call, so each is used before the next.
threadlocal var scratch: [64]u8 = undefined;

pub fn formatUptime(opt: ?u64) []const u8 {
    const secs = opt orelse return "-";
    const days = secs / 86_400;
    const hours = (secs % 86_400) / 3600;
    const mins = (secs % 3600) / 60;
    const s = secs % 60;
    const r = std.fmt.bufPrint(&scratch, "{d}d {d}h {d}m {d}s", .{ days, hours, mins, s }) catch return "-";
    return r;
}

pub fn formatMemory(used_opt: ?u64, limit_opt: ?u64) []const u8 {
    const used = used_opt orelse return "-";
    if (limit_opt) |limit| {
        if (limit == 0) return "-";
        const pct = (@as(u128, used) * 100) / limit;
        const r = std.fmt.bufPrint(&scratch, "{d:.1} / {d:.1} MB ({d}%)", .{
            mb(used), mb(limit), pct,
        }) catch return "-";
        return r;
    }
    const r = std.fmt.bufPrint(&scratch, "{d:.1} MB", .{mb(used)}) catch return "-";
    return r;
}

fn mb(bytes: u64) f64 {
    return @as(f64, @floatFromInt(bytes)) / (1024.0 * 1024.0);
}

pub fn formatRate(opt: ?f64) []const u8 {
    const r = opt orelse return "-";
    const out = std.fmt.bufPrint(&scratch, "{d:.0} lines/sec", .{r}) catch return "-";
    return out;
}

pub fn formatOptU32(opt: ?u32) []const u8 {
    const v = opt orelse return "-";
    const out = std.fmt.bufPrint(&scratch, "{d}", .{v}) catch return "-";
    return out;
}

pub fn formatOptU64(opt: ?u64) []const u8 {
    const v = opt orelse return "-";
    const out = std.fmt.bufPrint(&scratch, "{d}", .{v}) catch return "-";
    return out;
}

pub fn formatHistoryCount(opt: ?u64) []const u8 {
    const value = opt orelse return "unknown";
    return std.fmt.bufPrint(&scratch, "{d} retained confirmations", .{value}) catch "unknown";
}

pub fn formatAge(ms: u64) []const u8 {
    return std.fmt.bufPrint(&scratch, "{d} ms", .{ms}) catch "unknown";
}

pub fn matchedText(buffer: []u8, matches: ?[]const []const u8) []const u8 {
    if (matches) |lines| if (lines.len != 0) return renderDiagnostic(buffer, lines[0]);
    return if (buffer.len != 0) "-" else "";
}

fn writeMatchedChunk(writer: anytype, chunk: []const u8, width: usize, continuation: []const u8, column: *usize) !void {
    if (chunk.len > width - column.*) {
        try writer.writeAll("\n");
        try writer.writeAll(continuation);
        column.* = continuation.len;
    }
    try writer.writeAll(chunk);
    column.* += chunk.len;
}

pub fn writeMatchedLine(writer: anytype, matches: ?[]const []const u8, columns: usize) !void {
    var buffered = std.io.BufferedWriter(256, @TypeOf(writer)){ .unbuffered_writer = writer };
    const out = buffered.writer();
    const label = "  Matched: ";
    const wide = columns >= label.len + 4;
    const width = @max(columns, 4);
    const continuation: []const u8 = if (wide) "  " else "";
    if (wide) {
        try out.writeAll(label);
    } else {
        try out.writeAll(if (columns >= 2) "M:\n" else "M\n");
    }
    var column: usize = if (wide) label.len else 0;
    if (matches) |lines| if (lines.len != 0) {
        const line = lines[0];
        var unit_buffer: [16]u8 = undefined;
        var index: usize = 0;
        while (index < line.len) {
            const unit = diagnosticUnit(line[index..]);
            emitUnit(unit_buffer[0..unit.output_len], line[index..][0..unit.input_len], unit);
            if (unit.kind == .hex and unit.input_len > 1) {
                // Why: Each \xNN goes out as its own chunk, so a wrap may fall between byte escapes but never inside one.
                var offset: usize = 0;
                while (offset < unit.output_len) : (offset += 4) {
                    try writeMatchedChunk(out, unit_buffer[offset..][0..4], width, continuation, &column);
                }
            } else {
                try writeMatchedChunk(out, unit_buffer[0..unit.output_len], width, continuation, &column);
            }
            index += unit.input_len;
        }
        try out.writeAll("\n");
        try buffered.flush();
        return;
    };
    try out.writeAll("-\n");
    try buffered.flush();
}

pub fn padRightPrint(writer: anytype, s: []const u8, width: usize) !void {
    try writer.writeAll(s);
    if (s.len < width) try writeSpaces(writer, width - s.len);
}

pub fn formatRemaining(opt: ?i64) []const u8 {
    const secs = opt orelse return "-";
    if (secs < 0) return "expired";
    const mins = @divTrunc(secs, 60);
    const s: u64 = @intCast(@mod(secs, 60));
    const out = std.fmt.bufPrint(&scratch, "{d}m {d:0>2}s", .{ mins, s }) catch return "-";
    return out;
}

pub fn formatOptU32Local(opt: ?u32) []const u8 {
    const v = opt orelse return "-";
    const out = std.fmt.bufPrint(&scratch, "{d}", .{v}) catch return "-";
    return out;
}

pub const col_max: usize = 48;

pub fn longestLen(comptime T: type, entries: []const T, comptime field: []const u8) usize {
    var widest: usize = 0;
    for (entries) |e| widest = @max(widest, (@field(e, field) orelse "-").len);
    return widest;
}

pub fn colWidth(header: []const u8, longest: usize) usize {
    return @max(header.len, @min(longest, col_max)) + 1;
}

pub fn writeCell(writer: anytype, s: []const u8, width: usize) !void {
    const value_max = width - 1;
    if (s.len <= value_max) return padRightPrint(writer, s, width);
    var cut = value_max - 3;
    // Why: Bytes of the form 10xxxxxx continue a UTF-8 character (RFC 3629 section 3), so the cut moves back to a character start.
    while (cut > 0 and (s[cut] & 0xC0) == 0x80) cut -= 1;
    try writer.writeAll(s[0..cut]);
    try writer.writeAll("...");
    try writeSpaces(writer, width - (cut + 3));
}

pub fn writeClipped(writer: anytype, s: []const u8, width: usize) !void {
    if (s.len <= width) return writer.writeAll(s);
    if (width <= 3) return writer.writeAll(s[0..width]);
    var cut = width - 3;
    while (cut > 0 and (s[cut] & 0xC0) == 0x80) cut -= 1;
    try writer.writeAll(s[0..cut]);
    try writer.writeAll("...");
}

pub fn formatDurationSecs(opt: ?u32) []const u8 {
    const secs = opt orelse return "-";
    if (secs >= 86400) {
        const out = std.fmt.bufPrint(&scratch, "{d}d", .{secs / 86400}) catch return "-";
        return out;
    }
    if (secs >= 3600) {
        const out = std.fmt.bufPrint(&scratch, "{d}h", .{secs / 3600}) catch return "-";
        return out;
    }
    if (secs >= 60) {
        const out = std.fmt.bufPrint(&scratch, "{d}m", .{secs / 60}) catch return "-";
        return out;
    }
    const out = std.fmt.bufPrint(&scratch, "{d}s", .{secs}) catch return "-";
    return out;
}

pub fn escapeArgument(buffer: *[diagnostic_max_bytes]u8, argument: []const u8) []const u8 {
    const argument_max_bytes: usize = 64;
    var cut = @min(argument.len, argument_max_bytes);
    while (cut > 0 and cut < argument.len and (argument[cut] & 0xC0) == 0x80) cut -= 1;
    return renderDiagnostic(buffer, argument[0..cut]);
}

pub const ScopeView = struct {
    family: ?[]const u8 = null,
    address: ?[]const u8 = null,
    prefix: ?u8 = null,
    subject_kind: ?[]const u8 = null,
    protocols: ?[]const []const u8 = null,
    port_ranges: ?[]const PortRangeView = null,
    legacy_exact: ?bool = null,
    protocol: ?[]const u8 = null,
    port: ?u16 = null,
    direction: ?[]const u8 = null,
    target: ?[]const u8 = null,
};

pub const PortRangeView = struct {
    first: ?u16 = null,
    last: ?u16 = null,
};

pub fn formatQuery(
    comptime Payload: type,
    comptime label: []const u8,
    comptime plain: anytype,
    comptime table: anytype,
    allocator: std.mem.Allocator,
    writer: anytype,
    payload_json: []const u8,
    fmt: OutputFormat,
    color: Color,
) !void {
    switch (fmt) {
        .json => {
            try writer.writeAll(payload_json);
            if (payload_json.len == 0 or payload_json[payload_json.len - 1] != '\n') try writer.writeAll("\n");
        },
        .plain, .table => {
            const parsed = std.json.parseFromSlice(Payload, allocator, payload_json, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch |e| {
                try writer.print("error: could not parse " ++ label ++ " payload ({s})\n", .{@errorName(e)});
                return;
            };
            defer parsed.deinit();
            if (fmt == .plain) try plain(writer, parsed.value) else try table(writer, parsed.value, color);
        },
    }
}

pub fn plainOpt(writer: anytype, key: []const u8, value: ?[]const u8) !void {
    try writer.print("{s}\t{s}\n", .{ key, value orelse "-" });
}

pub fn plainBool(writer: anytype, key: []const u8, value: ?bool) !void {
    try writer.print("{s}\t{s}\n", .{ key, boolStr(value) });
}

pub fn plainInt(writer: anytype, key: []const u8, value: anytype) !void {
    if (value) |v| try writer.print("{s}\t{d}\n", .{ key, v }) else try writer.print("{s}\t-\n", .{key});
}

pub fn plainList(writer: anytype, key: []const u8, values: ?[]const []const u8) !void {
    try writer.print("{s}\t", .{key});
    if (values) |list| {
        for (list, 0..) |v, i| {
            if (i != 0) try writer.writeAll(",");
            try writer.writeAll(v);
        }
    } else try writer.writeAll("-");
    try writer.writeAll("\n");
}

pub fn boolStr(value: ?bool) []const u8 {
    const v = value orelse return "-";
    return if (v) "true" else "false";
}

pub fn scopeAddress(buffer: *[64]u8, scope: ?ScopeView) []const u8 {
    const s = scope orelse return "-";
    const address = s.address orelse return "-";
    const prefix = s.prefix orelse return address;
    const host_prefix: u8 = if (std.mem.eql(u8, s.family orelse "", "v6")) 128 else 32;
    if (prefix == host_prefix) return address;
    return std.fmt.bufPrint(buffer, "{s}/{d}", .{ address, prefix }) catch address;
}

pub const scope_match_max_bytes: usize = 384;

pub fn scopeMatch(buffer: []u8, scope: ?ScopeView) []const u8 {
    const s = scope orelse return "-";
    if (s.protocols) |protocols| {
        if (protocols.len == 0) return "unknown";
        var stream = std.io.fixedBufferStream(buffer);
        const writer = stream.writer();
        const all = protocols.len == 1 and std.mem.eql(u8, protocols[0], "all");
        if (all) {
            writer.writeAll("any") catch return "unknown";
        } else {
            for (protocols, 0..) |protocol, index| {
                if (index != 0) writer.writeByte(',') catch return "unknown";
                var diagnostic: [diagnostic_max_bytes]u8 = undefined;
                writer.writeAll(renderDiagnostic(&diagnostic, protocol)) catch return "unknown";
            }
        }
        if (s.port_ranges) |ranges| if (ranges.len != 0) {
            writer.writeByte('/') catch return "unknown";
            for (ranges, 0..) |range, index| {
                if (index != 0) writer.writeByte(',') catch return "unknown";
                const first = range.first orelse {
                    writer.writeByte('?') catch return "unknown";
                    continue;
                };
                const last = range.last orelse {
                    writer.writeByte('?') catch return "unknown";
                    continue;
                };
                if (first == last) {
                    writer.print("{d}", .{first}) catch return "unknown";
                } else {
                    writer.print("{d}-{d}", .{ first, last }) catch return "unknown";
                }
            }
        };
        return stream.getWritten();
    }
    if (s.protocol == null and s.port == null) return "any";
    if (s.port) |port| {
        var diagnostic: [diagnostic_max_bytes]u8 = undefined;
        const protocol = if (s.protocol) |value| renderDiagnostic(&diagnostic, value) else "any";
        return std.fmt.bufPrint(buffer, "{s}/{d}", .{ protocol, port }) catch "unknown";
    }
    return renderDiagnostic(buffer, s.protocol.?);
}

pub fn itemKey(buffer: *[64]u8, index: usize, field_name: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, "items.{d}.{s}", .{ index, field_name }) catch error.NameTooLong;
}

pub fn formatOptU64Local(opt: ?u64) []const u8 {
    const v = opt orelse return "-";
    return std.fmt.bufPrint(&scratch, "{d}", .{v}) catch "-";
}

pub fn formatUtc(buffer: *[32]u8, confirmed_us: ?i64) []const u8 {
    const us = confirmed_us orelse return "-";
    if (us < 0) return "out-of-range";
    const secs: u64 = @intCast(@divTrunc(us, std.time.us_per_s));
    // Why: 253402300799 is 9999-12-31 23:59:59 UTC, the last second whose year prints in four digits.
    const max_supported_utc_seconds: u64 = 253_402_300_799;
    if (secs > max_supported_utc_seconds) return "out-of-range";
    const day = std.time.epoch.EpochSeconds{ .secs = secs };
    const ymd = day.getEpochDay().calculateYearDay().calculateMonthDay();
    const hms = day.getDaySeconds();
    return std.fmt.bufPrint(buffer, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}", .{
        day.getEpochDay().calculateYearDay().year,
        ymd.month.numeric(),
        ymd.day_index + 1,
        hms.getHoursIntoDay(),
        hms.getMinutesIntoHour(),
        hms.getSecondsIntoMinute(),
    }) catch "-";
}
