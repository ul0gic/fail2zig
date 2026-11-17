// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Matches PortSentry 2.0.7 history records of a triggered scan that PortSentry itself did not block.
// Holds: A line matches only if every field parses and nothing follows `blocked: [false]`; the address comes from the brackets alone.

const std = @import("std");
const shared = @import("shared");
const native_time = @import("../time/time.zig");
const parser = @import("../detect/parser.zig");
const types = @import("types.zig");

pub const PatternDef = types.PatternDef;

// Why: PortSentry 2.0.7 builds each history record in a 1024-byte buffer that also holds the newline and NUL.
const max_history_bytes: usize = 1024 - 2;
// Why: PortSentry stamps records as %Y-%m-%dT%H:%M:%S., three millisecond digits, then %z: 28 bytes.
const timestamp_bytes: usize = 28;

pub const patterns = [_]PatternDef{
    .{ .name = "triggered-scan", .match = matchTriggeredScan },
};

fn matchTriggeredScan(line: []const u8) ?parser.ParseResult {
    if (line.len > max_history_bytes or line.len < timestamp_bytes) return null;
    if (!validTimestamp(line[0..timestamp_bytes])) return null;

    var cursor: usize = timestamp_bytes;
    if (!takeLiteral(line, &cursor, " Scan from: [")) return null;
    // Why: 45 bytes is the longest textual IPv6 address, INET6_ADDRSTRLEN less its NUL (inet_ntop(3)).
    const address_text = takeUntil(line, &cursor, ']', 45) orelse return null;
    const address = shared.IpAddress.parse(address_text) catch return null;

    if (!takeLiteral(line, &cursor, " (")) return null;
    const displayed_host = takeUntil(line, &cursor, ')', 45) orelse return null;
    // Why: With RESOLVE_HOST=0 PortSentry writes the bracketed address here again, so a record whose two fields differ is refused.
    if (!std.mem.eql(u8, displayed_host, address_text)) return null;

    if (!takeLiteral(line, &cursor, " protocol: [")) return null;
    const protocol = takeUntil(line, &cursor, ']', 3) orelse return null;
    const tcp = std.mem.eql(u8, protocol, "TCP");
    const udp = std.mem.eql(u8, protocol, "UDP");
    if (!tcp and !udp) return null;

    if (!takeLiteral(line, &cursor, " port: [")) return null;
    const port_text = takeUntil(line, &cursor, ']', 5) orelse return null;
    if (!validPort(port_text)) return null;

    if (!takeLiteral(line, &cursor, " type: [")) return null;
    const scan_type = takeUntil(line, &cursor, ']', 128) orelse return null;
    if (tcp) {
        if (!validTcpType(scan_type)) return null;
    } else if (!std.mem.eql(u8, scan_type, "UDP") and
        !std.mem.eql(u8, scan_type, "Connect")) return null;

    if (!takeLiteral(line, &cursor, " IP opts: [")) return null;
    const ip_options = takeUntil(line, &cursor, ']', 7) orelse return null;
    if (!std.mem.eql(u8, ip_options, "unknown") and
        !std.mem.eql(u8, ip_options, "not set") and
        !std.mem.eql(u8, ip_options, "set")) return null;

    if (!takeLiteral(
        line,
        &cursor,
        " ignored: [false] triggered: [true] noblock: [true] blocked: [false]",
    )) return null;
    if (cursor != line.len) return null;

    return .{ .ip = address };
}

fn takeLiteral(line: []const u8, cursor: *usize, literal: []const u8) bool {
    const end = std.math.add(usize, cursor.*, literal.len) catch return false;
    if (end > line.len or !std.mem.eql(u8, line[cursor.*..end], literal)) return false;
    cursor.* = end;
    return true;
}

fn takeUntil(line: []const u8, cursor: *usize, delimiter: u8, max_len: usize) ?[]const u8 {
    if (cursor.* >= line.len) return null;
    const relative_end = std.mem.indexOfScalar(u8, line[cursor.*..], delimiter) orelse return null;
    if (relative_end == 0 or relative_end > max_len) return null;
    const start = cursor.*;
    const end = start + relative_end;
    cursor.* = end + 1;
    return line[start..end];
}

fn validPort(text: []const u8) bool {
    if (text.len == 0 or text.len > 5 or (text.len > 1 and text[0] == '0')) return false;
    var value: u32 = 0;
    for (text) |byte| {
        if (!std.ascii.isDigit(byte)) return false;
        value = value * 10 + @as(u32, byte - '0');
    }
    return value >= 1 and value <= 65535;
}

fn validTcpType(text: []const u8) bool {
    for ([_][]const u8{
        "Connect",
        "TCP NULL scan",
        "TCP XMAS scan",
        "TCP FIN scan",
        "TCP SYN/Normal scan",
    }) |known| if (std.mem.eql(u8, text, known)) return true;
    return validUnknownTcpType(text);
}

fn validUnknownTcpType(text: []const u8) bool {
    var cursor: usize = 0;
    if (!takeLiteral(text, &cursor, "Unknown Type: TCP Packet Flags: SYN: ")) return false;
    inline for (.{ " FIN: ", " ACK: ", " PSH: ", " URG: ", " RST: " }) |separator| {
        if (cursor >= text.len or (text[cursor] != '0' and text[cursor] != '1')) return false;
        cursor += 1;
        if (!takeLiteral(text, &cursor, separator)) return false;
    }
    if (cursor >= text.len or (text[cursor] != '0' and text[cursor] != '1')) return false;
    return cursor + 1 == text.len;
}

fn validTimestamp(text: []const u8) bool {
    if (text.len != timestamp_bytes or text[4] != '-' or text[7] != '-' or
        text[10] != 'T' or text[13] != ':' or text[16] != ':' or
        text[19] != '.' or (text[23] != '+' and text[23] != '-')) return false;
    _ = native_time.parse(.iso8601, text, .{}) catch return false;
    return true;
}
