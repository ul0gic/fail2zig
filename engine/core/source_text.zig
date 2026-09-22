// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");

pub const max_record_bytes = 1024 * 1024;
pub const Encoding = enum {
    utf8,
    ascii,
    latin1,
    utf16le,
    utf16be,
    utf32le,
    utf32be,

    pub fn width(self: Encoding) usize {
        return switch (self) {
            .utf8, .ascii, .latin1 => 1,
            .utf16le, .utf16be => 2,
            .utf32le, .utf32be => 4,
        };
    }

    fn endian(self: Encoding) std.builtin.Endian {
        return switch (self) {
            .utf16be, .utf32be => .big,
            else => .little,
        };
    }
};
pub const Error = error{ RecordTooLarge, InvalidEncoding, IncompleteEncoding, OutputTooSmall, MisalignedOffset, ConflictingBom };
pub const Bom = enum { preserve, strip_stream_start };
pub const Frame = struct { consumed: usize, payload: []const u8 };

fn unit(encoding: Encoding, bytes: []const u8) u32 {
    return switch (encoding.width()) {
        1 => bytes[0],
        2 => std.mem.readInt(u16, bytes[0..2], encoding.endian()),
        4 => std.mem.readInt(u32, bytes[0..4], encoding.endian()),
        else => unreachable,
    };
}

pub fn frame(encoding: Encoding, bytes: []const u8, absolute_offset: u64) Error!?Frame {
    if (bytes.len > max_record_bytes) return error.RecordTooLarge;
    const width = encoding.width();
    if (absolute_offset % width != 0) return error.MisalignedOffset;
    var i: usize = 0;
    while (i + width <= bytes.len) : (i += width) {
        if (unit(encoding, bytes[i..]) == '\n') {
            const end = if (i >= width and unit(encoding, bytes[i - width ..]) == '\r') i - width else i;
            return .{ .consumed = i + width, .payload = bytes[0..end] };
        }
    }
    return null;
}

fn bomLength(encoding: Encoding, input: []const u8) Error!usize {
    const Signature = struct { encoding: Encoding, bytes: []const u8 };
    const signatures = [_]Signature{
        .{ .encoding = .utf32le, .bytes = "\xff\xfe\x00\x00" },
        .{ .encoding = .utf32be, .bytes = "\x00\x00\xfe\xff" },
        .{ .encoding = .utf8, .bytes = "\xef\xbb\xbf" },
        .{ .encoding = .utf16le, .bytes = "\xff\xfe" },
        .{ .encoding = .utf16be, .bytes = "\xfe\xff" },
    };
    for (signatures) |signature| {
        if (signature.encoding == encoding and std.mem.startsWith(u8, input, signature.bytes)) return signature.bytes.len;
    }
    for (signatures) |signature| {
        if (std.mem.startsWith(u8, input, signature.bytes)) {
            if (signature.encoding != encoding) return error.ConflictingBom;
            return signature.bytes.len;
        }
    }
    return 0;
}

pub fn decode(encoding: Encoding, input: []const u8, scratch: []u8, absolute_offset: u64, bom: Bom) Error![]const u8 {
    if (input.len > max_record_bytes) return error.RecordTooLarge;
    if (absolute_offset % encoding.width() != 0) return error.MisalignedOffset;
    if (input.len % encoding.width() != 0) return error.IncompleteEncoding;
    const skip = if (absolute_offset == 0 and bom == .strip_stream_start and encoding != .ascii and encoding != .latin1)
        try bomLength(encoding, input)
    else
        0;
    const bytes = input[skip..];
    const output = scratch[0..@min(scratch.len, max_record_bytes)];
    var i: usize = 0;
    var written: usize = 0;
    while (i < bytes.len) {
        var point: u32 = undefined;
        switch (encoding) {
            .ascii => {
                if (bytes[i] > 127) return error.InvalidEncoding;
                point = bytes[i];
                i += 1;
            },
            .latin1 => {
                point = bytes[i];
                i += 1;
            },
            .utf8 => {
                const n = std.unicode.utf8ByteSequenceLength(bytes[i]) catch return error.InvalidEncoding;
                if (n > bytes.len - i) return error.IncompleteEncoding;
                point = std.unicode.utf8Decode(bytes[i .. i + n]) catch return error.InvalidEncoding;
                i += n;
            },
            .utf16le, .utf16be => {
                point = unit(encoding, bytes[i..]);
                i += 2;
                if (point >= 0xd800 and point <= 0xdbff) {
                    if (bytes.len - i < 2) return error.IncompleteEncoding;
                    const low = unit(encoding, bytes[i..]);
                    if (low < 0xdc00 or low > 0xdfff) return error.InvalidEncoding;
                    point = 0x10000 + ((point - 0xd800) << 10) + low - 0xdc00;
                    i += 2;
                } else if (point >= 0xdc00 and point <= 0xdfff) return error.InvalidEncoding;
            },
            .utf32le, .utf32be => {
                point = unit(encoding, bytes[i..]);
                i += 4;
            },
        }
        if (point > 0x10ffff or (point >= 0xd800 and point <= 0xdfff)) return error.InvalidEncoding;
        var encoded: [4]u8 = undefined;
        const n = std.unicode.utf8Encode(@intCast(point), &encoded) catch return error.InvalidEncoding;
        if (n > output.len - written) return error.OutputTooSmall;
        @memcpy(output[written .. written + n], encoded[0..n]);
        written += n;
    }
    return output[0..written];
}

pub const Decoded = struct { text: []const u8, replaced: bool, exceeded: bool = false };

// File records are byte-framed before decoding. Replace maximal invalid subsequences
// without consuming a following valid character or joining text across damaged bytes.
pub fn decodeFile(encoding: Encoding, input: []const u8, scratch: []u8, absolute_offset: u64, bom: Bom) Error!Decoded {
    if (input.len > max_record_bytes) return error.RecordTooLarge;
    if (absolute_offset % encoding.width() != 0) return error.MisalignedOffset;
    const skip = if (absolute_offset == 0 and bom == .strip_stream_start and encoding != .ascii and encoding != .latin1)
        try bomLength(encoding, input)
    else
        0;
    const bytes = input[skip..];
    const output = scratch[0..@min(scratch.len, max_record_bytes)];
    var i: usize = 0;
    var written: usize = 0;
    var replaced = false;
    var exceeded = false;
    while (i < bytes.len) {
        var point: u32 = 0xfffd;
        var damaged = false;
        switch (encoding) {
            .ascii, .latin1 => {
                point = bytes[i];
                i += 1;
                if (encoding == .ascii and point > 127) damaged = true;
            },
            .utf8 => utf8: {
                const first = bytes[i];
                const count: usize = if (first < 0x80) 1 else if (first >= 0xc2 and first <= 0xdf) 2 else if (first >= 0xe0 and first <= 0xef) 3 else if (first >= 0xf0 and first <= 0xf4) 4 else 0;
                if (count == 0) {
                    i += 1;
                    damaged = true;
                    break :utf8;
                }
                var prefix: usize = 1;
                while (prefix < count and prefix < bytes.len - i) : (prefix += 1) {
                    const next = bytes[i + prefix];
                    if (next < 0x80 or next > 0xbf) break;
                    if (prefix == 1 and ((first == 0xe0 and next < 0xa0) or
                        (first == 0xed and next > 0x9f) or (first == 0xf0 and next < 0x90) or
                        (first == 0xf4 and next > 0x8f))) break;
                }
                if (prefix == count) {
                    point = std.unicode.utf8Decode(bytes[i .. i + count]) catch return error.InvalidEncoding;
                } else damaged = true;
                i += prefix;
            },
            .utf16le, .utf16be => utf16: {
                if (bytes.len - i < 2) {
                    i = bytes.len;
                    damaged = true;
                    break :utf16;
                }
                point = unit(encoding, bytes[i..]);
                i += 2;
                if (point >= 0xd800 and point <= 0xdbff) {
                    if (bytes.len - i < 2) {
                        i = bytes.len;
                        damaged = true;
                    } else {
                        const low = unit(encoding, bytes[i..]);
                        if (low >= 0xdc00 and low <= 0xdfff) {
                            point = 0x10000 + ((point - 0xd800) << 10) + low - 0xdc00;
                            i += 2;
                        } else damaged = true;
                    }
                } else if (point >= 0xdc00 and point <= 0xdfff) damaged = true;
            },
            .utf32le, .utf32be => {
                if (bytes.len - i < 4) {
                    i = bytes.len;
                    damaged = true;
                } else {
                    point = unit(encoding, bytes[i..]);
                    i += 4;
                    damaged = point > 0x10ffff or (point >= 0xd800 and point <= 0xdfff);
                }
            },
        }
        // These embedded framing controls cannot be admitted to the detector as text.
        if (damaged or point == 0 or point == '\r') {
            point = 0xfffd;
            replaced = true;
        }
        var encoded_point: [4]u8 = undefined;
        const count = std.unicode.utf8Encode(@intCast(point), &encoded_point) catch return error.InvalidEncoding;
        if (count > output.len - written) exceeded = true;
        if (!exceeded) {
            @memcpy(output[written .. written + count], encoded_point[0..count]);
            written += count;
        }
    }
    return .{ .text = if (exceeded) "" else output[0..written], .replaced = replaced, .exceeded = exceeded };
}

test "native text: strict codepoints and explicit encodings" {
    var scratch: [64]u8 = undefined;
    const Case = struct { encoding: Encoding, input: []const u8, output: []const u8 };
    for ([_]Case{
        .{ .encoding = .utf8, .input = "AΩ😀\x00", .output = "AΩ😀\x00" },
        .{ .encoding = .ascii, .input = "ordinary", .output = "ordinary" },
        .{ .encoding = .latin1, .input = "caf\xe9", .output = "café" },
        .{ .encoding = .utf16le, .input = "A\x00\xa9\x03\x3d\xd8\x00\xde", .output = "AΩ😀" },
        .{ .encoding = .utf16be, .input = "\x00A\x03\xa9\xd8\x3d\xde\x00", .output = "AΩ😀" },
        .{ .encoding = .utf32le, .input = "A\x00\x00\x00\xa9\x03\x00\x00\x00\xf6\x01\x00", .output = "AΩ😀" },
        .{ .encoding = .utf32be, .input = "\x00\x00\x00A\x00\x00\x03\xa9\x00\x01\xf6\x00", .output = "AΩ😀" },
    }) |case| try std.testing.expectEqualStrings(case.output, try decode(case.encoding, case.input, &scratch, 0, .preserve));
    for ([_][]const u8{ "\xc0\xaf", "\xed\xa0\x80", "\xf4\x90\x80\x80", "\x80", "\xff" }) |bad|
        try std.testing.expectError(error.InvalidEncoding, decode(.utf8, bad, &scratch, 0, .preserve));
    try std.testing.expectError(error.IncompleteEncoding, decode(.utf8, "\xe2\x82", &scratch, 0, .preserve));
    try std.testing.expectError(error.InvalidEncoding, decode(.ascii, "é", &scratch, 0, .preserve));
    try std.testing.expectError(error.InvalidEncoding, decode(.utf16le, "\x00\xdc", &scratch, 0, .preserve));
    try std.testing.expectError(error.InvalidEncoding, decode(.utf16be, "\xd8\x00\x00A", &scratch, 0, .preserve));
    try std.testing.expectError(error.IncompleteEncoding, decode(.utf16le, "\x00\xd8", &scratch, 0, .preserve));
    try std.testing.expectError(error.IncompleteEncoding, decode(.utf16le, "A", &scratch, 0, .preserve));
    try std.testing.expectError(error.InvalidEncoding, decode(.utf32le, "\x00\x00\x11\x00", &scratch, 0, .preserve));
    try std.testing.expectError(error.InvalidEncoding, decode(.utf32be, "\x00\x00\xd8\x00", &scratch, 0, .preserve));
    try std.testing.expectError(error.OutputTooSmall, decode(.latin1, "\xff", scratch[0..1], 0, .preserve));
    try std.testing.expectError(error.MisalignedOffset, decode(.utf32le, "", &scratch, 2, .preserve));
}

test "native text: BOM never silently chooses an encoding or strips later data" {
    var scratch: [32]u8 = undefined;
    try std.testing.expectEqualStrings("A", try decode(.utf8, "\xef\xbb\xbfA", &scratch, 0, .strip_stream_start));
    try std.testing.expectEqualStrings("\xef\xbb\xbfA", try decode(.utf8, "\xef\xbb\xbfA", &scratch, 8, .strip_stream_start));
    try std.testing.expectEqualStrings("A", try decode(.utf16le, "\xff\xfeA\x00", &scratch, 0, .strip_stream_start));
    try std.testing.expectEqualStrings("A", try decode(.utf32be, "\x00\x00\xfe\xff\x00\x00\x00A", &scratch, 0, .strip_stream_start));
    try std.testing.expectError(error.ConflictingBom, decode(.utf16be, "\xff\xfeA\x00", &scratch, 0, .strip_stream_start));
    try std.testing.expectError(error.ConflictingBom, decode(.utf8, "\xff\xfeA\x00", &scratch, 0, .strip_stream_start));
    try std.testing.expectEqualStrings("\x00", try decode(.utf16le, "\xff\xfe\x00\x00", &scratch, 0, .strip_stream_start));
    try std.testing.expectEqualStrings("ÿþ", try decode(.latin1, "\xff\xfe", &scratch, 0, .strip_stream_start));
}

test "native text: every input split preserves aligned record boundaries" {
    const Case = struct { encoding: Encoding, bytes: []const u8, consumed: usize, payload_len: usize };
    for ([_]Case{
        .{ .encoding = .utf8, .bytes = "Ω\r\r\nnext", .consumed = 5, .payload_len = 3 },
        .{ .encoding = .utf16le, .bytes = "\x0a\x01\r\x00\n\x00A\x00", .consumed = 6, .payload_len = 2 },
        .{ .encoding = .utf16be, .bytes = "\x01\x0a\x00\r\x00\n\x00A", .consumed = 6, .payload_len = 2 },
        .{ .encoding = .utf32le, .bytes = "\x0a\x01\x00\x00\n\x00\x00\x00", .consumed = 8, .payload_len = 4 },
        .{ .encoding = .utf32be, .bytes = "\x00\x00\x01\x0a\x00\x00\x00\n", .consumed = 8, .payload_len = 4 },
    }) |case| {
        for (0..case.bytes.len + 1) |split| {
            const result = try frame(case.encoding, case.bytes[0..split], 0);
            if (split < case.consumed) {
                try std.testing.expect(result == null);
            } else {
                try std.testing.expectEqual(case.consumed, result.?.consumed);
                try std.testing.expectEqualStrings(case.bytes[0..case.payload_len], result.?.payload);
            }
        }
    }
    try std.testing.expectError(error.MisalignedOffset, frame(.utf16le, "", 1));
    const bytes = try std.testing.allocator.alloc(u8, max_record_bytes + 1);
    defer std.testing.allocator.free(bytes);
    @memset(bytes, 'a');
    try std.testing.expectError(error.RecordTooLarge, frame(.utf8, bytes, 0));
    try std.testing.expectError(error.RecordTooLarge, decode(.utf8, bytes, &.{}, 0, .preserve));
    try std.testing.expect((try frame(.utf8, bytes[0..max_record_bytes], 0)) == null);
}

test "native text: file replacement preserves valid boundaries and bounds expansion" {
    var scratch: [128]u8 = undefined;
    const replacement = "\xef\xbf\xbd";
    const Case = struct { encoding: Encoding = .utf8, input: []const u8, expected: []const u8 };
    for ([_]Case{
        .{ .input = "\xffA", .expected = replacement ++ "A" },
        .{ .input = "A\xe2\x82Z", .expected = "A" ++ replacement ++ "Z" },
        .{ .input = "A\xe2\x82", .expected = "A" ++ replacement },
        .{ .input = "\xc0\xaf", .expected = replacement ++ replacement },
        .{ .input = "\xed\xa0\x80", .expected = replacement ++ replacement ++ replacement },
        .{ .input = "\xf4\x90\x80\x80", .expected = replacement ++ replacement ++ replacement ++ replacement },
        .{ .input = "192.0.\xff2.1", .expected = "192.0." ++ replacement ++ "2.1" },
        .{ .input = "Ω\x00😀\rA", .expected = "Ω" ++ replacement ++ "😀" ++ replacement ++ "A" },
        .{ .encoding = .ascii, .input = "A\xffZ", .expected = "A" ++ replacement ++ "Z" },
        .{ .encoding = .utf16le, .input = "\x00\xd8A\x00", .expected = replacement ++ "A" },
        .{ .encoding = .utf16be, .input = "\xd8\x00\x00A", .expected = replacement ++ "A" },
        .{ .encoding = .utf16le, .input = "\x00\xd8A", .expected = replacement },
        .{ .encoding = .utf16be, .input = "\xdc\x00\xd8\x3d\xde\x00", .expected = replacement ++ "😀" },
        .{ .encoding = .utf32le, .input = "\x00\x00\x11\x00A\x00\x00\x00", .expected = replacement ++ "A" },
        .{ .encoding = .utf32be, .input = "\x00\x00\xd8\x00\x00", .expected = replacement ++ replacement },
    }) |case| {
        const decoded = try decodeFile(case.encoding, case.input, &scratch, 0, .preserve);
        try std.testing.expect(decoded.replaced and !decoded.exceeded);
        try std.testing.expectEqualStrings(case.expected, decoded.text);
    }
    for ([_]Case{
        .{ .input = "AΩ😀", .expected = "AΩ😀" },
        .{ .input = replacement, .expected = replacement },
        .{ .encoding = .latin1, .input = "caf\xe9", .expected = "café" },
        .{ .encoding = .utf16le, .input = "A\x00\x3d\xd8\x00\xde", .expected = "A😀" },
        .{ .encoding = .utf32be, .input = "\x00\x00\x00A\x00\x01\xf6\x00", .expected = "A😀" },
    }) |case| {
        const decoded = try decodeFile(case.encoding, case.input, &scratch, 0, .preserve);
        try std.testing.expect(!decoded.replaced and !decoded.exceeded);
        try std.testing.expectEqualStrings(case.expected, decoded.text);
    }
    const damaged_limit = try decodeFile(.utf8, "\xffA", scratch[0..3], 0, .preserve);
    try std.testing.expect(damaged_limit.exceeded and damaged_limit.replaced);
    try std.testing.expectEqualStrings("", damaged_limit.text);
    const clean_limit = try decodeFile(.latin1, "\xe9\xe9", scratch[0..3], 0, .preserve);
    try std.testing.expect(clean_limit.exceeded and !clean_limit.replaced);
    try std.testing.expectEqualStrings("", clean_limit.text);
    const late_damage = try decodeFile(.utf8, "ABCD\xff", scratch[0..3], 0, .preserve);
    try std.testing.expect(late_damage.exceeded and late_damage.replaced);
    try std.testing.expectEqualStrings("", late_damage.text);
    try std.testing.expectEqualStrings(replacement ++ "A", (try decodeFile(.utf8, "\xffA", scratch[0..4], 0, .preserve)).text);
    try std.testing.expectError(error.ConflictingBom, decodeFile(.utf8, "\xff\xfeA", &scratch, 0, .strip_stream_start));
    try std.testing.expectError(error.MisalignedOffset, decodeFile(.utf16le, "A\x00", &scratch, 1, .preserve));
    try std.testing.expectEqualStrings("A", (try decodeFile(.utf8, "\xef\xbb\xbfA", &scratch, 0, .strip_stream_start)).text);
    // The journal/strict entry point retains its original rejection behavior.
    try std.testing.expectError(error.InvalidEncoding, decode(.utf8, "\xffA", &scratch, 0, .preserve));
}
