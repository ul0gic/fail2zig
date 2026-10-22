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
