// SPDX-License-Identifier: AGPL-3.0-or-later
// Experiment-only linker wrappers for a prebuilt Debian archive. Production should
// use a reviewed source build with explicit static codec calls, not this shim.
const std = @import("std");
var handles = [_]u8{ 0, 0, 0 };
const libraries = [_][]const u8{ "liblzma.so.5", "liblz4.so.1", "libzstd.so.1" };
const symbols = .{
    .{ "lzma_code", "lzma_easy_encoder", "lzma_end", "lzma_stream_buffer_encode", "lzma_stream_decoder" },
    .{ "LZ4F_compressBegin", "LZ4F_compressBound", "LZ4F_compressEnd", "LZ4F_compressUpdate", "LZ4F_createCompressionContext", "LZ4F_createDecompressionContext", "LZ4F_decompress", "LZ4F_freeCompressionContext", "LZ4F_freeDecompressionContext", "LZ4F_isError", "LZ4_compress_default", "LZ4_decompress_safe", "LZ4_decompress_safe_partial", "LZ4_versionNumber" },
    .{ "ZSTD_CCtx_setParameter", "ZSTD_CStreamInSize", "ZSTD_CStreamOutSize", "ZSTD_DStreamInSize", "ZSTD_DStreamOutSize", "ZSTD_compress", "ZSTD_compressStream2", "ZSTD_createCCtx", "ZSTD_createDCtx", "ZSTD_decompressStream", "ZSTD_freeCCtx", "ZSTD_freeDCtx", "ZSTD_getErrorCode", "ZSTD_getErrorName", "ZSTD_getFrameContentSize", "ZSTD_isError" },
};

export fn __wrap_dlopen(name: ?[*:0]const u8, _: c_int) ?*anyopaque {
    const n = name orelse return null;
    for (libraries, 0..) |library, i| {
        if (std.mem.eql(u8, std.mem.span(n), library)) return &handles[i];
    }
    return null;
}

export fn __wrap_dlsym(handle: ?*anyopaque, name: [*:0]const u8) ?*anyopaque {
    inline for (symbols, 0..) |group, i| {
        if (handle == @as(*anyopaque, &handles[i])) {
            inline for (group) |symbol| {
                if (std.mem.eql(u8, std.mem.span(name), symbol)) {
                    return @constCast(@extern(*const anyopaque, .{ .name = symbol }));
                }
            }
        }
    }
    return null;
}

export fn __wrap_dlclose(handle: ?*anyopaque) c_int {
    for (&handles) |*h| if (handle == @as(*anyopaque, h)) return 0;
    return -1;
}

export fn __wrap_dlerror() [*:0]const u8 {
    return "offline probe: dynamic loading disabled; codec symbol unavailable";
}
