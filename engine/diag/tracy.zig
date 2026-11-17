// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

pub const SourceLocation = extern struct {
    name: ?[*:0]const u8,
    function: [*:0]const u8,
    file: [*:0]const u8,
    line: u32,
    color: u32 = 0,
};

// Layout of ___tracy_c_zone_context without TRACY_ON_DEMAND, which build.zig never defines.
pub const Zone = extern struct {
    id: u32 = 0,
    active: i32 = 0,
};

const severity_info: i8 = 2;

extern fn ___tracy_startup_profiler() void;
extern fn ___tracy_profiler_started() i32;
extern fn ___tracy_emit_zone_begin(srcloc: *const SourceLocation, active: i32) Zone;
extern fn ___tracy_emit_zone_end(ctx: Zone) void;
extern fn ___tracy_emit_frame_mark(name: ?[*:0]const u8) void;
extern fn ___tracy_emit_logString(severity: i8, color: i32, callstack_depth: i32, size: usize, txt: [*]const u8) void;
extern fn ___tracy_emit_memory_alloc(ptr: *const anyopaque, size: usize) void;
extern fn ___tracy_emit_memory_free(ptr: *const anyopaque) void;

// The client is built with TRACY_MANUAL_LIFETIME so that only the daemon, not every CLI run, starts a profiler
// (an unconnected profiler blocks process exit); every other call here is invalid before this one.
pub fn startup() void {
    ___tracy_startup_profiler();
}

pub fn zoneBegin(location: *const SourceLocation) Zone {
    return ___tracy_emit_zone_begin(location, 1);
}

pub fn zoneEnd(zone: Zone) void {
    ___tracy_emit_zone_end(zone);
}

pub fn frameMark() void {
    ___tracy_emit_frame_mark(null);
}

pub fn message(text: []const u8) void {
    ___tracy_emit_logString(severity_info, 0, 0, text.len, text.ptr);
}
