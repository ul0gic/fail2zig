// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
//! Per-component memory budgets for the fail2zig daemon.
//!
//! `MemoryConfig` carries the byte budget for each component. `MemoryPool`
//! instantiates a `BudgetAllocator` per component from those budgets. Each
//! component runs against its own ceiling, independent of every other
//! component, so a runaway parser cannot starve the state tracker and vice
//! versa.
//!
//! The pool intentionally does NOT share a single backing buffer across
//! components. Each `BudgetAllocator` has its own page-allocated buffer.
//! This keeps the implementation simple and matches the mental model:
//! budgets are independent walls, not slices of one communal pie.

const std = @import("std");
const allocator_mod = @import("allocator.zig");

const BudgetAllocator = allocator_mod.BudgetAllocator;
const Stats = allocator_mod.Stats;

pub const one_mb: usize = 1024 * 1024;

/// Per-component byte budgets. Defaults target a 64MB total ceiling split
/// across the hot components: state tracker gets the lion's share because
/// it stores per-IP attempt windows; the parser scratch buffer is sized
/// for bursty log lines; event queue and log buffers are small. Callers
/// may override any field for tighter footprints (embedded) or larger
/// footprints (high-traffic servers).
pub const MemoryConfig = struct {
    /// IP state tracker: ban state, attempt windows, findtime timestamps.
    state_tracker_bytes: usize = 32 * one_mb,
    /// Parser scratch buffer for transient per-line work (arena-backed).
    parser_buffer_bytes: usize = 4 * one_mb,
    /// Event queue between log watcher → parser → state tracker.
    event_queue_bytes: usize = 1 * one_mb,
    /// Log line buffers for inotify reads.
    log_buffer_bytes: usize = 8 * one_mb,
    /// Hard ceiling on the sum of all component budgets. Init fails if
    /// the per-component budgets sum past this. Default provides 19MB
    /// of headroom beyond the shipped defaults for future components.
    total_ceiling_bytes: usize = 64 * one_mb,

    pub const Error = error{
        BudgetExceedsCeiling,
        BudgetZero,
    };

    /// Validate that every component has a nonzero budget and that the
    /// sum fits under the total ceiling.
    pub fn validate(self: MemoryConfig) Error!void {
        if (self.state_tracker_bytes == 0 or
            self.parser_buffer_bytes == 0 or
            self.event_queue_bytes == 0 or
            self.log_buffer_bytes == 0 or
            self.total_ceiling_bytes == 0)
        {
            return error.BudgetZero;
        }

        // Saturating-sum so a caller-controlled overflow cannot bypass the
        // check. If any partial sum overflows, we already know we exceed
        // the ceiling.
        var sum: usize = 0;
        inline for (.{
            self.state_tracker_bytes,
            self.parser_buffer_bytes,
            self.event_queue_bytes,
            self.log_buffer_bytes,
        }) |field| {
            sum = std.math.add(usize, sum, field) catch
                return error.BudgetExceedsCeiling;
        }
        if (sum > self.total_ceiling_bytes) return error.BudgetExceedsCeiling;
    }

    /// Sum of per-component budgets (excludes the ceiling).
    pub fn totalComponentBytes(self: MemoryConfig) usize {
        return self.state_tracker_bytes +
            self.parser_buffer_bytes +
            self.event_queue_bytes +
            self.log_buffer_bytes;
    }
};

/// Identifies a component within a `MemoryPool`. The enum values are
/// stable; add new components at the end.
pub const Component = enum(u8) {
    state_tracker,
    parser_buffer,
    event_queue,
    log_buffer,
};

/// Aggregate stats snapshot across every component in a pool.
pub const PoolStats = struct {
    state_tracker: Stats,
    parser_buffer: Stats,
    event_queue: Stats,
    log_buffer: Stats,

    pub fn totalBytesAllocated(self: PoolStats) usize {
        return self.state_tracker.bytes_allocated +
            self.parser_buffer.bytes_allocated +
            self.event_queue.bytes_allocated +
            self.log_buffer.bytes_allocated;
    }
};

/// Pool of per-component `BudgetAllocator`s.
///
/// `MemoryPool.init` validates the config then allocates each component's
/// backing buffer. If any allocation fails, previously allocated
/// components are released before returning. `deinit` releases all
/// component buffers. Thread-safety follows `BudgetAllocator` — each
/// component is single-threaded unless the caller wraps it.
pub const MemoryPool = struct {
    config: MemoryConfig,
    state_tracker: BudgetAllocator,
    parser_buffer: BudgetAllocator,
    event_queue: BudgetAllocator,
    log_buffer: BudgetAllocator,

    pub const Error = MemoryConfig.Error || error{OutOfMemory};

    pub fn init(config: MemoryConfig) Error!MemoryPool {
        try config.validate();

        // Each BudgetAllocator grabs its own page-backed buffer; we
        // unwind cleanly if any later allocation fails.
        var state_tracker = try BudgetAllocator.init(config.state_tracker_bytes);
        errdefer state_tracker.deinit();
        var parser_buffer = try BudgetAllocator.init(config.parser_buffer_bytes);
        errdefer parser_buffer.deinit();
        var event_queue = try BudgetAllocator.init(config.event_queue_bytes);
        errdefer event_queue.deinit();
        var log_buffer = try BudgetAllocator.init(config.log_buffer_bytes);
        errdefer log_buffer.deinit();

        return .{
            .config = config,
            .state_tracker = state_tracker,
            .parser_buffer = parser_buffer,
            .event_queue = event_queue,
            .log_buffer = log_buffer,
        };
    }

    pub fn deinit(self: *MemoryPool) void {
        self.state_tracker.deinit();
        self.parser_buffer.deinit();
        self.event_queue.deinit();
        self.log_buffer.deinit();
        self.* = undefined;
    }

    /// Return the `BudgetAllocator` for a component.
    pub fn budget(self: *MemoryPool, comp: Component) *BudgetAllocator {
        return switch (comp) {
            .state_tracker => &self.state_tracker,
            .parser_buffer => &self.parser_buffer,
            .event_queue => &self.event_queue,
            .log_buffer => &self.log_buffer,
        };
    }

    /// Return a Zig `Allocator` for a component.
    pub fn allocator(self: *MemoryPool, comp: Component) std.mem.Allocator {
        return self.budget(comp).allocator();
    }

    /// Snapshot stats for every component.
    pub fn stats(self: *const MemoryPool) PoolStats {
        return .{
            .state_tracker = self.state_tracker.stats(),
            .parser_buffer = self.parser_buffer.stats(),
            .event_queue = self.event_queue.stats(),
            .log_buffer = self.log_buffer.stats(),
        };
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "MemoryConfig: defaults validate" {
    const cfg = MemoryConfig{};
    try cfg.validate();
    try testing.expectEqual(
        32 * one_mb + 4 * one_mb + 1 * one_mb + 8 * one_mb,
        cfg.totalComponentBytes(),
    );
}

test "MemoryConfig: zero budget rejected" {
    var cfg = MemoryConfig{};
    cfg.state_tracker_bytes = 0;
    try testing.expectError(error.BudgetZero, cfg.validate());
}

test "MemoryConfig: sum exceeds ceiling rejected" {
    const cfg = MemoryConfig{
        .state_tracker_bytes = 30 * one_mb,
        .parser_buffer_bytes = 30 * one_mb,
        .event_queue_bytes = 5 * one_mb,
        .log_buffer_bytes = 5 * one_mb,
        .total_ceiling_bytes = 64 * one_mb,
    };
    try testing.expectError(error.BudgetExceedsCeiling, cfg.validate());
}

test "MemoryPool: init with custom small config" {
    // 4KB total — plenty for a unit test, no reason to allocate 64MB.
    const cfg = MemoryConfig{
        .state_tracker_bytes = 1024,
        .parser_buffer_bytes = 1024,
        .event_queue_bytes = 1024,
        .log_buffer_bytes = 1024,
        .total_ceiling_bytes = 4096,
    };
    var pool = try MemoryPool.init(cfg);
    defer pool.deinit();

    const s = pool.stats();
    try testing.expectEqual(@as(usize, 1024), s.state_tracker.capacity);
    try testing.expectEqual(@as(usize, 1024), s.parser_buffer.capacity);
    try testing.expectEqual(@as(usize, 1024), s.event_queue.capacity);
    try testing.expectEqual(@as(usize, 1024), s.log_buffer.capacity);
    try testing.expectEqual(@as(usize, 0), s.totalBytesAllocated());
}

test "MemoryPool: components enforce budgets independently" {
    const cfg = MemoryConfig{
        .state_tracker_bytes = 2048,
        .parser_buffer_bytes = 512,
        .event_queue_bytes = 512,
        .log_buffer_bytes = 512,
        .total_ceiling_bytes = 4096,
    };
    var pool = try MemoryPool.init(cfg);
    defer pool.deinit();

    // Fill parser buffer to cap.
    const parser_a = pool.allocator(.parser_buffer);
    const pbuf = try parser_a.alloc(u8, 512);
    defer parser_a.free(pbuf);
    try testing.expectError(error.OutOfMemory, parser_a.alloc(u8, 1));

    // State tracker still has its full budget despite parser saturated.
    const state_a = pool.allocator(.state_tracker);
    const sbuf = try state_a.alloc(u8, 2048);
    defer state_a.free(sbuf);
}

test "MemoryPool: stats aggregate across components" {
    const cfg = MemoryConfig{
        .state_tracker_bytes = 1024,
        .parser_buffer_bytes = 1024,
        .event_queue_bytes = 1024,
        .log_buffer_bytes = 1024,
        .total_ceiling_bytes = 4096,
    };
    var pool = try MemoryPool.init(cfg);
    defer pool.deinit();

    const st = pool.allocator(.state_tracker);
    const ps = pool.allocator(.parser_buffer);

    const a = try st.alloc(u8, 100);
    defer st.free(a);
    const b = try ps.alloc(u8, 50);
    defer ps.free(b);

    const s = pool.stats();
    try testing.expectEqual(@as(usize, 100), s.state_tracker.bytes_allocated);
    try testing.expectEqual(@as(usize, 50), s.parser_buffer.bytes_allocated);
    try testing.expectEqual(@as(usize, 150), s.totalBytesAllocated());
}

test "MemoryPool: budget() returns same pointer across calls" {
    const cfg = MemoryConfig{
        .state_tracker_bytes = 1024,
        .parser_buffer_bytes = 1024,
        .event_queue_bytes = 1024,
        .log_buffer_bytes = 1024,
        .total_ceiling_bytes = 4096,
    };
    var pool = try MemoryPool.init(cfg);
    defer pool.deinit();

    const p1 = pool.budget(.state_tracker);
    const p2 = pool.budget(.state_tracker);
    try testing.expectEqual(p1, p2);
}

test "MemoryPool: init rejects invalid config" {
    const cfg = MemoryConfig{
        .state_tracker_bytes = 0,
        .parser_buffer_bytes = 1024,
        .event_queue_bytes = 1024,
        .log_buffer_bytes = 1024,
        .total_ceiling_bytes = 4096,
    };
    try testing.expectError(error.BudgetZero, MemoryPool.init(cfg));
}
