//! Budget-enforcing allocator for fail2zig components.
//!
//! `BudgetAllocator` wraps a backing allocator and enforces a hard byte
//! ceiling. Allocation requests that would exceed the ceiling are rejected
//! with `error.OutOfMemory` — never silently serviced. This is the memory
//! safety backbone for every fail2zig component (state tracker, parser
//! buffers, event queue, log buffers): under adversarial load, we run out
//! of budget, not out of system memory.
//!
//! Backing storage is a single page-allocated buffer fed into a
//! `std.heap.FixedBufferAllocator`. The budget layer sits on top, so every
//! `alloc`/`resize`/`remap`/`free` goes through accounting before touching
//! the fixed buffer. This gives two guarantees at once:
//!   1. Hard byte ceiling (no unbounded growth).
//!   2. Bounded physical backing (no fragmentation across the heap).

const std = @import("std");
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;

/// Statistics snapshot for a `BudgetAllocator`.
pub const Stats = struct {
    /// Bytes currently allocated (live). Strictly ≤ `capacity`.
    bytes_allocated: usize,
    /// High-water mark of `bytes_allocated` since init.
    peak_bytes: usize,
    /// Monotonic counter of successful `alloc` calls (for debugging).
    allocation_count: u64,
    /// Configured byte ceiling (budget).
    capacity: usize,
};

/// Budget-enforcing allocator. Not thread-safe by design — each component
/// owns its own `BudgetAllocator` and may wrap it in a mutex if it shares
/// the allocator across threads.
pub const BudgetAllocator = struct {
    /// Hard byte ceiling. Allocations past this return `error.OutOfMemory`.
    capacity: usize,
    /// Live bytes outstanding. Incremented on alloc, decremented on free.
    bytes_allocated: usize,
    /// Max observed `bytes_allocated`.
    peak_bytes: usize,
    /// Count of successful `alloc` calls.
    allocation_count: u64,

    /// Backing page-allocated buffer. Owned by the `BudgetAllocator` and
    /// freed on `deinit`. Sized to `capacity`.
    backing_buffer: []u8,
    /// FixedBufferAllocator that serves physical memory from `backing_buffer`.
    fba: std.heap.FixedBufferAllocator,

    pub const Error = error{OutOfMemory};

    /// Initialize a budget allocator with the given ceiling. Allocates the
    /// full backing buffer from `std.heap.page_allocator` up front — there
    /// is no lazy growth. Caller must `deinit` to release the buffer.
    pub fn init(capacity: usize) Error!BudgetAllocator {
        const buf = std.heap.page_allocator.alloc(u8, capacity) catch
            return error.OutOfMemory;
        return .{
            .capacity = capacity,
            .bytes_allocated = 0,
            .peak_bytes = 0,
            .allocation_count = 0,
            .backing_buffer = buf,
            .fba = std.heap.FixedBufferAllocator.init(buf),
        };
    }

    /// Release the backing buffer. After this call the allocator is
    /// invalid and any outstanding allocations from it dangle.
    pub fn deinit(self: *BudgetAllocator) void {
        std.heap.page_allocator.free(self.backing_buffer);
        self.* = undefined;
    }

    /// Zig Allocator interface for this budget.
    pub fn allocator(self: *BudgetAllocator) Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    /// Snapshot current statistics.
    pub fn stats(self: *const BudgetAllocator) Stats {
        return .{
            .bytes_allocated = self.bytes_allocated,
            .peak_bytes = self.peak_bytes,
            .allocation_count = self.allocation_count,
            .capacity = self.capacity,
        };
    }

    /// Bytes available before the ceiling is hit.
    pub fn available(self: *const BudgetAllocator) usize {
        return self.capacity - self.bytes_allocated;
    }

    // ------------------------------------------------------------------
    // Allocator vtable implementation
    // ------------------------------------------------------------------

    fn alloc(ctx: *anyopaque, n: usize, alignment: Alignment, ret_addr: usize) ?[*]u8 {
        const self: *BudgetAllocator = @ptrCast(@alignCast(ctx));

        // Budget check up front — refuse before we even ask the fixed
        // buffer for memory. Use saturating addition to defend against
        // pathological `n` values that would wrap around.
        const new_total = std.math.add(usize, self.bytes_allocated, n) catch {
            @branchHint(.unlikely);
            return null;
        };
        if (new_total > self.capacity) {
            @branchHint(.unlikely);
            return null;
        }

        const fba_alloc = self.fba.allocator();
        const ptr = fba_alloc.rawAlloc(n, alignment, ret_addr) orelse {
            @branchHint(.unlikely);
            return null;
        };

        self.bytes_allocated = new_total;
        if (self.bytes_allocated > self.peak_bytes) {
            self.peak_bytes = self.bytes_allocated;
        }
        self.allocation_count += 1;
        return ptr;
    }

    fn resize(
        ctx: *anyopaque,
        buf: []u8,
        alignment: Alignment,
        new_len: usize,
        ret_addr: usize,
    ) bool {
        const self: *BudgetAllocator = @ptrCast(@alignCast(ctx));

        // A resize may grow or shrink. If growing, ensure the growth fits
        // the budget before asking the FBA.
        if (new_len > buf.len) {
            const delta = new_len - buf.len;
            const new_total = std.math.add(usize, self.bytes_allocated, delta) catch {
                @branchHint(.unlikely);
                return false;
            };
            if (new_total > self.capacity) {
                @branchHint(.unlikely);
                return false;
            }
            const fba_alloc = self.fba.allocator();
            if (!fba_alloc.rawResize(buf, alignment, new_len, ret_addr)) return false;
            self.bytes_allocated = new_total;
            if (self.bytes_allocated > self.peak_bytes) {
                self.peak_bytes = self.bytes_allocated;
            }
            return true;
        }

        // Shrink or same-size: always accounting-safe. Ask FBA; if it
        // refuses we leave the accounting untouched.
        const fba_alloc = self.fba.allocator();
        if (!fba_alloc.rawResize(buf, alignment, new_len, ret_addr)) return false;
        const delta = buf.len - new_len;
        self.bytes_allocated -= delta;
        return true;
    }

    fn remap(
        ctx: *anyopaque,
        buf: []u8,
        alignment: Alignment,
        new_len: usize,
        ret_addr: usize,
    ) ?[*]u8 {
        const self: *BudgetAllocator = @ptrCast(@alignCast(ctx));

        // Growing remap must pre-check budget. Shrinking is accounting-
        // safe. If the FBA can serve the remap in place, we adjust
        // accounting; otherwise we return null and the caller will do an
        // alloc+copy+free pair that will each pass through our vtable.
        if (new_len > buf.len) {
            const delta = new_len - buf.len;
            const new_total = std.math.add(usize, self.bytes_allocated, delta) catch {
                @branchHint(.unlikely);
                return null;
            };
            if (new_total > self.capacity) {
                @branchHint(.unlikely);
                return null;
            }
            const fba_alloc = self.fba.allocator();
            const ptr = fba_alloc.rawRemap(buf, alignment, new_len, ret_addr) orelse return null;
            self.bytes_allocated = new_total;
            if (self.bytes_allocated > self.peak_bytes) {
                self.peak_bytes = self.bytes_allocated;
            }
            return ptr;
        }

        const fba_alloc = self.fba.allocator();
        const ptr = fba_alloc.rawRemap(buf, alignment, new_len, ret_addr) orelse return null;
        const delta = buf.len - new_len;
        self.bytes_allocated -= delta;
        return ptr;
    }

    fn free(ctx: *anyopaque, buf: []u8, alignment: Alignment, ret_addr: usize) void {
        const self: *BudgetAllocator = @ptrCast(@alignCast(ctx));
        const fba_alloc = self.fba.allocator();
        fba_alloc.rawFree(buf, alignment, ret_addr);
        // FixedBufferAllocator reclaims only the last allocation; we still
        // decrement the budget counter so caps are measured by logical
        // lifetime rather than physical reclamation.
        self.bytes_allocated -= buf.len;
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "BudgetAllocator: init and deinit do not leak" {
    var budget = try BudgetAllocator.init(4096);
    defer budget.deinit();
    const s = budget.stats();
    try testing.expectEqual(@as(usize, 4096), s.capacity);
    try testing.expectEqual(@as(usize, 0), s.bytes_allocated);
    try testing.expectEqual(@as(usize, 0), s.peak_bytes);
    try testing.expectEqual(@as(u64, 0), s.allocation_count);
}

test "BudgetAllocator: allocate within budget succeeds" {
    var budget = try BudgetAllocator.init(1024);
    defer budget.deinit();
    const a = budget.allocator();

    const buf = try a.alloc(u8, 256);
    defer a.free(buf);

    const s = budget.stats();
    try testing.expectEqual(@as(usize, 256), s.bytes_allocated);
    try testing.expectEqual(@as(usize, 256), s.peak_bytes);
    try testing.expectEqual(@as(u64, 1), s.allocation_count);
}

test "BudgetAllocator: allocate beyond budget returns OOM" {
    var budget = try BudgetAllocator.init(512);
    defer budget.deinit();
    const a = budget.allocator();

    // Request more than the ceiling — must fail.
    try testing.expectError(error.OutOfMemory, a.alloc(u8, 1024));

    // Fill exactly to cap, then the next byte fails.
    const buf = try a.alloc(u8, 512);
    defer a.free(buf);
    try testing.expectError(error.OutOfMemory, a.alloc(u8, 1));
}

test "BudgetAllocator: peak bytes tracked across alloc/free cycles" {
    var budget = try BudgetAllocator.init(4096);
    defer budget.deinit();
    const a = budget.allocator();

    const buf1 = try a.alloc(u8, 100);
    const buf2 = try a.alloc(u8, 200);
    const buf3 = try a.alloc(u8, 300);
    try testing.expectEqual(@as(usize, 600), budget.stats().bytes_allocated);
    try testing.expectEqual(@as(usize, 600), budget.stats().peak_bytes);

    // Free in reverse order so the FixedBufferAllocator can actually
    // reclaim the storage. Our accounting decrements regardless of
    // reclamation, which is the point of the budget layer.
    a.free(buf3);
    a.free(buf2);
    a.free(buf1);
    try testing.expectEqual(@as(usize, 0), budget.stats().bytes_allocated);
    try testing.expectEqual(@as(usize, 600), budget.stats().peak_bytes);
}

test "BudgetAllocator: allocation_count increments" {
    var budget = try BudgetAllocator.init(4096);
    defer budget.deinit();
    const a = budget.allocator();

    const b1 = try a.alloc(u8, 16);
    const b2 = try a.alloc(u8, 32);
    const b3 = try a.alloc(u8, 64);
    try testing.expectEqual(@as(u64, 3), budget.stats().allocation_count);

    // Free in reverse order so the FBA reclaims each.
    a.free(b3);
    a.free(b2);
    a.free(b1);
}

test "BudgetAllocator: available reports remaining budget" {
    var budget = try BudgetAllocator.init(1000);
    defer budget.deinit();
    const a = budget.allocator();

    try testing.expectEqual(@as(usize, 1000), budget.available());
    const buf = try a.alloc(u8, 400);
    defer a.free(buf);
    try testing.expectEqual(@as(usize, 600), budget.available());
}

test "BudgetAllocator: rejects pathological huge request" {
    var budget = try BudgetAllocator.init(1024);
    defer budget.deinit();
    const a = budget.allocator();

    // A request that would overflow if naively added must be rejected
    // without crashing.
    try testing.expectError(error.OutOfMemory, a.alloc(u8, std.math.maxInt(usize)));
}

test "BudgetAllocator: arena on top of budget stays bounded" {
    // Exercise the common real pattern: an ArenaAllocator backed by a
    // BudgetAllocator. The arena can grab up to budget then OOMs, and
    // `arena.deinit()` frees everything through the budget.
    var budget = try BudgetAllocator.init(2048);
    defer budget.deinit();

    var arena = std.heap.ArenaAllocator.init(budget.allocator());
    defer arena.deinit();
    const aa = arena.allocator();

    _ = try aa.alloc(u8, 512);
    _ = try aa.alloc(u8, 512);
    _ = try aa.alloc(u8, 512);

    // Arena may round up; the 4th 512-byte alloc should exceed cap.
    try testing.expectError(error.OutOfMemory, aa.alloc(u8, 1024));
}
