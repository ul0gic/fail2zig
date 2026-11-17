// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Expands a log path glob into the sorted regular files it matches, a bounded number of directory entries per turn.
// Holds: Discovery visits at most 256 entries per turn and 65,536 per episode, and fails past 16 path components or its path limit.

const std = @import("std");
const durable = @import("durable_file_source.zig");
const Allocator = std.mem.Allocator;
const DiscoveryStatus = durable.DiscoveryStatus;
const discovery_entries_per_turn = durable.discovery_entries_per_turn;
const discovery_entries_per_episode = durable.discovery_entries_per_episode;
const discovery_max_depth = durable.discovery_max_depth;

// Why: A leading dot in a name must be matched explicitly by the pattern (glob(7)).
pub fn matchComponent(pattern: []const u8, name: []const u8) bool {
    if (name.len > 0 and name[0] == '.' and (pattern.len == 0 or pattern[0] != '.')) return false;
    return matchRest(pattern, name);
}

// Why: An undecodable byte maps to U+DC00 plus its value, a surrogate no valid UTF-8 decodes to, so it matches only itself.
fn glyph(bytes: []const u8, index: usize) struct { value: u32, size: usize } {
    const first = bytes[index];
    const length = std.unicode.utf8ByteSequenceLength(first) catch return .{ .value = 0xdc00 + @as(u32, first), .size = 1 };
    if (index + length > bytes.len) return .{ .value = 0xdc00 + @as(u32, first), .size = 1 };
    const value = std.unicode.utf8Decode(bytes[index .. index + length]) catch return .{ .value = 0xdc00 + @as(u32, first), .size = 1 };
    return .{ .value = value, .size = length };
}

fn matchRest(pattern: []const u8, name: []const u8) bool {
    var p: usize = 0;
    var n: usize = 0;
    var star: ?usize = null;
    var retry: usize = 0;
    while (n < name.len) {
        if (p < pattern.len and pattern[p] == '*') {
            star = p;
            p += 1;
            retry = n;
            continue;
        }
        if (p < pattern.len) {
            var class_handled = false;
            if (pattern[p] == '[') {
                if (classMatch(pattern[p..], glyph(name, n).value)) |result| {
                    class_handled = true;
                    if (result.matched) {
                        p += result.consumed;
                        n += glyph(name, n).size;
                        continue;
                    }
                }
            }
            if (!class_handled and (pattern[p] == '?' or glyph(pattern, p).value == glyph(name, n).value)) {
                p += glyph(pattern, p).size;
                n += glyph(name, n).size;
                continue;
            }
        }
        if (star) |s| {
            retry += glyph(name, retry).size;
            n = retry;
            p = s + 1;
            continue;
        }
        return false;
    }
    while (p < pattern.len and pattern[p] == '*') : (p += 1) {}
    return p == pattern.len;
}

fn classMatch(pattern: []const u8, c: u32) ?struct { matched: bool, consumed: usize } {
    var i: usize = 1;
    const negate = i < pattern.len and pattern[i] == '!';
    if (negate) i += 1;
    const start = i;
    if (i < pattern.len and pattern[i] == ']') i += 1;
    while (i < pattern.len and pattern[i] != ']') : (i += 1) {}
    if (i == pattern.len or i == start) return null;
    const finish = i;
    i = start;
    var matched = false;
    while (i < finish) {
        const first = glyph(pattern, i);
        const next = i + first.size;
        if (next + 1 < finish and pattern[next] == '-') {
            const last = glyph(pattern, next + 1);
            if (c >= first.value and c <= last.value) matched = true;
            i = next + 1 + last.size;
        } else {
            if (c == first.value) matched = true;
            i = next;
        }
    }
    return .{ .matched = matched != negate, .consumed = finish + 1 };
}

pub fn expandGlob(allocator: Allocator, pattern: []const u8, limit: usize) ![][]u8 {
    var discovery = try Discovery.init(allocator, pattern, limit);
    defer discovery.deinit();
    while (try discovery.pollTurn(discovery_entries_per_turn) != .complete) {}
    return discovery.takePaths();
}

pub const Discovery = struct {
    const Frame = struct {
        directory: std.fs.Dir,
        iterator: std.fs.Dir.Iterator,
        base: []u8,
        component: usize,
        direct_done: bool = false,
    };
    allocator: Allocator,
    pattern: []u8,
    components: [discovery_max_depth][]const u8 = undefined,
    component_count: usize = 0,
    frames: [discovery_max_depth]Frame = undefined,
    depth: usize = 0,
    paths: std.ArrayList([]u8),
    max_paths: usize,
    visited: usize = 0,
    max_entries: usize = discovery_entries_per_episode,
    complete: bool = false,
    failure: ?anyerror = null,

    pub fn init(allocator: Allocator, pattern: []const u8, max_paths: usize) !Discovery {
        if (pattern.len == 0 or pattern.len > 16 * 1024 or std.mem.indexOfScalar(u8, pattern, 0) != null) return error.InvalidSource;
        if (max_paths == 0 or max_paths > 4096) return error.SourceLimit;
        const owned = try allocator.dupe(u8, pattern);
        var self = Discovery{ .allocator = allocator, .pattern = owned, .paths = std.ArrayList([]u8).init(allocator), .max_paths = max_paths };
        errdefer self.deinit();
        var parts = std.mem.tokenizeScalar(u8, owned, '/');
        while (parts.next()) |part| {
            if (self.component_count == discovery_max_depth) return error.DiscoveryDepthLimit;
            self.components[self.component_count] = part;
            self.component_count += 1;
        }
        if (self.component_count == 0) {
            self.complete = true;
        } else _ = try self.push(if (std.fs.path.isAbsolute(pattern)) "/" else ".", 0);
        return self;
    }

    fn push(self: *Discovery, base: []const u8, component: usize) !bool {
        if (self.depth == discovery_max_depth) return error.DiscoveryDepthLimit;
        const owned = try self.allocator.dupe(u8, base);
        errdefer self.allocator.free(owned);
        var directory = std.fs.cwd().openDir(base, .{ .iterate = true }) catch |err| {
            if (err == error.FileNotFound or err == error.NotDir) {
                self.allocator.free(owned);
                return false;
            }
            return err;
        };
        self.frames[self.depth] = .{ .directory = directory, .iterator = directory.iterate(), .base = owned, .component = component };
        self.depth += 1;
        return true;
    }

    fn pop(self: *Discovery) void {
        self.depth -= 1;
        const frame = &self.frames[self.depth];
        frame.directory.close();
        self.allocator.free(frame.base);
    }

    pub fn deinit(self: *Discovery) void {
        while (self.depth > 0) self.pop();
        for (self.paths.items) |path| self.allocator.free(path);
        self.paths.deinit();
        self.allocator.free(self.pattern);
    }

    pub fn pollTurn(self: *Discovery, budget: usize) !DiscoveryStatus {
        if (budget == 0 or budget > discovery_entries_per_turn or self.max_entries > discovery_entries_per_episode) return error.InvalidDiscoveryBudget;
        if (self.failure) |failure| return failure;
        if (self.complete) return .complete;
        return self.pollAdmitted(budget) catch |err| {
            self.failure = err;
            while (self.depth > 0) self.pop();
            return err;
        };
    }

    fn pollAdmitted(self: *Discovery, budget: usize) !DiscoveryStatus {
        var work: usize = 0;
        while (self.depth > 0 and work < budget) {
            work += 1;
            const frame = &self.frames[self.depth - 1];
            const component = self.components[frame.component];
            const direct = std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, "..");
            const name = if (direct) blk: {
                if (frame.direct_done) {
                    self.pop();
                    continue;
                }
                frame.direct_done = true;
                break :blk component;
            } else blk: {
                const entry = (try frame.iterator.next()) orelse {
                    self.pop();
                    continue;
                };
                if (self.visited >= self.max_entries) return error.DiscoveryEntryLimit;
                self.visited += 1;
                if (!matchComponent(component, entry.name)) continue;
                break :blk entry.name;
            };
            const path = try std.fs.path.join(self.allocator, &.{ frame.base, name });
            defer self.allocator.free(path);
            if (frame.component + 1 < self.component_count) {
                _ = try self.push(path, frame.component + 1);
            } else {
                const stat = frame.directory.statFile(name) catch |err| {
                    if (err == error.FileNotFound or err == error.NotDir) continue;
                    return err;
                };
                if (stat.kind != .file) continue;
                if (self.paths.items.len == self.max_paths) return error.SourceLimit;
                const owned_path = try self.allocator.dupe(u8, path);
                errdefer self.allocator.free(owned_path);
                try self.paths.append(owned_path);
            }
        }
        if (self.depth != 0) return .pending;
        std.mem.sort([]u8, self.paths.items, {}, struct {
            fn less(_: void, a: []u8, b: []u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.less);
        self.complete = true;
        return .complete;
    }

    pub fn takePaths(self: *Discovery) ![][]u8 {
        if (self.failure) |failure| return failure;
        if (!self.complete) return error.DiscoveryIncomplete;
        return self.paths.toOwnedSlice();
    }
};
