// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
// Does:  Holds a jail's configured log patterns and the file sources discovered from them, admitting each file once and polling all.
// Holds: A discovered path whose source id, pending path, or device and inode at that same path is already held is not admitted again.

const std = @import("std");
const records = @import("source_record.zig");
const config = @import("../config/config.zig");
const durable = @import("durable_file_source.zig");
const Discovery = @import("file_discovery.zig").Discovery;
const Allocator = std.mem.Allocator;
const FileSource = durable.FileSource;
const Start = durable.Start;
const Presence = durable.Presence;
const Framing = durable.Framing;
const WallClock = durable.WallClock;
const Resume = durable.Resume;
const RemovedVerdict = durable.RemovedVerdict;
const DiscoveryStatus = durable.DiscoveryStatus;
const discovery_entries_per_turn = durable.discovery_entries_per_turn;
const discovery_entries_per_episode = durable.discovery_entries_per_episode;
const openRegularAt = durable.openRegularAt;

pub const RestoreCallback = *const fn (source_id: []const u8, userdata: ?*anyopaque) anyerror!?Resume;

pub const FileSet = struct {
    const Spec = struct { pattern: []u8, start: Start, presence: Presence = .unknown, discovered: bool = false };
    allocator: Allocator,
    jail: []u8,
    specs: std.ArrayList(Spec),
    sources: std.ArrayList(FileSource),
    max_sources: usize = 4096,
    framing: Framing = .bytes,
    policy: config.TruncationPolicy = .refuse,
    health: records.Health = .waiting,
    wall_clock: WallClock = .{},
    restore: ?RestoreCallback = null,
    restore_userdata: ?*anyopaque = null,
    initialize_source: ?*const fn (*FileSource, ?*anyopaque) anyerror!void = null,
    initialize_userdata: ?*anyopaque = null,
    discovery: ?Discovery = null,
    discovery_spec: usize = 0,
    discovery_path: usize = 0,
    discovery_visited: usize = 0,
    discovery_matched: bool = false,
    presence_revision: u64 = 0,

    pub fn init(allocator: Allocator, jail: []const u8) !FileSet {
        return .{ .allocator = allocator, .jail = try allocator.dupe(u8, jail), .specs = std.ArrayList(Spec).init(allocator), .sources = std.ArrayList(FileSource).init(allocator) };
    }
    pub fn deinit(self: *FileSet) void {
        self.cancelDiscovery();
        for (self.sources.items) |*source| source.deinit();
        self.sources.deinit();
        for (self.specs.items) |spec| self.allocator.free(spec.pattern);
        self.specs.deinit();
        self.allocator.free(self.jail);
    }
    pub fn add(self: *FileSet, pattern: []const u8, start: Start) !void {
        if (self.discovery != null or self.discovery_spec != 0) return error.DiscoveryInProgress;
        if (pattern.len == 0 or pattern.len > 16 * 1024) return error.InvalidSource;
        if (self.specs.items.len >= self.max_sources) return error.SourceLimit;
        const owned = try self.allocator.dupe(u8, pattern);
        errdefer self.allocator.free(owned);
        try self.specs.append(.{ .pattern = owned, .start = start });
    }
    pub fn configuredCount(self: *const FileSet) usize {
        return self.specs.items.len;
    }
    // Holds: The returned pattern is owned by this FileSet and stays valid until its deinit.
    pub fn configuredStatus(self: *const FileSet, index: usize) ?struct { pattern: []const u8, presence: Presence } {
        if (index >= self.specs.items.len) return null;
        const spec = self.specs.items[index];
        return .{ .pattern = spec.pattern, .presence = spec.presence };
    }
    fn setPresence(self: *FileSet, index: usize, presence: Presence) void {
        const spec = &self.specs.items[index];
        if (spec.presence == presence) return;
        spec.presence = presence;
        self.presence_revision +%= 1;
    }
    pub fn addResume(self: *FileSet, path: []const u8, source_id: []const u8, checkpoint: Resume) !void {
        for (self.sources.items) |source| if (std.mem.eql(u8, source.source_id, source_id)) return error.DuplicateSource;
        if (self.sources.items.len >= self.max_sources) return error.SourceLimit;
        var source = try FileSource.init(self.allocator, path, source_id, .head, checkpoint);
        errdefer source.deinit();
        source.policy = self.policy;
        source.jail = self.jail;
        source.siblings = &self.sources;
        source.wall_clock = self.wall_clock;
        if (self.initialize_source) |initialize| try initialize(&source, self.initialize_userdata);
        try self.sources.append(source);
    }

    pub fn addProposal(self: *FileSet, path: []const u8, source_id: []const u8, proposal: Resume) !void {
        try self.addResume(path, source_id, proposal);
        self.sources.items[self.sources.items.len - 1].baseline_committed = false;
    }

    pub fn removedSuccessor(self: *const FileSet, index: usize) ?usize {
        const failure = self.sources.items[index].continuity_failure orelse return null;
        if (failure.kind != .replaced) return null;
        const inode = failure.observed_inode orelse return null;
        const device = failure.observed_device orelse return null;
        for (self.sources.items, 0..) |other, position| {
            if (position == index) continue;
            const saved = other.committed orelse continue;
            if (saved.device == device and saved.inode == inode) return position;
        }
        return null;
    }

    pub fn removedVerdict(self: *const FileSet, index: usize) ?RemovedVerdict {
        _ = self.removedSuccessor(index) orelse return null;
        const saved = self.sources.items[index].committed orelse return null;
        const size = saved.observed_size orelse return .unknown;
        if (saved.offset == size) return .drained;
        return if (saved.offset < size) .unread else .unknown;
    }

    pub fn discover(self: *FileSet) !void {
        while (try self.discoverTurn() != .complete) {}
    }

    pub fn cancelDiscovery(self: *FileSet) void {
        if (self.discovery) |*discovery| discovery.deinit();
        self.discovery = null;
        self.discovery_spec = 0;
        self.discovery_path = 0;
        self.discovery_visited = 0;
        self.discovery_matched = false;
    }

    pub fn discoverTurn(self: *FileSet) !DiscoveryStatus {
        errdefer |err| {
            self.setPresence(self.discovery_spec, .failed);
            self.health = if (err == error.AccessDenied) .permission_denied else .read_failed;
            self.cancelDiscovery();
        }
        if (self.discovery_spec == self.specs.items.len) {
            self.cancelDiscovery();
            self.health = if (self.sources.items.len == 0) .missing else .healthy;
            return .complete;
        }
        const spec = self.specs.items[self.discovery_spec];
        if (self.discovery == null) {
            self.discovery_matched = false;
            self.discovery = try Discovery.init(self.allocator, spec.pattern, self.max_sources);
            self.discovery.?.max_entries = discovery_entries_per_episode - self.discovery_visited;
            self.discovery_path = 0;
        }
        const discovery = &self.discovery.?;
        if (!discovery.complete) {
            _ = try discovery.pollTurn(discovery_entries_per_turn);
            return .pending;
        }
        if (self.discovery_path < discovery.paths.items.len) {
            const matched = try self.admitDiscovered(discovery.paths.items[self.discovery_path], if (spec.discovered) .head else spec.start);
            self.discovery_matched = self.discovery_matched or matched;
            self.discovery_path += 1;
            return .pending;
        }
        self.setPresence(self.discovery_spec, if (self.discovery_matched) .present else .missing);
        self.specs.items[self.discovery_spec].discovered = true;
        self.discovery_visited += discovery.visited;
        discovery.deinit();
        self.discovery = null;
        self.discovery_spec += 1;
        return .pending;
    }

    fn admitDiscovered(self: *FileSet, path: []const u8, start: Start) !bool {
        const f = openRegularAt(std.fs.cwd(), path) catch |err| {
            if (err == error.FileNotFound or err == error.NotDir) return false;
            self.health = if (err == error.AccessDenied) .permission_denied else .read_failed;
            return err;
        };
        var owns_descriptor = true;
        defer if (owns_descriptor) f.close();
        const stat = try std.posix.fstat(f.handle);
        const id = try std.fmt.allocPrint(self.allocator, "{s}:{s}:{d}:{d}", .{ self.jail, path, stat.dev, stat.ino });
        defer self.allocator.free(id);
        var found = false;
        for (self.sources.items) |*source| {
            if (std.mem.eql(u8, source.source_id, id) or (source.awaiting_path and std.mem.eql(u8, source.path, path))) {
                found = true;
                break;
            }
            if (source.committed) |known| {
                if (known.device == stat.dev and known.inode == stat.ino) {
                    if (std.mem.eql(u8, source.path, path)) {
                        found = true;
                        break;
                    }
                    const current = std.posix.fstatat(std.fs.cwd().fd, source.path, 0) catch |err| {
                        if (err == error.FileNotFound or err == error.NotDir) {
                            found = true;
                            break;
                        }
                        self.health = if (err == error.AccessDenied) .permission_denied else .read_failed;
                        return err;
                    };
                    if (current.dev != known.device or current.ino != known.inode) {
                        found = true;
                        break;
                    }
                }
            }
        }
        if (found) return true;
        if (self.sources.items.len >= self.max_sources) {
            self.health = .read_failed;
            return error.SourceLimit;
        }
        try self.sources.ensureUnusedCapacity(1);
        const checkpoint = if (self.restore) |restore| try restore(id, self.restore_userdata) else null;
        var source = try FileSource.init(self.allocator, path, id, start, checkpoint);
        errdefer source.deinit();
        source.policy = self.policy;
        source.jail = self.jail;
        source.siblings = &self.sources;
        source.wall_clock = self.wall_clock;
        if (checkpoint == null) source.framing = self.framing;
        for (self.sources.items) |previous| {
            if (std.mem.eql(u8, previous.path, path) and previous.in_operation) source.in_operation = true;
        }
        if (self.initialize_source) |initialize| try initialize(&source, self.initialize_userdata);
        owns_descriptor = false;
        try source.acceptDescriptor(f);
        const observed = source.committed.?;
        if (observed.device != stat.dev or observed.inode != stat.ino) return error.SourceChanged;
        self.sources.appendAssumeCapacity(source);
        return true;
    }
    pub fn poll(self: *FileSet, callback: records.AckCallback, userdata: ?*anyopaque) !usize {
        try self.discover();
        var delivered: usize = 0;
        for (self.sources.items) |*source| {
            if (source.poll(callback, userdata) catch |err| {
                self.health = source.health;
                return err;
            }) delivered += 1;
        }
        return delivered;
    }
};
