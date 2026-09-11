// SPDX-License-Identifier: AGPL-3.0-or-later
//! Original fixture bridge to the actual durable record store, never actions.
const std = @import("std");
const durable = @import("core/record_store.zig");
const pipeline = @import("core/record_pipeline.zig");
const records = @import("core/source_record.zig");
const Request = struct {
    jail: []const u8,
    shared_name: []const u8,
    occurrence: ?[]const u8 = null,
    checkpoint: []const u8 = "",
    shared_payload: ?[]const u8 = null,
    jail_revision: u64 = 0,
    shared_revision: u64 = 0,
    fail: bool = false,
};
const Proposal = struct {
    request: Request,
    published: bool = false,
    fn restore(_: ?[]const u8, _: ?*anyopaque) !void {}
    fn publish(context: ?*anyopaque) void {
        const self: *Proposal = @ptrCast(@alignCast(context.?));
        self.published = true;
    }
    fn release(_: ?*anyopaque) void {}
    fn prepare(_: records.Record, context: ?*anyopaque) !pipeline.Prepared {
        const self: *Proposal = @ptrCast(@alignCast(context.?));
        return .{ .checkpoint = self.request.checkpoint, .disposition = "original-ignore-observation", .shared_state = .{ .name = self.request.shared_name, .expected_revision = self.request.shared_revision, .payload = self.request.shared_payload }, .context = self, .publish = publish, .release = release };
    }
};
pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const args = try std.process.argsAlloc(a);
    if (args.len != 3) return error.InvalidArguments;
    const bytes = try std.fs.cwd().readFileAlloc(a, args[2], 9 * 1024 * 1024);
    const parsed = try std.json.parseFromSlice(Request, a, bytes, .{});
    const request = parsed.value;
    var store = try durable.Store.open(a, args[1]);
    defer store.close();
    var proposal = Proposal{ .request = request };
    var owner = pipeline.Pipeline{ .store = &store, .jail = request.jail, .processor = .{ .context = &proposal, .prepare = Proposal.prepare, .restore = Proposal.restore } };
    var outcome: []const u8 = "read";
    if (request.occurrence) |occurrence| {
        if (request.fail) store.fail_at = .after_shared_checkpoint;
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(occurrence, &hash, .{});
        try owner.restore(a);
        if (owner.revision != request.jail_revision) return error.InvalidFixtureRevision;
        outcome = "committed";
        pipeline.Pipeline.acknowledge(.{
            .source = "original-source",
            .occurrence = occurrence,
            .cursor = occurrence,
            .message = occurrence,
            .raw_hash = hash,
        }, &owner) catch |err| {
            outcome = @errorName(err);
        };
    }
    const jail = try store.snapshot(a, request.jail);
    const shared = try store.sharedSnapshot(a, request.shared_name);
    const cursor = try store.sourceCursor(a, request.jail, "original-source");
    try std.json.stringify(.{ .outcome = outcome, .jail = jail, .shared = shared, .cursor = cursor, .published = proposal.published, .ready = owner.ready }, .{}, std.io.getStdOut().writer());
}
