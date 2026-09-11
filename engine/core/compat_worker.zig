// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");

pub const Identity = struct {
    daemon_epoch: []const u8,
    worker_epoch: []const u8,
    config_generation: []const u8,
    jail_id: []const u8,
};
pub const LaunchOptions = struct {
    credentials: ?struct { uid: u32, gid: u32 } = null,
    locale: []const u8 = "C.UTF-8",
    timezone: ?[]const u8 = null,
};
pub const Outcome = enum { complete, no_match, unsupported, invalid_input, resource_limit, internal_error };
/// Bounded protocol labels survive response-buffer release. No component data,
/// decoded record, configuration value or arbitrary exception text is retained.
pub const ResultDiagnostic = struct {
    outcome: Outcome,
    stage_bytes: [128]u8 = [_]u8{0} ** 128,
    reason_bytes: [128]u8 = [_]u8{0} ** 128,
    stage_length: u8,
    reason_length: u8,

    pub fn stage(self: *const ResultDiagnostic) []const u8 {
        return self.stage_bytes[0..self.stage_length];
    }
    pub fn reason(self: *const ResultDiagnostic) []const u8 {
        return self.reason_bytes[0..self.reason_length];
    }
};
pub const Worker = struct {
    allocator: std.mem.Allocator,
    child: std.process.Child,
    identity_json: []u8,
    alive: bool = true,
    max_frame: usize = 1024 * 1024,
    stderr_bytes: usize = 0,
    last_result: ?ResultDiagnostic = null,

    /// Explicit interpreter/script paths come from the verified installation.
    /// The helper drops privilege before accepting its first frame.
    pub fn start(allocator: std.mem.Allocator, python: []const u8, script: []const u8, identity: Identity) !Worker {
        return startWithOptions(allocator, python, script, identity, .{});
    }

    pub fn startWithOptions(allocator: std.mem.Allocator, python: []const u8, script: []const u8, identity: Identity, options: LaunchOptions) !Worker {
        if (!std.fs.path.isAbsolute(python) or !std.fs.path.isAbsolute(script) or python.len > 4096 or script.len > 4096 or std.mem.indexOfScalar(u8, python, 0) != null or std.mem.indexOfScalar(u8, script, 0) != null) return error.InvalidHelperPath;
        inline for (std.meta.fields(Identity)) |field| {
            const value = @field(identity, field.name);
            if (value.len == 0 or value.len > 512 or std.mem.indexOfScalar(u8, value, 0) != null) return error.InvalidIdentity;
        }
        if (options.locale.len == 0 or options.locale.len > 128 or std.mem.indexOfScalar(u8, options.locale, 0) != null) return error.InvalidLocale;
        if (options.timezone) |zone| if (zone.len > 256 or std.mem.indexOfScalar(u8, zone, 0) != null) return error.InvalidTimezone;
        if (options.credentials) |credentials| {
            if (credentials.uid == 0 or credentials.gid == 0) return error.InvalidWorkerCredentials;
        } else if (std.os.linux.geteuid() == 0) return error.MissingWorkerCredentials;
        const identity_json = try std.json.stringifyAlloc(allocator, identity, .{});
        var transferred = false;
        errdefer if (!transferred) allocator.free(identity_json);
        const argv = [_][]const u8{ python, "-I", "-B", script, "--stdio", "--daemon-epoch", identity.daemon_epoch, "--worker-epoch", identity.worker_epoch, "--config-generation", identity.config_generation, "--jail-id", identity.jail_id };
        var arguments = std.ArrayList([]const u8).init(allocator);
        defer arguments.deinit();
        try arguments.appendSlice(&argv);
        var uid_text: [10]u8 = undefined;
        var gid_text: [10]u8 = undefined;
        if (options.credentials) |credentials| {
            try arguments.appendSlice(&.{ "--uid", try std.fmt.bufPrint(&uid_text, "{d}", .{credentials.uid}), "--gid", try std.fmt.bufPrint(&gid_text, "{d}", .{credentials.gid}) });
        }
        var child = std.process.Child.init(arguments.items, allocator);
        child.pgid = 0;
        child.stdin_behavior = .Pipe;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        var environment = std.process.EnvMap.init(allocator);
        defer environment.deinit();
        try environment.put("LANG", options.locale);
        try environment.put("LC_ALL", options.locale);
        if (options.timezone) |zone| try environment.put("TZ", zone);
        try environment.put("PATH", "/usr/bin:/bin");
        child.env_map = &environment;
        try child.spawn();
        // Child.wait does not need argv/env_map; never retain stack pointers.
        child.argv = &.{};
        child.env_map = null;
        var self = Worker{ .allocator = allocator, .child = child, .identity_json = identity_json };
        transferred = true;
        errdefer self.stop();
        for ([_]std.fs.File{ child.stdin.?, child.stdout.?, child.stderr.? }) |file| {
            const flags = try std.posix.fcntl(file.handle, std.posix.F.GETFL, 0);
            _ = try std.posix.fcntl(file.handle, std.posix.F.SETFL, flags | @as(u32, @bitCast(std.posix.O{ .NONBLOCK = true })));
        }
        return self;
    }

    pub fn stop(self: *Worker) void {
        if (!self.alive) return;
        std.posix.kill(-self.child.id, std.posix.SIG.KILL) catch {};
        _ = self.child.wait() catch {};
        self.alive = false;
        self.allocator.free(self.identity_json);
    }

    fn drainErrors(self: *Worker) !void {
        var bytes: [1024]u8 = undefined;
        const n = std.posix.read(self.child.stderr.?.handle, &bytes) catch |err| switch (err) {
            error.WouldBlock => return,
            else => return err,
        };
        self.stderr_bytes += n;
        if (self.stderr_bytes > 4096) return error.HelperDiagnosticLimit;
    }

    fn tick(self: *Worker, timer: *std.time.Timer, deadline_ms: u64, fd: std.posix.fd_t, events: i16) !void {
        if (timer.read() / std.time.ns_per_ms >= deadline_ms) return error.HelperTimeout;
        try self.drainErrors();
        var pollers = [_]std.posix.pollfd{
            .{ .fd = fd, .events = events, .revents = 0 },
            .{ .fd = self.child.stderr.?.handle, .events = std.posix.POLL.IN, .revents = 0 },
        };
        _ = try std.posix.poll(&pollers, 5);
    }

    fn writeAll(self: *Worker, bytes: []const u8, timer: *std.time.Timer, deadline_ms: u64) !void {
        var offset: usize = 0;
        while (offset < bytes.len) {
            try self.tick(timer, deadline_ms, self.child.stdin.?.handle, std.posix.POLL.OUT);
            const n = std.posix.write(self.child.stdin.?.handle, bytes[offset..]) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => return err,
            };
            if (n == 0) return error.HelperClosed;
            offset += n;
        }
    }

    fn readAll(self: *Worker, bytes: []u8, timer: *std.time.Timer, deadline_ms: u64) !void {
        var offset: usize = 0;
        while (offset < bytes.len) {
            try self.tick(timer, deadline_ms, self.child.stdout.?.handle, std.posix.POLL.IN);
            const n = std.posix.read(self.child.stdout.?.handle, bytes[offset..]) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => return err,
            };
            if (n == 0) return error.HelperClosed;
            offset += n;
        }
    }

    /// A transport failure kills this worker. Callers must restore the last
    /// committed context in a new worker before retrying the unacknowledged record.
    pub fn exchange(self: *Worker, envelope: []const u8, deadline_ms: u64) ![]u8 {
        self.last_result = null;
        if (!self.alive) return error.HelperClosed;
        errdefer self.stop();
        if (envelope.len == 0 or envelope.len > self.max_frame or deadline_ms == 0 or deadline_ms > 60000) return error.InvalidRequest;
        var expected = try std.json.parseFromSlice(Identity, self.allocator, self.identity_json, .{});
        defer expected.deinit();
        var request = try std.json.parseFromSlice(std.json.Value, self.allocator, envelope, .{ .max_value_len = self.max_frame });
        defer request.deinit();
        if (request.value != .object) return error.InvalidRequest;
        inline for (std.meta.fields(Identity)) |field| {
            const item = request.value.object.get(field.name) orelse return error.InvalidRequest;
            if (item != .string or !std.mem.eql(u8, item.string, @field(expected.value, field.name))) return error.InvalidRequest;
        }
        var timer = try std.time.Timer.start();
        var header: [4]u8 = undefined;
        std.mem.writeInt(u32, &header, @intCast(envelope.len), .big);
        try self.writeAll(&header, &timer, deadline_ms);
        try self.writeAll(envelope, &timer, deadline_ms);
        try self.readAll(&header, &timer, deadline_ms);
        const length = std.mem.readInt(u32, &header, .big);
        if (length == 0 or length > self.max_frame) return error.InvalidResponse;
        const response = try self.allocator.alloc(u8, length);
        errdefer self.allocator.free(response);
        try self.readAll(response, &timer, deadline_ms);
        self.last_result = try validateResponse(self.allocator, envelope, response);
        return response;
    }
};

fn validateResponse(allocator: std.mem.Allocator, request: []const u8, response: []const u8) !ResultDiagnostic {
    var sent = try std.json.parseFromSlice(std.json.Value, allocator, request, .{ .max_value_len = 1024 * 1024 });
    defer sent.deinit();
    var received = try std.json.parseFromSlice(std.json.Value, allocator, response, .{ .max_value_len = 1024 * 1024 });
    defer received.deinit();
    if (sent.value != .object or received.value != .object or received.value.object.count() != 10) return error.InvalidResponse;
    const version = received.value.object.get("wire_version") orelse return error.InvalidResponse;
    if (version != .integer or version.integer != 1) return error.InvalidResponse;
    const kind = received.value.object.get("kind") orelse return error.InvalidResponse;
    if (kind != .string or !std.mem.eql(u8, kind.string, "result")) return error.InvalidResponse;
    for ([_][]const u8{ "request_id", "daemon_epoch", "worker_epoch", "config_generation", "jail_id", "sequence" }) |key| {
        const before = sent.value.object.get(key) orelse return error.InvalidRequest;
        const after = received.value.object.get(key) orelse return error.InvalidResponse;
        if (before != .string or after != .string or !std.mem.eql(u8, before.string, after.string)) return error.StaleResponse;
    }
    try finitePayload(received.value, 0);
    const capabilities = received.value.object.get("capabilities") orelse return error.InvalidResponse;
    const payload = received.value.object.get("payload") orelse return error.InvalidResponse;
    if (capabilities != .array or capabilities.array.items.len != 0 or payload != .object or payload.object.count() != 4) return error.InvalidResponse;
    for ([_][]const u8{ "outcome", "stage", "reason" }) |key| {
        const field = payload.object.get(key) orelse return error.InvalidResponse;
        if (field != .string or field.string.len == 0 or field.string.len > 128) return error.InvalidResponse;
        for (field.string) |character| {
            if (!std.ascii.isAlphanumeric(character) and character != '_' and character != '-' and character != '.') return error.InvalidResponse;
        }
    }
    const outcome = payload.object.get("outcome").?.string;
    const known = std.meta.stringToEnum(Outcome, outcome) orelse return error.InvalidResponse;
    const data = payload.object.get("data") orelse return error.InvalidResponse;
    if (data != .object) return error.InvalidResponse;
    const stage = payload.object.get("stage").?.string;
    const reason = payload.object.get("reason").?.string;
    var diagnostic = ResultDiagnostic{ .outcome = known, .stage_length = @intCast(stage.len), .reason_length = @intCast(reason.len) };
    @memcpy(diagnostic.stage_bytes[0..stage.len], stage);
    @memcpy(diagnostic.reason_bytes[0..reason.len], reason);
    return diagnostic;
}

fn finitePayload(value: std.json.Value, depth: usize) !void {
    if (depth > 64) return error.InvalidResponse;
    switch (value) {
        .float => |number| if (!std.math.isFinite(number)) return error.InvalidResponse,
        .array => |items| for (items.items) |item| try finitePayload(item, depth + 1),
        .object => |object| {
            var it = object.iterator();
            while (it.next()) |item| try finitePayload(item.value_ptr.*, depth + 1);
        },
        else => {},
    }
}

const test_request = "{\"wire_version\":1,\"kind\":\"hello\",\"request_id\":\"r\",\"daemon_epoch\":\"d\",\"worker_epoch\":\"w\",\"config_generation\":\"g\",\"jail_id\":\"j\",\"sequence\":\"0\",\"capabilities\":[],\"payload\":{}}";

test "compat worker: framed replies, stale identities, EOF and deadlines" {
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const script = try std.fs.path.join(allocator, &.{ root, "helper.py" });
    defer allocator.free(script);
    const identity = Identity{ .daemon_epoch = "d", .worker_epoch = "w", .config_generation = "g", .jail_id = "j" };
    const prelude =
        \\import json,sys,time
        \\n=int.from_bytes(sys.stdin.buffer.read(4),'big')
        \\v=json.loads(sys.stdin.buffer.read(n))
        \\v['kind']='result'
        \\v['payload']={'outcome':'complete','stage':'test','reason':'echo','data':{}}
        \\
    ;
    try temp.dir.writeFile(.{ .sub_path = "helper.py", .data = prelude ++ "data=json.dumps(v).encode();sys.stdout.buffer.write(len(data).to_bytes(4,'big')+data);sys.stdout.buffer.flush()\n" });
    var worker = try Worker.start(allocator, "/usr/bin/python3", script, identity);
    defer worker.stop();
    const response = try worker.exchange(test_request, 2000);
    defer allocator.free(response);
    _ = try validateResponse(allocator, test_request, response);
    try std.testing.expectEqual(Outcome.complete, worker.last_result.?.outcome);
    worker.stop();
    try temp.dir.writeFile(.{ .sub_path = "helper.py", .data = prelude ++ "v['payload']={'outcome':'invalid_input','stage':'journal_time','reason':'journal_timestamp_range','data':{}};data=json.dumps(v).encode();sys.stdout.buffer.write(len(data).to_bytes(4,'big')+data);sys.stdout.buffer.flush()\n" });
    worker = try Worker.start(allocator, "/usr/bin/python3", script, identity);
    const rejected = try worker.exchange(test_request, 2000);
    allocator.free(rejected);
    try std.testing.expectEqual(Outcome.invalid_input, worker.last_result.?.outcome);
    try std.testing.expectEqualStrings("journal_time", worker.last_result.?.stage());
    try std.testing.expectEqualStrings("journal_timestamp_range", worker.last_result.?.reason());
    worker.stop();
    try std.testing.expectError(error.HelperClosed, worker.exchange(test_request, 2000));
    try std.testing.expect(worker.last_result == null);
    try temp.dir.writeFile(.{ .sub_path = "helper.py", .data = prelude ++ "v['payload']['reason']='ordinary text';data=json.dumps(v).encode();sys.stdout.buffer.write(len(data).to_bytes(4,'big')+data);sys.stdout.buffer.flush()\n" });
    worker = try Worker.start(allocator, "/usr/bin/python3", script, identity);
    try std.testing.expectError(error.InvalidResponse, worker.exchange(test_request, 2000));
    try std.testing.expect(worker.last_result == null);
    try temp.dir.writeFile(.{ .sub_path = "helper.py", .data = prelude ++ "v['worker_epoch']='old';data=json.dumps(v).encode();sys.stdout.buffer.write(len(data).to_bytes(4,'big')+data);sys.stdout.buffer.flush()\n" });
    worker = try Worker.start(allocator, "/usr/bin/python3", script, identity);
    try std.testing.expectError(error.StaleResponse, worker.exchange(test_request, 2000));
    try std.testing.expect(!worker.alive);
    try std.testing.expect(worker.last_result == null);
    try temp.dir.writeFile(.{ .sub_path = "helper.py", .data = prelude ++ "sys.stdout.buffer.write(b'\\x00\\x00');sys.stdout.buffer.flush()\n" });
    worker = try Worker.start(allocator, "/usr/bin/python3", script, identity);
    try std.testing.expectError(error.HelperClosed, worker.exchange(test_request, 2000));
    try std.testing.expect(!worker.alive);
    try temp.dir.writeFile(.{ .sub_path = "helper.py", .data = prelude ++ "time.sleep(5)\n" });
    worker = try Worker.start(allocator, "/usr/bin/python3", script, identity);
    var timer = try std.time.Timer.start();
    try std.testing.expectError(error.HelperTimeout, worker.exchange(test_request, 100));
    try std.testing.expect(timer.read() < 2 * std.time.ns_per_s);
    try std.testing.expect(!worker.alive);
}

fn testEnvelope(allocator: std.mem.Allocator, kind: []const u8, sequence: []const u8, payload: anytype) ![]u8 {
    return std.json.stringifyAlloc(allocator, .{ .wire_version = 1, .kind = kind, .request_id = sequence, .daemon_epoch = "d", .worker_epoch = "w", .config_generation = "g", .jail_id = "j", .sequence = sequence, .capabilities = [_]bool{}, .payload = payload }, .{});
}

test "compat worker: actual Python helper handshake and exact duration response" {
    const allocator = std.testing.allocator;
    const path = try std.fs.cwd().realpathAlloc(allocator, "engine/compat/worker.py");
    defer allocator.free(path);
    var worker = try Worker.start(allocator, "/usr/bin/python3", path, .{ .daemon_epoch = "d", .worker_epoch = "w", .config_generation = "g", .jail_id = "j" });
    defer worker.stop();
    const hello = try worker.exchange(test_request, 2000);
    defer allocator.free(hello);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, hello, .{});
    defer parsed.deinit();
    const payload = parsed.value.object.get("payload").?.object;
    try std.testing.expectEqualStrings("complete", payload.get("outcome").?.string);
    const data = payload.get("data").?.object;
    try std.testing.expect(data.get("uid").?.integer != 0);
    const configuration = try testEnvelope(allocator, "configure", "1", .{ .profile_hash = data.get("profile_hash").?.string, .encoding = "utf-8", .date_patterns = [_][]const u8{"EPOCH"}, .reference_year = 2026, .default_tz = "UTC" });
    defer allocator.free(configuration);
    const configured = try worker.exchange(configuration, 2000);
    defer allocator.free(configured);
    var configured_json = try std.json.parseFromSlice(std.json.Value, allocator, configured, .{});
    defer configured_json.deinit();
    try std.testing.expectEqualStrings("complete", configured_json.value.object.get("payload").?.object.get("outcome").?.string);
    const request = try testEnvelope(allocator, "record", "2", .{ .operation = "duration", .text = "9007199254740993", .history = false });
    defer allocator.free(request);
    const result = try worker.exchange(request, 2000);
    defer allocator.free(result);
    var result_json = try std.json.parseFromSlice(std.json.Value, allocator, result, .{});
    defer result_json.deinit();
    const duration = result_json.value.object.get("payload").?.object.get("data").?.object;
    try std.testing.expectEqualStrings("integer", duration.get("representation").?.string);
    try std.testing.expectEqualStrings("9007199254740993", duration.get("value").?.string);
}

test "worker: actual ignore operation stages and restores profile-bound policy" {
    const allocator = std.testing.allocator;
    const path = try std.fs.cwd().realpathAlloc(allocator, "engine/compat/worker.py");
    defer allocator.free(path);
    var worker = try Worker.start(allocator, "/usr/bin/python3", path, .{ .daemon_epoch = "d", .worker_epoch = "w", .config_generation = "g", .jail_id = "j" });
    defer worker.stop();
    const hello = try worker.exchange(test_request, 2000);
    defer allocator.free(hello);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, hello, .{});
    defer parsed.deinit();
    const profile = parsed.value.object.get("payload").?.object.get("data").?.object.get("profile_hash").?.string;
    const config = .{ .ignoreself = false, .usedns = "no", .allowipv6 = "no", .ignoreip = [_][]const u8{"192.0.2.0/24"} };
    const request = try testEnvelope(allocator, "record", "1", .{ .operation = "ignore", .profile_hash = profile, .effective_config = config, .matched_identity = "192.0.2.7", .now_bits = "4059000000000000", .snapshot = null, .shared_snapshot = null, .ticket = null, .jail = null });
    defer allocator.free(request);
    const response = try worker.exchange(request, 2000);
    defer allocator.free(response);
    var staged = try std.json.parseFromSlice(std.json.Value, allocator, response, .{});
    defer staged.deinit();
    try std.testing.expectEqual(Outcome.complete, worker.last_result.?.outcome);
    try std.testing.expectEqualStrings("policy_staged", worker.last_result.?.reason());
    const data = staged.value.object.get("payload").?.object.get("data").?.object;
    try std.testing.expect(data.get("decisions").?.array.items[0].object.get("ignored").?.bool);
    const next = try testEnvelope(allocator, "record", "2", .{ .operation = "ignore", .profile_hash = profile, .effective_config = config, .matched_identity = "198.51.100.7", .now_bits = "4059000000000000", .snapshot = data.get("snapshot").?, .shared_snapshot = data.get("shared_snapshot").?, .ticket = null, .jail = null });
    defer allocator.free(next);
    const next_response = try worker.exchange(next, 2000);
    defer allocator.free(next_response);
    var restored = try std.json.parseFromSlice(std.json.Value, allocator, next_response, .{});
    defer restored.deinit();
    try std.testing.expectEqual(Outcome.complete, worker.last_result.?.outcome);
    try std.testing.expect(!restored.value.object.get("payload").?.object.get("data").?.object.get("decisions").?.array.items[0].object.get("ignored").?.bool);
}
