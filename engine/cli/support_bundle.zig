// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
const builtin = @import("builtin");
const shared = @import("shared");
const client = @import("cli");
const config_mod = @import("../config/native.zig");
const durable = @import("../core/record_store.zig");
const files = @import("../core/durable_file_source.zig");
const reload = @import("../runtime/native_reload.zig");
const ipc_auth = @import("../net/ipc_auth.zig");

pub const ExitClass = shared.ExitClass;
pub const default_config = "/etc/fail2zig/config.toml";
pub const bundle_schema: i64 = 1;
const default_log_lines: u16 = 200;
const max_log_lines: u16 = 2000;
const max_log_line_bytes = 1024;
const log_tail_bytes: u64 = 1024 * 1024;
const max_config_bytes = 16 * 1024 * 1024;
const max_pages: usize = 512;
const page_limit: u32 = 256;
const max_glob_matches = 4096;

pub const Options = struct {
    config: []const u8 = default_config,
    socket: ?[]const u8 = null,
    out: ?[]const u8 = null,
    include_addresses: bool = false,
    log_lines: u16 = default_log_lines,
    timeout_ms: u64 = 5000,
};

pub fn run(allocator: std.mem.Allocator, args: []const []const u8, version: []const u8, stdout: anytype, stderr: anytype) ExitClass {
    for (args) |arg| if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
        stdout.writeAll(usage_text) catch return .rejected;
        return .success;
    };
    const options = parseArgs(args, stderr) orelse return usage(stderr);
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    return execute(arena_state.allocator(), options, version, stdout, stderr);
}

fn parseArgs(args: []const []const u8, stderr: anytype) ?Options {
    var options: Options = .{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--include-addresses")) {
            options.include_addresses = true;
            continue;
        }
        const Flag = enum { config, socket, out, log_lines, timeout };
        const flag: Flag = if (std.mem.eql(u8, arg, "--config")) .config else if (std.mem.eql(u8, arg, "--socket")) .socket else if (std.mem.eql(u8, arg, "--out")) .out else if (std.mem.eql(u8, arg, "--log-lines")) .log_lines else if (std.mem.eql(u8, arg, "--timeout")) .timeout else {
            stderr.print("support-bundle: unknown argument '{s}'\n", .{arg[0..@min(arg.len, 64)]}) catch {};
            return null;
        };
        i += 1;
        if (i >= args.len) return null;
        const value = args[i];
        switch (flag) {
            .config => options.config = value,
            .socket => options.socket = value,
            .out => options.out = value,
            .log_lines => {
                const lines = std.fmt.parseInt(u16, value, 10) catch return null;
                if (lines > max_log_lines) {
                    stderr.print("support-bundle: --log-lines must be 0..{d}\n", .{max_log_lines}) catch {};
                    return null;
                }
                options.log_lines = lines;
            },
            .timeout => options.timeout_ms = std.fmt.parseInt(u64, value, 10) catch return null,
        }
    }
    return options;
}

const usage_text = client.args.help_support_bundle;

fn usage(stderr: anytype) ExitClass {
    stderr.writeAll(usage_text) catch {};
    return .usage;
}

const Value = std.json.Value;
const ObjectMap = std.json.ObjectMap;

const Bundle = struct {
    arena: std.mem.Allocator,
    socket_path: []const u8,
    timeout_ms: u64,
    failures: std.ArrayListUnmanaged([]const u8) = .empty,

    fn failed(self: *Bundle, name: []const u8, message: []const u8) !Value {
        try self.failures.append(self.arena, try std.fmt.allocPrint(self.arena, "{s}: {s}", .{ name, message }));
        var object = ObjectMap.init(self.arena);
        try object.put("error", .{ .string = message });
        return .{ .object = object };
    }
};

const Reply = union(enum) { value: Value, failed: []const u8 };

fn execute(arena: std.mem.Allocator, options: Options, version: []const u8, stdout: anytype, stderr: anytype) ExitClass {
    return collectAndWrite(arena, options, version, stdout, stderr) catch |err| {
        stderr.print("support-bundle: {s}\n", .{@errorName(err)}) catch {};
        return .rejected;
    };
}

fn collectAndWrite(arena: std.mem.Allocator, options: Options, version: []const u8, stdout: anytype, stderr: anytype) !ExitClass {
    const loaded: ?config_mod.Config = config_mod.Config.loadFile(arena, options.config) catch |err| blk: {
        stderr.print("support-bundle: config {s}: {s}; continuing with the daemon's view\n", .{ options.config, @errorName(err) }) catch {};
        break :blk null;
    };
    const socket_path = options.socket orelse if (loaded) |cfg| cfg.global.socket_path else client.socket.default_socket_path;
    var bundle = Bundle{ .arena = arena, .socket_path = socket_path, .timeout_ms = options.timeout_ms };

    var root = ObjectMap.init(arena);
    try root.put("bundle_schema", .{ .integer = bundle_schema });
    try root.put("created_utc", .{ .string = try utcStamp(arena, std.time.timestamp(), .iso) });
    try root.put("addresses", .{ .string = if (options.include_addresses) "included" else "hashed_per_bundle" });
    try root.put("client", try clientSection(arena, version));

    var daemon = ObjectMap.init(arena);
    try daemon.put("version", try section(&bundle, "daemon.version", request(&bundle, .{ .version = {} })));
    const status = request(&bundle, .{ .status = {} });
    try daemon.put("status", try section(&bundle, "daemon.status", status));
    try daemon.put("jails", try section(&bundle, "daemon.jails", request(&bundle, .{ .list_jails = {} })));
    const stats = request(&bundle, try queryCommand("stats", null));
    try daemon.put("continuity", try continuitySection(&bundle));
    const effective = request(&bundle, try queryCommand("config", null));
    try root.put("daemon", .{ .object = daemon });

    try root.put("config", try configSection(&bundle, options.config, loaded, effective));
    try root.put("state", try stateSection(&bundle, loaded));
    try root.put("kernel_readback", try readbackSection(&bundle, stats));
    try root.put("memory", try memorySection(&bundle, loaded, status));
    try root.put("log", try logSection(&bundle, loaded, options.log_lines));
    try root.put("host", try hostSection(&bundle));

    var redactor = Redactor{ .include_addresses = options.include_addresses, .log_paths = try logPaths(arena, loaded, effective) };
    std.crypto.random.bytes(&redactor.key);
    var tree: Value = .{ .object = root };
    try redactor.value(arena, &tree);

    const out_path = options.out orelse try std.fmt.allocPrint(arena, "fail2zig-support-{s}.json", .{try utcStamp(arena, std.time.timestamp(), .compact)});
    if (std.mem.eql(u8, out_path, "-")) {
        var buffered = std.io.bufferedWriter(stdout);
        try std.json.stringify(tree, .{ .whitespace = .indent_2 }, buffered.writer());
        try buffered.writer().writeByte('\n');
        try buffered.flush();
    } else {
        const file = std.fs.cwd().createFile(out_path, .{ .exclusive = true, .mode = 0o600 }) catch |err| {
            stderr.print("support-bundle: cannot create {s}: {s}\n", .{ out_path, @errorName(err) }) catch {};
            return .rejected;
        };
        defer file.close();
        var buffered = std.io.bufferedWriter(file.writer());
        try std.json.stringify(tree, .{ .whitespace = .indent_2 }, buffered.writer());
        try buffered.writer().writeByte('\n');
        try buffered.flush();
        try stdout.print("{s}\n", .{out_path});
    }
    for (bundle.failures.items) |message| stderr.print("support-bundle: incomplete section {s}\n", .{message}) catch {};
    return if (bundle.failures.items.len == 0) .success else .partial;
}

fn section(bundle: *Bundle, name: []const u8, reply: Reply) !Value {
    return switch (reply) {
        .value => |value| value,
        .failed => |message| bundle.failed(name, message),
    };
}

fn queryCommand(kind: []const u8, cursor: ?[]const u8) !shared.Command {
    var body_bytes: [shared.protocol.max_request_body]u8 = undefined;
    var stream = std.io.fixedBufferStream(&body_bytes);
    const limit: ?u32 = if (std.mem.eql(u8, kind, "continuity") or std.mem.eql(u8, kind, "firewall")) page_limit else null;
    try std.json.stringify(.{ .schema_version = @as(u32, 1), .kind = kind, .limit = limit, .cursor = cursor }, .{ .emit_null_optional_fields = false }, stream.writer());
    return .{ .query_v1 = try shared.Command.Body.init(stream.getWritten()) };
}

fn request(bundle: *Bundle, cmd: shared.Command) Reply {
    const arena = bundle.arena;
    var diag: client.socket.DiagBuf = .{};
    var connection = client.socket.connect(arena, bundle.socket_path, bundle.timeout_ms, &diag) catch
        return .{ .failed = arena.dupe(u8, diag.message()) catch "out of memory" };
    defer connection.close();
    const response = connection.sendCommand(cmd) catch
        return .{ .failed = arena.dupe(u8, connection.errorMessage()) catch "out of memory" };
    switch (response) {
        .ok => |ok| {
            const parsed = std.json.parseFromSliceLeaky(Value, arena, ok.payload, .{ .allocate = .alloc_always }) catch
                return .{ .failed = "malformed response from daemon" };
            return .{ .value = parsed };
        },
        .err => |e| return .{ .failed = std.fmt.allocPrint(arena, "daemon error {d}: {s}", .{ e.code, e.message }) catch "out of memory" },
    }
}

fn nextCursor(arena: std.mem.Allocator, page: Value) !?[]const u8 {
    if (page != .object) return error.MalformedPage;
    const next = page.object.get("next_cursor") orelse return null;
    return switch (next) {
        .null => null,
        .string => |text| try arena.dupe(u8, text),
        else => error.MalformedPage,
    };
}

fn pageItems(page: Value) ![]Value {
    if (page != .object) return error.MalformedPage;
    const items = page.object.get("items") orelse return error.MalformedPage;
    if (items != .array) return error.MalformedPage;
    return items.array.items;
}

fn continuitySection(bundle: *Bundle) !Value {
    var events = std.json.Array.init(bundle.arena);
    var cursor: ?[]const u8 = null;
    var pages: usize = 0;
    while (pages < max_pages) : (pages += 1) {
        const page = switch (request(bundle, try queryCommand("continuity", cursor))) {
            .value => |value| value,
            .failed => |message| return bundle.failed("daemon.continuity", message),
        };
        const items = pageItems(page) catch return bundle.failed("daemon.continuity", "malformed continuity page");
        try events.appendSlice(items);
        cursor = nextCursor(bundle.arena, page) catch return bundle.failed("daemon.continuity", "malformed continuity cursor");
        if (cursor == null) {
            var object = ObjectMap.init(bundle.arena);
            try object.put("events", .{ .array = events });
            return .{ .object = object };
        }
    }
    return bundle.failed("daemon.continuity", "continuity events exceed 512 pages");
}

fn hexValue(arena: std.mem.Allocator, bytes: [32]u8) !Value {
    return .{ .string = try arena.dupe(u8, &std.fmt.bytesToHex(bytes, .lower)) };
}

fn configSection(bundle: *Bundle, path: []const u8, loaded: ?config_mod.Config, effective: Reply) !Value {
    const arena = bundle.arena;
    var object = ObjectMap.init(arena);
    try object.put("effective", try section(bundle, "config.effective", effective));
    var file_digest: ?[32]u8 = null;
    if (std.fs.cwd().readFileAlloc(arena, path, max_config_bytes)) |bytes| {
        file_digest = reload.digestBytes(bytes);
        try object.put("file_sha256", try hexValue(arena, file_digest.?));
    } else |err| try object.put("file_sha256", try bundle.failed("config.file_sha256", @errorName(err)));
    const cfg = loaded orelse {
        try object.put("loaded", try bundle.failed("config.loaded", "configuration file could not be loaded"));
        return .{ .object = object };
    };
    var store = durable.Store.openReadOnly(arena, cfg.global.state_file) catch |err| {
        try object.put("loaded", try bundle.failed("config.loaded", @errorName(err)));
        return .{ .object = object };
    };
    defer store.close();
    const head = store.latestConfigGeneration() catch |err| {
        try object.put("loaded", try bundle.failed("config.loaded", @errorName(err)));
        return .{ .object = object };
    };
    if (head) |generation| {
        var loaded_object = ObjectMap.init(arena);
        try loaded_object.put("sha256", try hexValue(arena, generation.config_digest));
        try loaded_object.put("generation", try hexValue(arena, generation.generation));
        try loaded_object.put("published", .{ .bool = generation.published });
        try loaded_object.put("committed_us", .{ .integer = generation.committed_us });
        if (file_digest) |digest| try loaded_object.put("matches_file", .{ .bool = std.mem.eql(u8, &digest, &generation.config_digest) });
        try object.put("loaded", .{ .object = loaded_object });
    } else try object.put("loaded", .null);
    return .{ .object = object };
}

fn unsignedValue(arena: std.mem.Allocator, value: u64) !Value {
    if (std.math.cast(i64, value)) |fits| return .{ .integer = fits };
    return .{ .number_string = try std.fmt.allocPrint(arena, "{d}", .{value}) };
}

fn stateSection(bundle: *Bundle, loaded: ?config_mod.Config) !Value {
    const arena = bundle.arena;
    const cfg = loaded orelse return bundle.failed("state", "configuration file could not be loaded");
    var diagnostic: durable.OpenDiagnostic = .{};
    var store = durable.Store.openReadOnlyDetailed(arena, cfg.global.state_file, &diagnostic) catch |err| {
        const stage = if (diagnostic.stage) |stage| @tagName(stage) else "open";
        return bundle.failed("state", try std.fmt.allocPrint(arena, "{s} at {s}", .{ @errorName(err), stage }));
    };
    defer store.close();
    const footprint = store.footprint(arena) catch |err| return bundle.failed("state", @errorName(err));
    var object = ObjectMap.init(arena);
    try object.put("schema_version", .{ .integer = store.schema_version });
    try object.put("page_size", try unsignedValue(arena, footprint.page_size));
    try object.put("page_count", try unsignedValue(arena, footprint.page_count));
    try object.put("freelist_count", try unsignedValue(arena, footprint.freelist_count));
    try object.put("file_bytes", try unsignedValue(arena, footprint.page_size * footprint.page_count));
    var tables = std.json.Array.init(arena);
    for (footprint.tables) |table| {
        var row = ObjectMap.init(arena);
        try row.put("name", .{ .string = table.name });
        try row.put("rows", try unsignedValue(arena, table.rows));
        try row.put("bytes", try unsignedValue(arena, table.bytes));
        try tables.append(.{ .object = row });
    }
    try object.put("tables", .{ .array = tables });
    return .{ .object = object };
}

fn readbackSection(bundle: *Bundle, stats: Reply) !Value {
    const arena = bundle.arena;
    var object = ObjectMap.init(arena);
    try object.put("stats", try section(bundle, "kernel_readback.stats", stats));
    var v4: u64 = 0;
    var v6: u64 = 0;
    var observation: Value = .null;
    var cursor: ?[]const u8 = null;
    var pages: usize = 0;
    while (pages < max_pages) : (pages += 1) {
        const page = switch (request(bundle, try queryCommand("firewall", cursor))) {
            .value => |value| value,
            .failed => |message| {
                try object.put("observation", try bundle.failed("kernel_readback.observation", message));
                return .{ .object = object };
            },
        };
        const items = pageItems(page) catch {
            try object.put("observation", try bundle.failed("kernel_readback.observation", "malformed firewall page"));
            return .{ .object = object };
        };
        for (items) |item| switch (familyOf(item)) {
            .v4 => v4 += 1,
            .v6 => v6 += 1,
            .unknown => {},
        };
        if (pages == 0) {
            observation = page;
            _ = observation.object.orderedRemove("items");
            _ = observation.object.orderedRemove("next_cursor");
        }
        cursor = nextCursor(arena, page) catch {
            try object.put("observation", try bundle.failed("kernel_readback.observation", "malformed firewall cursor"));
            return .{ .object = object };
        };
        if (cursor == null) {
            try object.put("observation", observation);
            var counts = ObjectMap.init(arena);
            try counts.put("v4", try unsignedValue(arena, v4));
            try counts.put("v6", try unsignedValue(arena, v6));
            try object.put("sampled_elements_by_family", .{ .object = counts });
            return .{ .object = object };
        }
    }
    try object.put("observation", try bundle.failed("kernel_readback.observation", "firewall observation exceeds 512 pages"));
    return .{ .object = object };
}

fn familyOf(item: Value) enum { v4, v6, unknown } {
    if (item != .object) return .unknown;
    const scope = item.object.get("scope") orelse return .unknown;
    if (scope != .object) return .unknown;
    const family = scope.object.get("family") orelse return .unknown;
    if (family != .string) return .unknown;
    if (std.mem.eql(u8, family.string, "v4")) return .v4;
    if (std.mem.eql(u8, family.string, "v6")) return .v6;
    return .unknown;
}

fn daemonPid(bundle: *Bundle) !i32 {
    var diag: client.socket.DiagBuf = .{};
    var connection = client.socket.connect(bundle.arena, bundle.socket_path, bundle.timeout_ms, &diag) catch return error.DaemonUnreachable;
    defer connection.close();
    var cred: ipc_auth.PeerCred = undefined;
    var len: std.posix.socklen_t = @sizeOf(ipc_auth.PeerCred);
    const rc = std.os.linux.getsockopt(connection.fd, std.os.linux.SOL.SOCKET, std.os.linux.SO.PEERCRED, @ptrCast(&cred), &len);
    if (std.os.linux.E.init(rc) != .SUCCESS or len != @sizeOf(ipc_auth.PeerCred)) return error.PeerCredentialsUnavailable;
    if (cred.pid <= 0) return error.PeerOutsidePidNamespace;
    return cred.pid;
}

fn procFields(arena: std.mem.Allocator, path: []const u8, names: []const []const u8, object: *ObjectMap) !void {
    const bytes = try std.fs.cwd().readFileAlloc(arena, path, 64 * 1024);
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const key = line[0..colon];
        for (names) |name| if (std.mem.eql(u8, key, name)) {
            var words = std.mem.tokenizeAny(u8, line[colon + 1 ..], " \t");
            const number = words.next() orelse return error.MalformedProcFile;
            const amount = std.fmt.parseInt(u64, number, 10) catch return error.MalformedProcFile;
            const field_name = if (words.next()) |unit| if (std.mem.eql(u8, unit, "kB")) try std.fmt.allocPrint(arena, "{s}_kib", .{name}) else return error.MalformedProcFile else name;
            try object.put(field_name, try unsignedValue(arena, amount));
        };
    }
}

fn memorySection(bundle: *Bundle, loaded: ?config_mod.Config, status: Reply) !Value {
    const arena = bundle.arena;
    var object = ObjectMap.init(arena);
    if (loaded) |cfg| {
        try object.put("native_memory_ceiling_mb", .{ .integer = cfg.global.native_memory_ceiling_mb });
        try object.put("native_fd_ceiling", .{ .integer = cfg.global.native_fd_ceiling });
    }
    if (status == .value and status.value == .object) if (status.value.object.get("memory_admission_bytes")) |planned| try object.put("memory_admission_bytes", planned);
    const pid = daemonPid(bundle) catch |err| {
        try object.put("daemon_process", try bundle.failed("memory.daemon_process", @errorName(err)));
        return .{ .object = object };
    };
    var process = ObjectMap.init(arena);
    const path = try std.fmt.allocPrint(arena, "/proc/{d}/status", .{pid});
    procFields(arena, path, &.{ "VmRSS", "VmHWM", "VmSize", "Threads" }, &process) catch |err| {
        try object.put("daemon_process", try bundle.failed("memory.daemon_process", @errorName(err)));
        return .{ .object = object };
    };
    try object.put("daemon_process", .{ .object = process });
    return .{ .object = object };
}

fn isLevelLine(line: []const u8) bool {
    return std.mem.startsWith(u8, line, "warning:") or std.mem.startsWith(u8, line, "warning(") or
        std.mem.startsWith(u8, line, "error:") or std.mem.startsWith(u8, line, "error(");
}

fn keepLast(arena: std.mem.Allocator, bytes: []const u8, limit: u16, filter: bool, skip_first: bool) !Value {
    var lines = std.json.Array.init(arena);
    var split = std.mem.splitScalar(u8, bytes, '\n');
    if (skip_first) _ = split.next();
    var selected = std.ArrayListUnmanaged([]const u8).empty;
    while (split.next()) |line| {
        if (line.len == 0) continue;
        if (filter and !isLevelLine(line)) continue;
        try selected.append(arena, line[0..@min(line.len, max_log_line_bytes)]);
    }
    const start = selected.items.len -| limit;
    for (selected.items[start..]) |line| try lines.append(.{ .string = line });
    return .{ .array = lines };
}

fn logSection(bundle: *Bundle, loaded: ?config_mod.Config, limit: u16) !Value {
    const arena = bundle.arena;
    var object = ObjectMap.init(arena);
    const cfg = loaded orelse return bundle.failed("log", "configuration file could not be loaded");
    if (limit == 0) {
        try object.put("lines", .{ .array = std.json.Array.init(arena) });
        return .{ .object = object };
    }
    if (std.mem.eql(u8, cfg.global.log_target, "stderr")) {
        try object.put("source", .{ .string = "journal" });
        const lines_arg = try std.fmt.allocPrint(arena, "--lines={d}", .{limit});
        const result = std.process.Child.run(.{
            .allocator = arena,
            .argv = &.{ config_mod.journalctl_path, "--unit=fail2zig.service", "--priority=warning", lines_arg, "--output=short-iso", "--no-pager", "--quiet" },
            .max_output_bytes = @as(usize, max_log_lines) * max_log_line_bytes * 2,
        }) catch |err| return bundle.failed("log", @errorName(err));
        if (result.term != .Exited or result.term.Exited != 0) {
            const reason = std.mem.trim(u8, result.stderr, &std.ascii.whitespace);
            const first = reason[0 .. std.mem.indexOfScalar(u8, reason, '\n') orelse reason.len];
            return bundle.failed("log", if (first.len == 0) "journalctl did not exit cleanly" else try std.fmt.allocPrint(arena, "journalctl: {s}", .{first}));
        }
        try object.put("lines", try keepLast(arena, result.stdout, limit, false, false));
        return .{ .object = object };
    }
    try object.put("source", .{ .string = "file" });
    const file = std.fs.openFileAbsolute(cfg.global.log_target, .{}) catch |err| return bundle.failed("log", @errorName(err));
    defer file.close();
    const size = file.getEndPos() catch |err| return bundle.failed("log", @errorName(err));
    const start = size -| log_tail_bytes;
    file.seekTo(start) catch |err| return bundle.failed("log", @errorName(err));
    const buffer = try arena.alloc(u8, @intCast(size - start));
    const read = file.readAll(buffer) catch |err| return bundle.failed("log", @errorName(err));
    try object.put("lines", try keepLast(arena, buffer[0..read], limit, true, start != 0));
    return .{ .object = object };
}

fn hostSection(bundle: *Bundle) !Value {
    const arena = bundle.arena;
    var object = ObjectMap.init(arena);
    const uts = std.posix.uname();
    try object.put("kernel", .{ .string = try arena.dupe(u8, std.mem.sliceTo(&uts.release, 0)) });
    try object.put("machine", .{ .string = try arena.dupe(u8, std.mem.sliceTo(&uts.machine, 0)) });
    if (std.Thread.getCpuCount()) |count| {
        try object.put("cpus", try unsignedValue(arena, count));
    } else |err| try object.put("cpus", try bundle.failed("host.cpus", @errorName(err)));
    var memory = ObjectMap.init(arena);
    if (procFields(arena, "/proc/meminfo", &.{ "MemTotal", "MemAvailable" }, &memory)) {
        try object.put("memory", .{ .object = memory });
    } else |err| try object.put("memory", try bundle.failed("host.memory", @errorName(err)));
    const nft = std.process.Child.run(.{ .allocator = arena, .argv = &.{ "nft", "--version" }, .max_output_bytes = 4096 }) catch |err| {
        try object.put("nft", try bundle.failed("host.nft", @errorName(err)));
        return .{ .object = object };
    };
    if (nft.term != .Exited or nft.term.Exited != 0) {
        try object.put("nft", try bundle.failed("host.nft", "nft --version did not exit cleanly"));
    } else try object.put("nft", .{ .string = std.mem.trim(u8, nft.stdout, " \t\r\n") });
    return .{ .object = object };
}

fn clientSection(arena: std.mem.Allocator, version: []const u8) !Value {
    var object = ObjectMap.init(arena);
    try object.put("version", .{ .string = version });
    try object.put("target", .{ .string = try std.fmt.allocPrint(arena, "{s}-{s}-{s}", .{ @tagName(builtin.cpu.arch), @tagName(builtin.os.tag), @tagName(builtin.abi) }) });
    try object.put("optimize", .{ .string = @tagName(builtin.mode) });
    return .{ .object = object };
}

const StampStyle = enum { iso, compact };

fn utcStamp(arena: std.mem.Allocator, seconds: i64, style: StampStyle) ![]const u8 {
    const epoch = std.time.epoch.EpochSeconds{ .secs = std.math.cast(u64, seconds) orelse return error.ClockBeforeEpoch };
    const day = epoch.getEpochDay().calculateYearDay();
    const month = day.calculateMonthDay();
    const clock = epoch.getDaySeconds();
    const values = .{ day.year, month.month.numeric(), month.day_index + 1, clock.getHoursIntoDay(), clock.getMinutesIntoHour(), clock.getSecondsIntoMinute() };
    return switch (style) {
        .iso => std.fmt.allocPrint(arena, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", values),
        .compact => std.fmt.allocPrint(arena, "{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}Z", values),
    };
}

fn logPaths(arena: std.mem.Allocator, loaded: ?config_mod.Config, effective: Reply) ![]const []const u8 {
    var paths: std.ArrayListUnmanaged([]const u8) = .empty;
    if (loaded) |cfg| for (cfg.jails) |jail| for (jail.logpath) |pattern| try appendPattern(arena, &paths, pattern);
    if (effective == .value and effective.value == .object) if (effective.value.object.get("jails")) |jails| if (jails == .array) for (jails.array.items) |jail| {
        if (jail != .object) continue;
        const patterns = jail.object.get("logpath") orelse continue;
        if (patterns != .array) continue;
        for (patterns.array.items) |pattern| if (pattern == .string) try appendPattern(arena, &paths, pattern.string);
    };
    return paths.items;
}

fn appendPattern(arena: std.mem.Allocator, paths: *std.ArrayListUnmanaged([]const u8), pattern: []const u8) !void {
    try paths.append(arena, pattern);
    const expanded = files.expandGlob(arena, pattern, max_glob_matches) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return,
    };
    for (expanded) |path| try paths.append(arena, path);
}

const Redactor = struct {
    key: [32]u8 = undefined,
    include_addresses: bool,
    log_paths: []const []const u8,

    fn value(self: *const Redactor, arena: std.mem.Allocator, node: *Value) !void {
        switch (node.*) {
            .string => |original| node.* = .{ .string = try self.redactText(arena, original) },
            .array => |*array| for (array.items) |*item| try self.value(arena, item),
            .object => |*object| for (object.values()) |*item| try self.value(arena, item),
            else => {},
        }
    }

    fn isDelimiter(byte: u8) bool {
        return std.ascii.isWhitespace(byte) or std.mem.indexOfScalar(u8, "\"'`,;()[]{}<>=|", byte) != null;
    }

    fn redactText(self: *const Redactor, arena: std.mem.Allocator, input: []const u8) ![]const u8 {
        var out: std.ArrayListUnmanaged(u8) = .empty;
        var i: usize = 0;
        while (i < input.len) {
            if (isDelimiter(input[i])) {
                try out.append(arena, input[i]);
                i += 1;
                continue;
            }
            const start = i;
            while (i < input.len and !isDelimiter(input[i])) i += 1;
            const word = input[start..i];
            try out.appendSlice(arena, try self.redactWord(arena, word) orelse word);
        }
        return out.items;
    }

    fn redactWord(self: *const Redactor, arena: std.mem.Allocator, word: []const u8) !?[]const u8 {
        if (word[0] == '/') {
            for (self.log_paths) |path| if (std.mem.eql(u8, path, word)) return null;
            return "<path>";
        }
        if (self.include_addresses) return null;
        const end = if (shared.IpAddress.parse(word)) |_| word.len else |_| addressEnd(std.mem.trimRight(u8, word, ".,:")) orelse return null;
        const ip = shared.IpAddress.parse(word[0..end]) catch return null;
        if (ip.isUnenforceable()) return null;
        var label_buffer: [16]u8 = undefined;
        return try std.mem.concat(arena, u8, &.{ self.label(ip, &label_buffer), word[end..] });
    }

    fn addressEnd(core: []const u8) ?usize {
        if (core.len == 0) return null;
        if (shared.IpAddress.parse(core)) |_| return core.len else |_| {}
        const split = std.mem.lastIndexOfScalar(u8, core, '/') orelse blk: {
            const colon = std.mem.indexOfScalar(u8, core, ':') orelse return null;
            if (std.mem.lastIndexOfScalar(u8, core, ':') != colon) return null;
            break :blk colon;
        };
        const suffix = core[split + 1 ..];
        if (suffix.len == 0 or suffix.len > 5) return null;
        for (suffix) |byte| if (!std.ascii.isDigit(byte)) return null;
        return split;
    }

    fn label(self: *const Redactor, ip: shared.IpAddress, buffer: *[16]u8) []const u8 {
        var material: [17]u8 = undefined;
        const bytes: []const u8 = switch (ip) {
            .ipv4 => |bits| blk: {
                material[0] = 4;
                std.mem.writeInt(u32, material[1..5], bits, .big);
                break :blk material[0..5];
            },
            .ipv6 => |bits| blk: {
                material[0] = 6;
                std.mem.writeInt(u128, material[1..17], bits, .big);
                break :blk material[0..17];
            },
        };
        var mac: [std.crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 = undefined;
        std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, bytes, &self.key);
        @memcpy(buffer[0..2], if (ip == .ipv4) "v4" else "v6");
        buffer[2] = '-';
        @memcpy(buffer[3..15], &std.fmt.bytesToHex(mac[0..6].*, .lower));
        return buffer[0..15];
    }
};
