// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");

// Version single source of truth; build.zig.zon .version must match (release-stamp bumps both).
const fail2zig_version = "0.3.0";

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", fail2zig_version);
    const enable_bench = b.option(
        bool,
        "bench",
        "Auto-set FAIL2ZIG_RUN_BENCH=1 on benchmark test runs so `zig build test` exercises them.",
    ) orelse false;
    const test_filter = b.option(
        []const u8,
        "test-filter",
        "Only compile tests matching this substring (e.g. -Dtest-filter=allocator)",
    );

    const shared_mod = b.addModule("shared", .{
        .root_source_file = b.path("shared/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const engine_mod = b.addModule("engine", .{
        .root_source_file = b.path("engine/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    engine_mod.addImport("shared", shared_mod);
    engine_mod.addImport("build_options", build_options.createModule());

    const engine_exe = b.addExecutable(.{
        .name = "fail2zig",
        .root_module = engine_mod,
    });
    b.installArtifact(engine_exe);

    const run_engine = b.addRunArtifact(engine_exe);
    run_engine.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_engine.addArgs(args);
    b.step("run", "Run the fail2zig daemon").dependOn(&run_engine.step);

    const client_mod = b.createModule(.{
        .root_source_file = b.path("client/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    client_mod.addImport("shared", shared_mod);
    client_mod.addImport("build_options", build_options.createModule());

    const client_exe = b.addExecutable(.{
        .name = "fail2zig-client",
        .root_module = client_mod,
    });
    b.installArtifact(client_exe);

    const test_step = b.step("test", "Run all tests (engine, client, shared, integration)");
    const test_filters: []const []const u8 = if (test_filter) |f| &.{f} else &.{};

    const engine_tests = b.addTest(.{
        .root_module = engine_mod,
        .filters = test_filters,
    });
    const run_engine_tests = b.addRunArtifact(engine_tests);
    test_step.dependOn(&run_engine_tests.step);

    const client_tests = b.addTest(.{
        .root_module = client_mod,
        .filters = test_filters,
    });
    const run_client_tests = b.addRunArtifact(client_tests);
    test_step.dependOn(&run_client_tests.step);

    const shared_tests = b.addTest(.{
        .root_module = shared_mod,
        .filters = test_filters,
    });
    const run_shared_tests = b.addRunArtifact(shared_tests);
    test_step.dependOn(&run_shared_tests.step);

    const guard_options = b.addOptions();
    guard_options.addOption([]const u8, "tests_dir", b.pathFromRoot("tests"));
    const guard_mod = b.createModule(.{
        .root_source_file = b.path("tests/module_graph_guard.zig"),
        .target = target,
        .optimize = optimize,
    });
    guard_mod.addImport("guard_options", guard_options.createModule());
    const guard_tests = b.addTest(.{ .root_module = guard_mod, .filters = test_filters });
    test_step.dependOn(&b.addRunArtifact(guard_tests).step);

    const integration_mod = b.createModule(.{
        .root_source_file = b.path("tests/integration_ipc_roundtrip.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    integration_mod.addImport("shared", shared_mod);
    integration_mod.addImport("engine", engine_mod);

    const integration_tests = b.addTest(.{
        .root_module = integration_mod,
        .filters = test_filters,
    });
    const run_integration_tests = b.addRunArtifact(integration_tests);
    test_step.dependOn(&run_integration_tests.step);

    const IntegrationFile = struct {
        name: []const u8,
        path: []const u8,
        needs_daemon_binary: bool,
    };
    const integration_files = [_]IntegrationFile{
        .{ .name = "harness", .path = "tests/integration/harness.zig", .needs_daemon_binary = false },
        .{ .name = "ban", .path = "tests/integration/ban_test.zig", .needs_daemon_binary = true },
        .{ .name = "migration", .path = "tests/integration/migration_test.zig", .needs_daemon_binary = false },
        .{ .name = "persistence", .path = "tests/integration/persistence_test.zig", .needs_daemon_binary = true },
        .{ .name = "status_surface", .path = "tests/integration/status_surface_test.zig", .needs_daemon_binary = false },
        .{ .name = "startup_failclosed", .path = "tests/integration/startup_failclosed_test.zig", .needs_daemon_binary = true },
        .{ .name = "config_diag", .path = "tests/integration/config_diag_test.zig", .needs_daemon_binary = true },
        .{ .name = "no_backend", .path = "tests/integration/no_backend_test.zig", .needs_daemon_binary = true },
    };
    for (integration_files) |f| {
        const mod = b.createModule(.{
            .root_source_file = b.path(f.path),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        mod.addImport("shared", shared_mod);
        mod.addImport("engine", engine_mod);
        const t = b.addTest(.{ .root_module = mod, .filters = test_filters });
        const run = b.addRunArtifact(t);
        if (f.needs_daemon_binary) run.step.dependOn(b.getInstallStep());
        test_step.dependOn(&run.step);
    }

    const parser_only_mod = b.createModule(.{
        .root_source_file = b.path("engine/core/parser.zig"),
        .target = target,
        .optimize = optimize,
    });
    parser_only_mod.addImport("shared", shared_mod);

    const config_native_only_mod = b.createModule(.{
        .root_source_file = b.path("engine/config/native.zig"),
        .target = target,
        .optimize = optimize,
    });
    config_native_only_mod.addImport("shared", shared_mod);

    const FuzzFile = struct {
        path: []const u8,
        extra_import_name: ?[]const u8,
        extra_import_mod: ?*std.Build.Module,
    };
    const fuzz_files = [_]FuzzFile{
        .{ .path = "tests/fuzz/fuzz_parser.zig", .extra_import_name = "parser", .extra_import_mod = parser_only_mod },
        .{ .path = "tests/fuzz/fuzz_ip.zig", .extra_import_name = null, .extra_import_mod = null },
        .{ .path = "tests/fuzz/fuzz_protocol.zig", .extra_import_name = null, .extra_import_mod = null },
        .{ .path = "tests/fuzz/fuzz_config.zig", .extra_import_name = "config_native", .extra_import_mod = config_native_only_mod },
    };
    for (fuzz_files) |f| {
        const mod = b.createModule(.{
            .root_source_file = b.path(f.path),
            .target = target,
            .optimize = optimize,
        });
        mod.addImport("shared", shared_mod);
        if (f.extra_import_name) |n| mod.addImport(n, f.extra_import_mod.?);
        const t = b.addTest(.{ .root_module = mod, .filters = test_filters });
        test_step.dependOn(&b.addRunArtifact(t).step);
    }

    const BenchFile = struct {
        path: []const u8,
        needs_daemon_binary: bool,
    };
    const bench_files = [_]BenchFile{
        .{ .path = "tests/benchmark/parse_throughput.zig", .needs_daemon_binary = false },
        .{ .path = "tests/benchmark/memory_ceiling.zig", .needs_daemon_binary = false },
        .{ .path = "tests/benchmark/startup_time.zig", .needs_daemon_binary = true },
        .{ .path = "tests/benchmark/ban_latency.zig", .needs_daemon_binary = false },
        .{ .path = "tests/benchmark/loop_latency.zig", .needs_daemon_binary = false },
    };
    for (bench_files) |f| {
        const mod = b.createModule(.{
            .root_source_file = b.path(f.path),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        mod.addImport("shared", shared_mod);
        mod.addImport("engine", engine_mod);
        const t = b.addTest(.{ .root_module = mod, .filters = test_filters });
        const run = b.addRunArtifact(t);
        if (enable_bench) run.setEnvironmentVariable("FAIL2ZIG_RUN_BENCH", "1");
        if (f.needs_daemon_binary) run.step.dependOn(b.getInstallStep());
        test_step.dependOn(&run.step);
    }
}
