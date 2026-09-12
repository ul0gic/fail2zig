// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");

// Version single source of truth; build.zig.zon .version must match (release-stamp bumps both).
const fail2zig_version = "0.3.1-dev";

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Pinned upstream amalgamation: embedded storage, no installed SQLite library.
    const sqlite = b.addStaticLibrary(.{
        .name = "sqlite3",
        .root_module = b.createModule(.{ .target = target, .optimize = optimize, .link_libc = true }),
    });
    sqlite.root_module.addCSourceFile(.{
        .file = b.path("vendor/sqlite/sqlite3.c"),
        .flags = &.{"-DSQLITE_OMIT_LOAD_EXTENSION=1"},
    });

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
    engine_mod.linkLibrary(sqlite);

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
    b.step("test-engine", "Run native daemon tests").dependOn(&run_engine_tests.step);

    // Full-profile foundations remain independently testable before daemon
    // activation. These tests also participate in the ordinary test gate.
    const parity_runtime_mod = b.createModule(.{
        .root_source_file = b.path("engine/parity_runtime_tests.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const parity_runtime_tests = b.addTest(.{ .root_module = parity_runtime_mod, .filters = test_filters });
    parity_runtime_mod.linkLibrary(sqlite);
    const run_parity_runtime_tests = b.addRunArtifact(parity_runtime_tests);
    test_step.dependOn(&run_parity_runtime_tests.step);
    b.step("test-p2-runtime", "Test source, event-time and durable record foundations").dependOn(&run_parity_runtime_tests.step);

    const native_foundations = b.addTest(.{ .root_module = parity_runtime_mod, .filters = &.{ "storage health:", "native processor:", "record store:", "pipeline:", "receipt recovery:", "future time:", "time admission:", "event age:", "year inference:", "native journal:", "clock recovery:", "native retry:" } });
    b.step("test-native-foundations", "Test native storage, time, sources and recovery without legacy workers").dependOn(&b.addRunArtifact(native_foundations).step);

    // Focused native consumer gate: no legacy worker test execution.
    const detection_mod = b.createModule(.{
        .root_source_file = b.path("engine/native_detection_tests.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    detection_mod.addImport("shared", shared_mod);
    detection_mod.linkLibrary(sqlite);
    const detection_options = b.addOptions();
    detection_options.addOption([]const u8, "corpus_path", b.pathFromRoot("tests/integration/filter_corpus.json"));
    detection_mod.addImport("detection_test_options", detection_options.createModule());
    const detection_tests = b.addTest(.{ .root_module = detection_mod, .filters = &.{"native detection:"} });
    const run_detection_tests = b.addRunArtifact(detection_tests);
    b.step("test-native-detection", "Test native file and origin-qualified journal detection").dependOn(&run_detection_tests.step);
    test_step.dependOn(&run_detection_tests.step);

    const retry_mod = b.createModule(.{
        .root_source_file = b.path("engine/native_retry_tests.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    retry_mod.addImport("shared", shared_mod);
    retry_mod.linkLibrary(sqlite);
    const retry_tests = b.addTest(.{ .root_module = retry_mod, .filters = &.{"native retry:"} });
    const run_retry_tests = b.addRunArtifact(retry_tests);
    b.step("test-native-retry", "Test transactional native retry state and decisions").dependOn(&run_retry_tests.step);
    test_step.dependOn(&run_retry_tests.step);

    // Explicit offline qualification against a separately captured lab journal.
    // Never contact a host or require private lab artifacts in ordinary tests.
    const journal_lab_mod = b.createModule(.{
        .root_source_file = b.path("engine/journal_origin_lab_tests.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    journal_lab_mod.addImport("shared", shared_mod);
    const journal_lab_options = b.addOptions();
    journal_lab_options.addOption(?[]const u8, "fixture", b.option([]const u8, "journal-origin-fixture", "Captured journal JSON lines for explicit lab qualification"));
    journal_lab_options.addOption(?[]const u8, "machine_id", b.option([]const u8, "journal-origin-machine-id", "Independently captured machine ID for lab qualification"));
    journal_lab_mod.addImport("journal_lab_options", journal_lab_options.createModule());
    const journal_lab_tests = b.addTest(.{ .root_module = journal_lab_mod, .filters = &.{"lab journal:"} });
    b.step("test-journal-origin-lab", "Qualify captured SSH journal records without contacting a host").dependOn(&b.addRunArtifact(journal_lab_tests).step);

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
        .{ .name = "filter_corpus", .path = "tests/integration/filter_corpus_test.zig", .needs_daemon_binary = false },
        .{ .name = "harness", .path = "tests/integration/harness.zig", .needs_daemon_binary = false },
        .{ .name = "ban", .path = "tests/integration/ban_test.zig", .needs_daemon_binary = true },
        .{ .name = "migration", .path = "tests/integration/migration_test.zig", .needs_daemon_binary = false },
        .{ .name = "persistence", .path = "tests/integration/persistence_test.zig", .needs_daemon_binary = true },
        .{ .name = "status_surface", .path = "tests/integration/status_surface_test.zig", .needs_daemon_binary = false },
        .{ .name = "startup_failclosed", .path = "tests/integration/startup_failclosed_test.zig", .needs_daemon_binary = true },
        .{ .name = "native_daemon", .path = "tests/integration/native_daemon_test.zig", .needs_daemon_binary = true },
        .{ .name = "journalctl_contract", .path = "tests/integration/journalctl_contract_test.zig", .needs_daemon_binary = false },
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
        if (std.mem.eql(u8, f.name, "startup_failclosed"))
            b.step("test-startup", "Run daemon startup integration tests").dependOn(&run.step);
        if (std.mem.eql(u8, f.name, "native_daemon"))
            b.step("test-native-daemon", "Run actual native daemon ingestion and restart tests").dependOn(&run.step);
        if (std.mem.eql(u8, f.name, "journalctl_contract"))
            b.step("test-journalctl", "Qualify host journalctl against original offline fixtures").dependOn(&run.step);
        test_step.dependOn(&run.step);
    }

    const parser_only_mod = b.createModule(.{
        .root_source_file = b.path("engine/core/parser.zig"),
        .target = target,
        .optimize = optimize,
    });
    parser_only_mod.addImport("shared", shared_mod);

    const FuzzFile = struct {
        path: []const u8,
        extra_import_name: ?[]const u8,
        extra_import_mod: ?*std.Build.Module,
    };
    const fuzz_files = [_]FuzzFile{
        .{ .path = "tests/fuzz/fuzz_parser.zig", .extra_import_name = "parser", .extra_import_mod = parser_only_mod },
        .{ .path = "tests/fuzz/fuzz_ip.zig", .extra_import_name = null, .extra_import_mod = null },
        .{ .path = "tests/fuzz/fuzz_protocol.zig", .extra_import_name = null, .extra_import_mod = null },
        .{ .path = "tests/fuzz/fuzz_config.zig", .extra_import_name = "engine", .extra_import_mod = engine_mod },
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
