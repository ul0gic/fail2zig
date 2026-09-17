// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");

const fail2zig_version = "0.4.1";

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const strip = b.option(bool, "strip", "Strip debug information from the executable") orelse false;

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

    const client_mod = b.createModule(.{
        .root_source_file = b.path("client/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    client_mod.addImport("shared", shared_mod);
    const build_options_mod = build_options.createModule();
    client_mod.addImport("build_options", build_options_mod);

    const engine_mod = b.addModule("engine", .{
        .root_source_file = b.path("engine/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    engine_mod.strip = strip;
    engine_mod.addImport("shared", shared_mod);
    engine_mod.addImport("build_options", build_options_mod);
    engine_mod.addImport("cli", client_mod);
    engine_mod.linkLibrary(sqlite);

    const engine_exe = b.addExecutable(.{
        .name = "fail2zig",
        .root_module = engine_mod,
    });
    b.installArtifact(engine_exe);

    const release_lifecycle_mod = b.createModule(.{
        .root_source_file = b.path("tests/e2e/ban_lifecycle.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const release_lifecycle_exe = b.addExecutable(.{
        .name = "fail2zig-release-lifecycle",
        .root_module = release_lifecycle_mod,
    });
    const install_release_lifecycle = b.addInstallArtifact(release_lifecycle_exe, .{});
    b.step("test-release-lifecycle", "Build the test-only privileged release lifecycle helper").dependOn(&install_release_lifecycle.step);

    const run_engine = b.addRunArtifact(engine_exe);
    run_engine.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_engine.addArgs(args);
    b.step("run", "Run the fail2zig daemon").dependOn(&run_engine.step);

    const test_step = b.step("test", "Run all tests (engine, client, shared, integration)");
    const release_local_step = b.step("test-release-local", "Run the bounded assembled local release gate");
    const test_filters: []const []const u8 = if (test_filter) |f| &.{f} else &.{};

    const engine_tests = b.addTest(.{
        .root_module = engine_mod,
        .filters = test_filters,
    });
    const run_engine_tests = b.addRunArtifact(engine_tests);
    test_step.dependOn(&run_engine_tests.step);
    b.step("test-engine", "Run native daemon tests").dependOn(&run_engine_tests.step);

    inline for (.{
        .{ "test-native-firewall", "engine/native_firewall_tests.zig", "native firewall:" },
        .{ "test-native-rules", "engine/native_rule_tests.zig", "native rules:" },
        .{ "test-native-correlation", "engine/native_correlation_tests.zig", "native correlation:" },
        .{ "test-native-source-repair", "engine/source_repair_tests.zig", "source repair:" },
        .{ "test-native-consumers", "engine/native_consumer_tests.zig", "native consumers:" },
        .{ "test-native-effects", "engine/native_effect_tests.zig", "native effects:" },
        .{ "test-native-effect-runtime", "engine/native_effect_runtime_tests.zig", "native effect runtime:" },
        .{ "test-native-effect-history", "engine/native_effect_history_tests.zig", "native effect history:" },
        .{ "test-native-effect-history-store", "engine/native_effect_history_store_tests.zig", "native effect history store:" },
        .{ "test-native-consumer-manifest", "engine/native_consumer_manifest_tests.zig", "native consumer manifest:" },
        .{ "test-native-consumer-coordinator", "engine/native_consumer_coordinator_tests.zig", "native coordinator:" },
        .{ "test-native-consumer-runtime", "engine/native_consumer_runtime_tests.zig", "native consumer runtime:" },
        .{ "test-native-consumer-plan", "engine/native_consumer_plan_tests.zig", "native consumer plan:" },
        .{ "test-native-session-repair", "engine/native_session_repair_tests.zig", "native session repair:" },
        .{ "test-native-resource-budget", "engine/native_resource_budget_tests.zig", "native resource budget:" },
        .{ "test-native-maintenance", "engine/native_maintenance_tests.zig", "native maintenance:" },
        .{ "test-native-effective", "engine/native_effective_tests.zig", "native effective:" },
        .{ "test-native-timezone", "engine/native_timezone_tests.zig", "native timezone:" },
        .{ "test-native-config", "engine/native_config_tests.zig", "native:" },
        .{ "test-native-dns", "engine/native_dns_tests.zig", "native dns:" },
        .{ "test-native-ignore", "engine/native_ignore_tests.zig", "native ignore:" },
    }) |entry| {
        const module = b.createModule(.{
            .root_source_file = b.path(entry[1]),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        module.addImport("shared", shared_mod);
        if (comptime std.mem.eql(u8, entry[0], "test-native-consumers") or std.mem.eql(u8, entry[0], "test-native-effects") or std.mem.eql(u8, entry[0], "test-native-effect-runtime") or std.mem.eql(u8, entry[0], "test-native-consumer-manifest") or std.mem.eql(u8, entry[0], "test-native-consumer-runtime") or std.mem.eql(u8, entry[0], "test-native-session-repair") or std.mem.eql(u8, entry[0], "test-native-resource-budget") or std.mem.eql(u8, entry[0], "test-native-effect-history-store") or std.mem.eql(u8, entry[0], "test-native-maintenance")) module.linkLibrary(sqlite);
        const tests = b.addTest(.{ .root_module = module, .filters = &.{entry[2]} });
        const run_tests = b.addRunArtifact(tests);
        b.step(entry[0], "Test isolated N2 native component delivery").dependOn(&run_tests.step);
    }

    inline for (.{
        .{ "test-native-ipc-auth", "engine/native_ipc_auth_tests.zig", "native ipc auth:", false },
        .{ "test-native-migration-snapshot", "engine/migration_snapshot_tests.zig", "migration snapshot:", true },
        .{ "test-native-migration-inspect", "engine/migration_inspect_tests.zig", "migration inspect:", false },
        .{ "test-native-admin-store", "engine/native_admin_store_tests.zig", "native admin store:", true },
        .{ "test-native-reload", "engine/native_reload_tests.zig", "native reload:", false },
        .{ "test-native-readiness", "engine/native_readiness_tests.zig", "native readiness:", false },
        .{ "test-native-query", "engine/native_query_tests.zig", "native query:", false },
        .{ "test-native-migration-plan", "engine/migration_plan_tests.zig", "migration plan:", true },
        .{ "test-native-rule-test", "engine/native_rule_test_tests.zig", "native rule test:", false },
        .{ "test-native-migration-store", "engine/native_migration_store_tests.zig", "migration store:", true },
        .{ "test-native-migration-import", "engine/migration_import_tests.zig", "migration import:", true },
        .{ "test-native-migration-continuity", "engine/migration_continuity_tests.zig", "migration continuity:", true },
        .{ "test-native-migration-journal", "engine/migration_journal_tests.zig", "migration journal:", true },
        .{ "test-native-migration-conflict", "engine/native_migration_conflict_tests.zig", "migration conflict:", true },
        .{ "test-native-reload-crash", "engine/native_reload_crash_tests.zig", "reload crash:", true },
    }) |entry| {
        const module = b.createModule(.{
            .root_source_file = b.path(entry[1]),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        module.addImport("shared", shared_mod);
        if (entry[3]) module.linkLibrary(sqlite);
        const tests = b.addTest(.{ .root_module = module, .filters = &.{entry[2]} });
        const run_tests = b.addRunArtifact(tests);
        b.step(entry[0], "Test isolated native component delivery").dependOn(&run_tests.step);
    }

    const coordination_mod = b.createModule(.{
        .root_source_file = b.path("engine/native_daemon.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    coordination_mod.addImport("shared", shared_mod);
    coordination_mod.addImport("build_options", build_options_mod);
    coordination_mod.linkLibrary(sqlite);
    const coordination_tests = b.addTest(.{ .root_module = coordination_mod, .filters = &.{"native daemon BUG-0"} });
    b.step("test-native-coordination", "Test deterministic daemon ownership and publication races").dependOn(&b.addRunArtifact(coordination_tests).step);

    const native_foundations_mod = b.createModule(.{
        .root_source_file = b.path("engine/native_foundations_tests.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    native_foundations_mod.addImport("shared", shared_mod);
    const native_foundations_tests = b.addTest(.{ .root_module = native_foundations_mod, .filters = test_filters });
    native_foundations_mod.linkLibrary(sqlite);
    const run_native_foundations_tests = b.addRunArtifact(native_foundations_tests);
    test_step.dependOn(&run_native_foundations_tests.step);

    const native_foundations = b.addTest(.{ .root_module = native_foundations_mod, .filters = &.{ "storage health:", "native processor:", "record store:", "pipeline:", "receipt recovery:", "future time:", "time admission:", "event age:", "year inference:", "native journal:", "clock recovery:", "native retry:" } });
    b.step("test-native-foundations", "Test native storage, time, sources and recovery without legacy workers").dependOn(&b.addRunArtifact(native_foundations).step);

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
    const native_cli_step = b.step("test-native-cli", "Test the internal administration modules and shared exit classes");
    native_cli_step.dependOn(&run_client_tests.step);
    native_cli_step.dependOn(&run_shared_tests.step);

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

    const standalone_options = b.addOptions();
    standalone_options.addOption(?[]const u8, "release_dir", b.option([]const u8, "release-dir", "Directory of five named release artifacts for ELF inspection"));
    standalone_options.addOption([]const u8, "repo_root", b.pathFromRoot("."));
    standalone_options.addOption([]const u8, "daemon_path", b.pathFromRoot("zig-out/bin/fail2zig"));
    const standalone_mod = b.createModule(.{
        .strip = strip,
        .root_source_file = b.path("tests/integration/standalone_surface_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    standalone_mod.addImport("standalone_test_options", standalone_options.createModule());
    const standalone_tests = b.addTest(.{ .root_module = standalone_mod, .filters = &.{"standalone surface:"} });
    const run_standalone_tests = b.addRunArtifact(standalone_tests);
    run_standalone_tests.step.dependOn(b.getInstallStep());
    b.step("test-standalone-surface", "Verify required product and release paths have no interpreter dependency").dependOn(&run_standalone_tests.step);
    release_local_step.dependOn(&run_standalone_tests.step);

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
        .{ .name = "cli_entry", .path = "tests/integration/cli_entry_test.zig", .needs_daemon_binary = true },
        .{ .name = "reload", .path = "tests/integration/reload_test.zig", .needs_daemon_binary = true },
        .{ .name = "service_lifecycle", .path = "tests/integration/service_lifecycle_test.zig", .needs_daemon_binary = true },
        .{ .name = "admin", .path = "tests/integration/admin_test.zig", .needs_daemon_binary = true },
    };
    for (integration_files) |f| {
        const mod = b.createModule(.{
            .strip = strip,
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
        if (std.mem.eql(u8, f.name, "native_daemon") or
            std.mem.eql(u8, f.name, "startup_failclosed") or
            std.mem.eql(u8, f.name, "journalctl_contract") or
            std.mem.eql(u8, f.name, "no_backend") or
            std.mem.eql(u8, f.name, "cli_entry") or
            std.mem.eql(u8, f.name, "reload") or
            std.mem.eql(u8, f.name, "service_lifecycle") or
            std.mem.eql(u8, f.name, "admin"))
        {
            release_local_step.dependOn(&run.step);
        }
        if (std.mem.eql(u8, f.name, "startup_failclosed"))
            b.step("test-startup", "Run daemon startup integration tests").dependOn(&run.step);
        if (std.mem.eql(u8, f.name, "native_daemon"))
            b.step("test-native-daemon", "Run actual native daemon ingestion and restart tests").dependOn(&run.step);
        if (std.mem.eql(u8, f.name, "config_diag"))
            b.step("test-config-diag", "Run configuration diagnostic entry-point tests").dependOn(&run.step);
        if (std.mem.eql(u8, f.name, "no_backend"))
            b.step("test-no-backend", "Run native backend selection and fail-closed integration tests").dependOn(&run.step);
        if (std.mem.eql(u8, f.name, "admin"))
            b.step("test-admin", "Run typed administration daemon tests").dependOn(&run.step);
        if (std.mem.eql(u8, f.name, "reload"))
            b.step("test-reload", "Run live configuration reload daemon tests").dependOn(&run.step);
        if (std.mem.eql(u8, f.name, "service_lifecycle"))
            b.step("test-service-lifecycle", "Run installed service lifecycle (notify, signals, denied paths) tests").dependOn(&run.step);
        if (std.mem.eql(u8, f.name, "cli_entry"))
            b.step("test-cli-entry", "Run one-executable entry point and operator round trips").dependOn(&run.step);
        if (std.mem.eql(u8, f.name, "journalctl_contract"))
            b.step("test-journalctl", "Qualify host journalctl against original offline fixtures").dependOn(&run.step);
        test_step.dependOn(&run.step);
    }

    const release_migration_options = b.addOptions();
    release_migration_options.addOption([]const u8, "daemon_path", b.pathFromRoot("zig-out/bin/fail2zig"));
    release_migration_options.addOption([]const u8, "supported_fixture", b.pathFromRoot("tests/fixtures/fail2ban/config/stock-1.1.1"));
    const release_migration_mod = b.createModule(.{
        .strip = strip,
        .root_source_file = b.path("tests/integration/release_migration_test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    release_migration_mod.addImport("engine", engine_mod);
    release_migration_mod.addImport("release_migration_test_options", release_migration_options.createModule());
    const release_migration_tests = b.addTest(.{ .root_module = release_migration_mod, .filters = &.{"release migration:"} });
    const run_release_migration = b.addRunArtifact(release_migration_tests);
    run_release_migration.step.dependOn(b.getInstallStep());
    b.step("test-release-migration", "Run bounded one-executable release migration tests").dependOn(&run_release_migration.step);
    release_local_step.dependOn(&run_release_migration.step);

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
