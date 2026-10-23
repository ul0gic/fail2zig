// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");

const fail2zig_version = "0.4.9-dev";

fn releaseSignal(b: *std.Build, strip: bool) ?[]const u8 {
    if (strip) return "-Dstrip=true";
    if (b.graph.env_map.get("RELEASE_TAG") != null) return "RELEASE_TAG is set";
    if (b.graph.env_map.get("GITHUB_REF_TYPE")) |ref_type| if (std.mem.eql(u8, ref_type, "tag")) return "GITHUB_REF_TYPE=tag";
    return null;
}

const NoDiagCheck = struct {
    const markers = [_][]const u8{ "DIAGNOSTIC BUILD", "f2z_diag_", fail2zig_version ++ "+diag" };

    step: std.Build.Step,
    binary: []const u8,

    fn make(step: *std.Build.Step, options: std.Build.Step.MakeOptions) anyerror!void {
        _ = options;
        const self: *NoDiagCheck = @fieldParentPtr("step", step);
        const b = step.owner;
        const path = if (std.fs.path.isAbsolute(self.binary)) self.binary else b.pathFromRoot(self.binary);
        const bytes = std.fs.cwd().readFileAlloc(b.allocator, path, 1 << 30) catch |err| return step.fail("cannot read {s}: {s}", .{ path, @errorName(err) });
        for (markers) |marker| if (std.mem.indexOf(u8, bytes, marker) != null) return step.fail("{s} is a diagnostic build: contains '{s}'", .{ path, marker });
    }
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const strip = b.option(bool, "strip", "Strip debug information from the executable") orelse false;
    const diag = b.option(bool, "diag", "Build the internal diagnostic instrumentation; never shipped") orelse false;
    if (diag) if (releaseSignal(b, strip)) |signal| {
        std.debug.print("error: -Ddiag=true is refused for a release build ({s})\n", .{signal});
        std.process.exit(1);
    };
    const tracy = b.option(bool, "tracy", "Profile the diagnostic build with the Tracy client; requires -Ddiag=true") orelse false;
    if (tracy and !diag) {
        std.debug.print("error: -Dtracy=true requires -Ddiag=true\n", .{});
        std.process.exit(1);
    }

    const sqlite = b.addStaticLibrary(.{
        .name = "sqlite3",
        .root_module = b.createModule(.{ .target = target, .optimize = optimize, .link_libc = true }),
    });
    sqlite.root_module.addCSourceFile(.{
        .file = b.path("vendor/sqlite/sqlite3.c"),
        .flags = if (diag) &.{ "-DSQLITE_OMIT_LOAD_EXTENSION=1", "-DSQLITE_ENABLE_DBSTAT_VTAB=1", "-Dfsync=f2z_diag_fsync" } else &.{ "-DSQLITE_OMIT_LOAD_EXTENSION=1", "-DSQLITE_ENABLE_DBSTAT_VTAB=1" },
    });

    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", if (diag) fail2zig_version ++ "+diag" else fail2zig_version);
    build_options.addOption(bool, "diag", diag);
    build_options.addOption(bool, "tracy", tracy);

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
    if (tracy) if (b.lazyDependency("tracy", .{})) |tracy_dep| {
        const tracy_client = b.addStaticLibrary(.{
            .name = "tracy",
            .root_module = b.createModule(.{ .target = target, .optimize = optimize, .link_libc = true, .link_libcpp = true }),
        });
        tracy_client.root_module.addCSourceFile(.{
            .file = tracy_dep.path("public/TracyClient.cpp"),
            // Zig's C UBSan trap fires (ud1) in Tracy's queue dequeue switch, TracyProfiler.cpp:2569, and freezes the daemon.
            .flags = &.{ "-fno-sanitize=undefined", "-DTRACY_ENABLE", "-DTRACY_TIMER_FALLBACK", "-DTRACY_NO_BROADCAST", "-DTRACY_ONLY_LOCALHOST", "-DTRACY_DELAYED_INIT", "-DTRACY_MANUAL_LIFETIME" },
        });
        engine_mod.link_libcpp = true;
        engine_mod.linkLibrary(tracy_client);
    };

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

    const no_diag = b.allocator.create(NoDiagCheck) catch @panic("OOM");
    no_diag.* = .{
        .step = std.Build.Step.init(.{ .id = .custom, .name = "check-no-diag", .owner = b, .makeFn = NoDiagCheck.make }),
        .binary = b.option([]const u8, "check-binary", "Executable for check-no-diag (default: the installed fail2zig)") orelse b.getInstallPath(.bin, "fail2zig"),
    };
    b.step("check-no-diag", "Fail if an executable carries diagnostic build markers").dependOn(&no_diag.step);

    const run_engine = b.addRunArtifact(engine_exe);
    run_engine.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_engine.addArgs(args);
    b.step("run", "Run the fail2zig daemon").dependOn(&run_engine.step);

    const test_step = b.step("test", "Run the small delivered-daemon smoke check (alias of test-smoke)");
    const release_local_step = b.step("test-release-local", "Run the bounded assembled local release gate");
    const assembled_step = b.step("test-ci-assembled", "Run assembled daemon checks");

    const component_api = b.createModule(.{
        .root_source_file = b.path("engine/test_api.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    component_api.addImport("shared", shared_mod);
    component_api.addImport("build_options", build_options_mod);
    const probes = [_]struct { name: []const u8, path: []const u8, sqlite: bool }{
        .{ .name = "file-alias", .path = "engine/probes/file_alias_probe.zig", .sqlite = false },
        .{ .name = "file-mode", .path = "engine/probes/file_mode_probe.zig", .sqlite = false },
        .{ .name = "ignore-store", .path = "engine/probes/ignore_store_probe.zig", .sqlite = true },
        .{ .name = "journal-policy", .path = "engine/probes/journal_policy_probe.zig", .sqlite = false },
        .{ .name = "source", .path = "engine/probes/source_probe.zig", .sqlite = false },
    };
    for (probes) |probe| {
        const module = b.createModule(.{
            .root_source_file = b.path(probe.path),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        module.addImport("shared", shared_mod);
        module.addImport("engine_probe", component_api);
        if (probe.sqlite) module.linkLibrary(sqlite);
        const executable = b.addExecutable(.{ .name = b.fmt("f2z-{s}-probe", .{probe.name}), .root_module = module });
        b.step(b.fmt("build-probe-{s}", .{probe.name}), "Build a manual diagnostic probe").dependOn(&executable.step);
        const run = b.addRunArtifact(executable);
        if (b.args) |args| run.addArgs(args);
        b.step(b.fmt("probe-{s}", .{probe.name}), "Run a manual diagnostic probe").dependOn(&run.step);
    }
    // Manual load-reproduction state generator; not a test or CI member.
    const load_fixture_mod = b.createModule(.{
        .root_source_file = b.path("tests/harness/load_repro/fixture.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    load_fixture_mod.addImport("shared", shared_mod);
    load_fixture_mod.addImport("engine_test", component_api);
    load_fixture_mod.linkLibrary(sqlite);
    const load_fixture = b.addExecutable(.{ .name = "f2z-load-fixture", .root_module = load_fixture_mod });
    b.step("build-load-fixture", "Build the load reproduction state fixture generator").dependOn(&b.addInstallArtifact(load_fixture, .{}).step);

    const firewall_step = b.step("test-firewall", "Run the firewall readback parser suites");
    const firewall_suites = [_]struct { name: []const u8, path: []const u8, filter: []const u8 }{
        .{ .name = "test-native-firewall", .path = "tests/component/native_firewall_tests.zig", .filter = "native firewall:" },
        .{ .name = "test-firewall-inspection-inline", .path = "tests/component/firewall_inspection_inline_tests.zig", .filter = "native firewall:" },
        .{ .name = "test-nftables-inline", .path = "tests/component/nftables_inline_tests.zig", .filter = "nftables:" },
    };
    for (firewall_suites) |entry| {
        const module = b.createModule(.{
            .root_source_file = b.path(entry.path),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        module.addImport("shared", shared_mod);
        module.addImport("engine_test", component_api);
        const tests = b.addTest(.{ .root_module = module, .filters = &.{entry.filter} });
        const run_tests = b.addRunArtifact(tests);
        b.step(entry.name, "Test isolated native component delivery").dependOn(&run_tests.step);
        firewall_step.dependOn(&run_tests.step);
        // Compile-only entry point for isolated target execution; never run on the build host.
        if (std.mem.eql(u8, entry.name, "test-native-firewall")) {
            const installed = b.addInstallArtifact(tests, .{ .dest_sub_path = "native-firewall-tests" });
            b.step("build-native-firewall-tests", "Build an isolated target test binary without executing it").dependOn(&installed.step);
        }
    }

    const IntegrationFile = struct {
        release_local: bool,
        name: []const u8,
        path: []const u8,
    };
    const integration_files = [_]IntegrationFile{
        .{ .name = "startup_failclosed", .path = "tests/integration/startup_failclosed_test.zig", .release_local = true },
        .{ .name = "native_daemon", .path = "tests/integration/native_daemon_test.zig", .release_local = true },
        .{ .name = "config_diag", .path = "tests/integration/config_diag_test.zig", .release_local = false },
        .{ .name = "no_backend", .path = "tests/integration/no_backend_test.zig", .release_local = true },
        .{ .name = "cli_entry", .path = "tests/integration/cli_entry_test.zig", .release_local = true },
        .{ .name = "reload", .path = "tests/integration/reload_test.zig", .release_local = true },
        .{ .name = "service_lifecycle", .path = "tests/integration/service_lifecycle_test.zig", .release_local = true },
        .{ .name = "admin", .path = "tests/integration/admin_test.zig", .release_local = true },
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
        const t = b.addTest(.{ .root_module = mod });
        const run = b.addRunArtifact(t);
        run.step.dependOn(b.getInstallStep());
        if (f.release_local) release_local_step.dependOn(&run.step);
        assembled_step.dependOn(&run.step);
        if (std.mem.eql(u8, f.name, "startup_failclosed"))
            b.step("test-startup", "Run daemon startup integration tests").dependOn(&run.step);
        if (std.mem.eql(u8, f.name, "native_daemon")) {
            b.step("test-native-daemon", "Run actual native daemon ingestion and restart tests").dependOn(&run.step);
            const installed = b.addInstallArtifact(t, .{ .dest_sub_path = "native-daemon-tests" });
            b.step("build-native-daemon-tests", "Build daemon tests for an explicit F2Z_TEST_DAEMON candidate").dependOn(&installed.step);
            const smoke = b.addTest(.{ .root_module = mod, .filters = &.{"native daemon: delivered client renders native status jails version and decision deadlines"} });
            const smoke_run = b.addRunArtifact(smoke);
            smoke_run.removeEnvironmentVariable("F2Z_NATIVE_DAEMON_ENFORCEMENT");
            smoke_run.step.dependOn(b.getInstallStep());
            b.step("test-smoke", "Run one delivered daemon/client behavior check").dependOn(&smoke_run.step);
            test_step.dependOn(&smoke_run.step);
            const smoke_install = b.addInstallArtifact(smoke, .{ .dest_sub_path = "smoke-tests" });
            b.step("build-smoke-tests", "Build the smoke check without executing it").dependOn(&smoke_install.step);
        }
        if (std.mem.eql(u8, f.name, "config_diag"))
            b.step("test-config-diag", "Run configuration diagnostic entry-point tests").dependOn(&run.step);
        if (std.mem.eql(u8, f.name, "no_backend"))
            b.step("test-no-backend", "Run native backend selection and fail-closed integration tests").dependOn(&run.step);
        if (std.mem.eql(u8, f.name, "admin")) {
            b.step("test-admin", "Run typed administration daemon tests").dependOn(&run.step);
            const installed = b.addInstallArtifact(t, .{ .dest_sub_path = "admin-tests" });
            b.step("build-admin-tests", "Build administration checks for isolated target execution").dependOn(&installed.step);
        }
        if (std.mem.eql(u8, f.name, "reload"))
            b.step("test-reload", "Run live configuration reload daemon tests").dependOn(&run.step);
        if (std.mem.eql(u8, f.name, "service_lifecycle"))
            b.step("test-service-lifecycle", "Run installed service lifecycle (notify, signals, denied paths) tests").dependOn(&run.step);
        if (std.mem.eql(u8, f.name, "cli_entry"))
            b.step("test-cli-entry", "Run one-executable entry point and operator round trips").dependOn(&run.step);
    }
}
