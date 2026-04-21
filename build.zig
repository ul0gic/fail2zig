const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const enable_sim = b.option(
        bool,
        "sim",
        "Build the attack simulator (demo-only tool, not shipped).",
    ) orelse false;

    // Shared types + IPC protocol. Imported by engine and client as
    // `@import("shared")` — frozen contract between the two binaries.
    const shared_mod = b.addModule("shared", .{
        .root_source_file = b.path("shared/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // ===== Engine (fail2zig daemon) =====
    const engine_mod = b.createModule(.{
        .root_source_file = b.path("engine/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    engine_mod.addImport("shared", shared_mod);

    const engine_exe = b.addExecutable(.{
        .name = "fail2zig",
        .root_module = engine_mod,
    });
    b.installArtifact(engine_exe);

    const run_engine = b.addRunArtifact(engine_exe);
    run_engine.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_engine.addArgs(args);
    b.step("run", "Run the fail2zig daemon").dependOn(&run_engine.step);

    // ===== Client (fail2zig-client CLI) =====
    const client_mod = b.createModule(.{
        .root_source_file = b.path("client/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    client_mod.addImport("shared", shared_mod);

    const client_exe = b.addExecutable(.{
        .name = "fail2zig-client",
        .root_module = client_mod,
    });
    b.installArtifact(client_exe);

    // ===== Simulator (opt-in via -Dsim=true) =====
    if (enable_sim) {
        const sim_mod = b.createModule(.{
            .root_source_file = b.path("sim/main.zig"),
            .target = target,
            .optimize = optimize,
        });
        const sim_exe = b.addExecutable(.{
            .name = "fail2zig-sim",
            .root_module = sim_mod,
        });
        b.installArtifact(sim_exe);
    }

    // ===== Tests =====
    const test_step = b.step("test", "Run all tests (engine, client, shared)");

    const engine_tests = b.addTest(.{ .root_module = engine_mod });
    const run_engine_tests = b.addRunArtifact(engine_tests);
    if (b.args) |args| run_engine_tests.addArgs(args);
    test_step.dependOn(&run_engine_tests.step);

    const client_tests = b.addTest(.{ .root_module = client_mod });
    const run_client_tests = b.addRunArtifact(client_tests);
    if (b.args) |args| run_client_tests.addArgs(args);
    test_step.dependOn(&run_client_tests.step);

    const shared_tests = b.addTest(.{ .root_module = shared_mod });
    const run_shared_tests = b.addRunArtifact(shared_tests);
    if (b.args) |args| run_shared_tests.addArgs(args);
    test_step.dependOn(&run_shared_tests.step);
}
