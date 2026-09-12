// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers
const std = @import("std");
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const shared = b.createModule(.{ .root_source_file = b.path("../../shared/root.zig"), .target = target, .optimize = optimize });
    const lib = b.createModule(.{ .root_source_file = b.path("main.zig"), .target = target, .optimize = optimize });
    lib.addImport("shared", shared);
    const exe = b.addExecutable(.{ .name = "native-rules-probe", .root_module = lib });
    b.installArtifact(exe);
    const test_mod = b.createModule(.{ .root_source_file = b.path("tests.zig"), .target = target, .optimize = optimize });
    test_mod.addImport("shared", shared);
    const tests = b.addTest(.{ .root_module = test_mod, .filters = &.{"native rules:"} });
    const run_tests = b.addRunArtifact(tests);
    b.step("test", "Test isolated native rule feasibility").dependOn(&run_tests.step);
    const workloads = b.createModule(.{ .root_source_file = b.path("workload_tests.zig"), .target = target, .optimize = optimize });
    workloads.addImport("shared", shared);
    const workload_tests = b.addTest(.{ .root_module = workloads, .filters = &.{"native workload:"} });
    const run_workloads = b.addRunArtifact(workload_tests);
    b.step("test-workloads", "Qualify supported shapes and document real format gaps").dependOn(&run_workloads.step);
    const run = b.addRunArtifact(exe);
    if (b.args) |args| run.addArgs(args);
    b.step("run", "Explain offline candidate events; never enforce").dependOn(&run.step);
}
