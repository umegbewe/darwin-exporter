const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addStaticLibrary(.{
        .name = "process-exporter",
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib.linkLibC();
    lib.linkFramework("CoreFoundation");
    lib.linkFramework("IOKit");
    b.installArtifact(lib);

    const exe = b.addExecutable(.{
        .name = "process-exporter",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe.linkLibC();
    exe.linkFramework("CoreFoundation");
    exe.linkFramework("IOKit");
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run process exporter");
    run_step.dependOn(&run_cmd.step);

    const lib_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib_unit_tests.linkLibC();
    lib_unit_tests.linkFramework("CoreFoundation");
    lib_unit_tests.linkFramework("IOKit");

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);

    const lib_docs = b.addStaticLibrary(.{
        .name = "process-exporter-docs",
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = .Debug,
    });
    lib_docs.linkLibC();
    lib_docs.linkFramework("CoreFoundation");
    lib_docs.linkFramework("IOKit");

    const install_docs = b.addInstallDirectory(.{
        .source_dir = lib_docs.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });

    const docs_step = b.step("docs", "Generate documentation");
    docs_step.dependOn(&install_docs.step);
}