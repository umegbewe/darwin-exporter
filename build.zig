const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const sdk_path = std.zig.system.darwin.getSdk(b.allocator, target.result) orelse
        @panic("Failed to find macOS SDK");
    defer b.allocator.free(sdk_path);

    const macos_private_framework = b.fmt("{s}/System/Library/PrivateFrameworks", .{sdk_path});

    const objc_dep = b.dependency("objc", .{
        .target = target,
        .optimize = optimize,
    });

    const build_opts = b.addOptions();
    build_opts.addOption([]const u8, "version", "1.0.0");

    const darwin_exporter = b.addModule("darwin_exporter", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    darwin_exporter.addImport("objc", objc_dep.module("objc"));

    const exe = b.addExecutable(.{
        .name = "darwin-exporter",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .strip = optimize != .Debug,
    });
    exe.root_module.addOptions("build_options", build_opts);
    exe.root_module.addImport("lib", darwin_exporter);
    exe.root_module.addImport("objc", objc_dep.module("objc"));
    exe.linkLibC();
    exe.addFrameworkPath(.{ .cwd_relative = macos_private_framework });
    exe.linkFramework("CoreFoundation");
    exe.linkFramework("IOKit");
    exe.linkFramework("NetworkStatistics");
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run darwin-exporter");
    run_step.dependOn(&run_cmd.step);

    const tests = b.addTest(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    tests.root_module.addImport("objc", objc_dep.module("objc"));
    tests.linkLibC();
    tests.addFrameworkPath(.{ .cwd_relative = macos_private_framework });
    tests.linkFramework("CoreFoundation");
    tests.linkFramework("IOKit");
    tests.linkFramework("NetworkStatistics");

    const test_run = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&test_run.step);
}
