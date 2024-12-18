const std = @import("std");
const builtin = @import("builtin");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addStaticLibrary(.{
        .name = "bbb",
        .root_source_file = b.path("src/bbb.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(lib);

    const client = b.addExecutable(.{
        .name = "bbb_client",
        .root_source_file = b.path("src/client.zig"),
        .target = target,
        .optimize = optimize,
    });
    const server = b.addExecutable(.{
        .name = "bbb_server",
        .root_source_file = b.path("src/server.zig"),
        .target = target,
        .optimize = optimize,
    });

    client.linkLibC();

    client.root_module.addImport("bbb", &lib.root_module);
    server.root_module.addImport("bbb", &lib.root_module);

    b.installArtifact(client);
    b.installArtifact(server);

    const run_cmd_client = b.addRunArtifact(client);
    run_cmd_client.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd_client.addArgs(args);
    }

    const run_cmd_server = b.addRunArtifact(server);
    run_cmd_server.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd_server.addArgs(args);
    }
    const run_step_client = b.step("run-client", "Run the client");
    run_step_client.dependOn(&run_cmd_client.step);

    const run_step_server = b.step("run-server", "Run the server");
    run_step_server.dependOn(&run_cmd_server.step);

    const lib_tests = b.addTest(.{
        .root_source_file = b.path("src/bbb.zig"),
        .target = target,
        .optimize = optimize,
    });
    const client_tests = b.addTest(.{
        .root_source_file = b.path("src/client.zig"),
        .target = target,
        .optimize = optimize,
    });
    const server_tests = b.addTest(.{
        .root_source_file = b.path("src/server.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_lib_tests = b.addRunArtifact(lib_tests);
    const run_client_tests = b.addRunArtifact(client_tests);
    const run_server_tests = b.addRunArtifact(server_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_lib_tests.step);
    test_step.dependOn(&run_client_tests.step);
    test_step.dependOn(&run_server_tests.step);
}
