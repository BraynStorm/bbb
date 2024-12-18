const std = @import("std");
const builtin = @import("builtin");
const bbb = @import("bbb");

const log = std.log.scoped(.CLIENT);
const Allocator = std.mem.Allocator;

pub const std_options = std.Options{
    .log_level = .debug,
};

fn pipe_create_failed(e: std.posix.PipeError) void {
    log.err("failed to create pipes: {}", .{e});
    @panic("failed to create pipes");
}

pub const LivingChildPorcess = struct {
    pid: std.posix.pid_t,
    stdin: std.posix.fd_t,
    stdout: std.posix.fd_t,
    stderr: std.posix.fd_t,
};

pub const FinishedProcess = struct {
    code: i32,
    stdout: []u8,
    stderr: []u8,

    const Self = @This();

    pub fn deinit(self: *Self, alloc: Allocator) void {
        alloc.free(self.stdout);
        alloc.free(self.stderr);
    }
};

// Run 'bash -c $ARGV' and return the error code.
fn run_shell_command(alloc: Allocator, argv: []const [:0]const u8) FinishedProcess {
    const pid = std.posix.fork() catch unreachable;

    const new_stdin = std.posix.pipe2(.{}) catch unreachable;
    const new_stdout = std.posix.pipe2(.{}) catch unreachable;
    const new_stderr = std.posix.pipe2(.{}) catch unreachable;

    const parent = 0;
    const child = 1;

    if (pid == 0) {
        // Close the 'parent' set of pipes, they are only for the parent.
        std.posix.close(new_stdin[parent]);
        std.posix.close(new_stdout[parent]);
        std.posix.close(new_stderr[parent]);

        std.posix.close(new_stdin[child]);

        // Connect our STD to the pipes.
        // std.posix.dup2(new_stdin[child], std.posix.STDIN_FILENO) catch unreachable;
        std.posix.dup2(new_stdout[child], std.posix.STDOUT_FILENO) catch unreachable;
        std.posix.dup2(new_stderr[child], std.posix.STDERR_FILENO) catch unreachable;

        const shell = switch (builtin.os.tag) {
            .linux => "bash",
            .windows => "cmd",
            else => @compileError("Unsupported operating system"),
        };

        var mut_argv = alloc.alloc(?[*:0]const u8, argv.len + 3) catch unreachable;
        defer alloc.free(mut_argv);
        mut_argv[0] = shell;
        mut_argv[1] = "-c";
        mut_argv[mut_argv.len - 1] = null;
        for (0..argv.len) |i| {
            mut_argv[i + 2] = argv[i];
        }
        for (0.., mut_argv) |i, a| {
            log.info("actual argv[{}]: {?s}", .{ i, a });
        }

        const environ = std.os.environ;
        var null_terminated_environ = alloc.alloc(?[*:0]const u8, environ.len + 1) catch unreachable;
        defer alloc.free(null_terminated_environ);
        null_terminated_environ[null_terminated_environ.len - 1] = null;
        for (0..environ.len) |i| {
            null_terminated_environ[i] = environ[i];
        }

        // We're the child process
        switch (std.posix.execvpeZ_expandArg0(
            .expand,
            shell,
            @ptrCast(mut_argv.ptr),
            @ptrCast(null_terminated_environ.ptr),
        )) {
            error.Unexpected,
            error.SystemResources,
            error.AccessDenied,
            error.InvalidExe,
            error.FileSystem,
            error.IsDir,
            error.FileNotFound,
            error.NotDir,
            error.FileBusy,
            error.ProcessFdQuotaExceeded,
            error.SystemFdQuotaExceeded,
            error.NameTooLong,
            => |e| {
                std.log.err("execvpe error: {}", .{e});
                @panic("execvpe error");
            },
        }
        unreachable;
    } else {
        // Close the 'child' set of pipes, they are only for the child.
        // std.posix.close(new_stdin[child]);
        // std.posix.close(new_stdout[child]);
        // std.posix.close(new_stderr[child]);

        std.posix.close(new_stdin[parent]);

        // Buffer the STDOUT / STDERR data.
        const buffer_step = 1024;
        var buf_stdout = std.ArrayListUnmanaged(u8).initCapacity(alloc, buffer_step) catch unreachable;
        defer buf_stdout.deinit(alloc);
        var buf_stderr = std.ArrayListUnmanaged(u8).initCapacity(alloc, buffer_step) catch unreachable;
        defer buf_stderr.deinit(alloc);

        var can_read_err = true;
        var can_read_out = true;
        while (true) {
            log.info("loop", .{});
            if (can_read_out) {
                buf_stdout.ensureUnusedCapacity(alloc, buffer_step) catch unreachable;
                const read = std.posix.read(new_stdout[parent], buf_stdout.items.ptr[buf_stdout.items.len..buf_stdout.capacity]) catch |e| blk: {
                    log.err("failed to read from child's stdout: {}", .{e});
                    break :blk 0;
                };
                if (read == 0) {
                    can_read_out = false;
                } else {
                    log.info("read {}!", .{read});
                    buf_stdout.items.len += read;
                }
            } else if (can_read_err) {
                buf_stderr.ensureUnusedCapacity(alloc, buffer_step) catch unreachable;
                const read = std.posix.read(new_stderr[parent], buf_stdout.items.ptr[buf_stderr.items.len..buf_stderr.capacity]) catch |e| blk: {
                    log.err("failed to read from child's stderr: {}", .{e});
                    break :blk 0;
                };
                if (read == 0) {
                    can_read_err = false;
                } else {
                    log.info("read {}!", .{read});
                    buf_stderr.items.len += read;
                }
            } else {
                break;
            }
        }

        // Wait for the child process to finish.
        // TODO: Implement timeout mechanisms.
        const res = std.posix.waitpid(pid, 0);
        // Return the exit code.

        return FinishedProcess{
            .code = @bitCast(res.status),
            .stdout = buf_stdout.toOwnedSlice(alloc) catch unreachable,
            .stderr = buf_stderr.toOwnedSlice(alloc) catch unreachable,
        };
    }
    return 0;
}
fn run_simple_shell_command(alloc: Allocator, cmd: [:0]const u8) i32 {
    var result = run_shell_command(alloc, &[1][:0]const u8{cmd});
    result.deinit(alloc);
    return result.code;
}
pub fn main() void {
    var gpa = std.heap.GeneralPurposeAllocator(.{
        .enable_memory_limit = true,
    }){
        .requested_memory_limit = 16 * 1024 * 1024,
    };
    const alloc = gpa.allocator();
    _ = run_simple_shell_command(alloc, "curl ipconfig.org");
    // _ = run_shell_command(alloc, &[_][:0]const u8{"curl --help ipconfig.org"});
}

// test run_simple_shell_command {
//     const expect = std.testing.expect;
//     const alloc = std.testing.allocator;
//     switch (builtin.os.tag) {
//         .linux => {
//             // try expect(run_simple_shell_command(alloc, "true") == 0);
//             try expect(run_simple_shell_command(alloc, "false") != 0);
//             // try expect(run_simple_shell_command(alloc, "return $(1 + 1)") == 2);
//             // try expect(run_simple_shell_command(alloc, "[[ $(1 + 3) == 444 ]]") == 0);
//         },
//         else => {
//             @compileError("Unusupported OS");
//         },
//     }
// }
