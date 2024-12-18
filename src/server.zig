const std = @import("std");
const builtin = @import("builtin");
const bbb = @import("bbb");

const KiB = 1024;
const MiB = 1024 * 1024;

const log = std.log.scoped(.SERVER);
const debug = std.debug.print;
const Connection = std.net.Server.Connection;
const Connections = std.ArrayListUnmanaged(Connection);

const Config = struct {
    port: u16 = 33024,
    max_clients: usize = 128,
    max_memory: usize = 16 * MiB,

    pub fn load() Config {
        // TODO: Load the config from command line / environment.
        return .{};
    }
};

fn maybe_accept_client(server: *std.net.Server) ?std.net.Server.Connection {
    return server.accept() catch |err| {
        switch (err) {
            error.ProcessFdQuotaExceeded,
            error.SystemFdQuotaExceeded,
            error.SystemResources,
            error.Unexpected,
            error.NetworkSubsystemFailed,
            error.FileDescriptorNotASocket,
            error.OperationNotSupported,
            error.ConnectionAborted,
            error.SocketNotListening,
            error.ProtocolFailure,
            error.BlockedByFirewall,
            error.ConnectionResetByPeer,
            => {
                log.err("accept() - {}\n", .{err});
                return null;
            },
            error.WouldBlock => {
                return null;
            },
        }
    };
}

fn create_server(port: u16) !std.net.Server {
    const server_addr = std.net.Address.initIp4(
        [4]u8{ 0, 0, 0, 0 },
        port,
    );
    var server = try server_addr.listen(.{
        .reuse_address = true,
        .force_nonblocking = false,
    });
    errdefer server.deinit();
    return server;
}

pub fn main() !void {
    const config = Config.load();

    var gpa_store = std.heap.GeneralPurposeAllocator(.{
        .enable_memory_limit = true,
    }){
        // NOTE: Limit memorty to 16MiB.
        .requested_memory_limit = config.max_memory,
    };
    const gpa = gpa_store.allocator();

    var client_list = try Connections.initCapacity(gpa, config.max_clients);

    var server = try create_server(config.port);
    defer server.deinit();
    log.info("👂 on 0.0.0.0:{}", .{config.port});

    var running = true;
    running = true;
    while (running) {
        if (client_list.items.len < config.max_clients) {
            //NOTE:
            // Ensure we have enough capacity *BEFORE* we accept any clients.
            // That way, we don't need to close a client's connection just after
            // accepting it.
            client_list.ensureUnusedCapacity(gpa, 1) catch unreachable;

            if (maybe_accept_client(&server)) |client| {
                log.info("Accepted {}", .{client.address});
                client_list.appendAssumeCapacity(client);
            }
        } else {
            log.err(
                "info: Reached the maximum number of connected clients: {}",
                .{config.max_clients},
            );
        }
    }
}
