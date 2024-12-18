const std = @import("std");
const testing = std.testing;

pub const protocol_worker = @import("protocol/worker_v001.zig");

test "_" {
    std.testing.refAllDecls(protocol_worker);
}
