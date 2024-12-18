const std = @import("std");
const testing = std.testing;

const Protocol = @import("protocol.zig");

test "BBB Tests" {
    std.testing.refAllDecls(Protocol);
}
