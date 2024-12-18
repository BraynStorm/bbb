///
/// How do server and client communicate
///
const std = @import("std");
const builtin = @import("builtin");
pub const tools = @import("tools.zig");

/// Structure containing public declarations of all packets
pub const Packets = struct {
    pub const Ping = extern struct {
        timestamp: i64,
    };
};

/// Contains all packet declarations
pub const AnyPacket = union(enum(u16)) {
    Ping: Packets.Ping,
};

pub const PacketCode = @typeInfo(AnyPacket).Union.tag_type.?;
pub const PacketSize = u16;

/// Header for each packet in the network.
pub const Header = extern struct {
    code: PacketCode,
    size: PacketSize,
};

// Validate that this protocol makes sense.
comptime {
    tools.validate_protocol(@This());
}
