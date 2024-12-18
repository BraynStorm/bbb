///
/// How do server and client communicate
///
const std = @import("std");
const builtin = @import("builtin");
pub const tools = @import("tools.zig");

/// Structure containing public declarations of all packets
pub const Packets = struct {
    /// Should be sent every once in a while to sync up clocks,
    /// and to check if the connection is alive.
    pub const Ping = extern struct {
        timestamp: i64,
    };

    /// Node seends this when it connects.
    pub const NodeHello = extern struct {
        major: u16,
        minor: u16,
        patch: u16,
        dev: u16,
        ping: Ping,
        // Node's GUID
        guid: [1024]u8,
    };

    /// Server sends this after receiving a NodeHello if everything is OK.
    pub const Affirmative = extern struct {
        ping: Ping,
    };

    /// Server sends a new node-executable and tells the Node to update itself with it.
    pub const UpdateAndRestart = struct {
        content: LongString,
    };

    /// Instructs the Node to run a given command in the default shell.
    pub const RunShellCommand = struct {
        command: ShortString,
    };

    /// Node sends this packet at some interval to keep the Server up-to-date
    /// with the state of the outputs.
    ///
    /// The two fields should be appended by the server, thus keeping a
    /// rolling log.
    pub const RunShellCommandPartialResult = struct {
        stdout: LongString,
        stderr: LongString,
    };

    /// Node sends this packet when the command finshes with the exit code.
    pub const RunShellCommandFinished = extern struct {
        exit_code: u32,
    };
};

/// Contains all packet declarations
pub const AnyPacket = union(enum(u16)) {
    Ping: Packets.Ping,
    NodeHello: Packets.NodeHello,
    Affirmative: Packets.Affirmative,
    UpdateAndRestart: Packets.UpdateAndRestart,
    RunShellCommand: Packets.RunShellCommand,
    RunShellCommandPartialResult: Packets.RunShellCommandPartialResult,
    RunShellCommandFinished: Packets.RunShellCommandFinished,
};

pub const PacketCode = @typeInfo(AnyPacket).Union.tag_type.?;
pub const PacketSize = u16;
const VeryString = tools.PacketString(u8);
const ShortString = tools.PacketString(u16);
const LongString = tools.PacketString(u32);

/// Header for each packet in the network.
pub const Header = extern struct {
    code: PacketCode,
    size: PacketSize,
};

// Validate that this protocol makes sense.
comptime {
    tools.validate_protocol(@This());
}
