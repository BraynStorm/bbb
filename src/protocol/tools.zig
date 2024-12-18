///
/// How do server and client communicate
///
const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

/// Declare a dynamic array (vector, arraylist) inside a packet.
pub fn PacketArray(comptime SizeT: type, comptime ValueT: type) type {
    // Intentionally not 'extern', even though it would be correct.
    return struct {
        len: SizeT,
        ptr: [*]ValueT,

        /// Indicate to decode_type that this should be treated like a slice.
        const bbb_slice = true;

        pub fn slice(self: *@This()) []ValueT {
            return self.ptr[0..self.len];
        }
        pub fn const_slice(self: *const @This()) []const ValueT {
            return self.ptr[0..self.len];
        }
    };
}

/// Declare a dynamically sized string for a packet.
pub fn PacketString(comptime SizeT: type) type {
    return PacketArray(SizeT, u8);
}

/// Return the packet-code of a packet.
fn packet_code(comptime Protocol: type, comptime Packet: type) Protocol.PacketCode {
    inline for (@typeInfo(Protocol.Packets).Struct.decls, 0..) |decl, i| {
        if (@field(Protocol.Packets, decl.name) == Packet)
            return @enumFromInt(i);
    } else {
        @compileError("Unknown packet type.");
    }
}
/// Return the size of a packet (if it is statically known) given
/// a packet code.
fn static_size_from_code(comptime Protocol: type, code: Protocol.PacketCode) ?u32 {
    inline for (@typeInfo(Protocol.Packets).Struct.decls, 0..) |decl, i| {
        const PacketType: type = @field(Protocol.Packets, decl.name);
        if (i == @intFromEnum(code)) {
            return static_size_with_header(Protocol, PacketType) orelse null;
        }
    } else {
        std.log.err("Unknown packet type {}.", .{code});
        @panic("Unknown packet type.");
    }
}

fn static_size_with_header(comptime Protocol: type, comptime PacketType: type) ?comptime_int {
    return if (static_size(PacketType)) |sswh|
        sswh + @sizeOf(Protocol.Header)
    else
        null;
}

fn static_size(comptime PacketType: type) ?comptime_int {
    if (@typeInfo(PacketType).Struct.layout == .@"extern") {
        return @sizeOf(PacketType);
    } else {
        return null;
    }
}

/// Comptime description of a struct produced by PacketArray or similar.
const PacketSliceDecl = struct {
    TypeT: type, //  the type itself = PacketArray(u64, u8)
    SizeT: type, //  the size-type   = u64
    ValueT: type, // the value-type  = u8

    name_len: []const u8, // the name of the field containing the len-part
    name_ptr: []const u8, // the name of the field containing the ptr-part

    /// Attempt to construct this decl from a struct type.
    /// Returns null on failure.
    pub fn init(comptime T: type) ?PacketSliceDecl {
        // One of PacketArray's instances or similar?
        switch (@typeInfo(T)) {
            .Struct => |s| {
                if (!@hasDecl(T, "bbb_slice") or T.bbb_slice != true)
                    return null;

                var SizeT: type = undefined;
                var ValueT: type = undefined;
                var name_len: []const u8 = undefined;
                var name_ptr: []const u8 = undefined;

                if (s.fields.len != 2)
                    return null;

                for (s.fields) |field| {
                    switch (@typeInfo(field.type)) {
                        .Pointer => |p| {
                            std.debug.assert(p.size == .Many);
                            std.debug.assert(!p.is_const);
                            std.debug.assert(!p.is_volatile);
                            std.debug.assert(!p.is_allowzero);
                            std.debug.assert(p.sentinel == null);

                            ValueT = p.child;
                            name_ptr = field.name;
                        },
                        .Int => {
                            SizeT = field.type;
                            name_len = field.name;
                        },
                        else => {
                            @compileLog(s, T, field);
                            @compileError("bbb_slice on an invalid type");
                        },
                    }
                }

                validate_packet_struct(ValueT);

                return .{
                    .TypeT = T,
                    .SizeT = SizeT,
                    .ValueT = ValueT,
                    .name_len = name_len,
                    .name_ptr = name_ptr,
                };
            },
            else => return null,
        }
    }
};

fn is_extern_struct(comptime T: type) bool {
    comptime {
        return @typeInfo(T).Struct.layout == .@"extern";
    }
}

fn is_dynamic_struct(comptime T: type) bool {
    comptime {
        var dynamic = false;

        for (std.meta.fields(T)) |field| {
            if (PacketSliceDecl.init(field.type)) |_| {
                dynamic = true;
            }
        }

        if (dynamic)
            std.debug.assert(@typeInfo(T).Struct.layout == .auto);

        return dynamic;
    }
}

fn validate_packet_struct(comptime T: type) void {
    comptime {
        switch (@typeInfo(T)) {
            .Int, .Float => {},
            .Struct => |s| {
                if (PacketSliceDecl.init(T)) |_| {} else {
                    for (s.fields) |field| {
                        validate_packet_struct(field.type);
                    }
                }
            },
            .Array => |a| {
                validate_packet_struct(a.child);
            },
            .Bool => {
                @compileLog(T);
                @compileError("bbb: bool in packet is inefficient - wastes 7bits.");
            },
            .Pointer => |p| switch (p.size) {
                .C, .One, .Slice => {
                    @compileLog(T);
                    @compileError("bbb: Pointers(1) are not supported");
                },
                .Many => {
                    // If this succeeds, we're fine.
                    if (PacketSliceDecl.init(T)) |_| {} else {
                        @compileLog(T);
                        @compileError("bbb: Pointers(2) are not supported");
                    }
                },
            },
            else => {
                @compileLog(T);
                @compileError("bbb: Unknown Packet struct field type.");
            },
        }
    }
}

pub const DecodeError = error{
    NeedMoreData,
    Corrupted,
    TheSizeIsALie,
};

fn packet_code_type(comptime Protocol: type) type {
    switch (@typeInfo(Protocol.AnyPacket)) {
        .Union => |u| {
            if (u.tag_type == null) {
                @compileError("Protocol.AnyPacket must a be a 'union(enum(PacketCode))'.");
            }

            // TODO: Ensure the PacketCode int is big enough

            comptime assert(u.tag_type.? == Protocol.PacketCode);
            return u.tag_type.?;
        },
        else => {
            @compileError("Protocol.PacketCode must be an enum");
        },
    }
}
/// Ensure the types and relationships of a Protocol definition are supported.
pub fn validate_protocol(comptime Protocol: type) void {
    comptime {
        const Header = Protocol.Header;
        const AnyPacket = Protocol.AnyPacket;

        // The header must be extern.
        //NOTE:
        // This is not technically necessary, but it is much better
        // to have a static header size for easy parsing and early
        // error detection.
        assert(is_extern_struct(Header));

        // Header must look like this:
        //
        // pub const Header = extern struct {
        //     code: PacketCode,
        //     size: PacketSize,
        // };
        assert(@hasField(Header, "code"));
        assert(@hasField(Header, "size"));

        // The PacketCode must a be an enum(nice_int) :D.
        const Code = packet_code_type(Protocol);
        switch (@typeInfo(Code)) {
            .Enum => |e| switch (@typeInfo(e.tag_type)) {
                .Int => |i| assert(i.bits == 8 or i.bits == 16 or i.bits == 32 or i.bits == 64),
                else => @compileError("bbb: Protocol.PacketCode must be an 8, 16, 32 or 64 bit integer enum."),
            },
            else => @compileError("bbb: Protocol.PacketCode must be an Enum"),
        }

        // AnyPacket verficiation
        switch (@typeInfo(AnyPacket)) {
            .Union => |u| {
                assert(u.layout == .auto);
                if (u.tag_type.? != Code) {
                    @compileError("bbb: Protocol.AnyPacket must be union(PacketCode).");
                }

                // Check each PAcket struct for unsupported things.
                for (u.fields) |packet_field| {
                    const PacketType: type = packet_field.type;
                    assert(is_extern_struct(PacketType) or is_dynamic_struct(PacketType));
                    validate_packet_struct(PacketType);
                }
            },
            else => @compileError("bbb: Protocol.AnyPacket must be a union(PacketCode)."),
        }
    }
}

fn decode_header(comptime Protocol: type, bytes: []const u8) DecodeError!Protocol.Header {
    if (bytes.len < header_size(Protocol)) {
        return DecodeError.NeedMoreData;
    }
    const header = std.mem.bytesToValue(Protocol.Header, bytes[0..header_size(Protocol)]);

    // Do some simple checks
    // const code: Protocol.PacketCode = std.meta.intToEnum(
    //     Protocol.PacketCode,
    //     @as(usize, @intCast(header.code)),
    // ) catch return DecodeError.Corrupted;

    if (static_size_from_code(Protocol, header.code)) |ss| {
        if (header.size != ss) {
            return DecodeError.TheSizeIsALie;
        }
    }

    return header;
}

fn header_size(comptime Protocol: type) comptime_int {
    return @sizeOf(Protocol.Header);
}

/// Decode a slice
///
/// !!! May modify bytes even on error !!!
fn decode_type_psd(
    comptime PSD: PacketSliceDecl,
    alloc: Allocator,
    bytes: *[]const u8,
) (Allocator.Error || DecodeError)!PSD.TypeT {
    const len = try decode_type(PSD.SizeT, alloc, bytes);

    const data = try alloc.alloc(PSD.ValueT, len);
    errdefer alloc.free(data);

    for (0..len) |i| {
        data[i] = try decode_type(PSD.ValueT, alloc, bytes);
    }

    var result: PSD.TypeT = undefined;
    @field(result, PSD.name_len) = @intCast(data.len);
    @field(result, PSD.name_ptr) = data.ptr;
    return result;
}
/// Decode / deserialize a given type from the
///
/// !!! May modify bytes even on error !!!
fn decode_type(
    comptime T: type,
    alloc: Allocator,
    bytes: *[]const u8,
) (Allocator.Error || DecodeError)!T {
    var result: T = undefined;
    var advance_by: usize = 0;
    switch (@typeInfo(T)) {
        .Struct => |s| {
            const size = comptime static_size(T);

            if (comptime is_extern_struct(T) and size != null) {
                // For extern structs with no pointers or arrays, we can just memcpy.
                std.debug.print("decode_type({s}) -> memcpy\n", .{@typeName(T)});

                advance_by = size.?;
                if (bytes.len < advance_by)
                    return DecodeError.NeedMoreData;

                result = std.mem.bytesToValue(T, bytes.*.ptr);
            } else if (comptime PacketSliceDecl.init(T)) |psd| {
                advance_by = 0; // We rely on the internals to advance.

                result = try decode_type_psd(psd, alloc, bytes);
            } else {
                // Otherwise, we have to do stuff field by field.
                std.debug.print("decode_type({s}) -> field-by-field\n", .{@typeName(T)});

                advance_by = 0; // We rely on the internals to advance.

                // Decode each field of the struct sequentially
                inline for (s.fields) |field| {
                    // Try deocding it from the stream, advancing if successful.
                    @field(result, field.name) = try decode_type(field.type, alloc, bytes);
                }
            }
        },
        .Void => {},
        .Float => |f| {
            const read_bytes = @divExact(f.bits, 8);

            // Pretend we're reading an int with the same bit-width.
            const int_bytes = std.mem.readInt(
                std.meta.Int(.unsigned, f.bits),
                bytes.*[0..read_bytes],
                .little,
            );

            // Convert the int-bytes to float-bytes
            result = @bitCast(int_bytes);

            // We consumed exactly this many bytes.
            advance_by = read_bytes;
        },
        .Int => |i| {
            // Read the int.
            const read_bytes = @divExact(i.bits, 8);
            result = std.mem.readInt(T, bytes.*[0..read_bytes], .little);

            // We consumed exactly this many bytes.
            advance_by = read_bytes;
        },
        .Pointer => |rp| {
            switch (rp.size) {
                .Slice => {
                    comptime assert(rp.is_allowzero == false);
                    comptime assert(rp.is_const == false);
                    comptime assert(rp.is_volatile == false);
                    comptime assert(rp.sentinel == null);
                },
                else => {
                    @compileLog(rp, T);
                    @compileError("Undecodable pointer type");
                },
            }
        },
        else => |e| {
            @compileLog(e, T);
            @compileError("bbb: Undecodable type");
        },
    }

    // Advance.
    bytes.* = bytes.*[advance_by..];

    return result;
}

pub fn DecodedPacket(comptime Protocol: type) type {
    return struct {
        decoded_len: usize,
        packet: Protocol.AnyPacket,
    };
}

/// Convert a maybe-partialy serialized packet to an actual packet.
///
/// If decoding is successful, this function advances the 'bytes' slice to the
/// end of the decoded region.
///
/// It is recommended that alloc is a type of arena allocator that supports
/// "reset" or similar operation, instead of having to deinit a whole bunch of
/// arrays.
///
/// It is important to note that the allocations are only used for dynamically
/// sized arrays inside the decoded packet. The base packet itself or static packets
/// do not incur allocations.
pub fn decode(
    comptime Protocol: type,
    alloc: Allocator,
    bytes: []const u8,
) (Allocator.Error || DecodeError)!DecodedPacket(Protocol) {
    comptime validate_protocol(Protocol);
    const header = try decode_header(Protocol, bytes[0..header_size(Protocol)]);
    var raw_body = bytes[header_size(Protocol)..];

    inline for (@typeInfo(Protocol.AnyPacket).Union.fields, 0..) |field, packet_i| {
        if (packet_i == @intFromEnum(header.code)) {
            const PacketType: type = field.type;
            const packet: Protocol.AnyPacket = @unionInit(
                Protocol.AnyPacket,
                field.name,
                try decode_type(PacketType, alloc, &raw_body),
            );
            return .{
                // Strange way to compute how many bytes were read, but it works.
                .decoded_len = bytes.len - raw_body.len,
                .packet = packet,
            };
        }
    } else {
        // Unknown packet.
        return DecodeError.Corrupted;
    }
}

test "Packet declarations" {
    const Protocol = TestProtocol;
    validate_protocol(Protocol);
}

test packet_code {
    const Protocol = TestProtocol;
    try std.testing.expectEqual(0, @intFromEnum(packet_code(Protocol, Protocol.Packets.Ping)));
    try std.testing.expectEqual(1, @intFromEnum(packet_code(Protocol, Protocol.Packets.ClientHello)));
}

test decode_header {
    const Protocol = TestProtocol;
    try std.testing.expectEqual(
        Protocol.Header{
            .code = packet_code(Protocol, Protocol.Packets.Ping),
            .size = static_size_with_header(Protocol, Protocol.Packets.Ping) orelse unreachable,
        },
        try decode_header(Protocol, &[_]u8{
            // Header
            0x00, 0x00, 0x00, 0x00, // code: u32 |
            0x10, 0x00, 0x00, 0x00, // size: u32 | header + timestamp
            // Body
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // timestamp
        }),
    );
}

/// A simple protocol defintion for unit-testing.
const TestProtocol = struct {
    pub const AnyPacket = union(enum(u32)) {
        Ping: Packets.Ping,
        ClientHello: Packets.ClientHello,
        ServerHello: Packets.ServerHello,
        Void: Packets.Void,
        ClientUsername: Packets.ClientUsername,
    };

    pub const PacketCode = @typeInfo(AnyPacket).Union.tag_type.?;
    pub const PacketSize = u32;

    /// Header for each packet in the network.
    pub const Header = extern struct {
        code: PacketCode,
        size: PacketSize,
    };

    // List all packets
    pub const Packets = struct {
        pub const Ping = extern struct {
            timestamp: i64,
        };
        pub const ClientHello = extern struct {
            client_version: u64,
        };
        pub const ServerHello = extern struct {
            update: f32,
        };
        pub const Void = extern struct {};
        pub const ClientUsername = struct {
            name: PacketArray(u32, u8),
        };
    };
};

test decode {
    const Protocol = TestProtocol;
    const alloc = std.testing.allocator;
    const DecodedPacketT = DecodedPacket(Protocol);

    try std.testing.expectEqual(
        DecodedPacketT{
            .decoded_len = 0x10,
            .packet = Protocol.AnyPacket{
                .Ping = .{ .timestamp = 0x16 },
            },
        },
        try decode(Protocol, alloc, &[_]u8{
            // Header
            0x00, 0x00, 0x00, 0x00, // code: u32 |
            0x10, 0x00, 0x00, 0x00, // size: u32 | header + timestamp
            // Body
            0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // timestamp
        }),
    );
    try std.testing.expectEqual(
        DecodedPacketT{
            .decoded_len = 0x0C,
            .packet = Protocol.AnyPacket{
                .ServerHello = .{ .update = 2.25 },
            },
        },
        try decode(Protocol, alloc, &[_]u8{
            // Header
            0x02, 0x00, 0x00, 0x00, // code: u32 | ServerHello
            0x0C, 0x00, 0x00, 0x00, // size: u32 | header + f32
            // Body = f32 (2.25) means these hex bytes.
            0x00, 0x00, 0x10, 0x40, // update
        }),
    );
}
test "dynamic decode" {
    const Protocol = TestProtocol;
    const alloc = std.testing.allocator;

    var r = try decode(Protocol, alloc, &[_]u8{
        // Header
        0x04, 0x00, 0x00, 0x00, // code: u32 |
        0x10, 0x00, 0x00, 0x00, // size: u32 |
        // Body
        0x04, 0x00, 0x00, 0x00, // str-len u32
        'a', 'b', 'c', 'd', // str-content
    });

    try std.testing.expectEqual(0x10, r.decoded_len);
    try std.testing.expectEqualSlices(u8, "abcd", r.packet.ClientUsername.name.const_slice());
    alloc.free(r.packet.ClientUsername.name.slice());
}
