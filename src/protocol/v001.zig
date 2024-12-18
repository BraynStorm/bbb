///
/// How do server and client communicate
///
const std = @import("std");
const builtin = @import("builtin");

/// Contains all packet declarations
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

pub const PacketCode = enum(u32) { invalid = 0, _ };
pub const AnyPacket = union(enum(u32)) {
    Ping: Packets.Ping,
    Void: Packets.Void,
    ServerHello: Packets.ServerHello,
    ClientHello: Packets.ClientHello,
    ClientUsername: Packets.ClientUsername,
};

/// Header for each packet in the network.
pub const Header = extern struct {
    code: PacketCode,
    size: u32,
};

/// Return the packet-code of a packet.
pub fn packet_code(comptime PacketType: type) PacketCode {
    inline for (@typeInfo(Packets).Struct.decls, 1..) |decl, i| {
        if (@field(Packets, decl.name) == PacketType)
            return @enumFromInt(i);
    } else {
        @compileError("Unknown packet type.");
    }
}
/// Return the size of a packet (if it is statically known) given
/// a packet code.
pub fn static_size_from_code(code: PacketCode) ?u32 {
    inline for (@typeInfo(Packets).Struct.decls, 1..) |decl, i| {
        const PacketType: type = @field(Packets, decl.name);
        if (i == @intFromEnum(code)) {
            return static_size_with_header(PacketType) orelse null;
        }
    } else {
        std.log.err("Unknown packet type {}.", .{code});
        @panic("Unknown packet type.");
    }
}

pub fn static_size_with_header(comptime PacketType: type) ?comptime_int {
    return if (static_size(PacketType)) |sswh|
        sswh + @sizeOf(Header)
    else
        null;
}

pub fn static_size(comptime PacketType: type) ?comptime_int {
    if (@typeInfo(PacketType).Struct.layout == .@"extern") {
        return @sizeOf(PacketType);
    } else {
        return null;
    }
}

const PacketSliceDecl = struct {
    TypeT: type,
    SizeT: type,
    ValueT: type,

    name_len: []const u8,
    name_ptr: []const u8,

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
    return @typeInfo(T).Struct.layout == .@"extern";
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

pub const DecodeError = error{
    NeedMoreData,
    Corrupted,
};
pub fn decode_header(bytes: []const u8) DecodeError!Header {
    // Code is "u32".
    std.debug.assert(@sizeOf(PacketCode) == @sizeOf(u32));
    // Size is u32.
    std.debug.assert(@sizeOf(Header) - @sizeOf(PacketCode) == @sizeOf(u32));

    if (bytes.len < @sizeOf(Header)) {
        return DecodeError.NeedMoreData;
    }
    const raw_code = std.mem.readInt(u32, bytes[0..4], .little);
    const size = std.mem.readInt(u32, bytes[4..8], .little);

    // Do some simple checks
    const code: PacketCode = std.meta.intToEnum(PacketCode, raw_code) catch return DecodeError.Corrupted;

    if (static_size_from_code(code)) |ss| {
        if (size != ss) {
            return DecodeError.Corrupted;
        }
    }

    return Header{ .code = code, .size = size };
}

pub fn skip_header() comptime_int {
    return @sizeOf(Header);
}

const Allocator = std.mem.Allocator;

/// Decode a slice
///
/// !!! May modify bytes even on error !!!
pub fn decode_type_psd(
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
pub fn decode_type(
    comptime T: type,
    alloc: Allocator,
    bytes: *[]const u8,
) (Allocator.Error || DecodeError)!T {
    var result: T = undefined;
    var advance_by: usize = 0;
    switch (@typeInfo(T)) {
        .Struct => |s| {
            const size = static_size(T);

            if (is_extern_struct(T) and size != null) {
                // For extern structs with no pointers or arrays, we can just memcpy.
                std.debug.print("decode_type({s}) -> memcpy\n", .{@typeName(T)});

                advance_by = size.?;
                if (bytes.len < advance_by)
                    return DecodeError.NeedMoreData;

                result = std.mem.bytesToValue(T, bytes.*.ptr);
            } else if (PacketSliceDecl.init(T)) |psd| {
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
                    comptime std.debug.assert(rp.is_allowzero == false);
                    comptime std.debug.assert(rp.is_const == false);
                    comptime std.debug.assert(rp.is_volatile == false);
                    comptime std.debug.assert(rp.sentinel == null);
                },
                else => {
                    @compileLog(rp, T);
                    @compileError("Undecodable pointer type");
                },
            }
        },
        else => |e| {
            @compileLog(e, T);
            @compileError("Undecodable type");
        },
    }

    // Advance.
    bytes.* = bytes.*[advance_by..];

    return result;
}

/// Convert a maybe-partialy serialized packet to an actual packet.
///
/// If decoding is successful, this function advances the 'bytes' slice to the
/// end of the decoded region.
pub fn decode(alloc: Allocator, bytes: []const u8) (Allocator.Error || DecodeError)!struct {
    usize,
    AnyPacket,
} {
    const header = try decode_header(bytes[0..8]);
    var raw_body = bytes[skip_header()..];

    inline for (@typeInfo(Packets).Struct.decls, 1..) |packet_decl, packet_i| {
        if (packet_i == @intFromEnum(header.code)) {
            const PacketType: type = @field(Packets, packet_decl.name);
            const packet: AnyPacket = @unionInit(
                AnyPacket,
                packet_decl.name,
                try decode_type(PacketType, alloc, &raw_body),
            );
            return .{
                // Strange way to compute how many bytes were read, but it works.
                bytes.len - raw_body.len,
                packet,
            };
        }
    } else {
        // Unknown packet.
        return DecodeError.Corrupted;
    }
}

test "Packet declarations" {
    const expect = std.testing.expect;
    const expectEqual = std.testing.expectEqual;

    try expect(is_extern_struct(Header));
    comptime {
        for (@typeInfo(Packets).Struct.decls) |decl| {
            const PacketType: type = @field(Packets, decl.name);

            // All packets must be "extern" (C-style, stable layout).
            try expect(is_extern_struct(PacketType) or is_dynamic_struct(PacketType));
            // try expect(is_extern_struct(PacketWithHeader(PacketType)));
        }
    }

    try expectEqual(8 + @sizeOf(Header), static_size_with_header(Packets.Ping));
}

test packet_code {
    try std.testing.expectEqual(1, @intFromEnum(packet_code(Packets.Ping)));
    try std.testing.expectEqual(2, @intFromEnum(packet_code(Packets.ClientHello)));
}

test decode_header {
    try std.testing.expectEqual(
        Header{
            .code = packet_code(Packets.Ping),
            .size = static_size_with_header(Packets.Ping) orelse unreachable,
        },
        try decode_header(&[_]u8{
            // Header
            0x01, 0x00, 0x00, 0x00, // code: u32 |
            0x10, 0x00, 0x00, 0x00, // size: u32 | header + timestamp
            // Body
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // timestamp
        }),
    );
}

test decode {
    const alloc = std.testing.allocator;
    try std.testing.expectEqual(
        .{
            0x10, AnyPacket{
                .Ping = .{ .timestamp = 0x16 },
            },
        },
        try decode(alloc, &[_]u8{
            // Header
            0x01, 0x00, 0x00, 0x00, // code: u32 |
            0x10, 0x00, 0x00, 0x00, // size: u32 | header + timestamp
            // Body
            0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // timestamp
        }),
    );
    try std.testing.expectEqual(
        .{
            0x0C,
            AnyPacket{
                .ServerHello = .{ .update = 2.25 },
            },
        },
        try decode(alloc, &[_]u8{
            // Header
            0x03, 0x00, 0x00, 0x00, // code: u32 | ServerHello
            0x0C, 0x00, 0x00, 0x00, // size: u32 | header + f32
            // Body = f32 (2.25) means these hex bytes.
            0x00, 0x00, 0x10, 0x40, // update
        }),
    );
}
test "dynamic decode" {
    const alloc = std.testing.allocator;

    var r = try decode(alloc, &[_]u8{
        // Header
        0x05, 0x00, 0x00, 0x00, // code: u32 |
        0x10, 0x00, 0x00, 0x00, // size: u32 |
        // Body
        0x04, 0x00, 0x00, 0x00, // str-len u32
        'a', 'b', 'c', 'd', // str-content
    });

    try std.testing.expectEqual(0x10, r[0]);
    try std.testing.expectEqualSlices(u8, "abcd", r[1].ClientUsername.name.const_slice());
    alloc.free(r[1].ClientUsername.name.slice());
}

test "buffered" {
    // std.io.bufferedReader()
}
