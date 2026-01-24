//! Pure Zig DEFLATE Compression Implementation (RFC 1951)
//!
//! Implements DEFLATE compression algorithm with:
//! - LZ77 sliding window matching
//! - Fixed Huffman coding (type 1 blocks)
//! - GZIP container (RFC 1952)
//! - ZLIB container (RFC 1950)
//!
//! This is a custom implementation since Zig 0.15's std.compress.flate.Compress is incomplete.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

// =============================================================================
// Constants
// =============================================================================

const WINDOW_SIZE: usize = 32768; // 32KB sliding window
const MIN_MATCH: usize = 3; // Minimum match length
const MAX_MATCH: usize = 258; // Maximum match length

// =============================================================================
// BitWriter - Writes bits LSB first (DEFLATE order)
// =============================================================================

pub const BitWriter = struct {
    allocator: Allocator,
    output: std.ArrayListUnmanaged(u8) = .empty,
    bit_buffer: u32 = 0,
    bit_count: u5 = 0,

    pub fn init(allocator: Allocator) BitWriter {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *BitWriter) void {
        self.output.deinit(self.allocator);
    }

    /// Write bits LSB first
    pub fn writeBits(self: *BitWriter, value: u32, num_bits: u5) !void {
        self.bit_buffer |= value << self.bit_count;
        self.bit_count += num_bits;

        while (self.bit_count >= 8) {
            try self.output.append(self.allocator, @truncate(self.bit_buffer & 0xFF));
            self.bit_buffer >>= 8;
            self.bit_count -= 8;
        }
    }

    /// Write bits MSB first (for Huffman codes)
    pub fn writeBitsReversed(self: *BitWriter, value: u16, num_bits: u4) !void {
        var reversed: u32 = 0;
        var v = value;
        for (0..num_bits) |_| {
            reversed = (reversed << 1) | (v & 1);
            v >>= 1;
        }
        try self.writeBits(reversed, @intCast(num_bits));
    }

    /// Write a byte directly
    pub fn writeByte(self: *BitWriter, byte: u8) !void {
        try self.writeBits(byte, 8);
    }

    /// Flush remaining bits (pad with zeros)
    pub fn flush(self: *BitWriter) !void {
        if (self.bit_count > 0) {
            try self.output.append(self.allocator, @truncate(self.bit_buffer & 0xFF));
            self.bit_buffer = 0;
            self.bit_count = 0;
        }
    }

    pub fn getOutput(self: *BitWriter) []const u8 {
        return self.output.items;
    }

    pub fn toOwnedSlice(self: *BitWriter) ![]u8 {
        return self.output.toOwnedSlice(self.allocator);
    }
};

// =============================================================================
// Fixed Huffman Tables (RFC 1951 Section 3.2.6)
// =============================================================================

const FixedHuffman = struct {
    // Literal/Length codes (0-287)
    // 0-143: 8 bits, 00110000 - 10111111
    // 144-255: 9 bits, 110010000 - 111111111
    // 256-279: 7 bits, 0000000 - 0010111
    // 280-287: 8 bits, 11000000 - 11000111

    fn getLiteralCode(literal: u16) struct { code: u16, bits: u4 } {
        if (literal <= 143) {
            return .{ .code = @intCast(0x30 + literal), .bits = 8 };
        } else if (literal <= 255) {
            return .{ .code = @intCast(0x190 + literal - 144), .bits = 9 };
        } else if (literal <= 279) {
            return .{ .code = @intCast(literal - 256), .bits = 7 };
        } else {
            return .{ .code = @intCast(0xC0 + literal - 280), .bits = 8 };
        }
    }

    // Length encoding table (RFC 1951 Section 3.2.5)
    const LengthCode = struct {
        code: u16, // 257-285
        extra_bits: u4,
        base_length: u16,
    };

    const length_table = [_]LengthCode{
        .{ .code = 257, .extra_bits = 0, .base_length = 3 },
        .{ .code = 258, .extra_bits = 0, .base_length = 4 },
        .{ .code = 259, .extra_bits = 0, .base_length = 5 },
        .{ .code = 260, .extra_bits = 0, .base_length = 6 },
        .{ .code = 261, .extra_bits = 0, .base_length = 7 },
        .{ .code = 262, .extra_bits = 0, .base_length = 8 },
        .{ .code = 263, .extra_bits = 0, .base_length = 9 },
        .{ .code = 264, .extra_bits = 0, .base_length = 10 },
        .{ .code = 265, .extra_bits = 1, .base_length = 11 },
        .{ .code = 266, .extra_bits = 1, .base_length = 13 },
        .{ .code = 267, .extra_bits = 1, .base_length = 15 },
        .{ .code = 268, .extra_bits = 1, .base_length = 17 },
        .{ .code = 269, .extra_bits = 2, .base_length = 19 },
        .{ .code = 270, .extra_bits = 2, .base_length = 23 },
        .{ .code = 271, .extra_bits = 2, .base_length = 27 },
        .{ .code = 272, .extra_bits = 2, .base_length = 31 },
        .{ .code = 273, .extra_bits = 3, .base_length = 35 },
        .{ .code = 274, .extra_bits = 3, .base_length = 43 },
        .{ .code = 275, .extra_bits = 3, .base_length = 51 },
        .{ .code = 276, .extra_bits = 3, .base_length = 59 },
        .{ .code = 277, .extra_bits = 4, .base_length = 67 },
        .{ .code = 278, .extra_bits = 4, .base_length = 83 },
        .{ .code = 279, .extra_bits = 4, .base_length = 99 },
        .{ .code = 280, .extra_bits = 4, .base_length = 115 },
        .{ .code = 281, .extra_bits = 5, .base_length = 131 },
        .{ .code = 282, .extra_bits = 5, .base_length = 163 },
        .{ .code = 283, .extra_bits = 5, .base_length = 195 },
        .{ .code = 284, .extra_bits = 5, .base_length = 227 },
        .{ .code = 285, .extra_bits = 0, .base_length = 258 },
    };

    fn getLengthCode(length: u16) struct { code: u16, extra_bits: u4, extra_value: u16 } {
        var i: usize = length_table.len - 1;
        while (i > 0) : (i -= 1) {
            if (length >= length_table[i].base_length) {
                return .{
                    .code = length_table[i].code,
                    .extra_bits = length_table[i].extra_bits,
                    .extra_value = length - length_table[i].base_length,
                };
            }
        }
        return .{
            .code = length_table[0].code,
            .extra_bits = length_table[0].extra_bits,
            .extra_value = length - length_table[0].base_length,
        };
    }

    // Distance encoding table (RFC 1951 Section 3.2.5)
    const DistanceCode = struct {
        code: u5,
        extra_bits: u4,
        base_distance: u16,
    };

    const distance_table = [_]DistanceCode{
        .{ .code = 0, .extra_bits = 0, .base_distance = 1 },
        .{ .code = 1, .extra_bits = 0, .base_distance = 2 },
        .{ .code = 2, .extra_bits = 0, .base_distance = 3 },
        .{ .code = 3, .extra_bits = 0, .base_distance = 4 },
        .{ .code = 4, .extra_bits = 1, .base_distance = 5 },
        .{ .code = 5, .extra_bits = 1, .base_distance = 7 },
        .{ .code = 6, .extra_bits = 2, .base_distance = 9 },
        .{ .code = 7, .extra_bits = 2, .base_distance = 13 },
        .{ .code = 8, .extra_bits = 3, .base_distance = 17 },
        .{ .code = 9, .extra_bits = 3, .base_distance = 25 },
        .{ .code = 10, .extra_bits = 4, .base_distance = 33 },
        .{ .code = 11, .extra_bits = 4, .base_distance = 49 },
        .{ .code = 12, .extra_bits = 5, .base_distance = 65 },
        .{ .code = 13, .extra_bits = 5, .base_distance = 97 },
        .{ .code = 14, .extra_bits = 6, .base_distance = 129 },
        .{ .code = 15, .extra_bits = 6, .base_distance = 193 },
        .{ .code = 16, .extra_bits = 7, .base_distance = 257 },
        .{ .code = 17, .extra_bits = 7, .base_distance = 385 },
        .{ .code = 18, .extra_bits = 8, .base_distance = 513 },
        .{ .code = 19, .extra_bits = 8, .base_distance = 769 },
        .{ .code = 20, .extra_bits = 9, .base_distance = 1025 },
        .{ .code = 21, .extra_bits = 9, .base_distance = 1537 },
        .{ .code = 22, .extra_bits = 10, .base_distance = 2049 },
        .{ .code = 23, .extra_bits = 10, .base_distance = 3073 },
        .{ .code = 24, .extra_bits = 11, .base_distance = 4097 },
        .{ .code = 25, .extra_bits = 11, .base_distance = 6145 },
        .{ .code = 26, .extra_bits = 12, .base_distance = 8193 },
        .{ .code = 27, .extra_bits = 12, .base_distance = 12289 },
        .{ .code = 28, .extra_bits = 13, .base_distance = 16385 },
        .{ .code = 29, .extra_bits = 13, .base_distance = 24577 },
    };

    fn getDistanceCode(distance: u16) struct { code: u5, extra_bits: u4, extra_value: u16 } {
        var i: usize = distance_table.len - 1;
        while (i > 0) : (i -= 1) {
            if (distance >= distance_table[i].base_distance) {
                return .{
                    .code = distance_table[i].code,
                    .extra_bits = distance_table[i].extra_bits,
                    .extra_value = distance - distance_table[i].base_distance,
                };
            }
        }
        return .{
            .code = distance_table[0].code,
            .extra_bits = distance_table[0].extra_bits,
            .extra_value = distance - distance_table[0].base_distance,
        };
    }
};

// =============================================================================
// LZ77 Matching
// =============================================================================

const Match = struct {
    length: u16,
    distance: u16,
};

const LZ77 = struct {
    /// Find the longest match in the sliding window
    fn findMatch(data: []const u8, pos: usize, window_start: usize) ?Match {
        if (pos + MIN_MATCH > data.len) return null;

        var best_length: u16 = MIN_MATCH - 1;
        var best_distance: u16 = 0;

        const search_start = if (pos > WINDOW_SIZE) pos - WINDOW_SIZE else window_start;
        const max_length: u16 = @intCast(@min(MAX_MATCH, data.len - pos));

        // Simple brute-force search (can be optimized with hash chains)
        var search_pos = search_start;
        while (search_pos < pos) : (search_pos += 1) {
            var length: u16 = 0;
            while (length < max_length and
                search_pos + length < pos and
                data[search_pos + length] == data[pos + length])
            {
                length += 1;
            }

            if (length > best_length) {
                best_length = length;
                best_distance = @intCast(pos - search_pos);
                if (length == max_length) break;
            }
        }

        if (best_length >= MIN_MATCH) {
            return Match{ .length = best_length, .distance = best_distance };
        }
        return null;
    }
};

// =============================================================================
// DEFLATE Encoder
// =============================================================================

pub const DeflateEncoder = struct {
    allocator: Allocator,
    writer: BitWriter,

    pub fn init(allocator: Allocator) DeflateEncoder {
        return .{
            .allocator = allocator,
            .writer = BitWriter.init(allocator),
        };
    }

    pub fn deinit(self: *DeflateEncoder) void {
        self.writer.deinit();
    }

    /// Encode data using fixed Huffman codes
    pub fn encode(self: *DeflateEncoder, data: []const u8) ![]u8 {
        // Write block header: BFINAL=1, BTYPE=01 (fixed Huffman)
        try self.writer.writeBits(1, 1); // BFINAL
        try self.writer.writeBits(1, 2); // BTYPE = 01 (fixed Huffman)

        var pos: usize = 0;
        while (pos < data.len) {
            // Try to find a match
            if (LZ77.findMatch(data, pos, 0)) |match| {
                // Encode length
                const len_info = FixedHuffman.getLengthCode(match.length);
                const len_huff = FixedHuffman.getLiteralCode(len_info.code);
                try self.writer.writeBitsReversed(len_huff.code, len_huff.bits);
                if (len_info.extra_bits > 0) {
                    try self.writer.writeBits(len_info.extra_value, @intCast(len_info.extra_bits));
                }

                // Encode distance (5-bit code, reversed)
                const dist_info = FixedHuffman.getDistanceCode(match.distance);
                try self.writer.writeBitsReversed(dist_info.code, 5);
                if (dist_info.extra_bits > 0) {
                    try self.writer.writeBits(dist_info.extra_value, @intCast(dist_info.extra_bits));
                }

                pos += match.length;
            } else {
                // Encode literal
                const huff = FixedHuffman.getLiteralCode(data[pos]);
                try self.writer.writeBitsReversed(huff.code, huff.bits);
                pos += 1;
            }
        }

        // Write end-of-block marker (code 256)
        const eob = FixedHuffman.getLiteralCode(256);
        try self.writer.writeBitsReversed(eob.code, eob.bits);

        try self.writer.flush();
        return self.writer.toOwnedSlice();
    }
};

// =============================================================================
// CRC32 (for GZIP)
// =============================================================================

pub const Crc32 = struct {
    crc: u32 = 0xFFFFFFFF,

    // CRC32 lookup table (IEEE polynomial)
    fn makeTable() [256]u32 {
        @setEvalBranchQuota(10000);
        var t: [256]u32 = undefined;
        for (0..256) |i| {
            var c: u32 = @intCast(i);
            for (0..8) |_| {
                if (c & 1 != 0) {
                    c = 0xEDB88320 ^ (c >> 1);
                } else {
                    c = c >> 1;
                }
            }
            t[i] = c;
        }
        return t;
    }

    const table = makeTable();

    pub fn update(self: *Crc32, data: []const u8) void {
        for (data) |b| {
            self.crc = table[(self.crc ^ b) & 0xFF] ^ (self.crc >> 8);
        }
    }

    pub fn final(self: *Crc32) u32 {
        return self.crc ^ 0xFFFFFFFF;
    }
};

// =============================================================================
// Adler32 (for ZLIB)
// =============================================================================

pub const Adler32 = struct {
    a: u32 = 1,
    b: u32 = 0,

    const MOD: u32 = 65521;

    pub fn update(self: *Adler32, data: []const u8) void {
        for (data) |byte| {
            self.a = (self.a + byte) % MOD;
            self.b = (self.b + self.a) % MOD;
        }
    }

    pub fn final(self: *Adler32) u32 {
        return (self.b << 16) | self.a;
    }
};

// =============================================================================
// GZIP Encoder (RFC 1952)
// =============================================================================

pub fn compressGzip(allocator: Allocator, data: []const u8) ![]u8 {
    var result = std.ArrayListUnmanaged(u8).empty;
    errdefer result.deinit(allocator);

    // GZIP Header (10 bytes)
    try result.appendSlice(allocator, &[_]u8{
        0x1f, 0x8b, // Magic number
        0x08, // Compression method (deflate)
        0x00, // Flags
        0x00, 0x00, 0x00, 0x00, // Modification time
        0x00, // Extra flags
        0x03, // OS (Unix)
    });

    // Compress data
    var encoder = DeflateEncoder.init(allocator);
    defer encoder.deinit();
    const compressed = try encoder.encode(data);
    defer allocator.free(compressed);
    try result.appendSlice(allocator, compressed);

    // CRC32
    var crc = Crc32{};
    crc.update(data);
    const crc_value = crc.final();
    try result.appendSlice(allocator, &[_]u8{
        @truncate(crc_value),
        @truncate(crc_value >> 8),
        @truncate(crc_value >> 16),
        @truncate(crc_value >> 24),
    });

    // Original size (mod 2^32)
    const size: u32 = @truncate(data.len);
    try result.appendSlice(allocator, &[_]u8{
        @truncate(size),
        @truncate(size >> 8),
        @truncate(size >> 16),
        @truncate(size >> 24),
    });

    return result.toOwnedSlice(allocator);
}

// =============================================================================
// ZLIB Encoder (RFC 1950)
// =============================================================================

pub fn compressZlib(allocator: Allocator, data: []const u8) ![]u8 {
    var result = std.ArrayListUnmanaged(u8).empty;
    errdefer result.deinit(allocator);

    // ZLIB Header (2 bytes)
    // CMF: CM=8 (deflate), CINFO=7 (32K window)
    // FLG: FLEVEL=2 (default), FDICT=0, FCHECK for ((CMF*256+FLG) % 31 == 0)
    const cmf: u8 = 0x78; // 0111 1000
    const flg: u8 = 0x9C; // Check: (0x78 * 256 + 0x9C) % 31 = 0
    try result.appendSlice(allocator, &[_]u8{ cmf, flg });

    // Compress data
    var encoder = DeflateEncoder.init(allocator);
    defer encoder.deinit();
    const compressed = try encoder.encode(data);
    defer allocator.free(compressed);
    try result.appendSlice(allocator, compressed);

    // Adler32 (big endian)
    var adler = Adler32{};
    adler.update(data);
    const adler_value = adler.final();
    try result.appendSlice(allocator, &[_]u8{
        @truncate(adler_value >> 24),
        @truncate(adler_value >> 16),
        @truncate(adler_value >> 8),
        @truncate(adler_value),
    });

    return result.toOwnedSlice(allocator);
}

// =============================================================================
// Tests
// =============================================================================

test "CRC32" {
    var crc = Crc32{};
    crc.update("Hello, World!");
    try std.testing.expectEqual(@as(u32, 0xEC4AC3D0), crc.final());
}

test "Adler32" {
    var adler = Adler32{};
    adler.update("Hello, World!");
    try std.testing.expectEqual(@as(u32, 0x1F9E046A), adler.final());
}

test "BitWriter basic" {
    const allocator = std.testing.allocator;
    var writer = BitWriter.init(allocator);
    defer writer.deinit();

    try writer.writeBits(0b101, 3);
    try writer.writeBits(0b11010, 5);
    try writer.flush();

    try std.testing.expectEqual(@as(u8, 0b11010_101), writer.getOutput()[0]);
}

test "gzip compress and decompress round-trip" {
    const allocator = std.testing.allocator;
    const original = "Hello, World!";

    const compressed = try compressGzip(allocator, original);
    defer allocator.free(compressed);

    // Verify gzip magic number
    try std.testing.expectEqual(@as(u8, 0x1f), compressed[0]);
    try std.testing.expectEqual(@as(u8, 0x8b), compressed[1]);

    // Decompress using std library
    const flate = std.compress.flate;
    var input: std.Io.Reader = .fixed(compressed);
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();

    var decompressor: flate.Decompress = .init(&input, .gzip, &.{});
    _ = try decompressor.reader.streamRemaining(&output.writer);

    try std.testing.expectEqualStrings(original, output.written());
}

test "zlib compress and decompress round-trip" {
    const allocator = std.testing.allocator;
    const original = "Hello, World!";

    const compressed = try compressZlib(allocator, original);
    defer allocator.free(compressed);

    // Verify zlib header
    try std.testing.expectEqual(@as(u8, 0x78), compressed[0]);

    // Decompress using std library
    const flate = std.compress.flate;
    var input: std.Io.Reader = .fixed(compressed);
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();

    var decompressor: flate.Decompress = .init(&input, .zlib, &.{});
    _ = try decompressor.reader.streamRemaining(&output.writer);

    try std.testing.expectEqualStrings(original, output.written());
}

test "compress longer text" {
    const allocator = std.testing.allocator;
    const original = "The quick brown fox jumps over the lazy dog. " ** 10;

    const compressed = try compressGzip(allocator, original);
    defer allocator.free(compressed);

    // Should achieve some compression
    try std.testing.expect(compressed.len < original.len);

    // Decompress and verify
    const flate = std.compress.flate;
    var input: std.Io.Reader = .fixed(compressed);
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();

    var decompressor: flate.Decompress = .init(&input, .gzip, &.{});
    _ = try decompressor.reader.streamRemaining(&output.writer);

    try std.testing.expectEqualStrings(original, output.written());
}
