//! TLS 1.2 Server Implementation for httpx.zig
//!
//! Implements the server side of the TLS 1.2 handshake (RFC 5246) with
//! ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F) as the supported cipher suite.
//!
//! ## Protocol Flow
//! ```
//! Client                              Server
//!   | ---- ClientHello ------------>   |
//!   | <--- ServerHello -------------   |
//!   | <--- Certificate -------------   |
//!   | <--- ServerKeyExchange -------   |
//!   | <--- ServerHelloDone ---------   |
//!   | ---- ClientKeyExchange ------>   |
//!   | ---- ChangeCipherSpec ------->   |
//!   | ---- Finished --------------->   |
//!   | <--- ChangeCipherSpec --------   |
//!   | <--- Finished ----------------   |
//!   | <===> Application Data <=====>>  |
//! ```
//!
//! ## Supported Features
//! - Cipher: ECDHE_RSA_WITH_AES_128_GCM_SHA256
//! - Key Exchange: ECDHE with P-256 (secp256r1)
//! - Signature: RSA PKCS#1 v1.5 with SHA-256
//! - Record Protocol: TLS 1.2 with explicit nonce GCM

const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;
const der = std.crypto.Certificate.der;
const zio = @import("zio");
const Allocator = std.mem.Allocator;

// Crypto primitives
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
const Sha256 = crypto.hash.sha2.Sha256;
const HmacSha256 = crypto.auth.hmac.Hmac(Sha256);
const P256 = crypto.ecc.P256;

const RsaModulus = crypto.ff.Modulus(4096);
const RsaFe = RsaModulus.Fe;

/// TLS ContentType (RFC 5246 §6.2.1)
pub const ContentType = enum(u8) {
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
    _,
};

/// TLS HandshakeType (RFC 5246 §7.4)
pub const HandshakeType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    certificate = 11,
    server_key_exchange = 12,
    server_hello_done = 14,
    client_key_exchange = 16,
    finished = 20,
    _,
};

/// TLS Alert Level
pub const AlertLevel = enum(u8) {
    warning = 1,
    fatal = 2,
    _,
};

/// TLS Alert Description
pub const AlertDescription = enum(u8) {
    close_notify = 0,
    unexpected_message = 10,
    bad_record_mac = 20,
    handshake_failure = 40,
    decode_error = 50,
    protocol_version = 70,
    internal_error = 80,
    no_application_protocol = 120,
    _,
};

/// Our supported cipher suite
pub const ECDHE_RSA_WITH_AES_128_GCM_SHA256: u16 = 0xC02F;

/// TLS protocol version 1.2
pub const TLS_12: u16 = 0x0303;

/// Maximum TLS record payload size
pub const MAX_RECORD_LEN = 16384;
/// TLS record header: type(1) + version(2) + length(2)
pub const RECORD_HEADER_LEN = 5;
/// GCM tag size
pub const GCM_TAG_LEN = 16;
/// GCM explicit nonce size (for TLS 1.2)
pub const GCM_EXPLICIT_NONCE_LEN = 8;
/// GCM implicit nonce (IV) size
pub const GCM_IMPLICIT_IV_LEN = 4;

/// TLS 1.2 Server Configuration
pub const ServerTlsConfig = struct {
    /// DER-encoded certificate chain (one or more certificates)
    cert_chain: []const []const u8,
    /// RSA private key in DER format
    private_key_der: []const u8,
    /// Optional ALPN protocols this server is willing to negotiate.
    /// Example: &.{ "http/1.1", "h2" }
    supported_alpn_protocols: []const []const u8 = &.{},
    /// Allocator for temporary handshake buffers
    allocator: Allocator,
};

/// GCM cipher state for one direction (read or write)
const GcmCipherState = struct {
    key: [16]u8,
    implicit_nonce: [GCM_IMPLICIT_IV_LEN]u8,
    seq_num: u64 = 0,

    fn makeNonce(self: *const GcmCipherState, explicit: [GCM_EXPLICIT_NONCE_LEN]u8) [12]u8 {
        var nonce: [12]u8 = undefined;
        @memcpy(nonce[0..GCM_IMPLICIT_IV_LEN], &self.implicit_nonce);
        @memcpy(nonce[GCM_IMPLICIT_IV_LEN..], &explicit);
        return nonce;
    }

    fn nextExplicitNonce(self: *GcmCipherState) [GCM_EXPLICIT_NONCE_LEN]u8 {
        var nonce: [GCM_EXPLICIT_NONCE_LEN]u8 = undefined;
        mem.writeInt(u64, &nonce, self.seq_num, .big);
        self.seq_num += 1;
        return nonce;
    }
};

/// Errors that can occur during TLS operations
pub const TlsError = error{
    HandshakeFailed,
    NoApplicationProtocol,
    UnsupportedCipherSuite,
    UnsupportedProtocolVersion,
    BadRecordMac,
    DecodeError,
    UnexpectedMessage,
    InternalError,
    AlertReceived,
    ConnectionClosed,
    RecordTooLarge,
    InvalidCertificate,
    InvalidPrivateKey,
    OutOfMemory,
    ReadFailed,
    WriteFailed,
};

/// TLS 1.2 Server connection state.
///
/// Wraps a raw byte stream (anything with `read` and `writeAll` methods)
/// and provides transparent TLS encryption/decryption.
pub fn TlsServer(comptime Stream: type) type {
    return struct {
        stream: Stream,
        allocator: Allocator,

        // Cipher states (set after handshake)
        read_cipher: ?GcmCipherState = null,
        write_cipher: ?GcmCipherState = null,
        read_encrypted: bool = false,
        write_encrypted: bool = false,

        // Handshake transcript (SHA-256 hash of all handshake messages)
        transcript: Sha256 = Sha256.init(.{}),

        // Master secret (derived during handshake)
        master_secret: [48]u8 = undefined,

        // Connection state
        handshake_done: bool = false,
        negotiated_alpn_protocol: ?[]const u8 = null,

        // Read buffer for decrypted data
        plaintext_buf: [MAX_RECORD_LEN]u8 = undefined,
        plaintext_len: usize = 0,
        plaintext_off: usize = 0,

        read_timeout: zio.Timeout = .none,
        write_timeout: zio.Timeout = .none,

        const Self = @This();

        pub fn init(stream: Stream, allocator: Allocator) Self {
            return .{
                .stream = stream,
                .allocator = allocator,
            };
        }

        pub fn setReadTimeout(self: *Self, timeout: zio.Timeout) void {
            self.read_timeout = timeout;
        }

        pub fn setWriteTimeout(self: *Self, timeout: zio.Timeout) void {
            self.write_timeout = timeout;
        }

        pub fn negotiatedAlpnProtocol(self: *const Self) ?[]const u8 {
            return self.negotiated_alpn_protocol;
        }

        // =================================================================
        // Record Layer
        // =================================================================

        /// Read a single TLS record from the stream.
        /// Returns (content_type, payload).
        /// Caller must use the returned payload before the next call.
        fn readRecord(self: *Self, buf: []u8) !struct { ContentType, []const u8 } {
            // Read 5-byte header
            var hdr: [RECORD_HEADER_LEN]u8 = undefined;
            try self.readExact(&hdr);

            const ct: ContentType = @enumFromInt(hdr[0]);
            const length = mem.readInt(u16, hdr[3..5], .big);

            if (length > MAX_RECORD_LEN + 256) return TlsError.RecordTooLarge;
            if (length > buf.len) return TlsError.RecordTooLarge;

            try self.readExact(buf[0..length]);
            const payload = buf[0..length];

            // If cipher is active, decrypt
            if (self.read_encrypted) {
                const cipher = &(self.read_cipher orelse return TlsError.HandshakeFailed);
                if (length < GCM_EXPLICIT_NONCE_LEN + GCM_TAG_LEN)
                    return TlsError.BadRecordMac;

                const explicit_nonce = payload[0..GCM_EXPLICIT_NONCE_LEN].*;
                const ciphertext_with_tag = payload[GCM_EXPLICIT_NONCE_LEN..];
                const ct_len = ciphertext_with_tag.len - GCM_TAG_LEN;
                const ciphertext = ciphertext_with_tag[0..ct_len];
                const tag = ciphertext_with_tag[ct_len..][0..GCM_TAG_LEN].*;

                const nonce = cipher.makeNonce(explicit_nonce);

                // Additional data: seq_num(8) + type(1) + version(2) + length(2)
                var aad: [13]u8 = undefined;
                mem.writeInt(u64, aad[0..8], cipher.seq_num, .big);
                aad[8] = hdr[0];
                aad[9] = hdr[1];
                aad[10] = hdr[2];
                mem.writeInt(u16, aad[11..13], @intCast(ct_len), .big);

                // Decrypt in-place into buf
                Aes128Gcm.decrypt(
                    buf[0..ct_len],
                    ciphertext,
                    tag,
                    &aad,
                    nonce,
                    cipher.key,
                ) catch return TlsError.BadRecordMac;

                cipher.seq_num += 1;
                return .{ ct, buf[0..ct_len] };
            }

            return .{ ct, payload };
        }

        /// Write a TLS record to the stream.
        fn writeRecord(self: *Self, ct: ContentType, payload: []const u8) !void {
            if (self.write_encrypted) {
                const cipher = &(self.write_cipher orelse return TlsError.HandshakeFailed);
                // Encrypted record
                const explicit = cipher.nextExplicitNonce();
                const nonce = cipher.makeNonce(explicit);

                // AAD: seq_num(8) + type(1) + version(2) + plaintext_length(2)
                var aad: [13]u8 = undefined;
                mem.writeInt(u64, aad[0..8], cipher.seq_num - 1, .big); // seq was already incremented
                aad[8] = @intFromEnum(ct);
                aad[9] = 0x03;
                aad[10] = 0x03;
                mem.writeInt(u16, aad[11..13], @intCast(payload.len), .big);

                var ciphertext_buf: [MAX_RECORD_LEN]u8 = undefined;
                var tag: [GCM_TAG_LEN]u8 = undefined;
                Aes128Gcm.encrypt(
                    ciphertext_buf[0..payload.len],
                    &tag,
                    payload,
                    &aad,
                    nonce,
                    cipher.key,
                );

                // Record: header + explicit_nonce + ciphertext + tag
                const record_len = GCM_EXPLICIT_NONCE_LEN + payload.len + GCM_TAG_LEN;
                var hdr: [RECORD_HEADER_LEN]u8 = undefined;
                hdr[0] = @intFromEnum(ct);
                hdr[1] = 0x03;
                hdr[2] = 0x03;
                mem.writeInt(u16, hdr[3..5], @intCast(record_len), .big);

                try self.writeAllStream(&hdr);
                try self.writeAllStream(&explicit);
                try self.writeAllStream(ciphertext_buf[0..payload.len]);
                try self.writeAllStream(&tag);
            } else {
                // Plaintext record
                var hdr: [RECORD_HEADER_LEN]u8 = undefined;
                hdr[0] = @intFromEnum(ct);
                hdr[1] = 0x03;
                hdr[2] = 0x03;
                mem.writeInt(u16, hdr[3..5], @intCast(payload.len), .big);

                try self.writeAllStream(&hdr);
                try self.writeAllStream(payload);
            }
        }

        // =================================================================
        // Handshake
        // =================================================================

        /// Perform the TLS 1.2 server handshake.
        pub fn handshake(self: *Self, config: ServerTlsConfig) !void {
            self.handshakeImpl(config) catch |err| {
                self.sendFatalAlertForError(err);
                return err;
            };
        }

        fn handshakeImpl(self: *Self, config: ServerTlsConfig) !void {
            // 1. Read ClientHello
            var record_buf: [MAX_RECORD_LEN + 256]u8 = undefined;
            const ct1, const client_hello = try self.readRecord(&record_buf);
            if (ct1 != .handshake) return TlsError.UnexpectedMessage;
            if (client_hello.len < 4) return TlsError.DecodeError;
            if (client_hello[0] != @intFromEnum(HandshakeType.client_hello))
                return TlsError.UnexpectedMessage;

            self.transcript.update(client_hello);

            // Parse ClientHello to extract client_random
            const ch = try parseClientHello(client_hello, config.supported_alpn_protocols);
            self.negotiated_alpn_protocol = ch.selected_alpn_protocol;

            // 2. Generate server random and ECDHE keypair
            var server_random: [32]u8 = undefined;
            crypto.random.bytes(&server_random);

            // ECDHE: Generate server ephemeral key pair (P-256)
            const ecdhe_secret = P256.scalar.random(.big);
            const ecdhe_point = try P256.basePoint.mul(ecdhe_secret, .big);
            const server_pubkey = ecdhe_point.toUncompressedSec1();

            // 3. Send ServerHello
            try self.sendServerHello(server_random, ch.selected_alpn_protocol);

            // 4. Send Certificate
            try self.sendCertificate(config.cert_chain);

            // 5. Send ServerKeyExchange (ECDHE params + RSA signature)
            try self.sendServerKeyExchange(
                ch.client_random,
                server_random,
                server_pubkey,
                config.private_key_der,
            );

            // 6. Send ServerHelloDone
            try self.sendServerHelloDone();

            // 7. Read ClientKeyExchange
            var record_buf2: [MAX_RECORD_LEN + 256]u8 = undefined;
            const ct2, const cke_data = try self.readRecord(&record_buf2);
            if (ct2 != .handshake) return TlsError.UnexpectedMessage;
            self.transcript.update(cke_data);

            // Parse client public key from ClientKeyExchange
            const client_pubkey_sec1 = try parseClientKeyExchange(cke_data);

            // Compute shared secret via ECDH
            const client_point = try P256.fromSec1(client_pubkey_sec1);
            const shared_point = try client_point.mul(ecdhe_secret, .big);
            const premaster_secret = shared_point.affineCoordinates().x.toBytes(.big);

            // Derive master secret (PRF)
            self.master_secret = prfMasterSecret(
                premaster_secret,
                ch.client_random,
                server_random,
            );

            // Derive key material
            const key_block = prfKeyExpansion(
                self.master_secret,
                server_random,
                ch.client_random,
            );

            // Extract keys from key_block
            // client_write_key(16) + server_write_key(16) + client_write_iv(4) + server_write_iv(4)
            self.read_cipher = .{
                .key = key_block[0..16].*,
                .implicit_nonce = key_block[32..36].*,
            };
            self.write_cipher = .{
                .key = key_block[16..32].*,
                .implicit_nonce = key_block[36..40].*,
            };

            // 8. Read ChangeCipherSpec from client
            var record_buf3: [MAX_RECORD_LEN + 256]u8 = undefined;
            const ct3, _ = try self.readRecord(&record_buf3);
            if (ct3 != .change_cipher_spec) return TlsError.UnexpectedMessage;
            self.read_encrypted = true;

            // 9. Read client Finished (now encrypted)
            var record_buf4: [MAX_RECORD_LEN + 256]u8 = undefined;
            const ct4, const client_finished = try self.readRecord(&record_buf4);
            if (ct4 != .handshake) return TlsError.UnexpectedMessage;

            // Verify client Finished
            const transcript_hash = self.transcriptHash();
            const expected_verify = prfVerifyData(self.master_secret, "client finished", transcript_hash);
            if (client_finished.len < 16 or !mem.eql(u8, client_finished[4..16], &expected_verify)) {
                return TlsError.HandshakeFailed;
            }
            self.transcript.update(client_finished);

            // 10. Send ChangeCipherSpec
            try self.writeRecord(.change_cipher_spec, &[_]u8{1});
            self.write_encrypted = true;

            // 11. Send server Finished
            const server_transcript_hash = self.transcriptHash();
            const server_verify = prfVerifyData(self.master_secret, "server finished", server_transcript_hash);
            var finished_msg: [16]u8 = undefined;
            finished_msg[0] = @intFromEnum(HandshakeType.finished);
            finished_msg[1] = 0;
            finished_msg[2] = 0;
            finished_msg[3] = 12; // verify_data length
            @memcpy(finished_msg[4..16], &server_verify);
            try self.writeRecord(.handshake, &finished_msg);

            self.handshake_done = true;
        }

        // =================================================================
        // Handshake Message Builders
        // =================================================================

        fn sendServerHello(self: *Self, server_random: [32]u8, selected_alpn_protocol: ?[]const u8) !void {
            // Fixed body fields: version(2) + random(32) + session_id_len(1) +
            // cipher_suite(2) + compression(1)
            const fixed_body_len = 38;
            // Always include renegotiation_info extension (5 bytes total)
            var extensions_len: usize = 5;
            if (selected_alpn_protocol) |proto| {
                // ALPN extension: type(2) + ext_len(2) + list_len(2) + proto_len(1) + proto
                extensions_len += 7 + proto.len;
            }

            const body_len = fixed_body_len + 2 + extensions_len; // + extensions_len field
            const msg_len = 4 + body_len;

            var msg = try self.allocator.alloc(u8, msg_len);
            defer self.allocator.free(msg);

            msg[0] = @intFromEnum(HandshakeType.server_hello);
            msg[1] = @intCast((body_len >> 16) & 0xFF);
            msg[2] = @intCast((body_len >> 8) & 0xFF);
            msg[3] = @intCast(body_len & 0xFF);

            // Protocol version TLS 1.2
            msg[4] = 0x03;
            msg[5] = 0x03;
            // Server random
            @memcpy(msg[6..38], &server_random);
            // Session ID length = 0
            msg[38] = 0;
            // Cipher suite
            mem.writeInt(u16, msg[39..41], ECDHE_RSA_WITH_AES_128_GCM_SHA256, .big);
            // Compression method (null)
            msg[41] = 0;

            // Extensions total length
            mem.writeInt(u16, msg[42..44], @intCast(extensions_len), .big);
            var off: usize = 44;

            // Extension: renegotiation_info (RFC 5746)
            msg[off] = 0xFF;
            msg[off + 1] = 0x01;
            msg[off + 2] = 0x00;
            msg[off + 3] = 0x01;
            msg[off + 4] = 0x00;
            off += 5;

            if (selected_alpn_protocol) |proto| {
                // Extension type: ALPN (0x0010)
                msg[off] = 0x00;
                msg[off + 1] = 0x10;
                // Extension data length: list_len(2) + proto_len(1) + proto
                mem.writeInt(u16, msg[off + 2 .. off + 4], @intCast(3 + proto.len), .big);
                // ProtocolNameList length
                mem.writeInt(u16, msg[off + 4 .. off + 6], @intCast(1 + proto.len), .big);
                msg[off + 6] = @intCast(proto.len);
                @memcpy(msg[off + 7 .. off + 7 + proto.len], proto);
                off += 7 + proto.len;
            }

            std.debug.assert(off == msg.len);

            self.transcript.update(msg);
            try self.writeRecord(.handshake, msg);
        }

        fn sendFatalAlertForError(self: *Self, err: anyerror) void {
            const desc = alertDescriptionForError(err);
            // Skip if we can no longer write reliably.
            switch (err) {
                TlsError.ConnectionClosed,
                TlsError.ReadFailed,
                TlsError.WriteFailed,
                => return,
                else => {},
            }

            const alert = [_]u8{
                @intFromEnum(AlertLevel.fatal),
                @intFromEnum(desc),
            };
            self.writeRecord(.alert, &alert) catch {};
        }

        fn sendCertificate(self: *Self, cert_chain: []const []const u8) !void {
            // Calculate total certificates size
            var certs_len: usize = 0;
            for (cert_chain) |cert| {
                certs_len += 3 + cert.len; // 3 bytes length prefix per cert
            }

            const total_len = 3 + certs_len; // 3 bytes for certificates list length
            const msg_len = 4 + total_len; // 4 bytes handshake header

            var msg = try self.allocator.alloc(u8, msg_len);
            defer self.allocator.free(msg);

            // Handshake header
            msg[0] = @intFromEnum(HandshakeType.certificate);
            msg[1] = @intCast((total_len >> 16) & 0xFF);
            msg[2] = @intCast((total_len >> 8) & 0xFF);
            msg[3] = @intCast(total_len & 0xFF);

            // Certificates list length (3 bytes)
            msg[4] = @intCast((certs_len >> 16) & 0xFF);
            msg[5] = @intCast((certs_len >> 8) & 0xFF);
            msg[6] = @intCast(certs_len & 0xFF);

            // Each certificate
            var off: usize = 7;
            for (cert_chain) |cert| {
                msg[off] = @intCast((cert.len >> 16) & 0xFF);
                msg[off + 1] = @intCast((cert.len >> 8) & 0xFF);
                msg[off + 2] = @intCast(cert.len & 0xFF);
                @memcpy(msg[off + 3 .. off + 3 + cert.len], cert);
                off += 3 + cert.len;
            }

            self.transcript.update(msg);
            try self.writeRecord(.handshake, msg);
        }

        fn sendServerKeyExchange(
            self: *Self,
            client_random: [32]u8,
            server_random: [32]u8,
            server_pubkey: [65]u8,
            private_key_der: []const u8,
        ) !void {
            // ServerKeyExchange for ECDHE:
            //   ec_params: curve_type(1) + named_curve(2) = 3
            //   public_key: length(1) + point(65) = 66
            //   signature: hash_algo(1) + sig_algo(1) + sig_len(2) + sig
            const ec_params_len = 3 + 1 + 65; // curve_type + named_curve + pubkey_len + pubkey

            // Data to sign: client_random + server_random + ec_params
            var sign_data: [32 + 32 + ec_params_len]u8 = undefined;
            @memcpy(sign_data[0..32], &client_random);
            @memcpy(sign_data[32..64], &server_random);
            // EC params
            sign_data[64] = 0x03; // named_curve
            sign_data[65] = 0x00; // secp256r1 = 0x0017
            sign_data[66] = 0x17;
            sign_data[67] = 65; // public key length
            @memcpy(sign_data[68..133], &server_pubkey);

            // Sign with RSA (SHA-256 + PKCS#1 v1.5)
            const signature = try rsaSign(self.allocator, private_key_der, &sign_data);
            defer self.allocator.free(signature);

            // Build message
            const sig_section_len = 2 + 2 + signature.len; // hash+sig algo(2) + sig_len(2) + sig
            const body_len = ec_params_len + sig_section_len;
            const msg_len = 4 + body_len; // handshake header(4) + body

            var msg = try self.allocator.alloc(u8, msg_len);
            defer self.allocator.free(msg);

            // Handshake header
            msg[0] = @intFromEnum(HandshakeType.server_key_exchange);
            msg[1] = @intCast((body_len >> 16) & 0xFF);
            msg[2] = @intCast((body_len >> 8) & 0xFF);
            msg[3] = @intCast(body_len & 0xFF);

            // EC parameters
            var off: usize = 4;
            @memcpy(msg[off .. off + ec_params_len], sign_data[64 .. 64 + ec_params_len]);
            off += ec_params_len;

            // Signature algorithm: SHA256(4) + RSA(1)
            msg[off] = 0x04; // SHA-256
            msg[off + 1] = 0x01; // RSA
            off += 2;

            // Signature length
            mem.writeInt(u16, msg[off..][0..2], @intCast(signature.len), .big);
            off += 2;

            // Signature
            @memcpy(msg[off .. off + signature.len], signature);

            self.transcript.update(msg);
            try self.writeRecord(.handshake, msg);
        }

        fn sendServerHelloDone(self: *Self) !void {
            var msg: [4]u8 = undefined;
            msg[0] = @intFromEnum(HandshakeType.server_hello_done);
            msg[1] = 0;
            msg[2] = 0;
            msg[3] = 0;

            self.transcript.update(&msg);
            try self.writeRecord(.handshake, &msg);
        }

        fn transcriptHash(self: *Self) [32]u8 {
            // Get hash without finalizing the running state
            var copy = self.transcript;
            var hash: [32]u8 = undefined;
            copy.final(&hash);
            return hash;
        }

        // =================================================================
        // Application Data (public API)
        // =================================================================

        /// Read decrypted application data.
        /// Returns 0 on connection close.
        pub fn read(self: *Self, buf: []u8) !usize {
            // Return buffered plaintext first
            if (self.plaintext_off < self.plaintext_len) {
                const avail = self.plaintext_len - self.plaintext_off;
                const n = @min(avail, buf.len);
                @memcpy(buf[0..n], self.plaintext_buf[self.plaintext_off..][0..n]);
                self.plaintext_off += n;
                return n;
            }

            // Read next record
            var record_buf: [MAX_RECORD_LEN + 256]u8 = undefined;
            const ct, const data = self.readRecord(&record_buf) catch |err| switch (err) {
                TlsError.ConnectionClosed => return 0,
                else => return err,
            };

            switch (ct) {
                .application_data => {
                    const n = @min(data.len, buf.len);
                    @memcpy(buf[0..n], data[0..n]);
                    if (data.len > n) {
                        // Buffer remaining
                        const remaining = data.len - n;
                        @memcpy(self.plaintext_buf[0..remaining], data[n..]);
                        self.plaintext_len = remaining;
                        self.plaintext_off = 0;
                    }
                    return n;
                },
                .alert => {
                    if (data.len >= 2 and data[1] == 0) return 0; // close_notify
                    return TlsError.AlertReceived;
                },
                else => return TlsError.UnexpectedMessage,
            }
        }

        /// Write application data (encrypted).
        pub fn writeAll(self: *Self, data: []const u8) !void {
            if (!self.handshake_done) return TlsError.HandshakeFailed;

            var off: usize = 0;
            while (off < data.len) {
                const chunk = @min(data.len - off, MAX_RECORD_LEN);
                try self.writeRecord(.application_data, data[off .. off + chunk]);
                off += chunk;
            }
        }

        /// Send close_notify alert.
        pub fn close(self: *Self) void {
            const alert = [_]u8{
                @intFromEnum(AlertLevel.warning),
                @intFromEnum(AlertDescription.close_notify),
            };
            self.writeRecord(.alert, &alert) catch {};
        }

        // =================================================================
        // Low-level I/O helpers
        // =================================================================

        fn readExact(self: *Self, buf: []u8) !void {
            var total: usize = 0;
            while (total < buf.len) {
                const n = self.stream.read(buf[total..], self.read_timeout) catch
                    return TlsError.ReadFailed;
                if (n == 0) return TlsError.ConnectionClosed;
                total += n;
            }
        }

        fn writeAllStream(self: *Self, data: []const u8) !void {
            self.stream.writeAll(data, self.write_timeout) catch
                return TlsError.WriteFailed;
        }
    };
}

// =====================================================================
// ClientHello parsing
// =====================================================================

const ClientHelloInfo = struct {
    client_random: [32]u8,
    has_supported_cipher: bool,
    client_offered_alpn: bool = false,
    selected_alpn_protocol: ?[]const u8 = null,
};

fn parseClientHello(data: []const u8, supported_alpn_protocols: []const []const u8) !ClientHelloInfo {
    if (data.len < 4 + 2 + 32) return TlsError.DecodeError;

    // Skip handshake header (type + length = 4 bytes)
    var off: usize = 4;

    // Protocol version (2 bytes)
    if (off + 2 > data.len) return TlsError.DecodeError;
    const version = mem.readInt(u16, data[off..][0..2], .big);
    if (version != TLS_12) return TlsError.UnsupportedProtocolVersion;
    off += 2;

    // Client random (32 bytes)
    if (off + 32 > data.len) return TlsError.DecodeError;
    var client_random: [32]u8 = undefined;
    @memcpy(&client_random, data[off .. off + 32]);
    off += 32;

    // Session ID
    if (off >= data.len) return TlsError.DecodeError;
    const session_id_len = data[off];
    if (off + 1 + session_id_len > data.len) return TlsError.DecodeError;
    off += 1 + session_id_len;

    // Cipher suites
    if (off + 2 > data.len) return TlsError.DecodeError;
    const cs_len = mem.readInt(u16, data[off..][0..2], .big);
    off += 2;
    if ((cs_len & 1) != 0) return TlsError.DecodeError;
    if (off + cs_len > data.len) return TlsError.DecodeError;

    var has_our_cipher = false;
    var cs_off: usize = 0;
    while (cs_off + 2 <= cs_len) : (cs_off += 2) {
        const suite = mem.readInt(u16, data[off + cs_off ..][0..2], .big);
        if (suite == ECDHE_RSA_WITH_AES_128_GCM_SHA256) {
            has_our_cipher = true;
            break;
        }
    }

    if (!has_our_cipher) return TlsError.UnsupportedCipherSuite;
    off += cs_len;

    // Compression methods
    if (off >= data.len) return TlsError.DecodeError;
    const compression_methods_len = data[off];
    off += 1;
    if (compression_methods_len == 0) return TlsError.DecodeError;
    if (off + compression_methods_len > data.len) return TlsError.DecodeError;

    var has_null_compression = false;
    for (data[off .. off + compression_methods_len]) |cm| {
        if (cm == 0) {
            has_null_compression = true;
            break;
        }
    }
    if (!has_null_compression) return TlsError.DecodeError;
    off += compression_methods_len;

    var client_offered_alpn = false;
    var selected_alpn_protocol: ?[]const u8 = null;

    // Extensions (optional, but if present must be well-formed)
    if (off < data.len) {
        if (off + 2 > data.len) return TlsError.DecodeError;
        const ext_len = mem.readInt(u16, data[off..][0..2], .big);
        off += 2;
        if (off + ext_len > data.len) return TlsError.DecodeError;

        const ext_end = off + ext_len;
        while (off < ext_end) {
            if (off + 4 > ext_end) return TlsError.DecodeError;
            const ext_type = mem.readInt(u16, data[off..][0..2], .big);
            const ext_data_len = mem.readInt(u16, data[off + 2 ..][0..2], .big);
            off += 4;
            if (off + ext_data_len > ext_end) return TlsError.DecodeError;

            if (ext_type == 0x0010) {
                client_offered_alpn = true;
                selected_alpn_protocol = try selectAlpnProtocol(data[off .. off + ext_data_len], supported_alpn_protocols);
            }

            off += ext_data_len;
        }

        if (off != ext_end) return TlsError.DecodeError;
    }

    if (client_offered_alpn and supported_alpn_protocols.len > 0 and selected_alpn_protocol == null) {
        return TlsError.NoApplicationProtocol;
    }

    return .{
        .client_random = client_random,
        .has_supported_cipher = has_our_cipher,
        .client_offered_alpn = client_offered_alpn,
        .selected_alpn_protocol = selected_alpn_protocol,
    };
}

fn selectAlpnProtocol(extension_data: []const u8, supported_alpn_protocols: []const []const u8) !?[]const u8 {
    if (extension_data.len < 2) return TlsError.DecodeError;

    const list_len = mem.readInt(u16, extension_data[0..2], .big);
    if (2 + list_len != extension_data.len) return TlsError.DecodeError;

    var off: usize = 2;
    while (off < extension_data.len) {
        const proto_len = extension_data[off];
        off += 1;
        if (proto_len == 0) return TlsError.DecodeError;
        if (off + proto_len > extension_data.len) return TlsError.DecodeError;

        const offered = extension_data[off .. off + proto_len];
        for (supported_alpn_protocols) |supported| {
            if (mem.eql(u8, offered, supported)) {
                return supported;
            }
        }

        off += proto_len;
    }

    if (off != extension_data.len) return TlsError.DecodeError;
    return null;
}

fn alertDescriptionForError(err: anyerror) AlertDescription {
    return switch (err) {
        TlsError.UnsupportedProtocolVersion => .protocol_version,
        TlsError.UnsupportedCipherSuite,
        TlsError.HandshakeFailed,
        => .handshake_failure,
        TlsError.NoApplicationProtocol => .no_application_protocol,
        TlsError.DecodeError => .decode_error,
        TlsError.UnexpectedMessage => .unexpected_message,
        TlsError.BadRecordMac => .bad_record_mac,
        else => .internal_error,
    };
}

fn parseClientKeyExchange(data: []const u8) ![]const u8 {
    if (data.len < 4) return TlsError.DecodeError;
    // Skip handshake header
    var off: usize = 4;
    if (off >= data.len) return TlsError.DecodeError;
    const pubkey_len = data[off];
    off += 1;
    if (off + pubkey_len > data.len) return TlsError.DecodeError;
    return data[off .. off + pubkey_len];
}

// =====================================================================
// TLS PRF (RFC 5246 §5)
// =====================================================================

/// P_SHA256(secret, seed) for TLS 1.2 PRF
fn pSha256(secret: []const u8, seed: []const u8, out: []u8) void {
    // A(0) = seed
    // A(i) = HMAC_SHA256(secret, A(i-1))
    // P(secret, seed) = HMAC(secret, A(1) ++ seed) ++ HMAC(secret, A(2) ++ seed) ++ ...
    var a: [32]u8 = undefined;
    HmacSha256.create(&a, seed, secret);

    var off: usize = 0;
    while (off < out.len) {
        // HMAC(secret, A(i) ++ seed)
        var hmac_state = HmacSha256.init(secret);
        hmac_state.update(&a);
        hmac_state.update(seed);
        var block: [32]u8 = undefined;
        hmac_state.final(&block);

        const n = @min(32, out.len - off);
        @memcpy(out[off .. off + n], block[0..n]);
        off += n;

        // A(i+1) = HMAC(secret, A(i))
        HmacSha256.create(&a, &a, secret);
    }
}

fn prfMasterSecret(premaster: [32]u8, client_random: [32]u8, server_random: [32]u8) [48]u8 {
    const label = "master secret";
    var seed: [label.len + 64]u8 = undefined;
    @memcpy(seed[0..label.len], label);
    @memcpy(seed[label.len .. label.len + 32], &client_random);
    @memcpy(seed[label.len + 32 .. label.len + 64], &server_random);

    var result: [48]u8 = undefined;
    pSha256(&premaster, &seed, &result);
    return result;
}

fn prfKeyExpansion(master_secret: [48]u8, server_random: [32]u8, client_random: [32]u8) [40]u8 {
    // For AES_128_GCM we need:
    // client_write_key(16) + server_write_key(16) + client_write_iv(4) + server_write_iv(4) = 40
    const label = "key expansion";
    var seed: [label.len + 64]u8 = undefined;
    @memcpy(seed[0..label.len], label);
    @memcpy(seed[label.len .. label.len + 32], &server_random);
    @memcpy(seed[label.len + 32 .. label.len + 64], &client_random);

    var result: [40]u8 = undefined;
    pSha256(&master_secret, &seed, &result);
    return result;
}

fn prfVerifyData(master_secret: [48]u8, label: []const u8, hash: [32]u8) [12]u8 {
    var seed: [256]u8 = undefined;
    @memcpy(seed[0..label.len], label);
    @memcpy(seed[label.len .. label.len + 32], &hash);
    const seed_len = label.len + 32;

    var result_full: [12]u8 = undefined;
    pSha256(&master_secret, seed[0..seed_len], &result_full);
    return result_full;
}

// =====================================================================
// RSA PKCS#1 v1.5 Signing (SHA-256)
// =====================================================================

/// Sign data with RSA private key (PKCS#1 v1.5 SHA-256).
/// Returns the signature. Caller owns the returned slice.
fn rsaSign(allocator: Allocator, private_key_der: []const u8, data: []const u8) ![]u8 {

    // SHA-256 hash the data
    var hash: [32]u8 = undefined;
    Sha256.hash(data, &hash, .{});

    // DigestInfo for SHA-256:
    // 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 + hash
    const digest_info_prefix = [_]u8{
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
        0x00, 0x04, 0x20,
    };

    var digest_info: [digest_info_prefix.len + hash.len]u8 = undefined;
    @memcpy(digest_info[0..digest_info_prefix.len], &digest_info_prefix);
    @memcpy(digest_info[digest_info_prefix.len..], &hash);

    const key = try parseRsaPrivateKey(private_key_der);
    const modulus_len = key.modulus.len;
    if (modulus_len < digest_info.len + 11) return TlsError.InvalidPrivateKey;

    if (modulus_len > 512) return TlsError.InvalidPrivateKey;
    var em_buf: [512]u8 = undefined;
    const em = em_buf[0..modulus_len];
    @memset(em, 0);
    em[0] = 0x00;
    em[1] = 0x01;
    const ps_len = modulus_len - digest_info.len - 3;
    @memset(em[2 .. 2 + ps_len], 0xFF);
    em[2 + ps_len] = 0x00;
    @memcpy(em[3 + ps_len ..], &digest_info);

    const n = RsaModulus.fromBytes(key.modulus, .big) catch return TlsError.InvalidPrivateKey;
    const m = RsaFe.fromBytes(n, em, .big) catch return TlsError.InvalidPrivateKey;
    const d = RsaFe.fromBytes(n, key.private_exponent, .big) catch return TlsError.InvalidPrivateKey;
    const s = n.pow(m, d) catch return TlsError.InvalidPrivateKey;

    const sig = try allocator.alloc(u8, modulus_len);
    s.toBytes(sig, .big) catch return TlsError.InvalidPrivateKey;
    return sig;
}

const ParsedRsaPrivateKey = struct {
    modulus: []const u8,
    private_exponent: []const u8,
};

fn parseRsaPrivateKey(private_key_der: []const u8) !ParsedRsaPrivateKey {
    if (private_key_der.len == 0) return TlsError.InvalidPrivateKey;

    return parsePkcs8RsaPrivateKey(private_key_der) catch
        parsePkcs1RsaPrivateKey(private_key_der);
}

fn parsePkcs8RsaPrivateKey(private_key_der: []const u8) !ParsedRsaPrivateKey {
    const top = try der.Element.parse(private_key_der, 0);
    if (top.identifier.tag != .sequence) return TlsError.InvalidPrivateKey;

    var off = top.slice.start;
    const version = try der.Element.parse(private_key_der, off);
    if (version.identifier.tag != .integer) return TlsError.InvalidPrivateKey;
    off = version.slice.end;

    const algorithm = try der.Element.parse(private_key_der, off);
    if (algorithm.identifier.tag != .sequence) return TlsError.InvalidPrivateKey;
    off = algorithm.slice.end;

    const key_octets = try der.Element.parse(private_key_der, off);
    if (key_octets.identifier.tag != .octetstring) return TlsError.InvalidPrivateKey;

    const inner = private_key_der[key_octets.slice.start..key_octets.slice.end];
    return parsePkcs1RsaPrivateKey(inner);
}

fn parsePkcs1RsaPrivateKey(private_key_der: []const u8) !ParsedRsaPrivateKey {
    const top = try der.Element.parse(private_key_der, 0);
    if (top.identifier.tag != .sequence) return TlsError.InvalidPrivateKey;

    var off = top.slice.start;
    const version = try der.Element.parse(private_key_der, off);
    if (version.identifier.tag != .integer) return TlsError.InvalidPrivateKey;
    off = version.slice.end;

    const modulus_elem = try der.Element.parse(private_key_der, off);
    const modulus = try parseDerInteger(private_key_der, modulus_elem);
    off = modulus_elem.slice.end;

    const public_exp_elem = try der.Element.parse(private_key_der, off);
    if (public_exp_elem.identifier.tag != .integer) return TlsError.InvalidPrivateKey;
    off = public_exp_elem.slice.end;

    const private_exp_elem = try der.Element.parse(private_key_der, off);
    const private_exponent = try parseDerInteger(private_key_der, private_exp_elem);

    if (modulus.len == 0 or private_exponent.len == 0) return TlsError.InvalidPrivateKey;
    if (modulus.len > 512) return TlsError.InvalidPrivateKey;

    return .{
        .modulus = modulus,
        .private_exponent = private_exponent,
    };
}

fn parseDerInteger(der_bytes: []const u8, element: der.Element) ![]const u8 {
    if (element.identifier.tag != .integer) return TlsError.InvalidPrivateKey;
    const raw = der_bytes[element.slice.start..element.slice.end];
    if (raw.len == 0) return TlsError.InvalidPrivateKey;

    const start = for (raw, 0..) |b, i| {
        if (b != 0) break i;
    } else raw.len;

    if (start == raw.len) return &[_]u8{0};
    return raw[start..];
}

// =====================================================================
// Tests
// =====================================================================

test "ContentType enum values" {
    try std.testing.expectEqual(@as(u8, 20), @intFromEnum(ContentType.change_cipher_spec));
    try std.testing.expectEqual(@as(u8, 21), @intFromEnum(ContentType.alert));
    try std.testing.expectEqual(@as(u8, 22), @intFromEnum(ContentType.handshake));
    try std.testing.expectEqual(@as(u8, 23), @intFromEnum(ContentType.application_data));
}

test "HandshakeType enum values" {
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(HandshakeType.client_hello));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(HandshakeType.server_hello));
    try std.testing.expectEqual(@as(u8, 14), @intFromEnum(HandshakeType.server_hello_done));
    try std.testing.expectEqual(@as(u8, 20), @intFromEnum(HandshakeType.finished));
}

test "GcmCipherState nonce generation" {
    var state = GcmCipherState{
        .key = [_]u8{0x42} ** 16,
        .implicit_nonce = [_]u8{ 0x01, 0x02, 0x03, 0x04 },
    };

    const explicit1 = state.nextExplicitNonce();
    try std.testing.expectEqual(@as(u64, 0), mem.readInt(u64, &explicit1, .big));

    const explicit2 = state.nextExplicitNonce();
    try std.testing.expectEqual(@as(u64, 1), mem.readInt(u64, &explicit2, .big));

    const nonce = state.makeNonce(explicit1);
    try std.testing.expectEqual(@as(u8, 0x01), nonce[0]);
    try std.testing.expectEqual(@as(u8, 0x02), nonce[1]);
    try std.testing.expectEqual(@as(u8, 0x03), nonce[2]);
    try std.testing.expectEqual(@as(u8, 0x04), nonce[3]);
    // Explicit nonce part (seq 0 = all zeros)
    try std.testing.expectEqual(@as(u8, 0), nonce[4]);
}

test "PRF master secret derivation" {
    var premaster: [32]u8 = undefined;
    @memset(&premaster, 0xAA);
    var client_random: [32]u8 = undefined;
    @memset(&client_random, 0xBB);
    var server_random: [32]u8 = undefined;
    @memset(&server_random, 0xCC);

    const ms = prfMasterSecret(premaster, client_random, server_random);
    // Master secret should be deterministic
    const ms2 = prfMasterSecret(premaster, client_random, server_random);
    try std.testing.expectEqualSlices(u8, &ms, &ms2);
    // And non-trivial
    try std.testing.expect(!mem.eql(u8, &ms, &[_]u8{0} ** 48));
}

test "PRF key expansion" {
    var ms: [48]u8 = undefined;
    @memset(&ms, 0xDD);
    var server_random: [32]u8 = undefined;
    @memset(&server_random, 0xEE);
    var client_random: [32]u8 = undefined;
    @memset(&client_random, 0xFF);

    const kb = prfKeyExpansion(ms, server_random, client_random);
    try std.testing.expectEqual(@as(usize, 40), kb.len);
    // Should be deterministic
    const kb2 = prfKeyExpansion(ms, server_random, client_random);
    try std.testing.expectEqualSlices(u8, &kb, &kb2);
}

test "PRF verify data" {
    var ms: [48]u8 = undefined;
    @memset(&ms, 0x11);
    var hash: [32]u8 = undefined;
    @memset(&hash, 0x22);

    const vd = prfVerifyData(ms, "client finished", hash);
    try std.testing.expectEqual(@as(usize, 12), vd.len);
    // Should be deterministic
    const vd2 = prfVerifyData(ms, "client finished", hash);
    try std.testing.expectEqualSlices(u8, &vd, &vd2);
    // Different labels should produce different results
    const vd3 = prfVerifyData(ms, "server finished", hash);
    try std.testing.expect(!mem.eql(u8, &vd, &vd3));
}

test "parseClientHello rejects missing cipher" {
    // Minimal ClientHello with only cipher suite 0x0000
    var data: [128]u8 = undefined;
    @memset(&data, 0);
    data[0] = @intFromEnum(HandshakeType.client_hello);
    data[1] = 0;
    data[2] = 0;
    data[3] = 60; // body length
    // version
    data[4] = 0x03;
    data[5] = 0x03;
    // random: 32 bytes of zero (already set)
    // session_id_len = 0
    data[38] = 0;
    // cipher_suites_len = 2
    data[39] = 0;
    data[40] = 2;
    // cipher suite 0x0000 (not ours)
    data[41] = 0;
    data[42] = 0;

    const result = parseClientHello(&data, &.{});
    try std.testing.expectError(TlsError.UnsupportedCipherSuite, result);
}

test "parseClientHello returns no_application_protocol when ALPN has no overlap" {
    var data: [64]u8 = undefined;
    @memset(&data, 0);

    data[0] = @intFromEnum(HandshakeType.client_hello);
    data[1] = 0;
    data[2] = 0;
    data[3] = 52; // body length
    data[4] = 0x03;
    data[5] = 0x03;
    data[38] = 0; // session_id_len
    data[39] = 0;
    data[40] = 2; // cipher_suites_len
    data[41] = 0xC0;
    data[42] = 0x2F; // ECDHE_RSA_WITH_AES_128_GCM_SHA256
    data[43] = 1; // compression methods len
    data[44] = 0; // null compression
    data[45] = 0;
    data[46] = 9; // extensions length
    data[47] = 0x00;
    data[48] = 0x10; // ALPN extension
    data[49] = 0x00;
    data[50] = 0x05; // ext data len
    data[51] = 0x00;
    data[52] = 0x03; // protocol list len
    data[53] = 0x02;
    data[54] = 'h';
    data[55] = '2';

    const result = parseClientHello(data[0..56], &.{"http/1.1"});
    try std.testing.expectError(TlsError.NoApplicationProtocol, result);
}

test "sendServerHello includes ALPN extension when negotiated" {
    const allocator = std.testing.allocator;

    const FakeStream = struct {
        allocator: Allocator,
        writes: std.ArrayListUnmanaged(u8) = .empty,

        fn read(_: *@This(), _: []u8, _: zio.Timeout) !usize {
            return 0;
        }

        fn writeAll(self: *@This(), data: []const u8, _: zio.Timeout) !void {
            try self.writes.appendSlice(self.allocator, data);
        }
    };

    var tls = TlsServer(FakeStream).init(.{ .allocator = allocator }, allocator);
    defer tls.stream.writes.deinit(allocator);

    var server_random: [32]u8 = undefined;
    @memset(&server_random, 0xAB);
    try tls.sendServerHello(server_random, "h2");

    const record = tls.stream.writes.items;
    try std.testing.expect(record.len > RECORD_HEADER_LEN);
    try std.testing.expectEqual(ContentType.handshake, @as(ContentType, @enumFromInt(record[0])));

    const record_len = mem.readInt(u16, record[3..5], .big);
    try std.testing.expectEqual(record.len, RECORD_HEADER_LEN + record_len);

    const payload = record[RECORD_HEADER_LEN..];
    const alpn_ext = [_]u8{ 0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '2' };
    try std.testing.expect(mem.indexOf(u8, payload, &alpn_ext) != null);
}

test "selectAlpnProtocol selects first supported match" {
    const ext_data = [_]u8{
        0x00, 0x0C, // ProtocolNameList length
        0x02, 'h', '2',
        0x08, 'h', 't', 't', 'p', '/', '1', '.', '1',
    };

    const selected = try selectAlpnProtocol(&ext_data, &.{ "http/1.1", "h2" });
    try std.testing.expect(selected != null);
    try std.testing.expectEqualStrings("h2", selected.?);
}

test "selectAlpnProtocol returns null when no overlap" {
    const ext_data = [_]u8{
        0x00, 0x03, // ProtocolNameList length
        0x02, 'h', '2',
    };

    const selected = try selectAlpnProtocol(&ext_data, &.{"http/1.1"});
    try std.testing.expect(selected == null);
}

test "alertDescriptionForError maps common handshake failures" {
    try std.testing.expectEqual(AlertDescription.protocol_version, alertDescriptionForError(TlsError.UnsupportedProtocolVersion));
    try std.testing.expectEqual(AlertDescription.handshake_failure, alertDescriptionForError(TlsError.UnsupportedCipherSuite));
    try std.testing.expectEqual(AlertDescription.no_application_protocol, alertDescriptionForError(TlsError.NoApplicationProtocol));
    try std.testing.expectEqual(AlertDescription.decode_error, alertDescriptionForError(TlsError.DecodeError));
    try std.testing.expectEqual(AlertDescription.unexpected_message, alertDescriptionForError(TlsError.UnexpectedMessage));
}

test "handshake integration emits ServerHello with negotiated ALPN" {
    const allocator = std.testing.allocator;

    const client_hello_record = try buildClientHelloRecordAlloc(allocator, &.{ "h2", "http/1.1" });
    defer allocator.free(client_hello_record);

    const pkcs8_b64 = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALXVPe4YaeHv3i2fhtShslykIBbyz9ukhSTG0Z9OJjFzmE6Cr4b5xKMzrVKvqA/6zl5s5Zt/E2zs3AnGlkuh8Aqwgsjopjei66RRildxFfKo+45Fo9pvA4HNmXbzUrS+TzRdUCjNjkxY3s9n3/v4vXCOMMvMMc4rTb5IPwUSnoNzAgMBAAECgYAu8/iA8ebtg74Qc+AiKfrftzXeFycbZXlIDNr2UvzDykCrDU38AaUIK4D3GArCzZXahi4oIAFJIESVdaU7tH5CJE8azF6wXj5AfHlxqHq+krWOYuxv7d+Cd61Pbn8yg9DJ2TlJgD765hDP3wabFaM/kfXnv87W993n9KnIxiRVwQJBAPAt1GYX2eu3xq0tWrD+1cvv/FRURO1Fj/CEdj7KvuMnd8ApQTVABeFJPWdm01dwwh1ljxNFvgUQ74ooMTxtbJMCQQDBz4PlFpd87DYvv2N/FP5++z8Jm6lhIssqP/42TI4c0YQZEra9nh18iQfchgPpjszEi/qipVDeWrOvrT9FrbmhAkAAtvIx15JTbDmQHFlvu2Jhd/ZVPebymcli2tILP8kvnddyX+0MvoMF95TSMPEiCnjZY4r4cLWvCCzeSV5UIrM3AkAIsD7fdEXSSdycA154gf5uvuCyk5HiUub8u+WvlXsBe7sKTLZ4hbAYtyPtFOzz+Xzgis3voK2hajuH8qJVg1ZBAkEAs3XDARhj0tVrWkKDi1vQn9VgQGHIvftO5v94Ibxbd1ceGsyDKNMkJXhHadaSKy2lxSQI24MINEaEJIuPClOWqg==";
    const private_key_der = try decodeBase64Alloc(allocator, pkcs8_b64);
    defer allocator.free(private_key_der);

    var stream = ScriptedStream.init(allocator, client_hello_record);
    defer stream.deinit();

    var tls = TlsServer(ScriptedStream).init(stream, allocator);

    const result = tls.handshake(.{
        .cert_chain = &.{},
        .private_key_der = private_key_der,
        .supported_alpn_protocols = &.{ "http/1.1", "h2" },
        .allocator = allocator,
    });
    try std.testing.expectError(TlsError.ConnectionClosed, result);

    try std.testing.expect(tls.negotiatedAlpnProtocol() != null);
    try std.testing.expectEqualStrings("h2", tls.negotiatedAlpnProtocol().?);

    const first_record_payload = try firstWrittenRecordPayload(tls.stream.writes.items, .handshake);
    const alpn_ext = [_]u8{ 0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '2' };
    try std.testing.expect(mem.indexOf(u8, first_record_payload, &alpn_ext) != null);
}

test "handshake integration emits no_application_protocol fatal alert" {
    const allocator = std.testing.allocator;

    const client_hello_record = try buildClientHelloRecordAlloc(allocator, &.{"h2"});
    defer allocator.free(client_hello_record);

    const pkcs8_b64 = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALXVPe4YaeHv3i2fhtShslykIBbyz9ukhSTG0Z9OJjFzmE6Cr4b5xKMzrVKvqA/6zl5s5Zt/E2zs3AnGlkuh8Aqwgsjopjei66RRildxFfKo+45Fo9pvA4HNmXbzUrS+TzRdUCjNjkxY3s9n3/v4vXCOMMvMMc4rTb5IPwUSnoNzAgMBAAECgYAu8/iA8ebtg74Qc+AiKfrftzXeFycbZXlIDNr2UvzDykCrDU38AaUIK4D3GArCzZXahi4oIAFJIESVdaU7tH5CJE8azF6wXj5AfHlxqHq+krWOYuxv7d+Cd61Pbn8yg9DJ2TlJgD765hDP3wabFaM/kfXnv87W993n9KnIxiRVwQJBAPAt1GYX2eu3xq0tWrD+1cvv/FRURO1Fj/CEdj7KvuMnd8ApQTVABeFJPWdm01dwwh1ljxNFvgUQ74ooMTxtbJMCQQDBz4PlFpd87DYvv2N/FP5++z8Jm6lhIssqP/42TI4c0YQZEra9nh18iQfchgPpjszEi/qipVDeWrOvrT9FrbmhAkAAtvIx15JTbDmQHFlvu2Jhd/ZVPebymcli2tILP8kvnddyX+0MvoMF95TSMPEiCnjZY4r4cLWvCCzeSV5UIrM3AkAIsD7fdEXSSdycA154gf5uvuCyk5HiUub8u+WvlXsBe7sKTLZ4hbAYtyPtFOzz+Xzgis3voK2hajuH8qJVg1ZBAkEAs3XDARhj0tVrWkKDi1vQn9VgQGHIvftO5v94Ibxbd1ceGsyDKNMkJXhHadaSKy2lxSQI24MINEaEJIuPClOWqg==";
    const private_key_der = try decodeBase64Alloc(allocator, pkcs8_b64);
    defer allocator.free(private_key_der);

    var stream = ScriptedStream.init(allocator, client_hello_record);
    defer stream.deinit();

    var tls = TlsServer(ScriptedStream).init(stream, allocator);

    const result = tls.handshake(.{
        .cert_chain = &.{},
        .private_key_der = private_key_der,
        .supported_alpn_protocols = &.{"http/1.1"},
        .allocator = allocator,
    });
    try std.testing.expectError(TlsError.NoApplicationProtocol, result);

    const payload = try firstWrittenRecordPayload(tls.stream.writes.items, .alert);
    try std.testing.expectEqual(@as(usize, 2), payload.len);
    try std.testing.expectEqual(@as(u8, @intFromEnum(AlertLevel.fatal)), payload[0]);
    try std.testing.expectEqual(@as(u8, @intFromEnum(AlertDescription.no_application_protocol)), payload[1]);
}

const ScriptedStream = struct {
    allocator: Allocator,
    input: []const u8,
    read_off: usize = 0,
    writes: std.ArrayListUnmanaged(u8) = .empty,

    fn init(allocator: Allocator, input: []const u8) ScriptedStream {
        return .{ .allocator = allocator, .input = input };
    }

    fn deinit(self: *ScriptedStream) void {
        self.writes.deinit(self.allocator);
    }

    fn read(self: *ScriptedStream, dest: []u8, _: zio.Timeout) !usize {
        if (self.read_off >= self.input.len) return 0;
        const n = @min(dest.len, self.input.len - self.read_off);
        @memcpy(dest[0..n], self.input[self.read_off .. self.read_off + n]);
        self.read_off += n;
        return n;
    }

    fn writeAll(self: *ScriptedStream, data: []const u8, _: zio.Timeout) !void {
        try self.writes.appendSlice(self.allocator, data);
    }
};

fn buildClientHelloRecordAlloc(allocator: Allocator, alpn_protocols: []const []const u8) ![]u8 {
    var alpn_list = std.ArrayListUnmanaged(u8){};
    defer alpn_list.deinit(allocator);
    for (alpn_protocols) |proto| {
        if (proto.len == 0 or proto.len > 255) return TlsError.DecodeError;
        try alpn_list.append(allocator, @intCast(proto.len));
        try alpn_list.appendSlice(allocator, proto);
    }

    var extensions = std.ArrayListUnmanaged(u8){};
    defer extensions.deinit(allocator);
    if (alpn_list.items.len > 0) {
        // ALPN extension type
        try extensions.append(allocator, 0x00);
        try extensions.append(allocator, 0x10);
        const ext_data_len = 2 + alpn_list.items.len;
        try extensions.append(allocator, @intCast((ext_data_len >> 8) & 0xFF));
        try extensions.append(allocator, @intCast(ext_data_len & 0xFF));
        try extensions.append(allocator, @intCast((alpn_list.items.len >> 8) & 0xFF));
        try extensions.append(allocator, @intCast(alpn_list.items.len & 0xFF));
        try extensions.appendSlice(allocator, alpn_list.items);
    }

    var body = std.ArrayListUnmanaged(u8){};
    defer body.deinit(allocator);
    // version TLS 1.2
    try body.appendSlice(allocator, &.{ 0x03, 0x03 });
    // random
    try body.appendNTimes(allocator, 0x11, 32);
    // session id len
    try body.append(allocator, 0x00);
    // cipher suites len + one suite (0xC02F)
    try body.appendSlice(allocator, &.{ 0x00, 0x02, 0xC0, 0x2F });
    // compression methods len + null
    try body.appendSlice(allocator, &.{ 0x01, 0x00 });
    // extensions
    try body.append(allocator, @intCast((extensions.items.len >> 8) & 0xFF));
    try body.append(allocator, @intCast(extensions.items.len & 0xFF));
    try body.appendSlice(allocator, extensions.items);

    var handshake = std.ArrayListUnmanaged(u8){};
    defer handshake.deinit(allocator);
    try handshake.append(allocator, @intFromEnum(HandshakeType.client_hello));
    try handshake.append(allocator, @intCast((body.items.len >> 16) & 0xFF));
    try handshake.append(allocator, @intCast((body.items.len >> 8) & 0xFF));
    try handshake.append(allocator, @intCast(body.items.len & 0xFF));
    try handshake.appendSlice(allocator, body.items);

    var record = std.ArrayListUnmanaged(u8){};
    defer record.deinit(allocator);
    try record.append(allocator, @intFromEnum(ContentType.handshake));
    try record.appendSlice(allocator, &.{ 0x03, 0x03 });
    try record.append(allocator, @intCast((handshake.items.len >> 8) & 0xFF));
    try record.append(allocator, @intCast(handshake.items.len & 0xFF));
    try record.appendSlice(allocator, handshake.items);

    return record.toOwnedSlice(allocator);
}

fn firstWrittenRecordPayload(writes: []const u8, expected_type: ContentType) ![]const u8 {
    if (writes.len < RECORD_HEADER_LEN) return error.TestUnexpectedResult;
    const ct: ContentType = @enumFromInt(writes[0]);
    if (ct != expected_type) return error.TestUnexpectedResult;
    const record_len = mem.readInt(u16, writes[3..5], .big);
    if (writes.len < RECORD_HEADER_LEN + record_len) return error.TestUnexpectedResult;
    return writes[RECORD_HEADER_LEN .. RECORD_HEADER_LEN + record_len];
}

test "AES-128-GCM encrypt/decrypt roundtrip" {
    const key = [_]u8{0x42} ** 16;
    const nonce = [_]u8{0x01} ** 12;
    const plaintext = "Hello, TLS 1.2!";
    const aad = [_]u8{0xAA} ** 13;

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    Aes128Gcm.encrypt(&ciphertext, &tag, plaintext, &aad, nonce, key);

    var decrypted: [plaintext.len]u8 = undefined;
    try Aes128Gcm.decrypt(&decrypted, &ciphertext, tag, &aad, nonce, key);
    try std.testing.expectEqualStrings(plaintext, &decrypted);
}

test "P-256 ECDH key exchange" {
    // Server generates ephemeral secret
    const server_secret = P256.scalar.random(.big);
    const server_pub = (try P256.basePoint.mul(server_secret, .big)).toUncompressedSec1();

    // Client generates ephemeral secret
    const client_secret = P256.scalar.random(.big);
    const client_pub = (try P256.basePoint.mul(client_secret, .big)).toUncompressedSec1();

    // Both sides compute shared secret
    const client_point = try P256.fromSec1(&server_pub);
    const server_shared = try client_point.mul(client_secret, .big);

    const server_point = try P256.fromSec1(&client_pub);
    const client_shared = try server_point.mul(server_secret, .big);

    // Shared secrets should match
    const ss1 = server_shared.affineCoordinates().x.toBytes(.big);
    const ss2 = client_shared.affineCoordinates().x.toBytes(.big);
    try std.testing.expectEqualSlices(u8, &ss1, &ss2);
}

test "rsaSign supports PKCS#1 and PKCS#8 DER keys" {
    const allocator = std.testing.allocator;
    const message = "server key exchange test payload";

    const pkcs1_b64 = "MIICXAIBAAKBgQC11T3uGGnh794tn4bUobJcpCAW8s/bpIUkxtGfTiYxc5hOgq+G+cSjM61Sr6gP+s5ebOWbfxNs7NwJxpZLofAKsILI6KY3ouukUYpXcRXyqPuORaPabwOBzZl281K0vk80XVAozY5MWN7PZ9/7+L1wjjDLzDHOK02+SD8FEp6DcwIDAQABAoGALvP4gPHm7YO+EHPgIin637c13hcnG2V5SAza9lL8w8pAqw1N/AGlCCuA9xgKws2V2oYuKCABSSBElXWlO7R+QiRPGsxesF4+QHx5cah6vpK1jmLsb+3fgnetT25/MoPQydk5SYA++uYQz98GmxWjP5H157/O1vfd5/SpyMYkVcECQQDwLdRmF9nrt8atLVqw/tXL7/xUVETtRY/whHY+yr7jJ3fAKUE1QAXhST1nZtNXcMIdZY8TRb4FEO+KKDE8bWyTAkEAwc+D5RaXfOw2L79jfxT+fvs/CZupYSLLKj/+NkyOHNGEGRK2vZ4dfIkH3IYD6Y7MxIv6oqVQ3lqzr60/Ra25oQJAALbyMdeSU2w5kBxZb7tiYXf2VT3m8pnJYtrSCz/JL53Xcl/tDL6DBfeU0jDxIgp42WOK+HC1rwgs3kleVCKzNwJACLA+33RF0kncnANeeIH+br7gspOR4lLm/Lvlr5V7AXu7Cky2eIWwGLcj7RTs8/l84IrN76CtoWo7h/KiVYNWQQJBALN1wwEYY9LVa1pCg4tb0J/VYEBhyL37Tub/eCG8W3dXHhrMgyjTJCV4R2nWkistpcUkCNuDCDRGhCSLjwpTlqo=";
    const pkcs8_b64 = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALXVPe4YaeHv3i2fhtShslykIBbyz9ukhSTG0Z9OJjFzmE6Cr4b5xKMzrVKvqA/6zl5s5Zt/E2zs3AnGlkuh8Aqwgsjopjei66RRildxFfKo+45Fo9pvA4HNmXbzUrS+TzRdUCjNjkxY3s9n3/v4vXCOMMvMMc4rTb5IPwUSnoNzAgMBAAECgYAu8/iA8ebtg74Qc+AiKfrftzXeFycbZXlIDNr2UvzDykCrDU38AaUIK4D3GArCzZXahi4oIAFJIESVdaU7tH5CJE8azF6wXj5AfHlxqHq+krWOYuxv7d+Cd61Pbn8yg9DJ2TlJgD765hDP3wabFaM/kfXnv87W993n9KnIxiRVwQJBAPAt1GYX2eu3xq0tWrD+1cvv/FRURO1Fj/CEdj7KvuMnd8ApQTVABeFJPWdm01dwwh1ljxNFvgUQ74ooMTxtbJMCQQDBz4PlFpd87DYvv2N/FP5++z8Jm6lhIssqP/42TI4c0YQZEra9nh18iQfchgPpjszEi/qipVDeWrOvrT9FrbmhAkAAtvIx15JTbDmQHFlvu2Jhd/ZVPebymcli2tILP8kvnddyX+0MvoMF95TSMPEiCnjZY4r4cLWvCCzeSV5UIrM3AkAIsD7fdEXSSdycA154gf5uvuCyk5HiUub8u+WvlXsBe7sKTLZ4hbAYtyPtFOzz+Xzgis3voK2hajuH8qJVg1ZBAkEAs3XDARhj0tVrWkKDi1vQn9VgQGHIvftO5v94Ibxbd1ceGsyDKNMkJXhHadaSKy2lxSQI24MINEaEJIuPClOWqg==";

    const der_pkcs1 = try decodeBase64Alloc(allocator, pkcs1_b64);
    defer allocator.free(der_pkcs1);
    const der_pkcs8 = try decodeBase64Alloc(allocator, pkcs8_b64);
    defer allocator.free(der_pkcs8);

    const sig1 = try rsaSign(allocator, der_pkcs1, message);
    defer allocator.free(sig1);
    const sig2 = try rsaSign(allocator, der_pkcs8, message);
    defer allocator.free(sig2);

    try std.testing.expectEqual(sig1.len, sig2.len);
    try std.testing.expectEqual(@as(usize, 128), sig1.len);
    try std.testing.expectEqualSlices(u8, sig1, sig2);

    const parsed = try parseRsaPrivateKey(der_pkcs1);
    const public_key = std.crypto.Certificate.rsa.PublicKey.fromBytes(&[_]u8{ 0x01, 0x00, 0x01 }, parsed.modulus) catch return error.TestUnexpectedResult;

    var sig_arr: [128]u8 = undefined;
    @memcpy(&sig_arr, sig1);
    try std.crypto.Certificate.rsa.PKCS1v1_5Signature.verify(128, sig_arr, message, public_key, Sha256);
}

fn decodeBase64Alloc(allocator: Allocator, b64: []const u8) ![]u8 {
    const out_len = try std.base64.standard.Decoder.calcSizeForSlice(b64);
    const out = try allocator.alloc(u8, out_len);
    errdefer allocator.free(out);
    _ = try std.base64.standard.Decoder.decode(out, b64);
    return out;
}
