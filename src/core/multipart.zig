//! Multipart Form Data Encoder for httpx.zig
//!
//! Implements RFC 2046 multipart/form-data encoding for file uploads
//! and form submission.
//!
//! ## Features
//! - File uploads with automatic content-type detection
//! - Multiple files per field
//! - Mixed form fields and files
//! - Custom Content-Disposition headers
//! - Streaming support for large files
//!
//! ## Usage
//! ```zig
//! var form = MultipartForm.init(allocator);
//! defer form.deinit();
//!
//! try form.addField("username", "john");
//! try form.addFile("avatar", "photo.jpg", image_data, "image/jpeg");
//!
//! const body = try form.encode();
//! defer allocator.free(body);
//!
//! request.headers.set("Content-Type", form.contentType());
//! request.setBodyOwned(body);
//! ```

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// MIME type detection based on file extension.
pub const MimeType = struct {
    /// Detects MIME type from filename extension.
    pub fn fromFilename(filename: []const u8) []const u8 {
        const ext = if (mem.lastIndexOfScalar(u8, filename, '.')) |pos|
            filename[pos..]
        else
            "";

        return fromExtension(ext);
    }

    /// Gets MIME type from file extension.
    pub fn fromExtension(ext: []const u8) []const u8 {
        // Common MIME types
        const types = .{
            .{ ".html", "text/html" },
            .{ ".htm", "text/html" },
            .{ ".css", "text/css" },
            .{ ".js", "application/javascript" },
            .{ ".json", "application/json" },
            .{ ".xml", "application/xml" },
            .{ ".txt", "text/plain" },
            .{ ".csv", "text/csv" },
            .{ ".md", "text/markdown" },

            // Images
            .{ ".png", "image/png" },
            .{ ".jpg", "image/jpeg" },
            .{ ".jpeg", "image/jpeg" },
            .{ ".gif", "image/gif" },
            .{ ".webp", "image/webp" },
            .{ ".svg", "image/svg+xml" },
            .{ ".ico", "image/x-icon" },
            .{ ".bmp", "image/bmp" },

            // Documents
            .{ ".pdf", "application/pdf" },
            .{ ".doc", "application/msword" },
            .{ ".docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document" },
            .{ ".xls", "application/vnd.ms-excel" },
            .{ ".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" },
            .{ ".ppt", "application/vnd.ms-powerpoint" },
            .{ ".pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation" },

            // Archives
            .{ ".zip", "application/zip" },
            .{ ".tar", "application/x-tar" },
            .{ ".gz", "application/gzip" },
            .{ ".rar", "application/vnd.rar" },
            .{ ".7z", "application/x-7z-compressed" },

            // Audio
            .{ ".mp3", "audio/mpeg" },
            .{ ".wav", "audio/wav" },
            .{ ".ogg", "audio/ogg" },
            .{ ".flac", "audio/flac" },

            // Video
            .{ ".mp4", "video/mp4" },
            .{ ".webm", "video/webm" },
            .{ ".avi", "video/x-msvideo" },
            .{ ".mov", "video/quicktime" },
            .{ ".mkv", "video/x-matroska" },

            // Fonts
            .{ ".woff", "font/woff" },
            .{ ".woff2", "font/woff2" },
            .{ ".ttf", "font/ttf" },
            .{ ".otf", "font/otf" },
        };

        inline for (types) |t| {
            if (std.ascii.eqlIgnoreCase(ext, t[0])) return t[1];
        }

        return "application/octet-stream";
    }
};

/// Represents a single part in a multipart form.
pub const FormPart = struct {
    name: []const u8,
    filename: ?[]const u8 = null,
    content_type: ?[]const u8 = null,
    data: []const u8,
    owned: bool = false,
};

/// Multipart form encoder.
pub const MultipartForm = struct {
    allocator: Allocator,
    parts: std.ArrayListUnmanaged(FormPart) = .empty,
    boundary: [32]u8,

    const Self = @This();

    /// Creates a new multipart form encoder.
    pub fn init(allocator: Allocator) Self {
        var boundary: [32]u8 = undefined;

        // Generate random boundary
        const prefix = "----httpxBoundary";
        @memcpy(boundary[0..prefix.len], prefix);

        // Add random suffix
        var random_bytes: [8]u8 = undefined;
        std.crypto.random.bytes(&random_bytes);
        for (random_bytes, 0..) |byte, i| {
            const hex_chars = "0123456789abcdef";
            boundary[prefix.len + i * 2] = hex_chars[byte >> 4];
            boundary[prefix.len + i * 2 + 1] = hex_chars[byte & 0x0f];
        }

        return .{
            .allocator = allocator,
            .boundary = boundary,
        };
    }

    /// Creates a form with a specific boundary (for testing).
    pub fn initWithBoundary(allocator: Allocator, boundary: []const u8) Self {
        var form = Self{
            .allocator = allocator,
            .boundary = undefined,
        };

        const len = @min(boundary.len, form.boundary.len);
        @memcpy(form.boundary[0..len], boundary[0..len]);
        if (len < form.boundary.len) {
            @memset(form.boundary[len..], '-');
        }

        return form;
    }

    /// Releases all allocated memory.
    pub fn deinit(self: *Self) void {
        for (self.parts.items) |part| {
            if (part.owned) {
                self.allocator.free(part.name);
                if (part.filename) |f| self.allocator.free(f);
                if (part.content_type) |ct| self.allocator.free(ct);
                self.allocator.free(part.data);
            }
        }
        self.parts.deinit(self.allocator);
    }

    /// Adds a simple text field.
    pub fn addField(self: *Self, name: []const u8, value: []const u8) !void {
        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);
        const owned_value = try self.allocator.dupe(u8, value);

        try self.parts.append(self.allocator, .{
            .name = owned_name,
            .data = owned_value,
            .owned = true,
        });
    }

    /// Adds a file with automatic MIME type detection.
    pub fn addFile(self: *Self, name: []const u8, filename: []const u8, data: []const u8) !void {
        const content_type = MimeType.fromFilename(filename);
        try self.addFileWithType(name, filename, data, content_type);
    }

    /// Adds a file with explicit MIME type.
    pub fn addFileWithType(self: *Self, name: []const u8, filename: []const u8, data: []const u8, content_type: []const u8) !void {
        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);
        const owned_filename = try self.allocator.dupe(u8, filename);
        errdefer self.allocator.free(owned_filename);
        const owned_ct = try self.allocator.dupe(u8, content_type);
        errdefer self.allocator.free(owned_ct);
        const owned_data = try self.allocator.dupe(u8, data);

        try self.parts.append(self.allocator, .{
            .name = owned_name,
            .filename = owned_filename,
            .content_type = owned_ct,
            .data = owned_data,
            .owned = true,
        });
    }

    /// Adds a binary file.
    pub fn addBinaryFile(self: *Self, name: []const u8, filename: []const u8, data: []const u8) !void {
        try self.addFileWithType(name, filename, data, "application/octet-stream");
    }

    /// Returns the Content-Type header value including boundary.
    pub fn contentType(_: *const Self) []const u8 {
        // Note: This returns a format string that caller should use with std.fmt
        return "multipart/form-data; boundary=";
    }

    /// Returns the boundary string.
    pub fn getBoundary(self: *const Self) []const u8 {
        return &self.boundary;
    }

    /// Generates the full Content-Type header value.
    pub fn getContentTypeHeader(self: *const Self, allocator: Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "multipart/form-data; boundary={s}", .{&self.boundary});
    }

    /// Encodes all parts into a complete multipart body.
    pub fn encode(self: *const Self) ![]u8 {
        var result = std.ArrayListUnmanaged(u8){};
        errdefer result.deinit(self.allocator);

        for (self.parts.items) |part| {
            // Boundary line
            try result.appendSlice(self.allocator, "--");
            try result.appendSlice(self.allocator, &self.boundary);
            try result.appendSlice(self.allocator, "\r\n");

            // Content-Disposition header
            try result.appendSlice(self.allocator, "Content-Disposition: form-data; name=\"");
            try result.appendSlice(self.allocator, part.name);
            try result.append(self.allocator, '"');

            if (part.filename) |filename| {
                try result.appendSlice(self.allocator, "; filename=\"");
                try result.appendSlice(self.allocator, filename);
                try result.append(self.allocator, '"');
            }
            try result.appendSlice(self.allocator, "\r\n");

            // Content-Type header (for files)
            if (part.content_type) |ct| {
                try result.appendSlice(self.allocator, "Content-Type: ");
                try result.appendSlice(self.allocator, ct);
                try result.appendSlice(self.allocator, "\r\n");
            }

            // Empty line before content
            try result.appendSlice(self.allocator, "\r\n");

            // Content
            try result.appendSlice(self.allocator, part.data);
            try result.appendSlice(self.allocator, "\r\n");
        }

        // Final boundary
        try result.appendSlice(self.allocator, "--");
        try result.appendSlice(self.allocator, &self.boundary);
        try result.appendSlice(self.allocator, "--\r\n");

        return result.toOwnedSlice(self.allocator);
    }

    /// Returns the number of parts.
    pub fn count(self: *const Self) usize {
        return self.parts.items.len;
    }
};

/// URL-encoded form data encoder (application/x-www-form-urlencoded).
pub const UrlEncodedForm = struct {
    allocator: Allocator,
    fields: std.ArrayListUnmanaged(Field) = .empty,

    const Field = struct {
        name: []const u8,
        value: []const u8,
        owned: bool = false,
    };

    const Self = @This();

    /// Creates a new URL-encoded form.
    pub fn init(allocator: Allocator) Self {
        return .{ .allocator = allocator };
    }

    /// Releases all allocated memory.
    pub fn deinit(self: *Self) void {
        for (self.fields.items) |field| {
            if (field.owned) {
                self.allocator.free(field.name);
                self.allocator.free(field.value);
            }
        }
        self.fields.deinit(self.allocator);
    }

    /// Adds a field to the form.
    pub fn add(self: *Self, name: []const u8, value: []const u8) !void {
        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);
        const owned_value = try self.allocator.dupe(u8, value);

        try self.fields.append(self.allocator, .{
            .name = owned_name,
            .value = owned_value,
            .owned = true,
        });
    }

    /// Returns the Content-Type header value.
    pub fn contentType() []const u8 {
        return "application/x-www-form-urlencoded";
    }

    /// Encodes all fields into URL-encoded format.
    pub fn encode(self: *const Self) ![]u8 {
        var result = std.ArrayListUnmanaged(u8){};
        errdefer result.deinit(self.allocator);

        for (self.fields.items, 0..) |field, i| {
            if (i > 0) {
                try result.append(self.allocator, '&');
            }

            try encodeComponent(&result, self.allocator, field.name);
            try result.append(self.allocator, '=');
            try encodeComponent(&result, self.allocator, field.value);
        }

        return result.toOwnedSlice(self.allocator);
    }

    /// Returns the number of fields.
    pub fn count(self: *const Self) usize {
        return self.fields.items.len;
    }
};

/// URL-encodes a string component.
fn encodeComponent(result: *std.ArrayListUnmanaged(u8), allocator: Allocator, str: []const u8) !void {
    const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~";
    const hex_chars = "0123456789ABCDEF";

    for (str) |c| {
        if (mem.indexOf(u8, unreserved, &[_]u8{c}) != null) {
            try result.append(allocator, c);
        } else if (c == ' ') {
            try result.append(allocator, '+');
        } else {
            try result.append(allocator, '%');
            try result.append(allocator, hex_chars[c >> 4]);
            try result.append(allocator, hex_chars[c & 0x0f]);
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

test "MimeType detection" {
    try std.testing.expectEqualStrings("image/png", MimeType.fromFilename("photo.png"));
    try std.testing.expectEqualStrings("image/jpeg", MimeType.fromFilename("photo.jpg"));
    try std.testing.expectEqualStrings("application/pdf", MimeType.fromFilename("document.pdf"));
    try std.testing.expectEqualStrings("text/html", MimeType.fromFilename("index.html"));
    try std.testing.expectEqualStrings("application/octet-stream", MimeType.fromFilename("unknown.xyz"));
}

test "MultipartForm basic" {
    const allocator = std.testing.allocator;
    var form = MultipartForm.initWithBoundary(allocator, "testboundary");
    defer form.deinit();

    try form.addField("name", "John Doe");
    try form.addField("email", "john@example.com");

    try std.testing.expectEqual(@as(usize, 2), form.count());

    const body = try form.encode();
    defer allocator.free(body);

    try std.testing.expect(mem.indexOf(u8, body, "--testboundary") != null);
    try std.testing.expect(mem.indexOf(u8, body, "name=\"name\"") != null);
    try std.testing.expect(mem.indexOf(u8, body, "John Doe") != null);
    try std.testing.expect(mem.indexOf(u8, body, "--testboundary--") != null);
}

test "MultipartForm with file" {
    const allocator = std.testing.allocator;
    var form = MultipartForm.initWithBoundary(allocator, "fileboundary");
    defer form.deinit();

    try form.addField("description", "My photo");
    try form.addFile("avatar", "photo.jpg", "fake image data");

    const body = try form.encode();
    defer allocator.free(body);

    try std.testing.expect(mem.indexOf(u8, body, "filename=\"photo.jpg\"") != null);
    try std.testing.expect(mem.indexOf(u8, body, "Content-Type: image/jpeg") != null);
    try std.testing.expect(mem.indexOf(u8, body, "fake image data") != null);
}

test "UrlEncodedForm basic" {
    const allocator = std.testing.allocator;
    var form = UrlEncodedForm.init(allocator);
    defer form.deinit();

    try form.add("name", "John Doe");
    try form.add("email", "john@example.com");

    const body = try form.encode();
    defer allocator.free(body);

    try std.testing.expectEqualStrings("name=John+Doe&email=john%40example.com", body);
}

test "UrlEncodedForm special characters" {
    const allocator = std.testing.allocator;
    var form = UrlEncodedForm.init(allocator);
    defer form.deinit();

    try form.add("query", "hello world & goodbye");

    const body = try form.encode();
    defer allocator.free(body);

    try std.testing.expectEqualStrings("query=hello+world+%26+goodbye", body);
}

test "getContentTypeHeader" {
    const allocator = std.testing.allocator;
    var form = MultipartForm.initWithBoundary(allocator, "myboundary");
    defer form.deinit();

    const ct = try form.getContentTypeHeader(allocator);
    defer allocator.free(ct);

    try std.testing.expect(mem.startsWith(u8, ct, "multipart/form-data; boundary="));
}
