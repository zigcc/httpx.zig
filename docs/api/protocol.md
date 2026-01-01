# Protocol API

Low-level protocol framing and parsing.

## HTTP Framing

### `Http2Connection`

Manages HTTP/2 frames and streams.

```zig
pub const Http2Connection = struct {
    // ...
};
```

### `Http2FrameHeader`

Parses and serializes HTTP/2 frame headers.

```zig
pub const Http2FrameHeader = struct {
    length: u24,
    frame_type: Http2FrameType,
    flags: u8,
    stream_id: u31,
    
    pub fn parse(bytes: [9]u8) Http2FrameHeader
    pub fn serialize(self: Http2FrameHeader) [9]u8
};
```

### `Http3FrameType`

Enum of HTTP/3 frame types.

### `VarInt`

Helpers for QUIC variable-length integer encoding.

- `encodeVarInt(val: u62, buf: []u8) !usize`
- `decodeVarInt(buf: []const u8) !struct{ value: u62, len: usize }`

## Parser

### `Parser`

A state-machine based HTTP/1.1 parser.

```zig
var parser = Parser.init(allocator);
defer parser.deinit();

const bytes_read = try parser.feed(data);
if (parser.isComplete()) {
   // ...
}
```

- `feed(data: []const u8) !usize`: Ingests data.
- `reset()`: Resets state for next request.
