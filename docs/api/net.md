# Network API

Low-level networking abstractions.

## Socket

Cross-platform TCP socket wrapper.

```zig
pub const Socket = struct {
    handle: posix.socket_t,
    connected: bool,
};
```

### Methods

- `connect(addr: net.Address) !void`: Connects to a remote address.
- `send(data: []const u8) !usize`: Sends data.
- `sendAll(data: []const u8) !void`: reliably sends all data.
- `recv(buffer: []u8) !usize`: Receives data.
- `close()`: Closes the connection.

### Configuration

- `setNoDelay(enable: bool)`: TCP_NODELAY.
- `setRecvTimeout(ms: u64)`: Receive timeout.
- `setSendTimeout(ms: u64)`: Send timeout.
- `setKeepAlive(enable: bool)`: TCP Keep-Alive.

## TcpListener

Helper for accepting incoming connections.

```zig
var listener = try TcpListener.init(addr);
defer listener.deinit();

const conn = try listener.accept();
```

### Methods

- `accept() !struct { socket: Socket, addr: net.Address }`
- `getLocalAddress() !net.Address`
