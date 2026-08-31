# rust-utp

A pure-Rust implementation of µTP (the [Micro Transport Protocol]), ported from
[libutp] — BitTorrent's reference implementation — by way of
[go-libutp]'s vendored copy and API.

µTP is a reliable, ordered, stream-oriented transport that runs over UDP and
uses the LEDBAT delay-based congestion controller, so bulk transfers back off
in the presence of competing interactive traffic instead of saturating the
link. It's the transport behind most BitTorrent traffic.

No runtime dependencies; no unsafe code beyond a best-effort `setsockopt` to
enlarge kernel UDP buffers.

[Micro Transport Protocol]: https://www.bittorrent.org/beps/bep_0029.html
[libutp]: https://github.com/bittorrent/libutp
[go-libutp]: https://github.com/anacrolix/go-libutp

## Usage

The library name is `utp`. `Socket` binds a UDP port and both listens and
dials; `Conn` is a blocking byte stream implementing `io::Read`/`io::Write`
(on `&Conn` too, so one connection can be shared across threads).

```rust
use std::io::{Read, Write};

let server = utp::Socket::bind("0.0.0.0:0")?;
let server_addr = server.local_addr();
std::thread::spawn(move || {
    let conn = server.accept().unwrap();
    let mut buf = Vec::new();
    (&conn).read_to_end(&mut buf).unwrap();
});

let client = utp::Socket::bind("0.0.0.0:0")?;
let mut conn = client.connect(server_addr)?;
conn.write_all(b"hello over utp")?;
conn.close(); // sends FIN; also happens on drop
```

Also available:

- `Socket::recv_from` / `Socket::send_to`: raw datagrams that aren't uTP pass
  through, so the UDP port can be shared with another protocol (e.g. the
  BitTorrent DHT), as with go-libutp's `net.PacketConn` behavior.
- `Socket::set_firewall_callback`: silently ignore chosen incoming
  connections without sending any reply.
- `Conn::set_read_timeout` / `Conn::set_write_timeout`,
  `Socket::connect_timeout`.
- `Socket::with_transport`: run the protocol over a custom datagram
  `Transport` (used by the test suite to inject packet loss).

## Fidelity to libutp

The engine (`src/engine.rs`) is a function-for-function port of libutp's
`utp_internal.cpp`: the wire format, the LEDBAT controller and slow start,
delay histories with clock-drift compensation, selective acks (EACK), fast
resend and fast timeout, RTO backoff, MTU probing/binary search, keepalives,
RST handling and the RST-info cache, window decay, and zero-window probing
all follow the C code — including its wrapping 16-bit sequence arithmetic.
Comments from the original are kept where they explain protocol decisions.

Deliberate differences:

- Callbacks are replaced by direct calls into per-connection state; the
  public API is a port of go-libutp's `Socket`/`Conn` layer instead.
- `utp_process_icmp_error` / `utp_process_icmp_fragmentation` are not
  implemented (go-libutp never wired ICMP up either).
- One out-of-bounds mask read in `selective_ack_bytes` in the C original is
  replaced by treating the out-of-range bit as unset.
- Sockets are keyed in a `HashMap` rather than libutp's custom hash table,
  and packet buffers are `Vec`s rather than malloc'd blobs.

## Concurrency model

Like go-libutp, one mutex guards the whole engine per `Socket`. A background
reader thread feeds received datagrams to the engine, issues deferred acks,
and runs `check_timeouts` (every 500ms). Blocked `accept`/`connect`/
`recv`/`send` callers wait on condvars signalled by the engine. Closing the
`Socket` (or dropping it) destroys all its connections.

## Testing

`cargo test` runs unit tests plus integration tests over real UDP loopback
sockets: bidirectional 1 MiB transfers, EOF/FIN sequencing, dial and
read/write timeouts (both caller deadlines and the engine's own SYN
retransmit give-up), firewalling, non-uTP passthrough, and a transfer across
a transport that drops ~7% of packets in each direction, which exercises
retransmission, selective acks and RTO recovery.

`cargo run --release --example throughput` measures single-connection
loopback throughput.

## License

MIT, same as libutp and go-libutp. See [LICENSE](LICENSE).
