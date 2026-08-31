//! A pure-Rust implementation of uTP (the Micro Transport Protocol), ported
//! from [libutp] (BitTorrent's reference implementation) by way of
//! [go-libutp].
//!
//! µTP is a reliable, ordered, stream-oriented transport that runs over UDP
//! and uses the LEDBAT delay-based congestion controller, so bulk transfers
//! back off in the presence of competing interactive traffic instead of
//! saturating the link.
//!
//! # Example
//!
//! ```no_run
//! use std::io::{Read, Write};
//!
//! # fn main() -> std::io::Result<()> {
//! let server = utp::Socket::bind("127.0.0.1:0")?;
//! let server_addr = server.local_addr();
//! let handle = std::thread::spawn(move || {
//!     let conn = server.accept().unwrap();
//!     let mut buf = Vec::new();
//!     (&conn).read_to_end(&mut buf).unwrap();
//!     buf
//! });
//!
//! let client = utp::Socket::bind("127.0.0.1:0")?;
//! let mut conn = client.connect(server_addr)?;
//! conn.write_all(b"hello over utp")?;
//! conn.close();
//! assert_eq!(handle.join().unwrap(), b"hello over utp");
//! # Ok(())
//! # }
//! ```
//!
//! # Architecture
//!
//! - [`engine`](crate::engine) (private): a faithful port of libutp's
//!   `utp_internal.cpp` — packet handling, LEDBAT congestion control,
//!   selective acks, retransmission, and MTU discovery — running under a
//!   single per-socket mutex.
//! - [`Socket`]/[`Conn`]: a blocking, thread-safe API in the shape of
//!   go-libutp's `Socket`/`Conn` (themselves shaped like `std::net`
//!   listeners and streams). A background thread reads datagrams and drives
//!   engine timeouts.
//! - [`Transport`]: the datagram layer, defaulting to `std::net::UdpSocket`;
//!   substitutable for testing (e.g. injecting packet loss).
//!
//! ICMP-assisted MTU discovery and connection teardown (libutp's
//! `utp_process_icmp_*`) are not implemented; like go-libutp, this crate
//! never wired up ICMP handling.
//!
//! [libutp]: https://github.com/bittorrent/libutp
//! [go-libutp]: https://github.com/anacrolix/go-libutp

mod circular;
mod clock;
mod conn_shared;
mod delay_hist;
mod engine;
mod packet;
mod socket;
mod transport;
mod util;

pub use socket::{Conn, Socket};
pub use transport::{Transport, UdpTransport, RECV_POLL_INTERVAL};
