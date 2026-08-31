//! The datagram transport a [`crate::Socket`] runs over. The stock
//! implementation wraps a [`std::net::UdpSocket`]; tests (and exotic setups)
//! can substitute their own, e.g. to inject packet loss.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

/// How often the engine gets a chance to run timeouts when no traffic
/// arrives. Mirrors go-libutp's 500ms utp_check_timeouts cadence.
pub const RECV_POLL_INTERVAL: Duration = Duration::from_millis(500);

pub trait Transport: Send + Sync {
    /// Receive one datagram. Must return within roughly
    /// [`RECV_POLL_INTERVAL`] even when idle, using an error of kind
    /// [`io::ErrorKind::WouldBlock`] or [`io::ErrorKind::TimedOut`] to
    /// indicate that nothing arrived.
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;

    fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize>;

    fn local_addr(&self) -> io::Result<SocketAddr>;
}

pub struct UdpTransport(UdpSocket);

impl UdpTransport {
    pub fn new(socket: UdpSocket) -> io::Result<Self> {
        socket.set_read_timeout(Some(RECV_POLL_INTERVAL))?;
        // Ask for large kernel buffers: the congestion window regularly
        // exceeds the default UDP buffer size (often ~208KiB on Linux), and
        // overflow there shows up as heavy loss and RTO stalls. Best effort;
        // the kernel caps the value at its configured maximum.
        set_udp_buffer_sizes(&socket, 4 << 20);
        Ok(UdpTransport(socket))
    }
}

/// Best-effort SO_RCVBUF/SO_SNDBUF enlargement without pulling in libc.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_udp_buffer_sizes(socket: &UdpSocket, bytes: i32) {
    use std::os::fd::AsRawFd;
    const SOL_SOCKET: i32 = 1;
    const SO_RCVBUF: i32 = 8;
    const SO_SNDBUF: i32 = 7;
    extern "C" {
        fn setsockopt(fd: i32, level: i32, optname: i32, optval: *const u8, optlen: u32) -> i32;
    }
    let fd = socket.as_raw_fd();
    let val = bytes.to_ne_bytes();
    unsafe {
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, val.as_ptr(), 4);
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, val.as_ptr(), 4);
    }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
fn set_udp_buffer_sizes(socket: &UdpSocket, bytes: i32) {
    use std::os::fd::AsRawFd;
    // BSD-derived platforms (macOS, the BSDs).
    const SOL_SOCKET: i32 = 0xffff;
    const SO_RCVBUF: i32 = 0x1002;
    const SO_SNDBUF: i32 = 0x1001;
    extern "C" {
        fn setsockopt(fd: i32, level: i32, optname: i32, optval: *const u8, optlen: u32) -> i32;
    }
    let fd = socket.as_raw_fd();
    let val = bytes.to_ne_bytes();
    unsafe {
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, val.as_ptr(), 4);
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, val.as_ptr(), 4);
    }
}

#[cfg(windows)]
fn set_udp_buffer_sizes(socket: &UdpSocket, bytes: i32) {
    use std::os::windows::io::AsRawSocket;
    const SOL_SOCKET: i32 = 0xffff;
    const SO_RCVBUF: i32 = 0x1002;
    const SO_SNDBUF: i32 = 0x1001;
    #[link(name = "ws2_32")]
    extern "system" {
        fn setsockopt(s: usize, level: i32, optname: i32, optval: *const u8, optlen: i32) -> i32;
    }
    let s = socket.as_raw_socket() as usize;
    let val = bytes.to_ne_bytes();
    unsafe {
        setsockopt(s, SOL_SOCKET, SO_RCVBUF, val.as_ptr(), 4);
        setsockopt(s, SOL_SOCKET, SO_SNDBUF, val.as_ptr(), 4);
    }
}

#[cfg(not(any(unix, windows)))]
fn set_udp_buffer_sizes(_socket: &UdpSocket, _bytes: i32) {}

impl Transport for UdpTransport {
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.0.recv_from(buf)
    }

    fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.0.send_to(buf, addr)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }
}
