//! The public blocking API: [`Socket`] (listener/dialer sharing one UDP
//! port) and [`Conn`] (a reliable, ordered byte stream). This layer is the
//! Rust counterpart of go-libutp's `socket.go` / `conn.go`: one big mutex
//! guards the engine, a reader thread feeds it datagrams and drives timeouts,
//! and per-connection condition variables wake blocked readers and writers.

use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::conn_shared::ConnShared;
use crate::engine::{Context, Key, ProcessUdp};
use crate::transport::{Transport, UdpTransport};

/// Pending incoming connections we hold before `accept` collects them,
/// mirroring go-libutp's backlog channel capacity.
const BACKLOG: usize = 5;
/// Buffered non-uTP datagrams (go-libutp: nonUtpReads channel).
const NON_UTP_BACKLOG: usize = 100;

fn err_socket_closed() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "utp socket closed")
}

fn err_conn_closed() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "utp connection closed")
}

fn err_conn_destroyed() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "utp connection destroyed")
}

struct Inner {
    ctx: Context,
    backlog: VecDeque<(Key, Arc<ConnShared>)>,
    non_utp: VecDeque<(Vec<u8>, SocketAddr)>,
    closed: bool,
    firewall: Option<Box<dyn FnMut(SocketAddr) -> bool + Send>>,
}

struct Shared {
    inner: Mutex<Inner>,
    accept_cond: Condvar,
    non_utp_cond: Condvar,
    transport: Arc<dyn Transport>,
    local_addr: SocketAddr,
}

/// A uTP socket bound to one UDP port. Accepts incoming connections
/// ([`Socket::accept`]) and dials outgoing ones ([`Socket::connect`]) over
/// the same port; datagrams that aren't uTP are surfaced through
/// [`Socket::recv_from`], so the port can be shared with other protocols
/// (e.g. BitTorrent DHT).
///
/// Dropping the socket closes it and destroys all its connections.
pub struct Socket {
    shared: Arc<Shared>,
}

impl Inner {
    fn process_datagram(&mut self, shared: &Shared, buf: &[u8], addr: SocketAddr) {
        let mut fw = self.firewall.take();
        let res = {
            let mut fw_fn = |a: SocketAddr| fw.as_mut().is_some_and(|f| f(a));
            self.ctx.process_udp(buf, addr, &mut fw_fn)
        };
        self.firewall = fw;
        match res {
            ProcessUdp::NotUtp => {
                if self.non_utp.len() < NON_UTP_BACKLOG {
                    self.non_utp.push_back((buf.to_vec(), addr));
                    shared.non_utp_cond.notify_all();
                }
                // else: dropped, like go-libutp
            }
            ProcessUdp::Handled => {}
            ProcessUdp::Accepted(key, user) => {
                if self.backlog.len() >= BACKLOG {
                    // No room; close it immediately (go-libutp pushBacklog).
                    user.lock().closed = true;
                    self.ctx.close(key);
                } else {
                    self.backlog.push_back((key, user));
                    shared.accept_cond.notify_all();
                }
            }
        }
    }
}

fn reader_loop(shared: Arc<Shared>) {
    let mut buf = vec![0u8; 0x10000];
    let mut consecutive_errors = 0u32;
    loop {
        match shared.transport.recv_from(&mut buf) {
            Ok((n, addr)) => {
                consecutive_errors = 0;
                let mut g = shared.inner.lock().unwrap();
                if g.closed {
                    return;
                }
                g.process_datagram(&shared, &buf[..n], addr);
                // The socket is drained (we're about to block); flush
                // deferred acks and give timeouts a chance to run.
                g.ctx.issue_deferred_acks();
                g.ctx.check_timeouts();
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                let mut g = shared.inner.lock().unwrap();
                if g.closed {
                    return;
                }
                g.ctx.check_timeouts();
            }
            Err(_e) => {
                // Some platforms raise read errors (e.g. ICMP-derived) that
                // don't mean we should stop; tolerate a bounded run of them,
                // as go-libutp does.
                let close;
                {
                    let mut g = shared.inner.lock().unwrap();
                    if g.closed {
                        return;
                    }
                    consecutive_errors += 1;
                    close = consecutive_errors >= 100;
                    if !close {
                        g.ctx.check_timeouts();
                    }
                }
                if close {
                    Shared::close(&shared);
                    return;
                }
            }
        }
    }
}

impl Shared {
    fn close(self: &Arc<Self>) {
        {
            let mut g = self.inner.lock().unwrap();
            if g.closed {
                return;
            }
            g.closed = true;
            g.ctx.destroy_all();
            g.backlog.clear();
            g.non_utp.clear();
        }
        self.accept_cond.notify_all();
        self.non_utp_cond.notify_all();
        // Nudge the reader thread awake so it exits promptly.
        let mut addr = self.local_addr;
        if addr.ip().is_unspecified() {
            addr.set_ip(match addr.ip() {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
            });
        }
        let _ = self.transport.send_to(&[], addr);
    }
}

impl Socket {
    /// Bind a new uTP socket to `addr` (e.g. `"0.0.0.0:0"`).
    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<Socket> {
        Socket::from_udp(UdpSocket::bind(addr)?)
    }

    /// Run uTP over an already-bound [`UdpSocket`].
    pub fn from_udp(udp: UdpSocket) -> io::Result<Socket> {
        Socket::with_transport(Arc::new(UdpTransport::new(udp)?))
    }

    /// Run uTP over a custom [`Transport`].
    pub fn with_transport(transport: Arc<dyn Transport>) -> io::Result<Socket> {
        let local_addr = transport.local_addr()?;
        let shared = Arc::new(Shared {
            inner: Mutex::new(Inner {
                ctx: Context::new(transport.clone()),
                backlog: VecDeque::new(),
                non_utp: VecDeque::new(),
                closed: false,
                firewall: None,
            }),
            accept_cond: Condvar::new(),
            non_utp_cond: Condvar::new(),
            transport,
            local_addr,
        });
        let t_shared = shared.clone();
        std::thread::Builder::new()
            .name("utp-reader".into())
            .spawn(move || reader_loop(t_shared))?;
        Ok(Socket { shared })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.shared.local_addr
    }

    /// Block until an incoming connection arrives.
    pub fn accept(&self) -> io::Result<Conn> {
        let mut g = self.shared.inner.lock().unwrap();
        loop {
            if let Some((key, user)) = g.backlog.pop_front() {
                return Ok(Conn {
                    key,
                    user,
                    shared: self.shared.clone(),
                });
            }
            if g.closed {
                return Err(err_socket_closed());
            }
            g = self.shared.accept_cond.wait(g).unwrap();
        }
    }

    /// Connect to a remote uTP endpoint. Blocks until the handshake
    /// completes or the engine gives up (a few seconds of SYN retries).
    pub fn connect<A: ToSocketAddrs>(&self, addr: A) -> io::Result<Conn> {
        self.connect_deadline(resolve(addr)?, None)
    }

    /// Like [`Socket::connect`] with an overall timeout.
    pub fn connect_timeout<A: ToSocketAddrs>(
        &self,
        addr: A,
        timeout: Duration,
    ) -> io::Result<Conn> {
        self.connect_deadline(resolve(addr)?, Some(Instant::now() + timeout))
    }

    fn connect_deadline(&self, addr: SocketAddr, deadline: Option<Instant>) -> io::Result<Conn> {
        let mut g = self.shared.inner.lock().unwrap();
        if g.closed {
            return Err(err_socket_closed());
        }
        let (key, user) = g.ctx.connect(addr);
        let conn = Conn {
            key,
            user: user.clone(),
            shared: self.shared.clone(),
        };
        loop {
            {
                let c = user.lock();
                if let Some(kind) = c.error {
                    drop(c);
                    conn.close_locked(&mut g);
                    return Err(io::Error::new(kind, "utp connect failed"));
                }
                if c.got_connect {
                    return Ok(conn);
                }
                if c.destroyed {
                    return Err(err_conn_destroyed());
                }
                if c.closed {
                    return Err(err_conn_closed());
                }
            }
            if g.closed {
                return Err(err_socket_closed());
            }
            match deadline {
                Some(d) => {
                    let now = Instant::now();
                    if now >= d {
                        conn.close_locked(&mut g);
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "utp connect timed out",
                        ));
                    }
                    g = user.cond.wait_timeout(g, d - now).unwrap().0;
                }
                None => g = user.cond.wait(g).unwrap(),
            }
        }
    }

    /// Receive a datagram that arrived on the underlying port but was not
    /// recognized as uTP traffic (go-libutp's `ReadFrom`). This lets the UDP
    /// port be shared with another protocol.
    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut g = self.shared.inner.lock().unwrap();
        loop {
            if let Some((b, from)) = g.non_utp.pop_front() {
                let n = b.len().min(buf.len());
                buf[..n].copy_from_slice(&b[..n]);
                return Ok((n, from));
            }
            if g.closed {
                return Err(err_socket_closed());
            }
            g = self.shared.non_utp_cond.wait(g).unwrap();
        }
    }

    /// Send a raw datagram on the underlying port (go-libutp's `WriteTo`).
    pub fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.shared.transport.send_to(buf, addr)
    }

    /// A firewall callback returns true if an incoming connection request
    /// should be ignored. This is better than accepting and closing, as no
    /// acknowledgement packet is sent at all. Called with the socket lock
    /// held.
    pub fn set_firewall_callback(&self, f: impl FnMut(SocketAddr) -> bool + Send + 'static) {
        self.shared.inner.lock().unwrap().firewall = Some(Box::new(f));
    }

    /// Send buffer limit applied to connections created after this call.
    pub fn set_send_buffer_size(&self, bytes: usize) {
        assert!(bytes >= 1);
        self.shared.inner.lock().unwrap().ctx.opt_sndbuf = bytes;
    }

    /// Receive buffer limit (i.e. maximum receive window) applied to
    /// connections created after this call.
    pub fn set_recv_buffer_size(&self, bytes: usize) {
        assert!(bytes >= 1);
        self.shared.inner.lock().unwrap().ctx.opt_rcvbuf = bytes;
    }

    /// LEDBAT target delay in microseconds for connections created after
    /// this call (default 100ms).
    pub fn set_target_delay(&self, micros: usize) {
        self.shared.inner.lock().unwrap().ctx.target_delay = micros;
    }

    /// Close the socket: all connections are destroyed and blocked calls
    /// return errors. Also performed on drop.
    pub fn close(&self) {
        self.shared.close();
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        self.shared.close();
    }
}

impl std::fmt::Debug for Socket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socket")
            .field("local", &self.shared.local_addr)
            .finish_non_exhaustive()
    }
}

fn resolve<A: ToSocketAddrs>(addr: A) -> io::Result<SocketAddr> {
    addr.to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no addresses resolved"))
}

/// A single uTP connection: a reliable, ordered, congestion-controlled byte
/// stream. Obtained from [`Socket::connect`] or [`Socket::accept`].
///
/// Blocking reads and writes are available through both the inherent
/// [`Conn::recv`] / [`Conn::send`] (which take `&self`, so the connection can
/// be shared across threads) and the [`io::Read`] / [`io::Write`]
/// implementations on `Conn` and `&Conn`.
///
/// Dropping the connection closes it (sends a FIN; delivery of already
/// written data continues in the background while the socket lives).
pub struct Conn {
    key: Key,
    user: Arc<ConnShared>,
    shared: Arc<Shared>,
}

impl Conn {
    /// Read bytes from the connection, blocking until some are available,
    /// EOF (returns 0), an error, or the configured read timeout
    /// ([`io::ErrorKind::TimedOut`]).
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let deadline = self.user.lock().read_timeout.map(|t| Instant::now() + t);
        let mut g = self.shared.inner.lock().unwrap();
        loop {
            {
                let mut c = self.user.lock();
                if !c.read_buf.is_empty() {
                    let mut copied;
                    {
                        let (s1, s2) = c.read_buf.as_slices();
                        let n1 = s1.len().min(buf.len());
                        buf[..n1].copy_from_slice(&s1[..n1]);
                        copied = n1;
                        if copied < buf.len() {
                            let n2 = s2.len().min(buf.len() - copied);
                            buf[copied..copied + n2].copy_from_slice(&s2[..n2]);
                            copied += n2;
                        }
                    }
                    c.read_buf.drain(..copied);
                    let drained = c.read_buf.is_empty();
                    let destroyed = c.destroyed;
                    drop(c);
                    if drained && !destroyed {
                        // Reopened receive window; let the engine ack it.
                        g.ctx.read_drained(self.key);
                        g.ctx.issue_deferred_acks();
                    }
                    return Ok(copied);
                }
                // Order matters and mirrors go-libutp's readNoWait.
                if c.got_eof {
                    return Ok(0);
                }
                if let Some(kind) = c.error {
                    return Err(io::Error::new(kind, "utp read failed"));
                }
                if c.destroyed {
                    return Err(err_conn_destroyed());
                }
                if c.closed {
                    return Err(err_conn_closed());
                }
            }
            match deadline {
                Some(d) => {
                    let now = Instant::now();
                    if now >= d {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "utp read timed out",
                        ));
                    }
                    g = self.user.cond.wait_timeout(g, d - now).unwrap().0;
                }
                None => g = self.user.cond.wait(g).unwrap(),
            }
        }
    }

    /// Write bytes to the connection, blocking until at least some were
    /// accepted into the send window, an error, or the configured write
    /// timeout ([`io::ErrorKind::TimedOut`]).
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let deadline = self.user.lock().write_timeout.map(|t| Instant::now() + t);
        let mut g = self.shared.inner.lock().unwrap();
        loop {
            {
                let c = self.user.lock();
                if let Some(kind) = c.error {
                    return Err(io::Error::new(kind, "utp write failed"));
                }
                if c.closed {
                    return Err(err_conn_closed());
                }
                if c.destroyed {
                    return Err(err_conn_destroyed());
                }
            }
            if let Some(n) = g.ctx.write(self.key, buf) {
                if n > 0 {
                    return Ok(n);
                }
            }
            match deadline {
                Some(d) => {
                    let now = Instant::now();
                    if now >= d {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "utp write timed out",
                        ));
                    }
                    g = self.user.cond.wait_timeout(g, d - now).unwrap().0;
                }
                None => g = self.user.cond.wait(g).unwrap(),
            }
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.shared.local_addr
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.user.lock().remote_addr
    }

    /// Timeout applied to future [`Conn::recv`] calls; `None` blocks forever.
    pub fn set_read_timeout(&self, t: Option<Duration>) {
        self.user.lock().read_timeout = t;
    }

    /// Timeout applied to future [`Conn::send`] calls; `None` blocks forever.
    pub fn set_write_timeout(&self, t: Option<Duration>) {
        self.user.lock().write_timeout = t;
    }

    /// Close the connection. A FIN is sent and remaining in-flight data
    /// keeps being delivered in the background while the socket lives; the
    /// call itself does not block. Also performed on drop.
    pub fn close(&self) {
        let mut g = self.shared.inner.lock().unwrap();
        self.close_locked(&mut g);
    }

    fn close_locked(&self, g: &mut MutexGuard<'_, Inner>) {
        let mut c = self.user.lock();
        let need_engine_close = !c.destroyed && !c.closed;
        c.closed = true;
        drop(c);
        if need_engine_close {
            g.ctx.close(self.key);
        }
        self.user.cond.notify_all();
    }
}

impl std::fmt::Debug for Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conn")
            .field("local", &self.shared.local_addr)
            .field("peer", &self.user.lock().remote_addr)
            .finish_non_exhaustive()
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        let done = {
            let c = self.user.lock();
            c.closed || c.destroyed
        };
        if !done {
            self.close();
        }
    }
}

impl io::Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv(buf)
    }
}

impl io::Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.send(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl io::Read for &Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv(buf)
    }
}

impl io::Write for &Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.send(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
