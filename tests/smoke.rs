//! Integration tests exercising the full stack over real UDP sockets on
//! loopback, including a lossy-transport test that proves retransmission and
//! selective acks recover from drops.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use utp::{Socket, Transport, UdpTransport};

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

fn pair(a: &Socket, b: &Socket) -> (utp::Conn, utp::Conn) {
    let b_addr = b.local_addr();
    let accepted = thread::scope(|s| {
        let h = s.spawn(|| b.accept().unwrap());
        let dialed = a.connect(b_addr).unwrap();
        (dialed, h.join().unwrap())
    });
    accepted
}

#[test]
fn connect_accept_exchange() {
    let s0 = Socket::bind("127.0.0.1:0").unwrap();
    let s1 = Socket::bind("127.0.0.1:0").unwrap();
    let (dialed, accepted) = pair(&s0, &s1);

    assert_eq!(dialed.peer_addr(), s1.local_addr());

    // Small message each way.
    dialed.send(b"ping").unwrap();
    let mut buf = [0u8; 16];
    let n = accepted.recv(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"ping");

    accepted.send(b"pong").unwrap();
    let n = dialed.recv(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"pong");
}

#[test]
fn ipv6_loopback() {
    let s0 = match Socket::bind("[::1]:0") {
        Ok(s) => s,
        Err(e) => {
            // Environment without an IPv6 stack.
            eprintln!("skipping: cannot bind IPv6 loopback: {e}");
            return;
        }
    };
    let s1 = Socket::bind("[::1]:0").unwrap();
    let (dialed, accepted) = pair(&s0, &s1);
    dialed.send(b"six").unwrap();
    let mut buf = [0u8; 8];
    let n = accepted.recv(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"six");
}

#[test]
fn large_transfer_both_directions() {
    const N: usize = 1 << 20; // 1 MiB each way
    let s0 = Socket::bind("127.0.0.1:0").unwrap();
    let s1 = Socket::bind("127.0.0.1:0").unwrap();
    let (dialed, accepted) = pair(&s0, &s1);

    let up = pattern(N, 3);
    let down = pattern(N, 7);

    thread::scope(|s| {
        let up_ref = &up;
        let down_ref = &down;
        let d = &dialed;
        let a = &accepted;
        s.spawn(move || {
            let mut w = d;
            w.write_all(up_ref).unwrap();
        });
        s.spawn(move || {
            let mut w = a;
            w.write_all(down_ref).unwrap();
        });
        s.spawn(move || {
            let mut got = vec![0u8; N];
            let mut r = a;
            r.read_exact(&mut got).unwrap();
            assert!(got == *up_ref, "uploaded data corrupted");
        });
        s.spawn(move || {
            let mut got = vec![0u8; N];
            let mut r = d;
            r.read_exact(&mut got).unwrap();
            assert!(got == *down_ref, "downloaded data corrupted");
        });
    });
}

#[test]
fn eof_after_close() {
    let s0 = Socket::bind("127.0.0.1:0").unwrap();
    let s1 = Socket::bind("127.0.0.1:0").unwrap();
    let (dialed, accepted) = pair(&s0, &s1);

    dialed.send(b"bye").unwrap();
    dialed.close();

    let mut got = Vec::new();
    (&accepted).read_to_end(&mut got).unwrap();
    assert_eq!(got, b"bye");

    // Further reads keep returning EOF.
    let mut buf = [0u8; 4];
    assert_eq!(accepted.recv(&mut buf).unwrap(), 0);
}

#[test]
fn self_dial_single_socket() {
    // Both ends of a connection on one socket (go-libutp's connPairSocket).
    let s = Socket::bind("127.0.0.1:0").unwrap();
    let addr = s.local_addr();
    let (dialed, accepted) = thread::scope(|scope| {
        let h = scope.spawn(|| s.accept().unwrap());
        let d = s.connect(addr).unwrap();
        (d, h.join().unwrap())
    });
    dialed.send(b"loop").unwrap();
    let mut buf = [0u8; 8];
    let n = accepted.recv(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"loop");
}

#[test]
fn read_timeout() {
    let s0 = Socket::bind("127.0.0.1:0").unwrap();
    let s1 = Socket::bind("127.0.0.1:0").unwrap();
    let (dialed, _accepted) = pair(&s0, &s1);

    dialed.set_read_timeout(Some(Duration::from_millis(300)));
    let started = Instant::now();
    let mut buf = [0u8; 4];
    let err = dialed.recv(&mut buf).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    assert!(started.elapsed() >= Duration::from_millis(300));
}

#[test]
fn connect_timeout_to_black_hole() {
    // A plain UDP socket that never answers.
    let black_hole = UdpSocket::bind("127.0.0.1:0").unwrap();
    let target = black_hole.local_addr().unwrap();

    let s = Socket::bind("127.0.0.1:0").unwrap();
    let started = Instant::now();
    let err = s
        .connect_timeout(target, Duration::from_millis(500))
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    assert!(started.elapsed() >= Duration::from_millis(500));
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn engine_gives_up_dialing_on_its_own() {
    // Without a caller-imposed deadline, the engine's SYN retransmit limit
    // (2 retries in SYN_SENT: ~3s + ~6s) fails the connect by itself.
    let black_hole = UdpSocket::bind("127.0.0.1:0").unwrap();
    let target = black_hole.local_addr().unwrap();

    let s = Socket::bind("127.0.0.1:0").unwrap();
    let started = Instant::now();
    let err = s.connect(target).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(30));
}

#[test]
fn write_timeout_when_receiver_stalls() {
    let s0 = Socket::bind("127.0.0.1:0").unwrap();
    let s1 = Socket::bind("127.0.0.1:0").unwrap();
    // Small buffers so the send window fills up quickly against a receiver
    // that never reads.
    s0.set_send_buffer_size(64 << 10);
    s1.set_recv_buffer_size(64 << 10);
    let (dialed, _accepted) = pair(&s0, &s1);

    dialed.set_write_timeout(Some(Duration::from_millis(500)));
    let buf = vec![0u8; 16 << 10];
    let mut written = 0usize;
    let err = loop {
        match dialed.send(&buf) {
            Ok(n) => written += n,
            Err(e) => break e,
        }
        assert!(written < 64 << 20, "wrote unboundedly with no reader");
    };
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    assert!(
        written > 0,
        "should have buffered something before stalling"
    );
}

#[test]
fn non_utp_passthrough() {
    let s = Socket::bind("127.0.0.1:0").unwrap();
    let raw = UdpSocket::bind("127.0.0.1:0").unwrap();
    raw.send_to(b"\x00not utp, too short", s.local_addr())
        .unwrap();
    let mut buf = [0u8; 64];
    let (n, from) = s.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"\x00not utp, too short");
    assert_eq!(from, raw.local_addr().unwrap());

    // And sending raw datagrams out through the shared port works too.
    s.send_to(b"reply", raw.local_addr().unwrap()).unwrap();
    let mut rbuf = [0u8; 16];
    raw.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let (n, _) = raw.recv_from(&mut rbuf).unwrap();
    assert_eq!(&rbuf[..n], b"reply");
}

#[test]
fn firewall_blocks_incoming() {
    let s0 = Socket::bind("127.0.0.1:0").unwrap();
    let s1 = Socket::bind("127.0.0.1:0").unwrap();
    s1.set_firewall_callback(|_addr| true);
    let err = s0
        .connect_timeout(s1.local_addr(), Duration::from_millis(700))
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
}

#[test]
fn socket_close_errors_blocked_accept() {
    let s = Arc::new(Socket::bind("127.0.0.1:0").unwrap());
    let s2 = s.clone();
    let h = thread::spawn(move || s2.accept());
    thread::sleep(Duration::from_millis(100));
    s.close();
    assert!(h.join().unwrap().is_err());
}

#[test]
fn connect_after_close_fails() {
    let s = Socket::bind("127.0.0.1:0").unwrap();
    let addr = s.local_addr();
    s.close();
    assert!(s.connect(addr).is_err());
}

/// Drops a deterministic fraction of outgoing datagrams.
struct LossyTransport {
    inner: UdpTransport,
    counter: AtomicU64,
    // drop packets where counter % modulus == offset
    modulus: u64,
    offset: u64,
}

impl Transport for LossyTransport {
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.inner.recv_from(buf)
    }

    fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        let c = self.counter.fetch_add(1, Ordering::Relaxed);
        if c % self.modulus == self.offset {
            // Swallowed by the network.
            return Ok(buf.len());
        }
        self.inner.send_to(buf, addr)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

#[test]
fn survives_packet_loss() {
    const N: usize = 256 << 10; // 256 KiB through a lossy link

    let lossy = |modulus, offset| -> Socket {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        Socket::with_transport(Arc::new(LossyTransport {
            inner: UdpTransport::new(udp).unwrap(),
            counter: AtomicU64::new(0),
            modulus,
            offset,
        }))
        .unwrap()
    };

    // ~7% loss in each direction, desynchronized so the handshake can
    // eventually make it through even if a SYN or SYN-ACK is eaten.
    let s0 = lossy(14, 5);
    let s1 = lossy(14, 9);

    let data = pattern(N, 11);
    let (dialed, accepted) = pair(&s0, &s1);

    thread::scope(|s| {
        let data_ref = &data;
        let d = &dialed;
        s.spawn(move || {
            let mut w = d;
            w.write_all(data_ref).unwrap();
        });
        let mut got = vec![0u8; N];
        let mut r = &accepted;
        r.read_exact(&mut got).unwrap();
        assert!(got == data, "data corrupted crossing a lossy link");
    });
}
