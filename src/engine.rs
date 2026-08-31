//! The uTP protocol engine: a port of libutp's `utp_internal.cpp` (as
//! vendored in go-libutp). Structure and semantics deliberately mirror the C
//! original — including its wrapping 16-bit sequence arithmetic and LEDBAT
//! congestion controller — so behavior stays interoperable and comparable.
//!
//! The C library drove the application through callbacks; here the
//! per-connection user state ([`ConnShared`]) is invoked directly. All engine
//! code runs under the owning socket's big mutex.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::circular::CircularBuffer;
use crate::clock::Clock;
use crate::conn_shared::ConnShared;
use crate::delay_hist::DelayHist;
use crate::packet::{
    self, Header, HEADER_SIZE, ST_DATA, ST_FIN, ST_NUM_STATES, ST_RESET, ST_STATE, ST_SYN,
};
use crate::transport::Transport;
use crate::util::{wrapping_compare_less, Rng};

const TIMEOUT_CHECK_INTERVAL: u64 = 500; // ms

// number of bytes to increase max window size by, per RTT. This is
// scaled down linearly proportional to off_target. i.e. if all packets
// in one window have 0 delay, window size will increase by this number.
const MAX_CWND_INCREASE_BYTES_PER_RTT: usize = 3000;
const MAX_WINDOW_DECAY: i64 = 100; // ms

const REORDER_BUFFER_MAX_SIZE: usize = 1024;
const OUTGOING_BUFFER_MAX_SIZE: usize = 1024;

pub const PACKET_SIZE: usize = 1435;

// this is the minimum max_window value. It can never drop below this
const MIN_WINDOW_SIZE: usize = 10;

// if we receive 4 or more duplicate acks, we resend the packet
// that hasn't been acked yet
const DUPLICATE_ACKS_BEFORE_RESEND: u32 = 3;

// Allow a reception window of at least 3 ack_nrs behind seq_nr.
// A non-SYN packet with an ack_nr difference greater than this is
// considered suspicious and ignored
const ACK_NR_ALLOWED_WINDOW: u16 = 3;

// The furthest a single delay sample may sit from the average delay baseline.
const MAX_AVERAGE_DELAY_SAMPLE: u32 = (i32::MAX / 4) as u32;

// The smallest MTU we will search down to. Less would not pass TCP
const MTU_FLOOR_MIN: u32 = 576;

const RST_INFO_TIMEOUT: i32 = 10000;
const RST_INFO_LIMIT: usize = 1000;
// 29 seconds determined from measuring many home NAT devices
const KEEPALIVE_INTERVAL: i32 = 29000;

const TIMESTAMP_MASK: u32 = 0xffff_ffff;
const ACK_NR_MASK: u32 = 0xffff;

const MAX_EACK: usize = 128;

// Defaults from struct_utp_context's constructor / utp_utils.cpp.
pub const CCONTROL_TARGET: usize = 100 * 1000; // us
const DEFAULT_BUF: usize = 1024 * 1024;
const UDP_IPV4_MTU: u32 = 1500 - 20 - 8 - 24 - 8 - 2 - 36;
const UDP_TEREDO_MTU: u32 = 1280 - 40 - 8;
const UDP_IPV4_OVERHEAD: usize = 20 + 8;
const UDP_TEREDO_OVERHEAD: usize = UDP_IPV4_OVERHEAD + 40 + 8;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Key {
    pub addr: SocketAddr,
    pub recv_id: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConnState {
    Idle,
    SynSent,
    SynRecv,
    Connected,
    ConnectedFull,
    Reset,
    Destroy,
}

pub struct OutgoingPacket {
    payload: usize,
    time_sent: u64, // microseconds
    transmissions: u32,
    need_resend: bool,
    /// header + payload; total wire length is data.len()
    data: Vec<u8>,
}

struct RstInfo {
    addr: SocketAddr,
    connid: u32,
    ack_nr: u16,
    timestamp: u64,
}

#[derive(PartialEq)]
enum AckResult {
    Acked,
    AlreadyAcked,
    NotSent,
}

pub enum ProcessUdp {
    /// Not recognized as uTP; hand to the non-uTP path.
    NotUtp,
    Handled,
    /// A new incoming connection was accepted; push it to the backlog.
    Accepted(Key, Arc<ConnShared>),
}

fn wrap16(v: u16) -> usize {
    v as usize
}

/// `(int)(a - b) >= 0` on u64 millisecond clocks, as the C code does it.
fn ms_elapsed(a: u64, b: u64) -> bool {
    (a.wrapping_sub(b) as u32 as i32) >= 0
}

pub struct Context {
    pub sockets: HashMap<Key, UtpSock>,
    ack_list: Vec<Key>,
    rst_info: Vec<RstInfo>,
    pub target_delay: usize,
    pub opt_sndbuf: usize,
    pub opt_rcvbuf: usize,
    pub current_ms: u64,
    last_check: u64,
    pub clock: Clock,
    pub rng: Rng,
    pub transport: Arc<dyn Transport>,
}

impl Context {
    pub fn new(transport: Arc<dyn Transport>) -> Self {
        Context {
            sockets: HashMap::new(),
            ack_list: Vec::new(),
            rst_info: Vec::new(),
            target_delay: CCONTROL_TARGET,
            opt_sndbuf: DEFAULT_BUF,
            opt_rcvbuf: DEFAULT_BUF,
            current_ms: 0,
            last_check: 0,
            clock: Clock::new(),
            rng: Rng::new(),
            transport,
        }
    }

    fn send_to_addr(&mut self, buf: &[u8], addr: SocketAddr) -> io::Result<()> {
        self.transport.send_to(buf, addr).map(|_| ())
    }

    // removeSocketFromAckList
    fn ack_list_remove(&mut self, sock: &mut UtpSock) {
        if sock.in_ack_list {
            sock.in_ack_list = false;
            let key = sock.key;
            self.ack_list.retain(|k| *k != key);
        }
    }

    /// Detach a socket, run `f` on it, then either reinsert it or (if `f`
    /// left it in `Destroy` and `destroy_now`) tear it down. The C code only
    /// destroys sockets inside utp_check_timeouts, so callers pass
    /// `destroy_now = false` to preserve that deferral.
    fn with_sock<R>(
        &mut self,
        key: Key,
        f: impl FnOnce(&mut Context, &mut UtpSock) -> R,
    ) -> Option<R> {
        let mut sock = self.sockets.remove(&key)?;
        let r = f(self, &mut sock);
        self.sockets.insert(key, sock);
        Some(r)
    }

    fn destroy_sock(&mut self, mut sock: UtpSock) {
        sock.user.on_destroying();
        self.ack_list_remove(&mut sock);
        // dropped: buffers freed
    }

    // UTPSocket::send_rst
    fn send_rst(&mut self, addr: SocketAddr, conn_id_send: u32, ack_nr: u16, seq_nr: u16) {
        let mut b = [0u8; HEADER_SIZE];
        packet::set_version_type(&mut b, 1, ST_RESET);
        packet::set_conn_id(&mut b, conn_id_send as u16);
        packet::set_ack_nr(&mut b, ack_nr);
        packet::set_seq_nr(&mut b, seq_nr);
        packet::set_window_size(&mut b, 0);
        let _ = self.send_to_addr(&b, addr);
    }

    // utp_initialize_socket
    fn initialize_socket(
        &mut self,
        sock: &mut UtpSock,
        addr: SocketAddr,
        need_seed_gen: bool,
        conn_seed: u32,
        conn_id_recv: u32,
        conn_id_send: u32,
    ) {
        let mut seed = conn_seed;
        let mut recv = conn_id_recv;
        let mut send = conn_id_send;
        if need_seed_gen {
            loop {
                seed = self.rng.next_u32() & 0xffff;
                if !self.sockets.contains_key(&Key {
                    addr,
                    recv_id: seed,
                }) {
                    break;
                }
            }
            recv = conn_id_recv.wrapping_add(seed);
            send = conn_id_send.wrapping_add(seed);
        }
        sock.state = ConnState::Idle;
        sock.conn_seed = seed;
        sock.conn_id_recv = recv;
        sock.conn_id_send = send;
        sock.key = Key {
            addr,
            recv_id: recv,
        };
        self.current_ms = self.clock.millis();
        sock.last_got_packet = self.current_ms;
        sock.last_sent_packet = self.current_ms;
        sock.last_measured_delay = self.current_ms + 0x7000_0000;
        sock.average_sample_time = self.current_ms + 5000;
        sock.last_rwin_decay = self.current_ms as i64 - MAX_WINDOW_DECAY;
        sock.our_hist.clear(self.current_ms);
        sock.their_hist.clear(self.current_ms);
        sock.rtt_hist.clear(self.current_ms);
        // initialize MTU floor and ceiling
        sock.mtu_reset(self.clock.millis());
        sock.mtu_last = sock.mtu_ceiling;
        // we need to fit one packet in the window when we start the connection
        sock.max_window = sock.get_packet_size();
    }

    /// utp_create_socket + utp_connect fused, as go-libutp does (a created
    /// but unconnected libutp socket cannot be deallocated cleanly).
    pub fn connect(&mut self, addr: SocketAddr) -> (Key, Arc<ConnShared>) {
        let user = Arc::new(ConnShared::new(addr));
        let mut sock = UtpSock::new(self, addr, user.clone());
        self.initialize_socket(&mut sock, addr, true, 0, 0, 1);
        sock.state = ConnState::SynSent;
        self.current_ms = self.clock.millis();

        // Setup initial timeout timer.
        sock.retransmit_timeout = 3000;
        sock.rto_timeout = self.current_ms + sock.retransmit_timeout as u64;
        sock.last_rcv_win = sock.get_rcv_window();
        sock.seq_nr = self.rng.next_u32() as u16;

        // Create the connect packet. SYN packets are special and have the
        // receive ID in the connid field, instead of conn_id_send.
        let mut data = vec![0u8; HEADER_SIZE];
        packet::set_version_type(&mut data, 1, ST_SYN);
        packet::set_conn_id(&mut data, sock.conn_id_recv as u16);
        packet::set_window_size(&mut data, sock.last_rcv_win as u32);
        packet::set_seq_nr(&mut data, sock.seq_nr);
        let pkt = OutgoingPacket {
            payload: 0,
            time_sent: 0,
            transmissions: 0,
            need_resend: false,
            data,
        };
        sock.outbuf
            .ensure_size(wrap16(sock.seq_nr), sock.cur_window_packets as usize);
        sock.outbuf.put(wrap16(sock.seq_nr), Some(pkt));
        let syn_seq = sock.seq_nr;
        sock.seq_nr = sock.seq_nr.wrapping_add(1);
        sock.cur_window_packets += 1;
        sock.send_packet_at(self, syn_seq);

        let key = sock.key;
        self.sockets.insert(key, sock);
        (key, user)
    }

    // utp_process_udp. Returns whether the datagram was recognized as uTP,
    // and surfaces accepted connections to the caller.
    pub fn process_udp(
        &mut self,
        buf: &[u8],
        addr: SocketAddr,
        firewall: &mut dyn FnMut(SocketAddr) -> bool,
    ) -> ProcessUdp {
        if buf.len() < HEADER_SIZE {
            return ProcessUdp::NotUtp;
        }
        // go-libutp refuses zero ports before libutp sees them.
        if addr.port() == 0 {
            return ProcessUdp::NotUtp;
        }
        let h = Header(buf);
        if h.wire_version() != 1 {
            return ProcessUdp::NotUtp;
        }
        let id = h.conn_id() as u32;
        let flags = h.packet_type();

        if flags == ST_RESET {
            // id is either our recv id or our send id
            // if it's our send id, and we initiated the connection, our recv id is id + 1
            // if it's our send id, and we did not initiate the connection, our recv id is id - 1
            // we have to check every case
            let mut found = None;
            let k0 = Key { addr, recv_id: id };
            if self.sockets.contains_key(&k0) {
                found = Some(k0);
            } else {
                let k1 = Key {
                    addr,
                    recv_id: id.wrapping_add(1),
                };
                let k2 = Key {
                    addr,
                    recv_id: id.wrapping_sub(1),
                };
                if self.sockets.get(&k1).is_some_and(|s| s.conn_id_send == id) {
                    found = Some(k1);
                } else if self.sockets.get(&k2).is_some_and(|s| s.conn_id_send == id) {
                    found = Some(k2);
                }
            }
            if let Some(key) = found {
                self.with_sock(key, |_ctx, sock| {
                    if sock.close_requested {
                        sock.state = ConnState::Destroy;
                    } else {
                        sock.state = ConnState::Reset;
                    }
                    // As in the C original, the state is overwritten before
                    // the SYN_SENT check, so this is always ECONNRESET.
                    sock.user.on_error(io::ErrorKind::ConnectionReset);
                });
            }
            return ProcessUdp::Handled;
        } else if flags != ST_SYN {
            let key = Key { addr, recv_id: id };
            if self.sockets.contains_key(&key) {
                self.with_sock(key, |ctx, sock| {
                    sock.process_incoming(ctx, buf, false);
                });
                return ProcessUdp::Handled;
            }
        }

        // We have not found a matching utp_socket, and this isn't a SYN.
        // Reject it, replying with an RST (at most once per stream).
        let seq_nr = h.seq_nr();
        if flags != ST_SYN {
            self.current_ms = self.clock.millis();
            for r in self.rst_info.iter_mut() {
                if r.connid == id && r.addr == addr && r.ack_nr == seq_nr {
                    r.timestamp = self.current_ms;
                    return ProcessUdp::Handled;
                }
            }
            if self.rst_info.len() > RST_INFO_LIMIT {
                return ProcessUdp::Handled;
            }
            self.rst_info.push(RstInfo {
                addr,
                connid: id,
                ack_nr: seq_nr,
                timestamp: self.current_ms,
            });
            let rand_seq = self.rng.next_u32() as u16;
            self.send_rst(addr, id, seq_nr, rand_seq);
            return ProcessUdp::Handled;
        }

        // Incoming connection (ST_SYN).
        if self.sockets.contains_key(&Key {
            addr,
            recv_id: id.wrapping_add(1),
        }) {
            // connection already exists
            return ProcessUdp::Handled;
        }
        if self.sockets.len() > 3000 {
            return ProcessUdp::Handled;
        }
        // true means yes, block connection. false means no, don't block.
        if firewall(addr) {
            return ProcessUdp::Handled;
        }

        // Create a new socket to handle this new connection
        let user = Arc::new(ConnShared::new(addr));
        let mut sock = UtpSock::new(self, addr, user.clone());
        self.initialize_socket(&mut sock, addr, false, id, id.wrapping_add(1), id);
        sock.ack_nr = seq_nr;
        sock.seq_nr = self.rng.next_u32() as u16;
        sock.fast_resend_seq_nr = sock.seq_nr;
        sock.state = ConnState::SynRecv;
        sock.process_incoming(self, buf, true);
        sock.send_ack(self, true);
        let key = sock.key;
        self.sockets.insert(key, sock);
        ProcessUdp::Accepted(key, user)
    }

    // utp_issue_deferred_acks
    pub fn issue_deferred_acks(&mut self) {
        let keys = std::mem::take(&mut self.ack_list);
        for key in keys {
            if let Some(mut sock) = self.sockets.remove(&key) {
                sock.in_ack_list = false;
                sock.send_ack(self, false);
                self.sockets.insert(key, sock);
            }
        }
    }

    // utp_check_timeouts. Internally rate limited to every 500ms.
    pub fn check_timeouts(&mut self) {
        self.current_ms = self.clock.millis();
        if self.current_ms.wrapping_sub(self.last_check) < TIMEOUT_CHECK_INTERVAL {
            return;
        }
        self.last_check = self.current_ms;

        let mut i = 0;
        while i < self.rst_info.len() {
            if self.current_ms.wrapping_sub(self.rst_info[i].timestamp) as u32 as i32
                >= RST_INFO_TIMEOUT
            {
                self.rst_info.swap_remove(i);
            } else {
                i += 1;
            }
        }

        let keys: Vec<Key> = self.sockets.keys().copied().collect();
        for key in keys {
            let Some(mut sock) = self.sockets.remove(&key) else {
                continue;
            };
            sock.check_timeouts(self);
            if sock.state == ConnState::Destroy {
                self.destroy_sock(sock);
            } else {
                self.sockets.insert(key, sock);
            }
        }
    }

    /// utp_writev on the socket identified by `key`. Returns None if the
    /// engine socket no longer exists.
    pub fn write(&mut self, key: Key, buf: &[u8]) -> Option<usize> {
        self.with_sock(key, |ctx, sock| sock.write_engine(ctx, buf))
    }

    // utp_read_drained
    pub fn read_drained(&mut self, key: Key) {
        self.with_sock(key, |ctx, sock| sock.read_drained(ctx));
    }

    // utp_close
    pub fn close(&mut self, key: Key) {
        self.with_sock(key, |ctx, sock| sock.close_engine(ctx));
    }

    /// utp_destroy: tear down every socket immediately (Socket::close).
    pub fn destroy_all(&mut self) {
        let keys: Vec<Key> = self.sockets.keys().copied().collect();
        for key in keys {
            if let Some(sock) = self.sockets.remove(&key) {
                self.destroy_sock(sock);
            }
        }
        self.ack_list.clear();
    }
}

pub struct UtpSock {
    pub key: Key,
    pub user: Arc<ConnShared>,
    in_ack_list: bool,

    retransmit_count: u16,
    reorder_count: u16,
    duplicate_ack: u8,

    // the number of packets in the send queue. Packets that haven't
    // yet been sent count as well as packets marked as needing resend.
    // the oldest un-acked packet in the send queue is seq_nr - cur_window_packets
    cur_window_packets: u16,
    // how much of the window is used, number of bytes in-flight
    cur_window: usize,
    // maximum window size, in bytes
    max_window: usize,
    opt_sndbuf: usize,
    opt_rcvbuf: usize,
    // target delay in microseconds
    target_delay: usize,

    got_fin: bool,
    got_fin_reached: bool,
    fin_sent: bool,
    fin_sent_acked: bool,
    read_shutdown: bool,
    close_requested: bool,
    fast_timeout: bool,

    // max receive window for other end, in bytes
    max_window_user: usize,
    pub state: ConnState,
    // ms when we last decayed window (wraps)
    last_rwin_decay: i64,

    // the sequence number of the FIN packet
    eof_pkt: u16,

    // All sequence numbers up to including this have been properly received
    // by us
    ack_nr: u16,
    // This is the sequence number for the next packet to be sent.
    seq_nr: u16,

    timeout_seq_nr: u16,
    // sequence number of the next packet we're allowed to fast-resend
    fast_resend_seq_nr: u16,

    reply_micro: u32,

    last_got_packet: u64,
    last_sent_packet: u64,
    last_measured_delay: u64,
    // timestamp of the last time the cwnd was full
    last_maxed_out_window: u64,

    // Round trip time, variance, timeout
    rtt: u32,
    rtt_var: u32,
    rto: u32,
    rtt_hist: DelayHist,
    retransmit_timeout: u32,
    // The RTO timer will timeout here
    rto_timeout: u64,
    // window-probe timer for a zero remote window
    zerowindow_time: u64,

    conn_seed: u32,
    // Connection ID for packets I receive
    pub conn_id_recv: u32,
    // Connection ID for packets I send
    pub conn_id_send: u32,
    // Last rcv window we advertised, in bytes
    last_rcv_win: usize,

    our_hist: DelayHist,
    their_hist: DelayHist,

    // extension bytes from SYN packet
    extensions: [u8; 8],

    // MTU discovery
    mtu_discover_time: u64,
    mtu_ceiling: u32,
    mtu_floor: u32,
    mtu_last: u32,
    mtu_probe_seq: u32,
    mtu_probe_size: u32,

    // average delay bookkeeping for the clock drift estimate
    average_delay: i32,
    current_delay_sum: i64,
    current_delay_samples: i32,
    average_delay_base: u32,
    average_sample_time: u64,
    // estimated clock drift, microseconds per 5 seconds
    clock_drift: i32,
    #[allow(dead_code)]
    clock_drift_raw: i32,

    inbuf: CircularBuffer<Vec<u8>>,
    outbuf: CircularBuffer<OutgoingPacket>,

    // true if we're in slow-start (exponential growth) phase
    slow_start: bool,
    // the slow-start threshold, in bytes
    ssthresh: usize,
}

impl UtpSock {
    // utp_create_socket defaults
    fn new(ctx: &Context, addr: SocketAddr, user: Arc<ConnShared>) -> Self {
        UtpSock {
            key: Key { addr, recv_id: 0 },
            user,
            in_ack_list: false,
            retransmit_count: 0,
            reorder_count: 0,
            duplicate_ack: 0,
            cur_window_packets: 0,
            cur_window: 0,
            max_window: 0,
            opt_sndbuf: ctx.opt_sndbuf,
            opt_rcvbuf: ctx.opt_rcvbuf,
            target_delay: ctx.target_delay,
            got_fin: false,
            got_fin_reached: false,
            fin_sent: false,
            fin_sent_acked: false,
            read_shutdown: false,
            close_requested: false,
            fast_timeout: false,
            max_window_user: 255 * PACKET_SIZE,
            state: ConnState::Idle,
            last_rwin_decay: 0,
            eof_pkt: 0,
            ack_nr: 0,
            seq_nr: 1,
            timeout_seq_nr: 0,
            fast_resend_seq_nr: 1,
            reply_micro: 0,
            last_got_packet: 0,
            last_sent_packet: 0,
            last_measured_delay: 0,
            last_maxed_out_window: 0,
            rtt: 0,
            rtt_var: 800,
            rto: 3000,
            rtt_hist: DelayHist::new(0),
            retransmit_timeout: 0,
            rto_timeout: 0,
            zerowindow_time: 0,
            conn_seed: 0,
            conn_id_recv: 0,
            conn_id_send: 0,
            last_rcv_win: 0,
            our_hist: DelayHist::new(0),
            their_hist: DelayHist::new(0),
            extensions: [0; 8],
            mtu_discover_time: 0,
            mtu_ceiling: 0,
            mtu_floor: 0,
            mtu_last: 0,
            mtu_probe_seq: 0,
            mtu_probe_size: 0,
            average_delay: 0,
            current_delay_sum: 0,
            current_delay_samples: 0,
            average_delay_base: 0,
            average_sample_time: 0,
            clock_drift: 0,
            clock_drift_raw: 0,
            inbuf: CircularBuffer::new(),
            outbuf: CircularBuffer::new(),
            slow_start: true,
            ssthresh: ctx.opt_sndbuf,
        }
    }

    fn schedule_ack(&mut self, ctx: &mut Context) {
        if !self.in_ack_list {
            self.in_ack_list = true;
            ctx.ack_list.push(self.key);
        }
    }

    // Calculates the current receive window
    fn get_rcv_window(&self) -> usize {
        // Trim window down according to what's already buffered for the app.
        let numbuf = self.user.read_buffer_len();
        self.opt_rcvbuf.saturating_sub(numbuf)
    }

    fn can_decay_win(&self, msec: i64) -> bool {
        msec - self.last_rwin_decay >= MAX_WINDOW_DECAY
    }

    // If we can, decay max window
    fn maybe_decay_win(&mut self, current_ms: u64) {
        if self.can_decay_win(current_ms as i64) {
            // TCP uses 0.5
            self.max_window = (self.max_window as f64 * 0.5) as usize;
            self.last_rwin_decay = current_ms as i64;
            if self.max_window < MIN_WINDOW_SIZE {
                self.max_window = MIN_WINDOW_SIZE;
            }
            self.slow_start = false;
            self.ssthresh = self.max_window;
        }
    }

    fn get_udp_mtu(&self) -> u32 {
        // Be conservative and assume all IPv6 connections are Teredo.
        if self.key.addr.is_ipv6() {
            UDP_TEREDO_MTU
        } else {
            UDP_IPV4_MTU
        }
    }

    #[allow(dead_code)]
    fn get_udp_overhead(&self) -> usize {
        if self.key.addr.is_ipv6() {
            UDP_TEREDO_OVERHEAD
        } else {
            UDP_IPV4_OVERHEAD
        }
    }

    // returns the max number of bytes of payload the connection is allowed
    // to send in one packet
    fn get_packet_size(&self) -> usize {
        let mtu = if self.mtu_last != 0 {
            self.mtu_last
        } else {
            self.mtu_ceiling
        };
        mtu as usize - HEADER_SIZE
    }

    // UTPSocket::send_data: stamp the header timestamps and put the packet on
    // the wire.
    fn send_data(&mut self, ctx: &mut Context, buf: &mut [u8]) {
        let time = ctx.clock.micros();
        packet::set_tv_usec(buf, time as u32);
        packet::set_reply_micro(buf, self.reply_micro);
        self.last_sent_packet = ctx.current_ms;
        if let Err(e) = ctx.send_to_addr(buf, self.key.addr) {
            // go-libutp fails the connection on unrecoverable argument /
            // routing errors and ignores transient ones.
            match e.kind() {
                io::ErrorKind::InvalidInput | io::ErrorKind::AddrNotAvailable => {
                    self.user.on_error(e.kind());
                }
                _ => {}
            }
        }
        ctx.ack_list_remove(self);
    }

    // UTPSocket::send_ack
    fn send_ack(&mut self, ctx: &mut Context, synack: bool) {
        let mut b = [0u8; HEADER_SIZE + 6];
        self.last_rcv_win = self.get_rcv_window();
        packet::set_version_type(&mut b, 1, ST_STATE);
        packet::set_conn_id(&mut b, self.conn_id_send as u16);
        packet::set_ack_nr(&mut b, self.ack_nr);
        packet::set_seq_nr(&mut b, self.seq_nr);
        packet::set_window_size(&mut b, self.last_rcv_win as u32);
        let mut len = HEADER_SIZE;

        // we never need to send EACK for connections that are shutting down
        if self.reorder_count != 0 && !self.got_fin_reached {
            // if reorder count > 0, send an EACK. reorder count should
            // always be 0 for synacks
            debug_assert!(!synack);
            packet::set_ext(&mut b, 1);
            b[HEADER_SIZE] = 0; // ext_next
            b[HEADER_SIZE + 1] = 4; // ext_len
            let window = std::cmp::min(14 + 16, self.inbuf.size());
            let mut m: u32 = 0;
            // Generate bit mask of segments received.
            for i in 0..window {
                if self.inbuf.get(wrap16(self.ack_nr) + i + 2).is_some() {
                    m |= 1 << i;
                }
            }
            b[HEADER_SIZE + 2..HEADER_SIZE + 6].copy_from_slice(&m.to_le_bytes());
            len += 6;
        }
        let _ = synack;
        let mut out = b;
        self.send_data(ctx, &mut out[..len]);
        ctx.ack_list_remove(self);
    }

    // UTPSocket::send_keep_alive
    fn send_keep_alive(&mut self, ctx: &mut Context) {
        self.ack_nr = self.ack_nr.wrapping_sub(1);
        self.send_ack(ctx, false);
        self.ack_nr = self.ack_nr.wrapping_add(1);
    }

    // UTPSocket::send_packet, addressed by sequence number since packets
    // live in outbuf.
    fn send_packet_at(&mut self, ctx: &mut Context, seq: u16) {
        let Some(mut pkt) = self.outbuf.take(wrap16(seq)) else {
            return;
        };
        let cur_time = ctx.clock.millis();

        // only count against the window the first time we send the packet
        if pkt.transmissions == 0 || pkt.need_resend {
            self.cur_window += pkt.payload;
        }
        pkt.need_resend = false;

        packet::set_ack_nr(&mut pkt.data, self.ack_nr);
        pkt.time_sent = ctx.clock.micros();

        if self.mtu_discover_time < cur_time {
            // it's time to reset our MTU assumptions and trigger a new search
            self.mtu_reset(cur_time);
        }

        // don't use packets larger than mtu_ceiling as probes. if seq_nr ==
        // 1, the probe would end up being 0 which is a magic number
        // representing no-probe.
        if self.mtu_floor < self.mtu_ceiling
            && pkt.data.len() as u32 > self.mtu_floor
            && pkt.data.len() as u32 <= self.mtu_ceiling
            && self.mtu_probe_seq == 0
            && self.seq_nr != 1
            && pkt.transmissions == 0
        {
            // we've already incremented seq_nr for this packet
            self.mtu_probe_seq = (self.seq_nr.wrapping_sub(1)) as u32;
            self.mtu_probe_size = pkt.data.len() as u32;
        }

        pkt.transmissions += 1;
        let mut data = std::mem::take(&mut pkt.data);
        self.send_data(ctx, &mut data);
        pkt.data = data;
        self.outbuf.put(wrap16(seq), Some(pkt));
    }

    // UTPSocket::is_full
    fn is_full(&mut self, ctx: &Context, bytes: Option<usize>) -> bool {
        let packet_size = self.get_packet_size();
        let bytes = match bytes {
            None => packet_size,
            Some(b) => std::cmp::min(b, packet_size),
        };
        let max_send = self
            .max_window
            .min(self.opt_sndbuf)
            .min(self.max_window_user);

        // subtract one to save space for the FIN packet
        if self.cur_window_packets as usize >= OUTGOING_BUFFER_MAX_SIZE - 1 {
            self.last_maxed_out_window = ctx.current_ms;
            return true;
        }
        if self.cur_window + bytes > max_send {
            self.last_maxed_out_window = ctx.current_ms;
            return true;
        }
        false
    }

    // UTPSocket::flush_packets. Returns true if it ran out of window.
    fn flush_packets(&mut self, ctx: &mut Context) -> bool {
        let packet_size = self.get_packet_size();

        // i has to be a wrapping 16 bit counter
        let mut i = self.seq_nr.wrapping_sub(self.cur_window_packets);
        while i != self.seq_nr {
            let (send, payload) = match self.outbuf.get(wrap16(i)) {
                None => (false, 0),
                Some(p) => (p.transmissions == 0 || p.need_resend, p.payload),
            };
            if send {
                // have we run out of quota?
                if self.is_full(ctx, None) {
                    return true;
                }
                // Nagle check: don't send the last packet if we have packets
                // in-flight and the current packet is still small.
                if i != self.seq_nr.wrapping_sub(1)
                    || self.cur_window_packets == 1
                    || payload >= packet_size
                {
                    self.send_packet_at(ctx, i);
                }
            }
            i = i.wrapping_add(1);
        }
        false
    }

    // UTPSocket::write_outgoing_packet
    // @payload: number of bytes to send
    // @flags: either ST_DATA or ST_FIN
    fn write_outgoing_packet(
        &mut self,
        ctx: &mut Context,
        mut payload: usize,
        flags: u8,
        data: &mut &[u8],
    ) {
        // Setup initial timeout timer
        if self.cur_window_packets == 0 {
            self.retransmit_timeout = self.rto;
            self.rto_timeout = ctx.current_ms + self.retransmit_timeout as u64;
            debug_assert_eq!(self.cur_window, 0);
        }

        let packet_size = self.get_packet_size();
        loop {
            debug_assert!((self.cur_window_packets as usize) < OUTGOING_BUFFER_MAX_SIZE);
            debug_assert!(flags == ST_DATA || flags == ST_FIN);

            let last_rcv_win = self.get_rcv_window();
            self.last_rcv_win = last_rcv_win;

            let last_seq = self.seq_nr.wrapping_sub(1);
            // if there's any room left in the last packet in the window and
            // it hasn't been sent yet, fill that frame first
            let extend_last = payload > 0
                && self.cur_window_packets > 0
                && match self.outbuf.get(wrap16(last_seq)) {
                    Some(p) => p.transmissions == 0 && p.payload < packet_size,
                    None => false,
                };

            let added;
            let target_seq;
            if extend_last {
                let pkt = self.outbuf.get_mut(wrap16(last_seq)).unwrap();
                debug_assert!(!pkt.need_resend);
                added = std::cmp::min(
                    payload + pkt.payload,
                    std::cmp::max(packet_size, pkt.payload),
                ) - pkt.payload;
                let n = std::cmp::min(added, data.len());
                pkt.data.extend_from_slice(&data[..n]);
                *data = &data[n..];
                debug_assert_eq!(n, added);
                pkt.payload += added;
                target_seq = last_seq;
            } else {
                added = payload;
                let mut buf = Vec::with_capacity(HEADER_SIZE + added);
                buf.resize(HEADER_SIZE, 0);
                let n = std::cmp::min(added, data.len());
                buf.extend_from_slice(&data[..n]);
                *data = &data[n..];
                debug_assert_eq!(n, added);
                let pkt = OutgoingPacket {
                    payload: added,
                    time_sent: 0,
                    transmissions: 0,
                    need_resend: false,
                    data: buf,
                };
                // Remember the message in the outgoing queue.
                self.outbuf
                    .ensure_size(wrap16(self.seq_nr), self.cur_window_packets as usize);
                self.outbuf.put(wrap16(self.seq_nr), Some(pkt));
                target_seq = self.seq_nr;
                self.seq_nr = self.seq_nr.wrapping_add(1);
                self.cur_window_packets += 1;
            }

            {
                let seq_for_header = if extend_last { None } else { Some(target_seq) };
                let conn_id = self.conn_id_send as u16;
                let ack_nr = self.ack_nr;
                let pkt = self.outbuf.get_mut(wrap16(target_seq)).unwrap();
                packet::set_version_type(&mut pkt.data, 1, flags);
                packet::set_ext(&mut pkt.data, 0);
                packet::set_conn_id(&mut pkt.data, conn_id);
                packet::set_window_size(&mut pkt.data, last_rcv_win as u32);
                packet::set_ack_nr(&mut pkt.data, ack_nr);
                if let Some(s) = seq_for_header {
                    packet::set_seq_nr(&mut pkt.data, s);
                }
            }

            payload -= added;
            if payload == 0 {
                break;
            }
        }
        self.flush_packets(ctx);
    }

    // UTPSocket::check_timeouts (per socket)
    fn check_timeouts(&mut self, ctx: &mut Context) {
        if self.state != ConnState::Destroy {
            self.flush_packets(ctx);
        }

        match self.state {
            ConnState::SynSent
            | ConnState::SynRecv
            | ConnState::ConnectedFull
            | ConnState::Connected => {
                // Reset max window...
                if ms_elapsed(ctx.current_ms, self.zerowindow_time) && self.max_window_user == 0 {
                    self.max_window_user = PACKET_SIZE;
                }

                if ms_elapsed(ctx.current_ms, self.rto_timeout) && self.rto_timeout > 0 {
                    let mut ignore_loss = false;

                    if self.cur_window_packets == 1
                        && self.seq_nr.wrapping_sub(1) as u32 == self.mtu_probe_seq
                        && self.mtu_probe_seq != 0
                    {
                        // our only outstanding packet timed out, and it was
                        // the MTU probe: likely dropped for size, not
                        // congestion
                        self.mtu_ceiling = self.mtu_probe_size - 1;
                        self.mtu_search_update(ctx);
                        ignore_loss = true;
                    }
                    // we dropped the probe, allow a new one
                    self.mtu_probe_seq = 0;
                    self.mtu_probe_size = 0;

                    // Increase RTO
                    let new_timeout = if ignore_loss {
                        self.retransmit_timeout
                    } else {
                        self.retransmit_timeout * 2
                    };

                    // They initiated the connection but failed to respond
                    // before the rto. Kill the connection and do not notify
                    // the accept side beyond the error.
                    if self.state == ConnState::SynRecv {
                        self.state = ConnState::Destroy;
                        self.user.on_error(io::ErrorKind::TimedOut);
                        return;
                    }

                    if self.retransmit_count >= 4
                        || (self.state == ConnState::SynSent && self.retransmit_count >= 2)
                    {
                        // 4 consecutive transmissions have timed out (2 when
                        // still connecting). Kill it.
                        self.state = if self.close_requested {
                            ConnState::Destroy
                        } else {
                            ConnState::Reset
                        };
                        self.user.on_error(io::ErrorKind::TimedOut);
                        return;
                    }

                    self.retransmit_timeout = new_timeout;
                    self.rto_timeout = ctx.current_ms + new_timeout as u64;

                    if !ignore_loss {
                        // On Timeout
                        self.duplicate_ack = 0;
                        let packet_size = self.get_packet_size();
                        if self.cur_window_packets == 0 && self.max_window > packet_size {
                            // connection is idling; let the window decay by a
                            // third
                            self.max_window = std::cmp::max(self.max_window * 2 / 3, packet_size);
                        } else {
                            // reset the congestion window to fit one packet,
                            // to start over again
                            self.max_window = packet_size;
                            self.slow_start = true;
                        }
                    }

                    // every packet should be considered lost
                    for i in 0..self.cur_window_packets {
                        let seq = self.seq_nr.wrapping_sub(i).wrapping_sub(1);
                        let payload = match self.outbuf.get_mut(wrap16(seq)) {
                            None => continue,
                            Some(pkt) => {
                                if pkt.transmissions == 0 || pkt.need_resend {
                                    continue;
                                }
                                pkt.need_resend = true;
                                pkt.payload
                            }
                        };
                        debug_assert!(self.cur_window >= payload);
                        self.cur_window -= payload;
                    }

                    if self.cur_window_packets > 0 {
                        self.retransmit_count += 1;
                        self.fast_timeout = true;
                        self.timeout_seq_nr = self.seq_nr;

                        // Re-send the oldest packet.
                        let seq = self.seq_nr.wrapping_sub(self.cur_window_packets);
                        self.send_packet_at(ctx, seq);
                    }
                }

                // Mark the socket as writable
                if self.state == ConnState::ConnectedFull && !self.is_full(ctx, None) {
                    self.state = ConnState::Connected;
                    self.user.on_writable();
                }

                if matches!(self.state, ConnState::Connected | ConnState::ConnectedFull)
                    && !self.fin_sent
                    && ctx.current_ms.wrapping_sub(self.last_sent_packet) as u32 as i32
                        >= KEEPALIVE_INTERVAL
                {
                    self.send_keep_alive(ctx);
                }
            }
            _ => {}
        }
    }

    // this should be called every time we change mtu_floor or mtu_ceiling
    fn mtu_search_update(&mut self, ctx: &Context) {
        // the floor can end up above the ceiling; repair the range and search
        // again from half way down rather than from the bottom
        if self.mtu_floor > self.mtu_ceiling {
            self.mtu_ceiling = self.mtu_floor;
            self.mtu_floor = if self.mtu_ceiling > MTU_FLOOR_MIN {
                (MTU_FLOOR_MIN + self.mtu_ceiling) / 2
            } else {
                self.mtu_ceiling
            };
        }
        debug_assert!(self.mtu_floor <= self.mtu_ceiling);

        // binary search
        self.mtu_last = (self.mtu_floor + self.mtu_ceiling) / 2;

        // enable a new probe to be sent
        self.mtu_probe_seq = 0;
        self.mtu_probe_size = 0;

        // if the floor and ceiling are close enough, the search is done. We
        // use the floor since that's the only size we know can go through.
        if self.mtu_ceiling - self.mtu_floor <= 16 {
            self.mtu_last = self.mtu_floor;
            self.mtu_ceiling = self.mtu_floor;
            // Do another search in 30 minutes
            self.mtu_discover_time = ctx.clock.millis() + 30 * 60 * 1000;
        }
    }

    fn mtu_reset(&mut self, current_ms: u64) {
        self.mtu_ceiling = self.get_udp_mtu();
        self.mtu_floor = MTU_FLOOR_MIN;
        // an interface can report an MTU below the smallest size we would
        // otherwise search down to. Follow it down rather than inverting the
        // range.
        if self.mtu_floor > self.mtu_ceiling {
            self.mtu_floor = self.mtu_ceiling;
        }
        self.mtu_discover_time = current_ms + 30 * 60 * 1000;
    }

    // UTPSocket::ack_packet
    fn ack_packet(&mut self, ctx: &mut Context, seq: u16) -> AckResult {
        match self.outbuf.get(wrap16(seq)) {
            // the packet has already been acked (or not sent)
            None => return AckResult::AlreadyAcked,
            // can't ack packets that haven't been sent yet!
            Some(pkt) if pkt.transmissions == 0 => return AckResult::NotSent,
            _ => {}
        }
        let pkt = self.outbuf.take(wrap16(seq)).unwrap();

        // if we never re-sent the packet, update the RTT estimate
        if pkt.transmissions == 1 {
            // Estimate the round trip time.
            let ertt = (ctx.clock.micros().wrapping_sub(pkt.time_sent) / 1000) as u32;
            if self.rtt == 0 {
                // First round trip time sample
                self.rtt = ertt;
                self.rtt_var = ertt / 2;
            } else {
                // Compute new round trip times
                let delta = self.rtt as i32 - ertt as i32;
                self.rtt_var =
                    (self.rtt_var as i32 + (delta.abs() - self.rtt_var as i32) / 4) as u32;
                self.rtt = self.rtt - self.rtt / 8 + ertt / 8;
                self.rtt_hist.add_sample(ertt, ctx.current_ms);
            }
            self.rto = std::cmp::max(self.rtt + self.rtt_var * 4, 1000);
        }
        self.retransmit_timeout = self.rto;
        self.rto_timeout = ctx.current_ms + self.rto as u64;
        // if need_resend is set, this packet was already considered
        // timed-out, and is not included in the cur_window anymore
        if !pkt.need_resend {
            debug_assert!(self.cur_window >= pkt.payload);
            self.cur_window -= pkt.payload;
        }
        self.retransmit_count = 0;
        AckResult::Acked
    }

    // count the number of bytes that were acked by the EACK header
    fn selective_ack_bytes(
        &mut self,
        ctx: &Context,
        base: u16,
        mask: &[u8],
        min_rtt: &mut i64,
    ) -> usize {
        if self.cur_window_packets == 0 {
            return 0;
        }
        let mut acked_bytes = 0usize;
        let now = ctx.clock.micros();
        let top_bit = mask.len() as i32 * 8;

        for bits in (-1..=top_bit).rev() {
            let v = base.wrapping_add(bits as u16);

            // ignore bits that haven't been sent yet
            // (see the comment in selective_ack)
            if wrap16(self.seq_nr.wrapping_sub(v).wrapping_sub(1))
                >= self.cur_window_packets as usize - 1
            {
                continue;
            }

            // ignore bits that represent packets we haven't sent yet
            // or packets that have already been acked
            let (payload, time_sent) = match self.outbuf.get(wrap16(v)) {
                Some(p) if p.transmissions > 0 => (p.payload, p.time_sent),
                _ => continue,
            };

            // (The C original indexes one byte past the mask on the first
            // iteration; we treat out-of-range bits as unset instead.)
            let bit_set =
                bits >= 0 && bits < top_bit && mask[(bits >> 3) as usize] & (1 << (bits & 7)) != 0;
            if bit_set {
                acked_bytes += payload;
                *min_rtt = std::cmp::min(
                    *min_rtt,
                    if time_sent < now {
                        (now - time_sent) as i64
                    } else {
                        50000
                    },
                );
            }
        }
        acked_bytes
    }

    // UTPSocket::selective_ack
    fn selective_ack(&mut self, ctx: &mut Context, base: u16, mask: &[u8]) {
        if self.cur_window_packets == 0 {
            return;
        }

        // the range is inclusive [0, 31] bits
        let top_bit = mask.len() as i32 * 8 - 1;
        let mut count: u32 = 0;

        // resends is a stack of sequence numbers we need to resend. Since we
        // iterate in reverse over the acked packets, at the end, the top
        // packets are the ones we want to resend
        let mut resends: Vec<u16> = Vec::new();

        for bits in (-1..=top_bit).rev() {
            // we're iterating over the bits from higher sequence numbers to
            // lower
            let v = base.wrapping_add(bits as u16);

            // ignore bits that haven't been sent yet and bits that fall below
            // the ACKed sequence number. Sequence number space:
            //
            //     rejected <   accepted   > rejected
            // <============+--------------+============>
            //              ^              ^
            //        (seq_nr-wnd)         seq_nr
            if wrap16(self.seq_nr.wrapping_sub(v).wrapping_sub(1))
                >= self.cur_window_packets as usize - 1
            {
                continue;
            }

            // this counts as a duplicate ack, even though we might have
            // received an ack for this packet previously (in another EACK
            // message for instance)
            let bit_set = bits >= 0 && mask[(bits >> 3) as usize] & (1 << (bits & 7)) != 0;
            if bit_set {
                count += 1;
            }

            // ignore bits that represent packets we haven't sent yet
            // or packets that have already been acked
            let sent = matches!(self.outbuf.get(wrap16(v)), Some(p) if p.transmissions > 0);
            if !sent {
                continue;
            }

            if bit_set {
                self.ack_packet(ctx, v);
                continue;
            }

            // Resend segments: if count is less than our re-send limit, we
            // haven't seen enough acked packets in front of this one to
            // warrant a re-send
            if wrap16(v.wrapping_sub(self.fast_resend_seq_nr)) <= OUTGOING_BUFFER_MAX_SIZE
                && count >= DUPLICATE_ACKS_BEFORE_RESEND
            {
                // resends is a stack; if we're full, just throw away the
                // lower half
                if resends.len() >= MAX_EACK - 2 {
                    resends.drain(0..MAX_EACK / 2);
                }
                resends.push(v);
            }
        }

        if wrap16(base.wrapping_sub(1).wrapping_sub(self.fast_resend_seq_nr))
            <= OUTGOING_BUFFER_MAX_SIZE
            && count >= DUPLICATE_ACKS_BEFORE_RESEND
        {
            // if we get enough duplicate acks to start resending, the first
            // packet we should resend is base-1
            resends.push(base.wrapping_sub(1));
        }

        let mut back_off = false;
        let mut i = 0;
        while let Some(v) = resends.pop() {
            // don't consider the tail of 0:es to be lost packets; some of
            // these may have been acked already
            if self.outbuf.get(wrap16(v)).is_none() {
                continue;
            }

            // On Loss
            back_off = true;
            self.send_packet_at(ctx, v);
            self.fast_resend_seq_nr = v.wrapping_add(1);

            // Re-send max 4 packets.
            i += 1;
            if i >= 4 {
                break;
            }
        }

        if back_off {
            self.maybe_decay_win(ctx.current_ms);
        }
        self.duplicate_ack = count as u8;
    }

    // UTPSocket::apply_ccontrol — the LEDBAT congestion controller
    fn apply_ccontrol(
        &mut self,
        ctx: &Context,
        bytes_acked: usize,
        _actual_delay: u32,
        min_rtt: i64,
    ) {
        // the delay can never be greater than the rtt
        debug_assert!(min_rtt >= 0);
        let mut our_delay =
            std::cmp::min(self.our_hist.get_value() as u64, min_rtt as u64) as i64 as i32;

        // target is microseconds
        let mut target = self.target_delay as i32;
        if target <= 0 {
            target = 100_000;
        }

        // compensate for very large clock drift that would otherwise give
        // certain endpoints an unfair share of the bandwidth (e.g. peers
        // "cheating" uTP by making their clock run slower)
        if self.clock_drift < -200_000 {
            let penalty = (-self.clock_drift - 200_000) / 7;
            our_delay += penalty;
        }

        let off_target = (target - our_delay) as f64;

        // scale the max increase by the fraction of the window this ack
        // represents, and the fraction of the target delay the current delay
        // represents
        debug_assert!(bytes_acked > 0);
        let window_factor = std::cmp::min(bytes_acked, self.max_window) as f64
            / std::cmp::max(self.max_window, bytes_acked) as f64;
        let delay_factor = off_target / target as f64;
        let mut scaled_gain = MAX_CWND_INCREASE_BYTES_PER_RTT as f64 * window_factor * delay_factor;

        if scaled_gain > 0.0 && ctx.current_ms.wrapping_sub(self.last_maxed_out_window) > 1000 {
            // if it was more than 1 second since we tried to send a packet
            // and stopped because we hit the max window, we're most likely
            // rate limited; don't let the window grow indefinitely
            scaled_gain = 0.0;
        }

        let ledbat_cwnd = if (self.max_window as f64 + scaled_gain) < MIN_WINDOW_SIZE as f64 {
            MIN_WINDOW_SIZE
        } else {
            (self.max_window as f64 + scaled_gain) as usize
        };

        if self.slow_start {
            let ss_cwnd =
                (self.max_window as f64 + window_factor * self.get_packet_size() as f64) as usize;
            if ss_cwnd > self.ssthresh {
                self.slow_start = false;
            } else if our_delay as f64 > target as f64 * 0.9 {
                // even a little under the target delay, we conservatively
                // discontinue the slow start phase
                self.slow_start = false;
                self.ssthresh = self.max_window;
            } else {
                self.max_window = std::cmp::max(ss_cwnd, ledbat_cwnd);
            }
        } else {
            self.max_window = ledbat_cwnd;
        }

        // make sure that the congestion window is below max and that we
        // don't shrink our window too small
        self.max_window = self.max_window.clamp(MIN_WINDOW_SIZE, self.opt_sndbuf);

        static DBG: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        if *DBG.get_or_init(|| std::env::var_os("UTP_DBG_CCONTROL").is_some()) {
            eprintln!(
                "ccontrol ms:{} max_window:{} cur_window:{} cwp:{} acked:{} our_delay:{} gain:{:.1} ss:{} rtt:{}",
                ctx.current_ms, self.max_window, self.cur_window, self.cur_window_packets,
                bytes_acked, our_delay, scaled_gain, self.slow_start, self.rtt,
            );
        }
    }

    // utp_writev (single buffer). Returns bytes accepted; 0 means the socket
    // is not currently writable.
    fn write_engine(&mut self, ctx: &mut Context, buf: &[u8]) -> usize {
        if self.state != ConnState::Connected {
            return 0;
        }
        if self.fin_sent {
            return 0;
        }
        ctx.current_ms = ctx.clock.millis();

        // don't send unless it will all fit in the window
        let packet_size = self.get_packet_size();
        let mut remaining = buf;
        let mut sent = 0usize;
        let mut num_to_send = std::cmp::min(remaining.len(), packet_size);
        while !self.is_full(ctx, Some(num_to_send)) {
            // Send an outgoing packet. Also add it to the outgoing queue of
            // packets that have been sent but not ACKed.
            sent += num_to_send;
            self.write_outgoing_packet(ctx, num_to_send, ST_DATA, &mut remaining);
            num_to_send = std::cmp::min(remaining.len(), packet_size);
            if num_to_send == 0 {
                return sent;
            }
        }
        if self.is_full(ctx, None) {
            // mark the socket as not being writable
            self.state = ConnState::ConnectedFull;
        }
        sent
    }

    // utp_read_drained
    fn read_drained(&mut self, ctx: &mut Context) {
        let rcvwin = self.get_rcv_window();
        if rcvwin > self.last_rcv_win {
            // If last window was 0 send ACK immediately, otherwise defer
            if self.last_rcv_win == 0 {
                self.send_ack(ctx, false);
            } else {
                ctx.current_ms = ctx.clock.millis();
                self.schedule_ack(ctx);
            }
        }
    }

    // utp_close
    fn close_engine(&mut self, ctx: &mut Context) {
        match self.state {
            ConnState::Connected | ConnState::ConnectedFull => {
                self.read_shutdown = true;
                self.close_requested = true;
                if !self.fin_sent {
                    self.fin_sent = true;
                    self.write_outgoing_packet(ctx, 0, ST_FIN, &mut &[][..]);
                } else if self.fin_sent_acked {
                    self.state = ConnState::Destroy;
                }
            }
            ConnState::SynSent => {
                self.rto_timeout = ctx.clock.millis() + std::cmp::min(self.rto * 2, 60) as u64;
                self.state = ConnState::Destroy;
            }
            _ => {
                self.state = ConnState::Destroy;
            }
        }
    }

    // utp_process_incoming. `syn` is true when this is the SYN of an incoming
    // connection; parsing stops after the header in that case.
    // Returns the number of payload bytes consumed.
    fn process_incoming(&mut self, ctx: &mut Context, buf: &[u8], syn: bool) -> usize {
        ctx.current_ms = ctx.clock.millis();

        let h = Header(buf);
        let pk_seq_nr = h.seq_nr();
        let pk_ack_nr = h.ack_nr();
        let pk_flags = h.packet_type();

        if pk_flags >= ST_NUM_STATES {
            return 0;
        }

        // mark receipt time
        let time = ctx.clock.micros();

        // window packets size is used to calculate a minimum permissible
        // range for received acks. Acks falling out of this range are dropped
        let curr_window = std::cmp::max(
            self.cur_window_packets.wrapping_add(ACK_NR_ALLOWED_WINDOW),
            ACK_NR_ALLOWED_WINDOW,
        );

        // ignore packets whose ack_nr is invalid; this would imply a spoofed
        // address or a malicious attempt to attack us
        if (pk_flags != ST_SYN || self.state != ConnState::SynRecv)
            && (wrapping_compare_less(
                self.seq_nr.wrapping_sub(1) as u32,
                pk_ack_nr as u32,
                ACK_NR_MASK,
            ) || wrapping_compare_less(
                pk_ack_nr as u32,
                self.seq_nr.wrapping_sub(1).wrapping_sub(curr_window) as u32,
                ACK_NR_MASK,
            ))
        {
            return 0;
        }

        // RSTs are handled earlier, since the connid matches the send id not
        // the recv id
        debug_assert!(pk_flags != ST_RESET);

        let mut selack: Option<(usize, usize)> = None;

        if HEADER_SIZE > buf.len() {
            return 0;
        }
        // Skip the extension headers
        let mut data_start = HEADER_SIZE;
        let mut extension = h.ext();
        if extension != 0 {
            loop {
                // Verify that the packet is valid.
                data_start += 2;
                if data_start > buf.len() {
                    return 0;
                }
                let elen = buf[data_start - 1] as usize;
                if buf.len() - data_start < elen {
                    return 0;
                }
                match extension {
                    1 => {
                        // Selective Acknowledgment
                        selack = Some((data_start, elen));
                    }
                    2 => {
                        // extension bits
                        if elen != 8 {
                            return 0;
                        }
                        self.extensions
                            .copy_from_slice(&buf[data_start..data_start + 8]);
                    }
                    _ => {}
                }
                extension = buf[data_start - 2];
                data_start += elen;
                if extension == 0 {
                    break;
                }
            }
        }

        if self.state == ConnState::SynSent {
            // if this is a syn-ack, initialize our ack_nr to match the
            // sequence number we got from the other end
            self.ack_nr = pk_seq_nr.wrapping_sub(1);
        }

        self.last_got_packet = ctx.current_ms;

        if syn {
            return 0;
        }

        // seqnr is how many packets past the expected packet this is.
        // Subtracting 1 makes 0 mean "this is the next expected packet".
        let seqnr = wrap16(pk_seq_nr.wrapping_sub(self.ack_nr).wrapping_sub(1));

        // Getting an invalid sequence number?
        if seqnr >= REORDER_BUFFER_MAX_SIZE {
            if seqnr >= 0x10000 - REORDER_BUFFER_MAX_SIZE && pk_flags != ST_STATE {
                self.schedule_ack(ctx);
            }
            return 0;
        }

        // Process acknowledgment: acks is the number of packets acked
        let mut acks = pk_ack_nr.wrapping_sub(
            self.seq_nr
                .wrapping_sub(1)
                .wrapping_sub(self.cur_window_packets),
        );
        // this happens when we receive an old ack nr
        if acks > self.cur_window_packets {
            acks = 0;
        }

        // if we get the same ack_nr as in the last packet, increase the
        // duplicate_ack counter, otherwise reset it to 0. It's important to
        // only count ACKs in ST_STATE packets (in line with BSD4.4 TCP).
        if self.cur_window_packets > 0 {
            if pk_ack_nr
                == self
                    .seq_nr
                    .wrapping_sub(self.cur_window_packets)
                    .wrapping_sub(1)
                && pk_flags == ST_STATE
            {
                self.duplicate_ack = self.duplicate_ack.wrapping_add(1);
                if self.duplicate_ack as u32 == DUPLICATE_ACKS_BEFORE_RESEND
                    && self.mtu_probe_seq != 0
                {
                    // it's likely the probe was rejected due to its size, but
                    // we haven't got an ICMP report back yet
                    if pk_ack_nr as u32 == self.mtu_probe_seq.wrapping_sub(1) & ACK_NR_MASK {
                        self.mtu_ceiling = self.mtu_probe_size - 1;
                        self.mtu_search_update(ctx);
                    } else {
                        // A non-probe was blocked before our probe. Can't
                        // conclude much, send a new probe
                        self.mtu_probe_seq = 0;
                        self.mtu_probe_size = 0;
                    }
                }
            } else {
                self.duplicate_ack = 0;
            }
        }

        // figure out how many bytes were acked
        let mut acked_bytes = 0usize;

        // the minimum rtt of all acks: an upper limit on the delay we'll
        // accept back from the other peer
        let mut min_rtt = i64::MAX;

        let now = ctx.clock.micros();

        for i in 0..acks {
            let seq = self
                .seq_nr
                .wrapping_sub(self.cur_window_packets)
                .wrapping_add(i);
            let (payload, time_sent) = match self.outbuf.get(wrap16(seq)) {
                Some(p) if p.transmissions > 0 => (p.payload, p.time_sent),
                _ => continue,
            };
            acked_bytes += payload;
            if self.mtu_probe_seq != 0 && seq as u32 == self.mtu_probe_seq {
                self.mtu_floor = self.mtu_probe_size;
                self.mtu_search_update(ctx);
            }
            // in case our clock is not monotonic
            min_rtt = std::cmp::min(
                min_rtt,
                if time_sent < now {
                    (now - time_sent) as i64
                } else {
                    50000
                },
            );
        }

        // count bytes acked by EACK
        if let Some((off, len)) = selack {
            acked_bytes += self.selective_ack_bytes(
                ctx,
                pk_ack_nr.wrapping_add(2),
                &buf[off..off + len],
                &mut min_rtt,
            );
        }

        let p = h.tv_usec();

        self.last_measured_delay = ctx.current_ms;

        // get delay in both directions, record the delay to report back
        let their_delay = if p == 0 {
            0
        } else {
            (time as u32).wrapping_sub(p)
        };
        self.reply_micro = their_delay;
        let prev_delay_base = self.their_hist.delay_base;
        if their_delay != 0 {
            self.their_hist.add_sample(their_delay, ctx.current_ms);
        }

        // if their new delay base is less than their previous one, we should
        // shift our delay base in the other direction in order to take the
        // clock skew into account
        if prev_delay_base != 0
            && wrapping_compare_less(self.their_hist.delay_base, prev_delay_base, TIMESTAMP_MASK)
        {
            // never adjust more than 10 milliseconds
            if prev_delay_base.wrapping_sub(self.their_hist.delay_base) <= 10000 {
                self.our_hist
                    .shift(prev_delay_base.wrapping_sub(self.their_hist.delay_base));
            }
        }

        let actual_delay = {
            let rm = h.reply_micro();
            if rm == i32::MAX as u32 {
                0
            } else {
                rm
            }
        };

        // if actual_delay is 0, the other end hasn't received a sample from
        // us yet; we can't update our history without a true sample
        if actual_delay != 0 {
            self.our_hist.add_sample(actual_delay, ctx.current_ms);

            // keep an average of the delay samples received within the last
            // 5 seconds, based off average_delay_base to deal with wrapping
            if self.average_delay_base == 0 {
                self.average_delay_base = actual_delay;
            }
            // distances walking from the base to the sample, both directions
            let dist_down = self.average_delay_base.wrapping_sub(actual_delay);
            let dist_up = actual_delay.wrapping_sub(self.average_delay_base);
            // both are derived from reply_micro, which the peer picks
            // freely, so clamp the sample to the range this average can
            // represent
            let average_delay_sample: i64 = if dist_down > dist_up {
                // base < sample: positive sample
                std::cmp::min(dist_up, MAX_AVERAGE_DELAY_SAMPLE) as i64
            } else {
                // base >= sample: negative sample
                -(std::cmp::min(dist_down, MAX_AVERAGE_DELAY_SAMPLE) as i64)
            };
            self.current_delay_sum += average_delay_sample;
            self.current_delay_samples += 1;

            if ctx.current_ms > self.average_sample_time {
                let mut prev_average_delay = self.average_delay;

                self.average_delay =
                    (self.current_delay_sum / self.current_delay_samples as i64) as i32;
                // each slot represents 5 seconds
                self.average_sample_time += 5000;

                self.current_delay_sum = 0;
                self.current_delay_samples = 0;

                // We're only interested in the slope of the curve formed by
                // the average delay samples, so cancel out the offset to
                // avoid trouble with wrapping. Normalize around zero: try to
                // keep min <= 0 and max >= 0.
                let min_sample = std::cmp::min(prev_average_delay, self.average_delay);
                let max_sample = std::cmp::max(prev_average_delay, self.average_delay);
                let mut adjust = 0;
                if min_sample > 0 {
                    adjust = -min_sample;
                } else if max_sample < 0 {
                    adjust = -max_sample;
                }
                if adjust != 0 {
                    self.average_delay_base = self.average_delay_base.wrapping_sub(adjust as u32);
                    self.average_delay += adjust;
                    prev_average_delay += adjust;
                }

                // update the clock drift estimate: the average slope across
                // our history, in microseconds per 5 seconds
                let drift = self.average_delay - prev_average_delay;
                // clock_drift is a rolling average
                self.clock_drift = ((self.clock_drift as i64 * 7 + drift as i64) / 8) as i32;
                self.clock_drift_raw = drift;
            }
        }

        // if the delay estimate exceeds the RTT, adjust the base_delay to
        // compensate
        debug_assert!(min_rtt >= 0);
        if self.our_hist.get_value() as i64 > min_rtt {
            let shift = (self.our_hist.get_value() as i64 - min_rtt) as u32;
            self.our_hist.shift(shift);
        }

        // only apply the congestion controller on acks
        if actual_delay != 0 && acked_bytes >= 1 {
            self.apply_ccontrol(ctx, acked_bytes, actual_delay, min_rtt);
        }

        // sanity check: the other end should never ack packets past the
        // point we've sent
        if acks <= self.cur_window_packets {
            self.max_window_user = h.window_size() as usize;

            // if the remote window is 0, start a timer that will reset it to
            // a packet after 15 seconds
            if self.max_window_user == 0 {
                self.zerowindow_time = ctx.current_ms + 15000;
            }

            // Incoming connection completion
            if pk_flags == ST_DATA && self.state == ConnState::SynRecv {
                self.state = ConnState::Connected;
                // Writes are refused until the connection is established;
                // wake anyone waiting to retry.
                self.user.on_writable();
            }

            // Outgoing connection completion
            if pk_flags == ST_STATE && self.state == ConnState::SynSent {
                self.state = ConnState::Connected;
                self.user.on_connect();

                // A dialled connection will not tell the remote it's ready
                // until it writes. If the dialer has no intention of writing,
                // this stalls everything, so do an empty write to get things
                // rolling (mirrors go-libutp's stateChangeCallback).
                self.write_engine(ctx, &[]);

            // We've sent a fin, and everything was ACKed (including the FIN)
            } else if self.fin_sent && self.cur_window_packets == acks {
                self.fin_sent_acked = true;
                if self.close_requested {
                    self.state = ConnState::Destroy;
                }
            }

            // Update fast resend counter
            if wrapping_compare_less(
                self.fast_resend_seq_nr as u32,
                pk_ack_nr.wrapping_add(1) as u32,
                ACK_NR_MASK,
            ) {
                self.fast_resend_seq_nr = pk_ack_nr.wrapping_add(1);
            }

            for _ in 0..acks {
                let seq = self.seq_nr.wrapping_sub(self.cur_window_packets);
                // if the packet has not been sent yet we have to break; this
                // can happen when an ack_nr covers packets stuffed into the
                // outgoing buffer that were never sent
                if self.ack_packet(ctx, seq) == AckResult::NotSent {
                    break;
                }
                self.cur_window_packets -= 1;
            }

            // packets in front of this may have been acked by a selective
            // ack (EACK). Keep shrinking the window until we hit a packet
            // still waiting to be acked
            while self.cur_window_packets > 0
                && self
                    .outbuf
                    .get(wrap16(self.seq_nr.wrapping_sub(self.cur_window_packets)))
                    .is_none()
            {
                self.cur_window_packets -= 1;
            }

            // this invariant should always be true
            debug_assert!(
                self.cur_window_packets == 0
                    || self
                        .outbuf
                        .get(wrap16(self.seq_nr.wrapping_sub(self.cur_window_packets)))
                        .is_some()
            );

            // flush Nagle
            if self.cur_window_packets == 1 {
                let seq = self.seq_nr.wrapping_sub(1);
                let unsent =
                    matches!(self.outbuf.get(wrap16(seq)), Some(p) if p.transmissions == 0);
                if unsent {
                    self.send_packet_at(ctx, seq);
                }
            }

            // Fast timeout-retry
            if self.fast_timeout {
                // if fast_resend_seq_nr is not pointing to the oldest
                // outstanding packet, we've already resent the packet that
                // timed out; leave fast-timeout mode
                if self.seq_nr.wrapping_sub(self.cur_window_packets) != self.fast_resend_seq_nr {
                    self.fast_timeout = false;
                } else {
                    // resend the oldest packet and bump fast_resend_seq_nr
                    // to not allow another fast resend on it again
                    let seq = self.seq_nr.wrapping_sub(self.cur_window_packets);
                    let resendable =
                        matches!(self.outbuf.get(wrap16(seq)), Some(p) if p.transmissions > 0);
                    if resendable {
                        self.fast_resend_seq_nr = self.fast_resend_seq_nr.wrapping_add(1);
                        self.send_packet_at(ctx, seq);
                    }
                }
            }
        }

        // Process selective acknowledgment
        if let Some((off, len)) = selack {
            self.selective_ack(ctx, pk_ack_nr.wrapping_add(2), &buf[off..off + len]);
        }

        // In case the ack dropped the current window below the max_window
        // size, mark the socket as writable
        if self.state == ConnState::ConnectedFull && !self.is_full(ctx, None) {
            self.state = ConnState::Connected;
            self.user.on_writable();
        }

        if pk_flags == ST_STATE {
            // This is a state packet only.
            return 0;
        }

        // The connection is not in a state that can accept data?
        if !matches!(self.state, ConnState::Connected | ConnState::ConnectedFull) {
            return 0;
        }

        // Is this a finalize packet?
        if pk_flags == ST_FIN && !self.got_fin {
            self.got_fin = true;
            self.eof_pkt = pk_seq_nr;
            // the other end may have sent packets past the FIN; our
            // reorder_count may be out of sync, dealt with when we re-order
            // and hit the eof_pkt
        }

        let data = &buf[data_start..];

        // Getting an in-order packet?
        if seqnr == 0 {
            if !data.is_empty() && !self.read_shutdown {
                // Post bytes to the upper layer
                self.user.on_read(data);
            }
            self.ack_nr = self.ack_nr.wrapping_add(1);

            // Check if the next packet has been received too, but is waiting
            // in the reorder buffer.
            loop {
                if !self.got_fin_reached && self.got_fin && self.eof_pkt == self.ack_nr {
                    self.got_fin_reached = true;
                    self.rto_timeout = ctx.current_ms + std::cmp::min(self.rto * 3, 60) as u64;
                    self.user.on_eof();

                    // if the other end wants to close, ack
                    self.send_ack(ctx, false);

                    // we have received all packets up to eof_pkt; ignore any
                    // stragglers with higher sequence numbers
                    self.reorder_count = 0;
                }

                if self.reorder_count == 0 {
                    break;
                }

                let Some(p) = self.inbuf.take(wrap16(self.ack_nr) + 1) else {
                    break;
                };
                if !p.is_empty() && !self.read_shutdown {
                    // Pass the bytes to the upper layer
                    self.user.on_read(&p);
                }
                self.ack_nr = self.ack_nr.wrapping_add(1);
                debug_assert!(self.reorder_count > 0);
                self.reorder_count -= 1;
            }

            self.schedule_ack(ctx);
        } else {
            // Getting an out of order packet. It needs to be remembered and
            // reordered later.

            // if we have received a FIN packet, and the EOF-sequence number
            // is lower than the sequence number of this packet, something is
            // wrong
            if self.got_fin && pk_seq_nr > self.eof_pkt {
                return 0;
            }

            // if the sequence number is entirely off the expected one, drop
            // it: we can't allocate buffer space based on untrusted input
            if seqnr > 0x3ff {
                return 0;
            }

            // grow the circle buffer before checking for duplicates so we
            // don't look at an older packet (the indices wrap)
            self.inbuf.ensure_size(wrap16(pk_seq_nr) + 1, seqnr + 1);

            // duplicate? discard
            if self.inbuf.get(wrap16(pk_seq_nr)).is_some() {
                return 0;
            }

            // Insert into the reorder buffer
            self.inbuf.put(wrap16(pk_seq_nr), Some(data.to_vec()));
            self.reorder_count += 1;

            self.schedule_ack(ctx);
        }

        data.len()
    }
}
