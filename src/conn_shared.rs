//! Per-connection state shared between the protocol engine and the public
//! [`crate::Conn`] handle. This is the Rust equivalent of go-libutp's `Conn`
//! struct fed by the libutp callbacks (on_read, on_state_change, on_error).
//!
//! Locking: `cell` is only ever locked while the owning socket's big mutex is
//! held (engine side) or with no other lock held (fast-path checks in `Drop`).
//! `cond` is always paired with the big mutex, never with `cell`.

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::Duration;

pub struct ConnShared {
    pub cell: Mutex<ConnCell>,
    /// Signalled on any state change relevant to a blocked reader/writer/
    /// connector. Waited on with the socket-wide mutex.
    pub cond: Condvar,
}

pub struct ConnCell {
    pub read_buf: VecDeque<u8>,
    pub got_eof: bool,
    pub got_connect: bool,
    /// Set on UTP_STATE_DESTROYING. The engine-side socket no longer exists.
    pub destroyed: bool,
    /// Conn::close was called (or the handle dropped).
    pub closed: bool,
    pub error: Option<io::ErrorKind>,
    pub read_timeout: Option<Duration>,
    pub write_timeout: Option<Duration>,
    pub remote_addr: SocketAddr,
}

impl ConnShared {
    pub fn new(remote_addr: SocketAddr) -> Self {
        ConnShared {
            cell: Mutex::new(ConnCell {
                read_buf: VecDeque::new(),
                got_eof: false,
                got_connect: false,
                destroyed: false,
                closed: false,
                error: None,
                read_timeout: None,
                write_timeout: None,
                remote_addr,
            }),
            cond: Condvar::new(),
        }
    }

    pub fn lock(&self) -> MutexGuard<'_, ConnCell> {
        self.cell.lock().unwrap()
    }

    // The "callbacks". All called by the engine with the big lock held.

    pub fn on_read(&self, data: &[u8]) {
        debug_assert!(!data.is_empty());
        self.lock().read_buf.extend(data);
        self.cond.notify_all();
    }

    pub fn read_buffer_len(&self) -> usize {
        self.lock().read_buf.len()
    }

    pub fn on_writable(&self) {
        self.cond.notify_all();
    }

    pub fn on_connect(&self) {
        self.lock().got_connect = true;
        self.cond.notify_all();
    }

    pub fn on_eof(&self) {
        self.lock().got_eof = true;
        self.cond.notify_all();
    }

    pub fn on_error(&self, kind: io::ErrorKind) {
        let mut c = self.lock();
        if c.error.is_none() {
            c.error = Some(kind);
        }
        drop(c);
        self.cond.notify_all();
    }

    pub fn on_destroying(&self) {
        self.lock().destroyed = true;
        self.cond.notify_all();
    }
}
