//! Monotonic clock used by the engine, replacing libutp's
//! UTP_GET_MILLISECONDS / UTP_GET_MICROSECONDS callbacks.
//!
//! Values are only ever used relatively (and the microsecond value is
//! truncated to 32 bits on the wire, where peers likewise only difference
//! it), so the epoch is arbitrary. An offset keeps early values away from 0,
//! which the protocol reserves to mean "no timestamp sample yet".

use std::time::Instant;

#[derive(Clone, Copy)]
pub struct Clock {
    start: Instant,
}

impl Clock {
    pub fn new() -> Self {
        Clock {
            start: Instant::now(),
        }
    }

    pub fn micros(&self) -> u64 {
        1_000_000 + self.start.elapsed().as_micros() as u64
    }

    pub fn millis(&self) -> u64 {
        1_000 + self.start.elapsed().as_millis() as u64
    }
}
