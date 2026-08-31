//! Port of libutp's DelayHist: one-way delay history with a drifting base.
//!
//! The two clocks (in the two peers) are assumed not to progress at the exact
//! same rate. They drift, which gives the delay samples a systematic error,
//! so the delay base is periodically re-derived from recent minima, and can
//! be shifted to compensate for observed clock skew in the other direction.

use crate::util::wrapping_compare_less;

pub const CUR_DELAY_SIZE: usize = 3;
// experiments suggest that a clock skew of 10 ms per 325 seconds
// is not impossible. Reset delay_base every 13 minutes. The clock
// skew is dealt with by observing the delay base in the other
// direction, and adjusting our own upwards if the opposite direction
// delay base keeps going down
pub const DELAY_BASE_HISTORY: usize = 13;

const TIMESTAMP_MASK: u32 = 0xffff_ffff;

#[derive(Clone)]
pub struct DelayHist {
    pub delay_base: u32,

    // history of delay samples, normalized by using the delay_base. These
    // values are always greater than 0 and measure the queuing delay in
    // microseconds
    cur_delay_hist: [u32; CUR_DELAY_SIZE],
    cur_delay_idx: usize,

    // history of delay_base. Relative values only.
    delay_base_hist: [u32; DELAY_BASE_HISTORY],
    delay_base_idx: usize,
    // the time when we last stepped the delay_base_idx
    delay_base_time: u64,

    delay_base_initialized: bool,
}

impl DelayHist {
    pub fn new(current_ms: u64) -> Self {
        DelayHist {
            delay_base: 0,
            cur_delay_hist: [0; CUR_DELAY_SIZE],
            cur_delay_idx: 0,
            delay_base_hist: [0; DELAY_BASE_HISTORY],
            delay_base_idx: 0,
            delay_base_time: current_ms,
            delay_base_initialized: false,
        }
    }

    pub fn clear(&mut self, current_ms: u64) {
        *self = DelayHist::new(current_ms);
    }

    /// Increase all base delays by `offset`, used to account for clock skew
    /// observed via the other side's shrinking base delay.
    pub fn shift(&mut self, offset: u32) {
        for v in self.delay_base_hist.iter_mut() {
            *v = v.wrapping_add(offset);
        }
        self.delay_base = self.delay_base.wrapping_add(offset);
    }

    pub fn add_sample(&mut self, sample: u32, current_ms: u64) {
        // The min-operations against the sample below are subject to
        // wrapping, and care needs to be taken to choose the true minimum;
        // all arithmetic that assumes wrapping must be unsigned.
        if !self.delay_base_initialized {
            // no real measurements yet; initialize everything with this
            // sample
            for v in self.delay_base_hist.iter_mut() {
                *v = sample;
            }
            self.delay_base = sample;
            self.delay_base_initialized = true;
        }

        if wrapping_compare_less(
            sample,
            self.delay_base_hist[self.delay_base_idx],
            TIMESTAMP_MASK,
        ) {
            self.delay_base_hist[self.delay_base_idx] = sample;
        }

        if wrapping_compare_less(sample, self.delay_base, TIMESTAMP_MASK) {
            self.delay_base = sample;
        }

        // this operation may wrap, and is supposed to
        let delay = sample.wrapping_sub(self.delay_base);

        self.cur_delay_hist[self.cur_delay_idx] = delay;
        self.cur_delay_idx = (self.cur_delay_idx + 1) % CUR_DELAY_SIZE;

        // once every minute
        if current_ms.wrapping_sub(self.delay_base_time) > 60 * 1000 {
            self.delay_base_time = current_ms;
            self.delay_base_idx = (self.delay_base_idx + 1) % DELAY_BASE_HISTORY;
            // initialize the new slot to the current sample, then pick the
            // lowest delay in the history as the new base
            self.delay_base_hist[self.delay_base_idx] = sample;
            self.delay_base = self.delay_base_hist[0];
            for &v in self.delay_base_hist.iter() {
                if wrapping_compare_less(v, self.delay_base, TIMESTAMP_MASK) {
                    self.delay_base = v;
                }
            }
        }
    }

    /// The lowest of the recent delay samples; u32::MAX if there are no
    /// samples yet.
    pub fn get_value(&self) -> u32 {
        let mut value = u32::MAX;
        for &v in self.cur_delay_hist.iter() {
            value = value.min(v);
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracks_min_queuing_delay() {
        let mut h = DelayHist::new(0);
        h.add_sample(1000, 0);
        h.add_sample(1500, 0);
        h.add_sample(1200, 0);
        // base is 1000, so queuing delays are 0, 500, 200 -> min 0
        assert_eq!(h.get_value(), 0);
        h.add_sample(1300, 0);
        h.add_sample(1400, 0);
        h.add_sample(1250, 0);
        // window of 3 now holds 300, 400, 250
        assert_eq!(h.get_value(), 250);
    }

    #[test]
    fn wrapped_sample_becomes_base() {
        let mut h = DelayHist::new(0);
        h.add_sample(0x0000_0400, 0);
        // sample that wrapped past zero must be considered smaller
        h.add_sample(0xffff_ff00, 0);
        assert_eq!(h.delay_base, 0xffff_ff00);
    }
}
