//! Small helpers shared by the engine: wrapping sequence-number comparison and
//! a self-seeding PRNG (stand-in for libutp's UTP_GET_RANDOM callback).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Compare if `lhs` is less than `rhs`, taking wrapping into account. If `lhs`
/// is close to the mask and `rhs` is close to 0, `lhs` is assumed to have
/// wrapped and considered smaller.
pub fn wrapping_compare_less(lhs: u32, rhs: u32, mask: u32) -> bool {
    // distance walking from lhs to rhs, downwards
    let dist_down = lhs.wrapping_sub(rhs) & mask;
    // distance walking from lhs to rhs, upwards
    let dist_up = rhs.wrapping_sub(lhs) & mask;
    // if the distance walking up is shorter, lhs is less than rhs. If the
    // distance walking down is shorter, then rhs is less than lhs.
    dist_up < dist_down
}

/// SplitMix64-based PRNG. Not cryptographic; libutp used libc rand() here.
/// Only feeds connection seeds (16 bits on the wire) and initial sequence
/// numbers.
pub struct Rng(u64);

impl Rng {
    pub fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let n = COUNTER.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed);
        Rng(nanos ^ n.wrapping_mul(0xbf58_476d_1ce4_e5b9) ^ 0x2545_f491_4f6c_dd1d)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapping_compare() {
        const M16: u32 = 0xffff;
        assert!(wrapping_compare_less(1, 2, M16));
        assert!(!wrapping_compare_less(2, 1, M16));
        assert!(!wrapping_compare_less(2, 2, M16));
        // 0xffff wrapped, considered smaller than 5
        assert!(wrapping_compare_less(0xffff, 5, M16));
        assert!(!wrapping_compare_less(5, 0xffff, M16));
        const M32: u32 = 0xffff_ffff;
        assert!(wrapping_compare_less(0xffff_ff00, 0x0000_0400, M32));
    }

    #[test]
    fn rng_varies() {
        let mut a = Rng::new();
        let x = a.next_u64();
        let y = a.next_u64();
        assert_ne!(x, y);
    }
}
