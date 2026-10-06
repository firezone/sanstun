use std::fmt;

use rand::RngExt;
use rand::rngs::StdRng;

/// A unique identifier for an instance of [`Tunnel`](super::Tunnel).
///
/// The top 24 bits are used as a unique, global identifier.
/// The lower 8 bits are used as a rotating session index with a given peer.
///
/// This allows for ~16M unique peers and 256 sessions per peer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Index(u32);

impl Index {
    pub(crate) fn new_local(idx: u32) -> Self {
        assert_eq!(idx >> 24, 0, "Must be at most a 24-bit number");

        Self(idx << 8)
    }

    pub fn from_peer(peer: u32) -> Self {
        Self(peer)
    }

    pub(crate) fn wrapping_increment(&mut self) -> Index {
        let index = self.0;
        let idx8 = index as u8;
        self.0 = (index & !0xff) | u32::from(idx8.wrapping_add(1));

        Self(self.0)
    }

    pub(crate) fn to_le_bytes(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }

    pub fn global(&self) -> usize {
        (self.0 >> 8) as usize
    }

    /// The rotating session part of the index.
    pub(crate) fn session(&self) -> usize {
        self.0 as u8 as usize
    }
}

/// Hands out the global part of local indices in a pseudorandom order, so that they reveal
/// neither how many tunnels exist nor which index comes next.
///
/// A linear-feedback shift register visits every non-zero 24-bit value once before repeating, so
/// indices only repeat after 2^24 - 1 tunnels.
pub(crate) struct IndexLfsr {
    lfsr: u32,
    mask: u32,
}

impl IndexLfsr {
    pub(crate) fn new(rng: &mut StdRng) -> Self {
        IndexLfsr {
            lfsr: random_index(rng),
            mask: random_index(rng),
        }
    }

    pub(crate) fn next(&mut self) -> Index {
        const LFSR_POLY: u32 = 0xd80000;

        let value = self.lfsr - 1;
        self.lfsr = (self.lfsr >> 1) ^ (0u32.wrapping_sub(self.lfsr & 1) & LFSR_POLY);

        Index::new_local(value ^ self.mask)
    }
}

/// A random, non-zero 24-bit number.
fn random_index(rng: &mut StdRng) -> u32 {
    loop {
        let i = rng.random::<u32>() & 0xff_ffff;
        if i != 0 {
            return i;
        }
    }
}

impl fmt::Display for Index {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let idx = self.0;

        let global = idx >> 8;
        let session = idx as u8;

        write!(f, "({global}|{session})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lfsr_visits_every_global_index_once() {
        use rand::SeedableRng as _;

        let mut lfsr = IndexLfsr::new(&mut StdRng::from_seed([1; 32]));
        let mut seen = vec![false; 1 << 24];

        for _ in 0..(1 << 24) - 1 {
            let global = lfsr.next().global();
            assert!(!seen[global], "{global} handed out twice");
            seen[global] = true;
        }
    }

    #[test]
    fn incrementing_never_changes_global_part() {
        let mut index = Index::new_local(0xab_cdef);

        let global = index.global();

        for _ in 0..23745 {
            index.wrapping_increment();

            assert_eq!(index.global(), global);
        }
    }

    #[test]
    fn incrementing_changes_session_index() {
        let mut index = Index::new_local(0xab_cdef);

        for i in 0..256 {
            assert_eq!(index.session(), i);

            index.wrapping_increment();
        }

        // Cycling through it again starts on 0
        for i in 0..256 {
            assert_eq!(index.session(), i);

            index.wrapping_increment();
        }
    }
}
