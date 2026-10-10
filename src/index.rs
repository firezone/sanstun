use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Weak};

use rand::rngs::StdRng;
use rand::{CryptoRng, RngExt, SeedableRng};

/// Identifies a [`Tunnel`](crate::Tunnel) among those of its [`Interface`](crate::Interface).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TunnelId(u32);

/// Identifies a session of a [`Tunnel`](super::Tunnel).
///
/// The top 24 bits identify the tunnel.
/// The lower 8 bits are used as a rotating session index with a given peer.
///
/// This allows for ~16M unique peers and 256 sessions per peer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub(crate) struct Index(u32);

impl Index {
    pub(crate) fn new_local(idx: u32) -> Self {
        assert_eq!(idx >> 24, 0, "Must be at most a 24-bit number");

        Self(idx << 8)
    }

    pub(crate) fn from_peer(peer: u32) -> Self {
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

    /// The part of the index that identifies the tunnel.
    pub(crate) fn global(&self) -> u32 {
        self.0 >> 8
    }

    pub(crate) fn tunnel_id(&self) -> TunnelId {
        TunnelId(self.global())
    }

    /// The rotating session part of the index.
    pub(crate) fn session(&self) -> usize {
        self.0 as u8 as usize
    }
}

/// Hands out random indices for new tunnels, skipping those of tunnels that are still alive.
pub(crate) struct TunnelIndices {
    rng: StdRng,
    in_use: HashMap<u32, Weak<()>>,
}

impl TunnelIndices {
    pub(crate) fn new(rng: &mut impl CryptoRng) -> Self {
        TunnelIndices {
            rng: StdRng::from_rng(rng),
            in_use: HashMap::new(),
        }
    }

    /// The index of a new tunnel, which stays reserved until the returned lease is dropped.
    pub(crate) fn next(&mut self) -> (Index, Arc<()>) {
        if self.in_use.len() == self.in_use.capacity() {
            for _ in self
                .in_use
                .extract_if(|_, tunnel| tunnel.strong_count() == 0)
            {}
        }

        loop {
            let index = Index::new_local(self.rng.random::<u32>() & 0xff_ffff);

            if self
                .in_use
                .get(&index.global())
                .is_some_and(|tunnel| tunnel.strong_count() > 0)
            {
                continue;
            }

            let lease = Arc::new(());
            self.in_use.insert(index.global(), Arc::downgrade(&lease));

            return (index, lease);
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
    fn tunnel_indices_skip_live_tunnels_and_reuse_dropped_ones() {
        use rand::SeedableRng as _;

        let fresh = || TunnelIndices::new(&mut StdRng::from_seed([1; 32]));
        let mut indices = fresh();
        let (taken, lease) = indices.next();

        indices.rng = fresh().rng;
        assert_ne!(indices.next().0, taken);

        drop(lease);
        indices.rng = fresh().rng;
        assert_eq!(indices.next().0, taken);
    }

    #[test]
    fn next_tunnel_index_cannot_be_predicted_from_previous_ones() {
        use rand::SeedableRng as _;

        let mut indices = TunnelIndices::new(&mut StdRng::from_seed([1; 32]));
        let [o0, o1, o2, o3] = std::array::from_fn(|_| indices.next().0.global());

        let predictions = predict_next_global_index([o0, o1, o2]);

        assert_ne!(
            predictions,
            [o3],
            "an observer of three tunnel indices predicted the fourth"
        );
    }

    /// What an observer of three consecutive tunnel indices on the wire predicts the next one to
    /// be, knowing only the public LFSR polynomial.
    ///
    /// Each index is `(state - 1) ^ mask`, so every guess of the 24-bit mask determines the
    /// LFSR states, and only the guesses consistent with the LFSR's steps survive.
    fn predict_next_global_index(observed: [u32; 3]) -> Vec<u32> {
        const POLY: u32 = 0xd80000;
        let step = |s: u32| (s >> 1) ^ (0u32.wrapping_sub(s & 1) & POLY);

        let mut predictions = Vec::new();

        for mask in 0..1 << 24 {
            let [s0, s1, s2] = observed.map(|o| (o ^ mask) + 1);

            if step(s0) == s1 && step(s1) == s2 {
                predictions.push((step(s2) - 1) ^ mask);
            }
        }

        predictions.sort_unstable();
        predictions.dedup();
        predictions
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
