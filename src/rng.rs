use std::convert::Infallible;

use rand::rngs::StdRng;
use rand::{CryptoRng, Rng, SeedableRng, TryCryptoRng, TryRng};
use zeroize::Zeroizing;

/// A [`StdRng`] that rekeys after each use to protect earlier output if its state is exposed.
pub(crate) struct ForwardSecureRng(StdRng);

impl ForwardSecureRng {
    pub(crate) fn new(seed: &mut impl CryptoRng) -> Self {
        Self(StdRng::from_rng(seed))
    }

    pub(crate) fn from_seed(seed: Zeroizing<[u8; 32]>) -> Self {
        Self(StdRng::from_seed(*seed))
    }

    fn rekey(&mut self) {
        self.0 = StdRng::from_rng(&mut self.0);
    }
}

impl TryRng for ForwardSecureRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let value = self.0.next_u32();
        self.rekey();

        Ok(value)
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let value = self.0.next_u64();
        self.rekey();

        Ok(value)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.0.fill_bytes(dst);
        self.rekey();

        Ok(())
    }
}

impl TryCryptoRng for ForwardSecureRng {}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`StdRng`] equality compares the key, stream and position. Matching an earlier generator
    /// at any position would reveal that its key survived the rekey.
    #[test]
    fn state_after_use_does_not_reproduce_earlier_output() {
        let start = || StdRng::from_rng(&mut StdRng::from_seed([1; 32]));
        let mut rng = ForwardSecureRng::new(&mut StdRng::from_seed([1; 32]));

        rng.next_u64();

        for words in 0..64 {
            let mut earlier = start();
            for _ in 0..words {
                earlier.next_u32();
            }

            assert_ne!(
                earlier, rng.0,
                "state is the starting generator after {words} words"
            );
        }
    }
}
