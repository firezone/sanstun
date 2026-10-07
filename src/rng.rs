use std::convert::Infallible;

use rand::rngs::StdRng;
use rand::{CryptoRng, Rng, SeedableRng, TryCryptoRng, TryRng};

/// A [`StdRng`] that re-keys itself from its own output after every use (fast key erasure), so a
/// copy of its state cannot reproduce anything it generated before.
pub(crate) struct ForwardSecureRng(pub(crate) StdRng);

impl ForwardSecureRng {
    pub(crate) fn new(seed: &mut impl CryptoRng) -> Self {
        Self(StdRng::from_rng(seed))
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
