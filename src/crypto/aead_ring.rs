use crate::errors::Error;
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};

/// A ChaCha20-Poly1305 key backed by `ring`.
pub(crate) struct AeadKey(LessSafeKey);

impl AeadKey {
    #[inline]
    pub(crate) fn new(key: &[u8; 32]) -> Self {
        Self(LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, key).expect("key has 32 bytes"),
        ))
    }

    /// Encrypts `in_out` in place and returns the authentication tag.
    ///
    /// Panics if `in_out` exceeds the AEAD's length limit of about 256 GiB, which WireGuard
    /// messages never approach.
    #[inline]
    pub(crate) fn seal_in_place_separate_tag(
        &self,
        nonce: [u8; 12],
        aad: &[u8],
        in_out: &mut [u8],
    ) -> [u8; 16] {
        let tag = self
            .0
            .seal_in_place_separate_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad), in_out)
            .expect("messages are always within the AEAD's length limit");

        tag.as_ref().try_into().expect("tag has 16 bytes")
    }

    /// Authenticates and decrypts `in_out`, the ciphertext followed by its tag, and returns the
    /// plaintext at its start.
    #[inline]
    pub(crate) fn open_in_place<'a>(
        &self,
        nonce: [u8; 12],
        aad: &[u8],
        in_out: &'a mut [u8],
    ) -> Result<&'a mut [u8], Error> {
        self.0
            .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(aad), in_out)
            .map_err(|_| Error::InvalidAeadTag)
    }
}
