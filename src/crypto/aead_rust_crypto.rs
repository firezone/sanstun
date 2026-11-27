use crate::errors::Error;
use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, Tag};

/// A ChaCha20-Poly1305 key backed by the pure-Rust `chacha20poly1305` crate.
pub(crate) struct AeadKey(ChaCha20Poly1305);

impl AeadKey {
    #[inline]
    pub(crate) fn new(key: &[u8; 32]) -> Self {
        Self(ChaCha20Poly1305::new(key.into()))
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
        self.0
            .encrypt_inout_detached(&Nonce::from(nonce), aad, in_out.into())
            .expect("messages are always within the AEAD's length limit")
            .into()
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
        let plaintext_len = in_out.len().checked_sub(16).ok_or(Error::InvalidAeadTag)?;
        let (plaintext, tag) = in_out.split_at_mut(plaintext_len);
        let tag = Tag::from(<[u8; 16]>::try_from(&*tag).expect("tag has 16 bytes"));

        self.0
            .decrypt_inout_detached(&Nonce::from(nonce), aad, (&mut *plaintext).into(), &tag)
            .map_err(|_| Error::InvalidAeadTag)?;

        Ok(plaintext)
    }
}
