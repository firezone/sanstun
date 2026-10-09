use std::fmt;

/// An X25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub(crate) fn to_dalek(self) -> x25519_dalek::PublicKey {
        x25519_dalek::PublicKey::from(self.0)
    }
}

impl From<[u8; 32]> for PublicKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<&StaticSecret> for PublicKey {
    fn from(secret: &StaticSecret) -> Self {
        Self(x25519_dalek::PublicKey::from(&secret.0).to_bytes())
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PublicKey(")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

/// An X25519 static private key, zeroized on drop.
#[derive(Clone)]
pub struct StaticSecret(x25519_dalek::StaticSecret);

impl StaticSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub(crate) fn as_dalek(&self) -> &x25519_dalek::StaticSecret {
        &self.0
    }
}

impl From<[u8; 32]> for StaticSecret {
    fn from(bytes: [u8; 32]) -> Self {
        Self(x25519_dalek::StaticSecret::from(bytes))
    }
}

impl fmt::Debug for StaticSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StaticSecret(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_only_the_secret() {
        let secret = StaticSecret::from([0xab; 32]);

        assert_eq!(format!("{secret:?}"), "StaticSecret(..)");
        assert_eq!(
            format!("{:?}", PublicKey::from([0xab; 32])),
            format!("PublicKey({})", "ab".repeat(32))
        );
    }
}
