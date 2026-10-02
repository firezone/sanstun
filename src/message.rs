use crate::{COOKIE_REPLY_SZ, DATA_OVERHEAD_SZ, HANDSHAKE_INIT_SZ, HANDSHAKE_RESP_SZ};

use std::ops::Deref;

macro_rules! owned_message {
    ($(#[$doc:meta])* $name:ident, $len:expr) => {
        $(#[$doc])*
        #[derive(Debug, Clone)]
        pub struct $name(pub(crate) [u8; $len]);

        impl $name {
            pub fn into_inner(self) -> [u8; $len] {
                self.0
            }
        }

        impl Deref for $name {
            type Target = [u8];

            fn deref(&self) -> &[u8] {
                &self.0
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }
    };
}

owned_message!(
    /// A handshake initiation to send to the network.
    HandshakeInitiationMessage,
    HANDSHAKE_INIT_SZ
);
owned_message!(
    /// A handshake response to send to the network.
    HandshakeResponseMessage,
    HANDSHAKE_RESP_SZ
);
owned_message!(
    /// A cookie reply to send to the network.
    CookieReplyMessage,
    COOKIE_REPLY_SZ
);
owned_message!(
    /// A keepalive, i.e. an encrypted empty data message, to send to the network.
    KeepaliveMessage,
    DATA_OVERHEAD_SZ
);
