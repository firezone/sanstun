use crate::PublicKey;
use crate::handshake::InitiatorStatic;

use std::ops::Deref;

type MessageType = u32;
pub(crate) const HANDSHAKE_INIT: MessageType = 1;
pub(crate) const HANDSHAKE_RESP: MessageType = 2;
pub(crate) const COOKIE_REPLY: MessageType = 3;
pub(crate) const DATA: MessageType = 4;

pub(crate) const HANDSHAKE_INIT_SZ: usize = 148;
pub(crate) const HANDSHAKE_RESP_SZ: usize = 92;
pub(crate) const COOKIE_REPLY_SZ: usize = 64;
/// The header of a data message: its type, receiver index and counter.
pub(crate) const DATA_HEADER_SZ: usize = 16;
/// The authentication tag of the AEAD sealing a data message.
pub(crate) const AEAD_TAG_SZ: usize = 16;
pub(crate) const DATA_OVERHEAD_SZ: usize = DATA_HEADER_SZ + AEAD_TAG_SZ;

/// The bytes of a handshake message that its MACs cover, and the MACs themselves.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Macs<'a> {
    pub(crate) msg: &'a [u8],
    pub(crate) mac1: &'a [u8],
    pub(crate) mac2: &'a [u8],
}

impl<'a> Macs<'a> {
    pub(crate) fn new(message: &'a [u8]) -> Self {
        let (msg, macs) = message.split_at(message.len() - 32);
        let (mac1, mac2) = macs.split_at(16);

        Self { msg, mac1, mac2 }
    }
}

/// A handshake initiation whose initiator's static public key we decrypted.
pub struct HandshakeInit<'a> {
    pub(crate) sender_idx: u32,
    pub(crate) encrypted_timestamp: &'a [u8],
    pub(crate) initiator: InitiatorStatic,
}

impl std::fmt::Debug for HandshakeInit<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeInit")
            .field("sender_idx", &self.sender_idx)
            .field("peer_static_public", &self.peer_static_public())
            .finish_non_exhaustive()
    }
}

impl HandshakeInit<'_> {
    pub fn sender_idx(&self) -> u32 {
        self.sender_idx
    }

    /// The initiator's static public key, e.g. to look up the [`Tunnel`](crate::Tunnel) it
    /// belongs to.
    pub fn peer_static_public(&self) -> PublicKey {
        self.initiator.peer_static_public
    }
}

#[derive(Debug)]
pub struct HandshakeResponse<'a> {
    pub(crate) sender_idx: u32,
    pub(crate) receiver_idx: u32,
    pub(crate) unencrypted_ephemeral: &'a [u8; 32],
    pub(crate) encrypted_nothing: &'a [u8],
}

impl HandshakeResponse<'_> {
    pub fn sender_idx(&self) -> u32 {
        self.sender_idx
    }

    pub fn receiver_idx(&self) -> u32 {
        self.receiver_idx
    }
}

#[derive(Debug)]
pub struct PacketCookieReply<'a> {
    pub(crate) receiver_idx: u32,
    pub(crate) nonce: &'a [u8],
    pub(crate) encrypted_cookie: &'a [u8],
}

impl PacketCookieReply<'_> {
    pub fn receiver_idx(&self) -> u32 {
        self.receiver_idx
    }
}

#[derive(Debug)]
pub struct PacketData {
    pub(crate) receiver_idx: u32,
    pub(crate) counter: u64,
}

impl PacketData {
    pub fn receiver_idx(&self) -> u32 {
        self.receiver_idx
    }

    pub fn counter(&self) -> u64 {
        self.counter
    }
}

/// A message received from the network.
///
/// It can only be obtained from [`Ingress::receive`](crate::Ingress::receive), which verifies it.
#[derive(Debug)]
pub enum Packet<'a> {
    HandshakeInit(HandshakeInit<'a>),
    HandshakeResponse(HandshakeResponse<'a>),
    PacketCookieReply(PacketCookieReply<'a>),
    PacketData(PacketData),
}

macro_rules! owned_message {
    ($(#[$doc:meta])* $name:ident, $len:expr) => {
        $(#[$doc])*
        #[derive(Debug)]
        pub struct $name(pub(crate) [u8; $len]);

        impl Deref for $name {
            type Target = [u8];

            fn deref(&self) -> &[u8] {
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

/// An encrypted data message to send to the network, in the buffer it was written into.
#[derive(Debug)]
pub struct DataMessage<'a>(pub(crate) &'a mut [u8]);

impl Deref for DataMessage<'_> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0
    }
}
