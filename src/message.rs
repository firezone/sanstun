use crate::PublicKey;
use crate::handshake::ResponderState;
use crate::index::Index;

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

/// An authenticated handshake initiation, ready to be answered by its [`Tunnel`](crate::Tunnel).
pub struct HandshakeInit {
    pub(crate) sender_idx: u32,
    pub(crate) initiation: ResponderState,
}

impl std::fmt::Debug for HandshakeInit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeInit")
            .field("sender_idx", &self.sender_idx)
            .field("peer_static_public", &self.peer_static_public())
            .finish_non_exhaustive()
    }
}

impl HandshakeInit {
    pub fn sender_idx(&self) -> u32 {
        self.sender_idx
    }

    /// The initiator's static public key, to look up the [`Tunnel`](crate::Tunnel) it belongs to.
    ///
    /// [`Interface::receive`](crate::Interface::receive) has authenticated it: the initiator
    /// holds the matching private key. For a key we created a tunnel for, the initiation is also
    /// newer than any accepted before, so it is not a replay.
    ///
    /// Anyone can generate a key pair, and replays are not detected for keys we have no tunnel
    /// for. Do not authorize anything or allocate state such as a new [`Tunnel`](crate::Tunnel)
    /// for a key you do not already know.
    pub fn peer_static_public(&self) -> PublicKey {
        self.initiation.peer_static_public
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
    pub(crate) nonce: &'a [u8; 24],
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
/// It can only be obtained from [`Interface::receive`](crate::Interface::receive), which verifies it.
#[derive(Debug)]
pub enum Packet<'a> {
    HandshakeInit(HandshakeInit),
    HandshakeResponse(HandshakeResponse<'a>),
    PacketCookieReply(PacketCookieReply<'a>),
    PacketData(PacketData),
}

impl Packet<'_> {
    /// The [`Tunnel::id`](crate::Tunnel::id) of the tunnel this message is addressed to.
    ///
    /// `None` for a handshake initiation, which is routed by [`HandshakeInit::peer_static_public`] instead.
    pub fn tunnel_id(&self) -> Option<u32> {
        let receiver_idx = match self {
            Packet::HandshakeInit(_) => return None,
            Packet::HandshakeResponse(p) => p.receiver_idx,
            Packet::PacketCookieReply(p) => p.receiver_idx,
            Packet::PacketData(p) => p.receiver_idx,
        };

        Some(Index::from_peer(receiver_idx).global())
    }
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
