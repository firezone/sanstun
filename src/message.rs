use crate::PublicKey;
use crate::index::{Index, TunnelId};
use crate::tai64n::Tai64N;

use std::ops::Deref;

use zeroize::Zeroizing;

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
pub struct HandshakeInitiation(pub(crate) Box<InnerHandshakeInitiation>);

/// Boxed in [`HandshakeInitiation`], so that a [`ReceivedMessage`] stays cheap to move.
pub(crate) struct InnerHandshakeInitiation {
    pub(crate) sender_idx: u32,
    pub(crate) peer_static_public: PublicKey,
    pub(crate) peer_ephemeral_public: PublicKey,
    /// The responder's Noise state after the initiation, from which it builds its response.
    pub(crate) chaining_key: Zeroizing<[u8; 32]>,
    pub(crate) hash: [u8; 32],
    pub(crate) timestamp: Tai64N,
}

impl std::fmt::Debug for HandshakeInitiation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeInitiation")
            .field("sender_idx", &self.sender_idx())
            .field("peer_static_public", &self.peer_static_public())
            .finish_non_exhaustive()
    }
}

impl HandshakeInitiation {
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
        self.0.peer_static_public
    }

    pub(crate) fn sender_idx(&self) -> u32 {
        self.0.sender_idx
    }

    pub(crate) fn timestamp(&self) -> Tai64N {
        self.0.timestamp
    }
}

#[derive(Debug)]
pub struct HandshakeResponse {
    pub(crate) sender_idx: u32,
    pub(crate) receiver_idx: u32,
    pub(crate) unencrypted_ephemeral: [u8; 32],
    pub(crate) encrypted_nothing: [u8; 16],
}

#[derive(Debug)]
pub struct CookieReply {
    pub(crate) receiver_idx: u32,
    pub(crate) nonce: [u8; 24],
    pub(crate) encrypted_cookie: [u8; 32],
}

#[derive(Debug)]
pub struct TransportData {
    pub(crate) receiver_idx: u32,
    pub(crate) counter: u64,
}

/// A message received from the network.
///
/// It can only be obtained from [`Interface::receive`](crate::Interface::receive), which verifies it.
/// Neither it nor the messages it carries can be constructed or duplicated otherwise:
///
/// ```compile_fail
/// let _ = sanstun::HandshakeInitiation {
///     sender_idx: 0,
///     peer_static_public: todo!(),
///     peer_ephemeral_public: todo!(),
///     chaining_key: todo!(),
///     hash: [0; 32],
///     timestamp: todo!(),
/// };
/// ```
///
/// ```compile_fail
/// let _ = sanstun::HandshakeResponse {
///     sender_idx: 0,
///     receiver_idx: 0,
///     unencrypted_ephemeral: [0; 32],
///     encrypted_nothing: [0; 16],
/// };
/// ```
///
/// ```compile_fail
/// let _ = sanstun::CookieReply {
///     receiver_idx: 0,
///     nonce: [0; 24],
///     encrypted_cookie: [0; 32],
/// };
/// ```
///
/// ```compile_fail
/// let _ = sanstun::TransportData {
///     receiver_idx: 0,
///     counter: 0,
/// };
/// ```
///
/// ```compile_fail
/// fn duplicate(
///     message: sanstun::ReceivedMessage,
/// ) -> (sanstun::ReceivedMessage, sanstun::ReceivedMessage) {
///     (message.clone(), message)
/// }
/// ```
#[derive(Debug)]
pub enum ReceivedMessage {
    HandshakeInitiation(HandshakeInitiation),
    HandshakeResponse(HandshakeResponse),
    CookieReply(CookieReply),
    TransportData(TransportData),
}

impl ReceivedMessage {
    /// The [`Tunnel::id`](crate::Tunnel::id) of the tunnel this message is addressed to.
    ///
    /// `None` for a handshake initiation, which is routed by [`HandshakeInitiation::peer_static_public`] instead.
    pub fn tunnel_id(&self) -> Option<TunnelId> {
        let receiver_idx = match self {
            ReceivedMessage::HandshakeInitiation(_) => return None,
            ReceivedMessage::HandshakeResponse(p) => p.receiver_idx,
            ReceivedMessage::CookieReply(p) => p.receiver_idx,
            ReceivedMessage::TransportData(p) => p.receiver_idx,
        };

        Some(Index::from_peer(receiver_idx).tunnel_id())
    }
}

/// Bytes to send to the peer as one UDP datagram.
///
/// Only sanstun produces it:
///
/// ```compile_fail
/// let _ = sanstun::Datagram(Box::new([0; 148]));
/// ```
///
/// ```compile_fail
/// let _ = sanstun::Datagram::new([0; 148]);
/// ```
///
/// Its bytes are on the heap, so that the [`Received`](crate::Received) and
/// [`Event`](crate::Event) carrying it stay cheap to move.
pub struct Datagram(Box<[u8]>);

impl Datagram {
    pub(crate) fn new<const N: usize>(bytes: [u8; N]) -> Self {
        const { assert!(N <= HANDSHAKE_INIT_SZ) };

        Self(Box::new(bytes))
    }
}

impl Deref for Datagram {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Datagram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Datagram").field(&&**self).finish()
    }
}

/// An encrypted data message to send to the network, in the buffer it was written into.
#[derive(Debug)]
pub struct DataMessage<'a>(pub(crate) &'a mut [u8]);

impl Deref for DataMessage<'_> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0
    }
}
