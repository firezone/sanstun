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
/// The authentication tag appended to a data message.
pub(crate) const AEAD_TAG_SZ: usize = 16;
pub(crate) const DATA_OVERHEAD_SZ: usize = DATA_HEADER_SZ + AEAD_TAG_SZ;

/// A handshake message split into its body and two MACs.
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

/// Boxed to keep [`ReceivedMessage`] cheap to move.
pub(crate) struct InnerHandshakeInitiation {
    pub(crate) sender_idx: u32,
    pub(crate) peer_static_public: PublicKey,
    pub(crate) peer_ephemeral_public: PublicKey,
    /// The Noise chaining key used to build the response.
    pub(crate) chaining_key: Zeroizing<[u8; 32]>,
    pub(crate) hash: [u8; 32],
    pub(crate) timestamp: Tai64N,
}

impl std::fmt::Debug for HandshakeInitiation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeInitiation")
            .field("sender_index", &self.sender_index())
            .field("peer_static_public", &self.peer_static_public())
            .finish_non_exhaustive()
    }
}

impl HandshakeInitiation {
    /// Returns the initiator's static public key for routing to its [`Tunnel`](crate::Tunnel).
    ///
    /// [`Interface::receive`](crate::Interface::receive) verifies that the initiator holds the
    /// matching private key. For peers you have created a tunnel for, it also rejects replays.
    ///
    /// Anyone can generate a key pair, and unknown peers are not checked for replays.
    /// Do not authorize an unknown peer or create a tunnel for it based on this key.
    pub fn peer_static_public(&self) -> PublicKey {
        self.0.peer_static_public
    }

    /// Returns the index the initiator chose for the session this initiation would create.
    ///
    /// Each initiation from a tunnel carries a fresh index. The message is authenticated but not
    /// authorized: see [`HandshakeInitiation::peer_static_public`].
    pub fn sender_index(&self) -> u32 {
        self.0.sender_idx
    }

    /// Returns the initiator's TAI64N timestamp as a single number.
    ///
    /// A later initiation from the same peer has a larger timestamp. The message is authenticated
    /// but not authorized: see [`HandshakeInitiation::peer_static_public`].
    pub fn timestamp(&self) -> u128 {
        self.0.timestamp.to_u128()
    }
}

#[derive(Debug)]
pub struct HandshakeResponse {
    pub(crate) sender_idx: u32,
    pub(crate) receiver_idx: u32,
    pub(crate) unencrypted_ephemeral: [u8; 32],
    pub(crate) encrypted_nothing: [u8; 16],
}

impl HandshakeResponse {
    /// Returns the destination tunnel's [`Tunnel::id`](crate::Tunnel::id).
    pub fn tunnel_id(&self) -> TunnelId {
        Index::from_peer(self.receiver_idx).tunnel_id()
    }
}

#[derive(Debug)]
pub struct CookieReply {
    pub(crate) receiver_idx: u32,
    pub(crate) nonce: [u8; 24],
    pub(crate) encrypted_cookie: [u8; 32],
}

impl CookieReply {
    /// Returns the destination tunnel's [`Tunnel::id`](crate::Tunnel::id).
    pub fn tunnel_id(&self) -> TunnelId {
        Index::from_peer(self.receiver_idx).tunnel_id()
    }
}

#[derive(Debug)]
pub struct TransportData {
    pub(crate) receiver_idx: u32,
    pub(crate) counter: u64,
}

impl TransportData {
    /// Returns the destination tunnel's [`Tunnel::id`](crate::Tunnel::id).
    pub fn tunnel_id(&self) -> TunnelId {
        Index::from_peer(self.receiver_idx).tunnel_id()
    }
}

/// A network message parsed by [`Interface::receive`](crate::Interface::receive).
///
/// Messages can only be obtained through that method and cannot be cloned or constructed directly.
/// Route a handshake initiation to its tunnel by [`HandshakeInitiation::peer_static_public`]
/// and every other message by its `tunnel_id`.
#[derive(Debug)]
pub enum ReceivedMessage {
    HandshakeInitiation(HandshakeInitiation),
    HandshakeResponse(HandshakeResponse),
    CookieReply(CookieReply),
    TransportData(TransportData),
}

/// Bytes to send to the peer as one UDP datagram.
///
/// Datagrams can only be created by sanstun.
///
/// The bytes are heap-allocated to keep [`Received`](crate::Received) and
/// [`Event`](crate::Event) cheap to move.
#[derive(Clone, PartialEq, Eq)]
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

/// An encrypted data message, borrowing its output buffer.
#[derive(Debug)]
pub struct DataMessage<'a>(pub(crate) &'a mut [u8]);

impl Deref for DataMessage<'_> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0
    }
}
