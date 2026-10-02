//! A sans-IO implementation of the WireGuard protocol, acting as both initiator and responder.

mod crypto;
mod errors;
mod handshake;
mod index;
mod message;
mod rate_limiter;
mod replay;
mod session;
mod tai64n;
mod timers;

pub use errors::Error;
pub use handshake::{HalfHandshake, parse_handshake_anon};
pub use index::Index;
pub use message::{
    CookieReplyMessage, HandshakeInitiationMessage, HandshakeResponseMessage, KeepaliveMessage,
};
pub use rate_limiter::{RateLimiter, Verified, VerifiedPacket};
pub use session::{Decrypted, PendingDecapsulate, PendingEncapsulate};
pub use x25519_dalek::{PublicKey, StaticSecret};

use crate::handshake::Handshake;
use crate::session::Sessions;
use crate::timers::{TimerName, Timers};

use rand::SeedableRng;
use rand::rngs::StdRng;

use std::convert::{TryFrom, TryInto};
use std::ops::Deref;
use std::time::{Duration, Instant};

/// What the caller needs to do after [`Tunnel::decapsulate`].
#[derive(Debug)]
pub enum Decapsulated {
    /// Send this handshake response to the peer, which sent a valid handshake initiation.
    HandshakeResponse(HandshakeResponseMessage),
    /// The peer's cookie is stored for the next handshake; nothing to send.
    CookieReceived,
    /// A keepalive is due: send it with [`Tunnel::encapsulate_keepalive`].
    KeepaliveDue(Keepalive),
    /// A data message whose decryption is deferred to the [`PendingDecapsulate`].
    Data(PendingDecapsulate),
}

/// What the caller needs to do after [`Tunnel::update_timers`].
#[derive(Debug)]
pub enum TimerAction {
    /// Send this handshake initiation to the peer.
    HandshakeInitiation(HandshakeInitiationMessage),
    /// A keepalive is due: send it with [`Tunnel::encapsulate_keepalive`].
    KeepaliveDue(Keepalive),
}

/// A keepalive to send with [`Tunnel::encapsulate_keepalive`], e.g. when probing a path.
#[derive(Debug)]
#[must_use = "a keepalive is due; send it with `Tunnel::encapsulate_keepalive`"]
pub struct Keepalive;

/// An encrypted data message to send to the network, in the buffer it was written into.
#[derive(Debug)]
pub struct DataMessage<'a>(&'a mut [u8]);

impl Deref for DataMessage<'_> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0
    }
}

/// What the caller needs to do after [`Tunnel::commit_decrypted`].
#[derive(Debug)]
pub enum Committed<B> {
    /// The first `len` bytes of `buffer` hold the decrypted payload: an IP packet for the tunnel,
    /// possibly followed by padding, which the caller strips when parsing it.
    Data { buffer: B, len: usize },
    /// The data message was a keepalive; nothing to write.
    Keepalive,
}

/// Tunnel represents a point-to-point WireGuard connection
pub struct Tunnel {
    /// The handshake currently in progress
    handshake: handshake::Handshake,
    sessions: Sessions,
    /// Keeps tabs on the expiring timers
    timers: timers::Timers,
    /// Source of the ephemeral keys and the handshake jitter
    rng: StdRng,
}

type MessageType = u32;
const HANDSHAKE_INIT: MessageType = 1;
const HANDSHAKE_RESP: MessageType = 2;
const COOKIE_REPLY: MessageType = 3;
const DATA: MessageType = 4;

const HANDSHAKE_INIT_SZ: usize = 148;
const HANDSHAKE_RESP_SZ: usize = 92;
const COOKIE_REPLY_SZ: usize = 64;
const DATA_OVERHEAD_SZ: usize = 32;

/// The bytes of a handshake message that its MACs cover, and the MACs themselves.
#[derive(Debug, Clone, Copy)]
struct Macs<'a> {
    msg: &'a [u8],
    mac1: &'a [u8],
    mac2: &'a [u8],
}

impl<'a> Macs<'a> {
    fn new(message: &'a [u8]) -> Self {
        let (msg, macs) = message.split_at(message.len() - 32);
        let (mac1, mac2) = macs.split_at(16);

        Self { msg, mac1, mac2 }
    }
}

#[derive(Debug)]
pub struct HandshakeInit<'a> {
    sender_idx: u32,
    unencrypted_ephemeral: &'a [u8; 32],
    encrypted_static: &'a [u8],
    encrypted_timestamp: &'a [u8],
    macs: Macs<'a>,
}

#[derive(Debug)]
pub struct HandshakeResponse<'a> {
    sender_idx: u32,
    pub receiver_idx: u32,
    unencrypted_ephemeral: &'a [u8; 32],
    encrypted_nothing: &'a [u8],
    macs: Macs<'a>,
}

#[derive(Debug)]
pub struct PacketCookieReply<'a> {
    pub receiver_idx: u32,
    nonce: &'a [u8],
    encrypted_cookie: &'a [u8],
}

#[derive(Debug)]
pub struct PacketData {
    pub receiver_idx: u32,
    counter: u64,
}

/// Describes a packet from network
#[derive(Debug)]
pub enum Packet<'a> {
    HandshakeInit(HandshakeInit<'a>),
    HandshakeResponse(HandshakeResponse<'a>),
    PacketCookieReply(PacketCookieReply<'a>),
    PacketData(PacketData),
}

impl<'a> Packet<'a> {
    /// Parses a datagram received from the network.
    #[inline(always)]
    pub fn parse(src: &'a [u8]) -> Result<Self, Error> {
        if src.len() < 4 {
            return Err(Error::InvalidPacket);
        }

        // Checks the type, as well as the reserved zero fields
        let packet_type = u32::from_le_bytes(src[0..4].try_into().unwrap());

        Ok(match (packet_type, src.len()) {
            (HANDSHAKE_INIT, HANDSHAKE_INIT_SZ) => Packet::HandshakeInit(HandshakeInit {
                sender_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                unencrypted_ephemeral: <&[u8; 32] as TryFrom<&[u8]>>::try_from(&src[8..40])
                    .expect("length already checked above"),
                encrypted_static: &src[40..88],
                encrypted_timestamp: &src[88..116],
                macs: Macs::new(src),
            }),
            (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ) => Packet::HandshakeResponse(HandshakeResponse {
                sender_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                receiver_idx: u32::from_le_bytes(src[8..12].try_into().unwrap()),
                unencrypted_ephemeral: <&[u8; 32] as TryFrom<&[u8]>>::try_from(&src[12..44])
                    .expect("length already checked above"),
                encrypted_nothing: &src[44..60],
                macs: Macs::new(src),
            }),
            (COOKIE_REPLY, COOKIE_REPLY_SZ) => Packet::PacketCookieReply(PacketCookieReply {
                receiver_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                nonce: &src[8..32],
                encrypted_cookie: &src[32..64],
            }),
            (DATA, DATA_OVERHEAD_SZ..=usize::MAX) => Packet::PacketData(PacketData {
                receiver_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                counter: u64::from_le_bytes(src[8..16].try_into().unwrap()),
            }),
            _ => return Err(Error::InvalidPacket),
        })
    }
}

impl Tunnel {
    pub fn is_expired(&self) -> bool {
        self.handshake.is_expired()
    }

    /// Create a new tunnel using own private key and the peer public key
    ///
    /// `rng_seed` must come from a cryptographically secure source because key material is derived from it.
    #[expect(clippy::too_many_arguments, reason = "We don't care that much.")]
    pub fn new(
        static_private: StaticSecret,
        peer_static_public: PublicKey,
        preshared_key: Option<StaticSecret>,
        persistent_keepalive: Option<u16>,
        index: Index,
        rng_seed: [u8; 32],
        now: Instant,
        unix_instant: Instant,
        unix: Duration,
    ) -> Self {
        let static_public = PublicKey::from(&static_private);

        Tunnel {
            handshake: Handshake::new(
                static_private,
                static_public,
                peer_static_public,
                index,
                preshared_key,
                unix_instant,
                unix,
            ),
            sessions: Sessions::default(),
            timers: Timers::new(persistent_keepalive, now),
            rng: StdRng::from_seed(rng_seed),
        }
    }

    pub fn remote_static_public(&self) -> PublicKey {
        self.handshake.remote_static_public()
    }

    pub fn preshared_key(&self) -> &StaticSecret {
        self.handshake.preshared_key()
    }

    /// Set the `REKEY_ATTEMPT_TIME`.
    ///
    /// Defaults to 90s.
    pub fn set_rekey_attempt_time(&mut self, rekey_attempt_time: Duration) {
        self.timers.set_rekey_attempt_time(rekey_attempt_time);
    }

    /// Set the `KEEPALIVE_TIMEOUT`.
    ///
    /// Defaults to 10s.
    pub fn set_keepalive_timeout(&mut self, keepalive_timeout: Duration) {
        self.timers.set_keepalive_timeout(keepalive_timeout);
    }

    /// Set the `REKEY_TIMEOUT`, i.e. the interval at which an unanswered
    /// handshake initiation is retried.
    ///
    /// Defaults to 5s.
    pub fn set_rekey_timeout(&mut self, rekey_timeout: Duration) {
        self.timers.set_rekey_timeout(rekey_timeout);
    }

    /// Prepares a data message, deferring writing and encrypting it to the returned
    /// [`PendingEncapsulate`].
    ///
    /// All state of the [`Tunnel`] is updated immediately; the caller may run
    /// [`PendingEncapsulate::encrypt`] later and on another thread. Keepalives are sent with
    /// [`Tunnel::encapsulate_keepalive`] instead. Returns `Err(Error::NoCurrentSession)` when
    /// there is no usable session; in that case **no** handshake is initiated.
    pub fn encapsulate_data(&mut self, now: Instant) -> Result<PendingEncapsulate, Error> {
        let pending = self
            .sending_session(now)
            .ok_or(Error::NoCurrentSession)?
            .prepare_packet_data();
        self.timers.tick(TimerName::TimeLastPacketSent, now);
        self.timers.tick(TimerName::TimeLastDataPacketSent, now);

        Ok(pending)
    }

    /// Encrypts a keepalive on the session that data messages are sent on.
    ///
    /// Returns `Err(Error::NoCurrentSession)` when there is no usable session; in that case **no**
    /// handshake is initiated.
    pub fn encapsulate_keepalive(
        &mut self,
        _keepalive: Keepalive,
        now: Instant,
    ) -> Result<KeepaliveMessage, Error> {
        let mut message = [0u8; DATA_OVERHEAD_SZ];
        self.sending_session(now)
            .ok_or(Error::NoCurrentSession)?
            .prepare_packet_data()
            .encrypt_payload(&[], &mut message)?;
        self.timers.tick(TimerName::TimeLastPacketSent, now);

        Ok(KeepaliveMessage(message))
    }

    /// The session that data messages are sent on, if one is usable.
    fn sending_session(&mut self, now: Instant) -> Option<&mut session::Session> {
        let is_responder = self.timers.is_responder();

        self.sessions
            .current_mut()
            .filter(|s| s.should_use_at(now) || is_responder)
    }

    /// Handles a message received from the network, after it passed [`RateLimiter::verify`].
    ///
    /// Handshake messages and cookie replies are processed right away. The decryption of a data
    /// message is deferred to the returned [`PendingDecapsulate`]: its session is selected and its
    /// counter checked against the replay window, without updating any state or reading the
    /// ciphertext. Hand the [`Decrypted`] message back to [`Tunnel::commit_decrypted`] to complete
    /// the decapsulation.
    pub fn decapsulate(
        &mut self,
        packet: VerifiedPacket<'_>,
        now: Instant,
    ) -> Result<Decapsulated, Error> {
        match packet.0 {
            Packet::HandshakeInit(p) => self.handle_handshake_init(p, now),
            Packet::HandshakeResponse(p) => self.handle_handshake_response(p, now),
            Packet::PacketCookieReply(p) => self.handle_cookie_reply(p, now),
            Packet::PacketData(p) => self.handle_data(p).map(Decapsulated::Data),
        }
    }

    /// Completes the decapsulation of a decrypted data message.
    ///
    /// Marks its counter as received, which rejects a duplicate that passed
    /// [`Tunnel::decapsulate`] before the original got here.
    pub fn commit_decrypted<B: AsRef<[u8]>>(
        &mut self,
        decrypted: Decrypted<B>,
        now: Instant,
    ) -> Result<Committed<B>, Error> {
        let Decrypted {
            receiving_index: remote_idx,
            counter,
            plaintext_len,
            buffer,
            _key: _,
        } = decrypted;

        let Some(session) = self.sessions.get_mut(remote_idx) else {
            tracing::trace!(%remote_idx, "Session was replaced during decryption");
            return Err(Error::NoCurrentSession);
        };
        let len = session.finish_receive_packet_data(counter, plaintext_len)?;

        self.sessions.set_current(remote_idx);
        self.timers.tick(TimerName::TimeLastPacketReceived, now);

        if len == 0 {
            return Ok(Committed::Keepalive);
        }
        self.timers.tick(TimerName::TimeLastDataPacketReceived, now);

        Ok(Committed::Data { buffer, len })
    }

    fn handle_handshake_init(
        &mut self,
        p: HandshakeInit,
        now: Instant,
    ) -> Result<Decapsulated, Error> {
        let remote_idx = Index::from_peer(p.sender_idx);

        tracing::debug!(%remote_idx, "Received handshake_initiation",);

        let (packet, session) =
            self.handshake
                .receive_handshake_initialization(p, &mut self.rng, now)?;

        // Store new session in ring buffer
        let local_idx = self.sessions.insert(session);

        self.timers.tick(TimerName::TimeLastPacketReceived, now);
        self.timers.tick(TimerName::TimeLastPacketSent, now);
        self.timers.session_established(false, now); // New session established, we are not the initiator

        tracing::debug!(%local_idx, %remote_idx, "Sending handshake_response");

        Ok(Decapsulated::HandshakeResponse(HandshakeResponseMessage(
            packet,
        )))
    }

    fn handle_handshake_response(
        &mut self,
        p: HandshakeResponse,
        now: Instant,
    ) -> Result<Decapsulated, Error> {
        tracing::debug!(
            local_idx = %Index::from_peer(p.receiver_idx),
            remote_idx = %Index::from_peer(p.sender_idx),
            "Received handshake_response"
        );

        let session = self.handshake.receive_handshake_response(p, now)?;

        // Store new session in ring buffer
        let local_idx = self.sessions.insert(session);

        self.timers.tick(TimerName::TimeLastPacketReceived, now);
        self.timers.session_established(true, now); // New session established, we are the initiator
        self.sessions.set_current(local_idx);

        // The keepalive confirms the session to the responder.
        Ok(Decapsulated::KeepaliveDue(Keepalive))
    }

    fn handle_cookie_reply(
        &mut self,
        p: PacketCookieReply,
        now: Instant,
    ) -> Result<Decapsulated, Error> {
        let local_idx = Index::from_peer(p.receiver_idx);

        tracing::debug!(%local_idx, "Received cookie_reply");

        self.handshake.receive_cookie_reply(p, now)?;
        self.timers.tick(TimerName::TimeLastPacketReceived, now);

        tracing::debug!(%local_idx, "Did set cookie");

        Ok(Decapsulated::CookieReceived)
    }

    fn handle_data(&self, packet: PacketData) -> Result<PendingDecapsulate, Error> {
        let remote_idx = Index::from_peer(packet.receiver_idx);

        let session = self.sessions.in_slot_of(remote_idx).ok_or_else(|| {
            tracing::trace!(%remote_idx, "No current session available");
            Error::NoCurrentSession
        })?;

        session.prepare_receive_packet_data(packet)
    }

    /// Formats a new handshake initiation message. If force_resend is true will send
    /// a new handshake, even if a handshake is already in progress (for example when a handshake times out)
    ///
    /// Returns `None` if no handshake initiation needs to be sent.
    pub fn format_handshake_initiation(
        &mut self,
        force_resend: bool,
        now: Instant,
    ) -> Option<HandshakeInitiationMessage> {
        if self.handshake.is_in_progress() && !force_resend {
            return None;
        }

        if self.handshake.is_expired() {
            self.timers.clear(now);
        }

        let starting_new_handshake = !self.handshake.is_in_progress();

        let (packet, local_idx) = self
            .handshake
            .format_handshake_initiation(&mut self.rng, now);

        tracing::debug!(%local_idx, "Sending handshake_initiation");

        if starting_new_handshake {
            self.timers.tick(TimerName::TimeLastHandshakeStarted, now);
        }
        self.timers.tick(TimerName::TimeLastPacketSent, now);

        Some(HandshakeInitiationMessage(packet))
    }
}
