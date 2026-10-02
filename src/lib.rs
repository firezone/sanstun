//! Simple implementation of the client-side of the WireGuard protocol.

mod errors;
mod handshake;
mod index;
mod rate_limiter;
mod session;
mod timers;

pub use errors::Error;
pub use handshake::{parse_handshake_anon, HalfHandshake};
pub use index::Index;
pub use rate_limiter::RateLimiter;
pub use session::{Opened, PendingDecapsulate, PendingEncapsulate};
pub use x25519_dalek::{PublicKey, StaticSecret};

use crate::handshake::Handshake;
use crate::timers::{TimerName, Timers};

use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};

use std::convert::{TryFrom, TryInto};
use std::net::IpAddr;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The default value to use for rate limiting, when no other rate limiter is defined
const PEER_HANDSHAKE_RATE_LIMIT: u64 = 10;

const IPV4_MIN_HEADER_SIZE: usize = 20;
const IPV4_LEN_OFF: usize = 2;

const IPV6_MIN_HEADER_SIZE: usize = 40;
const IPV6_LEN_OFF: usize = 4;

const IP_LEN_SZ: usize = 2;

/// number of sessions in the ring, better keep a PoT
///
/// We use a `u8` to align with the number of bits reserved in [`Index`] for the sessions.
const N_SESSIONS: u8 = 8;

/// What the caller needs to do after [`Tunnel::decapsulate`].
#[derive(Debug)]
pub enum Decapsulated<'a> {
    /// Nothing to do.
    Done,
    /// Send this datagram to the peer.
    WriteToNetwork(Ciphertext<'a>),
    /// A keepalive is due: send an empty data message, sealed through
    /// [`Tunnel::prepare_encapsulate`].
    KeepaliveDue,
    /// A data message whose decryption is deferred to the [`PendingDecapsulate`].
    Data(PendingDecapsulate),
}

/// What the caller needs to do after [`Tunnel::update_timers`].
#[derive(Debug)]
pub enum TimerAction<'a> {
    /// Send this datagram to the peer.
    WriteToNetwork(Ciphertext<'a>),
    /// A keepalive is due: send an empty data message, sealed through
    /// [`Tunnel::prepare_encapsulate`].
    KeepaliveDue,
}

/// A datagram to send to the network.
#[derive(Debug)]
pub struct Ciphertext<'a>(&'a mut [u8]);

impl<'a> Ciphertext<'a> {
    pub fn into_inner(self) -> &'a mut [u8] {
        self.0
    }
}

impl Deref for Ciphertext<'_> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0
    }
}

impl DerefMut for Ciphertext<'_> {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.0
    }
}

/// A decrypted IP packet to write to the tunnel, at the start of the buffer it was decrypted into.
pub struct Plaintext<B> {
    buffer: B,
    len: usize,
}

impl<B> Plaintext<B> {
    /// Returns the whole buffer; the IP packet is its first `self.len()` bytes.
    pub fn into_inner(self) -> B {
        self.buffer
    }
}

impl<B: AsRef<[u8]>> Deref for Plaintext<B> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.buffer.as_ref()[..self.len]
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> DerefMut for Plaintext<B> {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.buffer.as_mut()[..self.len]
    }
}

impl<B: AsRef<[u8]>> std::fmt::Debug for Plaintext<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Plaintext").field(&&**self).finish()
    }
}

/// Tunnel represents a point-to-point WireGuard connection
pub struct Tunnel {
    /// The handshake currently in progress
    handshake: handshake::Handshake,
    /// The N_SESSIONS most recent sessions, index is session id modulo N_SESSIONS
    sessions: [Option<session::Session>; N_SESSIONS as usize],
    /// Index of most recently used session
    current: Index,
    /// Keeps tabs on the expiring timers
    timers: timers::Timers,
    rate_limiter: Arc<RateLimiter>,
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
        rate_limiter: Option<Arc<RateLimiter>>,
        rng_seed: [u8; 32],
        now: Instant,
        unix_instant: Instant,
        unix: Duration,
    ) -> Self {
        let static_public = PublicKey::from(&static_private);
        let mut rng = StdRng::from_seed(rng_seed);

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
            sessions: Default::default(),
            current: Default::default(),
            timers: Timers::new(persistent_keepalive, rate_limiter.is_none(), now),

            rate_limiter: rate_limiter.unwrap_or_else(|| {
                Arc::new(RateLimiter::new(
                    &static_public,
                    PEER_HANDSHAKE_RATE_LIMIT,
                    rng.random(),
                    now,
                ))
            }),
            rng,
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

    /// Prepares a data message carrying a plaintext of `len` bytes, deferring writing and
    /// encrypting it to the returned [`PendingEncapsulate`].
    ///
    /// All state of the [`Tunnel`] is updated immediately; the caller may run
    /// [`PendingEncapsulate::seal_into`] later and on another thread. Returns
    /// `Err(Error::NoCurrentSession)` when there is no usable session; in that case **no**
    /// handshake is initiated.
    pub fn prepare_encapsulate(
        &mut self,
        len: usize,
        now: Instant,
    ) -> Result<PendingEncapsulate, Error> {
        let seal = self
            .sending_session(now)
            .ok_or(Error::NoCurrentSession)?
            .prepare_packet_data();

        self.timer_tick(TimerName::TimeLastPacketSent, now);
        // Exclude Keepalive packets from timer update.
        if len != 0 {
            self.timer_tick(TimerName::TimeLastDataPacketSent, now);
        }

        Ok(seal)
    }

    /// The session that data messages are sent on, if one is usable.
    fn sending_session(&mut self, now: Instant) -> Option<&mut session::Session> {
        let is_responder = self.timers.is_responder();

        self.sessions[self.current]
            .as_mut()
            .filter(|s| s.should_use_at(now) || is_responder)
    }

    /// Completes the decapsulation of a decrypted data message.
    ///
    /// Marks its counter as received, which rejects a duplicate that passed
    /// [`Tunnel::decapsulate`] before the original got here.
    ///
    /// Returns the IP packet to write to the tunnel interface, or `None` for a keepalive.
    pub fn finish_decapsulate<B: AsRef<[u8]>>(
        &mut self,
        opened: Opened<B>,
        now: Instant,
    ) -> Result<Option<Plaintext<B>>, Error> {
        let Opened {
            receiving_index: remote_idx,
            counter,
            plaintext_len,
            buffer,
            _key: _,
        } = opened;

        let Some(session) = self.sessions[remote_idx]
            .as_mut()
            .filter(|s| s.receiving_index == remote_idx)
        else {
            tracing::trace!(%remote_idx, "Session was replaced during decryption");
            return Err(Error::NoCurrentSession);
        };
        let len = session.finish_receive_packet_data(counter, plaintext_len)?;
        let plaintext = buffer
            .as_ref()
            .get(..len)
            .ok_or(Error::DestinationBufferTooSmall)?;

        self.set_current_session(remote_idx);

        self.timer_tick(TimerName::TimeLastPacketReceived, now);

        let Some(len) = self.validate_decapsulated_packet(plaintext, now)? else {
            return Ok(None);
        };

        Ok(Some(Plaintext { buffer, len }))
    }

    /// Handles a message received from the network.
    ///
    /// Handshake messages and cookie replies are processed right away. The decryption of a data
    /// message is deferred to the returned [`PendingDecapsulate`]: its session is selected and its
    /// counter checked against the replay window, without updating any state or reading the
    /// ciphertext. Hand the [`Opened`] message back to [`Tunnel::finish_decapsulate`] to complete
    /// the decapsulation.
    pub fn decapsulate<'a>(
        &mut self,
        src_addr: Option<IpAddr>,
        packet: Packet<'_>,
        dst: &'a mut [u8],
        now: Instant,
    ) -> Result<Decapsulated<'a>, Error> {
        let mut cookie = [0u8; COOKIE_REPLY_SZ];
        if let Some(cookie) =
            self.rate_limiter
                .verify_packet(src_addr, &packet, &mut cookie, now)?
        {
            dst[..cookie.len()].copy_from_slice(cookie);
            return Ok(Decapsulated::WriteToNetwork(Ciphertext(
                &mut dst[..cookie.len()],
            )));
        }

        self.handle_verified_packet(packet, dst, now)
    }

    pub(crate) fn handle_verified_packet<'a>(
        &mut self,
        packet: Packet,
        dst: &'a mut [u8],
        now: Instant,
    ) -> Result<Decapsulated<'a>, Error> {
        match packet {
            Packet::HandshakeInit(p) => self.handle_handshake_init(p, dst, now),
            Packet::HandshakeResponse(p) => self.handle_handshake_response(p, now),
            Packet::PacketCookieReply(p) => self.handle_cookie_reply(p, now),
            Packet::PacketData(p) => self.handle_data(p).map(Decapsulated::Data),
        }
    }

    fn handle_handshake_init<'a>(
        &mut self,
        p: HandshakeInit,
        dst: &'a mut [u8],
        now: Instant,
    ) -> Result<Decapsulated<'a>, Error> {
        let remote_idx = Index::from_peer(p.sender_idx);

        tracing::debug!(%remote_idx, "Received handshake_initiation",);

        let (packet, session) =
            self.handshake
                .receive_handshake_initialization(p, dst, &mut self.rng, now)?;

        // Store new session in ring buffer
        let local_idx = session.local_index();
        self.sessions[local_idx] = Some(session);

        self.timer_tick(TimerName::TimeLastPacketReceived, now);
        self.timer_tick(TimerName::TimeLastPacketSent, now);
        self.timer_tick_session_established(false, now); // New session established, we are not the initiator

        tracing::debug!(%local_idx, %remote_idx, "Sending handshake_response");

        Ok(Decapsulated::WriteToNetwork(Ciphertext(packet)))
    }

    fn handle_handshake_response<'a>(
        &mut self,
        p: HandshakeResponse,
        now: Instant,
    ) -> Result<Decapsulated<'a>, Error> {
        tracing::debug!(
            local_idx = %Index::from_peer(p.receiver_idx),
            remote_idx = %Index::from_peer(p.sender_idx),
            "Received handshake_response"
        );

        let session = self.handshake.receive_handshake_response(p, now)?;

        // Store new session in ring buffer
        let local_idx = session.local_index();
        self.sessions[local_idx] = Some(session);

        self.timer_tick(TimerName::TimeLastPacketReceived, now);
        self.timer_tick_session_established(true, now); // New session established, we are the initiator
        self.set_current_session(local_idx);

        // The keepalive confirms the session to the responder.
        Ok(Decapsulated::KeepaliveDue)
    }

    fn handle_cookie_reply<'a>(
        &mut self,
        p: PacketCookieReply,
        now: Instant,
    ) -> Result<Decapsulated<'a>, Error> {
        let local_idx = Index::from_peer(p.receiver_idx);

        tracing::debug!(%local_idx, "Received cookie_reply");

        self.handshake.receive_cookie_reply(p, now)?;
        self.timer_tick(TimerName::TimeLastPacketReceived, now);

        tracing::debug!(%local_idx, "Did set cookie");

        Ok(Decapsulated::Done)
    }

    fn handle_data(&self, packet: PacketData) -> Result<PendingDecapsulate, Error> {
        let remote_idx = Index::from_peer(packet.receiver_idx);

        let session = self.sessions[remote_idx].as_ref().ok_or_else(|| {
            tracing::trace!(%remote_idx, "No current session available");
            Error::NoCurrentSession
        })?;

        session.prepare_receive_packet_data(packet)
    }

    /// Update the index of the currently used session, if needed
    fn set_current_session(&mut self, new_idx: Index) {
        let cur_idx = self.current;
        if cur_idx == new_idx {
            // There is nothing to do, already using this session, this is the common case
            return;
        }

        let Some(new) = self.sessions[new_idx].as_ref() else {
            debug_assert!(false, "new session should always exist");
            return;
        };
        if self.sessions[cur_idx]
            .as_ref()
            .is_some_and(|current| current.established_at() > new.established_at())
        {
            // The current session is "newer" than the new one, don't update.
            return;
        }

        self.current = new_idx;
        tracing::debug!(idx = %new_idx, "New session");
    }

    /// Formats a new handshake initiation message and store it in dst. If force_resend is true will send
    /// a new handshake, even if a handshake is already in progress (for example when a handshake times out)
    ///
    /// Returns `Ok(None)` if no handshake initiation needs to be sent.
    pub fn format_handshake_initiation<'a>(
        &mut self,
        dst: &'a mut [u8],
        force_resend: bool,
        now: Instant,
    ) -> Result<Option<Ciphertext<'a>>, Error> {
        if self.handshake.is_in_progress() && !force_resend {
            return Ok(None);
        }

        if self.handshake.is_expired() {
            self.timers.clear(now);
        }

        let starting_new_handshake = !self.handshake.is_in_progress();

        let (packet, local_idx) =
            self.handshake
                .format_handshake_initiation(dst, &mut self.rng, now)?;

        tracing::debug!(%local_idx, "Sending handshake_initiation");

        if starting_new_handshake {
            self.timer_tick(TimerName::TimeLastHandshakeStarted, now);
        }
        self.timer_tick(TimerName::TimeLastPacketSent, now);

        Ok(Some(Ciphertext(packet)))
    }

    /// Check if an IP packet is v4 or v6 and truncate it to the length indicated by its length field
    fn validate_decapsulated_packet(
        &mut self,
        packet: &[u8],
        now: Instant,
    ) -> Result<Option<usize>, Error> {
        let computed_len = match packet.len() {
            0 => return Ok(None), // This is keepalive, and not an error
            _ if packet[0] >> 4 == 4 && packet.len() >= IPV4_MIN_HEADER_SIZE => {
                let len_bytes: [u8; IP_LEN_SZ] = packet[IPV4_LEN_OFF..IPV4_LEN_OFF + IP_LEN_SZ]
                    .try_into()
                    .unwrap();
                u16::from_be_bytes(len_bytes) as usize
            }
            _ if packet[0] >> 4 == 6 && packet.len() >= IPV6_MIN_HEADER_SIZE => {
                let len_bytes: [u8; IP_LEN_SZ] = packet[IPV6_LEN_OFF..IPV6_LEN_OFF + IP_LEN_SZ]
                    .try_into()
                    .unwrap();
                u16::from_be_bytes(len_bytes) as usize + IPV6_MIN_HEADER_SIZE
            }
            _ => return Err(Error::InvalidPacket),
        };

        if computed_len > packet.len() {
            return Err(Error::InvalidPacket);
        }

        self.timer_tick(TimerName::TimeLastDataPacketReceived, now);

        Ok(Some(computed_len))
    }
}
