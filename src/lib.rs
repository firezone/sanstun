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

#[derive(Debug)]
pub enum TunnelResult<'a> {
    Done,
    WriteToNetwork(Ciphertext<'a>),
    WriteToTunnel(Plaintext<'a>),
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

/// A decrypted IP packet to write to the tunnel.
#[derive(Debug)]
pub struct Plaintext<'a>(&'a mut [u8]);

impl<'a> Plaintext<'a> {
    pub fn into_inner(self) -> &'a mut [u8] {
        self.0
    }
}

impl Deref for Plaintext<'_> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0
    }
}

impl DerefMut for Plaintext<'_> {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.0
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

#[derive(Debug)]
pub struct HandshakeInit<'a> {
    sender_idx: u32,
    unencrypted_ephemeral: &'a [u8; 32],
    encrypted_static: &'a [u8],
    encrypted_timestamp: &'a [u8],
}

#[derive(Debug)]
pub struct HandshakeResponse<'a> {
    sender_idx: u32,
    pub receiver_idx: u32,
    unencrypted_ephemeral: &'a [u8; 32],
    encrypted_nothing: &'a [u8],
}

#[derive(Debug)]
pub struct PacketCookieReply<'a> {
    pub receiver_idx: u32,
    nonce: &'a [u8],
    encrypted_cookie: &'a [u8],
}

#[derive(Debug)]
pub struct PacketData<'a> {
    pub receiver_idx: u32,
    counter: u64,
    encrypted_encapsulated_packet: &'a [u8],
}

/// Describes a packet from network
#[derive(Debug)]
pub enum Packet<'a> {
    HandshakeInit(HandshakeInit<'a>),
    HandshakeResponse(HandshakeResponse<'a>),
    PacketCookieReply(PacketCookieReply<'a>),
    PacketData(PacketData<'a>),
}

impl Tunnel {
    #[inline(always)]
    pub fn parse_incoming_packet(src: &[u8]) -> Result<Packet<'_>, Error> {
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
            }),
            (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ) => Packet::HandshakeResponse(HandshakeResponse {
                sender_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                receiver_idx: u32::from_le_bytes(src[8..12].try_into().unwrap()),
                unencrypted_ephemeral: <&[u8; 32] as TryFrom<&[u8]>>::try_from(&src[12..44])
                    .expect("length already checked above"),
                encrypted_nothing: &src[44..60],
            }),
            (COOKIE_REPLY, COOKIE_REPLY_SZ) => Packet::PacketCookieReply(PacketCookieReply {
                receiver_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                nonce: &src[8..32],
                encrypted_cookie: &src[32..64],
            }),
            (DATA, DATA_OVERHEAD_SZ..=usize::MAX) => Packet::PacketData(PacketData {
                receiver_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                counter: u64::from_le_bytes(src[8..16].try_into().unwrap()),
                encrypted_encapsulated_packet: &src[16..],
            }),
            _ => return Err(Error::InvalidPacket),
        })
    }

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

    /// Encapsulate a single packet from the tunnel interface **in place**, but only if
    /// there is currently a usable session.
    ///
    /// Returns the encrypted WireGuard data message, written to the start of `dst`. Returns
    /// `Err(Error::NoCurrentSession)` when there is no usable session; in that case `dst` is left
    /// untouched and **no** handshake is initiated.
    pub fn encapsulate_data<'a>(
        &mut self,
        src: &[u8],
        dst: &'a mut [u8],
        now: Instant,
    ) -> Result<Ciphertext<'a>, Error> {
        let is_responder = self.timers.is_responder();
        let Some(session) = self.sessions[self.current]
            .as_mut()
            .filter(|s| s.should_use_at(now) || is_responder)
        else {
            return Err(Error::NoCurrentSession);
        };

        // Send the packet using an established session
        let packet = session.format_packet_data(src, dst)?;

        self.timer_tick(TimerName::TimeLastPacketSent, now);
        // Exclude Keepalive packets from timer update.
        if !src.is_empty() {
            self.timer_tick(TimerName::TimeLastDataPacketSent, now);
        }

        Ok(Ciphertext(packet))
    }

    /// Receives a UDP datagram from the network and parses it.
    /// Returns TunnelResult.
    pub fn decapsulate<'a>(
        &mut self,
        src_addr: Option<IpAddr>,
        datagram: &[u8],
        dst: &'a mut [u8],
        now: Instant,
    ) -> Result<TunnelResult<'a>, Error> {
        let mut cookie = [0u8; COOKIE_REPLY_SZ];
        let verified = self
            .rate_limiter
            .verify_packet(src_addr, datagram, &mut cookie, now)?;
        let packet = match verified {
            Ok(packet) => packet,
            Err(cookie) => {
                dst[..cookie.len()].copy_from_slice(cookie);
                return Ok(TunnelResult::WriteToNetwork(Ciphertext(
                    &mut dst[..cookie.len()],
                )));
            }
        };

        self.handle_verified_packet(packet, dst, now)
    }

    pub(crate) fn handle_verified_packet<'a>(
        &mut self,
        packet: Packet,
        dst: &'a mut [u8],
        now: Instant,
    ) -> Result<TunnelResult<'a>, Error> {
        match packet {
            Packet::HandshakeInit(p) => self.handle_handshake_init(p, dst, now),
            Packet::HandshakeResponse(p) => self.handle_handshake_response(p, dst, now),
            Packet::PacketCookieReply(p) => self.handle_cookie_reply(p, now),
            Packet::PacketData(p) => self.handle_data(p, dst, now),
        }
    }

    fn handle_handshake_init<'a>(
        &mut self,
        p: HandshakeInit,
        dst: &'a mut [u8],
        now: Instant,
    ) -> Result<TunnelResult<'a>, Error> {
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

        Ok(TunnelResult::WriteToNetwork(Ciphertext(packet)))
    }

    fn handle_handshake_response<'a>(
        &mut self,
        p: HandshakeResponse,
        dst: &'a mut [u8],
        now: Instant,
    ) -> Result<TunnelResult<'a>, Error> {
        tracing::debug!(
            local_idx = %Index::from_peer(p.receiver_idx),
            remote_idx = %Index::from_peer(p.sender_idx),
            "Received handshake_response"
        );

        let mut session = self.handshake.receive_handshake_response(p, now)?;

        let keepalive_packet = session.format_packet_data(&[], dst)?;
        // Store new session in ring buffer
        let local_idx = session.local_index();
        self.sessions[local_idx] = Some(session);

        self.timer_tick(TimerName::TimeLastPacketReceived, now);
        self.timer_tick_session_established(true, now); // New session established, we are the initiator
        self.set_current_session(local_idx);

        tracing::debug!(%local_idx, "Sending keepalive");

        Ok(TunnelResult::WriteToNetwork(Ciphertext(keepalive_packet))) // Send a keepalive as a response
    }

    fn handle_cookie_reply<'a>(
        &mut self,
        p: PacketCookieReply,
        now: Instant,
    ) -> Result<TunnelResult<'a>, Error> {
        let local_idx = Index::from_peer(p.receiver_idx);

        tracing::debug!(%local_idx, "Received cookie_reply");

        self.handshake.receive_cookie_reply(p, now)?;
        self.timer_tick(TimerName::TimeLastPacketReceived, now);

        tracing::debug!(%local_idx, "Did set cookie");

        Ok(TunnelResult::Done)
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

    /// Decrypts a data packet, and stores the decapsulated packet in dst.
    fn handle_data<'a>(
        &mut self,
        packet: PacketData,
        dst: &'a mut [u8],
        now: Instant,
    ) -> Result<TunnelResult<'a>, Error> {
        let remote_idx = Index::from_peer(packet.receiver_idx);

        // Get the (probably) right session
        let decapsulated_packet = {
            let session = self.sessions[remote_idx].as_mut();
            let session = session.ok_or_else(|| {
                tracing::trace!(%remote_idx, "No current session available");
                Error::NoCurrentSession
            })?;
            session.receive_packet_data(packet, dst)?
        };

        self.set_current_session(remote_idx);

        self.timer_tick(TimerName::TimeLastPacketReceived, now);

        self.validate_decapsulated_packet(decapsulated_packet, now)
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
    fn validate_decapsulated_packet<'a>(
        &mut self,
        packet: &'a mut [u8],
        now: Instant,
    ) -> Result<TunnelResult<'a>, Error> {
        let computed_len = match packet.len() {
            0 => return Ok(TunnelResult::Done), // This is keepalive, and not an error
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

        Ok(TunnelResult::WriteToTunnel(Plaintext(
            &mut packet[..computed_len],
        )))
    }
}
