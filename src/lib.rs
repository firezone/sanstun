//! A sans-IO implementation of the WireGuard protocol, acting as both initiator and responder.

mod crypto;
mod errors;
mod handshake;
mod index;
mod interface;
mod message;
mod replay;
mod ring_buffer;
mod session;
mod tai64n;
mod timers;

pub use errors::Error;
pub use interface::{Interface, Received};
pub use message::{
    CookieReplyMessage, DataMessage, HandshakeInit, HandshakeInitiationMessage, HandshakeResponse,
    HandshakeResponseMessage, KeepaliveMessage, Packet, PacketCookieReply, PacketData,
};
pub use session::{Decrypted, PendingDecapsulate, PendingEncapsulate};
pub use x25519_dalek::{PublicKey, StaticSecret};

use crate::handshake::Handshake;
use crate::index::Index;
use crate::message::DATA_OVERHEAD_SZ;
use crate::ring_buffer::RingBuffer;
use crate::session::Sessions;
use crate::tai64n::TimeStamper;
use crate::timers::{TimerName, Timers};

use rand::rngs::StdRng;
use rand::{CryptoRng, SeedableRng};

use std::time::{Duration, Instant};

/// What the caller needs to do, as returned by [`Tunnel::poll_event`].
#[derive(Debug)]
pub enum Event {
    /// Send this handshake initiation to the peer.
    HandshakeInitiation(HandshakeInitiationMessage),
    /// Send this handshake response to the peer, which sent a valid handshake initiation.
    HandshakeResponse(HandshakeResponseMessage),
    /// A keepalive is due: send it with [`Tunnel::encapsulate_keepalive`].
    KeepaliveDue(Keepalive),
    /// The connection expired and all session state was wiped.
    ///
    /// Emitted once per expiry, see [`Tunnel::is_expired`].
    ConnectionExpired,
}

/// A keepalive to send with [`Tunnel::encapsulate_keepalive`], e.g. when probing a path.
#[derive(Debug)]
#[must_use = "a keepalive is due; send it with `Tunnel::encapsulate_keepalive`"]
pub struct Keepalive;

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
    events: RingBuffer<Event, 16>,
}

impl Tunnel {
    pub fn is_expired(&self) -> bool {
        self.handshake.is_expired()
    }

    #[expect(clippy::too_many_arguments, reason = "We don't care that much.")]
    pub(crate) fn new(
        static_private: StaticSecret,
        peer_static_public: PublicKey,
        preshared_key: Option<StaticSecret>,
        persistent_keepalive: Option<u16>,
        index: Index,
        rng: &mut impl CryptoRng,
        now: Instant,
        stamper: TimeStamper,
    ) -> Result<Self, Error> {
        let static_public = PublicKey::from(&static_private);
        let handshake = Handshake::new(
            static_private,
            static_public,
            peer_static_public,
            preshared_key,
            stamper,
        )?;

        Ok(Tunnel {
            handshake,
            sessions: Sessions::new(index),
            timers: Timers::new(persistent_keepalive, now),
            rng: StdRng::from_rng(rng),
            events: RingBuffer::new(),
        })
    }

    /// Identifies this tunnel among those of its [`Interface`]: route a received [`Packet`] here if
    /// its [`Packet::tunnel_id`] matches.
    pub fn id(&self) -> u32 {
        self.sessions.tunnel_id()
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
        let session = self.sessions.current_mut()?;

        if session.sending_counter_exhausted() || session.expired_at(now) {
            return None;
        }
        if !session.should_use_at(now) && session.is_initiator() {
            return None;
        }

        Some(session)
    }

    /// Handles a message received from the network, as returned by [`Interface::receive`].
    ///
    /// Handshake messages and cookie replies are processed right away and return `None`; drain
    /// [`Tunnel::poll_event`] afterwards for any message to send in reply. The decryption of a
    /// data message is deferred to the returned [`PendingDecapsulate`]: its session is selected
    /// and its counter checked against the replay window, without updating any state or reading
    /// the ciphertext. Hand the [`Decrypted`] message back to [`Tunnel::commit_decrypted`] to
    /// complete the decapsulation.
    pub fn decapsulate(
        &mut self,
        packet: Packet<'_>,
        now: Instant,
    ) -> Result<Option<PendingDecapsulate>, Error> {
        match packet {
            Packet::HandshakeInit(p) => self.handle_handshake_init(p, now)?,
            Packet::HandshakeResponse(p) => self.handle_handshake_response(p, now)?,
            Packet::PacketCookieReply(p) => self.handle_cookie_reply(p, now)?,
            Packet::PacketData(p) => return self.handle_data(p, now).map(Some),
        }

        Ok(None)
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
            key,
        } = decrypted;

        let Some(session) = self
            .sessions
            .get_mut(remote_idx)
            .filter(|s| s.receives_with(&key))
        else {
            tracing::trace!(%remote_idx, "Session was replaced during decryption");
            return Err(Error::NoCurrentSession);
        };
        if session.expired_at(now) {
            tracing::trace!(%remote_idx, "Session expired during decryption");
            return Err(Error::NoCurrentSession);
        }
        let len = session.finish_receive_packet_data(counter, plaintext_len)?;

        self.sessions.set_current(remote_idx);
        self.timers.tick(TimerName::TimeLastPacketReceived, now);

        if len == 0 {
            return Ok(Committed::Keepalive);
        }
        self.timers.tick(TimerName::TimeLastDataPacketReceived, now);

        Ok(Committed::Data { buffer, len })
    }

    fn handle_handshake_init(&mut self, p: HandshakeInit, now: Instant) -> Result<(), Error> {
        let remote_idx = Index::from_peer(p.sender_idx);

        tracing::debug!(%remote_idx, "Received handshake_initiation",);

        let local_idx = self.sessions.next_index();
        let (packet, session) =
            self.handshake
                .receive_handshake_initialization(p, local_idx, &mut self.rng, now)?;

        self.sessions.insert(session);

        self.timers.tick(TimerName::TimeLastPacketReceived, now);
        self.timers.tick(TimerName::TimeLastPacketSent, now);
        self.timers.tick(TimerName::TimeLastHandshakeCompleted, now);

        tracing::debug!(%local_idx, %remote_idx, "Sending handshake_response");

        self.events
            .push_back(Event::HandshakeResponse(HandshakeResponseMessage(packet)));

        Ok(())
    }

    fn handle_handshake_response(
        &mut self,
        p: HandshakeResponse,
        now: Instant,
    ) -> Result<(), Error> {
        let local_idx = Index::from_peer(p.receiver_idx);

        tracing::debug!(
            %local_idx,
            remote_idx = %Index::from_peer(p.sender_idx),
            "Received handshake_response"
        );

        let session = self.handshake.receive_handshake_response(p, now)?;

        self.sessions.insert(session);

        self.timers.tick(TimerName::TimeLastPacketReceived, now);
        self.timers.tick(TimerName::TimeLastHandshakeCompleted, now);
        self.sessions.set_current(local_idx);

        // The keepalive confirms the session to the responder.
        self.events.push_back(Event::KeepaliveDue(Keepalive));

        Ok(())
    }

    fn handle_cookie_reply(&mut self, p: PacketCookieReply, now: Instant) -> Result<(), Error> {
        let local_idx = Index::from_peer(p.receiver_idx);

        tracing::debug!(%local_idx, "Received cookie_reply");

        self.handshake.receive_cookie_reply(p, now)?;
        self.timers.tick(TimerName::TimeLastPacketReceived, now);

        tracing::debug!(%local_idx, "Did set cookie");

        Ok(())
    }

    fn handle_data(&self, packet: PacketData, now: Instant) -> Result<PendingDecapsulate, Error> {
        let remote_idx = Index::from_peer(packet.receiver_idx);

        let session = self.sessions.in_slot_of(remote_idx).ok_or_else(|| {
            tracing::trace!(%remote_idx, "No current session available");
            Error::NoCurrentSession
        })?;
        if session.expired_at(now) {
            tracing::trace!(%remote_idx, "Session expired");
            return Err(Error::NoCurrentSession);
        }

        session.prepare_receive_packet_data(packet)
    }

    /// Formats a new handshake initiation message. If force_resend is true will send
    /// a new handshake, even if a handshake is already in progress (for example when a handshake times out)
    ///
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

        let local_idx = self.sessions.next_index();
        let packet = self
            .handshake
            .initiate_handshake(local_idx, &mut self.rng, now);

        tracing::debug!(%local_idx, "Sending handshake_initiation");

        if starting_new_handshake {
            self.timers.tick(TimerName::TimeLastHandshakeStarted, now);
        }
        self.timers.tick(TimerName::TimeLastPacketSent, now);

        Some(HandshakeInitiationMessage(packet))
    }
}
