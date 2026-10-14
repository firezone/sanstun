use crate::errors::Error;
use crate::handshake::Handshake;
use crate::index::{Index, TunnelId};
use crate::keys::{PresharedKey, PublicKey, StaticSecret};
use crate::message::{
    CookieReply, DATA_OVERHEAD_SZ, Datagram, HandshakeInitiation, HandshakeResponse,
    ReceivedMessage, TransportData,
};
use crate::ring_buffer::RingBuffer;
use crate::session::{self, Decrypted, PendingDecapsulate, PendingEncapsulate, Role, Sessions};
use crate::tai64n::TimeStamper;
use crate::timers::{MAX_JITTER, TimerName, Timers};

use crate::rng::ForwardSecureRng;
use rand::{CryptoRng, RngExt};

use std::iter;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// What the caller needs to do, as returned by [`Tunnel::poll_event`].
#[derive(Debug)]
pub enum Event {
    /// Send this handshake initiation to the peer.
    SendHandshakeInitiation(Datagram),
    /// Send this handshake response to the peer, which sent a valid handshake initiation.
    SendHandshakeResponse(Datagram),
    /// A keepalive is due: send it with [`Tunnel::encapsulate_keepalive`].
    KeepaliveDue(Keepalive),
    /// The connection expired and all session state was dropped.
    ///
    /// Emitted once per expiry. Drop the [`Tunnel`] and create a new one with
    /// [`Interface::new_tunnel`](crate::Interface::new_tunnel) to reach the peer again, see
    /// [`Tunnel::is_expired`].
    ConnectionExpired,
}

/// A keepalive to send with [`Tunnel::encapsulate_keepalive`], e.g. when probing a path.
#[derive(Debug)]
#[must_use = "a keepalive is due; send it with `Tunnel::encapsulate_keepalive`"]
pub struct Keepalive;

/// The result of committing a decrypted packet.
pub enum Committed<B> {
    /// The first `len` bytes of `buffer` hold the decrypted payload, possibly followed by padding.
    Data { buffer: B, len: usize },
    /// The data message was a keepalive.
    Keepalive,
}

impl<B> std::fmt::Debug for Committed<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Committed::Data { len, .. } => f
                .debug_struct("Data")
                .field("len", len)
                .finish_non_exhaustive(),
            Committed::Keepalive => f.write_str("Keepalive"),
        }
    }
}

/// The optional settings of a [`Tunnel`], passed to
/// [`Interface::new_tunnel`](crate::Interface::new_tunnel).
#[derive(Debug, Default)]
pub struct TunnelConfig {
    preshared_key: Option<PresharedKey>,
    persistent_keepalive: Option<Duration>,
}

impl TunnelConfig {
    /// Mixes `preshared_key` into every handshake.
    pub fn with_preshared_key(mut self, preshared_key: PresharedKey) -> Self {
        self.preshared_key = Some(preshared_key);

        self
    }

    /// Sends a keepalive once `interval` passed since the last message we sent.
    ///
    /// A zero `interval` leaves the persistent keepalive off.
    pub fn with_persistent_keepalive(mut self, interval: Duration) -> Self {
        self.persistent_keepalive = Some(interval).filter(|interval| !interval.is_zero());

        self
    }
}

/// A point-to-point WireGuard connection
pub struct Tunnel {
    handshake: Handshake,
    sessions: Sessions,
    timers: Timers,
    rng: ForwardSecureRng,
    events: RingBuffer<Event, 16>,

    /// Reserves this tunnel's index in its [`Interface`](crate::Interface) while the tunnel is alive.
    _index_lease: Arc<()>,
}

impl Tunnel {
    /// Whether the connection expired, as announced by [`Event::ConnectionExpired`].
    ///
    /// An expired tunnel is meant to be dropped: it has no timeout, formats no handshake
    /// initiation and fails everything else with [`Error::ConnectionExpired`].
    pub fn is_expired(&self) -> bool {
        self.handshake.is_expired()
    }

    fn ensure_not_expired(&self) -> Result<(), Error> {
        if self.is_expired() {
            return Err(Error::ConnectionExpired);
        }

        Ok(())
    }

    #[expect(clippy::too_many_arguments, reason = "We don't care that much.")]
    pub(crate) fn new(
        static_private: StaticSecret,
        peer_static_public: PublicKey,
        config: TunnelConfig,
        index: Index,
        index_lease: Arc<()>,
        rng: &mut impl CryptoRng,
        now: Instant,
        stamper: TimeStamper,
    ) -> Result<Self, Error> {
        let static_public = PublicKey::from(&static_private);
        let handshake = Handshake::new(
            static_private,
            static_public,
            peer_static_public,
            config.preshared_key,
            stamper,
        )?;

        Ok(Tunnel {
            handshake,
            sessions: Sessions::new(index),
            timers: Timers::new(config.persistent_keepalive, now),
            rng: ForwardSecureRng::new(rng),
            events: RingBuffer::new(),
            _index_lease: index_lease,
        })
    }

    /// Identifies this tunnel among those of its [`Interface`](crate::Interface).
    ///
    /// Route a [`ReceivedMessage`] here if its [`ReceivedMessage::tunnel_id`] matches.
    pub fn id(&self) -> TunnelId {
        self.sessions.tunnel_id()
    }

    pub fn remote_static_public(&self) -> PublicKey {
        self.handshake.remote_static_public()
    }

    /// Set the `REKEY_ATTEMPT_TIME`.
    ///
    /// Defaults to 90s. Must be at most 540s (`REJECT_AFTER_TIME * 3`), after which the tunnel
    /// expires without a new handshake anyway.
    pub fn set_rekey_attempt_time(&mut self, rekey_attempt_time: Duration) {
        self.timers.set_rekey_attempt_time(rekey_attempt_time);
    }

    /// Set the `KEEPALIVE_TIMEOUT`.
    ///
    /// Defaults to 10s. Together with the `REKEY_TIMEOUT`, must be at most 180s
    /// (`REJECT_AFTER_TIME`).
    pub fn set_keepalive_timeout(&mut self, keepalive_timeout: Duration) {
        self.timers.set_keepalive_timeout(keepalive_timeout);
    }

    /// Set the `REKEY_TIMEOUT`, i.e. the interval at which an unanswered
    /// handshake initiation is retried.
    ///
    /// Defaults to 5s. Together with the `KEEPALIVE_TIMEOUT`, must be at most 180s
    /// (`REJECT_AFTER_TIME`).
    pub fn set_rekey_timeout(&mut self, rekey_timeout: Duration) {
        self.timers.set_rekey_timeout(rekey_timeout);
    }

    /// Prepares a data message, deferring writing and encrypting it to the returned [`PendingEncapsulate`].
    pub fn begin_encapsulate(&mut self, now: Instant) -> Result<PendingEncapsulate, Error> {
        self.ensure_not_expired()?;

        let pending = self
            .sending_session(now)
            .ok_or(Error::NoCurrentSession)?
            .prepare_packet_data();
        self.timers.tick(TimerName::TimeLastPacketSent, now);
        self.timers.tick(TimerName::TimeLastDataPacketSent, now);

        Ok(pending)
    }

    /// Encrypts a keepalive on the session that data messages are sent on.
    pub fn encapsulate_keepalive(
        &mut self,
        _keepalive: Keepalive,
        now: Instant,
    ) -> Result<Datagram, Error> {
        self.ensure_not_expired()?;

        let mut message = [0u8; DATA_OVERHEAD_SZ];
        self.sending_session(now)
            .ok_or(Error::NoCurrentSession)?
            .prepare_keepalive()
            .encrypt_payload(&[], &mut message)?;
        self.timers.tick(TimerName::TimeLastPacketSent, now);

        Ok(Datagram::new(message))
    }

    /// The session that data messages are sent on, if one is usable.
    fn sending_session(&mut self, now: Instant) -> Option<&mut session::Session> {
        let session = self.sessions.current_mut()?;

        if session.sending_counter_exhausted() || session.expired_at(now) {
            return None;
        }
        if !session.should_use_at(now, self.timers.keepalive_timeout)
            && session.role() == Role::Initiator
        {
            return None;
        }

        Some(session)
    }

    /// Handles a message received from the network, as returned by [`Interface::receive`](crate::Interface::receive).
    ///
    /// Handshake messages and cookie replies are processed right away and return `None`. The
    /// decryption of a data message is deferred to the returned [`PendingDecapsulate`]. Hand
    /// the [`Decrypted`] message back to [`Tunnel::commit_decapsulate`] to complete the
    /// decapsulation.
    pub fn begin_decapsulate(
        &mut self,
        message: ReceivedMessage,
        now: Instant,
    ) -> Result<Option<PendingDecapsulate>, Error> {
        self.ensure_not_expired()?;

        match message {
            ReceivedMessage::HandshakeInitiation(p) => self.handle_handshake_init(p, now)?,
            ReceivedMessage::HandshakeResponse(p) => self.handle_handshake_response(p, now)?,
            ReceivedMessage::CookieReply(p) => self.handle_cookie_reply(p, now)?,
            ReceivedMessage::TransportData(p) => return self.handle_data(p, now).map(Some),
        }

        Ok(None)
    }

    /// Completes the decapsulation of a decrypted data message to obtain the plaintext.
    pub fn commit_decapsulate<B: AsRef<[u8]>>(
        &mut self,
        decrypted: Decrypted<B>,
        now: Instant,
    ) -> Result<Committed<B>, Error> {
        self.ensure_not_expired()?;

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

    fn handle_handshake_init(&mut self, p: HandshakeInitiation, now: Instant) -> Result<(), Error> {
        let remote_idx = Index::from_peer(p.sender_idx());

        tracing::debug!(%remote_idx, "Received handshake_initiation",);

        let local_idx = self.sessions.next_index();
        let (packet, session) =
            self.handshake
                .receive_handshake_initialization(&p, local_idx, &mut self.rng, now)?;

        self.sessions.insert(session);

        self.timers.tick(TimerName::TimeLastPacketReceived, now);
        self.timers.tick(TimerName::TimeLastPacketSent, now);
        self.timers.tick(TimerName::TimeLastHandshakeCompleted, now);

        tracing::debug!(%local_idx, %remote_idx, "Sending handshake_response");

        self.events
            .push_back(Event::SendHandshakeResponse(Datagram::new(packet)));

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

    fn handle_cookie_reply(&mut self, p: CookieReply, now: Instant) -> Result<(), Error> {
        let local_idx = Index::from_peer(p.receiver_idx);

        tracing::debug!(%local_idx, "Received cookie_reply");

        self.handshake.receive_cookie_reply(p, now)?;

        tracing::debug!(%local_idx, "Did set cookie");

        Ok(())
    }

    fn handle_data(
        &self,
        packet: TransportData,
        now: Instant,
    ) -> Result<PendingDecapsulate, Error> {
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

    /// Starts a handshake with the peer.
    ///
    /// Returns `None` if a handshake is already in progress or the tunnel
    /// [expired](Tunnel::is_expired).
    pub fn initiate_handshake(&mut self, now: Instant) -> Option<Datagram> {
        if self.handshake.is_in_progress() {
            return None;
        }

        self.restart_handshake(now)
    }

    /// Starts a new handshake with the peer, replacing one that is in progress.
    ///
    /// Returns `None` once the tunnel [expired](Tunnel::is_expired).
    pub fn restart_handshake(&mut self, now: Instant) -> Option<Datagram> {
        if self.is_expired() {
            return None;
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

        Some(Datagram::new(packet))
    }

    /// Drops all sessions and resets the timers to `now`.
    fn clear_all(&mut self, now: Instant) {
        self.sessions.clear();
        self.timers.clear(now);
    }

    /// The [`Instant`] at which we need to retransmit our handshake initiation,
    /// together with the local index of the in-flight handshake.
    ///
    /// Returns `None` unless we are currently the initiator of an in-progress
    /// handshake.
    fn handshake_rekey_timeout(&self) -> Option<(Instant, Index)> {
        let (time_sent, local_index) = self.handshake.in_flight_initiation()?;

        Some((self.timers.rekey_timeout(time_sent), local_index))
    }

    /// Advances the timers to `now`, queuing whatever is due for [`Tunnel::poll_event`].
    pub fn handle_timeout(&mut self, now: Instant) {
        if self.is_expired() {
            return;
        }

        self.timers.tick(TimerName::TimeLastUpdate, now);

        if self.timers.take_due_handshake(now).is_some() {
            if let Some(initiation) = self.restart_handshake(now) {
                self.events
                    .push_back(Event::SendHandshakeInitiation(initiation));
            }
            return;
        }

        if let Some(scheduled_handshake_at) = self.timers.scheduled_handshake() {
            debug_assert!(
                scheduled_handshake_at
                    .checked_duration_since(now)
                    .is_some_and(|remaining| remaining <= MAX_JITTER),
                "Should never suspend for longer than jitter duration"
            );

            // We have a handshake scheduled but the deadline is not expired yet.
            // Don't do anything to avoid repeated printing of logs.
            // The below logic would still evaluate that we need to send another handshake.
            return;
        }

        let mut handshake_initiation_required = false;
        let mut keepalive_required = false;

        // Both peers derive a session's lifetime from the same handshake, so the remote
        // discards it at the same moment we do. A session that carried data was due a
        // re-key at REKEY_AFTER_TIME, so reaching its expiry means that re-key never
        // landed and there is no shared state left to reach.
        if let Some(expired_current) = self.sessions.expire(now) {
            if expired_current.sent_data() {
                tracing::debug!("CONNECTION_EXPIRED(REJECT_AFTER_TIME)");
                self.expire(now);
                return;
            }

            // In case our session expired, create a new one iff we initiated it.
            if expired_current.role() == Role::Initiator && !self.handshake.is_in_progress() {
                handshake_initiation_required = true;
            }
        }

        // Clear cookie after COOKIE_EXPIRATION_TIME
        if self
            .handshake
            .cookie_expiration()
            .is_some_and(|deadline| now >= deadline)
        {
            tracing::debug!("COOKIE_EXPIRED");
            self.handshake.clear_cookie();
        }

        // Handshake state and sessions are discarded after (REJECT_AFTER_TIME * 3) ms
        // if no new keys have been exchanged. Handshake secrets are zeroized on drop,
        // session keys are only dropped.
        if now >= self.timers.reject_after_time() {
            tracing::debug!("CONNECTION_EXPIRED(REJECT_AFTER_TIME * 3)");
            self.expire(now);
            return;
        }

        if let Some((rekey_timeout, local_idx)) = self.handshake_rekey_timeout() {
            // Handshake Initiation Retransmission
            if now >= self.timers.rekey_attempt_time() {
                // After REKEY_ATTEMPT_TIME ms of trying to initiate a new handshake,
                // the retries give up and cease, and clear all existing packets queued
                // up to be sent. If a packet is explicitly queued up to be sent, then
                // this timer is reset.
                tracing::debug!(%local_idx, "CONNECTION_EXPIRED(REKEY_ATTEMPT_TIME)");
                self.expire(now);
                return;
            }

            if now >= rekey_timeout {
                // A handshake initiation is retried after REKEY_TIMEOUT + jitter ms,
                // if a response has not been received, where jitter is some random
                // value between 0 and 333 ms (`MAX_JITTER`).
                tracing::debug!(%local_idx, "HANDSHAKE(REKEY_TIMEOUT)");
                handshake_initiation_required = true;
            }
        } else {
            // After sending a packet, if the sender was the original initiator
            // of the handshake and if the current session key is REKEY_AFTER_TIME
            // ms old, we initiate a new handshake. If the sender was the original
            // responder of the handshake, it does not re-initiate a new handshake
            // after REKEY_AFTER_TIME ms like the original initiator does.
            if self
                .rekey_after_time_on_send()
                .is_some_and(|deadline| now >= deadline)
            {
                tracing::debug!("HANDSHAKE(REKEY_AFTER_TIME (on send))");
                handshake_initiation_required = true;
            }

            if self
                .rekey_after_messages()
                .is_some_and(|deadline| now >= deadline)
            {
                tracing::debug!("HANDSHAKE(REKEY_AFTER_MESSAGES)");
                handshake_initiation_required = true;
            }

            // After receiving a packet, if the receiver was the original initiator
            // of the handshake and if the current session key is REJECT_AFTER_TIME
            // - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT ms old, we initiate a new
            // handshake.
            if self
                .reject_after_time_on_receive()
                .is_some_and(|deadline| now >= deadline)
            {
                tracing::debug!(
                    "HANDSHAKE(REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT (on receive))"
                );
                handshake_initiation_required = true;
            }

            // If we have sent a packet to a given peer but have not received a
            // packet after from that peer for (KEEPALIVE + REKEY_TIMEOUT) ms,
            // we initiate a new handshake.
            if self
                .timers
                .rekey_after_time_without_response()
                .is_some_and(|deadline| now >= deadline)
            {
                tracing::debug!("HANDSHAKE(KEEPALIVE + REKEY_TIMEOUT)");
                handshake_initiation_required = true;
            }

            if !handshake_initiation_required {
                // If a packet has been received from a given peer, but we have not sent one back
                // to the given peer in KEEPALIVE ms, we send an empty packet.
                if self
                    .timers
                    .keepalive_after_time_without_send()
                    .is_some_and(|deadline| now >= deadline)
                {
                    tracing::debug!("KEEPALIVE(KEEPALIVE_TIMEOUT)");
                    // Consume the deadline now; the send below may fail and nothing else
                    // would clear it.
                    self.timers.consume_passive_keepalive();
                    keepalive_required = true;
                }

                // Persistent KEEPALIVE
                if self
                    .timers
                    .next_persistent_keepalive()
                    .is_some_and(|deadline| now >= deadline)
                {
                    tracing::debug!("KEEPALIVE(PERSISTENT_KEEPALIVE)");
                    self.timers.tick(TimerName::TimePersistentKeepalive, now);
                    keepalive_required = true;
                }
            }
        }

        if handshake_initiation_required {
            let jitter = self.rng.random_range(Duration::ZERO..=MAX_JITTER);

            self.timers.schedule_handshake(now + jitter);

            tracing::debug!(?jitter, "Scheduling new handshake");

            return;
        }

        // A keepalive is only ever sent on an established session; there is no need to queue it
        // or start a handshake.
        if keepalive_required && self.sending_session(now).is_some() {
            self.events.push_back(Event::KeepaliveDue(Keepalive));
        }
    }

    /// Returns the next [`Event`] queued by [`Tunnel::handle_timeout`] or [`Tunnel::begin_decapsulate`].
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Returns the [`Instant`] at which [`Tunnel::handle_timeout`] next needs to
    /// be called.
    ///
    /// Calling it earlier than the given [`Instant`] is safe but unlikely to
    /// have any effect. Driving the state machine by repeatedly polling at the
    /// returned [`Instant`] is sufficient: there is no need to call
    /// [`Tunnel::handle_timeout`] on a fixed interval. Returns `None` once the tunnel
    /// [expired](Tunnel::is_expired).
    pub fn poll_timeout(&self) -> Option<Instant> {
        if self.is_expired() {
            return None;
        }

        let next = self.next_deadline()?;
        let last_update = self.timers[TimerName::TimeLastUpdate];

        // Never announce an [`Instant`] in the past: a deadline may already have
        // elapsed by the time the caller polls us.
        Some(next.max(last_update))
    }

    fn next_deadline(&self) -> Option<Instant> {
        // Mimic `handle_timeout`: if we have a handshake scheduled, no other timer matters.
        if let Some(scheduled_handshake) = self.timers.scheduled_handshake() {
            return Some(scheduled_handshake);
        }

        let common_timers = iter::empty()
            .chain(self.sessions.next_expiry())
            .chain(self.handshake.cookie_expiration())
            .chain(iter::once(self.timers.reject_after_time()));

        if let Some((rekey_timeout, _)) = self.handshake_rekey_timeout() {
            // While a handshake is in progress, only the handshake timers matter.
            common_timers
                .chain(iter::once(rekey_timeout))
                .chain(iter::once(self.timers.rekey_attempt_time()))
                .min()
        } else {
            // Persistent keep-alive only makes sense if the current session is active.
            let persistent_keepalive = self
                .sessions
                .current()
                .and_then(|_| self.timers.next_persistent_keepalive());

            common_timers
                .chain(self.rekey_after_time_on_send())
                .chain(self.rekey_after_messages())
                .chain(self.reject_after_time_on_receive())
                .chain(self.timers.rekey_after_time_without_response())
                .chain(self.timers.keepalive_after_time_without_send())
                .chain(persistent_keepalive)
                .min()
        }
    }

    /// Either peer starts a new handshake once the current session has sent
    /// `REKEY_AFTER_MESSAGES`; that became due with the last packet sent.
    fn rekey_after_messages(&self) -> Option<Instant> {
        self.sessions
            .current()
            .filter(|s| s.rekey_after_messages_reached())?;

        Some(self.timers[TimerName::TimeLastPacketSent])
    }

    fn rekey_after_time_on_send(&self) -> Option<Instant> {
        self.sessions.current()?.rekey_after_time_on_send()
    }

    fn reject_after_time_on_receive(&self) -> Option<Instant> {
        self.sessions
            .current()?
            .reject_after_time_on_receive(self.timers.keepalive_timeout, self.timers.rekey_timeout)
    }

    fn expire(&mut self, now: Instant) {
        self.handshake.set_expired();
        self.clear_all(now);
        self.events.push_back(Event::ConnectionExpired);
    }

    pub fn time_since_last_handshake(&self, now: Instant) -> Option<Duration> {
        let current = self.sessions.current()?;

        Some(now.duration_since(current.established_at()))
    }
}
