use crate::errors::Error;
use crate::handshake::Handshake;
use crate::index::{Index, TunnelId};
use crate::keys::{PresharedKey, PublicKey, StaticSecret};
use crate::message::{
    CookieReply, DATA_OVERHEAD_SZ, Datagram, HandshakeInitiation, HandshakeResponse, TransportData,
};
use crate::ring_buffer::RingBuffer;
use crate::session::{
    self, Decrypted, PendingDecapsulate, PendingEncapsulate, Plaintext, Role, Sessions,
};
use crate::tai64n::TimeStamper;
use crate::timers::{MAX_JITTER, TimerName, Timers};

use crate::rng::ForwardSecureRng;
use rand::{CryptoRng, RngExt};

use std::iter;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// An action for the caller, returned by [`Tunnel::poll_event`].
#[derive(Debug)]
pub enum Event {
    /// Send this handshake initiation to the peer.
    SendHandshakeInitiation(Datagram),
    /// Send this keepalive to the peer.
    SendKeepalive(Datagram),
    /// The tunnel confirmed its first session.
    ///
    /// Emitted once per tunnel: for the initiator, when it accepts the handshake response; for
    /// the responder, when it accepts the first data message or keepalive under the new session.
    /// `confirmed_at - started_at` is how long the handshake took.
    Established {
        /// For the initiator, when it sent its first handshake initiation, so the duration
        /// includes retries. For the responder, when it accepted the initiation that created the
        /// session.
        started_at: Instant,
        /// When the session was confirmed.
        confirmed_at: Instant,
    },
    /// The connection expired and all session state was dropped.
    ///
    /// Emitted once. Drop the [`Tunnel`] and create a new one with
    /// [`Interface::new_tunnel`](crate::Interface::new_tunnel) to reconnect.
    ConnectionExpired,
}

/// The result of committing a decrypted packet.
pub enum Committed<B> {
    /// The first `len` bytes of `buffer` contain the decrypted payload, including any padding.
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

/// Optional settings for a [`Tunnel`], passed to
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

    /// Configures persistent keepalives at `interval`.
    ///
    /// A zero interval disables persistent keepalives.
    pub fn with_persistent_keepalive(mut self, interval: Duration) -> Self {
        self.persistent_keepalive = Some(interval).filter(|interval| !interval.is_zero());

        self
    }
}

/// A point-to-point WireGuard connection.
pub struct Tunnel {
    handshake: Handshake,
    sessions: Sessions,
    timers: Timers,
    rng: ForwardSecureRng,
    events: RingBuffer<Event, 16>,
    first_initiation_at: Option<Instant>,
    established: bool,

    /// Reserves this tunnel's index in its [`Interface`](crate::Interface) while the tunnel is alive.
    _index_lease: Arc<()>,
}

impl Tunnel {
    /// Returns whether the connection has expired, as announced by [`Event::ConnectionExpired`].
    ///
    /// Drop expired tunnels. They have no further timeouts or handshake initiations, and
    /// encapsulation and decapsulation fail with [`Error::ConnectionExpired`].
    pub fn is_expired(&self) -> bool {
        self.handshake.is_expired()
    }

    fn ensure_not_expired(&self) -> Result<(), Error> {
        if self.is_expired() {
            return Err(Error::ConnectionExpired);
        }

        Ok(())
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Initializes the peer, session index, timers and key material."
    )]
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
            first_initiation_at: None,
            established: false,
            _index_lease: index_lease,
        })
    }

    /// Returns this tunnel's ID within its [`Interface`](crate::Interface).
    ///
    /// Route a [`ReceivedMessage`](crate::ReceivedMessage) other than a handshake initiation
    /// here if its `tunnel_id` matches.
    pub fn id(&self) -> TunnelId {
        self.sessions.tunnel_id()
    }

    pub fn remote_static_public(&self) -> PublicKey {
        self.handshake.remote_static_public()
    }

    /// Sets how long to retry unanswered handshake initiations (`REKEY_ATTEMPT_TIME`).
    ///
    /// Defaults to 90 seconds. Must be at most 540 seconds (`REJECT_AFTER_TIME * 3`), when a
    /// tunnel without a new handshake expires.
    pub fn set_rekey_attempt_time(&mut self, rekey_attempt_time: Duration) {
        self.timers.set_rekey_attempt_time(rekey_attempt_time);
    }

    /// Sets how long to wait before replying to data with a keepalive (`KEEPALIVE_TIMEOUT`).
    ///
    /// Defaults to 10 seconds. The sum of this and `REKEY_TIMEOUT` must not exceed
    /// 180 seconds (`REJECT_AFTER_TIME`).
    pub fn set_keepalive_timeout(&mut self, keepalive_timeout: Duration) {
        self.timers.set_keepalive_timeout(keepalive_timeout);
    }

    /// Sets the retry interval for unanswered handshake initiations (`REKEY_TIMEOUT`).
    ///
    /// Defaults to 5 seconds. The sum of this and `KEEPALIVE_TIMEOUT` must not exceed
    /// 180 seconds (`REJECT_AFTER_TIME`).
    pub fn set_rekey_timeout(&mut self, rekey_timeout: Duration) {
        self.timers.set_rekey_timeout(rekey_timeout);
    }

    /// Reserves a data message's counter for encryption with [`PendingEncapsulate::encrypt`].
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

    /// Encrypts a keepalive using the current sending session.
    fn encrypt_keepalive(&mut self, now: Instant) -> Result<Datagram, Error> {
        let mut message = [0u8; DATA_OVERHEAD_SZ];
        self.sending_session(now)
            .ok_or(Error::NoCurrentSession)?
            .prepare_keepalive()
            .encrypt_payload(&[], &mut message)?;
        self.timers.tick(TimerName::TimeLastPacketSent, now);

        Ok(Datagram::new(message))
    }

    /// Returns a usable session for sending data, if one exists.
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

    /// Accepts a decrypted data message after checking its session and replay counter.
    pub fn commit_decapsulate<B>(
        &mut self,
        decrypted: Decrypted<B>,
        now: Instant,
    ) -> Result<Committed<B>, Error> {
        self.ensure_not_expired()?;

        let Decrypted {
            receiving_index: remote_idx,
            counter,
            plaintext,
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
        let plaintext = session.finish_receive_packet_data(counter, plaintext)?;
        let accepted_at = session.established_at();

        self.sessions.set_current(remote_idx);
        self.timers.tick(TimerName::TimeLastPacketReceived, now);
        self.confirm_first_session(accepted_at, now);

        let Plaintext::Data { buffer, len } = plaintext else {
            return Ok(Committed::Keepalive);
        };
        self.timers.tick(TimerName::TimeLastDataPacketReceived, now);

        Ok(Committed::Data { buffer, len })
    }

    /// Answers a handshake initiation.
    ///
    /// Returns the response to send back on the path the initiation arrived on. Fails with
    /// [`Error::ReplayedHandshakeInitiation`] if [`Interface::receive`](crate::Interface::receive)
    /// marked it as a replay.
    pub fn handle_handshake_initiation(
        &mut self,
        p: HandshakeInitiation,
        now: Instant,
    ) -> Result<Datagram, Error> {
        if p.0.replayed {
            return Err(Error::ReplayedHandshakeInitiation);
        }

        self.ensure_not_expired()?;

        let remote_idx = Index::from_peer(p.sender_index());

        tracing::debug!(%remote_idx, "Received handshake initiation");

        let local_idx = self.sessions.next_index();
        let (packet, session) =
            self.handshake
                .receive_handshake_initialization(&p, local_idx, &mut self.rng, now)?;

        self.sessions.insert(session);

        self.timers.tick(TimerName::TimeLastPacketReceived, now);
        self.timers.tick(TimerName::TimeLastPacketSent, now);
        self.timers.tick(TimerName::TimeLastHandshakeCompleted, now);

        tracing::debug!(%local_idx, %remote_idx, "Sending handshake response");

        Ok(Datagram::new(packet))
    }

    /// Completes a handshake this tunnel initiated.
    ///
    /// Returns the keepalive that confirms the session to the responder.
    pub fn handle_handshake_response(
        &mut self,
        p: HandshakeResponse,
        now: Instant,
    ) -> Result<Datagram, Error> {
        self.ensure_not_expired()?;

        let local_idx = Index::from_peer(p.receiver_idx);

        tracing::debug!(
            %local_idx,
            remote_idx = %Index::from_peer(p.sender_idx),
            "Received handshake response"
        );

        let session = self.handshake.receive_handshake_response(p, now)?;

        self.sessions.insert(session);

        self.timers.tick(TimerName::TimeLastPacketReceived, now);
        self.timers.tick(TimerName::TimeLastHandshakeCompleted, now);
        self.sessions.set_current(local_idx);
        self.confirm_first_session(self.first_initiation_at.unwrap_or(now), now);

        self.encrypt_keepalive(now)
    }

    fn confirm_first_session(&mut self, started_at: Instant, now: Instant) {
        if self.established {
            return;
        }

        self.established = true;
        self.events.push_back(Event::Established {
            started_at,
            confirmed_at: now,
        });
    }

    /// Stores the cookie from a reply to this tunnel's handshake initiation.
    pub fn handle_cookie_reply(&mut self, p: CookieReply, now: Instant) -> Result<(), Error> {
        self.ensure_not_expired()?;

        let local_idx = Index::from_peer(p.receiver_idx);

        tracing::debug!(%local_idx, "Received cookie reply");

        self.handshake.receive_cookie_reply(p, now)?;

        tracing::debug!(%local_idx, "Stored cookie");

        Ok(())
    }

    /// Prepares a data message for decryption.
    ///
    /// Decrypt the returned [`PendingDecapsulate`] and pass the result to
    /// [`Tunnel::commit_decapsulate`] to accept the plaintext. The tunnel only
    /// changes once the message is authenticated, in `commit_decapsulate`.
    pub fn begin_decapsulate(
        &self,
        packet: TransportData,
        now: Instant,
    ) -> Result<PendingDecapsulate, Error> {
        self.ensure_not_expired()?;

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
    /// has [expired](Tunnel::is_expired).
    pub fn initiate_handshake(&mut self, now: Instant) -> Option<Datagram> {
        if self.handshake.is_in_progress() {
            return None;
        }

        self.restart_handshake(now)
    }

    /// Starts a new handshake with the peer, replacing one that is in progress.
    ///
    /// Returns `None` once the tunnel has [expired](Tunnel::is_expired).
    pub fn restart_handshake(&mut self, now: Instant) -> Option<Datagram> {
        if self.is_expired() {
            return None;
        }

        let starting_new_handshake = !self.handshake.is_in_progress();

        let local_idx = self.sessions.next_index();
        let packet = self
            .handshake
            .initiate_handshake(local_idx, &mut self.rng, now);

        tracing::debug!(%local_idx, "Sending handshake initiation");

        if starting_new_handshake {
            self.timers.tick(TimerName::TimeLastHandshakeStarted, now);
        }
        self.timers.tick(TimerName::TimeLastPacketSent, now);
        self.first_initiation_at.get_or_insert(now);

        Some(Datagram::new(packet))
    }

    /// Drops all sessions and resets the timers to `now`.
    fn clear_all(&mut self, now: Instant) {
        self.sessions.clear();
        self.timers.clear(now);
    }

    /// Returns the retry deadline and local index of the in-flight handshake initiation.
    ///
    /// Returns `None` if no initiation is awaiting a response.
    fn handshake_rekey_timeout(&self) -> Option<(Instant, Index)> {
        let (time_sent, local_index) = self.handshake.in_flight_initiation()?;

        Some((self.timers.rekey_timeout(time_sent), local_index))
    }

    /// Advances timers to `now` and queues due events for [`Tunnel::poll_event`].
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
                "the scheduled handshake must be within the jitter interval"
            );

            // Wait for the scheduled handshake rather than scheduling another one.
            return;
        }

        let mut handshake_initiation_required = false;
        let mut keepalive_required = false;

        // A session that sent data should have rekeyed before expiry; otherwise presume it lost,
        // unless the peer already started a newer one.
        if let Some(expired_current) = self.sessions.expire(now) {
            if expired_current.sent_data() && self.sessions.is_empty() {
                tracing::debug!("Connection expired (REJECT_AFTER_TIME)");
                self.expire(now);
                return;
            }

            if expired_current.role() == Role::Initiator && !self.handshake.is_in_progress() {
                handshake_initiation_required = true;
            }
        }

        if self
            .handshake
            .cookie_expiration()
            .is_some_and(|deadline| now >= deadline)
        {
            tracing::debug!("Cookie expired");
            self.handshake.clear_cookie();
        }

        // Dropping handshake secrets and session keys zeroizes them.
        if now >= self.timers.reject_after_time() {
            tracing::debug!("Connection expired (REJECT_AFTER_TIME * 3)");
            self.expire(now);
            return;
        }

        if let Some((rekey_timeout, local_idx)) = self.handshake_rekey_timeout() {
            if now >= self.timers.rekey_attempt_time() {
                tracing::debug!(%local_idx, "Connection expired (REKEY_ATTEMPT_TIME)");
                self.expire(now);
                return;
            }

            if now >= rekey_timeout {
                tracing::debug!(%local_idx, "Retrying handshake (REKEY_TIMEOUT)");
                handshake_initiation_required = true;
            }
        } else {
            if self
                .rekey_after_time_on_send()
                .is_some_and(|deadline| now >= deadline)
            {
                tracing::debug!("Rekeying after sending data (REKEY_AFTER_TIME)");
                handshake_initiation_required = true;
            }

            if self
                .rekey_after_messages()
                .is_some_and(|deadline| now >= deadline)
            {
                tracing::debug!("Rekeying after message limit (REKEY_AFTER_MESSAGES)");
                handshake_initiation_required = true;
            }

            if self
                .reject_after_time_on_receive()
                .is_some_and(|deadline| now >= deadline)
            {
                tracing::debug!(
                    "Rekeying after receiving data (REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT)"
                );
                handshake_initiation_required = true;
            }

            if self
                .timers
                .rekey_after_time_without_response()
                .is_some_and(|deadline| now >= deadline)
            {
                tracing::debug!(
                    "Starting handshake after no reply (KEEPALIVE_TIMEOUT + REKEY_TIMEOUT)"
                );
                handshake_initiation_required = true;
            }

            if !handshake_initiation_required {
                if self
                    .timers
                    .keepalive_after_time_without_send()
                    .is_some_and(|deadline| now >= deadline)
                {
                    tracing::debug!("Keepalive due (KEEPALIVE_TIMEOUT)");
                    // Clear the deadline even if sending fails.
                    self.timers.consume_passive_keepalive();
                    keepalive_required = true;
                }

                if self
                    .timers
                    .next_persistent_keepalive()
                    .is_some_and(|deadline| now >= deadline)
                {
                    tracing::debug!("Persistent keepalive due");
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

        // Keepalives do not start handshakes or wait for a session to become available.
        if keepalive_required {
            match self.encrypt_keepalive(now) {
                Ok(keepalive) => self.events.push_back(Event::SendKeepalive(keepalive)),
                Err(e) => tracing::trace!("Skipping keepalive: {e}"),
            }
        }
    }

    /// Returns the next queued [`Event`].
    ///
    /// [`Tunnel::handle_timeout`], [`Tunnel::handle_handshake_response`] and
    /// [`Tunnel::commit_decapsulate`] queue events.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Returns the next deadline for calling [`Tunnel::handle_timeout`].
    ///
    /// After handling a timeout, poll again for the next deadline. A fixed timer interval is
    /// unnecessary, though early calls are safe. While events are queued, the deadline has
    /// already passed, so that a caller draining [`Tunnel::poll_event`] after each timeout
    /// handles them. Returns `None` once the tunnel has [expired](Tunnel::is_expired).
    pub fn poll_timeout(&self) -> Option<Instant> {
        if self.is_expired() {
            return None;
        }

        let last_update = self.timers[TimerName::TimeLastUpdate];

        if !self.events.is_empty() {
            return Some(last_update);
        }

        let next = self.next_deadline()?;

        // A deadline may have elapsed before the last timer update.
        Some(next.max(last_update))
    }

    fn next_deadline(&self) -> Option<Instant> {
        // Match `handle_timeout`'s priority for scheduled handshakes.
        if let Some(scheduled_handshake) = self.timers.scheduled_handshake() {
            return Some(scheduled_handshake);
        }

        let common_timers = iter::empty()
            .chain(self.sessions.next_expiry())
            .chain(self.handshake.cookie_expiration())
            .chain(iter::once(self.timers.reject_after_time()));

        if let Some((rekey_timeout, _)) = self.handshake_rekey_timeout() {
            common_timers
                .chain(iter::once(rekey_timeout))
                .chain(iter::once(self.timers.rekey_attempt_time()))
                .min()
        } else {
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

    /// Returns when the current session reached `REKEY_AFTER_MESSAGES` sent messages.
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
