use crate::{Event, Keepalive, Tunnel};
use std::iter;
use std::ops::{Index, IndexMut};

use rand::RngExt;
use std::time::{Duration, Instant};

// Some constants, represent time in seconds
// https://www.wireguard.com/papers/wireguard.pdf#page=14
const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
pub(crate) const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const COOKIE_EXPIRATION_TIME: Duration = Duration::from_secs(120);
const MAX_JITTER: Duration = Duration::from_millis(333);
pub(crate) const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
/// Counters at or above this are neither sent nor accepted, so the replay window's arithmetic
/// never overflows.
pub(crate) const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);

/// Time-period after which a session should no longer be used for new packets.
///
/// In order for [`REKEY_AFTER_TIME`] to take effect, at least one data packet needs to be sent on a session.
/// If this data packet is sent close to the expire of the session ([`REJECT_AFTER_TIME`]), the session
/// may be expired by the time the packet reaches the receiver (and thus will not be able to be decrypted).
///
/// To avoid this, we stop using the session after [`REJECT_AFTER_TIME`] - [`KEEPALIVE_TIMEOUT`].
pub(crate) const SHOULD_NOT_USE_AFTER_TIME: Duration =
    Duration::from_secs(REJECT_AFTER_TIME.as_secs() - KEEPALIVE_TIMEOUT.as_secs());

#[derive(Debug)]
pub(crate) enum TimerName {
    /// Time when last handshake was completed
    TimeSessionEstablished,
    /// Time the last attempt for a new handshake began
    TimeLastHandshakeStarted,
    /// Time we last received and authenticated a packet
    TimeLastPacketReceived,
    /// Time we last send a packet
    TimeLastPacketSent,
    /// Time we last received and authenticated a DATA packet
    TimeLastDataPacketReceived,
    /// Time we last send a DATA packet
    TimeLastDataPacketSent,
    /// Time we last sent persistent keepalive
    TimePersistentKeepalive,
    /// Time we last updated our timers
    TimeLastUpdate,
    Top,
}

use self::TimerName::*;

#[derive(Debug)]
pub(crate) struct Timers {
    /// Is the owner of the timer the initiator or the responder for the last handshake?
    is_initiator: bool,
    timers: [Instant; TimerName::Top as usize],
    /// The last data packet we received without having sent a reply since.
    ///
    /// If `Some`, the passive-keepalive deadline is derived from it on demand.
    last_data_received_without_reply: Option<Instant>,
    /// The first data packet we sent without having heard back since.
    ///
    /// If `Some`, the new-handshake deadline is derived from it on demand.
    first_data_sent_without_reply: Option<Instant>,
    persistent_keepalive: usize,
    /// When we should sent a scheduled handshake.
    send_handshake_at: Option<Instant>,

    rekey_attempt_time: Duration,
    keepalive_timeout: Duration,
    rekey_timeout: Duration,
}

impl Timers {
    pub(super) fn new(persistent_keepalive: Option<u16>, now: Instant) -> Timers {
        Timers {
            is_initiator: false,
            timers: [now; TimerName::Top as usize],
            last_data_received_without_reply: Default::default(),
            first_data_sent_without_reply: Default::default(),
            persistent_keepalive: usize::from(persistent_keepalive.unwrap_or(0)),
            send_handshake_at: None,
            rekey_attempt_time: REKEY_ATTEMPT_TIME,
            keepalive_timeout: KEEPALIVE_TIMEOUT,
            rekey_timeout: REKEY_TIMEOUT,
        }
    }

    fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    pub(crate) fn is_responder(&self) -> bool {
        !self.is_initiator
    }

    /// After `REJECT_AFTER_TIME * 3` without a new handshake, all ephemeral and
    /// symmetric key material is wiped and the connection is considered dead.
    pub(crate) fn reject_after_time(&self) -> Instant {
        self[TimeSessionEstablished] + REJECT_AFTER_TIME * 3
    }

    /// After `REKEY_ATTEMPT_TIME` of unsuccessfully trying to complete a
    /// handshake, we give up.
    pub(crate) fn rekey_attempt_time(&self) -> Instant {
        self[TimeLastHandshakeStarted] + self.rekey_attempt_time
    }

    /// Whether data has been sent on the current session since it was established.
    ///
    /// Only such a session is ever due a re-key: one that has carried nothing ages
    /// out without [`Timers::rekey_after_time_on_send`] ever arming.
    pub(crate) fn current_session_carried_data(&self) -> bool {
        self[TimeLastDataPacketSent] > self[TimeSessionEstablished]
    }

    /// As the initiator, we start a new handshake `REKEY_AFTER_TIME` after
    /// establishing a session on which we have since sent data.
    pub(crate) fn rekey_after_time_on_send(&self) -> Option<Instant> {
        if !self.is_initiator {
            // If we aren't the initiator of the current session, this timer does not matter.
            return None;
        }

        if !self.current_session_carried_data() {
            return None;
        }

        Some(self[TimeSessionEstablished] + REKEY_AFTER_TIME)
    }

    /// As the initiator, we start a new handshake once a session on which we
    /// have since received data gets close to its expiry.
    pub(crate) fn reject_after_time_on_receive(&self) -> Option<Instant> {
        if !self.is_initiator {
            // If we aren't the initiator of the current session, this timer does not matter.
            return None;
        }

        let session_established = self[TimeSessionEstablished];

        if session_established >= self[TimeLastDataPacketReceived] {
            // If we haven't received any data yet, this timer doesn't matter.
            return None;
        }

        Some(session_established + REJECT_AFTER_TIME - self.keepalive_timeout - self.rekey_timeout)
    }

    /// If we sent data but have not heard back within `KEEPALIVE_TIMEOUT +
    /// REKEY_TIMEOUT`, we assume the session is dead and start a new handshake.
    pub(crate) fn rekey_after_time_without_response(&self) -> Option<Instant> {
        let first_packet_without_reply = self.first_data_sent_without_reply?;

        Some(first_packet_without_reply + self.keepalive_timeout + self.rekey_timeout)
    }

    /// If we received data but have not sent anything back within
    /// `KEEPALIVE_TIMEOUT`, we send a passive keepalive.
    pub(crate) fn keepalive_after_time_without_send(&self) -> Option<Instant> {
        let last_data_received_without_reply = self.last_data_received_without_reply?;

        Some(last_data_received_without_reply + self.keepalive_timeout)
    }

    /// If configured, we send a keepalive every `persistent_keepalive` seconds.
    pub(crate) fn next_persistent_keepalive(&self) -> Option<Instant> {
        let keepalive = Duration::from_secs(self.persistent_keepalive as u64);

        if keepalive.is_zero() {
            return None;
        }

        Some(self[TimePersistentKeepalive] + keepalive)
    }

    // We don't really clear the timers, but we set them to the current time to
    // so the reference time frame is the same
    pub(super) fn clear(&mut self, now: Instant) {
        for t in &mut self.timers[..] {
            *t = now;
        }
        self.first_data_sent_without_reply = None;
        self.last_data_received_without_reply = None;
    }

    pub(crate) fn tick(&mut self, timer_name: TimerName, now: Instant) {
        match timer_name {
            TimeLastPacketReceived => {
                self.first_data_sent_without_reply = None;
            }
            TimeLastPacketSent => {
                self.last_data_received_without_reply = None;
            }
            TimeLastDataPacketReceived => {
                self.last_data_received_without_reply = Some(now);
            }
            TimeLastDataPacketSent => {
                match self.first_data_sent_without_reply {
                    Some(_) => {
                        // This isn't the first timer tick (i.e. not the first packet)
                        // we haven't received a response to.
                    }
                    None => {
                        // We sent a packet and haven't heard back yet.
                        // Remember when, so we can derive the new-handshake deadline.
                        self.first_data_sent_without_reply = Some(now)
                    }
                }
            }
            _ => {}
        }

        self[timer_name] = now;
    }

    pub(crate) fn session_established(&mut self, is_initiator: bool, now: Instant) {
        self.tick(TimeSessionEstablished, now);
        self.is_initiator = is_initiator;
    }

    /// The [`Instant`] at which an unanswered handshake initiation sent at `sent_at` is retried.
    fn rekey_timeout(&self, sent_at: Instant) -> Instant {
        sent_at + self.rekey_timeout
    }

    fn scheduled_handshake(&self) -> Option<Instant> {
        self.send_handshake_at
    }

    fn schedule_handshake(&mut self, at: Instant) {
        let existing = self.send_handshake_at.replace(at);
        debug_assert!(
            existing.is_none(),
            "Should never override existing handshake"
        );
    }

    /// Clears the scheduled handshake if it is due at `now`.
    fn take_due_handshake(&mut self, now: Instant) -> Option<Instant> {
        self.send_handshake_at.take_if(|at| now >= *at)
    }

    fn consume_passive_keepalive(&mut self) {
        self.last_data_received_without_reply = None;
    }

    pub(crate) fn set_rekey_attempt_time(&mut self, rekey_attempt_time: Duration) {
        self.rekey_attempt_time = rekey_attempt_time;
    }

    pub(crate) fn set_keepalive_timeout(&mut self, keepalive_timeout: Duration) {
        self.keepalive_timeout = keepalive_timeout;
    }

    pub(crate) fn set_rekey_timeout(&mut self, rekey_timeout: Duration) {
        self.rekey_timeout = rekey_timeout;
    }
}

impl Index<TimerName> for Timers {
    type Output = Instant;
    fn index(&self, index: TimerName) -> &Self::Output {
        &self.timers[index as usize]
    }
}

impl IndexMut<TimerName> for Timers {
    fn index_mut(&mut self, index: TimerName) -> &mut Self::Output {
        &mut self.timers[index as usize]
    }
}

impl Tunnel {
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
    fn handshake_rekey_timeout(&self) -> Option<(Instant, super::Index)> {
        let (time_sent, local_index) = self.handshake.in_flight_initiation()?;

        Some((self.timers.rekey_timeout(time_sent), local_index))
    }

    /// Advances the timers to `now`, queuing whatever is due for [`Tunnel::poll_event`].
    pub fn handle_timeout(&mut self, now: Instant) {
        self.timers.tick(TimeLastUpdate, now);

        if self.timers.take_due_handshake(now).is_some() {
            if let Some(initiation) = self.format_handshake_initiation(true, now) {
                self.queue_event(Event::HandshakeInitiation(initiation));
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
        if self.sessions.expire(now) && self.timers.current_session_carried_data() {
            tracing::debug!("CONNECTION_EXPIRED(REJECT_AFTER_TIME)");
            self.expire(now);
            return;
        }

        // In case our session expired, create a new one iff we initiated the previous one.
        if self.sessions.current().is_none()
            && !self.handshake.is_in_progress()
            && self.timers.is_initiator()
        {
            handshake_initiation_required = true;
        }

        if self.handshake.is_expired() {
            return;
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
                .timers
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
                .timers
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
                    self.timers.tick(TimePersistentKeepalive, now);
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
            self.queue_event(Event::KeepaliveDue(Keepalive));
        }
    }

    /// Returns the next [`Event`] queued by [`Tunnel::handle_timeout`] or [`Tunnel::decapsulate`].
    pub fn poll_event(&mut self) -> Option<Event> {
        let event = self.events[0].take()?;
        self.events.rotate_left(1);

        Some(event)
    }

    /// Returns the [`Instant`] at which [`Tunnel::handle_timeout`] next needs to
    /// be called, together with a human-readable reason for debugging.
    ///
    /// Calling it earlier than the given [`Instant`] is safe but unlikely to
    /// have any effect. Driving the state machine by repeatedly polling at the
    /// returned [`Instant`] is sufficient: there is no need to call
    /// [`Tunnel::handle_timeout`] on a fixed interval.
    pub fn poll_timeout(&self) -> Option<(Instant, &'static str)> {
        let (next, reason) = self.next_deadline()?;
        let last_update = self.timers[TimeLastUpdate];

        // Never announce an [`Instant`] in the past: a deadline may already have
        // elapsed by the time the caller polls us.
        Some((next.max(last_update), reason))
    }

    fn next_deadline(&self) -> Option<(Instant, &'static str)> {
        // Mimic `handle_timeout`: if we have a handshake scheduled, no other timer matters.
        if let Some(scheduled_handshake) = self.timers.scheduled_handshake() {
            return Some((scheduled_handshake, "scheduled handshake"));
        }

        let common_timers = iter::empty()
            .chain(
                self.sessions
                    .next_expiry()
                    .map(|instant| (instant, "next expired session")),
            )
            .chain(
                self.handshake
                    .cookie_expiration()
                    .map(|instant| (instant, "cookie expiration")),
            )
            .chain(iter::once((
                self.timers.reject_after_time(),
                "reject-after-time",
            )));

        if let Some((rekey_timeout, _)) = self.handshake_rekey_timeout() {
            // While a handshake is in progress, only the handshake timers matter.
            common_timers
                .chain(iter::once((rekey_timeout, "rekey-timeout")))
                .chain(iter::once((
                    self.timers.rekey_attempt_time(),
                    "rekey-attempt",
                )))
                .min_by_key(|(instant, _)| *instant)
        } else {
            // Persistent keep-alive only makes sense if the current session is active.
            let persistent_keepalive = self
                .sessions
                .current()
                .and_then(|_| self.timers.next_persistent_keepalive());

            common_timers
                .chain(
                    self.timers
                        .rekey_after_time_on_send()
                        .map(|instant| (instant, "rekey-after-time (on send)")),
                )
                .chain(
                    self.rekey_after_messages()
                        .map(|instant| (instant, "rekey-after-messages")),
                )
                .chain(
                    self.timers
                        .reject_after_time_on_receive()
                        .map(|instant| (instant, "reject-after-time (on receive)")),
                )
                .chain(
                    self.timers
                        .rekey_after_time_without_response()
                        .map(|instant| (instant, "rekey-after-time (without response)")),
                )
                .chain(
                    self.timers
                        .keepalive_after_time_without_send()
                        .map(|instant| (instant, "keepalive-after-time (without send)")),
                )
                .chain(persistent_keepalive.map(|instant| (instant, "persistent keep-alive")))
                .min_by_key(|(instant, _)| *instant)
        }
    }

    /// Either peer starts a new handshake once the current session has sent
    /// `REKEY_AFTER_MESSAGES`; that became due with the last packet sent.
    fn rekey_after_messages(&self) -> Option<Instant> {
        self.sessions
            .current()
            .filter(|s| s.rekey_after_messages_reached())?;

        Some(self.timers[TimeLastPacketSent])
    }

    fn expire(&mut self, now: Instant) {
        self.handshake.set_expired();
        self.clear_all(now);
        self.queue_event(Event::ConnectionExpired);
    }

    pub fn time_since_last_handshake(&self, now: Instant) -> Option<Duration> {
        if self.sessions.current().is_some() {
            let session_established_at = self.timers[TimeSessionEstablished];

            Some(now.duration_since(session_established_at))
        } else {
            None
        }
    }
}
