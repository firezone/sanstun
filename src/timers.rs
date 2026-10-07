//! <https://www.wireguard.com/papers/wireguard.pdf#page=14>

use std::ops::{Index, IndexMut};
use std::time::{Duration, Instant};

pub(crate) const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
pub(crate) const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const COOKIE_EXPIRATION_TIME: Duration = Duration::from_secs(120);
pub(crate) const MAX_JITTER: Duration = Duration::from_millis(333);
pub(crate) const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
/// Counters at or above this are neither sent nor accepted, so the replay window's arithmetic
/// never overflows.
pub(crate) const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);

#[derive(Debug)]
pub(crate) enum TimerName {
    /// Time the last handshake completed, whether or not its session is in use
    TimeLastHandshakeCompleted,
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
    timers: [Instant; TimerName::Top as usize],
    /// The last data packet we received without having sent a reply since.
    ///
    /// If `Some`, the passive-keepalive deadline is derived from it on demand.
    last_data_received_without_reply: Option<Instant>,
    /// The first data packet we sent without having heard back since.
    ///
    /// If `Some`, the new-handshake deadline is derived from it on demand.
    first_data_sent_without_reply: Option<Instant>,
    persistent_keepalive: Option<Duration>,
    /// When we should sent a scheduled handshake.
    send_handshake_at: Option<Instant>,

    rekey_attempt_time: Duration,
    pub(crate) keepalive_timeout: Duration,
    pub(crate) rekey_timeout: Duration,
}

impl Timers {
    pub(super) fn new(persistent_keepalive: Option<Duration>, now: Instant) -> Timers {
        Timers {
            timers: [now; TimerName::Top as usize],
            last_data_received_without_reply: Default::default(),
            first_data_sent_without_reply: Default::default(),
            persistent_keepalive,
            send_handshake_at: None,
            rekey_attempt_time: REKEY_ATTEMPT_TIME,
            keepalive_timeout: KEEPALIVE_TIMEOUT,
            rekey_timeout: REKEY_TIMEOUT,
        }
    }

    /// After `REJECT_AFTER_TIME * 3` without a new handshake, all ephemeral and
    /// symmetric key material is dropped and the connection is considered dead.
    pub(crate) fn reject_after_time(&self) -> Instant {
        self[TimeLastHandshakeCompleted] + REJECT_AFTER_TIME * 3
    }

    /// After `REKEY_ATTEMPT_TIME` of unsuccessfully trying to complete a
    /// handshake, we give up.
    pub(crate) fn rekey_attempt_time(&self) -> Instant {
        self[TimeLastHandshakeStarted] + self.rekey_attempt_time
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

    /// If configured, we send a keepalive every `persistent_keepalive`.
    pub(crate) fn next_persistent_keepalive(&self) -> Option<Instant> {
        Some(self[TimePersistentKeepalive] + self.persistent_keepalive?)
    }

    pub(crate) fn clear(&mut self, now: Instant) {
        // We don't really clear the timers, but we set them to the current time to
        // so the reference time frame is the same
        for t in &mut self.timers[..] {
            *t = now;
        }
        self.first_data_sent_without_reply = None;
        self.last_data_received_without_reply = None;
    }

    pub(crate) fn tick(&mut self, timer_name: TimerName, now: Instant) {
        match timer_name {
            TimeLastPacketReceived => self.first_data_sent_without_reply = None,
            TimeLastPacketSent => self.last_data_received_without_reply = None,
            TimeLastDataPacketReceived => self.last_data_received_without_reply = Some(now),
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

    /// The [`Instant`] at which an unanswered handshake initiation sent at `sent_at` is retried.
    pub(crate) fn rekey_timeout(&self, sent_at: Instant) -> Instant {
        sent_at + self.rekey_timeout
    }

    pub(crate) fn scheduled_handshake(&self) -> Option<Instant> {
        self.send_handshake_at
    }

    pub(crate) fn schedule_handshake(&mut self, at: Instant) {
        let existing = self.send_handshake_at.replace(at);
        debug_assert!(
            existing.is_none(),
            "Should never override existing handshake"
        );
    }

    /// Clears the scheduled handshake if it is due at `now`.
    pub(crate) fn take_due_handshake(&mut self, now: Instant) -> Option<Instant> {
        self.send_handshake_at.take_if(|at| now >= *at)
    }

    pub(crate) fn consume_passive_keepalive(&mut self) {
        self.last_data_received_without_reply = None;
    }

    pub(crate) fn set_rekey_attempt_time(&mut self, rekey_attempt_time: Duration) {
        debug_assert!(
            rekey_attempt_time <= REJECT_AFTER_TIME * 3,
            "REKEY_ATTEMPT_TIME must be at most REJECT_AFTER_TIME * 3"
        );

        self.rekey_attempt_time = rekey_attempt_time;
    }

    pub(crate) fn set_keepalive_timeout(&mut self, keepalive_timeout: Duration) {
        debug_assert!(
            keepalive_timeout
                .checked_add(self.rekey_timeout)
                .is_some_and(|sum| sum <= REJECT_AFTER_TIME),
            "KEEPALIVE_TIMEOUT + REKEY_TIMEOUT must be at most REJECT_AFTER_TIME"
        );

        self.keepalive_timeout = keepalive_timeout;
    }

    pub(crate) fn set_rekey_timeout(&mut self, rekey_timeout: Duration) {
        debug_assert!(
            rekey_timeout
                .checked_add(self.keepalive_timeout)
                .is_some_and(|sum| sum <= REJECT_AFTER_TIME),
            "KEEPALIVE_TIMEOUT + REKEY_TIMEOUT must be at most REJECT_AFTER_TIME"
        );

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
