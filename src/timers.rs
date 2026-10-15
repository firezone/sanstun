//! Timers from the [WireGuard protocol](https://www.wireguard.com/papers/wireguard.pdf#page=14).

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
/// The exclusive counter limit, leaving room for the replay window's arithmetic.
pub(crate) const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);

#[derive(Debug)]
pub(crate) enum TimerName {
    /// When the last handshake completed, even if its session is not in use.
    TimeLastHandshakeCompleted,
    /// When the current round of handshake attempts began.
    TimeLastHandshakeStarted,
    /// When we last authenticated an incoming packet.
    TimeLastPacketReceived,
    /// When we last sent a packet.
    TimeLastPacketSent,
    /// When we last authenticated an incoming data packet.
    TimeLastDataPacketReceived,
    /// When we last sent a data packet.
    TimeLastDataPacketSent,
    /// When we last sent a persistent keepalive.
    TimePersistentKeepalive,
    /// When we last updated the timers.
    TimeLastUpdate,
    Top,
}

use self::TimerName::*;

#[derive(Debug)]
pub(crate) struct Timers {
    timers: [Instant; TimerName::Top as usize],
    /// When we last received data without replying, used for the passive-keepalive deadline.
    last_data_received_without_reply: Option<Instant>,
    /// When we first sent data without a reply, used for the new-handshake deadline.
    first_data_sent_without_reply: Option<Instant>,
    persistent_keepalive: Option<Duration>,
    /// When the scheduled handshake is due.
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

    /// Returns the connection expiry deadline, `REJECT_AFTER_TIME * 3` after the last handshake.
    pub(crate) fn reject_after_time(&self) -> Instant {
        self[TimeLastHandshakeCompleted] + REJECT_AFTER_TIME * 3
    }

    /// Returns the deadline for giving up on unanswered handshake attempts.
    pub(crate) fn rekey_attempt_time(&self) -> Instant {
        self[TimeLastHandshakeStarted] + self.rekey_attempt_time
    }

    /// Returns the new-handshake deadline for data sent without a reply.
    pub(crate) fn rekey_after_time_without_response(&self) -> Option<Instant> {
        let first_packet_without_reply = self.first_data_sent_without_reply?;

        Some(first_packet_without_reply + self.keepalive_timeout + self.rekey_timeout)
    }

    /// Returns the passive-keepalive deadline for data received without a reply.
    pub(crate) fn keepalive_after_time_without_send(&self) -> Option<Instant> {
        let last_data_received_without_reply = self.last_data_received_without_reply?;

        Some(last_data_received_without_reply + self.keepalive_timeout)
    }

    /// Returns the next persistent-keepalive deadline, if configured.
    pub(crate) fn next_persistent_keepalive(&self) -> Option<Instant> {
        Some(self[TimePersistentKeepalive] + self.persistent_keepalive?)
    }

    pub(crate) fn clear(&mut self, now: Instant) {
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
                        // Later sends must not postpone the deadline for the first unanswered packet.
                    }
                    None => self.first_data_sent_without_reply = Some(now),
                }
            }
            _ => {}
        }

        self[timer_name] = now;
    }

    /// Returns the retry deadline for a handshake initiation sent at `sent_at`.
    pub(crate) fn rekey_timeout(&self, sent_at: Instant) -> Instant {
        sent_at + self.rekey_timeout
    }

    pub(crate) fn scheduled_handshake(&self) -> Option<Instant> {
        self.send_handshake_at
    }

    pub(crate) fn schedule_handshake(&mut self, at: Instant) {
        let existing = self.send_handshake_at.replace(at);
        debug_assert!(existing.is_none(), "a handshake is already scheduled");
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
