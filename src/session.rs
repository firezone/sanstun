use super::{
    index::Index,
    timers::{
        REJECT_AFTER_MESSAGES, REJECT_AFTER_TIME, REKEY_AFTER_MESSAGES, REKEY_AFTER_TIME,
        SHOULD_NOT_USE_AFTER_TIME,
    },
};
use crate::crypto::nonce;
use crate::errors::Error;
use crate::message::{AEAD_TAG_SZ, DATA, DATA_HEADER_SZ, DataMessage, PacketData};
use crate::replay::ReceivingKeyCounterValidator;
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(crate) struct Session {
    established_at: Instant,
    role: Role,
    sent_data: bool,
    received_data: bool,
    pub(crate) receiving_index: Index,
    sending_index: Index,
    receiver: Arc<Key>,
    sender: Arc<Key>,
    sending_key_counter: u64,
    receiving_key_counter: ReceivingKeyCounterValidator,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Session: {}<- ->{}",
            self.receiving_index, self.sending_index
        )
    }
}

/// Our role in the handshake that established a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Initiator,
    Responder,
}

/// The plaintext of a data message is zero-padded to a multiple of this
const PADDING_MULTIPLE: usize = 16;

impl Session {
    pub(super) fn new(
        local_index: Index,
        peer_index: Index,
        receiving_key: &[u8; 32],
        sending_key: &[u8; 32],
        role: Role,
        now: Instant,
    ) -> Session {
        Session {
            established_at: now,
            role,
            sent_data: false,
            received_data: false,
            receiving_index: local_index,
            sending_index: peer_index,
            receiver: Arc::new(Key(LessSafeKey::new(
                UnboundKey::new(&CHACHA20_POLY1305, receiving_key).unwrap(),
            ))),
            sender: Arc::new(Key(LessSafeKey::new(
                UnboundKey::new(&CHACHA20_POLY1305, sending_key).unwrap(),
            ))),
            sending_key_counter: 0,
            receiving_key_counter: Default::default(),
        }
    }

    pub(crate) fn established_at(&self) -> Instant {
        self.established_at
    }

    pub(crate) fn role(&self) -> Role {
        self.role
    }

    /// Whether we sent a data message, not just keepalives, on this session.
    pub(crate) fn sent_data(&self) -> bool {
        self.sent_data
    }

    /// As its initiator, we start a new handshake `REKEY_AFTER_TIME` after establishing this
    /// session, if we sent data on it.
    pub(crate) fn rekey_after_time_on_send(&self) -> Option<Instant> {
        if self.role != Role::Initiator || !self.sent_data {
            return None;
        }

        Some(self.established_at + REKEY_AFTER_TIME)
    }

    /// As its initiator, we start a new handshake once this session gets close to its expiry,
    /// if we received data on it.
    pub(crate) fn reject_after_time_on_receive(
        &self,
        keepalive_timeout: Duration,
        rekey_timeout: Duration,
    ) -> Option<Instant> {
        if self.role != Role::Initiator || !self.received_data {
            return None;
        }

        Some(self.established_at + REJECT_AFTER_TIME - keepalive_timeout - rekey_timeout)
    }

    pub(crate) fn expires_at(&self) -> Instant {
        self.established_at + REJECT_AFTER_TIME
    }

    pub(crate) fn expired_at(&self, time: Instant) -> bool {
        time >= self.expires_at()
    }

    pub(crate) fn should_use_at(&self, time: Instant) -> bool {
        time <= self.established_at + SHOULD_NOT_USE_AFTER_TIME
    }

    /// Whether `key` is this session's receiving key.
    pub(crate) fn receives_with(&self, key: &Arc<Key>) -> bool {
        Arc::ptr_eq(&self.receiver, key)
    }

    /// Whether the sending counter reached [`REKEY_AFTER_MESSAGES`].
    pub(crate) fn rekey_after_messages_reached(&self) -> bool {
        self.sending_key_counter >= REKEY_AFTER_MESSAGES
    }

    /// Whether the sending counter reached [`REJECT_AFTER_MESSAGES`].
    pub(crate) fn sending_counter_exhausted(&self) -> bool {
        self.sending_key_counter >= REJECT_AFTER_MESSAGES
    }

    /// Assigns the next counter to a data message, deferring writing and encrypting it.
    pub(super) fn prepare_packet_data(&mut self) -> PendingEncapsulate {
        self.sent_data = true;
        self.prepare_message()
    }

    /// Assigns the next counter to a keepalive.
    pub(super) fn prepare_keepalive(&mut self) -> PendingEncapsulate {
        self.prepare_message()
    }

    /// Checks the counter of a data message, deferring its decryption.
    pub(super) fn prepare_receive_packet_data(
        &self,
        packet: PacketData,
    ) -> Result<PendingDecapsulate, Error> {
        if Index::from_peer(packet.receiver_idx) != self.receiving_index {
            return Err(Error::WrongIndex);
        }
        // Don't reuse counters, in case this is a replay attack we want to quickly check the counter without running expensive decryption
        self.receiving_key_counter.will_accept(packet.counter)?;

        Ok(PendingDecapsulate {
            key: Arc::clone(&self.receiver),
            receiving_index: self.receiving_index,
            counter: packet.counter,
        })
    }

    /// Accepts the counter of a decrypted data message, returning the length of its plaintext.
    pub(super) fn finish_receive_packet_data(
        &mut self,
        counter: u64,
        plaintext_len: Result<usize, Error>,
    ) -> Result<usize, Error> {
        let plaintext_len = plaintext_len?;

        // Only an authenticated message may advance the replay window. The check is repeated
        // because a duplicate may have passed the quick check before this one was accepted.
        self.receiving_key_counter.mark_did_receive(counter)?;
        self.received_data |= plaintext_len > 0;

        Ok(plaintext_len)
    }

    fn prepare_message(&mut self) -> PendingEncapsulate {
        debug_assert!(
            !self.sending_counter_exhausted(),
            "the sending key is exhausted"
        );
        let counter = self.sending_key_counter;
        self.sending_key_counter += 1;

        PendingEncapsulate {
            key: Arc::clone(&self.sender),
            receiver_index: self.sending_index,
            counter,
        }
    }
}

/// Number of sessions in the ring, better keep a PoT
///
/// We use a `u8` to align with the number of bits reserved in [`Index`] for the sessions.
const N_SESSIONS: u8 = 8;

/// The [`N_SESSIONS`] most recent sessions, stored at their index modulo [`N_SESSIONS`].
pub(crate) struct Sessions {
    slots: [Option<Session>; N_SESSIONS as usize],
    /// Index of most recently used session
    current: Index,
    /// The most recently allocated local index
    last_index: Index,
}

impl Sessions {
    /// Creates an empty ring whose sessions take their local indices from `index`.
    pub(crate) fn new(index: Index) -> Self {
        Self {
            slots: Default::default(),
            current: Index::default(),
            last_index: index,
        }
    }

    /// The part of every local index that identifies the tunnel.
    pub(crate) fn tunnel_id(&self) -> u32 {
        self.last_index.global()
    }

    /// Allocates the local index of a new session.
    ///
    /// The index never maps to the slot of the current session, so storing the new session
    /// cannot replace it.
    pub(crate) fn next_index(&mut self) -> Index {
        loop {
            let index = self.last_index.wrapping_increment();

            if self
                .current()
                .is_none_or(|current| slot_of(current.receiving_index) != slot_of(index))
            {
                return index;
            }
        }
    }

    /// Stores a new session, replacing the one in its slot.
    pub(crate) fn insert(&mut self, session: Session) {
        let index = session.receiving_index;
        *self.slot_mut(index) = Some(session);
    }

    /// The most recently used session, if it still exists.
    pub(crate) fn current(&self) -> Option<&Session> {
        self.get(self.current)
    }

    pub(crate) fn current_mut(&mut self) -> Option<&mut Session> {
        self.get_mut(self.current)
    }

    /// The session in the slot of `index`, which may have a different index.
    pub(crate) fn in_slot_of(&self, index: Index) -> Option<&Session> {
        self.slot(index).as_ref()
    }

    /// The session with exactly `index`, if it still exists.
    pub(crate) fn get_mut(&mut self, index: Index) -> Option<&mut Session> {
        self.slot_mut(index)
            .as_mut()
            .filter(|s| s.receiving_index == index)
    }

    /// Update the index of the currently used session, if needed
    pub(crate) fn set_current(&mut self, new_idx: Index) {
        let cur_idx = self.current;
        if cur_idx == new_idx {
            // There is nothing to do, already using this session, this is the common case
            return;
        }

        let Some(new) = self.get(new_idx) else {
            debug_assert!(false, "new session should always exist");
            return;
        };
        if self
            .current()
            .is_some_and(|current| current.established_at() > new.established_at())
        {
            // The current session is "newer" than the new one, don't update.
            return;
        }

        self.current = new_idx;
        tracing::debug!(idx = %new_idx, "New session");
    }

    pub(crate) fn clear(&mut self) {
        for session in &mut self.slots {
            *session = None;
        }
    }

    /// Discards every session past [`REJECT_AFTER_TIME`].
    ///
    /// Returns the current session if it was among them.
    pub(crate) fn expire(&mut self, now: Instant) -> Option<Session> {
        let mut expired_current = None;

        for maybe_session in self.slots.iter_mut() {
            let Some(session) = maybe_session.take_if(|session| session.expired_at(now)) else {
                continue;
            };

            let is_current = self.current == session.receiving_index;

            tracing::debug!(
                session = %session.receiving_index,
                %is_current,
                "SESSION_EXPIRED(REJECT_AFTER_TIME)"
            );

            if is_current {
                expired_current = Some(session);
            }
        }

        expired_current
    }

    /// The earliest [`Instant`] at which one of our sessions expires.
    pub(crate) fn next_expiry(&self) -> Option<Instant> {
        self.slots.iter().flatten().map(Session::expires_at).min()
    }

    fn get(&self, index: Index) -> Option<&Session> {
        self.slot(index)
            .as_ref()
            .filter(|s| s.receiving_index == index)
    }

    fn slot(&self, index: Index) -> &Option<Session> {
        &self.slots[slot_of(index)]
    }

    fn slot_mut(&mut self, index: Index) -> &mut Option<Session> {
        &mut self.slots[slot_of(index)]
    }
}

fn slot_of(index: Index) -> usize {
    index.session() % N_SESSIONS as usize
}

/// The encryption of a data message whose counter is already assigned.
///
/// The nonce is fixed when the [`PendingEncapsulate`] is created, so encryptions may run in any
/// order and on any thread: the receiver's sliding replay window accepts data messages that arrive
/// out of order.
///
/// It holds its own handle to the session key and is not invalidated when the session expires,
/// so encrypt it soon after creating it.
#[derive(Debug)]
#[must_use = "the data message is not sent until it is encrypted"]
pub struct PendingEncapsulate {
    key: Arc<Key>,
    receiver_index: Index,
    counter: u64,
}

impl PendingEncapsulate {
    /// Writes the data message encrypting `plaintext` to the start of `dst`.
    ///
    /// `plaintext` is zero-padded to the next multiple of 16 bytes, so the data message, and the
    /// minimum length of `dst`, is `plaintext.len().next_multiple_of(16) + 32` bytes. Fails with
    /// `Err(Error::EmptyPlaintext)` if `plaintext` is empty: an empty data message is a keepalive,
    /// which is sent with [`Tunnel::encapsulate_keepalive`](crate::Tunnel::encapsulate_keepalive).
    pub fn encrypt<'a>(
        self,
        plaintext: &[u8],
        dst: &'a mut [u8],
    ) -> Result<DataMessage<'a>, Error> {
        if plaintext.is_empty() {
            return Err(Error::EmptyPlaintext);
        }

        self.encrypt_payload(plaintext, dst)
    }

    pub(crate) fn encrypt_payload<'a>(
        self,
        plaintext: &[u8],
        dst: &'a mut [u8],
    ) -> Result<DataMessage<'a>, Error> {
        let padded_len = plaintext.len().next_multiple_of(PADDING_MULTIPLE);
        let len = DATA_HEADER_SZ + padded_len + AEAD_TAG_SZ;
        let available = dst.len();

        let Some(message) = dst.get_mut(..len) else {
            return Err(Error::DestinationBufferTooSmall {
                required: len,
                available,
            });
        };

        let (header, rest) = message.split_at_mut(DATA_HEADER_SZ);
        let (data, tag) = rest.split_at_mut(padded_len);

        let (message_type, rest) = header.split_at_mut(4);
        let (receiver_index, counter) = rest.split_at_mut(4);
        message_type.copy_from_slice(&DATA.to_le_bytes());
        receiver_index.copy_from_slice(&self.receiver_index.to_le_bytes());
        counter.copy_from_slice(&self.counter.to_le_bytes());

        let (payload, padding) = data.split_at_mut(plaintext.len());
        payload.copy_from_slice(plaintext);
        padding.fill(0);

        let computed_tag = self
            .key
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce(self.counter)),
                Aad::from(&[]),
                data,
            )
            .expect("plaintext of a data message is always within the AEAD's limits");
        tag.copy_from_slice(computed_tag.as_ref());

        Ok(DataMessage(message))
    }
}

/// The decryption of a data message whose counter has been checked.
///
/// Its counter has passed the replay check but is not yet marked as received: that only happens
/// once the [`Decrypted`] message is handed back to the [`Tunnel`](crate::Tunnel), so a message that
/// fails to authenticate never advances the replay window.
#[derive(Debug)]
#[must_use = "the data message is not decrypted until `decrypt` is called"]
pub struct PendingDecapsulate {
    key: Arc<Key>,
    receiving_index: Index,
    counter: u64,
}

impl PendingDecapsulate {
    /// Copies the ciphertext of `message` to the start of `dst` and decrypts it in place.
    ///
    /// `message` is the data message this [`PendingDecapsulate`] was prepared from; anything else fails
    /// to authenticate. The returned [`Decrypted`] message owns `dst`; hand it to
    /// [`Tunnel::commit_decrypted`](crate::Tunnel::commit_decrypted).
    pub fn decrypt<B: AsMut<[u8]>>(self, message: &[u8], mut dst: B) -> Decrypted<B> {
        let ciphertext = message.get(DATA_HEADER_SZ..).unwrap_or_default();
        let plaintext_len = self.decrypt_in_place(ciphertext, dst.as_mut());

        Decrypted {
            receiving_index: self.receiving_index,
            counter: self.counter,
            plaintext_len,
            buffer: dst,
            key: self.key,
        }
    }

    fn decrypt_in_place(&self, ciphertext: &[u8], dst: &mut [u8]) -> Result<usize, Error> {
        let ct_len = ciphertext.len();
        let available = dst.len();

        let Some(buf) = dst.get_mut(..ct_len) else {
            return Err(Error::DestinationBufferTooSmall {
                required: ct_len,
                available,
            });
        };
        buf.copy_from_slice(ciphertext);

        let plaintext = self
            .key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce(self.counter)),
                Aad::from(&[]),
                buf,
            )
            .map_err(|_| Error::InvalidAeadTag)?;

        Ok(plaintext.len())
    }
}

/// A data message decrypted by [`PendingDecapsulate::decrypt`], to be committed to the
/// [`Tunnel`](crate::Tunnel) with [`Tunnel::commit_decrypted`](crate::Tunnel::commit_decrypted).
#[must_use = "the data message is not accepted until it is committed to the `Tunnel`"]
pub struct Decrypted<B> {
    pub(crate) receiving_index: Index,
    pub(crate) counter: u64,
    pub(crate) plaintext_len: Result<usize, Error>,
    pub(crate) buffer: B,
    /// Identifies the session the message may be committed to: its index alone is reused once
    /// the session part wraps around.
    ///
    /// Released when the [`Tunnel`](crate::Tunnel) handles the message, so that decrypting a
    /// message leaves the reference count of the key to the thread that owns the
    /// [`Tunnel`](crate::Tunnel).
    pub(crate) key: Arc<Key>,
}

impl<B> std::fmt::Debug for Decrypted<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Decrypted")
            .field("receiving_index", &self.receiving_index)
            .field("counter", &self.counter)
            .field("plaintext_len", &self.plaintext_len)
            .finish_non_exhaustive()
    }
}

/// A session key on a cache line of its own, apart from the reference count of its [`Arc`].
///
/// Threads that only read the key then never contend with the thread updating the count.
#[derive(Debug)]
#[repr(align(128))]
pub(crate) struct Key(LessSafeKey);

impl std::ops::Deref for Key {
    type Target = LessSafeKey;

    fn deref(&self) -> &LessSafeKey {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_counter_below_the_limit_is_handed_out_before_exhaustion() {
        let mut session = session(Index::new_local(0));
        session.sending_key_counter = REJECT_AFTER_MESSAGES - 1;
        assert!(!session.sending_counter_exhausted());

        let pending = session.prepare_packet_data();

        assert_eq!(pending.counter, REJECT_AFTER_MESSAGES - 1);
        assert!(session.sending_counter_exhausted());
    }

    #[test]
    fn next_index_skips_the_slot_of_the_current_session() {
        let mut sessions = Sessions::new(Index::new_local(0));
        let current = sessions.next_index();
        sessions.insert(session(current));
        sessions.set_current(current);

        for _ in 0..2 * N_SESSIONS {
            assert_ne!(slot_of(sessions.next_index()), slot_of(current));
        }
    }

    fn session(receiving_index: Index) -> Session {
        Session::new(
            receiving_index,
            Index::from_peer(0),
            &[0; 32],
            &[0; 32],
            Role::Initiator,
            Instant::now(),
        )
    }
}
