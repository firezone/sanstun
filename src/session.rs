use super::{
    PacketData,
    index::Index,
    timers::{REJECT_AFTER_TIME, SHOULD_NOT_USE_AFTER_TIME},
};
use crate::DataMessage;
use crate::errors::Error;
use crate::replay::ReceivingKeyCounterValidator;
use crossbeam_utils::CachePadded;
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use std::sync::Arc;
use std::time::Instant;

pub(crate) struct Session {
    established_at: Instant,
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

/// Where encrypted data resides in a data packet
const DATA_OFFSET: usize = 16;
/// The overhead of the AEAD
const AEAD_SIZE: usize = 16;

impl Session {
    pub(super) fn new(
        local_index: Index,
        peer_index: Index,
        receiving_key: [u8; 32],
        sending_key: [u8; 32],
        now: Instant,
    ) -> Session {
        Session {
            established_at: now,
            receiving_index: local_index,
            sending_index: peer_index,
            receiver: Arc::new(Key::new(LessSafeKey::new(
                UnboundKey::new(&CHACHA20_POLY1305, &receiving_key).unwrap(),
            ))),
            sender: Arc::new(Key::new(LessSafeKey::new(
                UnboundKey::new(&CHACHA20_POLY1305, &sending_key).unwrap(),
            ))),
            sending_key_counter: 0,
            receiving_key_counter: Default::default(),
        }
    }

    pub(super) fn local_index(&self) -> Index {
        self.receiving_index
    }

    pub(crate) fn established_at(&self) -> Instant {
        self.established_at
    }

    pub(crate) fn expired_at(&self, time: Instant) -> bool {
        time >= self.established_at + REJECT_AFTER_TIME
    }

    pub(crate) fn should_use_at(&self, time: Instant) -> bool {
        time <= self.established_at + SHOULD_NOT_USE_AFTER_TIME
    }

    /// Assigns the next counter to a data message, deferring writing and encrypting it.
    pub(super) fn prepare_packet_data(&mut self) -> PendingEncapsulate {
        let counter = self.sending_key_counter;
        self.sending_key_counter += 1;

        PendingEncapsulate {
            key: Arc::clone(&self.sender),
            receiver_index: self.sending_index,
            counter,
        }
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

        Ok(plaintext_len)
    }
}

/// The encryption of a data message whose counter is already assigned.
///
/// The nonce is fixed when the [`PendingEncapsulate`] is created, so encryptions may run in any
/// order and on any thread: the receiver's sliding replay window accepts data messages that arrive
/// out of order.
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
    /// The data message is 32 bytes longer than `plaintext`. Fails with
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
        let len = DATA_OFFSET + plaintext.len() + AEAD_SIZE;
        let available = dst.len();

        let Some(message) = dst.get_mut(..len) else {
            return Err(Error::DestinationBufferTooSmall {
                required: len,
                available,
            });
        };

        let (header, rest) = message.split_at_mut(DATA_OFFSET);
        let (data, tag) = rest.split_at_mut(plaintext.len());

        let (message_type, rest) = header.split_at_mut(4);
        let (receiver_index, counter) = rest.split_at_mut(4);
        message_type.copy_from_slice(&super::DATA.to_le_bytes());
        receiver_index.copy_from_slice(&self.receiver_index.to_le_bytes());
        counter.copy_from_slice(&self.counter.to_le_bytes());

        // TODO: spec requires padding to 16 bytes, but actually works fine without it
        data.copy_from_slice(plaintext);

        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&self.counter.to_le_bytes());
        let computed_tag = self
            .key
            .seal_in_place_separate_tag(Nonce::assume_unique_for_key(nonce), Aad::from(&[]), data)
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
        let ciphertext = message.get(DATA_OFFSET..).unwrap_or_default();
        let plaintext_len = self.decrypt_in_place(ciphertext, dst.as_mut());

        Decrypted {
            receiving_index: self.receiving_index,
            counter: self.counter,
            plaintext_len,
            buffer: dst,
            _key: self.key,
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

        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&self.counter.to_le_bytes());
        let plaintext = self
            .key
            .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(&[]), buf)
            .map_err(|_| Error::InvalidAeadTag)?;

        Ok(plaintext.len())
    }
}

/// A data message decrypted by [`PendingDecapsulate::decrypt`], to be committed to the
/// [`Tunnel`](crate::Tunnel) with [`Tunnel::commit_decrypted`](crate::Tunnel::commit_decrypted).
#[derive(Debug)]
#[must_use = "the data message is not accepted until it is committed to the `Tunnel`"]
pub struct Decrypted<B> {
    pub(crate) receiving_index: Index,
    pub(crate) counter: u64,
    pub(crate) plaintext_len: Result<usize, Error>,
    pub(crate) buffer: B,
    /// Released when the [`Tunnel`](crate::Tunnel) accepts the message, so that decrypting a message
    /// leaves the reference count of the key to the thread that owns the
    /// [`Tunnel`](crate::Tunnel).
    pub(crate) _key: Arc<Key>,
}

/// A session key on a cache line of its own, apart from the reference count of its [`Arc`].
///
/// Threads that only read the key then never contend with the thread updating the count.
pub(crate) type Key = CachePadded<LessSafeKey>;
