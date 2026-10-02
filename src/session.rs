use super::{
    index::Index,
    timers::{REJECT_AFTER_TIME, SHOULD_NOT_USE_AFTER_TIME},
    PacketData,
};
use crate::errors::Error;
use crate::DataMessage;
use crossbeam_utils::CachePadded;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
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

// Receiving buffer constants
const WORD_SIZE: u64 = 64;
const N_WORDS: u64 = 128; // Suffice to reorder 128*16 = 8192 packets; can be increased at will
const N_BITS: u64 = WORD_SIZE * N_WORDS;

#[derive(Debug, Clone)]
struct ReceivingKeyCounterValidator {
    /// In order to avoid replays while allowing for some reordering of the packets, we keep a
    /// bitmap of received packets, and the value of the highest counter
    next: u64,
    bitmap: [u64; N_WORDS as usize],
}

impl Default for ReceivingKeyCounterValidator {
    fn default() -> Self {
        Self {
            next: Default::default(),
            bitmap: [0; _],
        }
    }
}

impl ReceivingKeyCounterValidator {
    #[inline(always)]
    fn set_bit(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        self.bitmap[word] |= 1 << bit;
    }

    #[inline(always)]
    fn clear_bit(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        self.bitmap[word] &= !(1u64 << bit);
    }

    /// Clear the word that contains idx
    #[inline(always)]
    fn clear_word(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        self.bitmap[word] = 0;
    }

    /// Returns true if bit is set, false otherwise
    #[inline(always)]
    fn check_bit(&self, idx: u64) -> bool {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        ((self.bitmap[word] >> bit) & 1) == 1
    }

    /// Returns true if the counter was not yet received, and is not too far back
    #[inline(always)]
    fn will_accept(&self, counter: u64) -> Result<(), Error> {
        if counter >= self.next {
            // As long as the counter is growing no replay took place for sure
            return Ok(());
        }
        if counter + N_BITS < self.next {
            // Drop if too far back
            return Err(Error::InvalidCounter);
        }
        if !self.check_bit(counter) {
            Ok(())
        } else {
            Err(Error::DuplicateCounter)
        }
    }

    /// Marks the counter as received, and returns true if it is still good (in case during
    /// decryption something changed)
    #[inline(always)]
    fn mark_did_receive(&mut self, counter: u64) -> Result<(), Error> {
        if counter + N_BITS < self.next {
            // Drop if too far back
            return Err(Error::InvalidCounter);
        }
        if counter == self.next {
            // Usually the packets arrive in order, in that case we simply mark the bit and
            // increment the counter
            self.set_bit(counter);
            self.next += 1;
            return Ok(());
        }
        if counter < self.next {
            // A packet arrived out of order, check if it is valid, and mark
            if self.check_bit(counter) {
                return Err(Error::DuplicateCounter);
            }
            self.set_bit(counter);
            return Ok(());
        }
        // Packets where dropped, or maybe reordered, skip them and mark unused
        if counter - self.next >= N_BITS {
            // Too far ahead, clear all the bits
            for c in self.bitmap.iter_mut() {
                *c = 0;
            }
        } else {
            let mut i = self.next;
            while !i.is_multiple_of(WORD_SIZE) && i < counter {
                // Clear until i aligned to word size
                self.clear_bit(i);
                i += 1;
            }
            while i + WORD_SIZE < counter {
                // Clear whole word at a time
                self.clear_word(i);
                i = (i + WORD_SIZE) & 0u64.wrapping_sub(WORD_SIZE);
            }
            while i < counter {
                // Clear any remaining bits
                self.clear_bit(i);
                i += 1;
            }
        }
        self.set_bit(counter);
        self.next = counter + 1;
        Ok(())
    }
}

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

    /// Returns true if receiving counter is good to use
    fn receiving_counter_quick_check(&self, counter: u64) -> Result<(), Error> {
        self.receiving_key_counter.will_accept(counter)
    }

    /// Returns true if receiving counter is good to use, and marks it as used {
    fn receiving_counter_mark(&mut self, counter: u64) -> Result<(), Error> {
        self.receiving_key_counter.mark_did_receive(counter)
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
        self.receiving_counter_quick_check(packet.counter)?;

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
        self.receiving_counter_mark(counter)?;

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
