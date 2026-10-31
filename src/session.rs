use super::{
    index::{Index, TunnelId},
    timers::{REJECT_AFTER_MESSAGES, REJECT_AFTER_TIME, REKEY_AFTER_MESSAGES, REKEY_AFTER_TIME},
};
use crate::crypto::nonce;
use crate::errors::Error;
use crate::message::{AEAD_TAG_SZ, DATA, DATA_HEADER_SZ, DataMessage, TransportData};
use crate::replay::ReceivingKeyCounterValidator;
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub(crate) struct Session {
    id: SessionId,
    established_at: Instant,
    role: Role,
    sent_data: bool,
    received_data: bool,
    receiving_index: Index,
    sending_index: Index,
    receiver: SessionKey,
    sender: SessionKey,
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

/// Identifies a session of a tunnel even after its index has been reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionId(u64);

/// Our role in the handshake that established a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Initiator,
    Responder,
}

/// The block size used for zero-padding data messages.
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
            id: SessionId(0),
            established_at: now,
            role,
            sent_data: false,
            received_data: false,
            receiving_index: local_index,
            sending_index: peer_index,
            receiver: SessionKey::new(receiving_key),
            sender: SessionKey::new(sending_key),
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

    /// Returns whether this session has carried outgoing data, excluding keepalives.
    pub(crate) fn sent_data(&self) -> bool {
        self.sent_data
    }

    /// Returns the rekey deadline for an initiator session that has sent data.
    pub(crate) fn rekey_after_time_on_send(&self) -> Option<Instant> {
        if self.role != Role::Initiator || !self.sent_data {
            return None;
        }

        Some(self.established_at + REKEY_AFTER_TIME)
    }

    /// Returns the rekey deadline before expiry for an initiator session that has received data.
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

    /// Returns whether the session has enough time left to send a packet.
    ///
    /// Sending stops `keepalive_timeout` before expiry to allow packets to reach the peer in time.
    pub(crate) fn should_use_at(&self, time: Instant, keepalive_timeout: Duration) -> bool {
        time + keepalive_timeout <= self.established_at + REJECT_AFTER_TIME
    }

    pub(crate) fn id(&self) -> SessionId {
        self.id
    }

    /// Returns whether the sending counter has reached [`REKEY_AFTER_MESSAGES`].
    pub(crate) fn rekey_after_messages_reached(&self) -> bool {
        self.sending_key_counter >= REKEY_AFTER_MESSAGES
    }

    /// Returns whether the sending counter has reached [`REJECT_AFTER_MESSAGES`].
    pub(crate) fn sending_counter_exhausted(&self) -> bool {
        self.sending_key_counter >= REJECT_AFTER_MESSAGES
    }

    /// Starts a batch of data messages whose counters are reserved when it is finished.
    pub(super) fn prepare_packet_data(&mut self) -> EncapsulateBatch<'_> {
        self.sent_data = true;

        EncapsulateBatch { session: self }
    }

    /// Encrypts a keepalive with the next counter into `dst`.
    pub(super) fn encrypt_keepalive(&mut self, dst: &mut [u8]) -> Result<(), Error> {
        let counter = self.reserve_counters(NonZeroUsize::MIN)?;
        encrypt_payload(&self.sender.aead(), self.sending_index, counter, &[], dst)?;

        Ok(())
    }

    /// Reserves `len` consecutive counters and returns the first.
    fn reserve_counters(&mut self, len: NonZeroUsize) -> Result<u64, Error> {
        let first = self.sending_key_counter;
        let end = u64::try_from(len.get())
            .ok()
            .and_then(|len| first.checked_add(len))
            .filter(|end| *end <= REJECT_AFTER_MESSAGES)
            .ok_or(Error::NoCurrentSession)?;
        self.sending_key_counter = end;

        Ok(first)
    }

    /// Starts a batch of received data messages with `packet`.
    pub(super) fn prepare_receive_packet_data(
        &self,
        packet: TransportData,
    ) -> Result<DecapsulateBatch<'_>, Error> {
        let mut batch = DecapsulateBatch {
            session: self,
            counters: Vec::new(),
        };
        batch.increment(packet)?;

        Ok(batch)
    }

    /// Checks a data message's index and counter before decryption.
    fn will_receive(&self, packet: &TransportData) -> Result<(), Error> {
        if Index::from_peer(packet.receiver_idx) != self.receiving_index {
            return Err(Error::WrongIndex);
        }
        // Reject known replays before paying for decryption.
        self.receiving_key_counter.will_accept(packet.counter)
    }

    /// Commits an authenticated message's counter and returns its plaintext length.
    pub(super) fn finish_receive_packet_data<B>(
        &mut self,
        counter: u64,
        plaintext: Result<Plaintext<B>, Error>,
    ) -> Result<Plaintext<B>, Error> {
        let plaintext = plaintext?;

        // Recheck after authentication: another copy may have been accepted during decryption.
        self.receiving_key_counter.mark_did_receive(counter)?;
        self.received_data |= matches!(plaintext, Plaintext::Data { .. });

        Ok(plaintext)
    }
}

const N_SESSIONS: u8 = 8;

/// A ring of recent sessions, indexed by their local session index.
pub(crate) struct Sessions {
    slots: [Option<Session>; N_SESSIONS as usize],
    /// The current sending session's index.
    current: Option<Index>,
    /// The most recently allocated local index.
    last_index: Index,
    /// The number of sessions inserted so far, which identifies the next one.
    inserted: u64,
}

impl Sessions {
    /// Creates an empty session ring for the tunnel identified by `index`.
    pub(crate) fn new(index: Index) -> Self {
        Self {
            slots: Default::default(),
            current: None,
            last_index: index,
            inserted: 0,
        }
    }

    /// Returns the tunnel ID shared by all local session indices.
    pub(crate) fn tunnel_id(&self) -> TunnelId {
        self.last_index.tunnel_id()
    }

    /// Allocates a local index for a new session.
    ///
    /// Skips the current session's slot so it cannot be overwritten.
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
    pub(crate) fn insert(&mut self, mut session: Session) {
        session.id = SessionId(self.inserted);
        self.inserted += 1;

        let index = session.receiving_index;
        *self.slot_mut(index) = Some(session);
    }

    /// Returns the current sending session, if one exists.
    pub(crate) fn current(&self) -> Option<&Session> {
        self.get(self.current?)
    }

    /// Returns the current session if it is usable for sending.
    pub(crate) fn sending_session(
        &mut self,
        keepalive_timeout: Duration,
        now: Instant,
    ) -> Option<&mut Session> {
        let session = self.get_mut(self.current?)?;

        if session.sending_counter_exhausted() || session.expired_at(now) {
            return None;
        }
        if !session.should_use_at(now, keepalive_timeout) && session.role() == Role::Initiator {
            return None;
        }

        Some(session)
    }

    /// Returns the session in `index`'s slot, which may belong to a different index.
    pub(crate) fn in_slot_of(&self, index: Index) -> Option<&Session> {
        self.slot(index).as_ref()
    }

    /// Returns the session with exactly `index`, if it still exists.
    pub(crate) fn get_mut(&mut self, index: Index) -> Option<&mut Session> {
        self.slot_mut(index)
            .as_mut()
            .filter(|s| s.receiving_index == index)
    }

    /// Selects `new_idx` as the current session unless the current one is newer.
    pub(crate) fn set_current(&mut self, new_idx: Index) {
        if self.current == Some(new_idx) {
            return;
        }

        let Some(new) = self.get(new_idx) else {
            debug_assert!(false, "the selected session must exist");
            return;
        };
        if self
            .current()
            .is_some_and(|current| current.established_at() > new.established_at())
        {
            return;
        }

        self.current = Some(new_idx);
        tracing::debug!(idx = %new_idx, "Selected sending session");
    }

    pub(crate) fn clear(&mut self) {
        for session in &mut self.slots {
            *session = None;
        }
        self.current = None;
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

            let is_current = self.current == Some(session.receiving_index);

            tracing::debug!(
                session = %session.receiving_index,
                %is_current,
                "Session expired (REJECT_AFTER_TIME)"
            );

            if is_current {
                self.current = None;
                expired_current = Some(session);
            }
        }

        expired_current
    }

    /// Returns whether no session is stored, current or not.
    pub(crate) fn is_empty(&self) -> bool {
        self.slots.iter().all(Option::is_none)
    }

    /// Returns the earliest session expiry deadline.
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

/// A batch of data messages to encrypt on the current sending session.
///
/// Borrows the [`Tunnel`](crate::Tunnel) until [`EncapsulateBatch::finish`] reserves the
/// batch's counters, so nothing else can reserve a counter in between.
#[must_use = "no counters are reserved until the batch is finished"]
pub struct EncapsulateBatch<'t> {
    session: &'t mut Session,
}

impl EncapsulateBatch<'_> {
    /// Reserves `len` consecutive counters and releases the tunnel.
    ///
    /// Fails with [`Error::NoCurrentSession`] if the session cannot send `len` more messages
    /// (`REJECT_AFTER_MESSAGES`). No counter is reserved then.
    pub fn finish(self, len: NonZeroUsize) -> Result<PendingEncapsulate, Error> {
        let first_counter = self.session.reserve_counters(len)?;

        Ok(PendingEncapsulate {
            key: self.session.sender.clone(),
            receiver_index: self.session.sending_index,
            first_counter,
            len,
        })
    }
}

/// Data messages ready for encryption, with consecutive counters already reserved.
///
/// The reserved counters fix the nonces, so encryption can run on any thread and in any order.
/// The receiver's replay window allows some reordering of messages.
///
/// This holds the session key even after the session expires. Encrypt and send it promptly.
#[derive(Debug)]
#[must_use = "the data messages are not sent until they are encrypted"]
pub struct PendingEncapsulate {
    key: SessionKey,
    receiver_index: Index,
    first_counter: u64,
    len: NonZeroUsize,
}

#[expect(clippy::len_without_is_empty, reason = "a batch is never empty")]
impl PendingEncapsulate {
    /// Returns the number of reserved counters.
    pub fn len(&self) -> usize {
        self.len.get()
    }

    /// Encrypts each plaintext into a data message at the start of its buffer, as the iterator
    /// is pulled.
    ///
    /// The messages take the reserved counters in order. Encrypting fewer messages than
    /// reserved leaves the remaining counters unused, which the receiver tolerates. Pulling more
    /// is a bug; the iterator ends after the last reserved counter.
    ///
    /// Zero-padding rounds each payload up to a multiple of 16 bytes. Including the header and
    /// tag, a buffer must hold at least `plaintext.len().next_multiple_of(16) + 32` bytes.
    ///
    /// An empty plaintext fails with [`Error::EmptyPlaintext`]. The [`Tunnel`](crate::Tunnel)
    /// sends keepalives itself, as [`Event::SendKeepalive`](crate::Event::SendKeepalive).
    pub fn encrypt<'a, I>(self, messages: I) -> impl Iterator<Item = Result<DataMessage<'a>, Error>>
    where
        I: IntoIterator<Item = (&'a [u8], &'a mut [u8])>,
    {
        let aead = self.key.aead();
        let mut remaining = self.len.get();
        let mut counter = self.first_counter;

        messages.into_iter().map_while(move |(plaintext, dst)| {
            if remaining == 0 {
                debug_assert!(false, "more messages than reserved counters");
                return None;
            }
            remaining -= 1;

            let message = if plaintext.is_empty() {
                Err(Error::EmptyPlaintext)
            } else {
                encrypt_payload(&aead, self.receiver_index, counter, plaintext, dst)
            };
            counter += 1;

            Some(message)
        })
    }
}

fn encrypt_payload<'a>(
    aead: &LessSafeKey,
    receiver_index: Index,
    counter: u64,
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

    header.copy_from_slice(&data_header(receiver_index.to_le_bytes(), counter));

    let (payload, padding) = data.split_at_mut(plaintext.len());
    payload.copy_from_slice(plaintext);
    padding.fill(0);

    let computed_tag = aead
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(nonce(counter)),
            Aad::from(&[]),
            data,
        )
        .expect("plaintext of a data message is always within the AEAD's limits");
    tag.copy_from_slice(computed_tag.as_ref());

    Ok(DataMessage(message))
}

/// A batch of data messages received for one session.
///
/// Borrows the [`Tunnel`](crate::Tunnel) until [`DecapsulateBatch::finish`].
#[must_use = "the data messages are not decrypted until the batch is finished"]
pub struct DecapsulateBatch<'t> {
    session: &'t Session,
    counters: Vec<u64>,
}

impl DecapsulateBatch<'_> {
    /// Adds a data message received for the same session.
    ///
    /// Fails with [`Error::WrongIndex`] for a message of another session; begin a new batch for
    /// it. Fails with [`Error::DuplicateCounter`] or [`Error::InvalidCounter`] if the replay
    /// window already rejects the message's counter. The batch is unchanged on failure.
    pub fn increment(&mut self, message: TransportData) -> Result<(), Error> {
        self.session.will_receive(&message)?;
        self.counters.push(message.counter);

        Ok(())
    }

    /// Releases the tunnel.
    pub fn finish(self) -> PendingDecapsulate {
        PendingDecapsulate {
            key: self.session.receiver.clone(),
            receiving_index: self.session.receiving_index,
            session: self.session.id,
            counters: self.counters,
        }
    }
}

/// Data messages ready for decryption after an initial replay check.
///
/// A counter is only marked as received when its [`Decrypted`] result is committed to the
/// [`Tunnel`](crate::Tunnel). Failed authentication never advances the replay window.
#[derive(Debug)]
#[must_use = "the data messages are not decrypted until `decrypt` is called"]
pub struct PendingDecapsulate {
    key: SessionKey,
    receiving_index: Index,
    session: SessionId,
    counters: Vec<u64>,
}

#[expect(clippy::len_without_is_empty, reason = "a batch is never empty")]
impl PendingDecapsulate {
    /// Returns the number of data messages in the batch.
    pub fn len(&self) -> usize {
        self.counters.len()
    }

    /// Copies the ciphertext of each message to the start of its buffer and decrypts it in place.
    ///
    /// Pass the original data messages in the order they were added to the batch. The results
    /// own their buffers; commit each with
    /// [`Tunnel::commit_decapsulate`](crate::Tunnel::commit_decapsulate) to obtain its
    /// plaintext. A message that fails to decrypt does not affect the others.
    ///
    /// Passing fewer messages than the batch holds drops the rest. Passing more is a bug; the
    /// extra messages are ignored.
    pub fn decrypt<'a, B, I>(self, messages: I) -> DecryptedBatch<B>
    where
        B: AsMut<[u8]>,
        I: IntoIterator<Item = (&'a [u8], B)>,
    {
        let aead = self.key.aead();
        let mut messages = messages.into_iter();
        let mut decrypted = Vec::with_capacity(self.counters.len());

        for &counter in &self.counters {
            let Some((message, mut dst)) = messages.next() else {
                break;
            };
            let plaintext =
                decrypt_in_place(&aead, self.receiving_index, counter, message, dst.as_mut())
                    .map(|len| Plaintext::new(dst, len));

            decrypted.push(Decrypted {
                receiving_index: self.receiving_index,
                session: self.session,
                counter,
                plaintext,
            });
        }
        debug_assert!(
            messages.next().is_none(),
            "more messages than the batch holds"
        );

        DecryptedBatch(decrypted.into_iter())
    }
}

fn decrypt_in_place(
    aead: &LessSafeKey,
    receiving_index: Index,
    counter: u64,
    message: &[u8],
    dst: &mut [u8],
) -> Result<usize, Error> {
    let expected_header = data_header(receiving_index.to_le_bytes(), counter);
    let Some((header, ciphertext)) = message.split_first_chunk::<DATA_HEADER_SZ>() else {
        return Err(Error::InvalidAeadTag);
    };
    if *header != expected_header {
        return Err(Error::InvalidAeadTag);
    }

    let ct_len = ciphertext.len();
    let available = dst.len();

    let Some(buf) = dst.get_mut(..ct_len) else {
        return Err(Error::DestinationBufferTooSmall {
            required: ct_len,
            available,
        });
    };
    buf.copy_from_slice(ciphertext);

    let plaintext = aead
        .open_in_place(
            Nonce::assume_unique_for_key(nonce(counter)),
            Aad::from(&[]),
            buf,
        )
        .map_err(|_| Error::InvalidAeadTag)?;

    Ok(plaintext.len())
}

fn data_header(receiver_index: [u8; 4], counter: u64) -> [u8; DATA_HEADER_SZ] {
    let mut header = [0; DATA_HEADER_SZ];
    header[..4].copy_from_slice(&DATA.to_le_bytes());
    header[4..8].copy_from_slice(&receiver_index);
    header[8..].copy_from_slice(&counter.to_le_bytes());
    header
}

/// The results of decrypting one batch, in the order its messages were added.
#[must_use = "the data messages are not accepted until they are committed to the `Tunnel`"]
pub struct DecryptedBatch<B>(std::vec::IntoIter<Decrypted<B>>);

impl<B> Iterator for DecryptedBatch<B> {
    type Item = Decrypted<B>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl<B> ExactSizeIterator for DecryptedBatch<B> {}

impl<B> std::fmt::Debug for DecryptedBatch<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("DecryptedBatch")
            .field(&self.0.as_slice())
            .finish()
    }
}

/// A decryption result awaiting [`Tunnel::commit_decapsulate`](crate::Tunnel::commit_decapsulate).
#[must_use = "the data message is not accepted until it is committed to the `Tunnel`"]
pub struct Decrypted<B> {
    pub(crate) receiving_index: Index,
    /// Identifies the session the message was decrypted with, even after its index was reused.
    pub(crate) session: SessionId,
    pub(crate) counter: u64,
    pub(crate) plaintext: Result<Plaintext<B>, Error>,
}

impl<B> Decrypted<B> {
    /// The plaintext of a data message that decrypted.
    ///
    /// Decryption proves the message came from the peer with this session's key, but only
    /// [`Tunnel::commit_decapsulate`](crate::Tunnel::commit_decapsulate) checks it against the
    /// replay window and against the session still being current. Until then it may be a replay,
    /// so use it only for work without side effects, such as parsing or prefetching, and act on it
    /// only once it has been committed.
    pub fn plaintext(&self) -> Option<&B> {
        match &self.plaintext {
            Ok(Plaintext::Data { buffer, .. }) => Some(buffer),
            Ok(Plaintext::Keepalive) | Err(_) => None,
        }
    }

    /// Maps the plaintext of a data message before it is committed.
    ///
    /// Work that needs only the plaintext, such as parsing it, can thus happen on the thread that
    /// decrypted the message. The same caveat as for [`Decrypted::plaintext`] applies: the message
    /// has not been committed yet, so `f` must have no side effects.
    pub fn map<C>(self, f: impl FnOnce(B, usize) -> C) -> Decrypted<C> {
        Decrypted {
            receiving_index: self.receiving_index,
            session: self.session,
            counter: self.counter,
            plaintext: self.plaintext.map(|plaintext| match plaintext {
                Plaintext::Keepalive => Plaintext::Keepalive,
                Plaintext::Data { buffer, len } => Plaintext::Data {
                    buffer: f(buffer, len),
                    len,
                },
            }),
        }
    }
}

impl<B> std::fmt::Debug for Decrypted<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Decrypted")
            .field("receiving_index", &self.receiving_index)
            .field("counter", &self.counter)
            .field(
                "plaintext_len",
                &self.plaintext.as_ref().map(|plaintext| plaintext.len()),
            )
            .finish_non_exhaustive()
    }
}

/// The plaintext of a decrypted data message.
pub(crate) enum Plaintext<B> {
    Keepalive,
    /// The first `len` bytes of `buffer`, including any padding.
    Data {
        buffer: B,
        len: usize,
    },
}

impl<B> Plaintext<B> {
    fn new(buffer: B, len: usize) -> Self {
        if len == 0 {
            return Self::Keepalive;
        }

        Self::Data { buffer, len }
    }

    fn len(&self) -> usize {
        match self {
            Self::Keepalive => 0,
            Self::Data { len, .. } => *len,
        }
    }
}

/// The raw key of one direction of a session.
///
/// Pending batches carry a copy, so encrypting and decrypting on other threads shares no memory
/// with the session.
#[derive(Clone)]
pub(crate) struct SessionKey(Zeroizing<[u8; 32]>);

impl SessionKey {
    fn new(key: &[u8; 32]) -> Self {
        Self(Zeroizing::new(*key))
    }

    /// ChaCha20-Poly1305 has no key schedule, so this only copies the key.
    fn aead(&self) -> LessSafeKey {
        LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, &self.0[..]).expect("key has 32 bytes"),
        )
    }
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionKey")
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

        let pending = session
            .prepare_packet_data()
            .finish(NonZeroUsize::MIN)
            .unwrap();

        assert_eq!(pending.first_counter, REJECT_AFTER_MESSAGES - 1);
        assert!(session.sending_counter_exhausted());
    }

    #[test]
    fn batch_beyond_the_message_limit_reserves_nothing() {
        let mut session = session(Index::new_local(0));
        session.sending_key_counter = REJECT_AFTER_MESSAGES - 1;

        let result = session
            .prepare_packet_data()
            .finish(NonZeroUsize::new(2).unwrap());

        assert!(matches!(result, Err(Error::NoCurrentSession)));
        assert_eq!(session.sending_key_counter, REJECT_AFTER_MESSAGES - 1);
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

    #[test]
    fn increment_leaves_the_batch_unchanged_on_failure() {
        let mut session = session(Index::new_local(0));
        session.receiving_key_counter.mark_did_receive(1).unwrap();

        let mut batch = session.prepare_receive_packet_data(data(0, 0)).unwrap();

        assert!(matches!(
            batch.increment(data(1, 2)),
            Err(Error::WrongIndex)
        ));
        assert!(matches!(
            batch.increment(data(0, 1)),
            Err(Error::DuplicateCounter)
        ));
        assert_eq!(batch.counters, [0]);
    }

    #[test]
    fn decrypt_rejects_a_message_with_a_different_header() {
        let session = session(Index::new_local(0));
        let mut message = [0; DATA_HEADER_SZ + 16 + AEAD_TAG_SZ];
        encrypt_payload(
            &session.sender.aead(),
            session.sending_index,
            0,
            b"hello",
            &mut message,
        )
        .unwrap();
        message[8] = 1;

        let pending = session.prepare_receive_packet_data(data(0, 0)).unwrap();
        let decrypted = pending
            .finish()
            .decrypt([(message.as_slice(), [0; 32])])
            .next()
            .unwrap();

        assert!(matches!(decrypted.plaintext, Err(Error::InvalidAeadTag)));
    }

    fn data(receiver_idx: u32, counter: u64) -> TransportData {
        TransportData {
            receiver_idx,
            counter,
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
