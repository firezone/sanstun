//! A sans-IO implementation of the WireGuard protocol, acting as both initiator and responder.

mod crypto;
mod errors;
mod handshake;
mod index;
mod ingress;
mod message;
mod replay;
mod session;
mod tai64n;
mod timers;

pub use errors::Error;
pub use index::Index;
pub use ingress::{Ingress, Received};
pub use message::{
    CookieReplyMessage, DataMessage, HandshakeInit, HandshakeInitiationMessage, HandshakeResponse,
    HandshakeResponseMessage, KeepaliveMessage, Packet, PacketCookieReply, PacketData,
};
pub use session::{Decrypted, PendingDecapsulate, PendingEncapsulate};
pub use x25519_dalek::{PublicKey, StaticSecret};

use crate::handshake::Handshake;
use crate::message::DATA_OVERHEAD_SZ;
use crate::session::Sessions;
use crate::timers::{TimerName, Timers};

use rand::SeedableRng;
use rand::rngs::StdRng;

use std::collections::VecDeque;
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
    events: VecDeque<Event>,
}

impl Tunnel {
    pub fn is_expired(&self) -> bool {
        self.handshake.is_expired()
    }

    /// Create a new tunnel using own private key and the peer public key
    ///
    /// `rng_seed` must come from a cryptographically secure source because key material is derived from it.
    #[expect(clippy::too_many_arguments, reason = "We don't care that much.")]
    pub fn new(
        static_private: StaticSecret,
        peer_static_public: PublicKey,
        preshared_key: Option<StaticSecret>,
        persistent_keepalive: Option<u16>,
        index: Index,
        rng_seed: [u8; 32],
        now: Instant,
        unix_instant: Instant,
        unix: Duration,
    ) -> Self {
        let static_public = PublicKey::from(&static_private);

        Tunnel {
            handshake: Handshake::new(
                static_private,
                static_public,
                peer_static_public,
                index,
                preshared_key,
                unix_instant,
                unix,
            ),
            sessions: Sessions::default(),
            timers: Timers::new(persistent_keepalive, now),
            rng: StdRng::from_seed(rng_seed),
            events: VecDeque::new(),
        }
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
        let is_responder = self.timers.is_responder();

        self.sessions
            .current_mut()
            .filter(|s| s.can_send())
            .filter(|s| s.should_use_at(now) || is_responder)
    }

    /// Handles a message received from the network, as returned by [`Ingress::receive`].
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
            Packet::PacketData(p) => return self.handle_data(p).map(Some),
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

        let (packet, session) =
            self.handshake
                .receive_handshake_initialization(p, &mut self.rng, now)?;

        // Store new session in ring buffer
        let local_idx = self.sessions.insert(session);

        self.timers.tick(TimerName::TimeLastPacketReceived, now);
        self.timers.tick(TimerName::TimeLastPacketSent, now);
        self.timers.session_established(false, now); // New session established, we are not the initiator

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
        tracing::debug!(
            local_idx = %Index::from_peer(p.receiver_idx),
            remote_idx = %Index::from_peer(p.sender_idx),
            "Received handshake_response"
        );

        let session = self.handshake.receive_handshake_response(p, now)?;

        // Store new session in ring buffer
        let local_idx = self.sessions.insert(session);

        self.timers.tick(TimerName::TimeLastPacketReceived, now);
        self.timers.session_established(true, now); // New session established, we are the initiator
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

    fn handle_data(&self, packet: PacketData) -> Result<PendingDecapsulate, Error> {
        let remote_idx = Index::from_peer(packet.receiver_idx);

        let session = self.sessions.in_slot_of(remote_idx).ok_or_else(|| {
            tracing::trace!(%remote_idx, "No current session available");
            Error::NoCurrentSession
        })?;

        session.prepare_receive_packet_data(packet)
    }

    /// Formats a new handshake initiation message. If force_resend is true will send
    /// a new handshake, even if a handshake is already in progress (for example when a handshake times out)
    ///
    /// Returns `None` if no handshake initiation needs to be sent.
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

        let (packet, local_idx) = self
            .handshake
            .format_handshake_initiation(&mut self.rng, now);

        tracing::debug!(%local_idx, "Sending handshake_initiation");

        if starting_new_handshake {
            self.timers.tick(TimerName::TimeLastHandshakeStarted, now);
        }
        self.timers.tick(TimerName::TimeLastPacketSent, now);

        Some(HandshakeInitiationMessage(packet))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timers::{MAX_JITTER, REJECT_AFTER_MESSAGES, REKEY_AFTER_MESSAGES};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    const BUF: usize = 256;
    const SRC_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 51820);

    #[test]
    fn responder_rekeys_after_messages() {
        let mut now = Instant::now();
        let (mut a, mut b) = connected(now);
        set_sent_messages(&mut b.tunn, REKEY_AFTER_MESSAGES - 1);

        assert_ne!(b.tunn.poll_timeout().unwrap().1, "rekey-after-messages");
        let datagram = send(&mut b.tunn, now).unwrap();
        receive(&mut a, &datagram, now).unwrap();
        assert_eq!(
            b.tunn.poll_timeout().unwrap(),
            (now, "rekey-after-messages")
        );

        b.tunn.handle_timeout(now);
        assert!(b.tunn.poll_event().is_none());
        now += MAX_JITTER;
        b.tunn.handle_timeout(now);
        let Some(Event::HandshakeInitiation(init)) = b.tunn.poll_event() else {
            panic!("expected a handshake initiation");
        };

        let response = expect_response(&mut a, &init, now);
        assert!(decapsulate(&mut b, &response, now).unwrap().is_none());
        let Some(Event::KeepaliveDue(_)) = b.tunn.poll_event() else {
            panic!("expected a due keepalive");
        };
        let datagram = send(&mut b.tunn, now).unwrap();
        assert_eq!(u64::from_le_bytes(datagram[8..16].try_into().unwrap()), 0);
        receive(&mut a, &datagram, now).unwrap();
    }

    #[test]
    fn exhausted_session_refuses_to_send() {
        let now = Instant::now();
        let (mut a, mut b) = connected(now);
        set_sent_messages(&mut a.tunn, REJECT_AFTER_MESSAGES - 1);

        let last = send(&mut a.tunn, now).unwrap();
        receive(&mut b, &last, now).unwrap();

        assert!(matches!(
            send(&mut a.tunn, now),
            Err(Error::NoCurrentSession)
        ));
        assert!(matches!(
            a.tunn.encapsulate_keepalive(Keepalive, now),
            Err(Error::NoCurrentSession)
        ));
    }

    #[test]
    fn data_message_with_a_counter_beyond_the_limit_is_rejected() {
        let now = Instant::now();
        let (mut a, mut b) = connected(now);

        for counter in [REJECT_AFTER_MESSAGES, u64::MAX] {
            let mut datagram = send(&mut a.tunn, now).unwrap();
            datagram[8..16].copy_from_slice(&counter.to_le_bytes());

            assert!(matches!(
                receive(&mut b, &datagram, now),
                Err(Error::InvalidCounter)
            ));
        }

        let datagram = send(&mut a.tunn, now).unwrap();
        receive(&mut b, &datagram, now).unwrap();
    }

    /// A [`Tunnel`] together with the [`Ingress`] for its static key.
    struct Peer {
        tunn: Tunnel,
        ingress: Ingress,
    }

    /// Establishes a session with `a` as the initiator, confirmed to `b` by a keepalive.
    fn connected(now: Instant) -> (Peer, Peer) {
        let secret_a = StaticSecret::from([1; 32]);
        let secret_b = StaticSecret::from([2; 32]);
        let unix = Duration::from_secs(1_700_000_000);
        let mut a = Peer {
            tunn: Tunnel::new(
                secret_a.clone(),
                PublicKey::from(&secret_b),
                None,
                None,
                Index::new_local(1),
                [1; 32],
                now,
                now,
                unix,
            ),
            ingress: Ingress::new(secret_a.clone(), u64::MAX, [3; 32], now),
        };
        let mut b = Peer {
            tunn: Tunnel::new(
                secret_b.clone(),
                PublicKey::from(&secret_a),
                None,
                None,
                Index::new_local(2),
                [2; 32],
                now,
                now,
                unix,
            ),
            ingress: Ingress::new(secret_b, u64::MAX, [4; 32], now),
        };

        let init = a.tunn.format_handshake_initiation(false, now).unwrap();
        let response = expect_response(&mut b, &init, now);
        assert!(decapsulate(&mut a, &response, now).unwrap().is_none());
        let Some(Event::KeepaliveDue(keepalive)) = a.tunn.poll_event() else {
            panic!("expected a due keepalive");
        };
        let keepalive = a.tunn.encapsulate_keepalive(keepalive, now).unwrap();
        receive(&mut b, &keepalive, now).unwrap();

        (a, b)
    }

    fn expect_response(peer: &mut Peer, init: &[u8], now: Instant) -> HandshakeResponseMessage {
        assert!(decapsulate(peer, init, now).unwrap().is_none());
        match peer.tunn.poll_event() {
            Some(Event::HandshakeResponse(response)) => response,
            other => panic!("expected a handshake response, got {other:?}"),
        }
    }

    fn receive(peer: &mut Peer, datagram: &[u8], now: Instant) -> Result<(), Error> {
        let pending = decapsulate(peer, datagram, now)?.expect("a data message");
        let decrypted = pending.decrypt(datagram, vec![0; BUF]);
        peer.tunn.commit_decrypted(decrypted, now)?;

        Ok(())
    }

    fn decapsulate(
        peer: &mut Peer,
        datagram: &[u8],
        now: Instant,
    ) -> Result<Option<PendingDecapsulate>, Error> {
        let Received::Packet(packet) = peer.ingress.receive(SRC_ADDR, datagram, now)? else {
            panic!("expected a packet");
        };

        peer.tunn.decapsulate(packet, now)
    }

    fn send(tunn: &mut Tunnel, now: Instant) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0; BUF];
        let message = tunn.encapsulate_data(now)?.encrypt(b"data", &mut buf)?;

        Ok(message.to_vec())
    }

    fn set_sent_messages(tunn: &mut Tunnel, sent: u64) {
        tunn.sessions.current_mut().unwrap().set_sent_messages(sent);
    }
}
