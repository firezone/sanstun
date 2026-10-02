use super::index::Index;
use super::{HandshakeInit, HandshakeResponse};
use crate::cookie::Cookies;
use crate::crypto::{aead_chacha20_open, aead_chacha20_seal, b2s_hash, b2s_hmac, b2s_hmac2};
use crate::errors::Error;
use crate::session::Session;
use crate::tai64n::{Tai64N, TimeStamper};
use constant_time_eq::constant_time_eq;
use rand::rngs::StdRng;
use std::fmt::Debug;
use std::time::{Duration, Instant};
use x25519_dalek::{PublicKey, StaticSecret};

const KEY_LEN: usize = 32;
const TIMESTAMP_LEN: usize = 12;

// initiator.chaining_key = HASH(CONSTRUCTION)
const INITIAL_CHAIN_KEY: [u8; KEY_LEN] = [
    96, 226, 109, 174, 243, 39, 239, 192, 46, 195, 53, 226, 160, 37, 210, 208, 22, 235, 66, 6, 248,
    114, 119, 245, 45, 56, 209, 152, 139, 120, 205, 54,
];

// initiator.chaining_hash = HASH(initiator.chaining_key || IDENTIFIER)
const INITIAL_CHAIN_HASH: [u8; KEY_LEN] = [
    34, 17, 179, 97, 8, 26, 197, 102, 105, 18, 67, 219, 69, 138, 213, 50, 45, 156, 108, 102, 34,
    147, 232, 183, 14, 225, 156, 101, 186, 7, 158, 243,
];

/// Parameters used by the noise protocol
struct NoiseParams {
    /// Our static public key
    static_public: PublicKey,
    /// Our static private key
    static_private: StaticSecret,
    /// Static public key of the other party
    peer_static_public: PublicKey,
    /// A shared key = DH(static_private, peer_static_public)
    static_shared: x25519_dalek::SharedSecret,
    /// A preshared key.
    ///
    /// Initialized to all zeroes by default.
    preshared_key: StaticSecret,
}

impl std::fmt::Debug for NoiseParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseParams")
            .field("static_public", &self.static_public)
            .field("static_private", &"<redacted>")
            .field("peer_static_public", &self.peer_static_public)
            .field("static_shared", &"<redacted>")
            .field("preshared_key", &"<redacted>")
            .finish()
    }
}

struct HandshakeInitSentState {
    local_index: Index,
    hash: [u8; KEY_LEN],
    chaining_key: [u8; KEY_LEN],
    ephemeral_private: x25519_dalek::ReusableSecret,
    time_sent: Instant,
}

impl std::fmt::Debug for HandshakeInitSentState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeInitSentState")
            .field("local_index", &self.local_index)
            .field("hash", &self.hash)
            .field("chaining_key", &self.chaining_key)
            .field("ephemeral_private", &"<redacted>")
            .field("time_sent", &self.time_sent)
            .finish()
    }
}

#[derive(Debug)]
enum HandshakeState {
    /// No handshake in process
    None,
    /// We initiated the handshake
    InitSent(HandshakeInitSentState),
    /// Handshake was established too long ago (implies no handshake is in progress)
    Expired,
}

pub(crate) struct Handshake {
    params: NoiseParams,
    /// Index of the next session
    next_index: Index,
    /// Allow to have two outgoing handshakes in flight, because sometimes we may receive a delayed response to a handshake with bad networks
    previous: HandshakeState,
    /// Current handshake state
    state: HandshakeState,
    pub(crate) cookies: Cookies,
    /// The timestamp of the last handshake we received
    last_handshake_timestamp: Tai64N,
    stamper: TimeStamper,
}

#[derive(Debug)]
pub struct HalfHandshake {
    pub peer_static_public: [u8; 32],
}

pub fn parse_handshake_anon(
    static_private: &StaticSecret,
    static_public: &PublicKey,
    packet: &HandshakeInit,
) -> Result<HalfHandshake, Error> {
    let InitiatorStatic {
        peer_static_public, ..
    } = decrypt_initiator_static(static_private, static_public, packet)?;

    Ok(HalfHandshake { peer_static_public })
}

/// The responder's handshake state after decrypting the initiator's static public key.
struct InitiatorStatic {
    chaining_key: [u8; KEY_LEN],
    hash: [u8; KEY_LEN],
    peer_ephemeral_public: PublicKey,
    peer_static_public: [u8; KEY_LEN],
}

fn decrypt_initiator_static(
    static_private: &StaticSecret,
    static_public: &PublicKey,
    packet: &HandshakeInit,
) -> Result<InitiatorStatic, Error> {
    // initiator.chaining_key = HASH(CONSTRUCTION)
    let mut chaining_key = INITIAL_CHAIN_KEY;
    // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
    let mut hash = INITIAL_CHAIN_HASH;
    hash = b2s_hash(&hash, static_public.as_bytes());
    // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
    let peer_ephemeral_public = PublicKey::from(*packet.unencrypted_ephemeral);
    // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
    hash = b2s_hash(&hash, peer_ephemeral_public.as_bytes());
    // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
    // initiator.chaining_key = HMAC(temp, 0x1)
    chaining_key = b2s_hmac(
        &b2s_hmac(&chaining_key, peer_ephemeral_public.as_bytes()),
        &[0x01],
    );
    // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
    let ephemeral_shared = static_private.diffie_hellman(&peer_ephemeral_public);
    let temp = b2s_hmac(&chaining_key, &ephemeral_shared.to_bytes());
    // initiator.chaining_key = HMAC(temp, 0x1)
    chaining_key = b2s_hmac(&temp, &[0x01]);
    // key = HMAC(temp, initiator.chaining_key || 0x2)
    let key = b2s_hmac2(&temp, &chaining_key, &[0x02]);

    let mut peer_static_public = [0u8; KEY_LEN];
    // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
    aead_chacha20_open(
        &mut peer_static_public,
        &key,
        0,
        packet.encrypted_static,
        &hash,
    )?;

    Ok(InitiatorStatic {
        chaining_key,
        hash,
        peer_ephemeral_public,
        peer_static_public,
    })
}

/// Returns `(initiator.sending_key, initiator.receiving_key)` for the final chaining key.
fn derive_transport_keys(chaining_key: &[u8; KEY_LEN]) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    // temp1 = HMAC(initiator.chaining_key, [empty])
    // temp2 = HMAC(temp1, 0x1)
    // temp3 = HMAC(temp1, temp2 || 0x2)
    // initiator.sending_key = temp2
    // initiator.receiving_key = temp3
    // initiator.sending_key_counter = 0
    // initiator.receiving_key_counter = 0
    let temp1 = b2s_hmac(chaining_key, &[]);
    let temp2 = b2s_hmac(&temp1, &[0x01]);
    let temp3 = b2s_hmac2(&temp1, &temp2, &[0x02]);

    (temp2, temp3)
}

impl NoiseParams {
    /// New noise params struct from our secret key, peers public key, and optional preshared key
    fn new(
        static_private: StaticSecret,
        static_public: PublicKey,
        peer_static_public: PublicKey,
        preshared_key: Option<StaticSecret>,
    ) -> NoiseParams {
        let static_shared = static_private.diffie_hellman(&peer_static_public);

        NoiseParams {
            static_public,
            static_private,
            peer_static_public,
            static_shared,
            preshared_key: preshared_key.unwrap_or_else(|| StaticSecret::from([0u8; 32])),
        }
    }
}

impl Handshake {
    pub(crate) fn new(
        static_private: StaticSecret,
        static_public: PublicKey,
        peer_static_public: PublicKey,
        global_idx: Index,
        preshared_key: Option<x25519_dalek::StaticSecret>,
        unix_instant: Instant,
        unix: Duration,
    ) -> Handshake {
        let params = NoiseParams::new(
            static_private,
            static_public,
            peer_static_public,
            preshared_key,
        );

        Handshake {
            params,
            next_index: global_idx,
            previous: HandshakeState::None,
            state: HandshakeState::None,
            last_handshake_timestamp: Tai64N::zero(),
            stamper: TimeStamper::new(unix_instant, unix),
            cookies: Cookies::new(&peer_static_public),
        }
    }

    pub(crate) fn remote_static_public(&self) -> PublicKey {
        self.params.peer_static_public
    }

    pub(crate) fn preshared_key(&self) -> &StaticSecret {
        &self.params.preshared_key
    }

    pub(crate) fn is_in_progress(&self) -> bool {
        matches!(self.state, HandshakeState::InitSent(_))
    }

    pub(crate) fn in_flight_initiation(&self) -> Option<(Instant, Index)> {
        match self.state {
            HandshakeState::InitSent(HandshakeInitSentState {
                time_sent,
                local_index,
                ..
            }) => Some((time_sent, local_index)),
            _ => None,
        }
    }

    pub(crate) fn set_expired(&mut self) {
        self.previous = HandshakeState::Expired;
        self.state = HandshakeState::Expired;
    }

    pub(crate) fn is_expired(&self) -> bool {
        matches!(self.state, HandshakeState::Expired)
    }

    pub(super) fn receive_handshake_initialization(
        &mut self,
        packet: HandshakeInit,
        rng: &mut StdRng,
        now: Instant,
    ) -> Result<([u8; super::HANDSHAKE_RESP_SZ], Session), Error> {
        let InitiatorStatic {
            mut chaining_key,
            mut hash,
            peer_ephemeral_public,
            peer_static_public: peer_static_public_decrypted,
        } = decrypt_initiator_static(
            &self.params.static_private,
            &self.params.static_public,
            &packet,
        )?;
        // msg.sender_index = little_endian(initiator.sender_index)
        let peer_index = packet.sender_idx;

        if !constant_time_eq(
            self.params.peer_static_public.as_bytes(),
            &peer_static_public_decrypted,
        ) {
            return Err(Error::WrongKey);
        }

        // initiator.hash = HASH(initiator.hash || msg.encrypted_static)
        hash = b2s_hash(&hash, packet.encrypted_static);
        // temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
        let temp = b2s_hmac(&chaining_key, self.params.static_shared.as_bytes());
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        let key = b2s_hmac2(&temp, &chaining_key, &[0x02]);
        // msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
        let mut timestamp = [0u8; TIMESTAMP_LEN];
        aead_chacha20_open(&mut timestamp, &key, 0, packet.encrypted_timestamp, &hash)?;

        let timestamp = Tai64N::parse(&timestamp);

        tracing::debug!(new_handshake_ts = %timestamp, last_handshake_ts = %self.last_handshake_timestamp);

        if !timestamp.after(&self.last_handshake_timestamp) {
            // Possibly a replay
            return Err(Error::WrongTai64nTimestamp);
        }
        self.last_handshake_timestamp = timestamp;

        // initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
        hash = b2s_hash(&hash, packet.encrypted_timestamp);

        let response = self.format_handshake_response(
            hash,
            chaining_key,
            peer_ephemeral_public,
            peer_index,
            rng,
            now,
        );

        Ok(response)
    }

    pub(super) fn receive_handshake_response(
        &mut self,
        packet: HandshakeResponse,
        now: Instant,
    ) -> Result<Session, Error> {
        // Check if there is a handshake awaiting a response and return the correct one
        let (state, is_previous) = match (&self.state, &self.previous) {
            (HandshakeState::InitSent(s), _)
                if s.local_index == Index::from_peer(packet.receiver_idx) =>
            {
                (s, false)
            }
            (_, HandshakeState::InitSent(s))
                if s.local_index == Index::from_peer(packet.receiver_idx) =>
            {
                (s, true)
            }
            _ => return Err(Error::UnexpectedPacket),
        };

        let peer_index = packet.sender_idx;
        let local_index = state.local_index;

        let unencrypted_ephemeral = PublicKey::from(*packet.unencrypted_ephemeral);
        // msg.unencrypted_ephemeral = DH_PUBKEY(responder.ephemeral_private)
        // responder.hash = HASH(responder.hash || msg.unencrypted_ephemeral)
        let mut hash = b2s_hash(&state.hash, unencrypted_ephemeral.as_bytes());
        // temp = HMAC(responder.chaining_key, msg.unencrypted_ephemeral)
        let temp = b2s_hmac(&state.chaining_key, unencrypted_ephemeral.as_bytes());
        // responder.chaining_key = HMAC(temp, 0x1)
        let mut chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.ephemeral_public))
        let ephemeral_shared = state
            .ephemeral_private
            .diffie_hellman(&unencrypted_ephemeral);
        let temp = b2s_hmac(&chaining_key, &ephemeral_shared.to_bytes());
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.static_public))
        let temp = b2s_hmac(
            &chaining_key,
            &self
                .params
                .static_private
                .diffie_hellman(&unencrypted_ephemeral)
                .to_bytes(),
        );
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, preshared_key)
        let temp = b2s_hmac(&chaining_key, self.params.preshared_key.as_bytes());
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp2 = HMAC(temp, responder.chaining_key || 0x2)
        let temp2 = b2s_hmac2(&temp, &chaining_key, &[0x02]);
        // key = HMAC(temp, temp2 || 0x3)
        let key = b2s_hmac2(&temp, &temp2, &[0x03]);
        // responder.hash = HASH(responder.hash || temp2)
        hash = b2s_hash(&hash, &temp2);
        // msg.encrypted_nothing = AEAD(key, 0, [empty], responder.hash)
        aead_chacha20_open(&mut [], &key, 0, packet.encrypted_nothing, &hash)?;

        // responder.hash = HASH(responder.hash || msg.encrypted_nothing)
        // hash = b2s_hash(hash, buf[ENC_NOTHING_OFF..ENC_NOTHING_OFF + ENC_NOTHING_SZ]);

        let (temp2, temp3) = derive_transport_keys(&chaining_key);

        if is_previous {
            self.previous = HandshakeState::None;
        } else {
            self.state = HandshakeState::None;
        }
        Ok(Session::new(
            local_index,
            Index::from_peer(peer_index),
            temp3,
            temp2,
            now,
        ))
    }

    pub(super) fn format_handshake_initiation(
        &mut self,
        rng: &mut StdRng,
        now: Instant,
    ) -> ([u8; super::HANDSHAKE_INIT_SZ], Index) {
        let mut dst = [0u8; super::HANDSHAKE_INIT_SZ];

        let (message_type, rest) = dst.split_at_mut(4);
        let (sender_index, rest) = rest.split_at_mut(4);
        let (unencrypted_ephemeral, rest) = rest.split_at_mut(32);
        let (encrypted_static, rest) = rest.split_at_mut(32 + 16);
        let (encrypted_timestamp, _) = rest.split_at_mut(12 + 16);

        let local_index = self.next_index.wrapping_increment();

        // initiator.chaining_key = HASH(CONSTRUCTION)
        let mut chaining_key = INITIAL_CHAIN_KEY;
        // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
        let mut hash = INITIAL_CHAIN_HASH;
        hash = b2s_hash(&hash, self.params.peer_static_public.as_bytes());
        // initiator.ephemeral_private = DH_GENERATE()
        let ephemeral_private = x25519_dalek::ReusableSecret::random_from_rng(rng);
        // msg.message_type = 1
        // msg.reserved_zero = { 0, 0, 0 }
        message_type.copy_from_slice(&super::HANDSHAKE_INIT.to_le_bytes());
        // msg.sender_index = little_endian(initiator.sender_index)
        sender_index.copy_from_slice(&local_index.to_le_bytes());
        // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
        unencrypted_ephemeral.copy_from_slice(PublicKey::from(&ephemeral_private).as_bytes());
        // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
        hash = b2s_hash(&hash, unencrypted_ephemeral);
        // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&b2s_hmac(&chaining_key, unencrypted_ephemeral), &[0x01]);
        // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
        let ephemeral_shared = ephemeral_private.diffie_hellman(&self.params.peer_static_public);
        let temp = b2s_hmac(&chaining_key, &ephemeral_shared.to_bytes());
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        let key = b2s_hmac2(&temp, &chaining_key, &[0x02]);
        // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
        aead_chacha20_seal(
            encrypted_static,
            &key,
            0,
            self.params.static_public.as_bytes(),
            &hash,
        );
        // initiator.hash = HASH(initiator.hash || msg.encrypted_static)
        hash = b2s_hash(&hash, encrypted_static);
        // temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
        let temp = b2s_hmac(&chaining_key, self.params.static_shared.as_bytes());
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        let key = b2s_hmac2(&temp, &chaining_key, &[0x02]);
        // msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
        let timestamp = self.stamper.stamp(now);
        aead_chacha20_seal(encrypted_timestamp, &key, 0, &timestamp, &hash);
        // initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
        hash = b2s_hash(&hash, encrypted_timestamp);

        self.previous = std::mem::replace(
            &mut self.state,
            HandshakeState::InitSent(HandshakeInitSentState {
                local_index,
                chaining_key,
                hash,
                ephemeral_private,
                time_sent: now,
            }),
        );

        self.cookies.append_mac1_and_mac2(local_index, &mut dst);

        (dst, local_index)
    }

    fn format_handshake_response(
        &mut self,
        mut hash: [u8; KEY_LEN],
        mut chaining_key: [u8; KEY_LEN],
        peer_ephemeral_public: PublicKey,
        peer_index: u32,
        rng: &mut StdRng,
        now: Instant,
    ) -> ([u8; super::HANDSHAKE_RESP_SZ], Session) {
        let mut dst = [0u8; super::HANDSHAKE_RESP_SZ];

        let (message_type, rest) = dst.split_at_mut(4);
        let (sender_index, rest) = rest.split_at_mut(4);
        let (receiver_index, rest) = rest.split_at_mut(4);
        let (unencrypted_ephemeral, rest) = rest.split_at_mut(32);
        let (encrypted_nothing, _) = rest.split_at_mut(16);

        // responder.ephemeral_private = DH_GENERATE()
        let ephemeral_private = x25519_dalek::ReusableSecret::random_from_rng(rng);
        let local_index = self.next_index.wrapping_increment();
        // msg.message_type = 2
        // msg.reserved_zero = { 0, 0, 0 }
        message_type.copy_from_slice(&super::HANDSHAKE_RESP.to_le_bytes());
        // msg.sender_index = little_endian(responder.sender_index)
        sender_index.copy_from_slice(&local_index.to_le_bytes());
        // msg.receiver_index = little_endian(initiator.sender_index)
        receiver_index.copy_from_slice(&peer_index.to_le_bytes());
        // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
        unencrypted_ephemeral.copy_from_slice(PublicKey::from(&ephemeral_private).as_bytes());
        // responder.hash = HASH(responder.hash || msg.unencrypted_ephemeral)
        hash = b2s_hash(&hash, unencrypted_ephemeral);
        // temp = HMAC(responder.chaining_key, msg.unencrypted_ephemeral)
        let temp = b2s_hmac(&chaining_key, unencrypted_ephemeral);
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.ephemeral_public))
        let ephemeral_shared = ephemeral_private.diffie_hellman(&peer_ephemeral_public);
        let temp = b2s_hmac(&chaining_key, &ephemeral_shared.to_bytes());
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.static_public))
        let temp = b2s_hmac(
            &chaining_key,
            &ephemeral_private
                .diffie_hellman(&self.params.peer_static_public)
                .to_bytes(),
        );
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, preshared_key)
        let temp = b2s_hmac(&chaining_key, self.params.preshared_key.as_bytes());
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp2 = HMAC(temp, responder.chaining_key || 0x2)
        let temp2 = b2s_hmac2(&temp, &chaining_key, &[0x02]);
        // key = HMAC(temp, temp2 || 0x3)
        let key = b2s_hmac2(&temp, &temp2, &[0x03]);
        // responder.hash = HASH(responder.hash || temp2)
        hash = b2s_hash(&hash, &temp2);
        // msg.encrypted_nothing = AEAD(key, 0, [empty], responder.hash)
        aead_chacha20_seal(encrypted_nothing, &key, 0, &[], &hash);

        let (temp2, temp3) = derive_transport_keys(&chaining_key);

        self.cookies.append_mac1_and_mac2(local_index, &mut dst);

        (
            dst,
            Session::new(local_index, Index::from_peer(peer_index), temp2, temp3, now),
        )
    }
}
