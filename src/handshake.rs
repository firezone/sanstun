use super::index::Index;
use super::timers::COOKIE_EXPIRATION_TIME;
use crate::crypto::{
    SharedKey, aead_chacha20_open, aead_chacha20_seal, b2s_hash, b2s_hmac, b2s_hmac2,
    b2s_keyed_mac_16, dh, xaead_open,
};
use crate::errors::Error;
use crate::message::{
    HANDSHAKE_INIT, HANDSHAKE_INIT_SZ, HANDSHAKE_RESP, HANDSHAKE_RESP_SZ, HandshakeInit,
    HandshakeResponse, PacketCookieReply,
};
use crate::session::{Role, Session};
use crate::tai64n::{Tai64N, TimeStamper};
use rand::rngs::StdRng;
use std::fmt::Debug;
use std::time::Instant;
use subtle::ConstantTimeEq as _;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub(crate) const LABEL_MAC1: &[u8; 8] = b"mac1----";
pub(crate) const LABEL_COOKIE: &[u8; 8] = b"cookie--";
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
    static_shared: SharedKey,
    /// A pre-computation of HASH("mac1----", peer_static_public) for this peer
    sending_mac1_key: [u8; KEY_LEN],
    /// A preshared key.
    ///
    /// Initialized to all zeroes by default.
    preshared_key: StaticSecret,
}

impl std::fmt::Debug for NoiseParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseParams")
            .field("static_public", &self.static_public)
            .field("peer_static_public", &self.peer_static_public)
            .field("sending_mac1_key", &self.sending_mac1_key)
            .finish_non_exhaustive()
    }
}

struct HandshakeInitSentState {
    local_index: Index,
    hash: [u8; KEY_LEN],
    chaining_key: Zeroizing<[u8; KEY_LEN]>,
    ephemeral_private: x25519_dalek::ReusableSecret,
    time_sent: Instant,
}

impl std::fmt::Debug for HandshakeInitSentState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeInitSentState")
            .field("local_index", &self.local_index)
            .field("hash", &self.hash)
            .field("time_sent", &self.time_sent)
            .finish_non_exhaustive()
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

/// The handshake(s) currently in progress.
pub(crate) struct Handshake {
    params: NoiseParams,
    /// Allow to have two outgoing handshakes in flight, because sometimes we may receive a delayed response to a handshake with bad networks
    previous: HandshakeState,
    /// Current handshake state
    state: HandshakeState,
    cookies: Cookies,
    stamper: TimeStamper,
}

#[derive(Default)]
struct Cookies {
    last_mac1: Option<[u8; 16]>,
    index: Index,
    write_cookie: Option<WriteCookie>,
}

#[derive(Clone, Copy)]
struct WriteCookie {
    value: [u8; 16],
    received_at: Instant,
}

/// A handshake initiation whose sender proved it holds the claimed static key, with the state the
/// responder needs to answer it.
pub(crate) struct AuthenticatedInitiation {
    chaining_key: Zeroizing<[u8; KEY_LEN]>,
    hash: [u8; KEY_LEN],
    peer_ephemeral_public: PublicKey,
    pub(crate) peer_static_public: PublicKey,
}

/// Authenticates a handshake initiation, returning the responder's handshake state and the
/// initiator's timestamp.
pub(crate) fn authenticate_initiation(
    static_private: &StaticSecret,
    static_public: &PublicKey,
    unencrypted_ephemeral: &[u8; KEY_LEN],
    encrypted_static: &[u8],
    encrypted_timestamp: &[u8],
) -> Result<(AuthenticatedInitiation, Tai64N), Error> {
    // initiator.chaining_key = HASH(CONSTRUCTION)
    let mut chaining_key = Zeroizing::new(INITIAL_CHAIN_KEY);
    // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
    let mut hash = INITIAL_CHAIN_HASH;
    hash = b2s_hash(&hash, static_public.as_bytes());
    // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
    let peer_ephemeral_public = PublicKey::from(*unencrypted_ephemeral);
    // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
    hash = b2s_hash(&hash, peer_ephemeral_public.as_bytes());
    // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
    // initiator.chaining_key = HMAC(temp, 0x1)
    chaining_key = b2s_hmac(
        &b2s_hmac(&chaining_key, peer_ephemeral_public.as_bytes()),
        &[0x01],
    );
    // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
    let ephemeral_shared = dh(static_private, &peer_ephemeral_public)?;
    let temp = b2s_hmac(&chaining_key, ephemeral_shared.as_bytes());
    // initiator.chaining_key = HMAC(temp, 0x1)
    chaining_key = b2s_hmac(&temp, &[0x01]);
    // key = HMAC(temp, initiator.chaining_key || 0x2)
    let key = b2s_hmac2(&temp, &chaining_key, &[0x02]);

    let mut peer_static_public = [0u8; KEY_LEN];
    // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
    aead_chacha20_open(&mut peer_static_public, &key, 0, encrypted_static, &hash)?;
    let peer_static_public = PublicKey::from(peer_static_public);
    // initiator.hash = HASH(initiator.hash || msg.encrypted_static)
    hash = b2s_hash(&hash, encrypted_static);

    // temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
    let static_shared = dh(static_private, &peer_static_public)?;
    let temp = b2s_hmac(&chaining_key, static_shared.as_bytes());
    // initiator.chaining_key = HMAC(temp, 0x1)
    chaining_key = b2s_hmac(&temp, &[0x01]);
    // key = HMAC(temp, initiator.chaining_key || 0x2)
    let key = b2s_hmac2(&temp, &chaining_key, &[0x02]);
    // msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
    let mut timestamp = [0u8; TIMESTAMP_LEN];
    aead_chacha20_open(&mut timestamp, &key, 0, encrypted_timestamp, &hash)?;
    // initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
    hash = b2s_hash(&hash, encrypted_timestamp);

    Ok((
        AuthenticatedInitiation {
            chaining_key,
            hash,
            peer_ephemeral_public,
            peer_static_public,
        },
        Tai64N::parse(&timestamp),
    ))
}

/// Returns `(initiator.sending_key, initiator.receiving_key)` for the final chaining key.
fn derive_transport_keys(
    chaining_key: &[u8; KEY_LEN],
) -> (Zeroizing<[u8; KEY_LEN]>, Zeroizing<[u8; KEY_LEN]>) {
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
    ) -> Result<NoiseParams, Error> {
        let static_shared = dh(&static_private, &peer_static_public)?;
        let initial_sending_mac_key = b2s_hash(LABEL_MAC1, peer_static_public.as_bytes());

        Ok(NoiseParams {
            static_public,
            static_private,
            peer_static_public,
            static_shared,
            sending_mac1_key: initial_sending_mac_key,
            preshared_key: preshared_key.unwrap_or_else(|| StaticSecret::from([0u8; 32])),
        })
    }
}

impl Handshake {
    pub(crate) fn new(
        static_private: StaticSecret,
        static_public: PublicKey,
        peer_static_public: PublicKey,
        preshared_key: Option<x25519_dalek::StaticSecret>,
        stamper: TimeStamper,
    ) -> Result<Handshake, Error> {
        let params = NoiseParams::new(
            static_private,
            static_public,
            peer_static_public,
            preshared_key,
        )?;

        Ok(Handshake {
            params,
            previous: HandshakeState::None,
            state: HandshakeState::None,
            stamper,
            cookies: Default::default(),
        })
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

    pub(crate) fn cookie_expiration(&self) -> Option<Instant> {
        Some(self.cookies.write_cookie?.received_at + COOKIE_EXPIRATION_TIME)
    }

    pub(crate) fn clear_cookie(&mut self) {
        self.cookies.write_cookie = None;
    }

    /// Starts a new handshake, returning the initiation to send.
    pub(super) fn initiate_handshake(
        &mut self,
        local_index: Index,
        rng: &mut StdRng,
        now: Instant,
    ) -> [u8; HANDSHAKE_INIT_SZ] {
        let (mut initiation, state) = self.format_handshake_initiation(local_index, rng, now);

        self.previous = std::mem::replace(&mut self.state, HandshakeState::InitSent(state));
        self.append_mac1_and_mac2(local_index, &mut initiation);

        initiation
    }

    /// Answers a valid handshake initiation with a response and the session it establishes under
    /// `local_index`.
    pub(super) fn receive_handshake_initialization(
        &mut self,
        packet: HandshakeInit,
        local_index: Index,
        rng: &mut StdRng,
        now: Instant,
    ) -> Result<([u8; HANDSHAKE_RESP_SZ], Session), Error> {
        let HandshakeInit {
            // msg.sender_index = little_endian(initiator.sender_index)
            sender_idx: peer_index,
            initiation:
                AuthenticatedInitiation {
                    chaining_key,
                    hash,
                    peer_ephemeral_public,
                    peer_static_public,
                },
        } = packet;

        if !bool::from(
            self.params
                .peer_static_public
                .as_bytes()
                .ct_eq(peer_static_public.as_bytes()),
        ) {
            return Err(Error::WrongKey);
        }

        let (mut response, session) = self.format_handshake_response(
            hash,
            chaining_key,
            peer_ephemeral_public,
            local_index,
            peer_index,
            rng,
            now,
        )?;
        self.append_mac1_and_mac2(local_index, &mut response);

        Ok((response, session))
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
        let ephemeral_shared = dh(&state.ephemeral_private, &unencrypted_ephemeral)?;
        let temp = b2s_hmac(&chaining_key, ephemeral_shared.as_bytes());
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.static_public))
        let static_shared = dh(&self.params.static_private, &unencrypted_ephemeral)?;
        let temp = b2s_hmac(&chaining_key, static_shared.as_bytes());
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
        hash = b2s_hash(&hash, &*temp2);
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
            &temp3,
            &temp2,
            Role::Initiator,
            now,
        ))
    }

    pub(super) fn receive_cookie_reply(
        &mut self,
        packet: PacketCookieReply,
        now: Instant,
    ) -> Result<(), Error> {
        let mac1 = match self.cookies.last_mac1 {
            Some(mac) => mac,
            None => {
                return Err(Error::UnexpectedPacket);
            }
        };

        let local_index = self.cookies.index;
        if Index::from_peer(packet.receiver_idx) != local_index {
            return Err(Error::WrongIndex);
        }
        // msg.encrypted_cookie = XAEAD(HASH(LABEL_COOKIE || responder.static_public), msg.nonce, cookie, last_received_msg.mac1)
        let key = b2s_hash(LABEL_COOKIE, self.params.peer_static_public.as_bytes()); // TODO: pre-compute

        let mut cookie = [0u8; 16];
        xaead_open(
            &mut cookie,
            &key,
            packet.nonce,
            packet.encrypted_cookie,
            &mac1[0..16],
        )?;

        self.cookies.write_cookie = Some(WriteCookie {
            value: cookie,
            received_at: now,
        });
        Ok(())
    }

    /// Formats a handshake initiation without its MACs.
    fn format_handshake_initiation(
        &self,
        local_index: Index,
        rng: &mut StdRng,
        now: Instant,
    ) -> ([u8; HANDSHAKE_INIT_SZ], HandshakeInitSentState) {
        let mut dst = [0u8; HANDSHAKE_INIT_SZ];

        let (message_type, rest) = dst.split_at_mut(4);
        let (sender_index, rest) = rest.split_at_mut(4);
        let (unencrypted_ephemeral, rest) = rest.split_at_mut(32);
        let (encrypted_static, rest) = rest.split_at_mut(32 + 16);
        let (encrypted_timestamp, _) = rest.split_at_mut(12 + 16);

        // initiator.chaining_key = HASH(CONSTRUCTION)
        let mut chaining_key = Zeroizing::new(INITIAL_CHAIN_KEY);
        // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
        let mut hash = INITIAL_CHAIN_HASH;
        hash = b2s_hash(&hash, self.params.peer_static_public.as_bytes());
        // initiator.ephemeral_private = DH_GENERATE()
        let ephemeral_private = x25519_dalek::ReusableSecret::random_from_rng(rng);
        // msg.message_type = 1
        // msg.reserved_zero = { 0, 0, 0 }
        message_type.copy_from_slice(&HANDSHAKE_INIT.to_le_bytes());
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
        let ephemeral_shared = dh(&ephemeral_private, &self.params.peer_static_public)
            .expect("`Handshake::new` rejects a low-order peer static key");
        let temp = b2s_hmac(&chaining_key, ephemeral_shared.as_bytes());
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

        let state = HandshakeInitSentState {
            local_index,
            chaining_key,
            hash,
            ephemeral_private,
            time_sent: now,
        };

        (dst, state)
    }

    /// Formats a handshake response without its MACs.
    #[expect(
        clippy::too_many_arguments,
        reason = "The arguments are the handshake state so far."
    )]
    fn format_handshake_response(
        &self,
        mut hash: [u8; KEY_LEN],
        mut chaining_key: Zeroizing<[u8; KEY_LEN]>,
        peer_ephemeral_public: PublicKey,
        local_index: Index,
        peer_index: u32,
        rng: &mut StdRng,
        now: Instant,
    ) -> Result<([u8; HANDSHAKE_RESP_SZ], Session), Error> {
        let mut dst = [0u8; HANDSHAKE_RESP_SZ];

        let (message_type, rest) = dst.split_at_mut(4);
        let (sender_index, rest) = rest.split_at_mut(4);
        let (receiver_index, rest) = rest.split_at_mut(4);
        let (unencrypted_ephemeral, rest) = rest.split_at_mut(32);
        let (encrypted_nothing, _) = rest.split_at_mut(16);

        // responder.ephemeral_private = DH_GENERATE()
        let ephemeral_private = x25519_dalek::ReusableSecret::random_from_rng(rng);
        // msg.message_type = 2
        // msg.reserved_zero = { 0, 0, 0 }
        message_type.copy_from_slice(&HANDSHAKE_RESP.to_le_bytes());
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
        let ephemeral_shared = dh(&ephemeral_private, &peer_ephemeral_public)?;
        let temp = b2s_hmac(&chaining_key, ephemeral_shared.as_bytes());
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.static_public))
        let static_shared = dh(&ephemeral_private, &self.params.peer_static_public)?;
        let temp = b2s_hmac(&chaining_key, static_shared.as_bytes());
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
        hash = b2s_hash(&hash, &*temp2);
        // msg.encrypted_nothing = AEAD(key, 0, [empty], responder.hash)
        aead_chacha20_seal(encrypted_nothing, &key, 0, &[], &hash);

        let (temp2, temp3) = derive_transport_keys(&chaining_key);

        Ok((
            dst,
            Session::new(
                local_index,
                Index::from_peer(peer_index),
                &temp2,
                &temp3,
                Role::Responder,
                now,
            ),
        ))
    }

    // Compute and append mac1 and mac2 to a handshake message
    fn append_mac1_and_mac2(&mut self, local_index: Index, dst: &mut [u8]) {
        let mac1_off = dst.len() - 32;
        let mac2_off = dst.len() - 16;

        // msg.mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[0:offsetof(msg.mac1)])
        let msg_mac1 = b2s_keyed_mac_16(&self.params.sending_mac1_key, &dst[..mac1_off]);

        dst[mac1_off..mac2_off].copy_from_slice(&msg_mac1[..]);

        //msg.mac2 = MAC(initiator.last_received_cookie, msg[0:offsetof(msg.mac2)])
        let msg_mac2: [u8; 16] =
            if let Some(WriteCookie { value: cookie, .. }) = self.cookies.write_cookie {
                b2s_keyed_mac_16(&cookie, &dst[..mac2_off])
            } else {
                [0u8; 16]
            };

        dst[mac2_off..].copy_from_slice(&msg_mac2[..]);

        self.cookies.index = local_index;
        self.cookies.last_mac1 = Some(msg_mac1);
    }
}
