use crate::crypto::{b2s_hash, b2s_keyed_mac_16, b2s_keyed_mac_16_2};
use crate::handshake::{LABEL_COOKIE, LABEL_MAC1, decrypt_initiator_static};
use crate::message::{
    COOKIE_REPLY, COOKIE_REPLY_SZ, DATA, DATA_OVERHEAD_SZ, HANDSHAKE_INIT, HANDSHAKE_INIT_SZ,
    HANDSHAKE_RESP, HANDSHAKE_RESP_SZ, HandshakeInit, HandshakeResponse, Macs, Packet,
    PacketCookieReply, PacketData,
};
use crate::{CookieReplyMessage, Error, PublicKey, StaticSecret};

use std::net::IpAddr;
use std::time::Instant;

use aead::generic_array::GenericArray;
use aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305};
use constant_time_eq::constant_time_eq;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};

const COOKIE_REFRESH: u64 = 128; // Use 128 and not 120 so the compiler can optimize out the division
const COOKIE_SIZE: usize = 16;
const COOKIE_NONCE_SIZE: usize = 24;

/// How often should reset count in seconds
const RESET_PERIOD: u64 = 1;

type Cookie = [u8; COOKIE_SIZE];

/// The entry point for every datagram received from the network for one static key.
///
/// [`Ingress::receive`] verifies the MACs of handshake messages and applies the cookie mechanism
/// under load before any expensive work, and is the only way to obtain a [`Packet`] for
/// [`Tunnel::decapsulate`](crate::Tunnel::decapsulate).
pub struct Ingress {
    static_private: StaticSecret,
    static_public: PublicKey,
    /// The key we use to derive the cookie
    secret_key: [u8; 16],
    start_time: Instant,
    /// Draws the nonces of cookie replies
    rng: StdRng,
    mac1_key: [u8; 32],
    cookie_key: Key,
    limit: u64,
    /// The counter since last reset
    count: u64,
    /// The time the handshake count was last reset
    last_reset: Instant,
}

impl Ingress {
    /// Creates the entry point for datagrams addressed to our `static_private` key.
    ///
    /// Use one instance for all [`Tunnel`](crate::Tunnel)s of that key, so that `limit`
    /// handshake messages per second apply to all of them together.
    ///
    /// `rng_seed` must come from a cryptographically secure source because the cookie secrets are derived from it.
    pub fn new(static_private: StaticSecret, limit: u64, rng_seed: [u8; 32], now: Instant) -> Self {
        let mut rng = StdRng::from_seed(rng_seed);
        let static_public = PublicKey::from(&static_private);

        Ingress {
            static_private,
            static_public,
            secret_key: rng.random(),
            start_time: now,
            rng,
            mac1_key: b2s_hash(LABEL_MAC1, static_public.as_bytes()),
            cookie_key: b2s_hash(LABEL_COOKIE, static_public.as_bytes()).into(),
            limit,
            count: 0,
            last_reset: now,
        }
    }

    /// Parses and verifies a datagram received from the network.
    ///
    /// This is the only entry point for inbound datagrams and enforces WireGuard's cookie mechanism.
    ///
    /// `src_addr` is the source address of the datagram, which cookies are bound to.
    pub fn receive<'a>(
        &mut self,
        src_addr: IpAddr,
        datagram: &'a [u8],
        now: Instant,
    ) -> Result<Received<'a>, Error> {
        if datagram.len() < 4 {
            return Err(Error::InvalidPacket);
        }

        // Checks the type, as well as the reserved zero fields
        let packet_type = u32::from_le_bytes(datagram[0..4].try_into().unwrap());

        let packet = match (packet_type, datagram.len()) {
            (HANDSHAKE_INIT, HANDSHAKE_INIT_SZ) => {
                let sender_idx = u32::from_le_bytes(datagram[4..8].try_into().unwrap());
                if let Some(reply) = self.verify_macs(src_addr, sender_idx, datagram, now)? {
                    return Ok(Received::CookieReply(reply));
                }

                Packet::HandshakeInit(HandshakeInit {
                    sender_idx,
                    encrypted_timestamp: &datagram[88..116],
                    initiator: decrypt_initiator_static(
                        &self.static_private,
                        &self.static_public,
                        datagram[8..40]
                            .try_into()
                            .expect("length already checked above"),
                        &datagram[40..88],
                    )?,
                })
            }
            (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ) => {
                let sender_idx = u32::from_le_bytes(datagram[4..8].try_into().unwrap());
                if let Some(reply) = self.verify_macs(src_addr, sender_idx, datagram, now)? {
                    return Ok(Received::CookieReply(reply));
                }

                Packet::HandshakeResponse(HandshakeResponse {
                    sender_idx,
                    receiver_idx: u32::from_le_bytes(datagram[8..12].try_into().unwrap()),
                    unencrypted_ephemeral: datagram[12..44]
                        .try_into()
                        .expect("length already checked above"),
                    encrypted_nothing: &datagram[44..60],
                })
            }
            (COOKIE_REPLY, COOKIE_REPLY_SZ) => Packet::PacketCookieReply(PacketCookieReply {
                receiver_idx: u32::from_le_bytes(datagram[4..8].try_into().unwrap()),
                nonce: &datagram[8..32],
                encrypted_cookie: &datagram[32..64],
            }),
            (DATA, DATA_OVERHEAD_SZ..=usize::MAX) => Packet::PacketData(PacketData {
                receiver_idx: u32::from_le_bytes(datagram[4..8].try_into().unwrap()),
                counter: u64::from_le_bytes(datagram[8..16].try_into().unwrap()),
            }),
            _ => return Err(Error::InvalidPacket),
        };

        Ok(Received::Packet(packet))
    }

    /// Verifies the MACs of a handshake message and applies rate limiting.
    ///
    /// Returns the cookie reply to send instead of processing the message when we are under load
    /// and it lacks a valid mac2.
    fn verify_macs(
        &mut self,
        src_addr: IpAddr,
        sender_idx: u32,
        message: &[u8],
        now: Instant,
    ) -> Result<Option<CookieReplyMessage>, Error> {
        let Macs { msg, mac1, mac2 } = Macs::new(message);

        let computed_mac1 = b2s_keyed_mac_16(&self.mac1_key, msg);
        if !constant_time_eq(&computed_mac1[..16], mac1) {
            return Err(Error::InvalidMac);
        }

        // Advance the per-second window before checking it. Resetting it
        // lazily here, on use, means callers don't need a background timer
        // ticking once a second just to keep the counter accurate.
        self.reset_count(now);

        if !self.is_under_load() {
            return Ok(None);
        }

        let cookie = self.current_cookie(src_addr, now);
        let computed_mac2 = b2s_keyed_mac_16_2(&cookie, msg, mac1);

        if !constant_time_eq(&computed_mac2[..16], mac2) {
            return Ok(Some(CookieReplyMessage(
                self.format_cookie_reply(sender_idx, cookie, mac1),
            )));
        }

        Ok(None)
    }

    /// Reset packet count once `RESET_PERIOD` has passed since the last reset
    fn reset_count(&mut self, current_time: Instant) {
        // The rate limit is not very accurate, but at the scale we care about it doesn't matter much
        if current_time.duration_since(self.last_reset).as_secs() >= RESET_PERIOD {
            self.count = 0;
            self.last_reset = current_time;
        }
    }

    /// Compute the correct cookie value based on the current secret value and the source IP
    fn current_cookie(&self, addr: IpAddr, now: Instant) -> Cookie {
        let mut addr_bytes = [0u8; 16];

        match addr {
            IpAddr::V4(a) => addr_bytes[..4].copy_from_slice(&a.octets()[..]),
            IpAddr::V6(a) => addr_bytes[..].copy_from_slice(&a.octets()[..]),
        }

        // The current cookie for a given IP is the MAC(responder.changing_secret_every_two_minutes, initiator.ip_address)
        // First we derive the secret from the current time, the value of cur_counter would change with time.
        let cur_counter = now.duration_since(self.start_time).as_secs() / COOKIE_REFRESH;

        // Next we derive the cookie
        b2s_keyed_mac_16_2(&self.secret_key, &cur_counter.to_le_bytes(), &addr_bytes)
    }

    fn nonce(&mut self) -> [u8; COOKIE_NONCE_SIZE] {
        self.rng.random()
    }

    fn is_under_load(&mut self) -> bool {
        let count = self.count;
        self.count += 1;

        count >= self.limit
    }

    fn format_cookie_reply(
        &mut self,
        idx: u32,
        cookie: Cookie,
        mac1: &[u8],
    ) -> [u8; COOKIE_REPLY_SZ] {
        let mut dst = [0u8; COOKIE_REPLY_SZ];

        let (message_type, rest) = dst.split_at_mut(4);
        let (receiver_index, rest) = rest.split_at_mut(4);
        let (nonce, rest) = rest.split_at_mut(24);
        let (encrypted_cookie, _) = rest.split_at_mut(16 + 16);

        // msg.message_type = 3
        // msg.reserved_zero = { 0, 0, 0 }
        message_type.copy_from_slice(&COOKIE_REPLY.to_le_bytes());
        // msg.receiver_index = little_endian(initiator.sender_index)
        receiver_index.copy_from_slice(&idx.to_le_bytes());
        nonce.copy_from_slice(&self.nonce()[..]);

        let cipher = XChaCha20Poly1305::new(&self.cookie_key);

        let iv = GenericArray::from_slice(nonce);

        encrypted_cookie[..16].copy_from_slice(&cookie);
        let tag = cipher
            .encrypt_in_place_detached(iv, mac1, &mut encrypted_cookie[..16])
            .expect("a cookie is always within the AEAD's limits");

        encrypted_cookie[16..].copy_from_slice(&tag);

        dst
    }
}

/// What the caller needs to do after [`Ingress::receive`].
#[derive(Debug)]
pub enum Received<'a> {
    /// Route the packet to its [`Tunnel`](crate::Tunnel) and hand it to
    /// [`Tunnel::decapsulate`](crate::Tunnel::decapsulate).
    Packet(Packet<'a>),
    /// Send this cookie reply to the peer: we are under load and its handshake message needs
    /// a valid cookie.
    CookieReply(CookieReplyMessage),
}
