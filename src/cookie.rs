use crate::crypto::{b2s_hash, b2s_keyed_mac_16, b2s_keyed_mac_16_2, b2s_mac_24};
use crate::{
    Error, HandshakeInit, HandshakeResponse, Index, Macs, Packet, PacketCookieReply, PublicKey,
};

use std::net::IpAddr;
use std::time::{Duration, Instant};

use aead::generic_array::GenericArray;
use aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305};
use constant_time_eq::constant_time_eq;
use parking_lot::Mutex;
use portable_atomic::{AtomicU64, Ordering};
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};

const LABEL_MAC1: &[u8; 8] = b"mac1----";
const LABEL_COOKIE: &[u8; 8] = b"cookie--";
const COOKIE_EXPIRATION_TIME: Duration = Duration::from_secs(120);

/// The default value to use for rate limiting, when no other rate limiter is defined
pub(crate) const PEER_HANDSHAKE_RATE_LIMIT: u64 = 10;

const COOKIE_REFRESH: u64 = 128; // Use 128 and not 120 so the compiler can optimize out the division
const COOKIE_SIZE: usize = 16;
const COOKIE_NONCE_SIZE: usize = 24;

/// How often should reset count in seconds
const RESET_PERIOD: u64 = 1;

type Cookie = [u8; COOKIE_SIZE];

/// There are two places where WireGuard requires "randomness" for cookies
/// * The 24 byte nonce in the cookie massage - here the only goal is to avoid nonce reuse
/// * A secret value that changes every two minutes
///
/// Because the main goal of the cookie is simply for a party to prove ownership of an IP address
/// we can relax the randomness definition a bit, in order to avoid locking, because using less
/// resources is the main goal of any DoS prevention mechanism.
/// In order to avoid locking and calls to rand we derive pseudo random values using the AEAD and
/// some counters.
pub struct RateLimiter {
    /// The key we use to derive the nonce
    nonce_key: [u8; 32],
    /// The key we use to derive the cookie
    secret_key: [u8; 16],
    start_time: Instant,
    /// A single 64 bit counter (should suffice for many years)
    nonce_ctr: AtomicU64,
    mac1_key: [u8; 32],
    cookie_key: Key,
    limit: u64,
    /// The counter since last reset
    count: AtomicU64,
    /// The time last reset was performed on this rate limiter
    last_reset: Mutex<Instant>,
}

impl RateLimiter {
    /// `rng_seed` must come from a cryptographically secure source because the cookie secrets are derived from it.
    pub fn new(public_key: &PublicKey, limit: u64, rng_seed: [u8; 32], now: Instant) -> Self {
        let mut rng = StdRng::from_seed(rng_seed);

        RateLimiter {
            nonce_key: rng.random(),
            secret_key: rng.random(),
            start_time: now,
            nonce_ctr: AtomicU64::new(0),
            mac1_key: b2s_hash(LABEL_MAC1, public_key.as_bytes()),
            cookie_key: b2s_hash(LABEL_COOKIE, public_key.as_bytes()).into(),
            limit,
            count: AtomicU64::new(0),
            last_reset: Mutex::new(now),
        }
    }

    /// Reset packet count once `RESET_PERIOD` has passed since the last reset
    fn reset_count(&self, current_time: Instant) {
        // The rate limiter is not very accurate, but at the scale we care about it doesn't matter much
        let mut last_reset_time = self.last_reset.lock();
        if current_time.duration_since(*last_reset_time).as_secs() >= RESET_PERIOD {
            self.count.store(0, Ordering::SeqCst);
            *last_reset_time = current_time;
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

    fn nonce(&self) -> [u8; COOKIE_NONCE_SIZE] {
        let ctr = self.nonce_ctr.fetch_add(1, Ordering::Relaxed);

        b2s_mac_24(&self.nonce_key, &ctr.to_le_bytes())
    }

    fn is_under_load(&self) -> bool {
        self.count.fetch_add(1, Ordering::SeqCst) >= self.limit
    }

    pub(crate) fn format_cookie_reply(
        &self,
        idx: u32,
        cookie: Cookie,
        mac1: &[u8],
    ) -> [u8; super::COOKIE_REPLY_SZ] {
        let mut dst = [0u8; super::COOKIE_REPLY_SZ];

        let (message_type, rest) = dst.split_at_mut(4);
        let (receiver_index, rest) = rest.split_at_mut(4);
        let (nonce, rest) = rest.split_at_mut(24);
        let (encrypted_cookie, _) = rest.split_at_mut(16 + 16);

        // msg.message_type = 3
        // msg.reserved_zero = { 0, 0, 0 }
        message_type.copy_from_slice(&super::COOKIE_REPLY.to_le_bytes());
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

    /// Verify the MAC fields on the datagram, and apply rate limiting if needed
    ///
    /// Returns `Ok(Some(cookie_reply))` when the peer must be sent a cookie reply instead.
    pub(crate) fn verify_packet(
        &self,
        src_addr: Option<IpAddr>,
        packet: &Packet<'_>,
        now: Instant,
    ) -> Result<Option<[u8; super::COOKIE_REPLY_SZ]>, Error> {
        // Verify and rate limit handshake messages only
        if let Packet::HandshakeInit(HandshakeInit {
            sender_idx, macs, ..
        })
        | Packet::HandshakeResponse(HandshakeResponse {
            sender_idx, macs, ..
        }) = packet
        {
            let Macs { msg, mac1, mac2 } = *macs;

            let computed_mac1 = b2s_keyed_mac_16(&self.mac1_key, msg);
            if !constant_time_eq(&computed_mac1[..16], mac1) {
                return Err(Error::InvalidMac);
            }

            // Advance the per-second window before checking it. Resetting it
            // lazily here, on use, means callers don't need a background timer
            // ticking once a second just to keep the counter accurate.
            self.reset_count(now);

            if self.is_under_load() {
                let addr = match src_addr {
                    None => return Err(Error::UnderLoad),
                    Some(addr) => addr,
                };

                // Only given an address can we validate mac2
                let cookie = self.current_cookie(addr, now);
                let computed_mac2 = b2s_keyed_mac_16_2(&cookie, msg, mac1);

                if !constant_time_eq(&computed_mac2[..16], mac2) {
                    return Ok(Some(self.format_cookie_reply(*sender_idx, cookie, mac1)));
                }
            }
        }

        Ok(None)
    }
}

/// The initiator's side of the cookie mechanism: computes the MACs of our handshake messages
/// and keeps the cookie the peer last sent us.
pub(crate) struct Cookies {
    /// A pre-computation of HASH("mac1----", peer_static_public) for this peer
    mac1_key: [u8; 32],
    /// A pre-computation of HASH("cookie--", peer_static_public) for this peer
    cookie_key: Key,
    last_mac1: Option<[u8; 16]>,
    index: Index,
    write_cookie: Option<WriteCookie>,
}

#[derive(Clone, Copy)]
struct WriteCookie {
    value: Cookie,
    received_at: Instant,
}

impl Cookies {
    pub(crate) fn new(peer_static_public: &PublicKey) -> Self {
        Cookies {
            mac1_key: b2s_hash(LABEL_MAC1, peer_static_public.as_bytes()),
            cookie_key: b2s_hash(LABEL_COOKIE, peer_static_public.as_bytes()).into(),
            last_mac1: None,
            index: Default::default(),
            write_cookie: None,
        }
    }

    pub(crate) fn expiration(&self) -> Option<Instant> {
        Some(self.write_cookie?.received_at + COOKIE_EXPIRATION_TIME)
    }

    pub(crate) fn clear(&mut self) {
        self.write_cookie = None;
    }

    pub(crate) fn receive_cookie_reply(
        &mut self,
        packet: PacketCookieReply,
        now: Instant,
    ) -> Result<(), Error> {
        let mac1 = match self.last_mac1 {
            Some(mac) => mac,
            None => {
                return Err(Error::UnexpectedPacket);
            }
        };

        let local_index = self.index;
        if Index::from_peer(packet.receiver_idx) != local_index {
            return Err(Error::WrongIndex);
        }
        // msg.encrypted_cookie = XAEAD(HASH(LABEL_COOKIE || responder.static_public), msg.nonce, cookie, last_received_msg.mac1)
        let (encrypted_cookie, tag) = packet.encrypted_cookie.split_at(16);
        let mut cookie = [0u8; 16];
        cookie.copy_from_slice(encrypted_cookie);
        XChaCha20Poly1305::new(&self.cookie_key)
            .decrypt_in_place_detached(packet.nonce.into(), &mac1[0..16], &mut cookie, tag.into())
            .map_err(|_| Error::InvalidAeadTag)?;

        self.write_cookie = Some(WriteCookie {
            value: cookie,
            received_at: now,
        });
        Ok(())
    }

    // Compute and append mac1 and mac2 to a handshake message
    pub(crate) fn append_mac1_and_mac2(&mut self, local_index: Index, dst: &mut [u8]) {
        let mac1_off = dst.len() - 32;
        let mac2_off = dst.len() - 16;

        // msg.mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[0:offsetof(msg.mac1)])
        let msg_mac1 = b2s_keyed_mac_16(&self.mac1_key, &dst[..mac1_off]);

        dst[mac1_off..mac2_off].copy_from_slice(&msg_mac1[..]);

        //msg.mac2 = MAC(initiator.last_received_cookie, msg[0:offsetof(msg.mac2)])
        let msg_mac2: [u8; 16] = if let Some(WriteCookie { value: cookie, .. }) = self.write_cookie
        {
            b2s_keyed_mac_16(&cookie, &dst[..mac2_off])
        } else {
            [0u8; 16]
        };

        dst[mac2_off..].copy_from_slice(&msg_mac2[..]);

        self.index = local_index;
        self.last_mac1 = Some(msg_mac1);
    }
}
