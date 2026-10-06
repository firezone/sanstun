use crate::crypto::{b2s_hash, b2s_keyed_mac_16, b2s_keyed_mac_16_2};
use crate::handshake::{LABEL_COOKIE, LABEL_MAC1, decrypt_initiator_static};
use crate::message::{
    COOKIE_REPLY, COOKIE_REPLY_SZ, DATA, DATA_OVERHEAD_SZ, HANDSHAKE_INIT, HANDSHAKE_INIT_SZ,
    HANDSHAKE_RESP, HANDSHAKE_RESP_SZ, HandshakeInit, HandshakeResponse, Macs, Packet,
    PacketCookieReply, PacketData,
};
use crate::tai64n::TimeStamper;
use crate::{CookieReplyMessage, Error, Index, PublicKey, StaticSecret, Tunnel};

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use aead::generic_array::GenericArray;
use aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305};
use constant_time_eq::constant_time_eq;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use zeroize::Zeroizing;

/// How long a cookie secret is used before it is replaced
const COOKIE_SECRET_MAX_AGE: Duration = Duration::from_secs(120);
const COOKIE_SIZE: usize = 16;
const COOKIE_NONCE_SIZE: usize = 24;

/// How often should reset count in seconds
const RESET_PERIOD: u64 = 1;

type Cookie = [u8; COOKIE_SIZE];

/// The entry point for every datagram received from the network for one static key.
///
/// [`Ingress::receive`] verifies the MACs of handshake messages and applies the cookie mechanism
/// under load before any expensive work, and is the only way to obtain a [`Packet`] for
/// [`Tunnel::decapsulate`].
///
/// [`Ingress::new_tunnel`] is the only way to create a [`Tunnel`], which ties every tunnel to the
/// static key of its `Ingress`.
pub struct Ingress {
    static_private: StaticSecret,
    static_public: PublicKey,
    /// The secret that cookies are derived from
    cookie_secret: Zeroizing<[u8; 32]>,
    cookie_secret_created_at: Instant,
    /// Replaces the cookie secret and draws the nonces of cookie replies
    rng: StdRng,
    mac1_key: [u8; 32],
    cookie_key: Key,
    limit: u64,
    /// The counter since last reset
    count: u64,
    /// The time the handshake count was last reset
    last_reset: Instant,
    stamper: TimeStamper,
}

impl Ingress {
    /// Creates the entry point for datagrams addressed to our `static_private` key.
    ///
    /// Use one instance for all [`Tunnel`]s of that key, so that `limit`
    /// handshake messages per second apply to all of them together.
    ///
    /// `rng_seed` must come from a cryptographically secure source because the cookie secrets and
    /// the key material of every tunnel are derived from it.
    ///
    /// `unix` is the time since the Unix epoch at `now`, from which the timestamps of handshake
    /// initiations are derived.
    pub fn new(
        static_private: StaticSecret,
        limit: u64,
        rng_seed: [u8; 32],
        now: Instant,
        unix: Duration,
    ) -> Self {
        let mut rng = StdRng::from_seed(rng_seed);
        let static_public = PublicKey::from(&static_private);
        let mut cookie_secret = Zeroizing::new([0; 32]);
        rng.fill(&mut cookie_secret[..]);

        Ingress {
            static_private,
            static_public,
            cookie_secret,
            cookie_secret_created_at: now,
            rng,
            mac1_key: b2s_hash(LABEL_MAC1, static_public.as_bytes()),
            cookie_key: b2s_hash(LABEL_COOKIE, static_public.as_bytes()).into(),
            limit,
            count: 0,
            last_reset: now,
            stamper: TimeStamper::new(now, unix),
        }
    }

    /// Creates a [`Tunnel`] between our static key and `peer_static_public`.
    ///
    /// The tunnel's RNG is seeded from this `Ingress`, so every tunnel derives distinct ephemeral keys.
    ///
    /// Fails with [`Error::LowOrderPoint`] if `peer_static_public` is a low-order point.
    pub fn new_tunnel(
        &mut self,
        peer_static_public: PublicKey,
        preshared_key: Option<StaticSecret>,
        persistent_keepalive: Option<u16>,
        index: Index,
        now: Instant,
    ) -> Result<Tunnel, Error> {
        Tunnel::new(
            self.static_private.clone(),
            peer_static_public,
            preshared_key,
            persistent_keepalive,
            index,
            self.rng.random(),
            now,
            self.stamper.clone(),
        )
    }

    /// Parses and verifies a datagram received from the network.
    ///
    /// This is the only entry point for inbound datagrams and enforces WireGuard's cookie mechanism.
    ///
    /// `src_addr` is the address and port the datagram came from, which cookies are bound to.
    pub fn receive<'a>(
        &mut self,
        src_addr: SocketAddr,
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
        src_addr: SocketAddr,
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

    /// The cookie for `addr`: MAC(responder.changing_secret_every_two_minutes, initiator.ip_address || initiator.port)
    ///
    /// The address is tagged with its family so that an IPv4 and an IPv6 address never share an
    /// encoding.
    fn current_cookie(&mut self, addr: SocketAddr, now: Instant) -> Cookie {
        let mut addr_bytes = [0u8; 19];
        let len = match addr.ip() {
            IpAddr::V4(ip) => {
                addr_bytes[0] = 4;
                addr_bytes[1..5].copy_from_slice(&ip.octets());
                5
            }
            IpAddr::V6(ip) => {
                addr_bytes[0] = 6;
                addr_bytes[1..17].copy_from_slice(&ip.octets());
                17
            }
        };
        addr_bytes[len..len + 2].copy_from_slice(&addr.port().to_be_bytes());

        b2s_keyed_mac_16(self.cookie_secret(now), &addr_bytes[..len + 2])
    }

    /// The current cookie secret, replaced in place by a fresh one once it is
    /// `COOKIE_SECRET_MAX_AGE` old.
    fn cookie_secret(&mut self, now: Instant) -> &[u8; 32] {
        if now.duration_since(self.cookie_secret_created_at) >= COOKIE_SECRET_MAX_AGE {
            self.rng.fill(&mut self.cookie_secret[..]);
            self.cookie_secret_created_at = now;
        }

        &self.cookie_secret
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
    /// [`Tunnel::decapsulate`].
    Packet(Packet<'a>),
    /// Send this cookie reply to the peer: we are under load and its handshake message needs
    /// a valid cookie.
    CookieReply(CookieReplyMessage),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookies_differ_across_address_families() {
        let now = Instant::now();
        let mut ingress = under_load(now);

        let v4 = ingress.current_cookie("1.2.3.4:51820".parse().unwrap(), now);
        let v6 = ingress.current_cookie("[102:304::]:51820".parse().unwrap(), now);

        assert_ne!(v4, v6);
    }

    #[test]
    fn cookies_differ_across_ports() {
        let now = Instant::now();
        let mut ingress = under_load(now);

        let first = ingress.current_cookie("1.2.3.4:51820".parse().unwrap(), now);
        let second = ingress.current_cookie("1.2.3.4:51821".parse().unwrap(), now);

        assert_ne!(first, second);
    }

    #[test]
    fn cookie_secret_rotates_every_120_seconds() {
        let start = Instant::now();
        let mut ingress = under_load(start);
        let addr = "1.2.3.4:51820".parse().unwrap();

        let first = ingress.current_cookie(addr, start);
        let before_rotation = ingress.current_cookie(addr, start + secs(119));
        let second = ingress.current_cookie(addr, start + secs(120));
        let before_next_rotation = ingress.current_cookie(addr, start + secs(239));
        let third = ingress.current_cookie(addr, start + secs(240));

        assert_eq!(before_rotation, first);
        assert_ne!(second, first);
        assert_eq!(before_next_rotation, second);
        assert_ne!(third, second);
    }

    #[test]
    fn mac2_from_the_previous_cookie_secret_is_rejected() {
        let start = Instant::now();
        let mut ingress = under_load(start);
        let addr = "1.2.3.4:51820".parse().unwrap();
        let cookie = ingress.current_cookie(addr, start);
        let init = handshake_initiation(&ingress, &cookie);

        let within = ingress.verify_macs(addr, 0, &init, start + secs(119));
        let after = ingress.verify_macs(addr, 0, &init, start + secs(120));

        assert!(matches!(within, Ok(None)));
        assert!(matches!(after, Ok(Some(_))));
    }

    fn under_load(now: Instant) -> Ingress {
        Ingress::new(StaticSecret::from([1; 32]), 0, [2; 32], now, Duration::ZERO)
    }

    /// A handshake initiation with a valid mac1 and its mac2 keyed with `cookie`.
    fn handshake_initiation(ingress: &Ingress, cookie: &Cookie) -> [u8; HANDSHAKE_INIT_SZ] {
        let mac1_off = HANDSHAKE_INIT_SZ - 32;
        let mac2_off = HANDSHAKE_INIT_SZ - 16;
        let mut init = [0u8; HANDSHAKE_INIT_SZ];
        init[0] = 1;

        let mac1 = b2s_keyed_mac_16(&ingress.mac1_key, &init[..mac1_off]);
        init[mac1_off..mac2_off].copy_from_slice(&mac1);
        let mac2 = b2s_keyed_mac_16(cookie, &init[..mac2_off]);
        init[mac2_off..].copy_from_slice(&mac2);

        init
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }
}
