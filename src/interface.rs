use crate::crypto::{b2s_hash, b2s_keyed_mac_16, b2s_keyed_mac_16_2, xaead_seal};
use crate::handshake::{LABEL_COOKIE, LABEL_MAC1, parse_handshake_init};
use crate::index::TunnelIndices;
use crate::message::{
    COOKIE_REPLY, COOKIE_REPLY_SZ, CookieReply, DATA, DATA_OVERHEAD_SZ, HANDSHAKE_INIT,
    HANDSHAKE_INIT_SZ, HANDSHAKE_RESP, HANDSHAKE_RESP_SZ, HandshakeResponse, Macs, ReceivedMessage,
    TransportData,
};
use crate::ratelimiter::RateLimiter;
use crate::tai64n::{Tai64N, TimeStamper};
use crate::{Datagram, Error, PublicKey, StaticSecret, Tunnel, TunnelConfig};

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use crate::rng::ForwardSecureRng;
use rand::RngExt;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

/// How long a cookie secret is used before it is replaced.
const COOKIE_SECRET_MAX_AGE: Duration = Duration::from_secs(120);
const COOKIE_SIZE: usize = 16;

const COOKIE_NONCE_SIZE: usize = 24;

type Cookie = [u8; COOKIE_SIZE];

/// A WireGuard interface whose tunnels share one static key.
///
/// Create a [`Tunnel`] for each peer with [`Interface::new_tunnel`]. Pass incoming datagrams to
/// [`Interface::receive`], then route the parsed messages to their tunnels.
pub struct Interface {
    static_private: StaticSecret,
    static_public: PublicKey,

    cookie_secret: Zeroizing<[u8; 32]>,
    cookie_secret_created_at: Instant,
    mac1_key: [u8; 32],
    cookie_key: [u8; 32],

    rng: ForwardSecureRng,
    stamper: TimeStamper,
    indices: TunnelIndices,
    rate_limiter: RateLimiter,
    /// The latest accepted handshake timestamp for each peer we have created a tunnel for.
    last_handshake_timestamps: HashMap<PublicKey, Tai64N>,
}

impl Interface {
    /// Creates an interface with a randomly generated static key.
    ///
    /// All keys and random values derive from `seed`. Use fresh operating-system entropy for
    /// each instance, for example from `getrandom::fill`. Reusing a seed repeats keys and nonces
    /// and is only safe in tests.
    ///
    /// `unix` is the time since the Unix epoch at `now`, used to timestamp handshake initiations.
    pub fn new(seed: Zeroizing<[u8; 32]>, now: Instant, unix: Duration) -> Self {
        let mut rng = ForwardSecureRng::from_seed(seed);
        let mut static_private = Zeroizing::new([0; 32]);
        rng.fill(&mut static_private[..]);
        let static_private = StaticSecret::from(static_private);
        let static_public = PublicKey::from(&static_private);
        let mut cookie_secret = Zeroizing::new([0; 32]);
        rng.fill(&mut cookie_secret[..]);
        let indices = TunnelIndices::new(&mut rng);

        Interface {
            static_private,
            static_public,
            cookie_secret,
            cookie_secret_created_at: now,
            rng,
            mac1_key: b2s_hash(LABEL_MAC1, static_public.as_bytes()),
            cookie_key: b2s_hash(LABEL_COOKIE, static_public.as_bytes()),
            stamper: TimeStamper::new(now, unix),
            indices,
            rate_limiter: RateLimiter::new(now),
            last_handshake_timestamps: HashMap::new(),
        }
    }

    /// Sets the interface's static private key.
    pub fn with_static_private(mut self, static_private: StaticSecret) -> Self {
        let static_public = PublicKey::from(&static_private);

        self.mac1_key = b2s_hash(LABEL_MAC1, static_public.as_bytes());
        self.cookie_key = b2s_hash(LABEL_COOKIE, static_public.as_bytes());
        self.static_private = static_private;
        self.static_public = static_public;

        self
    }

    /// Sets the number of handshake messages allowed per second before cookies are required.
    ///
    /// Defaults to 100.
    pub fn with_handshake_limit(mut self, limit: u64) -> Self {
        self.rate_limiter.set_limit(limit);

        self
    }

    /// Returns the interface's static public key.
    pub fn static_public(&self) -> PublicKey {
        self.static_public
    }

    /// Creates a [`Tunnel`] between our static key and `peer_static_public`.
    ///
    /// Fails with [`Error::LowOrderPoint`] if `peer_static_public` is a low-order point.
    ///
    /// Enables handshake replay checks for `peer_static_public`. These remain in effect even
    /// if the tunnel is dropped or replaced.
    pub fn new_tunnel(
        &mut self,
        peer_static_public: PublicKey,
        config: TunnelConfig,
        now: Instant,
    ) -> Result<Tunnel, Error> {
        let (index, index_lease) = self.indices.next();

        let tunnel = Tunnel::new(
            self.static_private.clone(),
            peer_static_public,
            config,
            index,
            index_lease,
            &mut self.rng,
            now,
            self.stamper.clone(),
        )?;

        if let Entry::Vacant(entry) = self.last_handshake_timestamps.entry(peer_static_public) {
            entry.insert(Tai64N::zero());
        }

        Ok(tunnel)
    }

    /// Parses an incoming datagram and applies handshake cookie and rate-limit checks.
    ///
    /// Under load, handshakes with valid cookies are limited to 20 per second with a burst of 5
    /// per IPv4 address or IPv6 /64.
    /// Messages beyond this budget fail with [`Error::RateLimited`].
    ///
    /// For peers you have created a tunnel for, handshake initiations must be newer than the last
    /// accepted one or they fail with [`Error::ReplayedHandshakeInitiation`].
    ///
    /// Cookies are bound to `src_addr`, the datagram's source address and port.
    pub fn receive(
        &mut self,
        src_addr: SocketAddr,
        datagram: &[u8],
        now: Instant,
    ) -> Result<Received, Error> {
        if datagram.len() < 4 {
            return Err(Error::InvalidPacket);
        }

        // Reading all four bytes also checks the reserved zero fields.
        let packet_type = u32::from_le_bytes(datagram[0..4].try_into().unwrap());

        let message = match (packet_type, datagram.len()) {
            (HANDSHAKE_INIT, HANDSHAKE_INIT_SZ) => {
                let sender_idx = u32::from_le_bytes(datagram[4..8].try_into().unwrap());
                if let Some(reply) = self.verify_macs(src_addr, sender_idx, datagram, now)? {
                    return Ok(Received::SendCookieReply(reply));
                }

                let init = parse_handshake_init(
                    &self.static_private,
                    &self.static_public,
                    datagram.try_into().expect("handshake length was checked"),
                )?;

                if let Some(last) = self
                    .last_handshake_timestamps
                    .get_mut(&init.peer_static_public())
                {
                    if !init.timestamp().after(last) {
                        return Err(Error::ReplayedHandshakeInitiation {
                            peer_static_public: Box::new(init.peer_static_public()),
                        });
                    }
                    *last = init.timestamp();
                }

                ReceivedMessage::HandshakeInitiation(init)
            }
            (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ) => {
                let sender_idx = u32::from_le_bytes(datagram[4..8].try_into().unwrap());
                if let Some(reply) = self.verify_macs(src_addr, sender_idx, datagram, now)? {
                    return Ok(Received::SendCookieReply(reply));
                }

                ReceivedMessage::HandshakeResponse(HandshakeResponse {
                    sender_idx,
                    receiver_idx: u32::from_le_bytes(datagram[8..12].try_into().unwrap()),
                    unencrypted_ephemeral: datagram[12..44]
                        .try_into()
                        .expect("handshake length was checked"),
                    encrypted_nothing: datagram[44..60]
                        .try_into()
                        .expect("handshake length was checked"),
                })
            }
            (COOKIE_REPLY, COOKIE_REPLY_SZ) => ReceivedMessage::CookieReply(CookieReply {
                receiver_idx: u32::from_le_bytes(datagram[4..8].try_into().unwrap()),
                nonce: datagram[8..32].try_into().unwrap(),
                encrypted_cookie: datagram[32..64].try_into().unwrap(),
            }),
            (DATA, DATA_OVERHEAD_SZ..=usize::MAX) => {
                ReceivedMessage::TransportData(TransportData {
                    receiver_idx: u32::from_le_bytes(datagram[4..8].try_into().unwrap()),
                    counter: u64::from_le_bytes(datagram[8..16].try_into().unwrap()),
                })
            }
            _ => return Err(Error::InvalidPacket),
        };

        Ok(Received::Message(message))
    }

    /// Verifies the MACs of a handshake message and applies rate limiting.
    ///
    /// Returns a cookie reply if the message needs a valid `mac2` before it can be processed.
    fn verify_macs(
        &mut self,
        src_addr: SocketAddr,
        sender_idx: u32,
        message: &[u8],
        now: Instant,
    ) -> Result<Option<Datagram>, Error> {
        let Macs { msg, mac1, mac2 } = Macs::new(message);

        let computed_mac1 = b2s_keyed_mac_16(&self.mac1_key, msg);
        if !bool::from(computed_mac1[..16].ct_eq(mac1)) {
            return Err(Error::InvalidMac);
        }

        if !self.rate_limiter.is_under_load(now) {
            return Ok(None);
        }

        let cookie = self.current_cookie(src_addr, now);
        let computed_mac2 = b2s_keyed_mac_16_2(&cookie, msg, mac1);

        if !bool::from(computed_mac2[..16].ct_eq(mac2)) {
            return Ok(Some(Datagram::new(
                self.format_cookie_reply(sender_idx, cookie, mac1),
            )));
        }

        if !self.rate_limiter.allow(src_addr.ip(), now) {
            return Err(Error::RateLimited);
        }

        Ok(None)
    }

    /// Derives the cookie for `addr` using the rotating cookie secret.
    ///
    /// The address family is included so IPv4 and IPv6 encodings cannot collide.
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

    /// Returns the cookie secret, replacing it once it reaches `COOKIE_SECRET_MAX_AGE`.
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
        let nonce_value = self.nonce();

        // msg.message_type = 3
        // msg.reserved_zero = { 0, 0, 0 }
        message_type.copy_from_slice(&COOKIE_REPLY.to_le_bytes());
        // msg.receiver_index = little_endian(initiator.sender_index)
        receiver_index.copy_from_slice(&idx.to_le_bytes());
        nonce.copy_from_slice(&nonce_value);
        xaead_seal(
            encrypted_cookie,
            &self.cookie_key,
            &nonce_value,
            &cookie,
            mac1,
        );

        dst
    }
}

/// The result of [`Interface::receive`].
#[derive(Debug)]
pub enum Received {
    /// Route the message to its [`Tunnel`](crate::Tunnel) and hand it to [`Tunnel::begin_decapsulate`].
    Message(ReceivedMessage),
    /// Send this cookie reply to the peer. The interface is under load and requires a valid
    /// cookie before processing the handshake.
    SendCookieReply(Datagram),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookies_differ_across_address_families() {
        let now = Instant::now();
        let mut interface = under_load(now);

        let v4 = interface.current_cookie("1.2.3.4:51820".parse().unwrap(), now);
        let v6 = interface.current_cookie("[102:304::]:51820".parse().unwrap(), now);

        assert_ne!(v4, v6);
    }

    #[test]
    fn cookies_differ_across_ports() {
        let now = Instant::now();
        let mut interface = under_load(now);

        let first = interface.current_cookie("1.2.3.4:51820".parse().unwrap(), now);
        let second = interface.current_cookie("1.2.3.4:51821".parse().unwrap(), now);

        assert_ne!(first, second);
    }

    #[test]
    fn cookie_secret_rotates_every_120_seconds() {
        let start = Instant::now();
        let mut interface = under_load(start);
        let addr = "1.2.3.4:51820".parse().unwrap();

        let first = interface.current_cookie(addr, start);
        let before_rotation = interface.current_cookie(addr, start + secs(119));
        let second = interface.current_cookie(addr, start + secs(120));
        let before_next_rotation = interface.current_cookie(addr, start + secs(239));
        let third = interface.current_cookie(addr, start + secs(240));

        assert_eq!(before_rotation, first);
        assert_ne!(second, first);
        assert_eq!(before_next_rotation, second);
        assert_ne!(third, second);
    }

    #[test]
    fn mac2_from_the_previous_cookie_secret_is_rejected() {
        let start = Instant::now();
        let mut interface = under_load(start);
        let addr = "1.2.3.4:51820".parse().unwrap();
        let cookie = interface.current_cookie(addr, start);
        let init = handshake_initiation(&interface, &cookie);

        let within = interface.verify_macs(addr, 0, &init, start + secs(119));
        let after = interface.verify_macs(addr, 0, &init, start + secs(120));

        assert!(matches!(within, Ok(None)));
        assert!(matches!(after, Ok(Some(_))));
    }

    #[test]
    fn initiations_from_unknown_peers_leave_no_state() {
        let now = Instant::now();
        let mut initiator = Interface::new(Zeroizing::new([1; 32]), now, Duration::ZERO);
        let mut responder = Interface::new(Zeroizing::new([2; 32]), now, Duration::ZERO);
        let mut tunnel = initiator
            .new_tunnel(responder.static_public(), TunnelConfig::default(), now)
            .unwrap();
        let init = tunnel.initiate_handshake(now).unwrap();

        let received = responder.receive("1.2.3.4:51820".parse().unwrap(), &init, now);

        assert!(matches!(
            received,
            Ok(Received::Message(ReceivedMessage::HandshakeInitiation(_)))
        ));
        assert!(responder.last_handshake_timestamps.is_empty());
    }

    fn under_load(now: Instant) -> Interface {
        Interface::new(Zeroizing::new([2; 32]), now, Duration::ZERO).with_handshake_limit(0)
    }

    /// Builds a handshake initiation with valid `mac1` and `mac2` computed using `cookie`.
    fn handshake_initiation(interface: &Interface, cookie: &Cookie) -> [u8; HANDSHAKE_INIT_SZ] {
        let mac1_off = HANDSHAKE_INIT_SZ - 32;
        let mac2_off = HANDSHAKE_INIT_SZ - 16;
        let mut init = [0u8; HANDSHAKE_INIT_SZ];
        init[0] = 1;

        let mac1 = b2s_keyed_mac_16(&interface.mac1_key, &init[..mac1_off]);
        init[mac1_off..mac2_off].copy_from_slice(&mac1);
        let mac2 = b2s_keyed_mac_16(cookie, &init[..mac2_off]);
        init[mac2_off..].copy_from_slice(&mac2);

        init
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }
}
