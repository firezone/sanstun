//! Two [`Tunnel`] instances connected by an in-memory network and a virtual clock.
//!
//! Tests control time through [`Sim::advance`] and packet delivery through
//! [`Sim::route`] or [`Sim::deliver`]. [`Sim::log`] records routed traffic.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sanstun::Error;
use sanstun::{Committed, Decrypted, PendingDecapsulate, ReceivedMessage, Tunnel, TunnelConfig};
use sanstun::{Interface, Received};
use sanstun::{PresharedKey, PublicKey, StaticSecret};
use zeroize::Zeroizing;

// Define constants independently from the implementation to check conformance
// to the WireGuard whitepaper (§6.1, p. 14).
pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
pub const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
pub const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
pub const COOKIE_EXPIRATION_TIME: Duration = Duration::from_secs(120);
/// Handshake initiations are delayed by a random jitter of up to 333ms (§6.1).
pub const MAX_JITTER: Duration = Duration::from_millis(333);

/// The initiator's sending cutoff leaves `KEEPALIVE_TIMEOUT` for packets to
/// reach the peer before session expiry.
pub const SHOULD_NOT_USE_AFTER_TIME: Duration = Duration::from_secs(180 - 10);

/// A data message carries 16 bytes of header plus a 16-byte AEAD tag (§5.4.6).
pub const DATA_OVERHEAD: usize = 32;
/// A keepalive is a data message with an empty payload (§6.1).
pub const KEEPALIVE_SIZE: usize = DATA_OVERHEAD;
pub const HANDSHAKE_INIT_SIZE: usize = 148;
pub const HANDSHAKE_RESPONSE_SIZE: usize = 92;
pub const COOKIE_REPLY_SIZE: usize = 64;

/// sanstun uses an 8192-packet replay window; the paper uses 2000 packets.
pub const REPLAY_WINDOW: u64 = 8192;

/// Handshakes per second before a peer considers itself under load.
const HANDSHAKE_RATE_LIMIT: u64 = 10;

/// Timing tolerance for events that take multiple polls to schedule and emit.
pub const TICK: Duration = Duration::from_millis(100);

pub const BUF: usize = 4096;

pub fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Peer {
    A,
    B,
}

impl Peer {
    pub fn other(self) -> Peer {
        match self {
            Peer::A => Peer::B,
            Peer::B => Peer::A,
        }
    }
}

/// A datagram's protocol message type.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Init,
    Response,
    CookieReply,
    Data,
    Keepalive,
}

/// Classifies a datagram by message type and size (§5.4).
pub fn classify(datagram: &[u8]) -> Kind {
    let message_type = u32::from_le_bytes(datagram[..4].try_into().unwrap());

    match (message_type, datagram.len()) {
        (1, HANDSHAKE_INIT_SIZE) => Kind::Init,
        (2, HANDSHAKE_RESPONSE_SIZE) => Kind::Response,
        (3, COOKIE_REPLY_SIZE) => Kind::CookieReply,
        (4, KEEPALIVE_SIZE) => Kind::Keepalive,
        (4, len) if len > DATA_OVERHEAD => Kind::Data,
        other => panic!("only valid packets should be routed, got {other:?}"),
    }
}

/// Returns the receiver index identifying a data message's session.
pub fn receiver_index(datagram: &[u8]) -> u32 {
    assert!(matches!(classify(datagram), Kind::Data | Kind::Keepalive));

    u32::from_le_bytes(datagram[4..8].try_into().unwrap())
}

/// Returns a data message's counter, also used as its nonce (§5.4.6).
pub fn counter(datagram: &[u8]) -> u64 {
    assert!(matches!(classify(datagram), Kind::Data | Kind::Keepalive));

    u64::from_le_bytes(datagram[8..16].try_into().unwrap())
}

/// A datagram observed on the simulated wire.
#[derive(Debug)]
pub struct Event {
    /// Time since the start of the simulation.
    pub at: Duration,
    pub from: Peer,
    pub kind: Kind,
}

/// The result of feeding a single datagram into one peer.
#[derive(Debug)]
pub enum Out {
    /// A decrypted IP packet destined for the tunnel interface.
    Ip(Vec<u8>),
    /// A datagram to be sent back over the network.
    Net(Vec<u8>),
    Err(Error),
}

pub trait Outcome {
    fn expect_one_ip(self) -> Vec<u8>;
    fn expect_one_net(self) -> Vec<u8>;
    fn expect_err(self) -> Error;
    fn expect_consumed(self);
}

impl Outcome for Vec<Out> {
    #[track_caller]
    fn expect_one_ip(self) -> Vec<u8> {
        match <[Out; 1]>::try_from(self) {
            Ok([Out::Ip(p)]) => p,
            other => panic!("expected a single IP packet, got {other:?}"),
        }
    }

    #[track_caller]
    fn expect_one_net(self) -> Vec<u8> {
        match <[Out; 1]>::try_from(self) {
            Ok([Out::Net(p)]) => p,
            other => panic!("expected a single network packet, got {other:?}"),
        }
    }

    #[track_caller]
    fn expect_err(self) -> Error {
        match <[Out; 1]>::try_from(self) {
            Ok([Out::Err(e)]) => e,
            other => panic!("expected an error, got {other:?}"),
        }
    }

    #[track_caller]
    fn expect_consumed(self) {
        assert!(
            self.is_empty(),
            "expected the packet to be consumed silently, got {self:?}"
        );
    }
}

fn tunnel_config(psk: Option<[u8; 32]>, persistent_keepalive: Option<Duration>) -> TunnelConfig {
    let mut config = TunnelConfig::default();
    if let Some(psk) = psk {
        config = config.with_preshared_key(PresharedKey::from(Zeroizing::new(psk)));
    }
    if let Some(interval) = persistent_keepalive {
        config = config.with_persistent_keepalive(interval);
    }

    config
}

struct Node {
    tunn: Tunnel,
    interface: Interface,
    psk: Option<[u8; 32]>,
    addr: SocketAddr,
    inbox: Vec<Vec<u8>>,
    errors: Vec<Error>,
    expirations: usize,
    establishments: Vec<(Instant, Instant)>,
    drop_outgoing: bool,
}

pub struct Builder {
    psk_a: Option<[u8; 32]>,
    psk_b: Option<[u8; 32]>,
    persistent_keepalive_b: Option<Duration>,
    seed_a: [u8; 32],
    seed_b: [u8; 32],
    static_keys: Option<([u8; 32], [u8; 32])>,
    responder_under_load: bool,
    responder_expects_different_key: bool,
}

impl Builder {
    pub fn psk_a(mut self, psk: [u8; 32]) -> Self {
        self.psk_a = Some(psk);
        self
    }

    pub fn psk_b(mut self, psk: [u8; 32]) -> Self {
        self.psk_b = Some(psk);
        self
    }

    pub fn persistent_keepalive_b(mut self, interval: Duration) -> Self {
        self.persistent_keepalive_b = Some(interval);
        self
    }

    pub fn seeds(mut self, seed_a: [u8; 32], seed_b: [u8; 32]) -> Self {
        self.seed_a = seed_a;
        self.seed_b = seed_b;
        self
    }

    /// Sets fixed static private keys.
    pub fn static_keys(mut self, secret_a: [u8; 32], secret_b: [u8; 32]) -> Self {
        self.static_keys = Some((secret_a, secret_b));
        self
    }

    /// Requires a cookie for every handshake with the responder (§5.3).
    pub fn responder_under_load(mut self) -> Self {
        self.responder_under_load = true;
        self
    }

    /// Gives the responder an incorrect public key for the initiator.
    pub fn responder_expects_different_key(mut self) -> Self {
        self.responder_expects_different_key = true;
        self
    }

    pub fn build(self) -> Sim {
        let start = Instant::now();
        let unix = Duration::from_secs(1_700_000_000);

        let (secret_a, secret_b) = match self.static_keys {
            Some((a, b)) => (
                StaticSecret::from(Zeroizing::new(a)),
                StaticSecret::from(Zeroizing::new(b)),
            ),
            None => (
                StaticSecret::from(Zeroizing::new(rand::random())),
                StaticSecret::from(Zeroizing::new(rand::random())),
            ),
        };
        let public_a = PublicKey::from(&secret_a);
        let public_b = PublicKey::from(&secret_b);

        let limit_b = if self.responder_under_load {
            0
        } else {
            HANDSHAKE_RATE_LIMIT
        };
        let mut interface_a = Interface::new(Zeroizing::new(self.seed_a), start, unix)
            .with_static_private(secret_a)
            .with_handshake_limit(HANDSHAKE_RATE_LIMIT);
        let mut interface_b = Interface::new(Zeroizing::new(self.seed_b), start, unix)
            .with_static_private(secret_b)
            .with_handshake_limit(limit_b);

        let a = interface_a
            .new_tunnel(public_b, tunnel_config(self.psk_a, None), start)
            .expect("the test keys are valid");

        let expected_by_b = if self.responder_expects_different_key {
            PublicKey::from(&StaticSecret::from(Zeroizing::new(rand::random())))
        } else {
            public_a
        };
        let b = interface_b
            .new_tunnel(
                expected_by_b,
                tunnel_config(self.psk_b, self.persistent_keepalive_b),
                start,
            )
            .expect("the test keys are valid");

        Sim {
            start,
            now: start,
            nodes: [
                Node {
                    tunn: a,
                    interface: interface_a,
                    psk: self.psk_a,
                    addr: "10.0.0.1:51820".parse().unwrap(),
                    inbox: Vec::new(),
                    errors: Vec::new(),
                    expirations: 0,
                    establishments: Vec::new(),
                    drop_outgoing: false,
                },
                Node {
                    tunn: b,
                    interface: interface_b,
                    psk: self.psk_b,
                    addr: "10.0.0.2:51820".parse().unwrap(),
                    inbox: Vec::new(),
                    errors: Vec::new(),
                    expirations: 0,
                    establishments: Vec::new(),
                    drop_outgoing: false,
                },
            ],
            log: Vec::new(),
        }
    }
}

/// Two connected tunnels, with `A` usually initiating and `B` responding.
pub struct Sim {
    start: Instant,
    pub now: Instant,
    nodes: [Node; 2],
    pub log: Vec<Event>,
}

impl Sim {
    pub fn builder() -> Builder {
        Builder {
            psk_a: None,
            psk_b: None,
            persistent_keepalive_b: None,
            seed_a: [1; 32],
            seed_b: [2; 32],
            static_keys: None,
            responder_under_load: false,
            responder_expects_different_key: false,
        }
    }

    /// Creates a pair without an established session.
    pub fn new() -> Sim {
        Sim::builder().build()
    }

    /// Creates a connected pair with an empty packet log.
    pub fn connected() -> Sim {
        let mut sim = Sim::new();
        sim.establish();
        sim.clear_log();
        sim
    }

    fn node(&self, peer: Peer) -> &Node {
        &self.nodes[peer as usize]
    }

    fn node_mut(&mut self, peer: Peer) -> &mut Node {
        &mut self.nodes[peer as usize]
    }

    pub fn tunn(&self, peer: Peer) -> &Tunnel {
        &self.node(peer).tunn
    }

    pub fn tunn_mut(&mut self, peer: Peer) -> &mut Tunnel {
        &mut self.node_mut(peer).tunn
    }

    /// Replaces `peer`'s tunnel, preserving its interface and remote public key.
    pub fn replace_tunnel(&mut self, peer: Peer) {
        let now = self.now;
        let node = self.node_mut(peer);
        let remote = node.tunn.remote_static_public();

        node.tunn = node
            .interface
            .new_tunnel(remote, tunnel_config(node.psk, None), now)
            .expect("the test keys are valid");
    }

    pub fn elapsed(&self) -> Duration {
        self.now - self.start
    }

    /// Returns whether `peer` has an established session.
    pub fn is_established(&self, peer: Peer) -> bool {
        self.tunn(peer)
            .time_since_last_handshake(self.now)
            .is_some()
    }

    pub fn errors(&self, peer: Peer) -> &[Error] {
        &self.node(peer).errors
    }

    /// Counts [`sanstun::Event::ConnectionExpired`] events from `peer`.
    pub fn expirations(&self, peer: Peer) -> usize {
        self.node(peer).expirations
    }

    /// Returns `(started_at, confirmed_at)` of each [`sanstun::Event::Established`] from `peer`.
    pub fn establishments(&self, peer: Peer) -> &[(Instant, Instant)] {
        &self.node(peer).establishments
    }

    pub fn take_inbox(&mut self, peer: Peer) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.node_mut(peer).inbox)
    }

    /// Drops all subsequent packets in both directions.
    pub fn cut_link(&mut self) {
        self.nodes[0].drop_outgoing = true;
        self.nodes[1].drop_outgoing = true;
    }

    pub fn heal_link(&mut self) {
        self.nodes[0].drop_outgoing = false;
        self.nodes[1].drop_outgoing = false;
    }

    /// Advances time without polling either peer, simulating host suspension.
    pub fn suspend(&mut self, duration: Duration) {
        self.now += duration;
    }

    /// Advances time, polling at each announced deadline and routing emitted packets.
    ///
    /// Relying on `poll_timeout` exposes missing deadlines. The loop also checks
    /// that polling clears each deadline, so a stale timer cannot stall the caller.
    pub fn advance(&mut self, duration: Duration) {
        let end = self.now + duration;
        let mut polls_at_now = 0;

        while self.now < end {
            let next = [Peer::A, Peer::B]
                .into_iter()
                .filter_map(|peer| self.tunn(peer).poll_timeout())
                .min()
                // A deadline may have passed during suspension.
                .map(|at| at.max(self.now))
                .unwrap_or(end);

            // Several timers can be due at once. Repeated polls must eventually clear them.
            if next == self.now {
                polls_at_now += 1;
            } else {
                polls_at_now = 0;
            }
            assert!(
                polls_at_now < 10,
                "a deadline at {:?} is announced repeatedly but never fires",
                self.now
            );

            self.now = std::cmp::min(next, end);
            self.poll(Peer::A);
            self.poll(Peer::B);
        }
    }

    fn poll(&mut self, peer: Peer) {
        let now = self.now;
        self.tunn_mut(peer).handle_timeout(now);

        for datagram in self.drain_events(peer) {
            self.route(peer, datagram);
        }
    }

    /// Routes a datagram and its replies until the network is quiet, logging dropped packets too.
    pub fn route(&mut self, from: Peer, datagram: Vec<u8>) {
        let mut in_flight = VecDeque::from([(from, datagram)]);
        let mut hops = 0;

        while let Some((from, datagram)) = in_flight.pop_front() {
            hops += 1;
            assert!(
                hops < 64,
                "too many packets in flight; is the tunnel looping?"
            );

            self.log.push(Event {
                at: self.elapsed(),
                from,
                kind: classify(&datagram),
            });

            if self.node(from).drop_outgoing {
                continue;
            }

            let to = from.other();
            for out in self.deliver(to, &datagram) {
                match out {
                    Out::Net(reply) => in_flight.push_back((to, reply)),
                    Out::Ip(packet) => self.node_mut(to).inbox.push(packet),
                    Out::Err(e) => self.node_mut(to).errors.push(e),
                }
            }
        }
    }

    /// Delivers a datagram directly, bypassing the log and link faults and returning any replies.
    pub fn deliver(&mut self, to: Peer, datagram: &[u8]) -> Vec<Out> {
        let src = self.node(to.other()).addr;
        self.deliver_from(to, datagram, src)
    }

    /// Receives a datagram on `to`'s [`Interface`] from its peer's address.
    pub fn try_receive(&mut self, to: Peer, datagram: &[u8]) -> Result<Received, Error> {
        let src = self.node(to.other()).addr;
        self.try_receive_from(to, datagram, src)
    }

    /// Receives a datagram on `to`'s [`Interface`] from `src`.
    pub fn try_receive_from(
        &mut self,
        to: Peer,
        datagram: &[u8],
        src: SocketAddr,
    ) -> Result<Received, Error> {
        let now = self.now;
        self.node_mut(to).interface.receive(src, datagram, now)
    }

    /// Receives a datagram, panicking unless the interface accepts it as a message.
    #[track_caller]
    pub fn receive(&mut self, to: Peer, datagram: &[u8]) -> ReceivedMessage {
        match self.try_receive(to, datagram) {
            Ok(Received::Message(message)) => message,
            other => panic!("expected a message, got {other:?}"),
        }
    }

    fn deliver_from(&mut self, to: Peer, datagram: &[u8], src: SocketAddr) -> Vec<Out> {
        let now = self.now;
        let node = self.node_mut(to);
        let mut outs = Vec::new();

        let message = match node.interface.receive(src, datagram, now) {
            Ok(Received::Message(message)) => message,
            Ok(Received::SendCookieReply(reply)) => return vec![Out::Net(reply.to_vec())],
            Err(e) => return vec![Out::Err(e)],
        };

        match message {
            ReceivedMessage::HandshakeInitiation(init) => {
                match node.tunn.handle_handshake_initiation(init, now) {
                    Ok(response) => outs.push(Out::Net(response.to_vec())),
                    Err(e) => outs.push(Out::Err(e)),
                }
            }
            ReceivedMessage::HandshakeResponse(response) => {
                match node.tunn.handle_handshake_response(response, now) {
                    Ok(keepalive) => outs.push(Out::Net(keepalive.to_vec())),
                    Err(e) => outs.push(Out::Err(e)),
                }
            }
            ReceivedMessage::CookieReply(reply) => {
                if let Err(e) = node.tunn.handle_cookie_reply(reply, now) {
                    outs.push(Out::Err(e));
                }
            }
            ReceivedMessage::TransportData(data) => match node.tunn.begin_decapsulate(data, now) {
                Err(e) => outs.push(Out::Err(e)),
                Ok(pending) => {
                    let decrypted = pending.decrypt(datagram, vec![0u8; BUF]);
                    match self.commit(to, decrypted) {
                        Ok(None) => {}
                        Ok(Some(ip_packet)) => outs.push(Out::Ip(ip_packet)),
                        Err(e) => outs.push(Out::Err(e)),
                    }
                }
            },
        }
        outs.extend(self.drain_events(to).into_iter().map(Out::Net));

        outs
    }

    /// Drains `peer`'s events and returns outgoing datagrams.
    fn drain_events(&mut self, peer: Peer) -> Vec<Vec<u8>> {
        let node = self.node_mut(peer);
        let mut outgoing = Vec::new();

        while let Some(event) = node.tunn.poll_event() {
            match event {
                sanstun::Event::SendHandshakeInitiation(datagram)
                | sanstun::Event::SendKeepalive(datagram) => outgoing.push(datagram.to_vec()),
                sanstun::Event::Established {
                    started_at,
                    confirmed_at,
                } => node.establishments.push((started_at, confirmed_at)),
                sanstun::Event::ConnectionExpired => node.expirations += 1,
            }
        }

        outgoing
    }

    /// Prepares a data message for decryption on `to`.
    #[track_caller]
    pub fn prepare_decrypt(
        &mut self,
        to: Peer,
        datagram: &[u8],
    ) -> Result<PendingDecapsulate, Error> {
        let now = self.now;
        let ReceivedMessage::TransportData(data) = self.receive(to, datagram) else {
            panic!("expected a data message");
        };

        self.tunn_mut(to).begin_decapsulate(data, now)
    }

    /// Commits a decryption on `to`, returning an IP packet or `None` for a keepalive.
    pub fn commit<B: AsRef<[u8]>>(
        &mut self,
        to: Peer,
        decrypted: Decrypted<B>,
    ) -> Result<Option<Vec<u8>>, Error> {
        let now = self.now;
        match self.tunn_mut(to).commit_decapsulate(decrypted, now)? {
            Committed::Data { buffer, len } => {
                let payload = &buffer.as_ref()[..len];

                Ok(Some(payload[..ip_packet_len(payload)].to_vec()))
            }
            Committed::Keepalive => Ok(None),
        }
    }

    /// Creates a handshake initiation from `peer` without delivering it.
    #[track_caller]
    pub fn initiate_handshake(&mut self, peer: Peer) -> Vec<u8> {
        let now = self.now;
        self.node_mut(peer)
            .tunn
            .initiate_handshake(now)
            .expect("a handshake initiation to be emitted")
            .to_vec()
    }

    /// Creates an initiation even if a handshake is already in progress.
    #[track_caller]
    pub fn force_handshake_initiation(&mut self, peer: Peer) -> Vec<u8> {
        let now = self.now;
        self.node_mut(peer)
            .tunn
            .restart_handshake(now)
            .expect("a handshake initiation to be emitted")
            .to_vec()
    }

    /// Completes a handshake initiated by `A`.
    #[track_caller]
    pub fn establish(&mut self) {
        let init = self.initiate_handshake(Peer::A);
        self.route(Peer::A, init);

        assert!(
            self.is_established(Peer::A),
            "initiator has no session after handshake"
        );
        assert!(
            self.is_established(Peer::B),
            "responder has no session after handshake"
        );
    }

    /// Encrypts an IP packet, panicking if there is no usable session.
    #[track_caller]
    pub fn encapsulate(&mut self, from: Peer, ip_packet: &[u8]) -> Vec<u8> {
        self.try_encapsulate(from, ip_packet)
            .expect("an active session")
    }

    pub fn try_encapsulate(&mut self, from: Peer, ip_packet: &[u8]) -> Result<Vec<u8>, Error> {
        let now = self.now;
        let mut buf = vec![0u8; BUF];
        let packet = self
            .node_mut(from)
            .tunn
            .begin_encapsulate(now)?
            .encrypt(ip_packet, &mut buf)?;
        Ok(packet.to_vec())
    }

    /// Encrypts an IP packet and routes it through the network.
    pub fn send_ip(&mut self, from: Peer, ip_packet: &[u8]) {
        let datagram = self.encapsulate(from, ip_packet);
        self.route(from, datagram);
    }

    /// Sends an IP packet in each direction and checks that both arrive.
    #[track_caller]
    pub fn assert_connectivity(&mut self) {
        for from in [Peer::A, Peer::B] {
            let ip_packet = ipv4_packet(format!("ping from {from:?}").as_bytes());
            self.send_ip(from, &ip_packet);

            let received = self
                .node_mut(from.other())
                .inbox
                .pop()
                .unwrap_or_else(|| panic!("{:?} did not receive the packet", from.other()));
            assert_eq!(received, ip_packet);
        }
    }

    pub fn clear_log(&mut self) {
        self.log.clear();
    }

    /// Returns send times for packets of `kind`, measured from the start of the simulation.
    pub fn sent_at(&self, from: Peer, kind: Kind) -> Vec<Duration> {
        self.log
            .iter()
            .filter(|e| e.from == from && e.kind == kind)
            .map(|e| e.at)
            .collect()
    }

    pub fn count(&self, from: Peer, kind: Kind) -> usize {
        self.sent_at(from, kind).len()
    }
}

/// Checks that an event fired at `expected`, allowing for jitter and polling delay.
#[track_caller]
pub fn assert_fires_at(actual: Duration, expected: Duration) {
    let latest = expected + MAX_JITTER + 2 * TICK;
    assert!(
        (expected..=latest).contains(&actual),
        "event fired at {actual:?}, expected between {expected:?} and {latest:?}"
    );
}

/// Checks that an event fired within the polling tolerance of `expected`.
#[track_caller]
pub fn assert_close(actual: Duration, expected: Duration) {
    assert!(
        actual.abs_diff(expected) <= 2 * TICK,
        "event fired at {actual:?}, expected {expected:?} (±{:?})",
        2 * TICK
    );
}

/// Returns the IP packet length, excluding trailing padding.
pub fn ip_packet_len(buffer: &[u8]) -> usize {
    match buffer[0] >> 4 {
        4 => u16::from_be_bytes([buffer[2], buffer[3]]).into(),
        6 => 40 + usize::from(u16::from_be_bytes([buffer[4], buffer[5]])),
        version => panic!("expected an IP packet, got version {version}"),
    }
}

pub fn ipv4_packet(payload: &[u8]) -> Vec<u8> {
    let builder =
        etherparse::PacketBuilder::ipv4([192, 0, 2, 1], [192, 0, 2, 2], 64).udp(1111, 2222);
    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut packet, payload).unwrap();
    packet
}

pub fn ipv6_packet(payload: &[u8]) -> Vec<u8> {
    let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let builder = etherparse::PacketBuilder::ipv6(src, dst, 64).udp(1111, 2222);
    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut packet, payload).unwrap();
    packet
}
