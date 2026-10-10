//! A deterministic test harness that drives two [`Tunnel`] instances against
//! each other over an in-memory network with a virtual clock.
//!
//! Time only moves when a test says so ([`Sim::advance`]), packets only flow
//! when routed ([`Sim::route`]) or hand-delivered ([`Sim::deliver`]), and all
//! routed traffic is recorded in [`Sim::log`] so tests can assert *what* was
//! sent *when*.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rand::SeedableRng;
use rand::rngs::StdRng;

use sanstun::Error;
use sanstun::{Committed, Decrypted, Packet, PendingDecapsulate, Tunnel};
use sanstun::{Interface, Received};
use sanstun::{PresharedKey, PublicKey, StaticSecret};

// Protocol constants from the WireGuard whitepaper (§6.1, table on p. 14).
// They are deliberately redefined here instead of imported: the tests assert
// that the implementation conforms to the paper, not to itself.
pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
pub const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
pub const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
pub const COOKIE_EXPIRATION_TIME: Duration = Duration::from_secs(120);
/// Handshake initiations are delayed by a random jitter of up to 333ms (§6.1).
pub const MAX_JITTER: Duration = Duration::from_millis(333);

/// sanstun stops *initiating* on a session `KEEPALIVE_TIMEOUT` before
/// `REJECT_AFTER_TIME`, so that packets sent just before the deadline can
/// still be decrypted by the peer (implementation-specific safety margin).
pub const SHOULD_NOT_USE_AFTER_TIME: Duration = Duration::from_secs(180 - 10);

/// A data message carries 16 bytes of header plus a 16-byte AEAD tag (§5.4.6).
pub const DATA_OVERHEAD: usize = 32;
/// A keepalive is a data message with an empty payload (§6.1).
pub const KEEPALIVE_SIZE: usize = DATA_OVERHEAD;
pub const HANDSHAKE_INIT_SIZE: usize = 148;
pub const HANDSHAKE_RESPONSE_SIZE: usize = 92;
pub const COOKIE_REPLY_SIZE: usize = 64;

/// sanstun's anti-replay window: 128 words of 64 bits each
/// (implementation-specific; the paper's reference window is 2000 packets).
pub const REPLAY_WINDOW: u64 = 8192;

/// Handshake messages per second a peer accepts before it considers itself under load.
const HANDSHAKE_RATE_LIMIT: u64 = 10;

/// Slack the timing assertions allow on either side of a deadline, covering the
/// few polls a peer may take to act on one (scheduling a handshake at one
/// instant, sending it at the next).
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

/// What a datagram on the simulated wire is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Init,
    Response,
    CookieReply,
    Data,
    Keepalive,
}

/// The kind of a datagram by its message type and size (§5.4).
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

/// The receiver index of a data message, identifying the session it uses.
pub fn receiver_index(datagram: &[u8]) -> u32 {
    assert!(matches!(classify(datagram), Kind::Data | Kind::Keepalive));

    u32::from_le_bytes(datagram[4..8].try_into().unwrap())
}

/// The counter of a data message, which doubles as its nonce (§5.4.6).
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

struct Node {
    tunn: Tunnel,
    interface: Interface,
    psk: Option<[u8; 32]>,
    addr: SocketAddr,
    inbox: Vec<Vec<u8>>,
    errors: Vec<Error>,
    expirations: usize,
    drop_outgoing: bool,
}

pub struct Builder {
    psk_a: Option<[u8; 32]>,
    psk_b: Option<[u8; 32]>,
    persistent_keepalive_b: Option<u16>,
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

    pub fn persistent_keepalive_b(mut self, interval_secs: u16) -> Self {
        self.persistent_keepalive_b = Some(interval_secs);
        self
    }

    pub fn seeds(mut self, seed_a: [u8; 32], seed_b: [u8; 32]) -> Self {
        self.seed_a = seed_a;
        self.seed_b = seed_b;
        self
    }

    /// Use fixed static private keys instead of random ones.
    pub fn static_keys(mut self, secret_a: [u8; 32], secret_b: [u8; 32]) -> Self {
        self.static_keys = Some((secret_a, secret_b));
        self
    }

    /// Give the responder an [`Interface`] that considers it permanently under
    /// load, forcing the cookie mechanism (§5.3) on every handshake.
    pub fn responder_under_load(mut self) -> Self {
        self.responder_under_load = true;
        self
    }

    /// Configure the responder to expect a different static public key than
    /// the initiator's.
    pub fn responder_expects_different_key(mut self) -> Self {
        self.responder_expects_different_key = true;
        self
    }

    pub fn build(self) -> Sim {
        let start = Instant::now();
        let unix = Duration::from_secs(1_700_000_000);

        let (secret_a, secret_b) = match self.static_keys {
            Some((a, b)) => (StaticSecret::from(a), StaticSecret::from(b)),
            None => (
                StaticSecret::from(rand::random::<[u8; 32]>()),
                StaticSecret::from(rand::random::<[u8; 32]>()),
            ),
        };
        let public_a = PublicKey::from(&secret_a);
        let public_b = PublicKey::from(&secret_b);

        let limit_b = if self.responder_under_load {
            0
        } else {
            HANDSHAKE_RATE_LIMIT
        };
        let mut interface_a = Interface::new(&mut StdRng::from_seed(self.seed_a), start, unix)
            .with_static_private(secret_a)
            .with_handshake_limit(HANDSHAKE_RATE_LIMIT);
        let mut interface_b = Interface::new(&mut StdRng::from_seed(self.seed_b), start, unix)
            .with_static_private(secret_b)
            .with_handshake_limit(limit_b);

        let a = interface_a
            .new_tunnel(public_b, self.psk_a.map(PresharedKey::from), None, start)
            .expect("the test keys are valid");

        let expected_by_b = if self.responder_expects_different_key {
            PublicKey::from(&StaticSecret::from(rand::random::<[u8; 32]>()))
        } else {
            public_a
        };
        let b = interface_b
            .new_tunnel(
                expected_by_b,
                self.psk_b.map(PresharedKey::from),
                self.persistent_keepalive_b,
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
                    drop_outgoing: false,
                },
            ],
            log: Vec::new(),
        }
    }
}

/// Two [`Tunnel`] instances (`A`, the conventional initiator, and `B`, the
/// responder) connected by a simulated network.
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

    /// A fresh pair without an established session.
    pub fn new() -> Sim {
        Sim::builder().build()
    }

    /// A pair with a completed handshake and an empty packet log.
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

    /// Replace the tunnel of `peer` with a fresh one to the same remote static key, created by
    /// the same [`Interface`], as a caller does after dropping a tunnel.
    pub fn replace_tunnel(&mut self, peer: Peer) {
        let now = self.now;
        let node = self.node_mut(peer);
        let remote = node.tunn.remote_static_public();

        node.tunn = node
            .interface
            .new_tunnel(remote, node.psk.map(PresharedKey::from), None, now)
            .expect("the test keys are valid");
    }

    pub fn elapsed(&self) -> Duration {
        self.now - self.start
    }

    /// Whether `peer` currently has a usable session.
    pub fn is_established(&self, peer: Peer) -> bool {
        self.tunn(peer)
            .time_since_last_handshake(self.now)
            .is_some()
    }

    pub fn errors(&self, peer: Peer) -> &[Error] {
        &self.node(peer).errors
    }

    /// How often `peer` emitted [`sanstun::Event::ConnectionExpired`].
    pub fn expirations(&self, peer: Peer) -> usize {
        self.node(peer).expirations
    }

    pub fn take_inbox(&mut self, peer: Peer) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.node_mut(peer).inbox)
    }

    // --- Network fault injection ---

    /// Drop all packets in both directions from now on.
    pub fn cut_link(&mut self) {
        self.nodes[0].drop_outgoing = true;
        self.nodes[1].drop_outgoing = true;
    }

    pub fn heal_link(&mut self) {
        self.nodes[0].drop_outgoing = false;
        self.nodes[1].drop_outgoing = false;
    }

    // --- Driving the tunnels ---

    /// Advance time without polling either peer, as when the host suspends.
    ///
    /// Every deadline inside the window goes unserviced; the next poll meets
    /// them all at once.
    pub fn suspend(&mut self, duration: Duration) {
        self.now += duration;
    }

    /// Advance the virtual clock, driving both peers purely by the instants they
    /// announce via `poll_timeout` and routing whatever they emit.
    ///
    /// Rather than polling on a fixed interval, we jump straight to the earliest
    /// instant either peer asked to be called back at. That asserts two things
    /// about `poll_timeout` on every test that advances time.
    ///
    /// It is *complete*: a caller that only ever polls at the announced instants
    /// observes exactly the same behaviour as one polling once a second.
    ///
    /// Every instant it announces is also *actionable*: polling at one clears
    /// it. A deadline that survived being polled would be handed straight back
    /// here and stall the loop, which the assertion below reports.
    pub fn advance(&mut self, duration: Duration) {
        let end = self.now + duration;
        let mut polls_at_now = 0;

        while self.now < end {
            let next = [Peer::A, Peer::B]
                .into_iter()
                .filter_map(|peer| self.tunn(peer).poll_timeout())
                .map(|(at, _reason)| at)
                .min()
                // Never move backwards: a deadline may have elapsed already.
                .map(|at| at.max(self.now))
                .unwrap_or(end);

            // Landing on the current instant is legitimate as long as each poll
            // drains a timer that is due; the peers hold a handful between them,
            // so only a long run of them means one never fires at all.
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

    /// Put a datagram on the wire and let the peers exchange packets until the
    /// network is quiet. Every datagram is logged, dropped datagrams included.
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

    /// Feed a single datagram into `to`, bypassing the network (and thus the
    /// log and any link faults). Replies are returned, not routed.
    pub fn deliver(&mut self, to: Peer, datagram: &[u8]) -> Vec<Out> {
        let src = self.node(to.other()).addr;
        self.deliver_from(to, datagram, src)
    }

    /// Run a datagram through the [`Interface`] of `to`, as if sent by its peer.
    pub fn try_receive<'a>(&mut self, to: Peer, datagram: &'a [u8]) -> Result<Received<'a>, Error> {
        let src = self.node(to.other()).addr;
        self.try_receive_from(to, datagram, src)
    }

    /// Run a datagram through the [`Interface`] of `to`, as if sent from `src`.
    pub fn try_receive_from<'a>(
        &mut self,
        to: Peer,
        datagram: &'a [u8],
        src: SocketAddr,
    ) -> Result<Received<'a>, Error> {
        let now = self.now;
        self.node_mut(to).interface.receive(src, datagram, now)
    }

    /// Like [`Sim::try_receive`], panicking unless the datagram passes.
    #[track_caller]
    pub fn receive<'a>(&mut self, to: Peer, datagram: &'a [u8]) -> Packet<'a> {
        match self.try_receive(to, datagram) {
            Ok(Received::Packet(packet)) => packet,
            other => panic!("expected a packet, got {other:?}"),
        }
    }

    fn deliver_from(&mut self, to: Peer, datagram: &[u8], src: SocketAddr) -> Vec<Out> {
        let now = self.now;
        let node = self.node_mut(to);
        let mut outs = Vec::new();

        let packet = match node.interface.receive(src, datagram, now) {
            Ok(Received::Packet(packet)) => packet,
            Ok(Received::CookieReply(reply)) => return vec![Out::Net(reply.to_vec())],
            Err(e) => return vec![Out::Err(e)],
        };

        match node.tunn.decapsulate(packet, now) {
            Ok(None) => {}
            Err(e) => outs.push(Out::Err(e)),
            Ok(Some(pending)) => {
                let decrypted = pending.decrypt(datagram, vec![0u8; BUF]);
                match self.commit(to, decrypted) {
                    Ok(None) => {}
                    Ok(Some(ip_packet)) => outs.push(Out::Ip(ip_packet)),
                    Err(e) => outs.push(Out::Err(e)),
                }
            }
        }
        outs.extend(self.drain_events(to).into_iter().map(Out::Net));

        outs
    }

    /// Drain the events of `peer`, returning the datagrams it needs to send.
    fn drain_events(&mut self, peer: Peer) -> Vec<Vec<u8>> {
        let now = self.now;
        let node = self.node_mut(peer);
        let mut outgoing = Vec::new();

        while let Some(event) = node.tunn.poll_event() {
            match event {
                sanstun::Event::HandshakeInitiation(packet) => outgoing.push(packet.to_vec()),
                sanstun::Event::HandshakeResponse(packet) => outgoing.push(packet.to_vec()),
                sanstun::Event::KeepaliveDue(keepalive) => outgoing.push(
                    node.tunn
                        .encapsulate_keepalive(keepalive, now)
                        .expect("a keepalive is only due on a usable session")
                        .to_vec(),
                ),
                sanstun::Event::ConnectionExpired => node.expirations += 1,
            }
        }

        outgoing
    }

    /// Feed a data message into `to`, stopping before its decryption.
    #[track_caller]
    pub fn prepare_decrypt(
        &mut self,
        to: Peer,
        datagram: &[u8],
    ) -> Result<PendingDecapsulate, Error> {
        let now = self.now;
        let packet = self.receive(to, datagram);
        let pending = self.tunn_mut(to).decapsulate(packet, now)?;

        Ok(pending.expect("a data message"))
    }

    /// Complete a decryption on `to`, yielding the IP packet, or `None` for a
    /// keepalive.
    pub fn commit<B: AsRef<[u8]>>(
        &mut self,
        to: Peer,
        decrypted: Decrypted<B>,
    ) -> Result<Option<Vec<u8>>, Error> {
        let now = self.now;
        match self.tunn_mut(to).commit_decrypted(decrypted, now)? {
            Committed::Data { buffer, len } => {
                let payload = &buffer.as_ref()[..len];

                Ok(Some(payload[..ip_packet_len(payload)].to_vec()))
            }
            Committed::Keepalive => Ok(None),
        }
    }

    // --- Handshakes ---

    /// Create (but do not deliver) a handshake initiation from `peer`.
    #[track_caller]
    pub fn initiate_handshake(&mut self, peer: Peer) -> Vec<u8> {
        self.handshake_initiation(peer, false)
            .expect("a handshake initiation to be emitted")
    }

    /// Like [`Sim::initiate_handshake`], but also when one is already in flight.
    #[track_caller]
    pub fn force_handshake_initiation(&mut self, peer: Peer) -> Vec<u8> {
        self.handshake_initiation(peer, true)
            .expect("a handshake initiation to be emitted")
    }

    fn handshake_initiation(&mut self, peer: Peer, force: bool) -> Option<Vec<u8>> {
        let now = self.now;
        self.node_mut(peer)
            .tunn
            .format_handshake_initiation(force, now)
            .map(|p| p.to_vec())
    }

    /// Complete a full handshake initiated by `A`.
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

    // --- Data transfer ---

    /// Encrypt an IP packet on the current session, panicking if there is none.
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
            .encapsulate_data(now)?
            .encrypt(ip_packet, &mut buf)?;
        Ok(packet.to_vec())
    }

    /// Encrypt an IP packet and route it through the network.
    pub fn send_ip(&mut self, from: Peer, ip_packet: &[u8]) {
        let datagram = self.encapsulate(from, ip_packet);
        self.route(from, datagram);
    }

    /// Send one IP packet in each direction and assert that both arrive.
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

    // --- Log queries ---

    pub fn clear_log(&mut self) {
        self.log.clear();
    }

    /// Times (since simulation start) at which `from` sent packets of `kind`.
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

// --- Assertion helpers ---

/// Assert that a (possibly jittered) timer event fired at `expected`:
/// no earlier, and no later than jitter plus polling granularity allow.
#[track_caller]
pub fn assert_fires_at(actual: Duration, expected: Duration) {
    let latest = expected + MAX_JITTER + 2 * TICK;
    assert!(
        (expected..=latest).contains(&actual),
        "event fired at {actual:?}, expected between {expected:?} and {latest:?}"
    );
}

/// Assert that an unjittered timer event fired at `expected`, give or take
/// polling granularity.
#[track_caller]
pub fn assert_close(actual: Duration, expected: Duration) {
    assert!(
        actual.abs_diff(expected) <= 2 * TICK,
        "event fired at {actual:?}, expected {expected:?} (±{:?})",
        2 * TICK
    );
}

// --- Test IP packets ---

/// The length of the IP packet at the start of `buffer`, i.e. without the padding behind it.
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
