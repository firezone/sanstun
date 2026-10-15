//! A sans-IO implementation of the WireGuard protocol.
//!
//! # Example
//!
//! Alice and Bob complete a handshake, then Alice sends Bob a packet. In an application, your
//! event loop sends datagrams over UDP, handles events from [`Tunnel::poll_event`] and drives
//! timers with [`Tunnel::poll_timeout`] and [`Tunnel::handle_timeout`].
//!
//! ```
//! use std::time::{Instant, SystemTime, UNIX_EPOCH};
//!
//! use sanstun::{Committed, Event, Interface, Received, TunnelConfig};
//! use zeroize::Zeroizing;
//!
//! let now = Instant::now();
//! let unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
//! let alice_addr = "192.0.2.1:51820".parse().unwrap();
//! let bob_addr = "192.0.2.2:51820".parse().unwrap();
//!
//! let mut alice = Interface::new(Zeroizing::new(rand::random()), now, unix);
//! let mut bob = Interface::new(Zeroizing::new(rand::random()), now, unix);
//! let mut alice_to_bob = alice.new_tunnel(bob.static_public(), TunnelConfig::default(), now)?;
//! let mut bob_to_alice = bob.new_tunnel(alice.static_public(), TunnelConfig::default(), now)?;
//!
//! // Alice initiates the handshake and Bob responds.
//! let initiation = alice_to_bob.initiate_handshake(now).unwrap();
//! let message = match bob.receive(alice_addr, &initiation, now)? {
//!     Received::Message(message) => message,
//!     // Under load, send the cookie reply back to the peer.
//!     Received::SendCookieReply(_) => unreachable!("not under load"),
//! };
//! bob_to_alice.begin_decapsulate(message, now)?;
//! let response = match bob_to_alice.poll_event() {
//!     Some(Event::SendHandshakeResponse(response)) => response,
//!     event => unreachable!("only the response is queued, got {event:?}"),
//! };
//! let message = match alice.receive(bob_addr, &response, now)? {
//!     Received::Message(message) => message,
//!     Received::SendCookieReply(_) => unreachable!("not under load"),
//! };
//! alice_to_bob.begin_decapsulate(message, now)?;
//!
//! // Alice encrypts a packet.
//! let packet = b"an IP packet";
//! let mut buf = [0; 64];
//! let data = alice_to_bob.begin_encapsulate(now)?.encrypt(packet, &mut buf)?;
//!
//! // Bob decrypts and accepts it.
//! let message = match bob.receive(alice_addr, &data, now)? {
//!     Received::Message(message) => message,
//!     Received::SendCookieReply(_) => unreachable!("not under load"),
//! };
//! let decrypted = bob_to_alice.begin_decapsulate(message, now)?.unwrap().decrypt(&data, [0; 64]);
//! match bob_to_alice.commit_decapsulate(decrypted, now)? {
//!     // The plaintext is zero-padded to a multiple of 16 bytes.
//!     Committed::Data { buffer, len } => assert_eq!(&buffer[..len], b"an IP packet\0\0\0\0"),
//!     // A keepalive carries no packet to forward.
//!     Committed::Keepalive => unreachable!("Alice sent a packet"),
//! }
//! # Ok::<(), sanstun::Error>(())
//! ```
//!
//! # Caller responsibilities
//!
//! sanstun handles the protocol and cryptography. Your application is responsible for:
//!
//! - **Cryptokey routing:** check that each decrypted packet's source IP is allowed for the peer
//!   that sent it. Authentication alone does not grant permission to use an IP address.
//! - **Handshake routing:** use [`HandshakeInitiation::peer_static_public`] to look up an authorized
//!   peer. Anyone can generate a key pair, so an authenticated initiation is no reason to create a
//!   tunnel for an unknown key. Replay checks only apply to keys you have created a tunnel for.
//! - **Endpoint updates:** only update a peer's endpoint after [`Tunnel::begin_decapsulate`] accepts
//!   its handshake or [`Tunnel::commit_decapsulate`] accepts its data. A datagram's source address
//!   alone does not identify the peer.
//! - **Bounded queues:** limit queues used to send encryption or decryption work to other threads.
//!   A [`PendingDecapsulate`] is cheap to create but costly to decrypt, and a flood can exhaust memory.
//! - **Packet validation:** parse decrypted IP packets, check their declared lengths and strip
//!   padding before forwarding them. Data messages are zero-padded to a multiple of 16 bytes.
//! - **Errors:** handle [`Error`] locally. Never send errors to peers; they can reveal internal
//!   state such as the replay window.
//! - **Time:** use a monotonic clock for `now`. The Unix time passed to [`Interface::new`] must
//!   not go backwards across restarts, or peers may reject handshake initiations as replays.

mod crypto;
mod errors;
mod handshake;
mod index;
mod interface;
mod keys;
mod message;
mod ratelimiter;
mod replay;
mod ring_buffer;
mod rng;
mod session;
mod tai64n;
mod timers;
mod tunnel;

pub use errors::Error;
pub use index::TunnelId;
pub use interface::{Interface, Received};
pub use keys::{PresharedKey, PublicKey, StaticSecret};
pub use message::{
    CookieReply, DataMessage, Datagram, HandshakeInitiation, HandshakeResponse, ReceivedMessage,
    TransportData,
};
pub use session::{Decrypted, PendingDecapsulate, PendingEncapsulate};
pub use tunnel::{Committed, Event, Keepalive, Tunnel, TunnelConfig};
