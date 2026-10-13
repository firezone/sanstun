//! A sans-IO implementation of the WireGuard protocol, acting as both initiator and responder.
//!
//! # Example
//!
//! Alice and Bob complete a handshake and Alice sends Bob a packet. In a real application, an
//! event loop carries each message over UDP and drives the timers with [`Tunnel::poll_timeout`]
//! and [`Tunnel::handle_timeout`].
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
//! let Received::Message(message) = bob.receive(alice_addr, &initiation, now)? else {
//!     unreachable!()
//! };
//! bob_to_alice.decapsulate(message, now)?;
//! let Some(Event::SendHandshakeResponse(response)) = bob_to_alice.poll_event() else {
//!     unreachable!()
//! };
//! let Received::Message(message) = alice.receive(bob_addr, &response, now)? else {
//!     unreachable!()
//! };
//! alice_to_bob.decapsulate(message, now)?;
//!
//! // Alice encrypts a packet ...
//! let packet = b"an IP packet";
//! let mut buf = [0; 64];
//! let data = alice_to_bob.encapsulate_data(now)?.encrypt(packet, &mut buf)?;
//!
//! // ... and Bob decrypts it.
//! let Received::Message(message) = bob.receive(alice_addr, &data, now)? else {
//!     unreachable!()
//! };
//! let decrypted = bob_to_alice.decapsulate(message, now)?.unwrap().decrypt(&data, [0; 64]);
//! let Committed::Data { buffer, len } = bob_to_alice.commit_decrypted(decrypted, now)? else {
//!     unreachable!()
//! };
//!
//! // The plaintext is zero-padded to a multiple of 16 bytes.
//! assert_eq!(&buffer[..len], b"an IP packet\0\0\0\0");
//! # Ok::<(), sanstun::Error>(())
//! ```
//!
//! # Caller responsibilities
//!
//! sanstun authenticates and decrypts messages but leaves the following to the caller:
//!
//! - **Cryptokey routing:** a decrypted packet only proves which peer sent it. Drop it unless its
//!   source address is one that peer is allowed to use.
//! - **Handshake routing:** [`HandshakeInitiation::peer_static_public`] is authenticated, but
//!   anyone can generate a key pair and replays are only rejected for keys we created a tunnel
//!   for. Do not create a tunnel for an unknown key based on it.
//! - **Endpoint updates:** anyone can send a datagram from any address. Only move a peer's endpoint
//!   to the source address of a message once [`Tunnel::decapsulate`] accepted its handshake or
//!   [`Tunnel::commit_decrypted`] accepted its data.
//! - **Bounded queues:** a [`PendingDecapsulate`] is cheap to create but costly to decrypt. When
//!   deferring encryption or decryption to other threads, bound the queues in between so a flood of
//!   messages cannot exhaust memory.
//! - **Packet validation:** the plaintext of a data message is zero-padded to a multiple of 16
//!   bytes. Parse the IP packet, check its declared length and strip the padding before passing it
//!   on.
//! - **Silent errors:** an [`Error`] says why a message was dropped. Never send it back to the
//!   peer, as it can reveal internal state such as the replay window.
//! - **Time:** every `now` must come from a monotonic clock, and the Unix time given to
//!   [`Interface::new`] must not go backwards across restarts, or peers reject our handshake
//!   initiations as replays.

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
