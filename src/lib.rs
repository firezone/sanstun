//! A sans-IO implementation of the WireGuard protocol, acting as both initiator and responder.
//!
//! # Caller responsibilities
//!
//! sanstun authenticates and decrypts messages but leaves the following to the caller:
//!
//! - **Cryptokey routing:** a decrypted packet only proves which peer sent it. Drop it unless its
//!   source address is one that peer is allowed to use.
//! - **Handshake routing:** [`HandshakeInit::peer_static_public`] is an unauthenticated claim
//!   until [`Tunnel::decapsulate`] accepts the initiation. Use it only to find the tunnel; do not
//!   trust it, log it as the sender or create a tunnel for an unknown key based on it.
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
mod message;
mod ratelimiter;
mod replay;
mod ring_buffer;
mod session;
mod tai64n;
mod timers;
mod tunnel;

pub use errors::Error;
pub use interface::{Interface, Received};
pub use message::{
    CookieReplyMessage, DataMessage, HandshakeInit, HandshakeInitiationMessage, HandshakeResponse,
    HandshakeResponseMessage, KeepaliveMessage, Packet, PacketCookieReply, PacketData,
};
pub use session::{Decrypted, PendingDecapsulate, PendingEncapsulate};
pub use tunnel::{Committed, Event, Keepalive, Tunnel};
pub use x25519_dalek::{PublicKey, StaticSecret};
