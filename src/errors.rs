use std::fmt::Display;

use crate::PublicKey;

#[derive(Debug)]
pub enum Error {
    DestinationBufferTooSmall { required: usize, available: usize },
    UnexpectedPacket,
    WrongIndex,
    WrongKey,
    ReplayedHandshakeInitiation { peer_static_public: PublicKey },
    InvalidMac,
    InvalidAeadTag,
    InvalidCounter,
    DuplicateCounter,
    InvalidPacket,
    NoCurrentSession,
    ConnectionExpired,
    EmptyPlaintext,
    LowOrderPoint,
    RateLimited,
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::DestinationBufferTooSmall {
                required,
                available,
            } => write!(
                f,
                "destination buffer too small: need {required} bytes, have {available}"
            ),
            Error::UnexpectedPacket => write!(f, "unexpected packet type for the current state"),
            Error::WrongIndex => write!(f, "packet index does not match the expected index"),
            Error::WrongKey => write!(f, "handshake public key does not match the expected peer"),
            Error::ReplayedHandshakeInitiation { .. } => write!(
                f,
                "handshake initiation is not newer than the last one accepted from this peer"
            ),
            Error::InvalidMac => {
                write!(f, "invalid packet MAC")
            }
            Error::InvalidAeadTag => write!(f, "packet authentication failed"),
            Error::InvalidCounter => {
                write!(f, "packet counter is outside the allowed range")
            }
            Error::DuplicateCounter => {
                write!(f, "packet counter has already been accepted")
            }
            Error::InvalidPacket => {
                write!(f, "invalid packet format")
            }
            Error::NoCurrentSession => write!(f, "no active session"),
            Error::ConnectionExpired => {
                write!(f, "connection expired; create a new tunnel to reconnect")
            }
            Error::EmptyPlaintext => write!(
                f,
                "an empty data message is a keepalive; the tunnel sends those itself"
            ),
            Error::LowOrderPoint => write!(
                f,
                "low-order public key produces an all-zero X25519 shared secret"
            ),
            Error::RateLimited => write!(
                f,
                "too many handshake messages from this source while under load"
            ),
        }
    }
}

impl std::error::Error for Error {}
