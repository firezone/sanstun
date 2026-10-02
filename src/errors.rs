use std::fmt::Display;

#[derive(Debug)]
pub enum Error {
    DestinationBufferTooSmall { required: usize, available: usize },
    UnexpectedPacket,
    WrongIndex,
    WrongKey,
    WrongTai64nTimestamp,
    InvalidMac,
    InvalidAeadTag,
    InvalidCounter,
    DuplicateCounter,
    InvalidPacket,
    NoCurrentSession,
    ConnectionExpired,
    EmptyPlaintext,
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::DestinationBufferTooSmall {
                required,
                available,
            } => write!(
                f,
                "the destination buffer is too small (required: {required}, available: {available})"
            ),
            Error::UnexpectedPacket => write!(
                f,
                "packet of this type was not expected in the current state"
            ),
            Error::WrongIndex => write!(f, "index in packet did not match local state"),
            Error::WrongKey => write!(
                f,
                "decrypted public key from handshake initiation did not match expected key"
            ),
            Error::WrongTai64nTimestamp => {
                write!(f, "timestamp of packet is in the past; possibly a replay?")
            }
            Error::InvalidMac => {
                write!(f, "MAC mismatch in packet")
            }
            Error::InvalidAeadTag => write!(f, "failed to decrypt packet data"),
            Error::InvalidCounter => {
                write!(f, "packet counter is too old")
            }
            Error::DuplicateCounter => {
                write!(f, "packet with same counter already processed")
            }
            Error::InvalidPacket => {
                write!(f, "failed to parse packet (too short / invalid type / etc)")
            }
            Error::NoCurrentSession => write!(f, "no active session"),
            Error::ConnectionExpired => write!(f, "connection is expired"),
            Error::EmptyPlaintext => write!(
                f,
                "an empty data message is a keepalive; send it with `Tunnel::encapsulate_keepalive`"
            ),
        }
    }
}

impl std::error::Error for Error {}
