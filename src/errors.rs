// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::fmt::Display;

#[derive(Debug)]
pub enum Error {
    DestinationBufferTooSmall,
    UnexpectedPacket,
    WrongIndex,
    WrongKey,
    InvalidTai64nTimestamp,
    WrongTai64nTimestamp,
    InvalidMac,
    InvalidAeadTag,
    InvalidCounter,
    DuplicateCounter,
    InvalidPacket,
    NoCurrentSession,
    ConnectionExpired,
    UnderLoad,
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::DestinationBufferTooSmall => {
                write!(f, "the destination buffer is too small")
            }
            Error::UnexpectedPacket => write!(
                f,
                "packet of this type was not expected in the current state"
            ),
            Error::WrongIndex => write!(f, "index in packet did not match local state"),
            Error::WrongKey => write!(
                f,
                "decrypted public key from handshake initiation did not match expected key"
            ),
            Error::InvalidTai64nTimestamp => write!(f, "timestamp is less than 12bytes"),
            Error::WrongTai64nTimestamp => {
                write!(f, "timestamp of packet is in the past; possible a replay?")
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
            Error::UnderLoad => write!(f, "rate limit exceeded"),
        }
    }
}

impl std::error::Error for Error {}
