use std::convert::TryInto;
use std::fmt::{self, Debug};
use std::time::{Duration, Instant};

/// A 12-byte [TAI64N](https://cr.yp.to/libtai/tai64.html) timestamp.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tai64N {
    secs: u64,
    nano: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct TimeStamper {
    unix: Duration,
    created_at: Instant,
}

impl TimeStamper {
    pub(crate) fn new(now: Instant, unix: Duration) -> TimeStamper {
        TimeStamper {
            unix,
            created_at: now,
        }
    }

    /// Generates a timestamp for `now`.
    pub(crate) fn stamp(&self, now: Instant) -> [u8; 12] {
        let mut ext_stamp = [0u8; 12];
        let stamp = now.duration_since(self.created_at) + self.unix;
        ext_stamp[0..8].copy_from_slice(&(stamp.as_secs() + Tai64N::BASE).to_be_bytes());
        ext_stamp[8..12].copy_from_slice(&stamp.subsec_nanos().to_be_bytes());
        ext_stamp
    }
}

impl Tai64N {
    const BASE: u64 = (1u64 << 62) + 37;

    /// Returns a timestamp with all bytes set to zero.
    pub(crate) fn zero() -> Tai64N {
        Tai64N { secs: 0, nano: 0 }
    }

    pub(crate) fn parse(buf: &[u8; 12]) -> Tai64N {
        let (sec_bytes, nano_bytes) = buf.split_at(std::mem::size_of::<u64>());
        let secs = u64::from_be_bytes(sec_bytes.try_into().unwrap());
        let nano = u32::from_be_bytes(nano_bytes.try_into().unwrap());

        // WireGuard only requires timestamps to increase, so no calendar validation is needed.
        Tai64N { secs, nano }
    }

    /// Returns whether this timestamp is later than `other`.
    pub(crate) fn after(&self, other: &Tai64N) -> bool {
        (self.secs > other.secs) || ((self.secs == other.secs) && (self.nano > other.nano))
    }
}

impl fmt::Display for Tai64N {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let duration = Duration::from_secs(self.secs.saturating_sub(Self::BASE))
            + Duration::from_nanos(self.nano as u64);

        duration.fmt(f)
    }
}

impl fmt::Debug for Tai64N {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}
