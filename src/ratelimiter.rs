use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

const DEFAULT_HANDSHAKE_LIMIT: u64 = 100;

const PACKETS_PER_SECOND: u32 = 20;
const PACKETS_BURSTABLE: u32 = 5;
const PACKET_COST: Duration = Duration::from_nanos(1_000_000_000 / PACKETS_PER_SECOND as u64);
const TOKEN_MAX: Duration = PACKET_COST.saturating_mul(PACKETS_BURSTABLE);

/// How long an idle source keeps its bucket.
///
/// The bucket must be full by then so removal does not change the source's budget.
const IDLE_TIMEOUT: Duration = Duration::from_secs(1);
const _: () = assert!(IDLE_TIMEOUT.as_nanos() >= TOKEN_MAX.as_nanos());

const MAX_SOURCES: usize = 65536;

/// Limits handshake processing under load.
///
/// Once the global threshold is reached, each IPv4 address or IPv6 /64 gets a token bucket.
pub(crate) struct RateLimiter {
    limit: u64,
    /// Messages counted since `window_start`.
    count: u64,
    window_start: Instant,
    buckets: HashMap<Source, Bucket>,
    last_gc: Instant,
}

impl RateLimiter {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            limit: DEFAULT_HANDSHAKE_LIMIT,
            count: 0,
            window_start: now,
            buckets: HashMap::new(),
            last_gc: now,
        }
    }

    pub(crate) fn set_limit(&mut self, limit: u64) {
        self.limit = limit;
    }

    /// Counts a handshake message and returns whether it exceeds this second's limit.
    pub(crate) fn is_under_load(&mut self, now: Instant) -> bool {
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            self.count = 0;
            self.window_start = now;
        }

        let count = self.count;
        self.count += 1;

        count >= self.limit
    }

    /// Consumes one token for `addr`, returning whether the packet is allowed.
    ///
    /// Packets from new sources are refused while the table is full.
    pub(crate) fn allow(&mut self, addr: IpAddr, now: Instant) -> bool {
        self.gc(now);

        let source = Source::from(addr);

        if let Some(bucket) = self.buckets.get_mut(&source) {
            return bucket.take(now);
        }

        if self.buckets.len() >= MAX_SOURCES {
            return false;
        }

        self.buckets.insert(
            source,
            Bucket {
                tokens: TOKEN_MAX - PACKET_COST,
                last_seen: now,
            },
        );

        true
    }

    /// Removes idle buckets, at most once per `IDLE_TIMEOUT`.
    fn gc(&mut self, now: Instant) {
        if now.duration_since(self.last_gc) < IDLE_TIMEOUT {
            return;
        }

        for _ in self
            .buckets
            .extract_if(|_, bucket| now.duration_since(bucket.last_seen) >= IDLE_TIMEOUT)
        {}
        self.last_gc = now;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Source {
    V4(Ipv4Addr),
    /// The upper 64 bits of the address.
    V6(u64),
}

impl From<IpAddr> for Source {
    fn from(addr: IpAddr) -> Self {
        match addr.to_canonical() {
            IpAddr::V4(ip) => Source::V4(ip),
            IpAddr::V6(ip) => Source::V6((ip.to_bits() >> 64) as u64),
        }
    }
}

struct Bucket {
    tokens: Duration,
    last_seen: Instant,
}

impl Bucket {
    fn take(&mut self, now: Instant) -> bool {
        self.tokens = (self.tokens + now.duration_since(self.last_seen)).min(TOKEN_MAX);
        self.last_seen = now;

        if self.tokens < PACKET_COST {
            return false;
        }

        self.tokens -= PACKET_COST;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_table_refuses_new_sources_until_idle_ones_are_dropped() {
        let start = Instant::now();
        let mut limiter = RateLimiter::new(start);
        for i in 0..MAX_SOURCES as u32 {
            assert!(limiter.allow(Ipv4Addr::from_bits(i).into(), start));
        }

        let newcomer = Ipv4Addr::new(255, 255, 255, 255).into();
        let known = Ipv4Addr::from_bits(0).into();

        assert!(!limiter.allow(newcomer, start));
        assert!(limiter.allow(known, start));
        assert!(limiter.allow(newcomer, start + IDLE_TIMEOUT));
        assert_eq!(limiter.buckets.len(), 1);
    }

    #[test]
    fn ipv4_mapped_ipv6_sources_are_limited_per_ipv4_address() {
        let now = Instant::now();
        let mut limiter = RateLimiter::new(now);
        let mapped = |ip: Ipv4Addr| IpAddr::V6(ip.to_ipv6_mapped());

        for _ in 0..PACKETS_BURSTABLE {
            assert!(limiter.allow(mapped(Ipv4Addr::new(1, 2, 3, 4)), now));
        }

        assert!(!limiter.allow(Ipv4Addr::new(1, 2, 3, 4).into(), now));
        assert!(limiter.allow(mapped(Ipv4Addr::new(1, 2, 3, 5)), now));
    }
}
