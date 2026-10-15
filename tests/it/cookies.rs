//! Cookie-based DoS mitigation (whitepaper §5.3): a responder under load
//! requires a valid cookie in `mac2` before doing expensive handshake work.

use crate::harness::{
    COOKIE_EXPIRATION_TIME, COOKIE_REPLY_SIZE, HANDSHAKE_INIT_SIZE, KEEPALIVE_TIMEOUT, Kind,
    Outcome as _, Peer::A, Peer::B, REKEY_TIMEOUT, Sim, assert_fires_at, classify, ipv4_packet,
    secs,
};
use sanstun::{Error, Received};
use std::net::SocketAddr;
use std::time::Duration;

#[test]
fn responder_under_load_replies_with_a_cookie_instead_of_a_handshake() {
    let mut sim = Sim::builder().responder_under_load().build();

    let init = sim.initiate_handshake(A);
    let reply = sim.deliver(B, &init).expect_one_net();

    assert_eq!(classify(&reply), Kind::CookieReply);
    assert_eq!(reply.len(), COOKIE_REPLY_SIZE); // §5.4.7
    assert!(!sim.is_established(B), "no session state was created");
}

/// Cookie replies are handled by the [`Interface`](sanstun::Interface), before tunnel processing.
#[test]
fn interface_replies_with_a_cookie_before_any_tunnel_is_involved() {
    let mut sim = Sim::builder().responder_under_load().build();

    let init = sim.initiate_handshake(A);
    let result = sim.try_receive(B, &init);

    let Ok(Received::SendCookieReply(reply)) = result else {
        panic!("expected a cookie reply, got {result:?}");
    };
    assert_eq!(classify(&reply), Kind::CookieReply);
}

/// §5.4.4: an invalid `mac1` is rejected before any key exchange, even without load.
#[test]
fn interface_rejects_an_initiation_without_a_valid_mac1() {
    let mut garbage = [0xa5; HANDSHAKE_INIT_SIZE];
    garbage[..4].copy_from_slice(&1u32.to_le_bytes());

    for mut sim in [Sim::new(), Sim::builder().responder_under_load().build()] {
        let result = sim.try_receive(B, &garbage);

        assert!(
            matches!(result, Err(Error::InvalidMac)),
            "expected an invalid mac1, got {result:?}"
        );
    }
}

/// The handshake retry carries the cookie in `mac2`, allowing it through under load.
#[test]
fn handshake_completes_under_load_via_cookie_retry() {
    let mut sim = Sim::builder().responder_under_load().build();

    let init = sim.initiate_handshake(A);
    sim.route(A, init);
    assert!(
        !sim.is_established(A),
        "first attempt only yielded a cookie"
    );

    // Wait for the retry carrying `mac2`.
    sim.advance(secs(6));

    assert_eq!(sim.count(B, Kind::CookieReply), 1);
    assert_eq!(sim.count(B, Kind::Response), 1);
    assert!(sim.is_established(A));
    assert!(sim.is_established(B));
    sim.assert_connectivity();
}

/// A cookie can be reused for two minutes.
#[test]
fn fresh_cookie_is_reused_for_subsequent_handshakes() {
    let mut sim = Sim::builder().responder_under_load().build();
    let init = sim.initiate_handshake(A);
    sim.route(A, init);
    sim.advance(secs(6)); // Complete the handshake via the cookie retry.

    sim.advance(secs(30));
    let init = sim.force_handshake_initiation(A);
    let response = sim.deliver(B, &init).expect_one_net();

    assert_eq!(classify(&response), Kind::Response);
}

/// §5.3 / §6.1: a handshake with an expired cookie receives a fresh cookie reply.
#[test]
fn expired_cookie_forces_a_new_cookie_round_trip() {
    let mut sim = Sim::builder().responder_under_load().build();
    let init = sim.initiate_handshake(A);
    sim.route(A, init);
    sim.advance(secs(6));
    assert!(sim.is_established(A));

    sim.advance(COOKIE_EXPIRATION_TIME);
    let init = sim.force_handshake_initiation(A);
    let reply = sim.deliver(B, &init).expect_one_net();

    assert_eq!(classify(&reply), Kind::CookieReply);
}

#[test]
fn rate_limited_tunnel_recovers_once_load_subsides() {
    let mut sim = flooded();

    sim.advance(secs(2));

    let init = sim.force_handshake_initiation(A);
    let response = sim.deliver(B, &init).expect_one_net();
    assert_eq!(classify(&response), Kind::Response);
}

/// Resetting the rate limit on receive lets idle tunnels avoid periodic wakeups.
#[test]
fn rate_limit_resets_without_driving_timers() {
    let mut sim = flooded();

    // Bypass the timers so only the next handshake can reset the window.
    sim.now += secs(2);

    let init = sim.force_handshake_initiation(A);
    let response = sim.deliver(B, &init).expect_one_net();
    assert_eq!(
        classify(&response),
        Kind::Response,
        "window reset on receive, no timer needed"
    );
}

#[test]
fn cookie_reply_out_of_the_blue_is_rejected() {
    let mut sim = Sim::new();

    let mut cookie_reply = vec![0u8; COOKIE_REPLY_SIZE];
    cookie_reply[0] = 3;

    let error = sim.deliver(B, &cookie_reply).expect_err();

    assert!(matches!(error, Error::UnexpectedPacket));
}

/// §5.4.7: a cookie reply is bound to one handshake's `mac1` and can only be used once.
#[test]
fn cookie_reply_is_only_accepted_once() {
    let mut sim = Sim::builder().responder_under_load().build();
    let init = sim.initiate_handshake(A);
    let reply = sim.deliver(B, &init).expect_one_net();
    sim.deliver(A, &reply).expect_consumed();

    let error = sim.deliver(A, &reply).expect_err();

    assert!(matches!(error, Error::UnexpectedPacket));
}

/// An attacker can solicit a cookie reply by replaying our initiation from another address.
/// That reply must not reset the unanswered-data timer (§6.3).
#[test]
fn cookie_reply_does_not_count_as_a_reply_to_unanswered_data() {
    let mut sim = Sim::new();
    let init = sim.initiate_handshake(A);
    sim.route(A, init.clone());
    let cookie_reply = solicit_cookie_reply(&mut sim, &init, addr("192.0.2.66:4444"));
    sim.clear_log();

    sim.advance(secs(1));
    sim.cut_link();
    sim.send_ip(A, &ipv4_packet(b"into the void"));
    sim.advance(secs(5));
    sim.deliver(A, &cookie_reply).expect_consumed();
    sim.advance(secs(11));

    let inits = sim.sent_at(A, Kind::Init);
    assert_eq!(inits.len(), 1, "expected a new handshake, got {inits:?}");
    assert_fires_at(inits[0], secs(1) + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT);
}

/// Under load, even handshakes with valid cookies are rate-limited before key exchange.
#[test]
fn valid_cookies_are_rate_limited_per_source() {
    let mut sim = Sim::builder().responder_under_load().build();
    let src = addr("192.0.2.1:51820");
    fetch_cookie(&mut sim, src);

    for _ in 0..5 {
        assert!(passes(&mut sim, src));
    }
    assert!(!passes(&mut sim, src));
}

/// The rate limit recovers one handshake every 50ms, up to a burst of five.
#[test]
fn rate_limited_source_regains_a_handshake_every_50ms() {
    let mut sim = Sim::builder().responder_under_load().build();
    let src = addr("192.0.2.1:51820");
    exhaust(&mut sim, src);

    sim.now += Duration::from_millis(50);
    assert!(passes(&mut sim, src));
    assert!(!passes(&mut sim, src));

    sim.now += secs(1);
    for _ in 0..5 {
        assert!(passes(&mut sim, src));
    }
    assert!(!passes(&mut sim, src));
}

#[test]
fn ipv4_sources_are_rate_limited_per_address_regardless_of_port() {
    let mut sim = Sim::builder().responder_under_load().build();
    exhaust(&mut sim, addr("192.0.2.1:51820"));

    let other_port = addr("192.0.2.1:51821");
    fetch_cookie(&mut sim, other_port);
    assert!(!passes(&mut sim, other_port));

    let other_address = addr("192.0.2.2:51820");
    fetch_cookie(&mut sim, other_address);
    assert!(passes(&mut sim, other_address));
}

#[test]
fn ipv6_sources_are_rate_limited_per_64() {
    let mut sim = Sim::builder().responder_under_load().build();
    exhaust(&mut sim, addr("[2001:db8::1]:51820"));

    let same_64 = addr("[2001:db8::ffff:1]:51820");
    fetch_cookie(&mut sim, same_64);
    assert!(!passes(&mut sim, same_64));

    let other_64 = addr("[2001:db8:0:1::1]:51820");
    fetch_cookie(&mut sim, other_64);
    assert!(passes(&mut sim, other_64));
}

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// Stores a cookie from `B` for `src` on `A`.
#[track_caller]
fn fetch_cookie(sim: &mut Sim, src: SocketAddr) {
    let init = sim.force_handshake_initiation(A);
    let result = sim.try_receive_from(B, &init, src);
    let Ok(Received::SendCookieReply(reply)) = result else {
        panic!("expected a cookie reply, got {result:?}");
    };

    sim.deliver(A, &reply).expect_consumed();
}

/// Replays `init` from `src` until `B` responds with a cookie.
#[track_caller]
fn solicit_cookie_reply(sim: &mut Sim, init: &[u8], src: SocketAddr) -> Vec<u8> {
    for _ in 0..100 {
        if let Ok(Received::SendCookieReply(reply)) = sim.try_receive_from(B, init, src) {
            return reply.to_vec();
        }
    }

    panic!("expected the replayed initiation to put B under load");
}

/// Fetches a cookie for `src` and uses up its burst.
#[track_caller]
fn exhaust(sim: &mut Sim, src: SocketAddr) {
    fetch_cookie(sim, src);
    for _ in 0..5 {
        assert!(passes(sim, src));
    }
    assert!(!passes(sim, src));
}

/// Returns whether `B` accepts a handshake from `src` without rate limiting.
#[track_caller]
fn passes(sim: &mut Sim, src: SocketAddr) -> bool {
    // Give each initiation a distinct timestamp to avoid replay rejection.
    sim.now += Duration::from_micros(1);
    let init = sim.force_handshake_initiation(A);

    match sim.try_receive_from(B, &init, src) {
        Ok(Received::Message(_)) => true,
        Err(Error::RateLimited) => false,
        other => panic!("expected a message or a rate limit, got {other:?}"),
    }
}

/// Exceeds `B`'s handshake limit and returns the pair after a cookie reply.
#[track_caller]
fn flooded() -> Sim {
    let mut sim = Sim::new();

    for _ in 0..10 {
        let init = sim.force_handshake_initiation(A);
        sim.deliver(B, &init).expect_one_net();
        sim.now += Duration::from_millis(10);
    }

    let init = sim.force_handshake_initiation(A);
    let reply = sim.deliver(B, &init).expect_one_net();
    assert_eq!(
        classify(&reply),
        Kind::CookieReply,
        "11th handshake within a second"
    );

    sim
}
