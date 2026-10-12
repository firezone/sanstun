//! Cookie-based DoS mitigation (whitepaper §5.3): a responder under load
//! answers handshakes with a cookie reply instead of doing expensive
//! computation, and only proceeds once the initiator proves IP ownership by
//! echoing the cookie in mac2.

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

/// The [`Interface`](sanstun::Interface) answers an initiation without a valid
/// mac2 on its own, so the initiation never reaches the expensive handshake
/// processing.
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

/// §5.4.4: a datagram shaped like a handshake initiation but without a valid
/// mac1 is rejected before its static key is decrypted, whether or not we are
/// under load.
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

/// The initiator stores the received cookie and its next (retransmitted)
/// initiation carries a valid mac2, which the loaded responder accepts.
#[test]
fn handshake_completes_under_load_via_cookie_retry() {
    let mut sim = Sim::builder().responder_under_load().build();

    let init = sim.initiate_handshake(A);
    sim.route(A, init);
    assert!(
        !sim.is_established(A),
        "first attempt only yielded a cookie"
    );

    // The regular REKEY_TIMEOUT retransmission carries mac2.
    sim.advance(secs(6));

    assert_eq!(sim.count(B, Kind::CookieReply), 1);
    assert_eq!(sim.count(B, Kind::Response), 1);
    assert!(sim.is_established(A));
    assert!(sim.is_established(B));
    sim.assert_connectivity();
}

/// A cookie stays valid for two minutes; within that window new handshakes
/// keep using it and are accepted straight away.
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

/// §5.3 / §6.1: cookies are discarded after `COOKIE_EXPIRATION_TIME`; a later
/// handshake is back to square one and gets a fresh cookie reply.
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

/// An `Interface` with a limit of 10 considers itself under load beyond 10
/// handshake messages per second and recovers once the flood stops.
#[test]
fn rate_limited_tunnel_recovers_once_load_subsides() {
    let mut sim = flooded();

    sim.advance(secs(2)); // The rate limit resets its counter every second.

    let init = sim.force_handshake_initiation(A);
    let response = sim.deliver(B, &init).expect_one_net();
    assert_eq!(classify(&response), Kind::Response);
}

/// The rate limit resets its window lazily when a handshake is received, so
/// it recovers even if no timers are driven in the meantime. This is what lets
/// an idle tunnel avoid waking up once a second just to reset the counter.
#[test]
fn rate_limit_resets_without_driving_timers() {
    let mut sim = flooded();

    // Advance time *without* calling `handle_timeout`, so the only thing that
    // can clear the window is the lazy reset on the next received handshake.
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

    // A valid-looking cookie reply (type 3, 64 bytes) without a preceding
    // handshake from us must not be accepted.
    let mut cookie_reply = vec![0u8; COOKIE_REPLY_SIZE];
    cookie_reply[0] = 3;

    let error = sim.deliver(B, &cookie_reply).expect_err();

    assert!(matches!(error, Error::UnexpectedPacket));
}

/// §5.4.7: a cookie reply only answers the one handshake message whose mac1 it
/// is bound to. Once consumed, a replay of it is rejected.
#[test]
fn cookie_reply_is_only_accepted_once() {
    let mut sim = Sim::builder().responder_under_load().build();
    let init = sim.initiate_handshake(A);
    let reply = sim.deliver(B, &init).expect_one_net();
    sim.deliver(A, &reply).expect_consumed();

    let error = sim.deliver(A, &reply).expect_err();

    assert!(matches!(error, Error::UnexpectedPacket));
}

/// A cookie reply is not proof that the peer is alive: anyone who saw our
/// handshake initiation can get one by replaying it to the peer from their own
/// address. It must not stop us from noticing that our data goes unanswered
/// (§6.3, `KEEPALIVE_TIMEOUT + REKEY_TIMEOUT`).
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

/// Under load, a source with a valid cookie gets a burst of 5 handshake
/// messages before further ones are rejected, ahead of any Diffie-Hellman.
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

/// A rate-limited source regains one handshake message every 50ms, up to the
/// burst of 5.
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

/// Has `A` store the cookie that the loaded responder `B` hands out to `src`.
#[track_caller]
fn fetch_cookie(sim: &mut Sim, src: SocketAddr) {
    let init = sim.force_handshake_initiation(A);
    let result = sim.try_receive_from(B, &init, src);
    let Ok(Received::SendCookieReply(reply)) = result else {
        panic!("expected a cookie reply, got {result:?}");
    };

    sim.deliver(A, &reply).expect_consumed();
}

/// Replays `init` to `B` from `src` until `B` is under load and answers with a
/// cookie reply, as an on-path attacker who saw `init` could.
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

/// Whether a handshake initiation from `A`, sent from `src`, passes the
/// [`Interface`](sanstun::Interface) of `B` rather than being rate-limited.
#[track_caller]
fn passes(sim: &mut Sim, src: SocketAddr) -> bool {
    // `B` rejects an initiation with the same timestamp as the previous one as a replay.
    sim.now += Duration::from_micros(1);
    let init = sim.force_handshake_initiation(A);

    match sim.try_receive_from(B, &init, src) {
        Ok(Received::Message(_)) => true,
        Err(Error::RateLimited) => false,
        other => panic!("expected a message or a rate limit, got {other:?}"),
    }
}

/// A pair whose responder has just answered the 11th handshake initiation
/// within a second with a cookie reply.
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
