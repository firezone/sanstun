//! Cookie-based DoS mitigation (whitepaper §5.3): a responder under load
//! answers handshakes with a cookie reply instead of doing expensive
//! computation, and only proceeds once the initiator proves IP ownership by
//! echoing the cookie in mac2.

use crate::harness::{
    COOKIE_EXPIRATION_TIME, COOKIE_REPLY_SIZE, HANDSHAKE_INIT_SIZE, Kind, Outcome as _, Peer::A,
    Peer::B, Sim, classify, secs,
};
use sanstun::{Error, Received};
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

/// The [`Ingress`](sanstun::Ingress) answers an initiation without a valid
/// mac2 on its own, so the initiation never reaches the expensive handshake
/// processing.
#[test]
fn ingress_replies_with_a_cookie_before_any_tunnel_is_involved() {
    let mut sim = Sim::builder().responder_under_load().build();

    let init = sim.initiate_handshake(A);
    let result = sim.try_receive(B, &init);

    let Ok(Received::CookieReply(reply)) = result else {
        panic!("expected a cookie reply, got {result:?}");
    };
    assert_eq!(classify(&reply), Kind::CookieReply);
}

/// §5.4.4: a datagram shaped like a handshake initiation but without a valid
/// mac1 is rejected before its static key is decrypted, whether or not we are
/// under load.
#[test]
fn ingress_rejects_an_initiation_without_a_valid_mac1() {
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

/// An `Ingress` with a limit of 10 considers itself under load beyond 10
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

    // Advance time *without* calling `update_timers`, so the only thing that
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
