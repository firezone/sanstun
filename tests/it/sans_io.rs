//! Time handling and determinism in the sans-IO API.

use crate::harness::{
    KEEPALIVE_SIZE, KEEPALIVE_TIMEOUT, Kind, MAX_JITTER, Outcome as _, Peer::A, Peer::B,
    REJECT_AFTER_TIME, REKEY_AFTER_TIME, REKEY_TIMEOUT, Sim, classify, ipv4_packet, secs,
};
use sanstun::{Error, Event, ReceivedMessage};
use std::time::Duration;

/// Timer-driven handshakes use up to 333ms of jitter, exposed through `poll_timeout`.
#[test]
fn scheduled_handshake_honours_poll_timeout() {
    let mut sim = Sim::connected();
    sim.advance(secs(1));
    sim.cut_link();
    sim.send_ip(A, &ipv4_packet(b"unanswered"));

    let deadline = sim.now + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT;
    let tunn = sim.tunn_mut(A);

    tunn.handle_timeout(deadline - Duration::from_millis(1));
    assert!(tunn.poll_event().is_none());

    // The first deadline schedules the handshake with jitter.
    tunn.handle_timeout(deadline);
    assert!(tunn.poll_event().is_none());
    let wake = tunn.poll_timeout().expect("a scheduled handshake");
    assert!(wake >= deadline && wake <= deadline + MAX_JITTER);

    // The jittered deadline emits it exactly once.
    tunn.handle_timeout(wake);
    let Some(Event::SendHandshakeInitiation(initiation)) = tunn.poll_event() else {
        panic!("expected the scheduled handshake initiation");
    };
    assert_eq!(classify(&initiation), Kind::Init);
    tunn.handle_timeout(wake);
    assert!(tunn.poll_event().is_none());
}

#[test]
fn poll_timeout_predicts_the_passive_keepalive() {
    let mut sim = Sim::connected();
    let established_at = sim.now;
    sim.advance(secs(1));

    let datagram = sim.encapsulate(A, &ipv4_packet(b"ping"));
    sim.deliver(B, &datagram).expect_one_ip();
    let received_at = sim.now;

    let tunn = sim.tunn_mut(B);
    let wake = tunn.poll_timeout().expect("a pending keepalive");
    assert_eq!(wake, received_at + KEEPALIVE_TIMEOUT);

    tunn.handle_timeout(wake - Duration::from_millis(1));
    assert!(tunn.poll_event().is_none());
    tunn.handle_timeout(wake);
    let Some(Event::SendKeepalive(packet)) = tunn.poll_event() else {
        panic!("expected the keepalive");
    };
    assert_eq!(packet.len(), KEEPALIVE_SIZE);

    // Sending the keepalive leaves only the session expiry timer.
    let wake = tunn
        .poll_timeout()
        .expect("a session that still expires eventually");
    assert_eq!(wake, established_at + REJECT_AFTER_TIME);
}

/// Sending on an old session arms a rekey timer whose deadline has already passed.
/// `poll_timeout` must still return a deadline at or after the current time.
#[test]
fn poll_timeout_never_points_into_the_past() {
    let mut sim = Sim::connected();

    sim.advance(REKEY_AFTER_TIME + secs(1));

    sim.send_ip(A, &ipv4_packet(b"traffic after a long silence"));

    let wake = sim.tunn(A).poll_timeout().expect("a rekey is now due");
    assert!(
        wake >= sim.now,
        "poll_timeout returned an instant {:?} before now",
        sim.now.duration_since(wake),
    );
}

/// A late poll reports expiry once, even after missing every intermediate deadline.
#[test]
fn a_single_late_poll_observes_the_expiry() {
    let mut sim = Sim::connected();

    let late = sim.now + 4 * REJECT_AFTER_TIME;
    let tunn = sim.tunn_mut(A);
    tunn.handle_timeout(late);

    assert!(matches!(tunn.poll_event(), Some(Event::ConnectionExpired)));
    assert!(tunn.is_expired());

    tunn.handle_timeout(late + secs(1));
    assert!(tunn.poll_event().is_none());
}

#[test]
fn identical_seeds_produce_identical_schedules() {
    fn retransmissions(seed: u8) -> Vec<Duration> {
        let mut sim = Sim::builder()
            .seeds([seed; 32], [seed.wrapping_add(1); 32])
            .build();
        sim.cut_link();
        let init = sim.initiate_handshake(A);
        sim.route(A, init);
        sim.advance(secs(30));
        sim.sent_at(A, Kind::Init)
    }

    assert_eq!(retransmissions(7), retransmissions(7));
}

#[test]
fn different_seeds_produce_different_jitter() {
    fn first_jitter(seed: u8) -> Duration {
        let mut sim = Sim::builder().seeds([seed; 32], [99; 32]).build();
        let _init = sim.initiate_handshake(A);

        let retry_due = sim.now + REKEY_TIMEOUT;
        let tunn = sim.tunn_mut(A);
        tunn.handle_timeout(retry_due);
        assert!(tunn.poll_event().is_none());

        tunn.poll_timeout()
            .expect("a scheduled retry")
            .duration_since(retry_due)
    }

    assert_eq!(first_jitter(1), first_jitter(1));
    assert_ne!(first_jitter(1), first_jitter(2));
}

#[test]
fn encapsulate_data_has_no_side_effects_without_a_session() {
    let mut sim = Sim::new();

    let result = sim.try_encapsulate(A, &ipv4_packet(b"no session yet"));
    assert!(matches!(result, Err(Error::NoCurrentSession)));

    sim.advance(secs(10)); // Wait beyond `REKEY_TIMEOUT`.

    assert!(
        sim.log.is_empty(),
        "no handshake should have been initiated"
    );
}

/// Expiry must fire at its announced deadline; returning that same deadline would cause a busy loop.
#[test]
fn the_announced_session_expiry_is_actionable() {
    let mut sim = Sim::connected();
    let session_expiry = sim.now + REJECT_AFTER_TIME;

    // Drain the earlier timers so the session expiry is the next deadline.
    sim.advance(REJECT_AFTER_TIME - secs(1));
    let now = sim.now;
    let tunn = sim.tunn_mut(A);
    tunn.handle_timeout(now);

    let wake = tunn.poll_timeout().expect("a session that still expires");
    assert_eq!(
        wake, session_expiry,
        "expected the session expiry to be the next deadline"
    );

    tunn.handle_timeout(wake);

    assert_ne!(
        tunn.poll_timeout(),
        Some(wake),
        "polling at the announced instant left the same deadline outstanding"
    );
}

#[test]
fn poll_timeout_is_due_while_events_are_queued() {
    let mut sim = Sim::new();
    let init = sim.initiate_handshake(A);
    let response = sim.deliver(B, &init).expect_one_net();
    sim.advance(secs(1));

    let ReceivedMessage::HandshakeResponse(response) = sim.receive(A, &response) else {
        panic!("expected a handshake response");
    };
    let now = sim.now;
    let tunn = sim.tunn_mut(A);
    tunn.handle_handshake_response(response, now).unwrap();

    assert!(tunn.poll_timeout().is_some_and(|wake| wake <= now));
    assert!(
        matches!(tunn.poll_event(), Some(Event::Established { confirmed_at, .. }) if confirmed_at == now)
    );
    assert!(tunn.poll_timeout().is_some_and(|wake| wake > now));
}

#[test]
fn identical_seeds_produce_identical_handshakes() {
    assert_eq!(handshake([3; 32]), handshake([3; 32]));
    assert_ne!(handshake([3; 32]).0, handshake([5; 32]).0);

    fn handshake(seed_a: [u8; 32]) -> (Vec<u8>, Vec<u8>) {
        let mut sim = Sim::builder()
            .static_keys([1; 32], [2; 32])
            .seeds(seed_a, [4; 32])
            .build();

        let init = sim.initiate_handshake(A);
        let response = sim.deliver(B, &init).expect_one_net();

        (init, response)
    }
}
