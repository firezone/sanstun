//! Contracts specific to the sans-IO design: callers inject time explicitly,
//! learn when to call back via `poll_timeout`, and must get identical
//! behaviour for identical inputs.

use crate::harness::{
    KEEPALIVE_SIZE, KEEPALIVE_TIMEOUT, Kind, MAX_JITTER, Outcome as _, Peer::A, Peer::B,
    REJECT_AFTER_TIME, REKEY_AFTER_TIME, REKEY_TIMEOUT, Sim, classify, ipv4_packet, secs,
};
use sanstun::{Error, Event};
use std::time::Duration;

/// A handshake triggered by a timer is not sent immediately: it is scheduled
/// with a random jitter of up to 333ms, announced via `poll_timeout` and
/// emitted exactly once when that deadline is polled.
#[test]
fn scheduled_handshake_honours_poll_timeout() {
    let mut sim = Sim::connected();
    sim.advance(secs(1));
    sim.cut_link();
    sim.send_ip(A, &ipv4_packet(b"unanswered"));

    let deadline = sim.now + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT;
    let tunn = sim.tunn_mut(A);

    // Nothing is due before the deadline.
    tunn.handle_timeout(deadline - Duration::from_millis(1));
    assert!(tunn.poll_event().is_none());

    // At the deadline, the handshake is only *scheduled* ...
    tunn.handle_timeout(deadline);
    assert!(tunn.poll_event().is_none());
    let (wake, _reason) = tunn.poll_timeout().expect("a scheduled handshake");
    assert!(wake >= deadline && wake <= deadline + MAX_JITTER);

    // ... and emitted exactly once when the announced instant is polled.
    tunn.handle_timeout(wake);
    let Some(Event::HandshakeInitiation(packet)) = tunn.poll_event() else {
        panic!("expected the scheduled handshake initiation");
    };
    assert_eq!(classify(&packet), Kind::Init);
    tunn.handle_timeout(wake);
    assert!(tunn.poll_event().is_none());
}

#[test]
fn poll_timeout_predicts_the_passive_keepalive() {
    let mut sim = Sim::connected();
    sim.advance(secs(1));

    let datagram = sim.encapsulate(A, &ipv4_packet(b"ping"));
    sim.deliver(B, &datagram).expect_one_ip();
    let received_at = sim.now;

    let tunn = sim.tunn_mut(B);
    let (wake, _reason) = tunn.poll_timeout().expect("a pending keepalive");
    assert_eq!(wake, received_at + KEEPALIVE_TIMEOUT);

    tunn.handle_timeout(wake - Duration::from_millis(1));
    assert!(tunn.poll_event().is_none());
    tunn.handle_timeout(wake);
    let Some(Event::KeepaliveDue(keepalive)) = tunn.poll_event() else {
        panic!("expected the keepalive");
    };
    let packet = tunn.encapsulate_keepalive(keepalive, wake).unwrap();
    assert_eq!(packet.len(), KEEPALIVE_SIZE);

    // The passive keepalive has been answered, so it must not re-arm; the only
    // thing left on the clock is the eventual session expiry.
    let (_wake, reason) = tunn
        .poll_timeout()
        .expect("a session that still expires eventually");
    assert_eq!(reason, "next expired session");
}

/// `poll_timeout` must never announce an instant in the past. Timers are
/// anchored to the session start, so sending on a session already older than
/// `REKEY_AFTER_TIME` arms the rekey-on-send timer with a deadline that has
/// already elapsed; the caller must still be handed a usable (not past) instant.
#[test]
fn poll_timeout_never_points_into_the_past() {
    let mut sim = Sim::connected();

    // Age the session past REKEY_AFTER_TIME. With no traffic, nothing rekeys, so
    // the session is still alive and its start is now well over REKEY_AFTER_TIME
    // in the past.
    sim.advance(REKEY_AFTER_TIME + secs(1));

    // Sending now arms the rekey-on-send timer, whose deadline (session start +
    // REKEY_AFTER_TIME) is already behind us.
    sim.send_ip(A, &ipv4_packet(b"traffic after a long silence"));

    let (wake, _reason) = sim.tunn(A).poll_timeout().expect("a rekey is now due");
    assert!(
        wake >= sim.now,
        "poll_timeout returned an instant {:?} before now",
        sim.now.duration_since(wake),
    );
}

/// Callers may poll arbitrarily rarely; a single call after a long gap must
/// still observe the (by then) expired state instead of panicking or hanging.
/// Polling again reports nothing new.
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

/// The only source of randomness in timer behaviour is the seeded jitter RNG:
/// identical seeds must produce identical retransmission schedules.
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

        // Once REKEY_TIMEOUT passes, a retry is scheduled `jitter` in the future.
        let retry_due = sim.now + REKEY_TIMEOUT;
        let tunn = sim.tunn_mut(A);
        tunn.handle_timeout(retry_due);
        assert!(tunn.poll_event().is_none());

        tunn.poll_timeout()
            .expect("a scheduled retry")
            .0
            .duration_since(retry_due)
    }

    assert_eq!(first_jitter(1), first_jitter(1));
    assert_ne!(first_jitter(1), first_jitter(2));
}

/// `encapsulate_data` is advertised as side-effect free when no session
/// exists: no packet is queued and no handshake is started.
#[test]
fn encapsulate_data_has_no_side_effects_without_a_session() {
    let mut sim = Sim::new();

    let result = sim.try_encapsulate(A, &ipv4_packet(b"no session yet"));
    assert!(matches!(result, Err(Error::NoCurrentSession)));

    sim.advance(secs(10)); // Well past REKEY_TIMEOUT.

    assert!(sim.log.is_empty(), "no handshake may have been initiated");
}

/// Polling exactly at the announced instant must change something. A deadline
/// the caller cannot action is a busy-loop: `poll_timeout` keeps handing
/// back the same instant and `handle_timeout` keeps finding nothing to do.
///
/// The session expiry is the case that got this wrong: it was announced at
/// `established_at + REJECT_AFTER_TIME` while the session was only discarded
/// strictly *after* that instant, so the one instant the caller was told to
/// poll was the one instant at which polling could not expire it.
#[test]
fn the_announced_session_expiry_is_actionable() {
    let mut sim = Sim::connected();

    // Drain the earlier timers so the session expiry is the next deadline.
    sim.advance(REJECT_AFTER_TIME - secs(1));
    let now = sim.now;
    let tunn = sim.tunn_mut(A);
    tunn.handle_timeout(now);

    let Some((wake, "next expired session")) = tunn.poll_timeout() else {
        panic!("expected the session expiry to be the next deadline");
    };

    // Poll exactly when told to, then ask again.
    tunn.handle_timeout(wake);

    assert_ne!(
        tunn.poll_timeout().map(|(instant, _)| instant),
        Some(wake),
        "polling at the announced instant left the same deadline outstanding"
    );
}

/// A peer that never comes online: its tunnel expires `REJECT_AFTER_TIME * 3`
/// after creation. Sitting idle after that must not leave a deadline behind
/// that polling never clears, or a caller sleeping until `poll_timeout` spins.
#[test]
fn an_idle_expired_tunnel_announces_only_actionable_deadlines() {
    let mut sim = Sim::new();
    sim.advance(3 * REJECT_AFTER_TIME);
    assert!(sim.tunn(A).is_expired());

    let tunn = sim.tunn_mut(A);
    let Some((wake, reason)) = tunn.poll_timeout() else {
        return;
    };

    // Poll exactly when told to, then ask again.
    tunn.handle_timeout(wake);

    assert_ne!(
        tunn.poll_timeout().map(|(instant, _)| instant),
        Some(wake),
        "polling at the announced {reason:?} deadline left it outstanding"
    );
}

/// All randomness is derived from the caller's seed: two pairs of tunnels
/// built from the same inputs must emit byte-identical handshakes.
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
