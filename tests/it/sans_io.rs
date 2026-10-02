//! Contracts specific to the sans-IO design: callers inject time explicitly,
//! learn when to call back via `next_timer_update`, and must get identical
//! behaviour for identical inputs.

use crate::harness::{
    classify, ipv4_packet, secs, Kind, Outcome as _, Peer::A, Peer::B, Sim, KEEPALIVE_SIZE,
    KEEPALIVE_TIMEOUT, MAX_JITTER, REJECT_AFTER_TIME, REKEY_AFTER_TIME, REKEY_TIMEOUT,
};
use sanstun::{Error, Index, PublicKey, StaticSecret, Tunnel, TunnelResult};
use std::time::{Duration, Instant};

/// A handshake triggered by a timer is not sent immediately: it is scheduled
/// with a random jitter of up to 333ms, announced via `next_timer_update` and
/// emitted exactly once when that deadline is polled.
#[test]
fn scheduled_handshake_honours_next_timer_update() {
    let mut sim = Sim::connected();
    sim.advance(secs(1));
    sim.cut_link();
    sim.send_ip(A, &ipv4_packet(b"unanswered"));

    let deadline = sim.now + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT;
    let tunn = sim.tunn_mut(A);
    let mut buf = [0u8; 256];

    // Nothing is due before the deadline.
    assert!(matches!(
        tunn.update_timers(&mut buf, deadline - Duration::from_millis(1)),
        Ok(TunnelResult::Done)
    ));

    // At the deadline, the handshake is only *scheduled* ...
    assert!(matches!(
        tunn.update_timers(&mut buf, deadline),
        Ok(TunnelResult::Done)
    ));
    let (wake, _reason) = tunn.next_timer_update().expect("a scheduled handshake");
    assert!(wake >= deadline && wake <= deadline + MAX_JITTER);

    // ... and emitted exactly once when the announced instant is polled.
    let Ok(TunnelResult::WriteToNetwork(packet)) = tunn.update_timers(&mut buf, wake) else {
        panic!("expected the scheduled handshake initiation");
    };
    assert_eq!(classify(&packet), Kind::Init);
    assert!(matches!(
        tunn.update_timers(&mut buf, wake),
        Ok(TunnelResult::Done)
    ));
}

#[test]
fn next_timer_update_predicts_the_passive_keepalive() {
    let mut sim = Sim::connected();
    sim.advance(secs(1));

    let datagram = sim.encapsulate(A, &ipv4_packet(b"ping"));
    sim.deliver(B, &datagram).expect_one_ip();
    let received_at = sim.now;

    let tunn = sim.tunn_mut(B);
    let (wake, _reason) = tunn.next_timer_update().expect("a pending keepalive");
    assert_eq!(wake, received_at + KEEPALIVE_TIMEOUT);

    let mut buf = [0u8; 256];
    assert!(matches!(
        tunn.update_timers(&mut buf, wake - Duration::from_millis(1)),
        Ok(TunnelResult::Done)
    ));
    assert!(matches!(
        tunn.update_timers(&mut buf, wake),
        Ok(TunnelResult::KeepaliveDue)
    ));
    let packet = tunn
        .encapsulate_data(0, wake)
        .unwrap()
        .seal_into(&[], &mut buf)
        .unwrap();
    assert_eq!(packet.len(), KEEPALIVE_SIZE);

    // The passive keepalive has been answered, so it must not re-arm; the only
    // thing left on the clock is the eventual session expiry.
    let (_wake, reason) = tunn
        .next_timer_update()
        .expect("a session that still expires eventually");
    assert_eq!(reason, "next expired session");
}

/// `next_timer_update` must never announce an instant in the past. Timers are
/// anchored to the session start, so sending on a session already older than
/// `REKEY_AFTER_TIME` arms the rekey-on-send timer with a deadline that has
/// already elapsed; the caller must still be handed a usable (not past) instant.
#[test]
fn next_timer_update_never_points_into_the_past() {
    let mut sim = Sim::connected();

    // Age the session past REKEY_AFTER_TIME. With no traffic, nothing rekeys, so
    // the session is still alive and its start is now well over REKEY_AFTER_TIME
    // in the past.
    sim.advance(REKEY_AFTER_TIME + secs(1));

    // Sending now arms the rekey-on-send timer, whose deadline (session start +
    // REKEY_AFTER_TIME) is already behind us.
    sim.send_ip(A, &ipv4_packet(b"traffic after a long silence"));

    let (wake, _reason) = sim.tunn(A).next_timer_update().expect("a rekey is now due");
    assert!(
        wake >= sim.now,
        "next_timer_update returned an instant {:?} before now",
        sim.now.duration_since(wake),
    );
}

/// Callers may poll arbitrarily rarely; a single call after a long gap must
/// still observe the (by then) expired state instead of panicking or hanging.
#[test]
fn a_single_late_poll_observes_the_expiry() {
    let mut sim = Sim::connected();

    let late = sim.now + 4 * REJECT_AFTER_TIME;
    let mut buf = [0u8; 256];
    let result = sim.tunn_mut(A).update_timers(&mut buf, late);

    assert!(matches!(result, Err(Error::ConnectionExpired)));
    assert!(sim.tunn(A).is_expired());
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
        let mut buf = [0u8; 256];
        let tunn = sim.tunn_mut(A);
        assert!(matches!(
            tunn.update_timers(&mut buf, retry_due),
            Ok(TunnelResult::Done)
        ));

        tunn.next_timer_update()
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
fn encapsulate_data_at_has_no_side_effects_without_a_session() {
    let mut sim = Sim::new();

    let result = sim.try_encapsulate(A, &ipv4_packet(b"no session yet"));
    assert!(matches!(result, Err(Error::NoCurrentSession)));

    sim.advance(secs(10)); // Well past REKEY_TIMEOUT.

    assert!(sim.log.is_empty(), "no handshake may have been initiated");
}

/// Polling exactly at the announced instant must change something. A deadline
/// the caller cannot action is a busy-loop: `next_timer_update` keeps handing
/// back the same instant and `update_timers` keeps finding nothing to do.
///
/// The session expiry is the case that got this wrong: it was announced at
/// `established_at + REJECT_AFTER_TIME` while the session was only discarded
/// strictly *after* that instant, so the one instant the caller was told to
/// poll was the one instant at which polling could not expire it.
#[test]
fn the_announced_session_expiry_is_actionable() {
    let mut sim = Sim::connected();
    let mut buf = [0u8; 256];

    // Drain the earlier timers so the session expiry is the next deadline.
    sim.advance(REJECT_AFTER_TIME - secs(1));
    let now = sim.now;
    let tunn = sim.tunn_mut(A);
    let _ = tunn.update_timers(&mut buf, now);

    let Some((wake, "next expired session")) = tunn.next_timer_update() else {
        panic!("expected the session expiry to be the next deadline");
    };

    // Poll exactly when told to, then ask again.
    let _ = tunn.update_timers(&mut buf, wake);

    assert_ne!(
        tunn.next_timer_update().map(|(instant, _)| instant),
        Some(wake),
        "polling at the announced instant left the same deadline outstanding"
    );
}

/// All randomness is derived from the caller's seed: two pairs of tunnels
/// built from the same inputs must emit byte-identical handshakes.
#[test]
fn identical_seeds_produce_identical_handshakes() {
    fn handshake(seed_a: [u8; 32], now: Instant) -> (Vec<u8>, Vec<u8>) {
        let unix = Duration::from_secs(1_700_000_000);
        let secret_a = StaticSecret::from([1; 32]);
        let secret_b = StaticSecret::from([2; 32]);
        let public_a = PublicKey::from(&secret_a);
        let public_b = PublicKey::from(&secret_b);

        let mut a = Tunnel::new(
            secret_a,
            public_b,
            None,
            None,
            Index::new_local(1),
            None,
            seed_a,
            now,
            now,
            unix,
        );
        let mut b = Tunnel::new(
            secret_b,
            public_a,
            None,
            None,
            Index::new_local(2),
            None,
            [4; 32],
            now,
            now,
            unix,
        );

        let mut init = [0u8; 256];
        let init = a
            .format_handshake_initiation(&mut init, false, now)
            .unwrap()
            .expect("a handshake initiation")
            .to_vec();

        let mut response = [0u8; 256];
        let TunnelResult::WriteToNetwork(response) =
            b.decapsulate(None, &init, &mut response, now).unwrap()
        else {
            panic!("expected a handshake response");
        };

        (init, response.to_vec())
    }

    let now = Instant::now();

    assert_eq!(handshake([3; 32], now), handshake([3; 32], now));
    assert_ne!(handshake([3; 32], now).0, handshake([5; 32], now).0);
}
