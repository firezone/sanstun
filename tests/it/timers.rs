//! Timer behaviour (whitepaper §6): handshake retransmission, rekeying,
//! passive and persistent keepalives, and session expiry.

use crate::harness::{
    KEEPALIVE_TIMEOUT, Kind, MAX_JITTER, Outcome as _, Peer::A, Peer::B, REJECT_AFTER_TIME,
    REKEY_AFTER_TIME, REKEY_ATTEMPT_TIME, REKEY_TIMEOUT, SHOULD_NOT_USE_AFTER_TIME, Sim, TICK,
    assert_close, assert_fires_at, ipv4_packet, secs,
};
use sanstun::Error;

/// §6.4: an unanswered handshake initiation is retransmitted after
/// `REKEY_TIMEOUT + jitter`, where jitter is up to 333ms.
#[test]
fn unanswered_handshake_is_retransmitted_every_rekey_timeout() {
    let mut sim = Sim::new();
    sim.cut_link();

    let init = sim.initiate_handshake(A);
    sim.route(A, init);
    sim.advance(secs(18));

    let inits = sim.sent_at(A, Kind::Init);
    assert_eq!(inits.len(), 4, "one initiation plus three retries in 18s");
    for pair in inits.windows(2) {
        let gap = pair[1] - pair[0];
        assert!(
            gap >= REKEY_TIMEOUT && gap <= REKEY_TIMEOUT + MAX_JITTER + 2 * TICK,
            "retransmission gap was {gap:?}"
        );
    }
}

/// §6.4: retries stop and the tunnel expires after `REKEY_ATTEMPT_TIME`.
#[test]
fn handshake_retries_cease_after_rekey_attempt_time() {
    let mut sim = Sim::new();
    sim.cut_link();

    let init = sim.initiate_handshake(A);
    sim.route(A, init);
    sim.advance(secs(120));

    let inits = sim.sent_at(A, Kind::Init);
    assert!(
        inits.iter().all(|at| *at < REKEY_ATTEMPT_TIME),
        "no initiation may be sent after REKEY_ATTEMPT_TIME"
    );
    assert!(
        inits.len() >= 16,
        "expected steady retries for 90s, got {}",
        inits.len()
    );
    assert!(sim.tunn(A).is_expired());
    assert_eq!(sim.expirations(A), 1);
}

#[test]
fn expired_tunnel_stays_expired() {
    let mut sim = Sim::new();
    sim.cut_link();
    let init = sim.initiate_handshake(A);
    sim.route(A, init);
    sim.advance(secs(95));
    assert!(sim.tunn(A).is_expired());

    sim.heal_link();
    let now = sim.now;
    assert!(sim.tunn(A).poll_timeout().is_none());
    assert!(sim.tunn_mut(A).restart_handshake(now).is_none());
    assert!(matches!(
        sim.try_encapsulate(A, &ipv4_packet(b"data")),
        Err(Error::ConnectionExpired)
    ));

    let init = sim.initiate_handshake(B);
    sim.route(B, init);

    assert!(sim.tunn(A).is_expired());
    assert!(matches!(sim.errors(A), [.., Error::ConnectionExpired]));
}

#[test]
fn rekey_timeout_is_configurable() {
    let mut sim = Sim::new();
    sim.tunn_mut(A).set_rekey_timeout(secs(1));
    sim.cut_link();

    let init = sim.initiate_handshake(A);
    sim.route(A, init);
    sim.advance(secs(5));

    let inits = sim.sent_at(A, Kind::Init);
    assert!(
        inits.len() >= 4,
        "expected retries every ~1s, got {}",
        inits.len()
    );
}

#[test]
fn rekey_attempt_time_is_configurable() {
    let mut sim = Sim::new();
    sim.tunn_mut(A).set_rekey_attempt_time(secs(10));
    sim.cut_link();

    let init = sim.initiate_handshake(A);
    sim.route(A, init);
    sim.advance(secs(30));

    assert!(sim.sent_at(A, Kind::Init).iter().all(|at| *at < secs(10)));
    assert!(sim.tunn(A).is_expired());
}

/// §6.2: an initiator that has sent data rekeys at `REKEY_AFTER_TIME`.
#[test]
fn initiator_rekeys_when_session_is_older_than_rekey_after_time() {
    let mut sim = Sim::connected();
    sim.advance(secs(1));
    sim.send_ip(A, &ipv4_packet(b"some data"));

    sim.advance(REKEY_AFTER_TIME);

    let inits = sim.sent_at(A, Kind::Init);
    assert_eq!(inits.len(), 1);
    assert_fires_at(inits[0], REKEY_AFTER_TIME);
    sim.assert_connectivity();
}

/// §6.2: only the initiator rekeys based on session age.
#[test]
fn responder_does_not_rekey_based_on_session_age() {
    let mut sim = Sim::connected();
    sim.advance(secs(1));
    sim.send_ip(B, &ipv4_packet(b"from the responder"));

    // Stop before the initiator's rekey-on-receive deadline.
    sim.advance(secs(160));

    assert_eq!(sim.count(B, Kind::Init), 0);
    assert_eq!(sim.count(A, Kind::Init), 0);
    assert!(sim.is_established(B));
}

/// §6.2: crossed handshakes leave both peers sending as responders, without an initiator cutoff.
#[test]
fn crossed_handshakes_take_the_role_of_the_session_in_use() {
    let mut sim = Sim::new();

    let init_a = sim.initiate_handshake(A);
    let init_b = sim.initiate_handshake(B);
    let response_from_b = sim.deliver(B, &init_a).expect_one_net();
    let response_from_a = sim.deliver(A, &init_b).expect_one_net();
    let keepalive_from_a = sim.deliver(A, &response_from_b).expect_one_net();
    let keepalive_from_b = sim.deliver(B, &response_from_a).expect_one_net();
    sim.deliver(B, &keepalive_from_a).expect_consumed();
    sim.deliver(A, &keepalive_from_b).expect_consumed();

    sim.advance(SHOULD_NOT_USE_AFTER_TIME + secs(1));

    let ip_packet = ipv4_packet(b"past the initiator's cutoff");
    let from_a = sim.encapsulate(A, &ip_packet);
    let from_b = sim.encapsulate(B, &ip_packet);
    assert_eq!(sim.deliver(B, &from_a).expect_one_ip(), ip_packet);
    assert_eq!(sim.deliver(A, &from_b).expect_one_ip(), ip_packet);
}

/// §6.2: an unconfirmed session does not change the current session's rekey schedule.
#[test]
fn unconfirmed_initiation_keeps_the_role_of_the_session_in_use() {
    let mut sim = Sim::connected();
    sim.advance(secs(1));
    sim.send_ip(A, &ipv4_packet(b"some data"));
    sim.advance(secs(15)); // Let the passive keepalive settle.
    sim.cut_link();

    let init = sim.initiate_handshake(B);
    sim.deliver(A, &init).expect_one_net();
    sim.advance(secs(105));

    let inits = sim.sent_at(A, Kind::Init);
    assert_eq!(inits.len(), 1);
    assert_fires_at(inits[0], REKEY_AFTER_TIME);
}

/// §6.2: receiving data near expiry triggers a rekey to keep the session alive.
#[test]
fn initiator_rekeys_when_receiving_on_a_session_close_to_expiry() {
    let rekey_on_receive_after = REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT;

    let mut sim = Sim::connected();
    sim.advance(rekey_on_receive_after + secs(1));
    sim.send_ip(B, &ipv4_packet(b"late data"));
    sim.advance(secs(2));

    let inits = sim.sent_at(A, Kind::Init);
    assert_eq!(inits.len(), 1);
    assert_fires_at(inits[0], rekey_on_receive_after + secs(1));
    sim.assert_connectivity();
}

/// §6.1 / §6.3: a passive keepalive answers data after `KEEPALIVE_TIMEOUT`,
/// suppressing a rekey without triggering another keepalive.
#[test]
fn passive_keepalive_answers_unidirectional_traffic() {
    let mut sim = Sim::connected();
    sim.advance(secs(1));

    sim.send_ip(A, &ipv4_packet(b"ping"));
    sim.advance(secs(30));

    let keepalives = sim.sent_at(B, Kind::Keepalive);
    assert_eq!(keepalives.len(), 1, "exactly one keepalive, no ping-pong");
    assert_close(keepalives[0], secs(1) + KEEPALIVE_TIMEOUT);

    assert_eq!(
        sim.count(A, Kind::Init),
        0,
        "keepalive suppressed the rekey"
    );
    assert_eq!(sim.count(A, Kind::Keepalive), 0);
}

/// §6.3: a new handshake is due `KEEPALIVE_TIMEOUT + REKEY_TIMEOUT` after the
/// first unanswered data packet. Later sends must not postpone it.
#[test]
fn unanswered_data_triggers_a_new_handshake() {
    let mut sim = Sim::connected();
    sim.advance(secs(1));
    sim.cut_link();

    sim.send_ip(A, &ipv4_packet(b"into the void"));
    for _ in 0..5 {
        sim.advance(secs(1));
        sim.send_ip(A, &ipv4_packet(b"more of the same"));
    }
    sim.advance(secs(11));

    let inits = sim.sent_at(A, Kind::Init);
    assert_eq!(inits.len(), 1);
    assert_fires_at(inits[0], secs(1) + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT);
}

/// §6.1: persistent keepalives run even without user traffic.
#[test]
fn persistent_keepalive_fires_on_its_interval() {
    let mut sim = Sim::builder().persistent_keepalive_b(secs(25)).build();
    sim.establish();
    sim.clear_log();

    sim.advance(secs(80));

    let keepalives = sim.sent_at(B, Kind::Keepalive);
    assert_eq!(keepalives.len(), 3);
    for (i, at) in keepalives.iter().enumerate() {
        assert_close(*at, secs(25) * (i as u32 + 1));
    }

    assert!(
        sim.sent_at(A, Kind::Keepalive).is_empty(),
        "keepalives must not trigger a reply"
    );
}

#[test]
fn zero_persistent_keepalive_is_off() {
    let mut sim = Sim::builder().persistent_keepalive_b(secs(0)).build();
    sim.establish();
    sim.clear_log();

    sim.advance(secs(80));

    assert!(sim.sent_at(B, Kind::Keepalive).is_empty());
}

/// §6.1: the responder discards its session at `REJECT_AFTER_TIME`.
#[test]
fn responder_discards_the_session_after_reject_after_time() {
    let mut sim = Sim::connected();
    sim.assert_connectivity();
    sim.advance(secs(30)); // Let passive keepalives settle.
    sim.cut_link(); // Prevent the initiator from renewing the session.

    sim.advance(REJECT_AFTER_TIME - secs(20));

    assert!(!sim.is_established(B));
    assert!(matches!(
        sim.try_encapsulate(B, &ipv4_packet(b"too late")),
        Err(Error::ConnectionExpired)
    ));
    assert!(
        sim.errors(B).is_empty(),
        "expiry of a session is not an error"
    );
}

/// Expired sessions reject data even before `handle_timeout` runs.
#[test]
fn data_for_an_expired_session_is_rejected_before_timers_run() {
    let mut sim = Sim::connected();
    let datagram = sim.encapsulate(A, &ipv4_packet(b"too late"));

    sim.suspend(REJECT_AFTER_TIME);

    let error = sim.deliver(B, &datagram).expect_err();
    assert!(matches!(error, Error::NoCurrentSession));
}

/// Responders also reject encryption on expired sessions before `handle_timeout` runs.
#[test]
fn responder_does_not_encrypt_on_an_expired_session_before_timers_run() {
    let mut sim = Sim::connected();

    sim.suspend(REJECT_AFTER_TIME);

    assert!(matches!(
        sim.try_encapsulate(B, &ipv4_packet(b"too late")),
        Err(Error::NoCurrentSession)
    ));
}

/// The initiator renews an unused session on expiry, without waiting for outgoing data.
#[test]
fn initiator_renews_an_expired_session_automatically() {
    let mut sim = Sim::connected();

    sim.advance(REJECT_AFTER_TIME + secs(10));

    let inits = sim.sent_at(A, Kind::Init);
    assert_eq!(inits.len(), 1);
    assert_fires_at(inits[0], REJECT_AFTER_TIME);
    assert!(sim.is_established(A));
    assert!(sim.is_established(B));
    sim.assert_connectivity();
}

/// A used session should have rekeyed before expiry. If it expires, the tunnel
/// gives up without another `REKEY_ATTEMPT_TIME` of retries.
#[test]
fn tunnel_expires_when_a_used_session_expires() {
    let mut sim = Sim::connected();
    sim.advance(secs(1));
    sim.assert_connectivity();
    sim.cut_link();

    sim.advance(REJECT_AFTER_TIME);

    for peer in [A, B] {
        assert!(sim.tunn(peer).is_expired());
        assert_eq!(sim.expirations(peer), 1);
    }
    assert!(
        sim.sent_at(A, Kind::Init)
            .iter()
            .all(|at| *at < REJECT_AFTER_TIME),
        "retries stop once the session they were replacing is gone"
    );
}

/// A peer that lost its state re-initiates; the tunnel keeps the newer session even if the
/// response is lost and the used session expires before the peer retries.
#[test]
fn tunnel_survives_a_used_session_expiring_after_the_peer_reinitiated() {
    let mut sim = Sim::connected();
    sim.advance(secs(1));
    sim.send_ip(B, &ipv4_packet(b"on the first session"));
    sim.send_ip(A, &ipv4_packet(b"reply on the first session"));
    sim.replace_tunnel(A);
    sim.cut_link();
    sim.advance(REJECT_AFTER_TIME - secs(2));
    sim.heal_link();

    let init = sim.initiate_handshake(A);
    let _lost_response = sim.deliver(B, &init).expect_one_net();
    sim.advance(REKEY_TIMEOUT + secs(5));

    assert_eq!(sim.expirations(B), 0);
    sim.assert_connectivity();
}

/// An unused session never triggers an age-based rekey, so its expiry alone
/// does not mean the peer is unreachable.
#[test]
fn tunnel_survives_a_session_a_rekey_left_unused() {
    let mut sim = Sim::connected();
    sim.advance(secs(1));
    sim.assert_connectivity();

    sim.advance(REKEY_AFTER_TIME);
    sim.advance(REJECT_AFTER_TIME + secs(10));

    for peer in [A, B] {
        assert!(!sim.tunn(peer).is_expired());
    }
    sim.assert_connectivity();
}

/// Traffic on the previous session must not mark the unconfirmed session as used.
#[test]
fn data_sent_before_confirmation_does_not_count_for_the_new_session() {
    let mut sim = Sim::connected();
    sim.advance(secs(1));

    let init = sim.initiate_handshake(A);
    let response = sim.deliver(B, &init).expect_one_net();
    let keepalive = sim.deliver(A, &response).expect_one_net();
    sim.advance(secs(1));
    sim.encapsulate(B, &ipv4_packet(b"on the previous session"));
    sim.deliver(B, &keepalive).expect_consumed();

    sim.advance(REJECT_AFTER_TIME + secs(10));

    assert_eq!(sim.expirations(B), 0);
    sim.assert_connectivity();
}

/// §6.1: `3 * REJECT_AFTER_TIME` without a successful handshake expires the tunnel
/// and drops its handshake and session state.
#[test]
fn tunnel_is_wiped_after_three_times_reject_after_time() {
    let mut sim = Sim::connected();
    sim.cut_link();

    sim.advance(3 * REJECT_AFTER_TIME + secs(2));

    assert!(sim.tunn(B).is_expired());
    assert_eq!(sim.expirations(B), 1);
}

/// The initiator stops sending `KEEPALIVE_TIMEOUT` before expiry so packets
/// can reach the peer while the session is still valid.
#[test]
fn initiator_stops_sending_on_a_session_close_to_expiry() {
    let mut sim = Sim::connected();

    sim.advance(SHOULD_NOT_USE_AFTER_TIME + secs(1));

    assert!(matches!(
        sim.try_encapsulate(A, &ipv4_packet(b"risky")),
        Err(Error::NoCurrentSession)
    ));
    assert!(
        sim.is_established(A),
        "the session still exists; it is just not used for sending"
    );
}

#[test]
fn initiator_cutoff_follows_the_configured_keepalive_timeout() {
    let mut sim = Sim::connected();
    sim.tunn_mut(A).set_keepalive_timeout(secs(30));

    sim.advance(REJECT_AFTER_TIME - secs(30) + secs(1));

    assert!(matches!(
        sim.try_encapsulate(A, &ipv4_packet(b"risky")),
        Err(Error::NoCurrentSession)
    ));
}

/// The responder relies on the initiator to rekey, so it can send until `REJECT_AFTER_TIME`.
#[test]
fn responder_keeps_sending_on_a_session_close_to_expiry() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"still fine");

    sim.advance(SHOULD_NOT_USE_AFTER_TIME + secs(1));
    sim.send_ip(B, &ip_packet);

    assert_eq!(sim.take_inbox(A), [ip_packet]);
}

/// Rekeying must preserve connectivity as the eight session slots are reused.
#[test]
fn repeated_rekeys_do_not_disturb_connectivity() {
    let mut sim = Sim::connected();

    for _ in 0..12 {
        sim.advance(secs(1));
        let init = sim.initiate_handshake(A);
        sim.route(A, init);
        sim.assert_connectivity();
    }
}

/// §6.1: the previous session remains usable during the transition to a new one.
#[test]
fn previous_session_remains_usable_during_rekey_transition() {
    let mut sim = Sim::connected();
    sim.assert_connectivity();
    sim.advance(secs(1));

    // Complete a new handshake but hold back the confirming keepalive.
    let init = sim.initiate_handshake(A);
    let response = sim.deliver(B, &init).expect_one_net();
    let keepalive = sim.deliver(A, &response).expect_one_net();

    // B has not seen traffic on the new session and keeps using the old one.
    let old_data = sim.encapsulate(B, &ipv4_packet(b"old session"));
    sim.deliver(A, &old_data).expect_one_ip();

    // Once the keepalive arrives, B switches to the new session.
    sim.deliver(B, &keepalive).expect_consumed();
    let new_data = sim.encapsulate(B, &ipv4_packet(b"new session"));
    assert_ne!(
        crate::harness::receiver_index(&old_data),
        crate::harness::receiver_index(&new_data)
    );
    sim.deliver(A, &new_data).expect_one_ip();
}

/// Session expiry must clear pending keepalives, or their deadlines cause a busy loop.
#[test]
fn keepalive_does_not_outlive_the_session_it_needs() {
    let mut sim = Sim::connected();

    sim.send_ip(A, &ipv4_packet(b"ping"));

    // With the link down, nothing re-establishes the session B would need.
    sim.cut_link();
    sim.suspend(REJECT_AFTER_TIME + secs(30));

    sim.advance(secs(5));
}
