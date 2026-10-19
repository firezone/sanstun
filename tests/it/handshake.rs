//! The 1-RTT handshake (whitepaper §5.4): message flow, authentication
//! failures and replay of handshake messages.

use crate::harness::{
    HANDSHAKE_INIT_SIZE, HANDSHAKE_RESPONSE_SIZE, Kind, MAX_JITTER, Outcome as _, Peer::A, Peer::B,
    REJECT_AFTER_TIME, REKEY_TIMEOUT, Sim, classify, ipv4_packet, secs,
};
use sanstun::{Error, Interface, PublicKey, ReceivedMessage, TunnelConfig};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

#[test]
fn handshake_completes_in_one_round_trip() {
    let mut sim = Sim::new();

    sim.establish();

    // §6.5: the initiator confirms the session with a keepalive when it has no data to send.
    let flow = sim
        .log
        .iter()
        .map(|event| (event.from, event.kind))
        .collect::<Vec<_>>();
    assert_eq!(
        flow,
        [(A, Kind::Init), (B, Kind::Response), (A, Kind::Keepalive)]
    );

    sim.assert_connectivity();
}

#[test]
fn each_tunnel_announces_its_first_confirmed_session_once() {
    let mut sim = Sim::new();

    let initiated_at = sim.now;
    let init = sim.initiate_handshake(A);
    sim.advance(secs(1));
    let accepted_at = sim.now;
    let response = sim.deliver(B, &init).expect_one_net();
    assert!(
        sim.establishments(B).is_empty(),
        "the responder waits for key confirmation"
    );

    sim.advance(secs(1));
    let keepalive = sim.deliver(A, &response).expect_one_net();
    assert_eq!(sim.establishments(A), [(initiated_at, sim.now)]);

    sim.advance(secs(1));
    sim.deliver(B, &keepalive).expect_consumed();
    assert_eq!(sim.establishments(B), [(accepted_at, sim.now)]);

    // Later handshakes and data do not announce again.
    let init = sim.initiate_handshake(B);
    sim.route(B, init);
    sim.assert_connectivity();
    assert_eq!(sim.establishments(A).len(), 1);
    assert_eq!(sim.establishments(B).len(), 1);
}

#[test]
fn established_session_started_with_the_first_of_several_initiations() {
    let mut sim = Sim::new();

    let initiated_at = sim.now;
    let _lost = sim.initiate_handshake(A);
    sim.advance(REKEY_TIMEOUT + MAX_JITTER + secs(1));

    let &[(started_at, confirmed_at)] = sim.establishments(A) else {
        panic!("expected one establishment");
    };
    assert_eq!(started_at, initiated_at);
    assert!(confirmed_at - started_at >= REKEY_TIMEOUT);
}

#[test]
fn handshake_messages_have_the_sizes_mandated_by_the_paper() {
    let mut sim = Sim::new();

    let init = sim.initiate_handshake(A);
    assert_eq!(init.len(), HANDSHAKE_INIT_SIZE); // §5.4.2

    let response = sim.deliver(B, &init).expect_one_net();
    assert_eq!(response.len(), HANDSHAKE_RESPONSE_SIZE); // §5.4.3
}

#[test]
fn handshake_with_matching_preshared_key_succeeds() {
    let psk = [0x42; 32];
    let mut sim = Sim::builder().psk_a(psk).psk_b(psk).build();

    sim.establish();
    sim.assert_connectivity();
}

// §5.4.4: the PSK is part of the response's key derivation, so a mismatch prevents decryption.
#[test]
fn handshake_with_mismatched_preshared_key_fails() {
    let mut sim = Sim::builder().psk_a([0x42; 32]).build();

    let init = sim.initiate_handshake(A);
    sim.route(A, init);

    assert!(!sim.is_established(A));
    assert!(!sim.is_established(B));
    assert!(matches!(sim.errors(A), [Error::InvalidAeadTag]));
}

#[test]
fn responder_rejects_initiator_with_unexpected_static_key() {
    let mut sim = Sim::builder().responder_expects_different_key().build();

    let init = sim.initiate_handshake(A);
    sim.route(A, init);

    assert!(matches!(sim.errors(B), [Error::WrongKey]));
    assert_eq!(
        sim.count(B, Kind::Response),
        0,
        "responder must stay silent"
    );
    assert!(!sim.is_established(B));
}

// §5.1 / §5.4.2: the encrypted TAI64N timestamp protects against replay of
// handshake initiations.
#[test]
fn replayed_handshake_initiation_is_rejected() {
    let mut sim = Sim::new();

    let init = sim.initiate_handshake(A);
    sim.deliver(B, &init).expect_one_net();

    let error = sim.deliver(B, &init).expect_err();

    assert!(matches!(error, Error::ReplayedHandshakeInitiation));
}

#[test]
fn each_initiation_has_a_fresh_sender_index_and_a_later_timestamp() {
    let mut sim = Sim::new();
    let first = sim.initiate_handshake(A);
    sim.advance(secs(1));
    let second = sim.force_handshake_initiation(A);

    let ReceivedMessage::HandshakeInitiation(first) = sim.receive(B, &first) else {
        panic!("expected a handshake initiation");
    };
    let ReceivedMessage::HandshakeInitiation(second) = sim.receive(B, &second) else {
        panic!("expected a handshake initiation");
    };

    assert_ne!(first.sender_index(), second.sender_index());
    assert!(second.timestamp() > first.timestamp());
}

// Replay protection must survive tunnel replacement, so the `Interface` remembers timestamps.
#[test]
fn replayed_handshake_initiation_is_rejected_after_the_tunnel_is_replaced() {
    let mut sim = Sim::new();
    let init = sim.initiate_handshake(A);
    sim.deliver(B, &init).expect_one_net();

    sim.replace_tunnel(B);
    let error = sim.deliver(B, &init).expect_err();

    assert!(matches!(error, Error::ReplayedHandshakeInitiation));
}

// Keeping two outgoing handshakes allows a delayed response to complete either one.
#[test]
fn delayed_response_to_a_superseded_initiation_is_accepted() {
    let mut sim = Sim::new();

    let first_init = sim.initiate_handshake(A);
    sim.advance(crate::harness::secs(1));
    let _second_init = sim.force_handshake_initiation(A);

    sim.route(A, first_init);

    assert!(sim.is_established(A));
    assert!(sim.is_established(B));
    sim.assert_connectivity();
}

#[test]
fn simultaneous_handshake_initiations_converge() {
    let mut sim = Sim::new();

    let init_a = sim.initiate_handshake(A);
    let init_b = sim.initiate_handshake(B);
    sim.route(A, init_a);
    sim.route(B, init_b);

    assert!(sim.is_established(A));
    assert!(sim.is_established(B));
    sim.assert_connectivity();
}

// §6.1: only the initiator's confirmation allows the responder to switch sessions.
#[test]
fn unconfirmed_sessions_never_replace_the_current_one() {
    let mut sim = Sim::connected();
    sim.cut_link();

    for _ in 0..8 {
        sim.advance(secs(1));
        let init = sim.force_handshake_initiation(A);
        sim.deliver(B, &init).expect_one_net();
    }

    let ip_packet = ipv4_packet(b"still on the confirmed session");
    let datagram = sim.encapsulate(B, &ip_packet);
    assert_eq!(sim.deliver(A, &datagram).expect_one_ip(), ip_packet);
}

// §6.1: reusing an expired session's index must not bypass confirmation.
#[test]
fn responder_waits_for_confirmation_after_its_session_index_wraps() {
    let mut sim = Sim::connected();
    sim.cut_link();
    sim.advance(REJECT_AFTER_TIME + secs(1));
    assert!(matches!(
        sim.try_encapsulate(B, &ipv4_packet(b"no session")),
        Err(Error::NoCurrentSession)
    ));

    // After 256 handshakes, the 8-bit session index wraps to the expired session's index.
    for _ in 0..256 {
        sim.suspend(Duration::from_millis(200));
        let init = sim.force_handshake_initiation(A);
        sim.deliver(B, &init).expect_one_net();
    }

    // None of the responses reached A, so A has none of these sessions.
    let sent = sim.try_encapsulate(B, &ipv4_packet(b"into the void"));
    assert!(
        matches!(sent, Err(Error::NoCurrentSession)),
        "B sends on a session A never confirmed: {sent:?}"
    );
}

#[test]
fn tampered_handshake_initiation_is_rejected() {
    let mut sim = Sim::new();

    let mut init = sim.initiate_handshake(A);
    init[100] ^= 1; // Tamper with the bytes covered by `mac1` (§5.4.4).

    let error = sim.deliver(B, &init).expect_err();

    assert!(matches!(error, Error::InvalidMac));
}

#[test]
fn malformed_datagrams_are_rejected() {
    let mut sim = Sim::new();
    let init = sim.initiate_handshake(A);

    for garbage in [
        &[1u8, 2, 3] as &[u8],   // truncated message type
        &[0xff; 148],            // unknown message type
        &init[..init.len() - 1], // truncated handshake initiation
    ] {
        let error = sim.deliver(B, garbage).expect_err();

        assert!(matches!(error, Error::InvalidPacket));
    }

    let kind = classify(&init);
    assert_eq!(kind, Kind::Init, "the original packet should parse");
}

// A low-order static key gives an all-zero shared secret, allowing impersonation without a PSK.
#[test]
fn tunnel_rejects_low_order_peer_static_key() {
    let p_minus_1 = {
        let mut p = [0xff; 32];
        p[0] = 0xec;
        p[31] = 0x7f;
        p
    };
    let low_order_points = [
        [0; 32],
        {
            let mut one = [0; 32];
            one[0] = 1;
            one
        },
        p_minus_1,
        [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ],
        [
            0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
            0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
            0xd0, 0x9f, 0x11, 0x57,
        ],
    ];
    let now = Instant::now();
    let mut interface = Interface::new(
        Zeroizing::new([0; 32]),
        now,
        Duration::from_secs(1_700_000_000),
    );

    for point in low_order_points {
        let tunnel = interface.new_tunnel(PublicKey::from(point), TunnelConfig::default(), now);

        assert!(matches!(tunnel, Err(Error::LowOrderPoint)), "{point:x?}");
    }
}
