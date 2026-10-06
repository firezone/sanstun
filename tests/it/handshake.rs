//! The 1-RTT handshake (whitepaper §5.4): message flow, authentication
//! failures and replay of handshake messages.

use crate::harness::{
    HANDSHAKE_INIT_SIZE, HANDSHAKE_RESPONSE_SIZE, Kind, Outcome as _, Peer::A, Peer::B, Sim, TICK,
    classify,
};
use rand::SeedableRng;
use rand::rngs::StdRng;
use sanstun::{Error, Event, Interface, Packet, PublicKey};
use std::time::{Duration, Instant};

#[test]
fn handshake_completes_in_one_round_trip() {
    let mut sim = Sim::new();

    sim.establish();

    // §6.5: the first message of the initiator on the new session confirms
    // the key to the responder; with nothing to send, that is a keepalive.
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

// §5.4.4: the PSK is mixed into the key derivation of the response, so a
// mismatch surfaces as an unopenable response on the initiator.
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

    assert!(matches!(error, Error::WrongTai64nTimestamp));
}

// sanstun keeps two outgoing handshakes in flight so that a delayed
// response to an earlier initiation is not lost on flaky networks.
#[test]
fn delayed_response_to_a_superseded_initiation_is_accepted() {
    let mut sim = Sim::new();

    let first_init = sim.initiate_handshake(A);
    sim.advance(crate::harness::secs(1));
    let _second_init = sim.force_handshake_initiation(A);

    // The *first* initiation reaches the responder, whose response must still
    // complete the handshake on the initiator.
    sim.route(A, first_init);

    assert!(sim.is_established(A));
    assert!(sim.is_established(B));
    sim.assert_connectivity();
}

/// Initiations arriving faster than the responder's events are drained leave
/// only the responses to the 16 newest ones queued.
#[test]
fn only_the_16_newest_events_are_queued() {
    let mut sim = Sim::new();

    let mut sender_indices = Vec::new();
    for _ in 0..20 {
        let init = sim.force_handshake_initiation(A);
        let now = sim.now;
        let packet = sim.receive(B, &init);
        let Packet::HandshakeInit(p) = &packet else {
            panic!("expected a handshake initiation, got {packet:?}");
        };
        sender_indices.push(p.sender_idx());
        sim.tunn_mut(B).decapsulate(packet, now).unwrap();
        sim.suspend(TICK);
    }

    let responses = std::iter::from_fn(|| sim.tunn_mut(B).poll_event())
        .map(|event| match event {
            Event::HandshakeResponse(response) => response.to_vec(),
            other => panic!("expected a handshake response, got {other:?}"),
        })
        .collect::<Vec<_>>();
    assert_eq!(responses.len(), 16);
    for (response, sender_idx) in [
        (responses.first(), sender_indices[4]),
        (responses.last(), sender_indices[19]),
    ] {
        let Packet::HandshakeResponse(response) = sim.receive(A, response.unwrap()) else {
            panic!("expected a handshake response");
        };
        assert_eq!(response.receiver_idx(), sender_idx);
    }
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

#[test]
fn tampered_handshake_initiation_is_rejected() {
    let mut sim = Sim::new();

    let mut init = sim.initiate_handshake(A);
    init[100] ^= 1; // Any bit flip up to mac1 must invalidate mac1 (§5.4.4).

    let error = sim.deliver(B, &init).expect_err();

    assert!(matches!(error, Error::InvalidMac));
}

#[test]
fn malformed_datagrams_are_rejected() {
    let mut sim = Sim::new();
    let init = sim.initiate_handshake(A);

    for garbage in [
        &[1u8, 2, 3] as &[u8],   // too short to even carry a message type
        &[0xff; 148],            // unknown message type
        &init[..init.len() - 1], // truncated handshake initiation
    ] {
        let error = sim.deliver(B, garbage).expect_err();

        assert!(matches!(error, Error::InvalidPacket));
    }

    let kind = classify(&init);
    assert_eq!(kind, Kind::Init, "the untampered packet parses fine");
}

// A low-order peer static key makes DH(static, static) all zeros, which
// WireGuard rejects so that a peer without a PSK cannot be impersonated.
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
        &mut StdRng::from_seed([0; 32]),
        now,
        Duration::from_secs(1_700_000_000),
    );

    for point in low_order_points {
        let tunnel = interface.new_tunnel(PublicKey::from(point), None, None, now);

        assert!(matches!(tunnel, Err(Error::LowOrderPoint)), "{point:x?}");
    }
}
