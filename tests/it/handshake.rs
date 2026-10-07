//! The 1-RTT handshake (whitepaper §5.4): message flow, authentication
//! failures and replay of handshake messages.

use crate::harness::{
    HANDSHAKE_INIT_SIZE, HANDSHAKE_RESPONSE_SIZE, Kind, Outcome as _, Peer::A, Peer::B, Sim,
    classify, ipv4_packet, secs,
};
use rand::SeedableRng;
use rand::rngs::StdRng;
use sanstun::{Error, Interface, Packet, PublicKey};
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

// §5.4.2: the initiator's static key is encrypted under the ephemeral DH
// only, so anyone who knows the responder's public key can claim any static
// key. The claim is only proven by the timestamp, which needs the static DH.
#[test]
fn claimed_static_key_is_only_proven_by_the_tunnel() {
    let mut sim = Sim::new();
    let victim = sim.tunn(B).remote_static_public();
    let responder = sim.tunn(A).remote_static_public();

    let init = forged_initiation(responder, victim);

    let Packet::HandshakeInit(claim) = sim.receive(B, &init) else {
        panic!("expected a handshake initiation");
    };
    assert_eq!(claim.peer_static_public(), victim);

    let error = sim.deliver(B, &init).expect_err();
    assert!(matches!(error, Error::InvalidAeadTag));
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

// §6.1: the responder keeps sending on the previous session until the
// initiator confirms the new one, however many initiations it answers.
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

/// A handshake initiation to `responder` that claims `claimed` as its static
/// key, built without the private key of `claimed` (§5.4.2).
fn forged_initiation(responder: PublicKey, claimed: PublicKey) -> Vec<u8> {
    use blake2::digest::consts::U16;
    use blake2::digest::{FixedOutput as _, KeyInit as _};
    use blake2::{Blake2s256, Blake2sMac, Digest as _};
    use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};

    fn hash(a: &[u8], b: &[u8]) -> [u8; 32] {
        Blake2s256::new()
            .chain_update(a)
            .chain_update(b)
            .finalize()
            .into()
    }
    fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
        use hmac::Mac as _;
        let mut mac = hmac::SimpleHmac::<Blake2s256>::new_from_slice(key).unwrap();
        mac.update(data);
        mac.finalize().into_bytes().into()
    }

    let ephemeral = [0x66; 32];
    let ephemeral_public = x25519_dalek::x25519(ephemeral, x25519_dalek::X25519_BASEPOINT_BYTES);

    let chaining_key = hash(b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s", &[]);
    let h = hash(&chaining_key, b"WireGuard v1 zx2c4 Jason@zx2c4.com");
    let h = hash(&h, responder.as_bytes());
    let h = hash(&h, &ephemeral_public);
    let chaining_key = hmac(&hmac(&chaining_key, &ephemeral_public), &[1]);
    let temp = hmac(
        &chaining_key,
        &x25519_dalek::x25519(ephemeral, *responder.as_bytes()),
    );
    let chaining_key = hmac(&temp, &[1]);
    let key = hmac(&temp, &[&chaining_key[..], &[2]].concat());

    let mut encrypted_static = claimed.as_bytes().to_vec();
    LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &key).unwrap())
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key([0; 12]),
            Aad::from(h),
            &mut encrypted_static,
        )
        .unwrap();

    let mut init = Vec::with_capacity(HANDSHAKE_INIT_SIZE);
    init.extend_from_slice(&1u32.to_le_bytes());
    init.extend_from_slice(&42u32.to_le_bytes());
    init.extend_from_slice(&ephemeral_public);
    init.extend_from_slice(&encrypted_static);
    init.extend_from_slice(&[0; 12 + 16]); // Without the static DH, the timestamp is garbage.

    let mac1_key = hash(b"mac1----", responder.as_bytes());
    let mut mac = Blake2sMac::<U16>::new_from_slice(&mac1_key).unwrap();
    blake2::digest::Update::update(&mut mac, &init);
    let mac1: [u8; 16] = mac.finalize_fixed().into();
    init.extend_from_slice(&mac1);
    init.extend_from_slice(&[0; 16]);

    init
}
