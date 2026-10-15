//! Transport data messages (whitepaper §5.4.6): encryption overhead,
//! keepalives, tampering and validation of the decrypted payload.

use crate::harness::{
    DATA_OVERHEAD, KEEPALIVE_SIZE, Outcome as _, Peer::A, Peer::B, Sim, ipv4_packet, ipv6_packet,
    secs,
};
use sanstun::{Committed, Error, ReceivedMessage};

#[test]
fn ipv4_packets_round_trip() {
    let mut sim = Sim::connected();

    sim.assert_connectivity();
}

#[test]
fn ipv6_packets_round_trip() {
    let mut sim = Sim::connected();
    let ip_packet = ipv6_packet(b"hello v6");

    sim.send_ip(A, &ip_packet);

    assert_eq!(sim.take_inbox(B), [ip_packet]);
}

// §5.4.6: decrypted payloads include zero padding; callers remove it when parsing the IP packet.
#[test]
fn data_messages_are_zero_padded_to_a_multiple_of_16_bytes() {
    let mut sim = Sim::connected();

    for len in [1, 15, 16, 17, 100] {
        let plaintext = vec![0xff; len];
        let datagram = sim.encapsulate(A, &plaintext);
        let now = sim.now;
        let pending = sim.prepare_decrypt(B, &datagram).unwrap();
        let decrypted = pending.decrypt(&datagram, vec![0u8; 4096]);
        let Ok(Committed::Data {
            buffer,
            len: decrypted_len,
        }) = sim.tunn_mut(B).commit_decapsulate(decrypted, now)
        else {
            panic!("expected a data payload");
        };

        let padded_len = 16 * len.div_ceil(16);
        let mut padded = plaintext;
        padded.resize(padded_len, 0);
        assert_eq!(datagram.len(), padded_len + DATA_OVERHEAD);
        assert_eq!(buffer[..decrypted_len], padded);
    }
}

// §6.1: keepalives prove liveness but carry no IP packet to forward.
#[test]
fn keepalives_are_consumed_silently() {
    let mut sim = Sim::new();
    let init = sim.initiate_handshake(A);
    let response = sim.deliver(B, &init).expect_one_net();

    let keepalive = sim.deliver(A, &response).expect_one_net();
    assert_eq!(keepalive.len(), KEEPALIVE_SIZE);

    sim.deliver(B, &keepalive).expect_consumed();
}

#[test]
fn handshake_response_returns_the_confirming_keepalive() {
    let mut sim = Sim::new();
    let init = sim.initiate_handshake(A);
    let response = sim.deliver(B, &init).expect_one_net();
    let now = sim.now;

    let ReceivedMessage::HandshakeResponse(response) = sim.receive(A, &response) else {
        panic!("expected a handshake response");
    };
    let tunn = sim.tunn_mut(A);
    let keepalive = tunn.handle_handshake_response(response, now).unwrap();
    assert!(tunn.poll_event().is_none());

    sim.deliver(B, &keepalive).expect_consumed();
    sim.assert_connectivity();
}

#[test]
fn keepalive_without_a_session_is_skipped() {
    let mut sim = Sim::builder().persistent_keepalive_b(secs(25)).build();
    let now = sim.now;

    let tunn = sim.tunn_mut(B);
    tunn.handle_timeout(now + secs(25));

    assert!(tunn.poll_event().is_none());
}

#[test]
fn tampered_data_packet_is_rejected() {
    let mut sim = Sim::connected();

    let mut datagram = sim.encapsulate(A, &ipv4_packet(b"payload"));
    *datagram.last_mut().unwrap() ^= 1;

    let error = sim.deliver(B, &datagram).expect_err();

    assert!(matches!(error, Error::InvalidAeadTag));
    assert!(sim.take_inbox(B).is_empty());
}

#[test]
fn data_with_wrong_receiver_index_is_rejected() {
    let mut sim = Sim::connected();

    // The index points to an occupied slot but does not match its session.
    let mut datagram = sim.encapsulate(A, &ipv4_packet(b"payload"));
    let index = u32::from_le_bytes(datagram[4..8].try_into().unwrap());
    datagram[4..8].copy_from_slice(&(index + 8).to_le_bytes());
    let error = sim.deliver(B, &datagram).expect_err();
    assert!(matches!(error, Error::WrongIndex));

    // The index points to an empty session slot.
    let mut datagram = sim.encapsulate(A, &ipv4_packet(b"payload"));
    datagram[4..8].copy_from_slice(&(index + 6).to_le_bytes());
    let error = sim.deliver(B, &datagram).expect_err();
    assert!(matches!(error, Error::NoCurrentSession));
}

#[test]
fn data_messages_name_the_receiving_tunnel() {
    let mut sim = Sim::connected();
    let datagram = sim.encapsulate(A, b"hello");

    let message = sim.receive(B, &datagram);

    assert_eq!(message.tunnel_id(), Some(sim.tunn(B).id()));
    assert_ne!(sim.tunn(A).id(), sim.tunn(B).id());
}
