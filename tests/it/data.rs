//! Transport data messages (whitepaper §5.4.6): encryption overhead,
//! keepalives, tampering and validation of the decrypted payload.

use crate::harness::{
    DATA_OVERHEAD, KEEPALIVE_SIZE, Outcome as _, Peer::A, Peer::B, Sim, ipv4_packet, ipv6_packet,
};
use sanstun::{Decapsulated, Error, Keepalive};

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

#[test]
fn data_messages_have_32_bytes_of_overhead() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"some payload");

    let datagram = sim.encapsulate(A, &ip_packet);

    assert_eq!(datagram.len(), ip_packet.len() + DATA_OVERHEAD);
}

// §6.1: a keepalive is a data message with a zero-length payload; it proves
// liveness but is not forwarded to the tunnel interface.
#[test]
fn keepalives_are_consumed_silently() {
    let mut sim = Sim::connected();

    let now = sim.now;
    let keepalive = sim
        .tunn_mut(A)
        .encapsulate_keepalive(Keepalive, now)
        .unwrap();
    assert_eq!(keepalive.len(), KEEPALIVE_SIZE);

    sim.deliver(B, &keepalive).expect_consumed();
}

#[test]
fn keepalive_without_a_session_fails() {
    let mut sim = Sim::new();
    let now = sim.now;

    assert!(matches!(
        sim.tunn_mut(A).encapsulate_keepalive(Keepalive, now),
        Err(Error::NoCurrentSession)
    ));
}

#[test]
fn handshake_response_leaves_the_keepalive_to_the_caller() {
    let mut sim = Sim::new();
    let init = sim.initiate_handshake(A);
    let response = sim.deliver(B, &init).expect_one_net();
    let now = sim.now;

    let packet = sim.receive(A, &response);
    let result = sim.tunn_mut(A).decapsulate(packet, now);
    let Ok(Decapsulated::KeepaliveDue(keepalive)) = result else {
        panic!("expected a due keepalive, got {result:?}");
    };

    let keepalive = sim
        .tunn_mut(A)
        .encapsulate_keepalive(keepalive, now)
        .unwrap();
    sim.deliver(B, &keepalive).expect_consumed();
    sim.assert_connectivity();
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

    // Same session slot, different index: decryption is never attempted.
    let mut datagram = sim.encapsulate(A, &ipv4_packet(b"payload"));
    let index = u32::from_le_bytes(datagram[4..8].try_into().unwrap());
    datagram[4..8].copy_from_slice(&(index + 8).to_le_bytes());
    let error = sim.deliver(B, &datagram).expect_err();
    assert!(matches!(error, Error::WrongIndex));

    // Index pointing at an empty session slot.
    let mut datagram = sim.encapsulate(A, &ipv4_packet(b"payload"));
    datagram[4..8].copy_from_slice(&(index + 6).to_le_bytes());
    let error = sim.deliver(B, &datagram).expect_err();
    assert!(matches!(error, Error::NoCurrentSession));
}

// §5.4.6: encrypted packets may be padded; the caller parses the IP packet and
// truncates the padding, so the whole decrypted payload is returned.
#[test]
fn decrypted_payload_is_returned_with_its_padding() {
    let mut sim = Sim::connected();

    let mut padded = ipv4_packet(b"payload");
    padded.extend_from_slice(&[0u8; 13]);
    let datagram = sim.encapsulate(A, &padded);

    let received = sim.deliver(B, &datagram).expect_one_ip();

    assert_eq!(received, padded);
}
