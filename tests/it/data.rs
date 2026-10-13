//! Transport data messages (whitepaper §5.4.6): encryption overhead,
//! keepalives, tampering and validation of the decrypted payload.

use crate::harness::{
    DATA_OVERHEAD, KEEPALIVE_SIZE, Outcome as _, Peer::A, Peer::B, Sim, ipv4_packet, ipv6_packet,
};
use sanstun::{Committed, Error, Event, Keepalive};

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

// §5.4.6: the plaintext is zero-padded to a multiple of 16 bytes. The padding
// is returned with the payload; the caller strips it when parsing the IP packet.
#[test]
fn data_messages_are_zero_padded_to_a_multiple_of_16_bytes() {
    let mut sim = Sim::connected();

    for len in [1, 15, 16, 17, 100] {
        let plaintext = vec![0xff; len];
        let datagram = sim.encapsulate(A, &plaintext);
        let now = sim.now;
        let message = sim.receive(B, &datagram);
        let Ok(Some(pending)) = sim.tunn_mut(B).begin_decapsulate(message, now) else {
            panic!("expected a data message");
        };
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

    let message = sim.receive(A, &response);
    let tunn = sim.tunn_mut(A);
    assert!(tunn.begin_decapsulate(message, now).unwrap().is_none());
    let event = tunn.poll_event();
    let Some(Event::KeepaliveDue(keepalive)) = event else {
        panic!("expected a due keepalive, got {event:?}");
    };
    assert!(tunn.poll_event().is_none());

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

#[test]
fn data_messages_name_the_receiving_tunnel() {
    let mut sim = Sim::connected();
    let datagram = sim.encapsulate(A, b"hello");

    let message = sim.receive(B, &datagram);

    assert_eq!(message.tunnel_id(), Some(sim.tunn(B).id()));
    assert_ne!(sim.tunn(A).id(), sim.tunn(B).id());
}
