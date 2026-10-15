//! Nonce-based replay protection (whitepaper §5.4.6): a sliding window
//! tolerates reordering but rejects duplicates and stale packets.

use crate::harness::{Outcome as _, Peer::A, Peer::B, REPLAY_WINDOW, Sim, ipv4_packet};
use sanstun::Error;

#[test]
fn replayed_data_packet_is_rejected() {
    let mut sim = Sim::connected();
    let datagram = sim.encapsulate(A, &ipv4_packet(b"once only"));

    sim.deliver(B, &datagram).expect_one_ip();
    let error = sim.deliver(B, &datagram).expect_err();

    assert!(matches!(error, Error::DuplicateCounter));
}

#[test]
fn reordered_packets_within_the_window_are_accepted() {
    let mut sim = Sim::connected();
    let datagrams = (0..4)
        .map(|i| sim.encapsulate(A, &ipv4_packet(&[i])))
        .collect::<Vec<_>>();

    for i in [3, 0, 1, 2] {
        sim.deliver(B, &datagrams[i]).expect_one_ip();
    }

    let error = sim.deliver(B, &datagrams[1]).expect_err();
    assert!(matches!(error, Error::DuplicateCounter));
}

#[test]
fn packets_behind_the_replay_window_are_rejected() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"");

    let first = sim.encapsulate(A, &ip_packet);
    let mut last = first.clone();
    for _ in 0..REPLAY_WINDOW {
        last = sim.encapsulate(A, &ip_packet);
    }

    sim.deliver(B, &last).expect_one_ip();
    let error = sim.deliver(B, &first).expect_err();

    assert!(matches!(error, Error::InvalidCounter));
}

/// A counter jump advances the replay window without rejecting unseen packets inside it.
#[test]
fn counter_jump_slides_the_window() {
    const W: usize = REPLAY_WINDOW as usize;

    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"");
    let datagrams = (0..3 * W + 1)
        .map(|_| sim.encapsulate(A, &ip_packet))
        .collect::<Vec<_>>();

    sim.deliver(B, &datagrams[0]).expect_one_ip();
    sim.deliver(B, &datagrams[3 * W]).expect_one_ip();

    let error = sim.deliver(B, &datagrams[W]).expect_err();
    assert!(matches!(error, Error::InvalidCounter));

    // This is the oldest packet still inside the window.
    sim.deliver(B, &datagrams[2 * W + 1]).expect_one_ip();

    let error = sim.deliver(B, &datagrams[2 * W + 1]).expect_err();
    assert!(matches!(error, Error::DuplicateCounter));
}
