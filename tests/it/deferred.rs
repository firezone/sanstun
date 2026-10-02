//! Deferred encryption and decryption of data messages: all state changes
//! happen on the `Tunnel`, in order, while the AEAD work may run later, in any
//! order and on any thread.

use crate::harness::{
    ipv4_packet, Outcome as _, Peer::A, Peer::B, Sim, DATA_OVERHEAD, REPLAY_WINDOW,
};
use sanstun::{
    Decapsulated, Error, Opened, Packet, PendingDecapsulate, PendingEncapsulate, Tunnel,
};
use std::time::Instant;

const BUF: usize = 4096;

#[test]
fn seal_runs_on_another_thread() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"sealed elsewhere");
    let now = sim.now;

    let seal = sim
        .tunn_mut(A)
        .prepare_encapsulate(ip_packet.len(), now)
        .unwrap();
    let datagram = std::thread::scope(|s| {
        s.spawn(|| {
            let mut buf = vec![0u8; BUF];
            seal.seal_into(&ip_packet, &mut buf).unwrap().to_vec()
        })
        .join()
        .unwrap()
    });

    assert_eq!(datagram.len(), ip_packet.len() + DATA_OVERHEAD);
    assert_eq!(sim.deliver(B, &datagram).expect_one_ip(), ip_packet);
}

#[test]
fn seals_running_out_of_order_keep_their_counters() {
    let mut sim = Sim::connected();
    let ip_packets = (0..3).map(|i| ipv4_packet(&[i])).collect::<Vec<_>>();
    let now = sim.now;

    let seals = ip_packets
        .iter()
        .map(|ip_packet| {
            sim.tunn_mut(A)
                .prepare_encapsulate(ip_packet.len(), now)
                .unwrap()
        })
        .collect::<Vec<_>>();
    let mut datagrams = seals
        .into_iter()
        .zip(&ip_packets)
        .rev()
        .map(|(seal, ip_packet)| {
            let mut buf = vec![0u8; BUF];
            seal.seal_into(ip_packet, &mut buf).unwrap().to_vec()
        })
        .collect::<Vec<_>>();
    datagrams.reverse();

    let counters = datagrams.iter().map(|d| counter(d)).collect::<Vec<_>>();
    assert!(counters.is_sorted());
    for (datagram, ip_packet) in datagrams.iter().zip(&ip_packets) {
        assert_eq!(&sim.deliver(B, datagram).expect_one_ip(), ip_packet);
    }
}

#[test]
fn seal_into_a_short_buffer_fails() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"too big");
    let now = sim.now;

    let seal = sim
        .tunn_mut(A)
        .prepare_encapsulate(ip_packet.len(), now)
        .unwrap();
    let mut buf = vec![0u8; ip_packet.len() + DATA_OVERHEAD - 1];

    assert!(matches!(
        seal.seal_into(&ip_packet, &mut buf),
        Err(Error::DestinationBufferTooSmall)
    ));
}

#[test]
fn open_runs_on_another_thread() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"opened elsewhere");
    let datagram = sim.encapsulate(A, &ip_packet);
    let now = sim.now;

    let open = prepare_open(sim.tunn_mut(B), &datagram, now).unwrap();
    let mut buf = vec![0u8; BUF];
    let opened = std::thread::scope(|s| {
        s.spawn(|| open.open_into(&datagram, &mut buf))
            .join()
            .unwrap()
    });

    assert_eq!(
        finish_open(sim.tunn_mut(B), opened, &mut buf, now).unwrap(),
        Some(ip_packet)
    );
}

#[test]
fn duplicate_within_one_batch_is_accepted_only_once() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"twice");
    let datagram = sim.encapsulate(A, &ip_packet);
    let now = sim.now;
    let tunn = sim.tunn_mut(B);

    let mut first_buf = vec![0u8; BUF];
    let mut second_buf = vec![0u8; BUF];
    let first = prepare_open(tunn, &datagram, now).unwrap();
    let second = prepare_open(tunn, &datagram, now).unwrap();
    let first = first.open_into(&datagram, &mut first_buf);
    let second = second.open_into(&datagram, &mut second_buf);

    assert_eq!(
        finish_open(tunn, first, &mut first_buf, now).unwrap(),
        Some(ip_packet)
    );
    assert!(matches!(
        finish_open(tunn, second, &mut second_buf, now),
        Err(Error::DuplicateCounter)
    ));
}

#[test]
fn tampered_packet_does_not_advance_the_replay_window() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"");
    let datagrams = (0..REPLAY_WINDOW + 2)
        .map(|_| sim.encapsulate(A, &ip_packet))
        .collect::<Vec<_>>();
    let mut tampered = datagrams.last().unwrap().clone();
    *tampered.last_mut().unwrap() ^= 1;
    let now = sim.now;

    let mut buf = vec![0u8; BUF];
    let opened = prepare_open(sim.tunn_mut(B), &tampered, now)
        .unwrap()
        .open_into(&tampered, &mut buf);
    let result = finish_open(sim.tunn_mut(B), opened, &mut buf, now);

    assert!(matches!(result, Err(Error::InvalidAeadTag)));
    assert_eq!(sim.deliver(B, &datagrams[0]).expect_one_ip(), ip_packet);
}

#[test]
fn open_into_a_short_buffer_fails() {
    let mut sim = Sim::connected();
    let datagram = sim.encapsulate(A, &ipv4_packet(b"too big"));
    let now = sim.now;

    let mut buf = vec![0u8; datagram.len() - 17];
    let opened = prepare_open(sim.tunn_mut(B), &datagram, now)
        .unwrap()
        .open_into(&datagram, &mut buf);

    assert!(matches!(
        finish_open(sim.tunn_mut(B), opened, &mut buf, now),
        Err(Error::DestinationBufferTooSmall)
    ));
}

#[test]
fn handshake_response_leaves_the_keepalive_to_the_caller() {
    let mut sim = Sim::new();
    let init = sim.initiate_handshake(A);
    let response = sim.deliver(B, &init).expect_one_net();
    let now = sim.now;

    let mut buf = vec![0u8; BUF];
    let result =
        sim.tunn_mut(A)
            .decapsulate(None, Packet::parse(&response).unwrap(), &mut buf, now);
    assert!(matches!(result, Ok(Decapsulated::KeepaliveDue)));

    let keepalive = sim.encapsulate(A, &[]);
    sim.deliver(B, &keepalive).expect_consumed();
    sim.assert_connectivity();
}

#[test]
fn deferred_work_can_move_to_another_thread() {
    fn assert_send<T: Send>() {}

    assert_send::<PendingEncapsulate>();
    assert_send::<PendingDecapsulate>();
    assert_send::<Opened>();
}

fn prepare_open(
    tunn: &mut Tunnel,
    datagram: &[u8],
    now: Instant,
) -> Result<PendingDecapsulate, Error> {
    let mut buf = vec![0u8; BUF];
    match tunn.decapsulate(None, Packet::parse(datagram)?, &mut buf, now)? {
        Decapsulated::Data(open) => Ok(open),
        other => panic!("expected a data message, got {other:?}"),
    }
}

fn finish_open(
    tunn: &mut Tunnel,
    opened: Opened,
    buf: &mut [u8],
    now: Instant,
) -> Result<Option<Vec<u8>>, Error> {
    let plaintext = tunn.finish_decapsulate(opened, buf, now)?;

    Ok(plaintext.map(|p| p.to_vec()))
}

fn counter(datagram: &[u8]) -> u64 {
    u64::from_le_bytes(datagram[8..16].try_into().unwrap())
}
