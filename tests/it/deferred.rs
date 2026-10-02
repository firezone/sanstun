//! Deferred encryption and decryption of data messages: all state changes
//! happen on the `Tunnel`, in order, while the AEAD work may run later, in any
//! order and on any thread.

use crate::harness::{ipv4_packet, Outcome as _, Peer::A, Peer::B, Sim, DATA_OVERHEAD};
use sanstun::Error;

const BUF: usize = 4096;

#[test]
fn seal_runs_on_another_thread() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"sealed elsewhere");
    let now = sim.now;

    let seal = sim
        .tunn_mut(A)
        .encapsulate_data(ip_packet.len(), now)
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
                .encapsulate_data(ip_packet.len(), now)
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
        .encapsulate_data(ip_packet.len(), now)
        .unwrap();
    let mut buf = vec![0u8; ip_packet.len() + DATA_OVERHEAD - 1];

    assert!(matches!(
        seal.seal_into(&ip_packet, &mut buf),
        Err(Error::DestinationBufferTooSmall)
    ));
}

fn counter(datagram: &[u8]) -> u64 {
    u64::from_le_bytes(datagram[8..16].try_into().unwrap())
}
