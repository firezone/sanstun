//! Deferred encryption and decryption of data messages: all state changes
//! happen on the `Tunnel`, in order, while the AEAD work may run later, in any
//! order and on any thread.

use crate::harness::{
    ipv4_packet, Outcome as _, Peer::A, Peer::B, Sim, DATA_OVERHEAD, REPLAY_WINDOW,
};
use sanstun::{
    Committed, Decapsulated, Decrypted, Error, Keepalive, Packet, PendingDecapsulate,
    PendingEncapsulate, Tunnel,
};
use std::time::Instant;

const BUF: usize = 4096;

#[test]
fn encrypt_runs_on_another_thread() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"encrypted elsewhere");
    let now = sim.now;

    let pending = sim.tunn_mut(A).prepare_encapsulate(now).unwrap();
    let datagram = std::thread::scope(|s| {
        s.spawn(|| {
            let mut buf = vec![0u8; BUF];
            pending.encrypt(&ip_packet, &mut buf).unwrap().to_vec()
        })
        .join()
        .unwrap()
    });

    assert_eq!(datagram.len(), ip_packet.len() + DATA_OVERHEAD);
    assert_eq!(sim.deliver(B, &datagram).expect_one_ip(), ip_packet);
}

#[test]
fn encryptions_running_out_of_order_keep_their_counters() {
    let mut sim = Sim::connected();
    let ip_packets = (0..3).map(|i| ipv4_packet(&[i])).collect::<Vec<_>>();
    let now = sim.now;

    let pending = ip_packets
        .iter()
        .map(|_| sim.tunn_mut(A).prepare_encapsulate(now).unwrap())
        .collect::<Vec<_>>();
    let mut datagrams = pending
        .into_iter()
        .zip(&ip_packets)
        .rev()
        .map(|(pending, ip_packet)| {
            let mut buf = vec![0u8; BUF];
            pending.encrypt(ip_packet, &mut buf).unwrap().to_vec()
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
fn encrypt_into_a_short_buffer_fails() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"too big");
    let now = sim.now;

    let pending = sim.tunn_mut(A).prepare_encapsulate(now).unwrap();
    let mut buf = vec![0u8; ip_packet.len() + DATA_OVERHEAD - 1];

    assert!(matches!(
        pending.encrypt(&ip_packet, &mut buf),
        Err(Error::DestinationBufferTooSmall)
    ));
}

#[test]
fn encrypting_an_empty_plaintext_fails() {
    let mut sim = Sim::connected();
    let now = sim.now;

    let pending = sim.tunn_mut(A).prepare_encapsulate(now).unwrap();
    let mut buf = vec![0u8; BUF];

    assert!(matches!(
        pending.encrypt(&[], &mut buf),
        Err(Error::EmptyPlaintext)
    ));
}

#[test]
fn decrypt_runs_on_another_thread() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"decrypted elsewhere");
    let datagram = sim.encapsulate(A, &ip_packet);
    let now = sim.now;

    let pending = prepare_decrypt(sim.tunn_mut(B), &datagram, now).unwrap();
    let decrypted = std::thread::scope(|s| {
        s.spawn(|| pending.decrypt(&datagram, vec![0u8; BUF]))
            .join()
            .unwrap()
    });

    assert_eq!(
        commit(sim.tunn_mut(B), decrypted, now).unwrap(),
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
    let first = prepare_decrypt(tunn, &datagram, now).unwrap();
    let second = prepare_decrypt(tunn, &datagram, now).unwrap();
    let first = first.decrypt(&datagram, &mut first_buf[..]);
    let second = second.decrypt(&datagram, &mut second_buf[..]);

    assert_eq!(commit(tunn, first, now).unwrap(), Some(ip_packet));
    assert!(matches!(
        commit(tunn, second, now),
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
    let decrypted = prepare_decrypt(sim.tunn_mut(B), &tampered, now)
        .unwrap()
        .decrypt(&tampered, &mut buf);
    let result = commit(sim.tunn_mut(B), decrypted, now);

    assert!(matches!(result, Err(Error::InvalidAeadTag)));
    assert_eq!(sim.deliver(B, &datagrams[0]).expect_one_ip(), ip_packet);
}

#[test]
fn decrypt_into_a_short_buffer_fails() {
    let mut sim = Sim::connected();
    let datagram = sim.encapsulate(A, &ipv4_packet(b"too big"));
    let now = sim.now;

    let mut buf = vec![0u8; datagram.len() - 17];
    let decrypted = prepare_decrypt(sim.tunn_mut(B), &datagram, now)
        .unwrap()
        .decrypt(&datagram, &mut buf);

    assert!(matches!(
        commit(sim.tunn_mut(B), decrypted, now),
        Err(Error::DestinationBufferTooSmall)
    ));
}

#[test]
fn decrypted_message_owns_its_buffer() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"boxed");
    let mut padded = ip_packet.clone();
    padded.extend_from_slice(&[0u8; 7]);
    let datagram = sim.encapsulate(A, &padded);
    let now = sim.now;

    let buf: Box<[u8]> = vec![0u8; BUF].into_boxed_slice();
    let decrypted = prepare_decrypt(sim.tunn_mut(B), &datagram, now)
        .unwrap()
        .decrypt(&datagram, buf);
    let Committed::IpPacket { buffer, len } =
        sim.tunn_mut(B).commit_decrypted(decrypted, now).unwrap()
    else {
        panic!("expected an IP packet");
    };

    assert_eq!(len, ip_packet.len());
    assert_eq!(buffer.len(), BUF);
    assert_eq!(&buffer[..len], ip_packet.as_slice());
}

#[test]
fn handshake_response_leaves_the_keepalive_to_the_caller() {
    let mut sim = Sim::new();
    let init = sim.initiate_handshake(A);
    let response = sim.deliver(B, &init).expect_one_net();
    let now = sim.now;

    let result = sim
        .tunn_mut(A)
        .decapsulate(None, Packet::parse(&response).unwrap(), now);
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
fn self_created_keepalive_is_decapsulated_as_a_keepalive() {
    let mut sim = Sim::connected();
    let now = sim.now;

    let keepalive = sim
        .tunn_mut(A)
        .encapsulate_keepalive(Keepalive, now)
        .unwrap();
    assert_eq!(keepalive.len(), DATA_OVERHEAD);

    let decrypted = prepare_decrypt(sim.tunn_mut(B), &keepalive, now)
        .unwrap()
        .decrypt(&keepalive, vec![0u8; BUF]);
    assert!(matches!(
        sim.tunn_mut(B).commit_decrypted(decrypted, now),
        Ok(Committed::Keepalive)
    ));
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
fn deferred_work_can_move_to_another_thread() {
    fn assert_send<T: Send>() {}

    assert_send::<PendingEncapsulate>();
    assert_send::<PendingDecapsulate>();
    assert_send::<Decrypted<Vec<u8>>>();
}

fn prepare_decrypt(
    tunn: &mut Tunnel,
    datagram: &[u8],
    now: Instant,
) -> Result<PendingDecapsulate, Error> {
    match tunn.decapsulate(None, Packet::parse(datagram)?, now)? {
        Decapsulated::Data(pending) => Ok(pending),
        other => panic!("expected a data message, got {other:?}"),
    }
}

fn commit<B: AsRef<[u8]>>(
    tunn: &mut Tunnel,
    decrypted: Decrypted<B>,
    now: Instant,
) -> Result<Option<Vec<u8>>, Error> {
    match tunn.commit_decrypted(decrypted, now)? {
        Committed::IpPacket { buffer, len } => Ok(Some(buffer.as_ref()[..len].to_vec())),
        Committed::Keepalive => Ok(None),
    }
}

fn counter(datagram: &[u8]) -> u64 {
    u64::from_le_bytes(datagram[8..16].try_into().unwrap())
}
