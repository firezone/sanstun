//! Deferred encryption and decryption: tunnel state changes in order, while
//! cryptographic work can run in any order on other threads.

use crate::harness::{
    BUF, DATA_OVERHEAD, Outcome as _, Peer::A, Peer::B, REJECT_AFTER_TIME, REPLAY_WINDOW, Sim,
    counter, ip_packet_len, ipv4_packet, receiver_index,
};
use sanstun::{Committed, Decrypted, Error, PendingDecapsulate, PendingEncapsulate};
use std::time::Duration;

#[test]
fn encrypt_runs_on_another_thread() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"encrypted elsewhere");
    let now = sim.now;

    let pending = sim.tunn_mut(A).begin_encapsulate(now).unwrap();
    let datagram = std::thread::scope(|s| {
        s.spawn(|| {
            let mut buf = vec![0u8; BUF];
            pending.encrypt(&ip_packet, &mut buf).unwrap().to_vec()
        })
        .join()
        .unwrap()
    });

    assert_eq!(
        datagram.len(),
        ip_packet.len().next_multiple_of(16) + DATA_OVERHEAD
    );
    assert_eq!(sim.deliver(B, &datagram).expect_one_ip(), ip_packet);
}

#[test]
fn encryptions_running_out_of_order_keep_their_counters() {
    let mut sim = Sim::connected();
    let ip_packets = (0..3).map(|i| ipv4_packet(&[i])).collect::<Vec<_>>();
    let now = sim.now;

    let pending = ip_packets
        .iter()
        .map(|_| sim.tunn_mut(A).begin_encapsulate(now).unwrap())
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

    let pending = sim.tunn_mut(A).begin_encapsulate(now).unwrap();
    let required = ip_packet.len().next_multiple_of(16) + DATA_OVERHEAD;
    let mut buf = vec![0u8; required - 1];

    let Err(Error::DestinationBufferTooSmall {
        required: reported,
        available,
    }) = pending.encrypt(&ip_packet, &mut buf)
    else {
        panic!("expected the buffer to be too small");
    };
    assert_eq!((reported, available), (required, required - 1));
}

#[test]
fn encrypting_an_empty_plaintext_fails() {
    let mut sim = Sim::connected();
    let now = sim.now;

    let pending = sim.tunn_mut(A).begin_encapsulate(now).unwrap();
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

    let pending = sim.prepare_decrypt(B, &datagram).unwrap();
    let decrypted = std::thread::scope(|s| {
        s.spawn(|| pending.decrypt(&datagram, vec![0u8; BUF]))
            .join()
            .unwrap()
    });

    assert_eq!(sim.commit(B, decrypted).unwrap(), Some(ip_packet));
}

#[test]
fn duplicate_within_one_batch_is_accepted_only_once() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"twice");
    let datagram = sim.encapsulate(A, &ip_packet);

    let mut first_buf = vec![0u8; BUF];
    let mut second_buf = vec![0u8; BUF];
    let first = sim.prepare_decrypt(B, &datagram).unwrap();
    let second = sim.prepare_decrypt(B, &datagram).unwrap();
    let first = first.decrypt(&datagram, &mut first_buf[..]);
    let second = second.decrypt(&datagram, &mut second_buf[..]);

    assert_eq!(sim.commit(B, first).unwrap(), Some(ip_packet));
    assert!(matches!(
        sim.commit(B, second),
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

    let mut buf = vec![0u8; BUF];
    let decrypted = sim
        .prepare_decrypt(B, &tampered)
        .unwrap()
        .decrypt(&tampered, &mut buf);
    let result = sim.commit(B, decrypted);

    assert!(matches!(result, Err(Error::InvalidAeadTag)));
    assert_eq!(sim.deliver(B, &datagrams[0]).expect_one_ip(), ip_packet);
}

#[test]
fn decrypted_message_is_not_committed_to_a_later_session_with_the_same_index() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"stale");
    for _ in 0..3 {
        sim.encapsulate(A, &ip_packet);
    }
    let datagram = sim.encapsulate(A, &ip_packet);
    let decrypted = sim
        .prepare_decrypt(B, &datagram)
        .unwrap()
        .decrypt(&datagram, vec![0u8; BUF]);

    // The session part of an index wraps after 256 handshakes.
    for _ in 0..256 {
        sim.suspend(Duration::from_millis(200));
        sim.establish();
    }
    let fresh = sim.encapsulate(A, &ip_packet);
    assert_eq!(receiver_index(&fresh), receiver_index(&datagram));

    assert!(matches!(
        sim.commit(B, decrypted),
        Err(Error::NoCurrentSession)
    ));
    assert_eq!(sim.deliver(B, &fresh).expect_one_ip(), ip_packet);
}

#[test]
fn decryption_straddling_the_session_expiry_is_rejected() {
    let mut sim = Sim::connected();
    let datagram = sim.encapsulate(A, &ipv4_packet(b"too late"));

    let decrypted = sim
        .prepare_decrypt(B, &datagram)
        .unwrap()
        .decrypt(&datagram, vec![0u8; BUF]);
    sim.suspend(REJECT_AFTER_TIME);

    assert!(matches!(
        sim.commit(B, decrypted),
        Err(Error::NoCurrentSession)
    ));
}

#[test]
fn decrypt_into_a_short_buffer_fails() {
    let mut sim = Sim::connected();
    let datagram = sim.encapsulate(A, &ipv4_packet(b"too big"));

    let mut buf = vec![0u8; datagram.len() - 17];
    let decrypted = sim
        .prepare_decrypt(B, &datagram)
        .unwrap()
        .decrypt(&datagram, &mut buf);

    assert!(matches!(
        sim.commit(B, decrypted),
        Err(Error::DestinationBufferTooSmall { .. })
    ));
}

#[test]
fn decrypted_message_owns_its_buffer() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"boxed");
    let datagram = sim.encapsulate(A, &ip_packet);
    let now = sim.now;

    let buf: Box<[u8]> = vec![0u8; BUF].into_boxed_slice();
    let decrypted = sim
        .prepare_decrypt(B, &datagram)
        .unwrap()
        .decrypt(&datagram, buf);
    let Committed::Data { buffer, len } =
        sim.tunn_mut(B).commit_decapsulate(decrypted, now).unwrap()
    else {
        panic!("expected a data payload");
    };

    assert_eq!(buffer.len(), BUF);
    assert_eq!(
        &buffer[..ip_packet_len(&buffer[..len])],
        ip_packet.as_slice()
    );
}

#[test]
fn deferred_work_can_move_to_another_thread() {
    fn assert_send<T: Send>() {}

    assert_send::<PendingEncapsulate>();
    assert_send::<PendingDecapsulate>();
    assert_send::<Decrypted<Vec<u8>>>();
}
