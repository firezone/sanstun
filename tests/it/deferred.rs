//! Deferred encryption and decryption: tunnel state changes in order, while
//! cryptographic work can run in any order on other threads.

use crate::harness::{
    BUF, DATA_OVERHEAD, Outcome as _, Peer::A, Peer::B, REJECT_AFTER_TIME, REPLAY_WINDOW, Sim,
    counter, decrypt_one, encrypt_one, ip_packet_len, ipv4_packet, receiver_index,
};
use sanstun::{
    Committed, Decrypted, DecryptedBatch, Error, PendingDecapsulate, PendingEncapsulate,
};
use std::time::Duration;

#[test]
fn encrypt_runs_on_another_thread() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"encrypted elsewhere");

    let pending = sim.begin_encrypt(A, 1);
    let datagram = std::thread::scope(|s| {
        s.spawn(|| {
            let mut buf = vec![0u8; BUF];
            encrypt_one(pending, &ip_packet, &mut buf).unwrap().to_vec()
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

    let pending = ip_packets
        .iter()
        .map(|_| sim.begin_encrypt(A, 1))
        .collect::<Vec<_>>();
    let mut datagrams = pending
        .into_iter()
        .zip(&ip_packets)
        .rev()
        .map(|(pending, ip_packet)| {
            let mut buf = vec![0u8; BUF];
            encrypt_one(pending, ip_packet, &mut buf).unwrap().to_vec()
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

    let pending = sim.begin_encrypt(A, 1);
    let required = ip_packet.len().next_multiple_of(16) + DATA_OVERHEAD;
    let mut buf = vec![0u8; required - 1];

    let Err(Error::DestinationBufferTooSmall {
        required: reported,
        available,
    }) = encrypt_one(pending, &ip_packet, &mut buf)
    else {
        panic!("expected the buffer to be too small");
    };
    assert_eq!((reported, available), (required, required - 1));
}

#[test]
fn encrypting_an_empty_plaintext_fails() {
    let mut sim = Sim::connected();

    let pending = sim.begin_encrypt(A, 1);
    let mut buf = vec![0u8; BUF];

    assert!(matches!(
        encrypt_one(pending, &[], &mut buf),
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
        s.spawn(|| decrypt_one(pending, &datagram, vec![0u8; BUF]))
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
    let first = decrypt_one(first, &datagram, &mut first_buf[..]);
    let second = decrypt_one(second, &datagram, &mut second_buf[..]);

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
    let pending = sim.prepare_decrypt(B, &tampered).unwrap();
    let decrypted = decrypt_one(pending, &tampered, &mut buf);
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
    let pending = sim.prepare_decrypt(B, &datagram).unwrap();
    let decrypted = decrypt_one(pending, &datagram, vec![0u8; BUF]);

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

    let pending = sim.prepare_decrypt(B, &datagram).unwrap();
    let decrypted = decrypt_one(pending, &datagram, vec![0u8; BUF]);
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
    let pending = sim.prepare_decrypt(B, &datagram).unwrap();
    let decrypted = decrypt_one(pending, &datagram, &mut buf);

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
    let pending = sim.prepare_decrypt(B, &datagram).unwrap();
    let decrypted = decrypt_one(pending, &datagram, buf);
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
fn batch_reserves_consecutive_counters() {
    let mut sim = Sim::connected();
    let ip_packets = (0..3).map(|i| ipv4_packet(&[i])).collect::<Vec<_>>();
    let mut bufs = vec![vec![0u8; BUF]; 3];

    let pending = sim.begin_encrypt(A, 3);
    assert_eq!(pending.len(), 3);
    let datagrams = pending
        .encrypt(
            ip_packets
                .iter()
                .map(Vec::as_slice)
                .zip(bufs.iter_mut().map(Vec::as_mut_slice)),
        )
        .map(|message| message.unwrap().to_vec())
        .collect::<Vec<_>>();

    let first = counter(&datagrams[0]);
    let counters = datagrams.iter().map(|d| counter(d)).collect::<Vec<_>>();
    assert_eq!(counters, [first, first + 1, first + 2]);
    for (datagram, ip_packet) in datagrams.iter().zip(&ip_packets) {
        assert_eq!(&sim.deliver(B, datagram).expect_one_ip(), ip_packet);
    }
}

#[test]
fn unused_counters_of_a_batch_are_tolerated_by_the_peer() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"one of three");
    let mut buf = vec![0u8; BUF];

    let pending = sim.begin_encrypt(A, 3);
    let datagram = encrypt_one(pending, &ip_packet, &mut buf).unwrap().to_vec();
    let after = sim.encapsulate(A, &ip_packet);

    assert_eq!(counter(&after), counter(&datagram) + 3);
    assert_eq!(sim.deliver(B, &after).expect_one_ip(), ip_packet);
    assert_eq!(sim.deliver(B, &datagram).expect_one_ip(), ip_packet);
}

#[test]
fn increment_rejects_another_session_and_replays_without_changing_the_batch() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"batched");
    let old_session = sim.encapsulate(A, &ip_packet);
    sim.suspend(Duration::from_millis(200));
    sim.establish();
    let seen = sim.encapsulate(A, &ip_packet);
    assert_eq!(sim.deliver(B, &seen).expect_one_ip(), ip_packet);
    let fresh = sim.encapsulate(A, &ip_packet);
    assert_ne!(receiver_index(&fresh), receiver_index(&old_session));

    let fresh = sim.receive_data(B, &fresh);
    let old_session = sim.receive_data(B, &old_session);
    let seen = sim.receive_data(B, &seen);
    let now = sim.now;
    let mut batch = sim.tunn_mut(B).begin_decapsulate(fresh, now).unwrap();

    assert!(matches!(
        batch.increment(old_session),
        Err(Error::WrongIndex)
    ));
    assert!(matches!(
        batch.increment(seen),
        Err(Error::DuplicateCounter)
    ));
    assert_eq!(batch.finish().len(), 1);
}

#[test]
fn decrypted_batch_is_not_committed_to_a_later_session_with_the_same_index() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"stale");
    for _ in 0..3 {
        sim.encapsulate(A, &ip_packet);
    }
    let datagrams = (0..2)
        .map(|_| sim.encapsulate(A, &ip_packet))
        .collect::<Vec<_>>();
    let decrypted = sim.decrypt_batch(B, &datagrams);

    // The session part of an index wraps after 256 handshakes.
    for _ in 0..256 {
        sim.suspend(Duration::from_millis(200));
        sim.establish();
    }
    let fresh = sim.encapsulate(A, &ip_packet);
    assert_eq!(receiver_index(&fresh), receiver_index(&datagrams[0]));

    for decrypted in decrypted {
        assert!(matches!(
            sim.commit(B, decrypted),
            Err(Error::NoCurrentSession)
        ));
    }
    assert_eq!(sim.deliver(B, &fresh).expect_one_ip(), ip_packet);
}

#[test]
fn tampered_message_does_not_affect_the_rest_of_its_batch() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"batched");
    let mut datagrams = (0..3)
        .map(|_| sim.encapsulate(A, &ip_packet))
        .collect::<Vec<_>>();
    *datagrams[1].last_mut().unwrap() ^= 1;

    let results = sim
        .decrypt_batch(B, &datagrams)
        .map(|decrypted| sim.commit(B, decrypted))
        .collect::<Vec<_>>();

    assert_eq!(results.len(), 3);
    assert_eq!(results[0].as_ref().unwrap(), &Some(ip_packet.clone()));
    assert!(matches!(results[1], Err(Error::InvalidAeadTag)));
    assert_eq!(results[2].as_ref().unwrap(), &Some(ip_packet));
}

#[test]
fn deferred_work_can_move_to_another_thread() {
    fn assert_send<T: Send>() {}

    assert_send::<PendingEncapsulate>();
    assert_send::<PendingDecapsulate>();
    assert_send::<DecryptedBatch<Vec<u8>>>();
    assert_send::<Decrypted<Vec<u8>>>();
}
