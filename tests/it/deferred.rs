//! Deferred encryption and decryption: tunnel state changes in order, while
//! cryptographic work can run in any order on other threads.

use crate::harness::{
    BUF, DATA_OVERHEAD, Outcome as _, Peer::A, Peer::B, REJECT_AFTER_TIME, REPLAY_WINDOW, Sim,
    counter, decrypt_one, encrypt_one, ip_packet_len, ipv4_packet, receiver_index,
};
use sanstun::{
    Committed, CommittedBatch, DecryptedBatch, Error, PendingDecapsulate, PendingEncapsulate,
};
use std::num::NonZeroUsize;
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
    let mut committed = sim.tunn_mut(B).commit_decapsulate(decrypted, now).unwrap();
    let Some(Ok(Committed::Data { buffer, len })) = committed.next() else {
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
fn split_batch_keeps_consecutive_counters() {
    let mut sim = Sim::connected();
    let ip_packets = (0..3).map(|i| ipv4_packet(&[i])).collect::<Vec<_>>();
    let mut bufs = vec![vec![0u8; BUF]; 3];

    let mut first = sim.begin_encrypt(A, 3);
    let second = first.split_off(NonZeroUsize::new(2).unwrap()).unwrap();
    assert_eq!((first.len(), second.len()), (2, 1));
    let (first_bufs, second_bufs) = bufs.split_at_mut(2);
    let datagrams = second
        .encrypt(std::iter::zip(
            ip_packets[2..].iter().map(Vec::as_slice),
            second_bufs.iter_mut().map(Vec::as_mut_slice),
        ))
        .chain(first.encrypt(std::iter::zip(
            ip_packets[..2].iter().map(Vec::as_slice),
            first_bufs.iter_mut().map(Vec::as_mut_slice),
        )))
        .map(|message| message.unwrap().to_vec())
        .collect::<Vec<_>>();

    let first = counter(&datagrams[1]);
    let counters = datagrams.iter().map(|d| counter(d)).collect::<Vec<_>>();
    assert_eq!(counters, [first + 2, first, first + 1]);
    for (datagram, ip_packet) in datagrams.iter().zip([2, 0, 1].map(|i| &ip_packets[i])) {
        assert_eq!(&sim.deliver(B, datagram).expect_one_ip(), ip_packet);
    }
}

#[test]
fn split_at_or_beyond_the_batch_keeps_it_whole() {
    let mut sim = Sim::connected();

    let mut pending = sim.begin_encrypt(A, 2);

    assert!(pending.split_off(NonZeroUsize::new(2).unwrap()).is_none());
    assert!(pending.split_off(NonZeroUsize::new(3).unwrap()).is_none());
    assert_eq!(pending.len(), 2);
}

#[test]
fn unused_counters_of_a_batch_are_tolerated_by_the_peer() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"one of three");
    let mut bufs = vec![vec![0u8; BUF]; 3];

    let pending = sim.begin_encrypt(A, 3);
    let datagram = pending
        .encrypt(
            [ip_packet.as_slice(); 3]
                .into_iter()
                .zip(bufs.iter_mut().map(Vec::as_mut_slice)),
        )
        .next()
        .unwrap()
        .unwrap()
        .to_vec();
    let after = sim.encapsulate(A, &ip_packet);

    assert_eq!(counter(&after), counter(&datagram) + 3);
    assert_eq!(sim.deliver(B, &after).expect_one_ip(), ip_packet);
    assert_eq!(sim.deliver(B, &datagram).expect_one_ip(), ip_packet);
}

#[test]
#[should_panic(expected = "fewer messages than reserved counters")]
fn encrypting_fewer_messages_than_reserved_is_a_bug() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"one of two");
    let mut buf = vec![0u8; BUF];

    let pending = sim.begin_encrypt(A, 2);
    for _ in pending.encrypt([(ip_packet.as_slice(), buf.as_mut_slice())]) {}
}

#[test]
#[should_panic(expected = "more messages than the batch holds")]
fn decrypting_more_messages_than_the_batch_holds_is_a_bug() {
    let mut sim = Sim::connected();
    let datagram = sim.encapsulate(A, &ipv4_packet(b"one"));
    let pending = sim.prepare_decrypt(B, &datagram).unwrap();

    let _ = pending.decrypt([
        (datagram.as_slice(), vec![0u8; BUF]),
        (datagram.as_slice(), vec![0u8; BUF]),
    ]);
}

#[test]
fn push_rejects_another_session_and_replays_without_changing_the_batch() {
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

    assert!(matches!(batch.push(old_session), Err(Error::WrongIndex)));
    assert!(matches!(batch.push(seen), Err(Error::DuplicateCounter)));
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

    assert!(matches!(
        sim.commit_batch(B, decrypted),
        Err(Error::NoCurrentSession)
    ));
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

    let decrypted = sim.decrypt_batch(B, &datagrams);
    let results = sim.commit_batch(B, decrypted).unwrap();

    assert_eq!(results.len(), 3);
    assert_eq!(results[0].as_ref().unwrap(), &Some(ip_packet.clone()));
    assert!(matches!(results[1], Err(Error::InvalidAeadTag)));
    assert_eq!(results[2].as_ref().unwrap(), &Some(ip_packet));
}

#[test]
fn replay_within_a_batch_does_not_affect_the_rest_of_it() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"batched");
    let first = sim.encapsulate(A, &ip_packet);
    let second = sim.encapsulate(A, &ip_packet);

    let decrypted = sim.decrypt_batch(B, &[first.clone(), first, second]);
    let results = sim.commit_batch(B, decrypted).unwrap();

    assert_eq!(results.len(), 3);
    assert_eq!(results[0].as_ref().unwrap(), &Some(ip_packet.clone()));
    assert!(matches!(results[1], Err(Error::DuplicateCounter)));
    assert_eq!(results[2].as_ref().unwrap(), &Some(ip_packet));
}

#[test]
fn extracted_messages_commit_separately_from_the_rest_of_their_batch() {
    let mut sim = Sim::connected();
    let probe = ipv4_packet(b"probe");
    let data = ipv4_packet(b"data");
    let datagrams = [&data, &probe, &data, &probe]
        .map(|ip_packet| sim.encapsulate(A, ip_packet))
        .to_vec();

    let mut decrypted = sim.decrypt_batch(B, &datagrams);
    let probes = decrypted.extract_if(|buffer| buffer.starts_with(&probe));
    let probes = sim.commit_batch(B, probes).unwrap();
    let rest = sim.commit_batch(B, decrypted).unwrap();

    let ip_packets = |results: Vec<_>| results.into_iter().map(Result::unwrap).collect::<Vec<_>>();
    assert_eq!(ip_packets(probes), [Some(probe.clone()), Some(probe)]);
    assert_eq!(ip_packets(rest), [Some(data.clone()), Some(data)]);
    for datagram in &datagrams {
        assert!(matches!(
            sim.deliver(B, datagram).expect_err(),
            Error::DuplicateCounter
        ));
    }
}

#[test]
fn replayed_extracted_message_is_rejected_at_commit() {
    let mut sim = Sim::connected();
    let probe = ipv4_packet(b"probe");
    let data = ipv4_packet(b"data");
    let datagrams = [&probe, &data].map(|ip_packet| sim.encapsulate(A, ip_packet));

    let mut decrypted = sim.decrypt_batch(B, &datagrams);
    let probes = decrypted.extract_if(|buffer| buffer.starts_with(&probe));
    sim.deliver(B, &datagrams[0]).expect_one_ip();

    let [result] = sim.commit_batch(B, probes).unwrap().try_into().unwrap();
    assert!(matches!(result, Err(Error::DuplicateCounter)));
    let [result] = sim.commit_batch(B, decrypted).unwrap().try_into().unwrap();
    assert_eq!(result.unwrap(), Some(data));
}

#[test]
fn committed_batch_lists_its_accepted_data() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"accepted");
    let first = sim.encapsulate(A, &ip_packet);
    let mut tampered = sim.encapsulate(A, &ip_packet);
    *tampered.last_mut().unwrap() ^= 1;

    let decrypted = sim.decrypt_batch(B, &[first.clone(), first, tampered]);
    let now = sim.now;
    let mut committed = sim.tunn_mut(B).commit_decapsulate(decrypted, now).unwrap();

    assert_eq!(committed.data().count(), 1);
    committed.next();
    assert_eq!(committed.data().count(), 0);
}

#[test]
fn deferred_work_can_move_to_another_thread() {
    fn assert_send<T: Send>() {}

    assert_send::<PendingEncapsulate>();
    assert_send::<PendingDecapsulate>();
    assert_send::<DecryptedBatch<Vec<u8>>>();
    assert_send::<CommittedBatch<Vec<u8>>>();
}
