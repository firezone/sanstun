//! Measures the cost of each step in sending and receiving a data message.
//!
//! `begin_encapsulate`, `begin_decapsulate` and `commit_decapsulate` run on the thread that owns
//! the tunnel. Comparing their cost with `encrypt` and `decrypt` shows how much work can move
//! to other threads.

use std::cell::RefCell;
use std::hint::black_box;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use criterion::{BatchSize, Criterion};
use sanstun::{Interface, Received, ReceivedMessage, Tunnel, TunnelConfig};
use zeroize::Zeroizing;

const PACKET_SIZES: [usize; 2] = [64, 1280];

fn bench_data_path(c: &mut Criterion) {
    // Freeze time so the sessions stay usable throughout the benchmark.
    let now = Instant::now();
    let addr = "10.0.0.1:51820".parse().unwrap();

    for size in PACKET_SIZES {
        let mut group = c.benchmark_group(format!("data_path/{size}B"));
        let (mut sender, mut receiving_interface, receiver) = established_tunnels(addr, now);
        let receiver = RefCell::new(receiver);
        let payload = vec![0xab; size];
        let mut buf = vec![0; size + 64];

        group.bench_function("begin_encapsulate", |b| {
            b.iter(|| black_box(begin_encapsulate(&mut sender, now)))
        });

        group.bench_function("encrypt", |b| {
            b.iter_batched(
                || begin_encapsulate(&mut sender, now),
                |pending| black_box(encrypt(pending, &payload, &mut buf)),
                BatchSize::SmallInput,
            )
        });

        // The same message can be reused until its decryption is committed.
        let message = data_message(&mut sender, &payload, now);

        group.bench_function("receive", |b| {
            b.iter(|| black_box(receiving_interface.receive(addr, &message, now).unwrap()))
        });

        group.bench_function("begin_decapsulate", |b| {
            b.iter(|| {
                black_box(begin_decapsulate(
                    &mut receiving_interface,
                    &mut receiver.borrow_mut(),
                    addr,
                    &message,
                    now,
                ))
            })
        });

        group.bench_function("decrypt", |b| {
            b.iter_batched(
                || {
                    begin_decapsulate(
                        &mut receiving_interface,
                        &mut receiver.borrow_mut(),
                        addr,
                        &message,
                        now,
                    )
                },
                |pending| {
                    let _ = black_box(pending.decrypt([(message.as_slice(), &mut buf)]));
                },
                BatchSize::SmallInput,
            )
        });

        // Committing marks the counter as received, so every iteration needs a fresh message.
        group.bench_function("commit_decapsulate", |b| {
            b.iter_batched(
                || {
                    let message = data_message(&mut sender, &payload, now);

                    begin_decapsulate(
                        &mut receiving_interface,
                        &mut receiver.borrow_mut(),
                        addr,
                        &message,
                        now,
                    )
                    .decrypt([(message.as_slice(), vec![0; size + 64])])
                    .next()
                    .unwrap()
                },
                |decrypted| {
                    black_box(
                        receiver
                            .borrow_mut()
                            .commit_decapsulate(decrypted, now)
                            .unwrap(),
                    )
                },
                BatchSize::SmallInput,
            )
        });

        group.bench_function("poll_event", |b| {
            b.iter(|| black_box(receiver.borrow_mut().poll_event()))
        });

        group.finish();
    }
}

fn data_message(tunnel: &mut Tunnel, payload: &[u8], now: Instant) -> Vec<u8> {
    let mut message = vec![0; payload.len() + 64];
    let len = encrypt(begin_encapsulate(tunnel, now), payload, &mut message);
    message.truncate(len);

    message
}

fn begin_encapsulate(tunnel: &mut Tunnel, now: Instant) -> sanstun::PendingEncapsulate {
    tunnel
        .begin_encapsulate(now)
        .unwrap()
        .finish(NonZeroUsize::MIN)
        .unwrap()
}

/// Encrypts `payload` into `buf` and returns the message length.
fn encrypt(pending: sanstun::PendingEncapsulate, payload: &[u8], buf: &mut [u8]) -> usize {
    pending
        .encrypt([(payload, buf)])
        .next()
        .unwrap()
        .unwrap()
        .len()
}

fn begin_decapsulate(
    interface: &mut Interface,
    tunnel: &mut Tunnel,
    addr: SocketAddr,
    message: &[u8],
    now: Instant,
) -> sanstun::PendingDecapsulate {
    let Received::Message(ReceivedMessage::TransportData(message)) =
        interface.receive(addr, message, now).unwrap()
    else {
        unreachable!()
    };

    tunnel.begin_decapsulate(message, now).unwrap().finish()
}

/// Establishes two tunnels and returns the initiator, the responder's interface and the responder.
fn established_tunnels(addr: SocketAddr, now: Instant) -> (Tunnel, Interface, Tunnel) {
    let unix = Duration::from_secs(1_700_000_000);
    let mut interface_a = Interface::new(Zeroizing::new(rand::random()), now, unix);
    let mut interface_b = Interface::new(Zeroizing::new(rand::random()), now, unix);
    let mut a = interface_a
        .new_tunnel(interface_b.static_public(), TunnelConfig::default(), now)
        .unwrap();
    let mut b = interface_b
        .new_tunnel(interface_a.static_public(), TunnelConfig::default(), now)
        .unwrap();

    let initiation = a.initiate_handshake(now).unwrap();
    let Received::Message(ReceivedMessage::HandshakeInitiation(initiation)) =
        interface_b.receive(addr, &initiation, now).unwrap()
    else {
        unreachable!()
    };
    let response = b.handle_handshake_initiation(initiation, now).unwrap();

    let Received::Message(ReceivedMessage::HandshakeResponse(response)) =
        interface_a.receive(addr, &response, now).unwrap()
    else {
        unreachable!()
    };
    a.handle_handshake_response(response, now).unwrap();

    (a, interface_b, b)
}

criterion::criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3));
    targets = bench_data_path
}
criterion::criterion_main!(benches);
