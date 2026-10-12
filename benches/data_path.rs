//! Measures each step of sending and receiving a data message on its own.
//!
//! `encapsulate`, `decapsulate` and `commit` need `&mut Tunnel` and thus run on the thread that
//! owns it, while `encrypt` and `decrypt` can be deferred to other threads. Their ratio bounds how
//! much handing the crypto to other threads can gain.

use std::cell::RefCell;
use std::hint::black_box;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use criterion::{BatchSize, Criterion};
use sanstun::{Event, Interface, Received, Tunnel, TunnelConfig};
use zeroize::Zeroizing;

const PACKET_SIZES: [usize; 2] = [64, 1280];

fn bench_data_path(c: &mut Criterion) {
    // A fixed `now` keeps the sessions usable and no timer ever becomes due.
    let now = Instant::now();
    let addr = "10.0.0.1:51820".parse().unwrap();

    for size in PACKET_SIZES {
        let mut group = c.benchmark_group(format!("data_path/{size}B"));
        let (mut sender, mut receiving_interface, receiver) = established_tunnels(addr, now);
        let receiver = RefCell::new(receiver);
        let payload = vec![0xab; size];
        let mut buf = vec![0; size + 64];

        group.bench_function("encapsulate", |b| {
            b.iter(|| black_box(sender.encapsulate_data(now).unwrap()))
        });

        group.bench_function("encrypt", |b| {
            b.iter_batched(
                || sender.encapsulate_data(now).unwrap(),
                |pending| black_box(pending.encrypt(&payload, &mut buf).unwrap().len()),
                BatchSize::SmallInput,
            )
        });

        // A message that is not committed can be decapsulated and decrypted again and again.
        let message = data_message(&mut sender, &payload, now);

        group.bench_function("decapsulate", |b| {
            b.iter(|| {
                black_box(decapsulate(
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
                    decapsulate(
                        &mut receiving_interface,
                        &mut receiver.borrow_mut(),
                        addr,
                        &message,
                        now,
                    )
                },
                |pending| {
                    let _ = black_box(pending.decrypt(&message, &mut buf));
                },
                BatchSize::SmallInput,
            )
        });

        // Committing marks the counter as received, so every iteration needs a fresh message.
        group.bench_function("commit", |b| {
            b.iter_batched(
                || {
                    let message = data_message(&mut sender, &payload, now);

                    decapsulate(
                        &mut receiving_interface,
                        &mut receiver.borrow_mut(),
                        addr,
                        &message,
                        now,
                    )
                    .decrypt(&message, vec![0; size + 64])
                },
                |decrypted| {
                    black_box(
                        receiver
                            .borrow_mut()
                            .commit_decrypted(decrypted, now)
                            .unwrap(),
                    )
                },
                BatchSize::SmallInput,
            )
        });

        group.finish();
    }
}

fn data_message(tunnel: &mut Tunnel, payload: &[u8], now: Instant) -> Vec<u8> {
    let mut message = vec![0; payload.len() + 64];
    let len = tunnel
        .encapsulate_data(now)
        .unwrap()
        .encrypt(payload, &mut message)
        .unwrap()
        .len();
    message.truncate(len);

    message
}

fn decapsulate(
    interface: &mut Interface,
    tunnel: &mut Tunnel,
    addr: SocketAddr,
    message: &[u8],
    now: Instant,
) -> sanstun::PendingDecapsulate {
    let Received::Message(message) = interface.receive(addr, message, now).unwrap() else {
        unreachable!()
    };

    tunnel.decapsulate(message, now).unwrap().unwrap()
}

/// Completes a handshake between two tunnels, returning the initiator and the responder together
/// with its [`Interface`].
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
    let Received::Message(message) = interface_b.receive(addr, &initiation, now).unwrap() else {
        unreachable!()
    };
    b.decapsulate(message, now).unwrap();

    let Some(Event::SendHandshakeResponse(response)) = b.poll_event() else {
        unreachable!()
    };
    let Received::Message(message) = interface_a.receive(addr, &response, now).unwrap() else {
        unreachable!()
    };
    a.decapsulate(message, now).unwrap();

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
