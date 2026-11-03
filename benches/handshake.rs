//! Measures the handshake handlers.
//!
//! These run on the thread that owns the tunnel, so their cost bounds how many handshakes a single
//! tunnel can handle.

use std::hint::black_box;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

use criterion::{BatchSize, Criterion};
use sanstun::{
    HandshakeInitiation, HandshakeResponse, Interface, Received, ReceivedMessage, Tunnel,
    TunnelConfig,
};
use zeroize::Zeroizing;

const ADDR: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 51820));
/// Responders reject initiations whose timestamp does not increase, so each one is sent later.
const STEP: Duration = Duration::from_nanos(1);

fn bench_handshake(c: &mut Criterion) {
    let mut now = Instant::now();
    let mut group = c.benchmark_group("handshake");

    let mut interface_a = interface(now);
    let mut interface_b = interface(now);
    let a_public = interface_a.static_public();
    let b_public = interface_b.static_public();
    let mut a = interface_a
        .new_tunnel(b_public, TunnelConfig::default(), now)
        .unwrap();
    let mut b = interface_b
        .new_tunnel(a_public, TunnelConfig::default(), now)
        .unwrap();

    group.bench_function("initiate_handshake", |bencher| {
        bencher.iter_batched_ref(
            || {
                interface_a
                    .new_tunnel(b_public, TunnelConfig::default(), now)
                    .unwrap()
            },
            |initiator| black_box(initiator.initiate_handshake(now).unwrap()),
            BatchSize::LargeInput,
        )
    });

    group.bench_function("handle_handshake_initiation", |bencher| {
        bencher.iter_batched(
            || {
                now += STEP;
                let initiation = a.restart_handshake(now).unwrap();

                (receive_initiation(&mut interface_b, &initiation, now), now)
            },
            |(initiation, now)| black_box(b.handle_handshake_initiation(initiation, now).unwrap()),
            BatchSize::SmallInput,
        )
    });

    // Each response only completes the handshake it answers, so every one gets a new initiator.
    group.bench_function("handle_handshake_response", |bencher| {
        bencher.iter_batched(
            || {
                now += STEP;
                let mut initiator = interface_a
                    .new_tunnel(b_public, TunnelConfig::default(), now)
                    .unwrap();
                let response = handshake(
                    &mut interface_a,
                    &mut initiator,
                    &mut interface_b,
                    &mut b,
                    now,
                );

                (initiator, response, now)
            },
            |(mut initiator, response, now)| {
                let keepalive = initiator.handle_handshake_response(response, now).unwrap();

                (initiator, black_box(keepalive))
            },
            BatchSize::LargeInput,
        )
    });

    let mut loaded = interface(now).with_handshake_limit(0);
    let loaded_public = loaded.static_public();

    group.bench_function("handle_cookie_reply", |bencher| {
        bencher.iter_batched(
            || {
                let mut initiator = interface_a
                    .new_tunnel(loaded_public, TunnelConfig::default(), now)
                    .unwrap();
                let initiation = initiator.initiate_handshake(now).unwrap();
                let Received::SendCookieReply(reply) =
                    loaded.receive(ADDR, &initiation, now).unwrap()
                else {
                    unreachable!("the responder is under load")
                };
                let Received::Message(ReceivedMessage::CookieReply(reply)) =
                    interface_a.receive(ADDR, &reply, now).unwrap()
                else {
                    unreachable!()
                };

                (initiator, reply)
            },
            |(mut initiator, reply)| {
                initiator.handle_cookie_reply(reply, now).unwrap();

                initiator
            },
            BatchSize::LargeInput,
        )
    });

    group.finish();
}

/// Creates an interface that never requires cookies.
fn interface(now: Instant) -> Interface {
    Interface::new(
        Zeroizing::new(rand::random()),
        now,
        Duration::from_secs(1_700_000_000),
    )
    .with_handshake_limit(u64::MAX)
}

/// Sends a new initiation from `a` to `b` and returns `b`'s response, received by `a`'s interface.
fn handshake(
    interface_a: &mut Interface,
    a: &mut Tunnel,
    interface_b: &mut Interface,
    b: &mut Tunnel,
    now: Instant,
) -> HandshakeResponse {
    let initiation = receive_initiation(interface_b, &a.initiate_handshake(now).unwrap(), now);
    let response = b.handle_handshake_initiation(initiation, now).unwrap();

    let Received::Message(ReceivedMessage::HandshakeResponse(response)) =
        interface_a.receive(ADDR, &response, now).unwrap()
    else {
        unreachable!()
    };

    response
}

fn receive_initiation(
    interface: &mut Interface,
    initiation: &[u8],
    now: Instant,
) -> HandshakeInitiation {
    let Received::Message(ReceivedMessage::HandshakeInitiation(initiation)) =
        interface.receive(ADDR, initiation, now).unwrap()
    else {
        unreachable!()
    };

    initiation
}

criterion::criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3));
    targets = bench_handshake
}
criterion::criterion_main!(benches);
