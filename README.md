# sanstun

A parallel-friendly sans-IO implementation of the WireGuard® protocol.

## History

Its roots are a fork of [BoringTun](https://github.com/cloudflare/boringtun) in [firezone/boringtun](https://github.com/firezone/boringtun).
For a long time, the fork retained 100% API-compatibility with upstream to make cherry-picking and usage by other projects easier.

The fork at [firezone/boringtun](https://github.com/firezone/boringtun) is now deprecated in favor of `sanstun`.

## Scope

The `sanstun` project combines our experience of operating WireGuard in production in a sans-IO setting.
It features a re-designed API and internals that are tuned for maximizing throughput whilst making it easy and safe to use.

- `#![no_std]`, requiring only `alloc` (so your binary must provide a global allocator) and atomic pointers
- Fully sans-IO, including time and RNG seeds
- No internal buffering
- No locks or atomic counters in the protocol state
- Multi-core friendly API: Encapsulating and decapsulating packets performs only the minimal book-keeping necessary.
  The actual crypto operations can be deferred to other threads and thus parallelized when processing packets in batches.

## Features

- `std` (default): encrypts data with [`ring`](https://crates.io/crates/ring), uses `HashMap` internally and provides `Instant::now()`.
- Without `std`, `sanstun` encrypts with the pure-Rust [`chacha20poly1305`](https://crates.io/crates/chacha20poly1305) crate and builds for bare-metal targets.
  Encrypting and decrypting data is slower than with `ring`: we measured 2–4× on x86_64, and about 108 cycles per byte (roughly 17 Mbit/s per core) on a 240 MHz ESP32.
  Everything else performs the same.
  The handshake rate limiter tracks at most 128 sources by default, about 12 KB in the worst case; see `Interface::with_rate_limit_sources`.
- `embassy-time`: converts between `sanstun::Instant` and `embassy_time::Instant`.

## Out-of-scope

Being a sans-IO library, `sanstun` does not perform any kind of IO for you, neither towards the user via a TUN device nor on the network to other peers via UDP.
It needs an event loop to do something useful.

The API design of `sanstun` makes it easy for you to use it correctly.
Nevertheless, there are some things it cannot do for you by virtue of being sans-IO.

### Cryptokey routing

A decrypted packet only proves which peer sent it.
It is your responsibility to verify that the packet came from an allowed IP.

Similarly, `Tunnel` allows you to encrypt packets towards any peer.
It is your responsibility to pick the correct `Tunnel` based on the destination IP.

### Inner IP packet validation

You must parse the decrypted buffer and verify that it contains a valid IP packet.
The buffer may still be padded.

### Randomness

It is your responsibility to supply a seed with enough entropy.
Being sans-IO means the library is fully deterministic including all cryptography operations.
Supplying identical seeds will produce **the same keys, nonces, cookies etc**.
This is great for testing but needs to be taken seriously for production usecases.

With great power comes great responsibility.

### Time

`sanstun` does not read a clock. Pass the elapsed time of your monotonic clock as a `sanstun::Instant`: `Instant::now()` with the `std` feature, a conversion from `embassy_time::Instant` with the `embassy-time` feature, or `Instant::from_duration_since_epoch` otherwise. The time passed in needs to be monotonically increasing, otherwise other peers might reject handshakes as replays.

## Security

For a WireGuard implementation to be secure, it is not enough to just use sound & audited cryptography primitives.
The API of `sanstun` is designed to guide you towards using it in a safe manner by enforcing many aspects through the type-system.
For example, it is not possible to directly create a `Tunnel`.
Instead, `Interface` serves as a factory for new tunnels and derives all key material from a seed.
It is also not possible to handle inbound traffic in `sanstun` without going through a rate limiter.
This ensures expensive crypto operations like DH cannot be triggered arbitrarily by remote peers.

While we have taken great care to design and implement `sanstun` as secure as possible, it has not received a formal security audit.
Use it at your own risk.

## License

The project is licensed under the [Apache License, Version 2.0](LICENSE).
sanstun started as a fork of [boringtun](https://github.com/cloudflare/boringtun); see [NOTICE.txt](NOTICE.txt) for its license.

<sub>WireGuard is a registered trademark of Jason A. Donenfeld. sanstun is not sponsored or endorsed by Jason A. Donenfeld.</sub>
