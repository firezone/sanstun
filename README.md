# sanstun

This is a sans-IO, performance-orientation user-space implementation of the WireGuard protocol.

Its roots are a fork of [BoringTun](https://github.com/cloudflare/boringtun) in [firezone/boringtun](https://github.com/firezone/boringtun).
For a long time, the fork retained 100% API-compatibility with upstream to make cherry-picking and usage by other projects easier.

The fork at [firezone/boringtun](https://github.com/firezone/boringtun) is now deprecated in favor of `sanstun`.

The `sanstun` project combines our experience of operating WireGuard in production in a sans-IO setting.
It features a re-designed API and internals that are tuned for maximising throughput whilst making it easy and safe to use.

- Fully sans-IO, including time and RNG seeds
- No internal buffering
- No internal locks or atomics
- Multi-core friendly API: Encapsulating and decapsulating packets performs only the minimal book-keeping necessary.
  The actual crypto operations can be deferred to other threads and thus parallelized when processing packets in batches.

## Security

For a WireGuard implementation to be secure, it is not enough to just use sound & audited cryptography primitives.
The API of `sanstun` is designed to guide you towards using it in a safe manner by enforcing many aspects through the type-system.
For example, it is not possible to directly create a `Tunnel`.
Instead, `Interface` serves as a factory for new tunnels and derives all key material from a `CryptoRng`.
It is also not possible to handle inbound traffic in `sanstun` without going through a rate limiter.
This ensures expensive crypto operations like DH cannot be triggered arbitrarily by remote peers.

While we have taken great care to design and implement `sanstun` as secure as possible, it has not received a formal security audit.
Use it at your own risk.

## License

The project is licensed under the [3-Clause BSD License](LICENSE.md).

<sub>WireGuard is a registered trademark of Jason A. Donenfeld. sanstun is not sponsored or endorsed by Jason A. Donenfeld.</sub>
