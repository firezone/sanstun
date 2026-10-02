# sanstun

This is a sans-IO, performance-orientation user-space implementation of the WireGuard protocol.

## Features

- Fully sans-IO, including time and RNG seeds
- No internal buffering
- Multi-core friendly API: Encapsulating and decapsulating packets performs only the minimal book-keeping necessary.
  The actual crypto operations can be deferred to different thread and parallelized when processing packets in batches.

## History

It started out as a fork of [BoringTun](https://github.com/cloudflare/boringtun) in https://github.com/firezone/boringtun.
The fork carries many optimizations and fixes and is 100% API-compatible with upstream.
It is also deprecated in favor of `sanstun` and will not receive further updates.

## License

The project is licensed under the [3-Clause BSD License](LICENSE.md).

<sub>WireGuard is a registered trademark of Jason A. Donenfeld. sanstun is not sponsored or endorsed by Jason A. Donenfeld.</sub>
