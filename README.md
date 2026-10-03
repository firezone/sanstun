# sanstun

This is a sans-IO, performance-orientation user-space implementation of the WireGuard protocol.

Its roots are a fork of [BoringTun](https://github.com/cloudflare/boringtun) in [firezone/boringtun](https://github.com/firezone/boringtun).
For a long time, the fork retained 100% API-compatibility with upstream to make cherry-picking and usage by other projects easier.

The fork at [firezone/boringtun](https://github.com/firezone/boringtun) is now deprecated in favor of `sanstun`.

The `sanstun` project combines our experience of operating WireGuard in production in a sans-IO setting.
It features a re-design API and internals that are tuned for maximising throughput.

- Fully sans-IO, including time and RNG seeds
- No internal buffering
- No internal locks or atomics
- Multi-core friendly API: Encapsulating and decapsulating packets performs only the minimal book-keeping necessary.
  The actual crypto operations can be deferred to other threads and thus parallelized when processing packets in batches.

## License

The project is licensed under the [3-Clause BSD License](LICENSE.md).

<sub>WireGuard is a registered trademark of Jason A. Donenfeld. sanstun is not sponsored or endorsed by Jason A. Donenfeld.</sub>
