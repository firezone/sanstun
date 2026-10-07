# sanstun

This is a sans-IO, performance-oriented user-space implementation of the WireGuard protocol.

## History

Its roots are a fork of [BoringTun](https://github.com/cloudflare/boringtun) in [firezone/boringtun](https://github.com/firezone/boringtun).
For a long time, the fork retained 100% API-compatibility with upstream to make cherry-picking and usage by other projects easier.

The fork at [firezone/boringtun](https://github.com/firezone/boringtun) is now deprecated in favor of `sanstun`.

## Scope

The `sanstun` project combines our experience of operating WireGuard in production in a sans-IO setting.
It features a re-designed API and internals that are tuned for maximizing throughput whilst making it easy and safe to use.

- Fully sans-IO, including time and RNG seeds
- No internal buffering
- No locks or atomic counters in the protocol state
- Multi-core friendly API: Encapsulating and decapsulating packets performs only the minimal book-keeping necessary.
  The actual crypto operations can be deferred to other threads and thus parallelized when processing packets in batches.

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

### Handshake routing

A handshake initiation is routed by the static public key the initiator claims, via `HandshakeInit::peer_static_public`.
Anyone can claim any key, so the claim is only proven once `Tunnel::decapsulate` accepts the initiation.
Do not trust it, log it as the sender or create a `Tunnel` for an unknown key based on it.

### Inner IP packet validation

You must parse the decrypted buffer and verify that it contains a valid IP packet.
The buffer may still be padded.

### Randomness

It is your responsibility to supply a randomness source with enough entropy.
Being sans-IO means the library is fully deterministic including all cryptography operations.
Supplying identically seeded randomness sources will produce **the same keys, nonces, cookies etc**.
This is great for testing but needs to be taken seriously for production usecases.

With great power comes great responsibility.

### Time

The time passed in needs to be monotonically increasing, otherwise other peers might reject handshakes as replays.

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
