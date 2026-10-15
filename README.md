# sanstun

`sanstun` is a fast, sans-IO implementation of the WireGuard protocol that runs in user space.

## Design

`sanstun` draws on our experience running WireGuard in production.
Its API is designed for high throughput and safe integration into your own event loop.

- You supply time and randomness, so execution is deterministic.
- You own the packet buffers.
- The protocol state uses no locks or atomic packet counters.
- Packet processing separates bookkeeping from encryption and decryption, so you can run the cryptography on other threads or process batches in parallel.

## Caller responsibilities

Your application handles TUN and UDP I/O and drives the library's timers through an event loop.
It also needs to handle the following checks and inputs.

### Cryptokey routing

A decrypted packet proves which peer sent it, but you must check that its source IP is allowed for that peer.

For outgoing packets, choose the correct [`Tunnel`](src/tunnel.rs) based on the destination IP.

### Handshake routing

Route handshake initiations by the initiator's static public key, available through [`HandshakeInitiation::peer_static_public`](src/message.rs).
[`Interface::receive`](src/interface.rs) authenticates this key and rejects replays from peers you have created a tunnel for.
Anyone can generate a key pair, so an authenticated handshake is not a reason to trust an unknown peer.
Create tunnels only for peers you already trust.

### Packet validation

Parse the decrypted buffer, check that it contains a valid IP packet, and remove any padding before forwarding it.

### Randomness

Supply a fresh seed from the operating system for each [`Interface`](src/interface.rs).
Reusing a seed repeats keys, nonces, and cookies, which is unsafe in production.
Fixed seeds are useful for reproducible tests.

### Time

Use a monotonic clock for `now`.
The Unix time supplied when creating an interface must not go backwards across restarts, or peers may reject handshake initiations as replays.

## Security

`sanstun` uses its type system to enforce parts of the protocol's security requirements.
You create tunnels through [`Interface`](src/interface.rs), which derives their key material from its seed.
All inbound datagrams pass through this interface, which checks handshake MACs and applies cookie challenges and rate limits before expensive cryptography.

`sanstun` has not received a formal security audit.
Use it at your own risk.
See the [security policy](SECURITY.md) to report a vulnerability.

## History

`sanstun` grew out of [Firezone's fork](https://github.com/firezone/boringtun) of [BoringTun](https://github.com/cloudflare/boringtun).
The fork kept its API compatible with upstream to make it easier to share patches and use it in other projects.
It is now deprecated in favor of `sanstun`.

## License

The project is licensed under the [3-Clause BSD License](LICENSE.md).

<sub>WireGuard is a registered trademark of Jason A. Donenfeld. sanstun is not sponsored or endorsed by Jason A. Donenfeld.</sub>
