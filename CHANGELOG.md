# Changelog

This changelog follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Releases follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Breaking:** The crate is now `#![no_std]`; without the default `std` feature it only needs `alloc`. Time is passed as `sanstun::Instant` instead of `std::time::Instant`: use `Instant::now()` with the default `std` feature, convert from `embassy_time::Instant` with the `embassy-time` feature, or construct it from a monotonic `Duration` since a caller-chosen epoch (#160).
- Without the default `std` feature, sanstun uses the pure-Rust `chacha20poly1305` crate instead of `ring`, so it builds for bare-metal targets (#160).
- **Breaking:** Data messages are encrypted, decrypted and committed in batches, which sets up the session and AEAD key once per batch instead of once per message (#129).
- **Breaking:** A tunnel rejects handshake initiations received before it was created with the new `Error::InitiationPredatesTunnel`, because the replay check could not run for them (#152).

### Added

- `Tunnel::rekey_attempt_time` returns the configured `REKEY_ATTEMPT_TIME`.
- `Interface::with_rate_limit_sources` sets how many sources the handshake rate limiter tracks under load. It defaults to 65,536 with `std` and 128 without, which bounds the worst case to about 12 KB on a microcontroller instead of letting an attacker with many addresses exhaust the heap (#160).

### Fixed

- Fixes repeated handshakes and tunnel expiry when the round-trip time exceeds `REKEY_TIMEOUT` (#142).

## [0.1.0] - 2026-10-30

Initial release.

[Unreleased]: https://github.com/firezone/sanstun/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/firezone/sanstun/releases/tag/v0.1.0
