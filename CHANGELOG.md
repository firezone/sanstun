# Changelog

This changelog follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Releases follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Breaking:** Data messages are encrypted, decrypted and committed in batches, which sets up the session and AEAD key once per batch instead of once per message. [#129](https://github.com/firezone/sanstun/pull/129)
- **Breaking:** A tunnel rejects handshake initiations received before it was created with the new `Error::InitiationPredatesTunnel`, because the replay check could not run for them. [#152](https://github.com/firezone/sanstun/pull/152)
- The minimum supported Rust version is now 1.91.

### Added

- `Tunnel::rekey_attempt_time` returns the configured `REKEY_ATTEMPT_TIME`. [#144](https://github.com/firezone/sanstun/pull/144)
- `Interface::with_rate_limit_sources` sets how many sources the handshake rate limiter tracks under load.
  The default stays at 65,536. [#167](https://github.com/firezone/sanstun/pull/167)
- The `rust-crypto` feature encrypts data with the pure-Rust `chacha20poly1305` crate instead of `ring`, so depending on sanstun doesn't need a C compiler.
  `ring` stays the default and is used if both are enabled. [#172](https://github.com/firezone/sanstun/pull/172)

### Fixed

- Fixes repeated handshakes and tunnel expiry when the round-trip time exceeds `REKEY_TIMEOUT`. [#142](https://github.com/firezone/sanstun/pull/142)

## [0.1.0] - 2026-10-30

Initial release.

[Unreleased]: https://github.com/firezone/sanstun/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/firezone/sanstun/releases/tag/v0.1.0
