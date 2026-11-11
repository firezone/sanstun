# Changelog

This changelog follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Releases follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Breaking:** Data messages are encrypted, decrypted and committed in batches, which sets up the session and AEAD key once per batch instead of once per message (#129).

### Added

- `Tunnel::rekey_attempt_time` returns the configured `REKEY_ATTEMPT_TIME`.

### Fixed

- Fixes repeated handshakes and tunnel expiry when the round-trip time exceeds `REKEY_TIMEOUT` (#142).
- Cookie replies draw their nonce in one call to the RNG instead of one call per byte, which makes them cheaper to send under load.

## [0.1.0] - 2026-10-30

Initial release.

[Unreleased]: https://github.com/firezone/sanstun/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/firezone/sanstun/releases/tag/v0.1.0
