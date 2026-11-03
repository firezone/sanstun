# Changelog

This changelog follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Releases follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Breaking:** Data messages are encrypted and decrypted in batches (#129). `Tunnel::begin_encapsulate` returns an `EncapsulateBatch` that reserves consecutive counters for a whole batch, and `Tunnel::begin_decapsulate` returns a `DecapsulateBatch` that collects the data messages of one session, e.g. the segments of a GRO datagram. `PendingEncapsulate::encrypt` and `PendingDecapsulate::decrypt` take all messages of a batch, and `Tunnel::commit_decapsulate` commits a `DecryptedBatch` at once and returns a `CommittedBatch`. The session key is copied and the AEAD key built once per batch instead of once per message.

### Added

- `Tunnel::rekey_attempt_time` returns the configured `REKEY_ATTEMPT_TIME`.

### Fixed

- Fixes repeated handshakes and tunnel expiry when the round-trip time exceeds `REKEY_TIMEOUT` (#142).

## [0.1.0] - 2026-10-30

Initial release.

[Unreleased]: https://github.com/firezone/sanstun/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/firezone/sanstun/releases/tag/v0.1.0
