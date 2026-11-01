# Changelog

This changelog follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Releases follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `Tunnel::rekey_attempt_time` returns the configured `REKEY_ATTEMPT_TIME`.

### Fixed

- The initiator no longer sends handshake initiations after its handshake has completed. A response to either in-flight initiation now ends the handshake, and cancels a retry that is waiting for its jitter.

## [0.1.0] - 2026-10-30

Initial release.

[Unreleased]: https://github.com/firezone/sanstun/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/firezone/sanstun/releases/tag/v0.1.0
