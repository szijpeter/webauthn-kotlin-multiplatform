# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project follows coordinated pre-1.0 release-train versioning across published artifacts.

## Unreleased

### Added

- Maven Central publishing workflow and coordinated release metadata.
- Binary compatibility baselines for supported published modules.
- Public-module READMEs, root adoption guide, and maintainer publishing docs.
- PR-centric release-mode steering and CI preflight lanes.

### Changed

- Local `pre-push` verification is now advisory; PR CI is the blocking authority.
- Public launch and security docs now reflect Renovate rather than Dependabot as the dependency automation source.
- `samples:compose-passkey` now generates its demo build config through `build-logic` so full configuration-cache-enabled repo checks stay green.

## 0.1.0

- Pending first public release.
