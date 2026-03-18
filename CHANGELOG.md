# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project follows coordinated pre-1.0 release-train versioning across published artifacts.

## Unreleased

### Changed

- Breaking API change in `webauthn-model`: selected public string fields now use `NotBlankString` (`PublicKeyCredentialRpEntity.name`, `PublicKeyCredentialUserEntity.name`, `PublicKeyCredentialUserEntity.displayName`) and `PublicKeyCredentialCreationOptions.pubKeyCredParams` now uses `NotEmptyList`.
- Added explicit conversion helpers in `webauthn-model` (`toNotBlankStringOrThrow`, `toNotEmptyListOrThrow`) and migrated call sites across client/server/sample modules.
- `webauthn-network-ktor-client` transport internals now use `sandwich-ktor` `ApiResponse` flows while preserving existing external behavior, finish-result mapping, rejection semantics, and payload redaction behavior.
- Dependency catalog now includes `com.github.skydoves:sandwich`/`sandwich-ktor` and `org.kotools:types`.
- BCV baselines were intentionally updated via `apiDump` for the public API changes and validated with `apiCheck`.

### Migration Notes

- Recompile consumers and update model construction call sites that previously passed raw `String` and potentially empty credential-parameter lists.
- Use validated conversions when constructing public models from untrusted input (`toNotBlankStringOrThrow`, `toNotEmptyListOrThrow`) or construct `NotBlankString`/`NotEmptyList` directly.

## 0.1.0 - 2026-03-12

### Added

- Maven Central publishing workflow and coordinated release metadata.
- Binary compatibility baselines for supported published modules.
- Public-module READMEs, root adoption guide, and maintainer publishing docs.
- PR-centric release-mode steering and CI preflight lanes.
- First public release is live on Maven Central under `io.github.szijpeter`.

### Changed

- Local `pre-push` verification is now advisory; PR CI is the blocking authority.
- Public launch and security docs now reflect Renovate rather than Dependabot as the dependency automation source.
- `samples:compose-passkey` now generates its demo build config through `build-logic` so full configuration-cache-enabled repo checks stay green.
