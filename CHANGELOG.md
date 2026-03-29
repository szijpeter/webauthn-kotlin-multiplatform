# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project follows coordinated pre-1.0 release-train versioning across published artifacts.

## Unreleased

### Added

- Composable extension hook architecture (`TargetedExtensionHook`, `CompositeExtensionHook`) for modular WebAuthn extension validation.
- Typed `WebAuthnExtension` sealed class hierarchy replacing string-based extension identifiers.

### Changed

- **BREAKING**: `PasskeyCapabilities` now exposes `supported: Set<PasskeyCapability>` with deterministic key-based lookup and duplicate-key rejection. Migration: replace legacy booleans with `capabilities.supports(PasskeyCapability.Extension(WebAuthnExtension.Prf))`, `capabilities.supports(PasskeyCapability.Extension(WebAuthnExtension.LargeBlob))`, and `capabilities.supports(PasskeyCapability.PlatformFeature("securityKey"))`.
- **BREAKING**: Removed `PrfEvaluationRequest` type (no longer needed with new capability model).
- `WebAuthnExtensionValidator` now delegates to `CompositeExtensionHook` for composable validation.

## 0.2.0 - 2026-03-26

### Added

- Published-consumer smoke preflight script (`tools/agent/check-published-consumer-smoke.sh`) and CI wiring after `publishToMavenLocal`.

### Changed

- iOS registration request policy now defaults `authenticatorAttachment = null` to platform registration only; security-key registration is now explicit `cross-platform` on supported runtimes.
- JSON response mapping now emits standards-shaped `type = "public-key"` and always includes `clientExtensionResults` (empty object when no outputs are present).
- Authentication options decoding now tolerates `allowCredentials: null` and normalizes to an empty list as an interop shim.
- Android platform error mapping now appends targeted RP ID troubleshooting hints for known `RP ID cannot be validated` failures.

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
