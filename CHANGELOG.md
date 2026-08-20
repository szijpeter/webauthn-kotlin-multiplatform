# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project follows coordinated pre-1.0 release-train versioning across published artifacts.

## Unreleased

### Changed

- **BREAKING**: client ceremonies now use raw platform responses and the generic `PasskeyFlow` with opaque backend state and application-defined finish output. Replace the removed controller/server-client APIs with `PasskeyFlow`, `RegistrationBackend`, and `AuthenticationBackend`.
- **BREAKING**: JSON and Ktor transport seams are implementation-neutral. Depend on `webauthn-json-api`/`webauthn-client-ktor` and provide a codec; add `webauthn-json-kotlinx` or `webauthn-client-ktor-kotlinx` only when choosing the Kotlinx defaults.
- **BREAKING**: `webauthn-client-android` and `webauthn-client-ios` are replaced by the source-set-first `webauthn-client-platform`; use `webauthn-client-defaults` for recommended platform construction.
- **BREAKING**: `webauthn-network-ktor-client` is replaced by `webauthn-client-ktor-kotlinx` for the default contract or `webauthn-client-ktor` plus an application codec for custom contracts.
- Server finish requests now derive signed client data from the raw credential response, preventing separately supplied challenge, origin, or type values from bypassing the trust boundary.

## 0.3.0 - 2026-03-31

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
- `app:compose-passkey` now generates its demo build config through `build-logic` so full configuration-cache-enabled repo checks stay green.
