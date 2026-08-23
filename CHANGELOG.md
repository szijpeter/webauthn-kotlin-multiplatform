# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project follows coordinated pre-1.0 release-train versioning across published artifacts.

## Unreleased

## 0.4.0 - 2026-08-23

### Added

- Codec-neutral `webauthn-json-api` and binary `webauthn-protocol` artifacts, plus byte-preserving `RawRegistrationResponse` and `RawAuthenticationResponse` models for untrusted platform/transport data.
- Generic `PasskeyFlow` orchestration with typed registration/authentication backends, opaque continuation state, application-defined finish output, explicit concurrent-use failure, and application-owned presentation state.
- Replaceable client composition artifacts: `webauthn-client-ktor`, opt-in `webauthn-client-ktor-kotlinx`, `webauthn-client-defaults`, and the source-set-first `webauthn-client-platform` bridge for Android and iOS.
- Username-optional authentication start for discoverable-credential sign-in.
- Compiled documentation examples, dependency-purity consumer checks, WebAuthn compliance cross-checks, an experimental desktop passkey CLI, and configurable PR change-profile automation.

### Changed

- **BREAKING**: `PasskeyClient` now returns raw platform responses, and ceremonies use `PasskeyFlow`, `RegistrationBackend`, and `AuthenticationBackend`. Replace the removed controller/server-client APIs and keep UI state in the application. See the [client-first migration map](https://github.com/szijpeter/webauthn-kotlin-multiplatform/blob/v0.4.0/docs/CLIENT_FIRST_EXECUTION.md).
- **BREAKING**: `RegistrationFinishRequest` and `AuthenticationFinishRequest` now accept only the raw credential response. Custom server adapters must supply a neutral collected-client-data decoder; callers can no longer provide separate challenge, origin, or ceremony-type claims.
- **BREAKING**: JSON and Ktor seams are implementation-neutral. Supply a `WebAuthnJsonCodec` and, for custom HTTP contracts, a `KtorPasskeyContractCodec`; add the Kotlinx artifacts only when selecting the repository defaults.
- **BREAKING**: capability reporting is now tri-state: `PasskeyCapabilities.support` maps typed `PasskeyCapability` values to `CapabilitySupport`. Replace `supported`, `platformVersionHints`, `supports(String)`, and `PlatformFeature` with `supportOf`/`supports` and `PasskeyCapability.Platform(PlatformCapability)`.
- **BREAKING**: `PasskeyClientError.Platform` no longer retains a `Throwable`, and the low-level `Transport` error is removed; backend and HTTP failures belong to the flow/contract layers.
- **BREAKING**: `webauthn-serialization-kotlinx` is replaced by `webauthn-json-kotlinx`; `webauthn-client-android` and `webauthn-client-ios` are replaced by `webauthn-client-platform`; and `webauthn-network-ktor-client` is replaced by `webauthn-client-ktor-kotlinx` or `webauthn-client-ktor` with an application codec.
- **BREAKING**: `iosX64` artifacts are no longer published because upstream cryptography dependencies removed Apple X64 support. Supported Apple targets are `iosArm64` and `iosSimulatorArm64`.
- Project modules now use `core/`, `client/`, `server/`, and `sample/` source-set-oriented directories without changing retained Maven coordinates.
- Security-critical validation, parsing, conversion, cryptography, and trust APIs are marked for Kotlin's unused-return-value checker; repository builds treat ignored marked results as errors.
- The build baseline now uses Kotlin 2.4.10, Gradle 9.7, Android Gradle Plugin 9.3.1/compile SDK 37, Ktor 3.5.2, Signum 0.16.0, and Signum Indispensable 3.26.0.

### Fixed

- Platform prompt ownership and Android rotation handling now keep activity-bound UI context explicit and avoid retaining stale hosts.
- Flow failures no longer misclassify application callbacks or unexpected platform exceptions as backend failures; backend and callback exceptions follow the application's own policy.
- Codec-neutral Ktor backends preserve caller-defined continuation state from start through finish instead of assuming server-side `Unit` state.
- Public protocol return values retain immutable byte-value types rather than exposing mutable `ByteArray` results.

### Removed

- Legacy `PasskeyController`, `PasskeyServerClient`, `PasskeyFinishResult`, controller-owned Compose state, and the old Ktor server client.
- Published artifacts `webauthn-client-android`, `webauthn-client-ios`, `webauthn-network-ktor-client`, and `webauthn-serialization-kotlinx`. Use the replacements listed above.

### Security

- Server finish processing now derives challenge, origin, and ceremony type exclusively from the exact raw `clientDataJSON` bytes in the credential response. Authentication verifies `authenticatorData || SHA-256(clientDataJSON)` against the assertion signature, and signed registration attestation formats hash those same bytes during verification; `none` attestation remains unsigned. Regression coverage rejects mismatched claims and replaying an old response against a fresh ceremony.

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
