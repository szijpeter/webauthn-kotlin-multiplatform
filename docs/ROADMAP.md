# Roadmap

This roadmap tracks what to do next to reach a state-of-the-art WebAuthn Kotlin Multiplatform library.

Last updated: 2026-04-17

## North-Star Exit Criteria

1. Strong conformance coverage for core WebAuthn L3 semantics and major attestation paths.
2. Hardened server and client flows with predictable failure behavior and test depth.
3. Stable, documented module contracts for KMP consumers across JVM/Android/iOS.
4. High-signal CI and agent harness with low interruption and low waste.

## Immediate Execution Strategy (Client First)

1. Keep client implementation velocity independent from first-party backend hardening.
2. Use explicit backend contracts and the in-repo sample backend for client validation.
3. Keep shared client business logic in `webauthn-client-core`; platform wrappers stay thin.
4. Drive all client API and behavior decisions from WebAuthn spec requirements first.

## Phase Status Snapshot (2026-04-17)

1. Phase 1: Completed baseline; maintenance-only follow-up.
2. Phase 2: Active hardening.
3. Phase 3: Active hardening.
4. Phase 4: Active documentation and API stability hardening.
5. Phase 5: Completed for `v0.1.0`; release discipline remains ongoing.
6. Phase 6: Active roadmap stream.

## Phase 1: Client Readiness and Interoperability (Completed Baseline; Maintenance)

1. Keep shared typed ceremony orchestration in `webauthn-client-core` and maintain optional JSON APIs in `webauthn-client-json-core`.
2. Keep Android Credential Manager and iOS AuthenticationServices adapters as thin platform bridges.
3. Maintain interop paths for host-provided backend contracts and the local sample backend app (`samples/backend-ktor`).
4. Verify extension transport and response mapping for PRF and Large Blob semantics.
5. Align client API ergonomics against trusted ecosystem SDKs while preserving standards-first behavior.

Definition of done:

- Android/iOS clients are runnable end-to-end against at least one non-repo backend and one local dev backend.

## Phase 2: Conformance and Security Hardening (Active)

1. Attestation format matrix hardening (`packed`, `tpm` (done), `android-key` (done), `android-safetynet`, `apple`, `none`).
2. CBOR/COSE vector-based parser/validator expansion.
3. UV-required and BE/BS branching policy behavior coverage.
4. Core negative-path expansion tied to spec map rows.

Definition of done:

- Each new rule is reflected in tests and `spec-notes/webauthn-l3-validation-map.md`.

## Phase 3: Server Robustness and Store Semantics (Active)

1. Strengthen registration/authentication finish-path invariants.
2. Add replay, race, and persistence-oriented scenarios (in-memory and H2-backed store contracts done).
3. Expand server-ktor integration coverage.
4. JetBrains Exposed store module (`webauthn-server-store-exposed`) with `ExposedChallengeStore`, `ExposedCredentialStore`, `ExposedUserAccountStore` (done).
5. Strict UV policy coverage: `ChallengeSession` persists `userVerification`, `Services.kt` maps to `UserVerificationPolicy` for core validator (done).

Definition of done:

- JVM server behavior is deterministic under failure/race scenarios with test proof.

## Phase 4: Developer Experience and API Stability (Active)

1. API surface review and compatibility expectations by module maturity.
2. Documentation quality pass for integration guidance.
3. Sample app hardening for reference-quality usage.

Definition of done:

- External consumers can adopt core/server/client modules with low ambiguity.

## Phase 5: Release Readiness (Completed for `v0.1.0`; Ongoing Discipline)

1. Release checklist formalization and CI parity confirmation.
2. Stabilization pass on performance, logging, and diagnostics.
3. Versioning/release notes discipline with migration notes.
4. Maven Central publication path, BOM guidance, and public-module documentation.

Definition of done:

- Release candidate branch passes strict gate and CI with no unresolved critical gaps.

## Phase 6: Discoverable Credentials and Account Lifecycle (Active)

1. Promote discoverable-credential support (username-less first-factor paths) to a first-class server/client roadmap stream.
2. Expand account lifecycle support beyond ceremony happy paths to include credential/account delete and recovery-oriented integration points.
3. Keep this phase additive and BC-safe for published modules, with explicit compatibility checks when API changes are introduced.
4. Keep sample apps aligned with production guidance for passkey lifecycle UX (including last-passkey safety messaging and backup-path clarity).

Definition of done:

- Discoverable authentication and account lifecycle flows have documented contracts, deterministic tests, and sample-backed reference usage.

## Extension Coverage Strategy (Standards-First)

1. Do not treat "support all extensions" as a blanket parity promise.
2. Implement extension behavior in ordered slices, starting from standards-stable and cross-platform-feasible candidates.
3. For each extension candidate, require all gates before behavior-level support:
   - Standards maturity and stable semantics.
   - Platform viability on currently supported client bridges.
   - Deterministic validation and regression coverage.
4. Current implementation baseline:
   - Implemented hooks: `prf`, `largeBlob`.
   - Next candidate: `credProps` (discoverability-aligned).
   - Deferred queue (demand/interoperability-gated): `uvm`, `appidExclude`, `appid`.
5. Keep unknown/proprietary extension handling explicit and non-breaking.

## Platform Expansion Research Track (No New Published Modules This Cycle)

1. This cycle is research-only for new platform families; no new published client platform modules are planned.
2. Keep current published client posture centered on Android and iOS bridge modules plus shared KMP core.
3. Fits this repository now:
   - Web and desktop research/spikes using existing KMP core boundaries and sample-driven validation.
   - CLI experimentation remains valid as a sample-level proving ground.
4. Not a fit for this cycle:
   - First-class published `watch`, `auto`, or additional platform modules.
   - Promoting `samples/passkey-cli` from POC to production-grade SDK surface.
5. Reassess platform promotion only after concrete API maturity, test matrix feasibility, and maintainer capacity are verified.

## Fit Assessment for Current Scope

Makes sense now:

1. Discoverable credentials as a primary roadmap stream.
2. `credProps` as the first extension expansion after `prf`/`largeBlob`.
3. Delete-account and recovery integration guidance with reusable contracts.
4. Web and desktop research as non-published exploration tracks.

Not in scope now:

1. Full IANA/WebAuthn/CTAP extension parity in one phase.
2. New published platform modules for auto/watch/other targets in this cycle.
3. Treating the existing CLI sample as production API surface.

## Public API and Interface Guidance (Future Implementation)

Discoverable credentials:

1. Add additive server start/finish paths for username-less authentication without breaking named-user flows.
2. Extend session/store contracts only where required for discoverable-mode semantics.
3. Run `apiCheck` when BCV-covered API changes are introduced.

Extensions:

1. Keep model surface standards-first and typed.
2. Add behavior support only after standards, platform, and test gates pass.
3. Preserve non-breaking handling for custom extension identifiers.

Account lifecycle:

1. Introduce lifecycle-oriented credential/account operations as additive contracts.
2. Add provider-consistency signaling integration points for delete/rename/invalid-credential scenarios.
3. Keep server-core contracts generic and place product-specific policy wiring in adapters/samples.

## Validation and Acceptance Guidance

Discoverable credentials:

1. Username-less auth start/finish tests.
2. `allowCredentials` empty-path resolution tests.
3. Negative-path tests for unknown/mismatched credentials.

Extensions:

1. `credProps` parse/map/validation and round-trip coverage.
2. Extension hook-composition tests for mixed valid/invalid outcomes.
3. Differential/fixture checks where interoperability risk is high.

Account lifecycle:

1. Contract tests for delete semantics across in-memory and Exposed stores.
2. Signal integration tests with best-effort capability gating and safe fallback behavior.
3. Sample-flow UX policy checks for last-passkey warnings and recovery-path visibility.

Docs and gates:

1. Keep roadmap/status/spec-trace docs synchronized when implementation semantics change.
2. Run fast and strict changed-scope quality gates for roadmap and implementation updates.
3. Run `apiCheck` for BCV-covered published API changes.

## Active Priorities (Next 3)

1. Discoverable-credential username-less flow design plus conformance and negative-path tests.
2. Standards-first extension expansion kickoff with `credProps` after existing `prf`/`largeBlob` baselines.
3. Account lifecycle contracts and provider-consistency signaling guidance (Android Signal API and Apple credential update signaling references).

## Completed Item Handling

1. Keep old phase entries as historical context and intent memory unless they are factually obsolete.
2. Mark completion in the canonical tracker (`docs/IMPLEMENTATION_TRACKER.md`) with `Status=DONE`; do not rely on roadmap text alone for execution state.
3. Keep roadmap backlog entries focused on active or upcoming work; move finished execution details to tracker history sections.

## Phase 6 Backlog (Execution Queue)

1. Discoverable credential flow support (core + server + sample wiring).
Acceptance: username-less auth design is documented, core/server tests cover empty `allowCredentials` and credential resolution, and sample integration demonstrates the path.

2. `credProps` standards-first extension slice.
Acceptance: typed mapping and validation coverage is implemented, hook composition is covered by tests, and spec trace notes are updated with behavior boundaries.

3. Account lifecycle foundations (delete, recovery, consistency signaling).
Acceptance: additive contracts are documented, delete/recovery semantics are covered in store-level tests, and sample UX guidance includes last-passkey safeguards plus recovery fallback expectations.

## Assumptions and Defaults

1. Extension scope uses standards-first subset expansion rather than full-registry parity.
2. Platform expansion remains research-only for this cycle.
3. Account lifecycle scope targets reusable library contracts and sample-backed flows, not product-specific end-to-end policy engines in server core.
4. Published-target posture remains unchanged for this cycle; new platform work is research/spike-only.

## Research Basis (2026-04)

1. WebAuthn L3 and discoverable credential semantics: https://www.w3.org/TR/webauthn-3/
2. IANA WebAuthn registries: https://www.iana.org/assignments/webauthn/webauthn.xhtml
3. Android passkeys and form-factor guidance:
   - https://developer.android.com/identity/passkeys
   - https://developer.android.com/identity/form-factors
   - https://developer.android.com/training/wearables/apps/auth-wear
4. Android lifecycle/signaling guidance:
   - https://developer.android.com/identity/passkeys/manage-passkeys
   - https://developer.android.com/identity/credential-manager/signal-api-rp
5. Android for Cars sign-in constraints:
   - https://developer.android.com/design/ui/cars/guides/flows/create-sign-in-flow
6. FIDO recovery guidance:
   - https://fidoalliance.org/wp-content/uploads/2019/02/FIDO_Account_Recovery_Best_Practices-1.pdf
   - https://fidoalliance.org/wp-content/uploads/2024/05/Synced-Passkey-Deployment_-Emerging-Practices-for-Consumer-Use-Cases_2024-May-31.pdf
7. Apple passkey and credential update references:
   - https://developer.apple.com/documentation/authenticationservices/supporting-passkeys
   - https://developer.apple.com/documentation/authenticationservices/ascredentialupdater
