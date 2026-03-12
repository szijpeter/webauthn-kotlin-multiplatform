# AI Steering (Canonical Source)

This file is the single source of truth for Codex, Claude Code, Cursor, and Gemini instructions in this repository.

## North Star

Build the most robust and standards-first WebAuthn Kotlin Multiplatform library, and ship it as a trustworthy public open-source project.

## Non-Negotiables

1. Standards first: align behavior with W3C WebAuthn L3 + RFC 4648 + RFC 8949 + RFC 9052/9053.
2. Security critical paths must not regress (challenge/origin/type checks, flags, counters, attestation validation behavior).
3. Preserve strict layering and KMP boundaries (`webauthn-model` and `webauthn-core` remain free of platform/network dependencies).
4. Public release posture is active: changes to published artifacts must preserve compatibility expectations, release quality, and OSS-facing clarity.
5. `webauthn-client-core` owns shared client business logic; platform modules remain thin bridges to OS APIs.
6. Keep changes economic: smallest sufficient scope, minimal context load, targeted checks first.
7. Do not claim done without tests and quality gates matching impacted surface.
8. Public repo hygiene is mandatory: no credentials/secrets in tracked files or committed history.
9. Workflow security defaults are mandatory: least-privilege permissions and explicit action version references (major tags or pinned SHAs).
10. Security-facing workflow/policy changes require synchronized docs updates (`SECURITY.md`, public launch checklist, and affected workflow docs).

## Release Mode Policy

1. Use one coordinated release-train version for all published artifacts.
2. Publish only the curated public surface listed in this file; do not publish samples, internal modules, or build logic.
3. If any published module changes, release the full published set plus the BOM under a new coordinated version.
4. If only docs, samples, internal modules, or build logic change, a Maven Central release is not required.
5. GitHub release tags follow the coordinated version, for example `v0.1.0`.
6. For major release initiatives, maintain a temporary execution-map doc under `docs/ai/`, keep it updated when decisions drift, and delete it once the effort is complete.

## Published Artifact Surface

Published:

- `platform:bom` as `webauthn-bom`
- `webauthn-model`
- `webauthn-serialization-kotlinx`
- `webauthn-core`
- `webauthn-crypto-api`
- `webauthn-server-jvm-crypto`
- `webauthn-server-core-jvm`
- `webauthn-server-ktor`
- `webauthn-server-store-exposed`
- `webauthn-client-core`
- `webauthn-client-json-core`
- `webauthn-client-compose`
- `webauthn-client-android`
- `webauthn-client-ios`
- `webauthn-network-ktor-client`
- `webauthn-attestation-mds`

Not published:

- `webauthn-cbor-internal`
- `platform:constraints`
- `samples:*`
- `build-logic`

## Crypto Backend Policy

1. Signum is the default crypto backend across JVM/Android/iOS where capability exists.
2. Avoid parallel local crypto implementations when Signum already provides the needed primitive/parser/verification path.
3. Keep `webauthn-crypto-api` vendor-agnostic; do not expose Signum-specific types in public cross-module contracts.
4. If a target needs fallback to platform-native crypto because Signum capability is missing, keep fallback minimal and document the exact gap in `docs/dependency-decisions.md`.

## Module Criticality Map

Core-critical:

- `webauthn-model`
- `webauthn-core`
- `webauthn-serialization-kotlinx`
- `webauthn-crypto-api`
- `webauthn-server-core-jvm`
- `webauthn-server-jvm-crypto`

Adapter/transport/platform:

- `webauthn-server-ktor`
- `webauthn-server-store-exposed`
- `webauthn-network-ktor-client`
- `webauthn-client-core`
- `webauthn-client-json-core`
- `webauthn-client-compose`
- `webauthn-client-android`
- `webauthn-client-ios`

Optional trust source:

- `webauthn-attestation-mds`

Reference/samples:

- `samples/*`
- `docs/*`
- `spec-notes/*`

## Error Handling Policy

1. Prefer `KmmResult` (`at.asitplus.catching`, `.transform`, `.fold`) for internal sequential pipelines where failures are singular.
2. Keep `ValidationResult` in validation-heavy paths that intentionally aggregate multiple field-level errors.
3. Public API boundaries must use project domain result models (`PasskeyResult`, `ValidationResult`).
4. `KmmResult` usage must not leak into cross-module public contracts.

## Standards Source Policy

1. The WebAuthn specification is the primary source of truth for behavior and public API contracts.
2. Keep local snapshots/links under `spec-cache/` to reduce context switching during implementation.
3. Cached spec artifacts are reference material only; normative tie-breaker remains the latest upstream W3C publication/editor draft.

## Decision Ladder (Cheap -> Expensive)

1. Read changed files.
2. Read directly impacted module build files/tests.
3. Read architecture/spec note only if needed for behavior decisions.
4. Run `tools/agent/quality-gate.sh --mode fast --scope changed --block false`.
5. Run `tools/agent/quality-gate.sh --mode strict --scope changed --block false`.
6. Run `./gradlew apiCheck` when BCV-covered public API changes.
7. Run `./gradlew publishToMavenLocal` when publishing/build metadata changes.
8. Run full-repo checks only when cross-cutting risk or requested.

## Token Economy Protocol

1. Start with diff-only context.
2. Expand to nearest dependencies only.
3. Avoid full-repo scans unless blocked after focused search.
4. Prefer summary references to large file dumps.
5. Reuse existing docs instead of re-deriving intent.

## Done Criteria

A change is done only when all apply:

1. Code and tests updated for impacted modules.
2. `tools/agent/quality-gate.sh` passes at required mode.
3. If validator/model rule semantics changed, `spec-notes/webauthn-l3-validation-map.md` is updated.
4. If core/security-critical modules changed, `docs/IMPLEMENTATION_STATUS.md`, `docs/ROADMAP.md`, or `docs/IMPLEMENTATION_TRACKER.md` is updated.
5. If a BCV-covered published API changed, matching `.api` baselines are intentionally updated via `apiDump` and validated via `apiCheck`.
6. If publishing, coordinates, or metadata changed, `publishToMavenLocal` has been run locally or the gap is called out explicitly.
7. Documentation is updated when workflow/contracts/change adoption guidance changed.
8. If CI/security posture changed, `SECURITY.md` and `docs/PUBLIC_LAUNCH_CHECKLIST.md` are updated in the same change.
9. If a temporary release execution-map doc is active for the current effort, keep it updated in the same change when scope/sequence decisions change.

## Quality Gate Contract

Use `tools/agent/quality-gate.sh`.

Parameters:

- `--mode fast|strict`
- `--scope changed|full`
- `--format human|json`
- `--block true|false`

Defaults:

- `mode=fast`
- `scope=changed`
- `format=human`
- `block=true`

## Required Workflow Defaults

- Pre-commit: advisory fast changed-scope gate.
- Pre-push: advisory strict changed-scope gate.
- PR CI: blocking authority for quality, compatibility, and release preflight.
- Maven Central publishing: manual workflow dispatch only.

## Stop Conditions

Stop and ask before continuing when:

1. A required change conflicts with this steering file.
2. You need destructive git/file actions not explicitly requested.
3. Unknown policy would alter API compatibility or release semantics.
4. Live release publication, tag creation, or secret setup is required.

## Source Pointers

- Architecture: `docs/architecture.md`
- Dependency policy: `docs/dependency-decisions.md`
- Implementation status: `docs/IMPLEMENTATION_STATUS.md`
- Roadmap: `docs/ROADMAP.md`
- Tracker: `docs/IMPLEMENTATION_TRACKER.md`
- Validation mapping: `spec-notes/webauthn-l3-validation-map.md`
- Client-first execution: `docs/CLIENT_FIRST_EXECUTION.md`
- Client API benchmark notes: `docs/CLIENT_API_BENCHMARKS.md`
- Spec cache index: `spec-cache/README.md`
- CI baseline: `.github/workflows/ci.yml`
- Security policy: `SECURITY.md`
- Public launch checklist: `docs/PUBLIC_LAUNCH_CHECKLIST.md`
- Maven Central publishing guide: `docs/MAVEN_CENTRAL.md`
