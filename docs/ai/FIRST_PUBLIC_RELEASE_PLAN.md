# First Public Release Plan

Status: active temporary execution document for release-prep work.

## Working Rules

1. Keep this file up to date whenever release scope, sequencing, or key decisions materially change.
2. Use it as the maintainer-facing execution map while the first public release is in progress.
3. Delete this file in the final cleanup PR once the entire public-release plan is complete.

## Current Snapshot

- Canonical release mode is active.
- Coordinated repo versioning is in place via `GROUP` + `VERSION_NAME` in `gradle.properties`.
- Publishing conventions, Maven Central workflow wiring, and BCV baselines are implemented in-repo.
- Public API hardening follow-up [#59](https://github.com/szijpeter/webauthn-kotlin-multiplatform/issues/59) is merged via PR #60.
- Local release-prep verification is green as of 2026-03-12: strict full quality gate, `apiCheck`, `publishToMavenLocal`, and `verify-harness-sync`.
- Remote publish preflight on 2026-03-12 shows repository Actions secrets are not configured yet (`total_count=0`), so live publish is blocked until required secrets are added.
- Final release cut (`0.1.0`, Maven Central publish, GitHub tag/release, post-release snapshot bump) remains pending.

## Planned Sequence

1. Release-mode steering and workflow policy.
2. Compatibility, publishing, and Maven Central infrastructure.
3. Public docs, module docs, and OSS-facing polish.
4. Final release hardening and the live `0.1.0` cut.

## Published Surface

- Core/server: `webauthn-model`, `webauthn-serialization-kotlinx`, `webauthn-core`, `webauthn-crypto-api`, `webauthn-server-jvm-crypto`, `webauthn-server-core-jvm`, `webauthn-server-ktor`, `webauthn-server-store-exposed`
- Client: `webauthn-client-core`, `webauthn-client-json-core`, `webauthn-client-compose`, `webauthn-client-android`, `webauthn-client-ios`, `webauthn-network-ktor-client`
- Optional trust: `webauthn-attestation-mds`
- Alignment: `platform:bom` as `webauthn-bom`

Unpublished: `webauthn-cbor-internal`, `platform:constraints`, `samples:*`, `build-logic`

## Remaining Release-Cut Tasks

- Keep PR CI green while landing the release-prep PR set.
- Configure required publish secrets in GitHub (`MAVEN_CENTRAL_USERNAME`, `MAVEN_CENTRAL_PASSWORD`, `SIGNING_KEY`, `SIGNING_KEY_PASSWORD`, plus optional `SIGNING_KEY_ID`).
- Set `VERSION_NAME=0.1.0` for the release run.
- Trigger `.github/workflows/publish.yml` with `release_mode=publish-and-release`.
- Verify Maven Central resolution and then create Git tag `v0.1.0` plus GitHub release.
- Move `main` back to the next snapshot after the release is confirmed.
