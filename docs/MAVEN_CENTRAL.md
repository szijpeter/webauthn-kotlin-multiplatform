# Maven Central Publishing

This repository publishes with `com.vanniktech.maven.publish` to Sonatype Central Portal.

The same manual release train can also publish the native Swift package as a checksum-pinned XCFramework
asset. Maven coordinates and the Swift package use one resolved version.

## Coordinates

- Group: `io.github.szijpeter`
- BOM artifact: `io.github.szijpeter:webauthn-bom`
- Module artifact pattern: `io.github.szijpeter:<module-name>`
- Package names remain `dev.webauthn.*`

Examples:

- `io.github.szijpeter:webauthn-model`
- `io.github.szijpeter:webauthn-server-core-jvm`
- `io.github.szijpeter:webauthn-client-platform`

## Published Surface

Published:

- `webauthn-cbor-core`
- `webauthn-model`
- `webauthn-json-api`
- `webauthn-protocol`
- `webauthn-runtime-core`
- `webauthn-json-kotlinx`
- `webauthn-core`
- `webauthn-crypto-api`
- `webauthn-server-jvm-crypto`
- `webauthn-server-core-jvm`
- `webauthn-server-ktor`
- `webauthn-server-store-exposed`
- `webauthn-client-core`
- `webauthn-client-flow`
- `webauthn-client-ktor`
- `webauthn-client-ktor-kotlinx`
- `webauthn-client-defaults`
- `webauthn-client-json-core`
- `webauthn-client-compose`
- `webauthn-client-platform`
- `webauthn-client-prf-crypto`
- `webauthn-attestation-mds`
- `platform:bom` as `webauthn-bom`

Not published:

- `platform:constraints`
- `sample:*`
- `build-logic`

## One-Time Setup

1. Create/login to Central Portal.
2. Verify namespace ownership for `io.github.szijpeter`.
3. Create a Central Portal user token.
4. Prepare an ASCII-armored GPG private key.
5. Publish the public key to a supported keyserver.
6. Add repository secrets:
   - `MAVEN_CENTRAL_USERNAME`
   - `MAVEN_CENTRAL_PASSWORD`
   - `SIGNING_KEY`
   - `SIGNING_KEY_PASSWORD`
   - `SIGNING_KEY_ID` (optional, recommended)

## Local Validation

Before a release or any publishing change:

<!-- doc-example: id=docs-maven-central-bash-1; owner=markdown; verify=syntax; audience=contributor -->
```bash
tools/agent/quality-gate.sh --mode strict --scope full --block true
./gradlew apiCheck --stacktrace
./gradlew publishToMavenLocal --stacktrace
bash tools/agent/check-published-consumer-smoke.sh
```

If the workstation intentionally has no release signing key, `publishToMavenLocal` may be repeated with `-PsignAllPublications=false` after confirming that the only failure was a missing signatory. This validates publication metadata and consumer resolution but does not replace the live workflow's mandatory signed publication.

## Workflow

Use [`.github/workflows/publish.yml`](../.github/workflows/publish.yml).

Inputs:

- `release_mode=publish-only`
- `release_mode=publish-and-release`
- `release_mode=finalize-release` with the original workflow run ID after Central succeeded but GitHub finalization did not
- optional `version_name=x.y.z`
- `swift_device_qualified=true` and `swift_device_qualification_evidence=https://...` for `publish-and-release`

Guardrails:

- `publish-and-release` is blocked for snapshot versions and requires both the documented physical-iPhone qualification checkbox and a stable HTTPS evidence URL for the exact source commit.
- `publish-and-release` requires a matching versioned `CHANGELOG.md` section and creates the GitHub release/tag (`vX.Y.Z`) from those curated notes after successful Central publication.
- `publish-and-release` also builds and inspects the static Swift XCFramework, uploads it with its SHA-256 checksum, and tags a generated manifest whose binary-target URL and checksum point to that exact release asset.
- `publish-only` publishes Maven artifacts only; it intentionally creates neither a GitHub release nor a Swift package release.
- All Maven and Swift artifacts are built and checked before Central publication. The exact Swift manifest, archive, checksum, notes, source commit, and qualification metadata are retained together as an immutable workflow artifact for 30 days.
- The Central job has read-only repository contents and no persisted Git credentials; only the separate GitHub-release job receives `contents:write` after Central succeeds or during explicit finalization recovery.
- A new `publish-and-release` run requires an empty tag/release target. The privileged job creates a draft, uploads and reads back exact assets, then publishes it. Existing state is accepted only by `finalize-release` when the tag parent, manifest bytes, title, notes, and assets match the original retained inputs. Missing expected assets are repaired; conflicting or extra state is rejected without replacement or deletion.
- The generated commit is exactly one commit above the released `main` SHA and changes only `Package.swift`; it is reachable through the release tag, not pushed to `main`.
- `finalize-release` never republishes Maven artifacts. It requires the exact version and original workflow run ID, restores that run's immutable Swift inputs, and safely resumes or verifies GitHub release finalization.
- Publishing remains manual; merges to `main` do not auto-publish.

## Swift Artifact Dry Run

Prepare the exact release inputs without publishing:

<!-- doc-example: id=docs-maven-central-bash-2; owner=markdown; verify=syntax; audience=maintainer -->
```bash
VERSION=0.4.1
OUTPUT_DIRECTORY=/path/to/output
tools/swift/prepare-release.sh "$VERSION" "$OUTPUT_DIRECTORY"
```

Review the XCFramework archive, checksum, and generated `Package.swift`. The release archive supports arm64
iOS devices and arm64 simulators; `iosX64` is intentionally absent. The root manifest remains local-path based
for repository development, while versioned tags contain the remote checksum-pinned manifest.

## Release Runbook

1. Ensure PR CI is green, including `apiCheck`, `publishToMavenLocal` preflight, and `check-published-consumer-smoke`.
2. Set `VERSION_NAME=x.y.z` or pass `version_name` to the workflow.
3. Complete and record the physical-iPhone checks in `PUBLIC_LAUNCH_CHECKLIST.md` for the exact release commit.
4. Trigger the `Publish` workflow with `release_mode=publish-and-release`, `swift_device_qualified=true`, and the recorded `swift_device_qualification_evidence` URL.
5. Verify Central Portal status and artifact resolution.
6. Verify GitHub release/tag `vX.Y.Z` exists with both Swift assets and that the external-consumer smoke passed.
7. Confirm the release tag's `Package.swift` references the same version and SHA-256 value as the downloaded asset.
8. If Central succeeded but finalization failed, rerun with `release_mode=finalize-release`, the same explicit version, and the original run ID; do not rerun Central publication.
9. Move `main` back to the next snapshot version.

## Current State

Public releases are live on Maven Central; use the root README badge or GitHub Releases for the latest coordinated release version.
