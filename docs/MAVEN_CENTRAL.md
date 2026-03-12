# Maven Central Publishing

This repository publishes with `com.vanniktech.maven.publish` to Sonatype Central Portal.

## Coordinates

- Group: `io.github.szijpeter`
- BOM artifact: `io.github.szijpeter:webauthn-bom`
- Module artifact pattern: `io.github.szijpeter:<module-name>`
- Package names remain `dev.webauthn.*`

Examples:

- `io.github.szijpeter:webauthn-model`
- `io.github.szijpeter:webauthn-server-core-jvm`
- `io.github.szijpeter:webauthn-client-android`

## Published Surface

Published:

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
- `platform:bom` as `webauthn-bom`

Not published:

- `webauthn-cbor-internal`
- `platform:constraints`
- `samples:*`
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

```bash
tools/agent/quality-gate.sh --mode strict --scope full --block true
./gradlew apiCheck --stacktrace
./gradlew publishToMavenLocal --stacktrace
```

## Workflow

Use [`.github/workflows/publish.yml`](../.github/workflows/publish.yml).

Inputs:

- `release_mode=publish-only`
- `release_mode=publish-and-release`
- optional `version_name=x.y.z`

Guardrails:

- `publish-and-release` is blocked for snapshot versions.
- Publishing remains manual; merges to `main` do not auto-publish.

## Release Runbook

1. Ensure PR CI is green, including `apiCheck` and `publishToMavenLocal` preflight.
2. Set `VERSION_NAME=x.y.z` or pass `version_name` to the workflow.
3. Trigger the `Publish` workflow with `release_mode=publish-and-release`.
4. Verify Central Portal status and artifact resolution.
5. Create Git tag `vX.Y.Z` and the matching GitHub release.
6. Move `main` back to the next snapshot version.

## Current State

First public release is complete: `0.1.0` was published on 2026-03-12.
