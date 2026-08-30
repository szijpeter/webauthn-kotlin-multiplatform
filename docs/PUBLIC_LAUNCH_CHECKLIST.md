# Public Launch Checklist

Use this checklist when moving from private to public operation.

## In-Repo Baseline

1. Security policy file exists and is current: `SECURITY.md`.
2. CI workflows use least-privilege `permissions`, explicit versioned action references, and
   `persist-credentials: false` on every checkout before repository code executes.
   - Central publication runs with read-only repository contents and no persisted Git credentials; a separate GitHub-release job receives `contents:write` only after Central succeeds (or during an explicit `finalize-release` recovery) to create or reconcile the detached Swift package-manifest commit, coordinated release tag, curated GitHub release, and checksum-verified XCFramework assets.
   - Any privileged `pull_request_target` workflow loads executable code only from trusted, explicitly versioned references. Data-only configuration may come from the trusted default branch or the exact pull-request base commit, never the pull-request head; pull-request content is treated as API metadata only.
3. Dependency automation exists and is current: `.github/renovate.json`.
4. Local/sensitive files are ignored (`.env*`, `local.properties`, build outputs, IDE state).
5. Required quality and release-preflight gates pass:
   - `tools/agent/quality-gate.sh --mode fast --scope changed --block false`
   - `tools/agent/quality-gate.sh --mode strict --scope changed --block false`
   - `tools/agent/verify-harness-sync.sh`
   - `tools/agent/quality-gate.sh --mode strict --scope full --block true`
   - `./gradlew apiCheck --stacktrace`
   - `./gradlew publishToMavenLocal --stacktrace`
   - `bash tools/agent/check-published-consumer-smoke.sh`
   - `tools/swift/ci-check.sh` on macOS when the Swift facade, bridge, sample, or release packaging changes
   - `tools/swift/prepare-release.sh <version> <output-directory>` as a non-publishing artifact dry run before a coordinated release
6. Before setting `swift_device_qualified=true`, record a physical-iPhone qualification against the exact release commit and a production-like HTTPS relying party:
   - signed app entitlements contain the expected `webcredentials:` associated domain and the live AASA response authorizes the app identifier;
   - registration and authentication complete successfully, cancellation maps to the documented cancellation error, and a representative backend rejection remains distinct from platform failure;
   - PRF authentication establishes a session, encrypt/decrypt round-trips, clearing the session prevents later use, and surfaced UI/log diagnostics contain no salt, PRF output, derived key, user handle, or key fingerprint;
   - evidence records the commit, device model, iOS version, Xcode version, app identifier, relying-party ID, backend origin, AASA response, and pass/fail result without retaining credentials or secrets.
   - retain that record at a stable HTTPS URL and pass it as `swift_device_qualification_evidence`; the release metadata preserves the reference beside the exact source commit and immutable release inputs.
7. Demo/sample runtime security defaults are explicit (sample backend attestation mode defaults to `STRICT`; relaxed `NONE` mode is opt-in only).
8. If a temporary release execution-map doc is active, keep it current with scope/sequence changes.

## GitHub Repository Settings

1. Default branch is `main`.
2. Visibility is public.
3. Branch protections/rulesets require CI, dependency review, and release-preflight checks.
4. Enable security analysis features:
   - Dependency graph
   - Dependabot alerts
   - Dependabot security updates
   - Secret scanning
   - Secret scanning push protection
   - Code scanning (CodeQL for workflow files; Java/Kotlin scan can remain disabled while Kotlin `2.3.10` is unsupported upstream)
5. Ensure dependency review checks run on pull requests (`.github/workflows/dependency-review.yml`).
6. Ensure Renovate is active for Gradle and GitHub Actions updates.
7. Enable private vulnerability reporting.
8. Confirm GitHub Actions repository settings are least privilege.
9. Configure Maven Central and signing secrets before attempting a live publish.
10. Require the blocking Swift CI check in the branch ruleset before publishing the native Swift package.

## Post-Launch Verification

1. CI runs successfully on `main` pushes and pull requests.
2. Renovate creates update PRs for Gradle and GitHub Actions.
3. `SECURITY.md` appears in repository security surfaces.
4. Maven Central artifacts resolve using the published coordinates and BOM.
5. The release workflow's clean external iOS consumer resolves the exact version and compiles the `WebAuthn` product after publication.
6. The release tag is exactly one manifest-only commit above the recorded source commit; its `Package.swift` bytes and checksum match the retained workflow artifact and downloaded XCFramework.
7. The GitHub release contains exactly `WebAuthnBridge.xcframework.zip` and its SHA-256 file, while `main` retains the local-development package manifest.
8. No secret findings exist in baseline scans; if any are found, rotate credentials immediately and evaluate targeted history rewrite.
9. Delete any temporary release execution-map doc once that release effort is complete.
