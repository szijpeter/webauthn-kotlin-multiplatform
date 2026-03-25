# Public Launch Checklist

Use this checklist when moving from private to public operation.

## In-Repo Baseline

1. Security policy file exists and is current: `SECURITY.md`.
2. CI workflows use least-privilege `permissions` and explicit versioned action references.
   - `Publish` workflow requires `contents:write` only to create the release tag in `publish-and-release` mode.
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
6. Demo/sample runtime security defaults are explicit (sample backend attestation mode defaults to `STRICT`; relaxed `NONE` mode is opt-in only).
7. If a temporary release execution-map doc is active, keep it current with scope/sequence changes.

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

## Post-Launch Verification

1. CI runs successfully on `main` pushes and pull requests.
2. Renovate creates update PRs for Gradle and GitHub Actions.
3. `SECURITY.md` appears in repository security surfaces.
4. Maven Central artifacts resolve using the published coordinates and BOM.
5. No secret findings exist in baseline scans; if any are found, rotate credentials immediately and evaluate targeted history rewrite.
6. Delete any temporary release execution-map doc once that release effort is complete.
