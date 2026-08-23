# 0.4.0 Release Execution Map

Status: release candidate preparation in progress; publication requires explicit maintainer approval.

## Scope

- Latest official GitHub and Maven Central release: `v0.3.0` / `0.3.0`.
- Target release: `0.4.0`, a coordinated minor release across the complete published artifact surface.
- Release-prep base: `origin/main` at `476871db5eeb018ec8ae22a78622cdec17e6e060`; the final release SHA will be the merged release-prep commit after its current-head CI succeeds.
- Included: all commits on `main` since `v0.3.0`, including the signed-client-data security fix, raw/protocol/JSON foundation, server trust-boundary correction, final client/platform/flow/Ktor/default composition, dependency upgrades, documentation verification, and PR change-profile automation.
- Excluded unless merged and this plan/changelog are refreshed before publication: open PRs #170, #172, #171, and draft #202.

## Readiness Evidence

- Exact `main` head CI and CodeQL succeeded in GitHub Actions run `32370680456` and run `32370680461`.
- Android registration/sign-in smoke passed manually on the rebased client-feature descendant stack.
- Physical iOS registration and authentication passed on iOS 26.6 with a correctly provisioned Associated Domains entitlement; all four start/finish requests returned HTTP 200. The tested descendant includes current `main`, so it exercises the release architecture plus the still-open additive client feature stack.
- The physical smokes were not run from the exact release branch. Review of the intervening additive stack found the default iOS registration request construction semantically preserved and the authentication path unchanged; exact-head automated iOS/Android compilation and tests remain mandatory on the release PR.
- Local gates are complete; the release PR must still pass the current-head GitHub checks below.

## Required Pre-Publication Gates

- `tools/agent/verify-harness-sync.sh`
- `tools/agent/quality-gate.sh --mode strict --scope full --block true`
- `./gradlew apiCheck --stacktrace`
- `./gradlew publishToMavenLocal --stacktrace` with a configured signatory, or the documented credential-free `-PsignAllPublications=false` preflight when release keys are intentionally unavailable locally
- `bash tools/agent/check-published-consumer-smoke.sh`
- Release-note extraction for `0.4.0` produces the reviewed `CHANGELOG.md` section.
- Release PR current-head CI, dependency review, CodeQL, and release preflight are green.

## Completed Local Gates

- `tools/agent/quality-gate.sh --mode fast --scope changed --block false`: passed.
- `tools/agent/quality-gate.sh --mode strict --scope full --block true`: passed.
- `./gradlew apiCheck --stacktrace`: passed.
- `./gradlew publishToMavenLocal --stacktrace`: reached publication assembly but could not sign because this workstation has no configured PGP signatory.
- `./gradlew publishToMavenLocal -PsignAllPublications=false --stacktrace`: passed, matching CI's credential-free publication preflight.
- `bash tools/agent/check-published-consumer-smoke.sh`: passed against Maven Local `0.4.0` artifacts on JVM, Android, and iOS Simulator targets, including the must-use consumer probe.
- `bash tools/agent/check-client-dependency-purity.sh`: passed for the replaceable JSON, Ktor, platform, and server seams.
- Release-note extraction tests, harness synchronization, workflow YAML parsing, and `git diff --check`: passed.
- Repository Actions secrets still include the required Central username/password and signing key/id/password names; their values remain intentionally unreadable and will only be exercised by the approval-gated publish workflow.

## Approval Gate And Publication

Do not create a tag, publish to Maven Central, create/publish a GitHub Release, or dispatch the `Publish` workflow without explicit maintainer approval after the release PR is merged and final `main` checks pass.

After approval, dispatch `.github/workflows/publish.yml` on `main` with `release_mode=publish-and-release` and `version_name=0.4.0`. Verify all coordinated artifacts and the BOM resolve from Maven Central, and verify tag/release `v0.4.0` points at the approved `main` SHA with the curated changelog section as its body.

## Post-Release Cleanup

- Open a cleanup PR setting `VERSION_NAME=0.4.1-SNAPSHOT`.
- Remove this temporary execution map after Central/tag/release verification is complete.
- Re-run the consumer smoke against Maven Central `0.4.0` rather than Maven Local.
- Keep the open client feature stack out of `0.4.0` unless it is intentionally merged before the approval gate and the release delta is re-audited.

## Follow-Ups Not Blocking Current Main

- PR #172 explicitly retains a real cross-device Android Restore Credentials backup/restore validation gate. Do not ship that feature until the gate is satisfied or the scope/readiness claim is revised.
- PRs #170/#172/#171 are a separate additive client feature stack and require their own merge decision/current-head CI after each parent lands.
- Draft PR #202 is an opt-in community FIDO registration compatibility canary, not official FIDO certification or a prerequisite for `0.4.0`.
