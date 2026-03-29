# Client Sample Rework Execution Map

Status: Active  
Owner: `@ai-agent` (paired with maintainers)  
Started: 2026-03-29  
Target branch strategy: stacked PRs targeting `client-sample-rework-dev`, then one integration PR from `client-sample-rework-dev` to `main`

## Goal

Deliver the client sample rework in six reviewable PRs while keeping sample-only risk isolated from published modules.

## Scope Boundaries

- In scope: `samples:*`, sample-focused build logic/config, sample docs and roadmap entries.
- Out of scope for this effort: backend API contract changes, published artifact API changes, server behavior changes.
- Release impact: none expected (sample-only + docs).

## Branch and PR Queue

Each PR below should target `client-sample-rework-dev`.

| PR | Branch | Status | Scope | Exit Criteria |
| --- | --- | --- | --- | --- |
| 1 | `client-sample-rework-pr1-policy-visibility` | Completed | Sample policy boundary + visibility cleanup (`explicitApi` exclusion for samples, remove unnecessary `public`) | Sample modules compile with preserved host entrypoints and no accidental public-surface changes. |
| 2 | `client-sample-rework-pr2-foundation` | Planned | Compose sample architecture skeleton (MVVM+UDF), typed routes, Navigation 3 setup, Koin graph, orchestration split out of monolithic `App()` | Compose sample compiles for Android and iOS simulator targets with new architecture wiring in place and no feature regressions. |
| 3 | `client-sample-rework-pr3-auth-session` | Planned | Real login flow with `Auth` and `LoggedIn` screens, local session model, local logout behavior | Register/sign-in/logout transitions are deterministic in ViewModel tests and manual smoke checks. |
| 4 | `client-sample-rework-pr4-debug-structure` | Planned | Hidden debug logs in bottom sheet via secret trigger, composable file-structure discipline, state-driven renderers | Debug sheet remains hidden by default, opens via secret trigger, and composable boundaries follow one reusable `internal` composable per file. |
| 5 | `client-sample-rework-pr5-previews` | Planned | Preview catalog + preview-safe UI contracts + tooling setup + preview limitations doc | Previews render with fake/static data and compile paths stay free of DI/network/platform runtime dependencies. |
| 6 | `client-sample-rework-pr6-docs-roadmap` | Planned | README/readiness updates, roadmap backlog items, execution-map closure | Docs reflect new flow/behavior, roadmap entries exist, and execution map is closed with next-action pointers. |

## Validation Gates (Per PR)

1. `tools/agent/quality-gate.sh --mode fast --scope changed --block false`
2. `tools/agent/quality-gate.sh --mode strict --scope changed --block false`
3. If published modules are touched unexpectedly: `./gradlew apiCheck --stacktrace`

## Risks and Mitigations

| Risk | Impact | Mitigation | Status |
| --- | --- | --- | --- |
| Navigation 3 dependency variant coverage mismatch for sample iOS targets | Blocks cross-target compile in PR2/PR5 | Resolve dependency/target compatibility before merging PR2; keep any target-scope adjustment sample-only | Open |
| Koin Navigation 3 pre-release churn | Medium refactor churn risk in sample app | Isolate to sample modules and keep PR2 wiring narrow + typed contracts | Open |
| Preview annotation/tooling mismatch in common source sets | Compile failures for iOS/KMP | Keep preview code in preview-safe source set strategy and wire tooling explicitly in PR5 | Open |

## Decision Log

- 2026-03-29: Adopt Compose Multiplatform Navigation 3 path (not Android-only navigation component path).
- 2026-03-29: Use MVVM + UDF for sample app architecture.
- 2026-03-29: Implement local logout now; keep delete/recover/discoverable-credential as roadmap items.
- 2026-03-29: Keep explicit `internal` only where module boundaries matter; never keep redundant `public`.

## Completion Criteria

- PR1-PR6 merged into `client-sample-rework-dev`.
- Integration PR from `client-sample-rework-dev` to `main` is ready.
- This execution-map file is updated to `Status: Complete` and then removed in cleanup once effort is fully landed.
