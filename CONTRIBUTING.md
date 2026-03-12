# Contributing

Thanks for helping improve WebAuthn Kotlin Multiplatform.

## Workflow

1. Branch from `main`.
2. Keep changes small and reviewable.
3. Prefer PRs over direct pushes.
4. Update docs when public behavior, release workflow, or adoption guidance changes.

## Required Local Checks

Run the smallest set that matches your change:

```bash
tools/agent/quality-gate.sh --mode fast --scope changed --block false
tools/agent/quality-gate.sh --mode strict --scope changed --block false
```

If public API changed in a BCV-covered published module:

```bash
./gradlew apiDump apiCheck --stacktrace
```

If publishing/build metadata changed:

```bash
./gradlew publishToMavenLocal --stacktrace
```

For broad or risky changes:

```bash
tools/agent/quality-gate.sh --mode strict --scope full --block true
```

## Documentation Expectations

Update the relevant docs in the same change when you touch:

- public APIs
- publishing or release workflow
- security posture
- client/server integration guidance
- release sequencing during the first public release effort

While the first public release effort is active, keep `docs/ai/FIRST_PUBLIC_RELEASE_PLAN.md` current. Remove it in the final cleanup PR after the full effort is complete.

## Pull Requests

A good PR should include:

- a focused scope
- tests or a clear reason tests were not needed
- doc updates when behavior or workflow changed
- notes about API baseline updates if `apiDump` changed
- notes about publish preflight if publishing metadata changed

## Release Notes

If a PR changes a published artifact in a user-visible way, add or update a relevant `CHANGELOG.md` entry.
