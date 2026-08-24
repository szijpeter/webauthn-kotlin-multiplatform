# Contributing

Thanks for helping improve WebAuthn Kotlin Multiplatform.

## Workflow

1. Branch from `main`.
2. Keep changes small and reviewable.
3. Prefer PRs over direct pushes.
4. Update docs when public behavior, release workflow, or adoption guidance changes.

## Required Local Checks

Run the smallest set that matches your change:

<!-- doc-example: id=contributing-bash-1; owner=markdown; verify=syntax; audience=contributor -->
```bash
tools/agent/quality-gate.sh --mode fast --scope changed --block false
tools/agent/quality-gate.sh --mode strict --scope changed --block false
```

If public API changed in a BCV-covered published module:

<!-- doc-example: id=contributing-bash-2; owner=markdown; verify=syntax; audience=contributor -->
```bash
./gradlew apiDump apiCheck --stacktrace
```

If publishing/build metadata changed:

<!-- doc-example: id=contributing-bash-3; owner=markdown; verify=syntax; audience=contributor -->
```bash
./gradlew publishToMavenLocal --stacktrace
```

For broad or risky changes:

<!-- doc-example: id=contributing-bash-4; owner=markdown; verify=syntax; audience=contributor -->
```bash
tools/agent/quality-gate.sh --mode strict --scope full --block true
```

## Documentation Expectations

Update the relevant docs in the same change when you touch:

- public APIs
- published module implementation/build contracts (update that module `README.md`)
- module relationships or integration paths (update root `README.md` and `docs/architecture.md`)
- publishing or release workflow
- security posture
- client/server integration guidance
- release sequencing during the first public release effort

Use Mermaid for new or updated architecture/flow diagrams.

The public documentation site is authored under `docs/site/content`, stages public module/sample
READMEs through an explicit allowlist, and adds the aggregated Dokka reference at build time. Read
`docs/site/README.md` before changing its navigation, toolchain, staging rules, or deployment workflow.
Run `./gradlew docsSiteCheck --stacktrace` for any public-site change; this includes the existing
documentation example checks, staging tests, strict static-site build, Dokka generation, and local
link/anchor validation.

While the first public release effort is active, keep `docs/ai/FIRST_PUBLIC_RELEASE_PLAN.md` current. Remove it in the final cleanup PR after the full effort is complete.

## Documentation examples

Every user-facing fenced block and Kotlin KDoc example is managed. Before adding or changing one, read
[`docs/documentation-examples.md`](docs/documentation-examples.md) and choose a single ownership and
verification model. Edit canonical source regions instead of generated Markdown bodies, run
`./gradlew docsUpdate`, and verify the result with `./gradlew docsCheck`.

For source-, sample-, and configuration-owned examples, edit the canonical `docs-region` in the referenced
source file and run `./gradlew docsUpdate`. For markdown-owned shell examples, edit the fenced block directly
in Markdown. Illustrative blocks are edited directly in Markdown and must include a concise reason explaining
why executable verification is not applicable. Run `./gradlew docsCheck` after either path.

The generated [`documentation/example-inventory.md`](documentation/example-inventory.md) records complete
repository coverage and must not be edited manually.

## Pull Requests

A good PR should include:

- a focused scope
- tests or a clear reason tests were not needed
- doc updates when behavior or workflow changed
- docs trace updates when module contracts/relationships changed
- notes about API baseline updates if `apiDump` changed
- notes about publish preflight if publishing metadata changed

## Release Notes

If a PR changes a published artifact in a user-visible way, add or update a relevant `CHANGELOG.md` entry.
