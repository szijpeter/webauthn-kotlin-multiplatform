# Quality And Release

Last reviewed: 2026-04-06

The repo treats public release posture as active. Even small changes should be checked against compatibility, documentation trace, and quality-gate expectations.

## Default Quality Gates

Run the smallest matching checks first:

```bash
tools/agent/quality-gate.sh --mode fast --scope changed --block false
tools/agent/quality-gate.sh --mode strict --scope changed --block false
```

These are the standard advisory gates for local work and pre-PR validation.

## When To Run Extra Checks

- Run `./gradlew apiCheck --stacktrace` when a BCV-covered published API changes.
- Run `./gradlew publishToMavenLocal --stacktrace` when publishing coordinates, metadata, or release wiring change.
- Escalate to broader checks only when the change is cross-cutting, risky, or explicitly requested.

## Release-Train Model

- Published artifacts move together on one coordinated version.
- The BOM is the alignment entry point for consumers.
- Samples, `platform:constraints`, and `build-logic` are not part of the published artifact surface.
- Public-facing docs need to stay current when public API or integration paths change.

## Documentation Trace Rules

The steering doc requires synchronized docs updates when:

- a BCV-covered published module API changes
- public integration paths change
- security-facing workflows or policy change
- publishing workflow or release posture changes

In practice that usually means touching the relevant module `README.md`, and sometimes the root [`README.md`](../../README.md) plus [`docs/architecture.md`](../architecture.md).

## Decision Ladder

The preferred order is:

1. read the changed files
2. read nearby impacted docs/tests/build files
3. run fast changed-scope gate
4. run strict changed-scope gate
5. run `apiCheck` if public API changed
6. run `publishToMavenLocal` if publishing/build metadata changed

## Canonical Source Anchors

- Steering and done criteria: [`docs/ai/STEERING.md`](../ai/STEERING.md)
- Contribution workflow: [`CONTRIBUTING.md`](../../CONTRIBUTING.md)
- Maven Central guide: [`docs/MAVEN_CENTRAL.md`](../MAVEN_CENTRAL.md)
- Public launch checklist: [`docs/PUBLIC_LAUNCH_CHECKLIST.md`](../PUBLIC_LAUNCH_CHECKLIST.md)
