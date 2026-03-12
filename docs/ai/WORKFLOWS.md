# AI Workflows

Canonical policy: `docs/ai/STEERING.md`.

## Standard Change Workflow

1. Discover scope with:

```bash
tools/agent/changed-modules.sh --scope changed
```

2. Run the fast advisory gate during active iteration:

```bash
tools/agent/quality-gate.sh --mode fast --scope changed --block false
```

3. Before opening or updating a PR, run the strict advisory gate locally:

```bash
tools/agent/quality-gate.sh --mode strict --scope changed --block false
```

4. Let PR CI remain the blocking authority.
5. If core/model validation behavior changed, update `spec-notes/webauthn-l3-validation-map.md`.
6. If core/security-critical modules changed, update `docs/IMPLEMENTATION_STATUS.md` and/or `docs/ROADMAP.md`.
7. If public API changed in a BCV-covered published module, run:

```bash
./gradlew apiCheck --stacktrace
```

Only when the API change is intentional, regenerate baselines and re-check:

```bash
./gradlew apiDump apiCheck --stacktrace
```

8. If publishing/build metadata changed, run:

```bash
./gradlew publishToMavenLocal --stacktrace
```

## Docs-Only Workflow

For docs-only changes, `tools/agent/quality-gate.sh` intentionally skips heavy compile/test tasks. Update the temporary release plan doc as well when release scope or sequencing changes.

## Public Security Hygiene Workflow

1. Run targeted tracked-file secret scan:

```bash
git ls-files -z | xargs -0 rg -n -S '(?i)(api[_-]?key|secret[_-]?key|private[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY)'
```

2. Verify harness and policy wiring:

```bash
tools/agent/verify-harness-sync.sh
```

3. Run required gates:

```bash
tools/agent/quality-gate.sh --mode fast --scope changed --block false
tools/agent/quality-gate.sh --mode strict --scope changed --block false
```

4. Confirm public hardening checklist items in `docs/PUBLIC_LAUNCH_CHECKLIST.md`.

## Full Validation Workflow

Use for cross-cutting changes:

```bash
tools/agent/quality-gate.sh --mode strict --scope full --block true
```

## Release-Prep Workflow

1. For complex release initiatives, keep a temporary release execution-map doc under `docs/ai/` current while the effort is active.
2. Validate compatibility and publishing preflight:

```bash
./gradlew apiCheck publishToMavenLocal --stacktrace
```

3. For a live release, use `.github/workflows/publish.yml` via `workflow_dispatch`.
4. After the release effort is complete, delete the temporary execution-map doc in the cleanup PR.
