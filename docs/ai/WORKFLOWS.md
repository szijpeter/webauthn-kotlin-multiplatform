# AI Workflows

Canonical policy: `docs/ai/STEERING.md`.

## Standard Change Workflow

1. Discover scope with:

<!-- doc-example: id=docs-ai-workflows-bash-1; owner=markdown; verify=syntax; audience=contributor -->
```bash
tools/agent/changed-modules.sh --scope changed
```

2. Run the fast advisory gate during active iteration:

<!-- doc-example: id=docs-ai-workflows-bash-2; owner=markdown; verify=syntax; audience=contributor -->
```bash
tools/agent/quality-gate.sh --mode fast --scope changed --block false
```

3. Before opening or updating a PR, run the strict advisory gate locally:

<!-- doc-example: id=docs-ai-workflows-bash-3; owner=markdown; verify=syntax; audience=contributor -->
```bash
tools/agent/quality-gate.sh --mode strict --scope changed --block false
```

4. Let PR CI remain the blocking authority.
5. If core/model validation behavior changed, update `spec-notes/webauthn-l3-validation-map.md`.
6. If core/security-critical modules changed, update `docs/IMPLEMENTATION_STATUS.md` and/or `docs/ROADMAP.md`.
7. When a published module implementation/build contract changes, update the matching module `README.md` in the same change.
8. When module relationships or integration paths change, update both root `README.md` and `docs/architecture.md` in the same change.
9. Add Mermaid diagrams for any new or updated architecture or flow diagrams in docs.
10. If public API changed in a BCV-covered published module, run:

<!-- doc-example: id=docs-ai-workflows-bash-4; owner=markdown; verify=syntax; audience=contributor -->
```bash
./gradlew apiCheck --stacktrace
```

Only when the API change is intentional, regenerate baselines and re-check:

<!-- doc-example: id=docs-ai-workflows-bash-5; owner=markdown; verify=syntax; audience=contributor -->
```bash
./gradlew apiDump apiCheck --stacktrace
```

11. If publishing/build metadata changed, run:

<!-- doc-example: id=docs-ai-workflows-bash-6; owner=markdown; verify=syntax; audience=contributor -->
```bash
./gradlew publishToMavenLocal --stacktrace
```

## Docs-Only Workflow

For docs-only changes, `tools/agent/quality-gate.sh` intentionally skips heavy compile/test tasks. Update the temporary release execution-map doc as well when release scope or sequencing changes, and keep documentation trace expectations satisfied for any touched public module docs.

## Public Security Hygiene Workflow

1. Run targeted tracked-file secret scan:

<!-- doc-example: id=docs-ai-workflows-bash-7; owner=markdown; verify=syntax; audience=contributor -->
```bash
git ls-files -z | xargs -0 rg -n -S '(?i)(api[_-]?key|secret[_-]?key|private[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY)'
```

2. Verify harness and policy wiring:

<!-- doc-example: id=docs-ai-workflows-bash-8; owner=markdown; verify=syntax; audience=contributor -->
```bash
tools/agent/verify-harness-sync.sh
```

3. Run required gates:

<!-- doc-example: id=docs-ai-workflows-bash-9; owner=markdown; verify=syntax; audience=contributor -->
```bash
tools/agent/quality-gate.sh --mode fast --scope changed --block false
tools/agent/quality-gate.sh --mode strict --scope changed --block false
```

4. Confirm public hardening checklist items in `docs/PUBLIC_LAUNCH_CHECKLIST.md`.

## Full Validation Workflow

Use for cross-cutting changes:

<!-- doc-example: id=docs-ai-workflows-bash-10; owner=markdown; verify=syntax; audience=contributor -->
```bash
tools/agent/quality-gate.sh --mode strict --scope full --block true
```

## Release-Prep Workflow

1. For complex release initiatives, keep a temporary release execution-map doc under `docs/ai/` current while the effort is active.
2. Validate compatibility and publishing preflight:

<!-- doc-example: id=docs-ai-workflows-bash-11; owner=markdown; verify=syntax; audience=contributor -->
```bash
./gradlew apiCheck publishToMavenLocal --stacktrace
bash tools/agent/check-published-consumer-smoke.sh
```

3. For a live release, use `.github/workflows/publish.yml` via `workflow_dispatch`.
4. After the release effort is complete, delete the temporary release execution-map doc in the cleanup PR.
