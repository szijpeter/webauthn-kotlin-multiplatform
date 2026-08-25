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
5. CI checkout steps must disable persisted credentials before executing repository code.
   Privileged `pull_request_target` workflows must load executable code only from trusted, explicitly versioned references. Data-only configuration may come from the trusted default branch or the exact pull-request base commit, never the pull-request head. Such workflows must never check out or execute the pull-request head and may consume pull-request content only as API metadata with least-privilege permissions.
6. If core/model validation behavior changed, update `spec-notes/webauthn-l3-validation-map.md`.
7. If core/security-critical modules changed, update `docs/IMPLEMENTATION_STATUS.md` and/or `docs/ROADMAP.md`.
8. When a published module implementation/build contract changes, update the matching module `README.md` in the same change.
9. When module relationships or integration paths change, update both root `README.md` and `docs/architecture.md` in the same change.
10. Add Mermaid diagrams for any new or updated architecture or flow diagrams in docs.
11. If public API changed in a BCV-covered published module, run:

<!-- doc-example: id=docs-ai-workflows-bash-4; owner=markdown; verify=syntax; audience=contributor -->
```bash
./gradlew apiCheck --stacktrace
```

Only when the API change is intentional, regenerate baselines and re-check:

<!-- doc-example: id=docs-ai-workflows-bash-5; owner=markdown; verify=syntax; audience=contributor -->
```bash
./gradlew apiDump apiCheck --stacktrace
```

12. If publishing/build metadata changed, run:

<!-- doc-example: id=docs-ai-workflows-bash-6; owner=markdown; verify=syntax; audience=contributor -->
```bash
./gradlew publishToMavenLocal --stacktrace
```

## Diff Breakdown Workflow

`.github/workflows/diff-breakdown.yml` maintains one marker comment that
summarizes changed-file churn by review-oriented category, module, and platform
source set. The breakdown is descriptive review context, not a test-coverage
metric or a quality gate.

Repository path classification is customized in
`.github/diff-breakdown.yml`. Source-like files that do not match a
known layout remain visible as `Unclassified source` instead of being silently
folded into another category. The reusable
[Diff Breakdown](https://github.com/szijpeter/diff-breakdown) Action owns the
implementation and tests; this repository retains only its layout-specific
configuration and workflow wiring.

The commenting workflow uses `pull_request_target` only to support fork pull
requests. It pins the reusable action to an immutable commit, loads configuration
from the exact pull-request base commit, never checks out or executes the
pull-request head, and renders file metadata obtained through the GitHub API.

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
2. Add a versioned `CHANGELOG.md` section containing the curated GitHub Release notes. The publish workflow validates this section before Central publication.
3. Validate compatibility and publishing preflight:

<!-- doc-example: id=docs-ai-workflows-bash-11; owner=markdown; verify=syntax; audience=contributor -->
```bash
./gradlew apiCheck publishToMavenLocal --stacktrace
bash tools/agent/check-published-consumer-smoke.sh
```

On a workstation without a release signing key, use the credential-free Maven Local preflight documented in `docs/MAVEN_CENTRAL.md`; the approval-gated live workflow must still sign every publication.

4. For a live release, use `.github/workflows/publish.yml` via `workflow_dispatch`. Its Central job has read-only repository access and no persisted Git credentials; only the post-publication GitHub Release job receives `contents:write`.
5. After the release effort is complete, delete the temporary release execution-map doc in the cleanup PR.
