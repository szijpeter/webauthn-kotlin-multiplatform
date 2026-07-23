# Workflow: Fast PR Check

1. Inspect changed files and impacted modules.
2. Run:

<!-- doc-example: id=gemini-workflows-fast-pr-check-bash-1; owner=markdown; verify=syntax; audience=contributor -->
```bash
tools/agent/quality-gate.sh --mode fast --scope changed --block false
```

3. If fast gate fails, fix and rerun.
4. Before updating the PR, run:

<!-- doc-example: id=gemini-workflows-fast-pr-check-bash-2; owner=markdown; verify=syntax; audience=contributor -->
```bash
tools/agent/quality-gate.sh --mode strict --scope changed --block false
```

5. If public API or publishing changed, also run:

<!-- doc-example: id=gemini-workflows-fast-pr-check-bash-3; owner=markdown; verify=syntax; audience=contributor -->
```bash
./gradlew apiCheck --stacktrace
./gradlew publishToMavenLocal --stacktrace
```
