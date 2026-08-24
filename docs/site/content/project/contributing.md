# Contributing

Contributions should be narrow, source-backed, and verified at the smallest meaningful scope. Update public documentation with public API, integration, module, release, or security behavior changes.

## Local checks

<!-- doc-example: id=site-contributing-bash-1; owner=markdown; verify=syntax; audience=contributor -->
```bash
tools/agent/quality-gate.sh --mode fast --scope changed --block false
```

Before updating a pull request, run the strict changed-scope gate. Public API changes also require `apiCheck`; publishing metadata changes require the Maven Local preflight described in the repository policy.

## Documentation contract

Every user-facing fenced block is inventoried. Source-, sample-, and configuration-owned examples point to canonical source regions and are synchronized by `docsUpdate`; Markdown commands and illustrative Mermaid blocks declare their verification model explicitly.

Build the full public documentation locally with:

<!-- doc-example: id=site-contributing-bash-2; owner=markdown; verify=syntax; audience=contributor -->
```bash
./gradlew docsSiteCheck --stacktrace
```

[Read the complete contribution guide](https://github.com/szijpeter/webauthn-kotlin-multiplatform/blob/@@SOURCE_REF@@/CONTRIBUTING.md){ .md-button }
