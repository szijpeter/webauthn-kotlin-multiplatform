# Agent Adapter: Claude Code

Canonical policy lives in `docs/ai/STEERING.md`.

## Operating Mode

1. Follow the canonical steering document for all implementation decisions.
2. Use cheap-first validation (`fast` gate) before stricter checks.
3. Preserve KMP boundaries, standards-first semantics, and public-release compatibility expectations.

## Hook-Aware Workflow

1. Pre-commit runs advisory fast gate.
2. Pre-push runs advisory strict gate.
3. PR CI remains the blocking authority.
4. If public API or publishing changes are involved, run `apiCheck` and `publishToMavenLocal` before calling the change ready.

## Commands

```bash
tools/agent/quality-gate.sh --mode fast --scope changed --block false
tools/agent/quality-gate.sh --mode strict --scope changed --block false
./gradlew apiCheck --stacktrace
./gradlew publishToMavenLocal --stacktrace
```
