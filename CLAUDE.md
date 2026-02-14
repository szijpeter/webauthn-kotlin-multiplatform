# Agent Adapter: Claude Code

Canonical policy lives in `docs/ai/STEERING.md`.

## Operating Mode

1. Follow the canonical steering document for all implementation decisions.
2. Use cheap-first validation (`fast` gate) before strict checks.
3. Preserve KMP boundaries and standards-first semantics.

## Hook-Aware Workflow

1. Pre-commit should run advisory fast gate.
2. Pre-push should run blocking strict gate.
3. If strict gate fails, fix root cause and rerun before push.

## Commands

```bash
tools/agent/quality-gate.sh --mode fast --scope changed --block false
tools/agent/quality-gate.sh --mode strict --scope changed --block true
```
