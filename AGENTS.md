# Agent Adapter: Codex

Canonical policy lives in `docs/ai/STEERING.md`.

## Required Behavior

1. Apply `docs/ai/STEERING.md` as authoritative repository policy.
2. Prefer smallest viable change with targeted tests.
3. Run quality gates via `tools/agent/quality-gate.sh`.
4. Keep token usage low: changed files first, no broad scans unless blocked.

## Standard Commands

Fast advisory:

```bash
tools/agent/quality-gate.sh --mode fast --scope changed --block false
```

Strict blocking:

```bash
tools/agent/quality-gate.sh --mode strict --scope changed --block true
```

## Stop Conditions

Stop and escalate when destructive actions or policy conflicts are required.
