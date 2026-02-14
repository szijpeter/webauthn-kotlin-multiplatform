# Cost and Token Policy

Canonical policy: `docs/ai/STEERING.md`.

## Goals

1. Minimize token and compute cost per task.
2. Preserve full correctness in security-sensitive areas.
3. Reduce interruption via deterministic local checks.

## Token Strategy

1. Changed files first.
2. Direct dependencies second.
3. Architecture/spec references third.
4. Full-repo context only when blocked or high-risk.

## Compute Strategy

1. Run targeted module checks before full repo checks.
2. Use strict gate only when push-ready.
3. Keep CI as final blocking authority.

## Escalation Rules

Escalate to full checks when:

1. Build logic or CI config changes.
2. Core protocol/validation semantics change.
3. Multiple critical modules change in one diff.

## Reporting

Every task should end with:

1. What checks ran.
2. What was skipped and why.
3. Whether spec-trace requirements were satisfied.
