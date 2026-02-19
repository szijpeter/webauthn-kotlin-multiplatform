# AI Workflows

Canonical policy: `docs/ai/STEERING.md`.

## Standard Change Workflow

1. Discover scope with:

```bash
tools/agent/changed-modules.sh --scope changed
```

2. Run fast advisory gate during active iteration:

```bash
tools/agent/quality-gate.sh --mode fast --scope changed --block false
```

3. Before push, run strict blocking gate:

```bash
tools/agent/quality-gate.sh --mode strict --scope changed --block true
```

4. If core/model validation behavior changed, ensure:
- `spec-notes/webauthn-l3-validation-map.md` is updated.
5. If core/security-critical modules changed, ensure:
- `docs/IMPLEMENTATION_STATUS.md` and/or `docs/ROADMAP.md` is updated.
6. If API models or error boundaries were modified, manually verify:
- Use `KmmResult` as a default for internal sequential pipelines, but keep structured multi-error validation flows on `ValidationResult`.
- Pipeline results (`KmmResult`) must not leak into public contracts (`ValidationResult`, `PasskeyResult`, exceptions).

## Docs-Only Workflow

For docs-only changes, gates intentionally skip heavy compile/test tasks.

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
tools/agent/quality-gate.sh --mode strict --scope changed --block true
```

4. Confirm public hardening checklist items:
- `docs/PUBLIC_LAUNCH_CHECKLIST.md`

## Full Validation Workflow

Use for cross-cutting changes:

```bash
tools/agent/quality-gate.sh --mode strict --scope full --block true
```

## Next-Step Agent Workflow

1. Get the next queued implementation prompt:

```bash
tools/agent/next-step.sh --format prompt
```

2. Run the prompt with your agent and implement the scoped change.
3. Update `docs/IMPLEMENTATION_TRACKER.md` status for touched items.
4. Validate with strict changed-scope gate:

```bash
tools/agent/quality-gate.sh --mode strict --scope changed --block true
```

## Progress Tracking Workflow

1. Check current tracker completion:

```bash
tools/agent/progress-report.sh --format human
```

2. For automation or dashboards, use JSON:

```bash
tools/agent/progress-report.sh --format json
```

## Onboarding Workflow

1. Install repo hooks:

```bash
tools/agent/setup-hooks.sh
```

2. Verify harness files:

```bash
tools/agent/verify-harness-sync.sh
```
