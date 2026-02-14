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

## Docs-Only Workflow

For docs-only changes, gates intentionally skip heavy compile/test tasks.

## Full Validation Workflow

Use for cross-cutting changes:

```bash
tools/agent/quality-gate.sh --mode strict --scope full --block true
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
