# Workflow: Fast PR Check

1. Inspect changed files and impacted modules.
2. Run:

```bash
tools/agent/quality-gate.sh --mode fast --scope changed --block false
```

3. If fast gate fails, fix and rerun.
4. Before push, run:

```bash
tools/agent/quality-gate.sh --mode strict --scope changed --block true
```
