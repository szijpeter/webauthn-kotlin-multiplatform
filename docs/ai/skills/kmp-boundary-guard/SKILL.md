---
name: kmp-boundary-guard
description: Use when dependency changes or source-set changes could violate KMP layering and module boundaries.
---

# KMP Boundary Guard

## Trigger

Use when editing `build.gradle.kts`, `build-logic`, source sets, or adding dependencies.

## Workflow

1. Confirm no platform/network dependency leaks into model/core common code.
2. Validate changed modules with targeted compile/tests.
3. Run full check when build logic or global dependency policies change.
