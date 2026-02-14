---
name: webauthn-conformance-negative
description: Use when adding or hardening negative-path tests for ceremony and validation behaviors.
---

# WebAuthn Conformance Negative

## Trigger

Use when adding strict validation behavior in core/model/serialization.

## Workflow

1. Add one positive-path and one negative-path test per rule change.
2. Prefer explicit error expectations and stable fixtures.
3. Validate with module-targeted `allTests` or `test` tasks.
