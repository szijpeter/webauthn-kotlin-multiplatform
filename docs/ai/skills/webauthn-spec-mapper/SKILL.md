---
name: webauthn-spec-mapper
description: Use when WebAuthn core/model validation logic changes and a standards trace update is needed.
---

# WebAuthn Spec Mapper

## Trigger

Use this skill when changing validator/model semantics in:

- `webauthn-core/src/commonMain/...`
- `webauthn-model/src/commonMain/...`

## Workflow

1. Identify changed semantic rules.
2. Map each rule to normative source (W3C/RFC).
3. Update `spec-notes/webauthn-l3-validation-map.md`.
4. Ensure negative-path tests cover the changed rule.
