# AI Skill Pack

Canonical policy: `docs/ai/STEERING.md`.

This repository defines a recommended skill pack for high-quality, low-interruption autonomous work.

## Recommended Skills

1. `webauthn-spec-mapper`
- Purpose: map code changes to normative requirements and keep `spec-notes/webauthn-l3-validation-map.md` current.

2. `webauthn-conformance-negative`
- Purpose: generate and harden negative-path tests for ceremony validation logic.

3. `webauthn-attestation-hardening`
- Purpose: plan and implement attestation format/trust-path hardening.

4. `kmp-boundary-guard`
- Purpose: protect strict common/platform boundaries and dependency layering.

5. `release-readiness`
- Purpose: enforce release checks, API compatibility expectations, and release notes completeness.

## Skill Locations (repo-local templates)

- `docs/ai/skills/webauthn-spec-mapper/SKILL.md`
- `docs/ai/skills/webauthn-conformance-negative/SKILL.md`
- `docs/ai/skills/webauthn-attestation-hardening/SKILL.md`
- `docs/ai/skills/kmp-boundary-guard/SKILL.md`
- `docs/ai/skills/release-readiness/SKILL.md`

## Usage Notes

1. Keep skills concise and workflow-first.
2. Use scripts in `tools/agent` for deterministic checks.
3. Only load deep references when directly relevant to the current task.
