---
name: webauthn-attestation-hardening
description: Use when implementing or tightening attestation statement parsing, verification, and trust checks.
---

# WebAuthn Attestation Hardening

## Trigger

Use when touching attestation formats (`packed`, `tpm`, `android-key`, `android-safetynet`, `apple`, `none`) or trust source logic.

## Workflow

1. Expand coverage by format.
2. Add trust-path and failure-mode tests.
3. Keep optional module boundaries intact (`webauthn-attestation-mds`).
