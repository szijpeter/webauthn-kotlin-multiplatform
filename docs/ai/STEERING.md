# AI Steering (Canonical Source)

This file is the single source of truth for Codex, Claude Code, Cursor, and Google Antigravity instructions in this repository.

## North Star

Build the most robust and standards-first WebAuthn Kotlin Multiplatform library.

## Non-Negotiables

1. Standards first: align behavior with W3C WebAuthn L3 + RFC 4648 + RFC 8949 + RFC 9052/9053.
2. Security critical paths must not regress (challenge/origin/type checks, flags, counters, attestation validation behavior).
3. Preserve strict layering and KMP boundaries (`webauthn-model` and `webauthn-core` remain free of platform/network dependencies).
4. Keep changes economic: smallest sufficient scope, minimal context load, targeted checks first.
5. Do not claim done without tests and quality gates matching impacted surface.
6. Public repo hygiene is mandatory: no credentials/secrets in tracked files or committed history.
7. Workflow security defaults are mandatory: least-privilege permissions and explicit action version references (major tags or pinned SHAs).
8. Security-facing workflow/policy changes require synchronized docs updates (`SECURITY.md`, public launch checklist, and affected workflow docs).

## Crypto Backend Policy

1. Signum is the default crypto backend across JVM/Android/iOS where capability exists.
2. Avoid parallel local crypto implementations when Signum already provides the needed primitive/parser/verification path.
3. Keep `webauthn-crypto-api` vendor-agnostic; do not expose Signum-specific types in public cross-module contracts.
4. If a target needs fallback to platform-native crypto because Signum capability is missing, keep fallback minimal and document the exact gap in `docs/dependency-decisions.md`.

## Module Criticality Map

Core-critical:

- `webauthn-model`
- `webauthn-core`
- `webauthn-serialization-kotlinx`
- `webauthn-crypto-api`
- `webauthn-server-core-jvm`
- `webauthn-server-jvm-crypto`

Adapter/transport/platform:

- `webauthn-server-ktor`
- `webauthn-network-ktor-client`
- `webauthn-client-core`
- `webauthn-client-android`
- `webauthn-client-ios`

Optional trust source:

- `webauthn-attestation-mds`

Reference/samples:

- `samples/*`
- `docs/*`
- `spec-notes/*`

## Decision Ladder (Cheap -> Expensive)

1. Read changed files.
2. Read directly impacted module build files/tests.
3. Read architecture/spec note only if needed for behavior decisions.
4. Run `tools/agent/quality-gate.sh --mode fast --scope changed`.
5. Run strict changed-scope gate.
6. Run full-repo checks only when cross-cutting risk or requested.

## Token Economy Protocol

1. Start with diff-only context.
2. Expand to nearest dependencies only.
3. Avoid full-repo scans unless blocked after focused search.
4. Prefer summary references to large file dumps.
5. Reuse existing docs (`docs/architecture.md`, `spec-notes/webauthn-l3-validation-map.md`) instead of re-deriving intent.

## Context Budget Policy

Default budget per task:

- Read budget: <= 1,500 lines before first implementation attempt.
- Extra budget allowed only if: cross-module protocol change, CI-only failure, or unclear spec mapping.
- If budget exceeded, write a compact progress summary and continue from that summary.

## Done Criteria

A change is done only when all apply:

1. Code and tests updated for impacted modules.
2. `tools/agent/quality-gate.sh` passes at required mode.
3. If validator/model rule semantics changed, `spec-notes/webauthn-l3-validation-map.md` is updated.
4. If core/security-critical modules changed, `docs/IMPLEMENTATION_STATUS.md`, `docs/ROADMAP.md`, or `docs/IMPLEMENTATION_TRACKER.md` is updated.
5. CI parity command for impacted area has been run locally or explicitly called out as not run.
6. Documentation updated when workflow/contracts changed.
7. If CI/security posture changed, `SECURITY.md` and `docs/PUBLIC_LAUNCH_CHECKLIST.md` are updated in the same change.

## Quality Gate Contract

Use `tools/agent/quality-gate.sh`.

Parameters:

- `--mode fast|strict`
- `--scope changed|full`
- `--format human|json`
- `--block true|false`

Defaults:

- `mode=fast`
- `scope=changed`
- `format=human`
- `block=true`

## Required Workflow Defaults

- Pre-commit: advisory fast changed-scope gate.
- Pre-push: blocking strict changed-scope gate.
- CI remains final authority.

## Stop Conditions

Stop and ask before continuing when:

1. A required change conflicts with this steering file.
2. You need destructive git/file actions not explicitly requested.
3. Unknown policy would alter API compatibility or release semantics.

## Source Pointers

- Architecture: `docs/architecture.md`
- Dependency policy: `docs/dependency-decisions.md`
- Implementation status: `docs/IMPLEMENTATION_STATUS.md`
- Roadmap: `docs/ROADMAP.md`
- Tracker: `docs/IMPLEMENTATION_TRACKER.md`
- Validation mapping: `spec-notes/webauthn-l3-validation-map.md`
- CI baseline: `.github/workflows/ci.yml`
- Security policy: `SECURITY.md`
- Public launch checklist: `docs/PUBLIC_LAUNCH_CHECKLIST.md`
