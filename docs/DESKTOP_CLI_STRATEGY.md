# Desktop + CLI Strategy (POC)

Date: April 5, 2026  
Scope: sample-only implementation (`samples:passkey-cli`)

## 1. Should We Add Desktop Support?

Yes. Desktop support makes sense, but production direction should prefer browser-orchestrated passkey flows for broad platform compatibility.

For this POC, we also validate a no-browser native CLI path to understand practical feasibility and constraints.

## 2. Desktop Support Types We Can Offer

1. Browser-orchestrated desktop flow (recommended production track)
- Desktop app/CLI orchestrates start/finish and opens system browser for passkey UX.
- Best fit for synced platform passkeys and standard platform behavior.

2. Compose Desktop UI shell
- Desktop UI wrapper over shared client orchestration with browser handoff.
- Useful as a UX layer, but not the core authenticator integration mechanism by itself.

3. Native CTAP device bridge (this POC)
- Direct security-key communication through external CTAP tooling.
- Good for diagnostics, lab flows, and hardware-focused scenarios.
- Higher complexity and narrower compatibility than browser-orchestrated flows.

## 3. What Other WebAuthn Libraries Do

- Server-focused libraries dominate Java/Kotlin ecosystems (`java-webauthn-server`, `WebAuthn4J` style positioning).
- Native desktop/device CLI patterns exist in ecosystems like `libfido2`, `python-fido2`, and `webauthn-rs` companion tools.
- Common pattern: keep WebAuthn ceremony/business logic in library modules and place CLI/GUI in separate deployable modules.

## 4. CLI Strategy For This Repository

1. Keep CLI as a separate deployable sample module (`samples:passkey-cli`), not an additional JVM target inside an existing KMP module.
2. Reuse existing typed contracts for backend orchestration (`KtorPasskeyServerClient`).
3. Keep native authenticator interaction behind a narrow adapter boundary:
- `AuthenticatorAdapter`
- `PythonFido2Adapter`
4. Mark native no-browser path as experimental macOS-first POC with explicit caveats:
- security-key/CTAP path only in v1
- synced platform passkeys not covered in this POC

## POC Outcome

- Added a runnable sample CLI (`doctor`, `register`, `authenticate`) with browser-orchestrated platform passkey flow (default) and optional macOS-first native CTAP integration via `python-fido2`.
- Kept scope isolated to samples/docs with no published API changes.

## Post-Merge Next Steps

1. Stabilize sample ergonomics
- Keep `samples/passkey-cli` as the integration sandbox.
- Continue smoke-testing browser mode with `samples/backend-ktor/start-server.sh` (HTTPS/ngrok path) as the default local flow.
- Keep CTAP mode explicitly optional/experimental.

2. Validate real-world usage before API design
- Collect at least a short set of real usage runs across multiple browser/platform combinations.
- Track friction points (origin/rp defaults, browser handoff UX, timeout/error diagnostics).
- Do not publish a desktop API surface until those friction points converge.

3. If we add library-level desktop support, phase it narrowly
- Phase A (recommended first): browser-orchestrated desktop helper module only (start/finish orchestration + browser handoff contracts).
- Phase B (only if justified): evaluate native desktop authenticator abstractions separately, with clear per-OS support/maintenance ownership.

4. Keep CTAP native integration out of published modules for now
- Maintain CTAP bridge in samples/spikes unless there is a funded, cross-platform support commitment.
- Treat Python/libfido2-based desktop authenticator access as operational tooling, not stable public SDK API.

## Go/No-Go Criteria For Full Desktop Library Support

Go only if all are true:
- We commit to explicit OS support targets (macOS/Windows/Linux) and test matrix ownership.
- We can provide a stable abstraction that does not lock consumers into one external runtime/tooling stack.
- We can sustain security and compatibility maintenance for desktop authenticator behavior over time.

No-go (stay sample-level) if any are true:
- Desktop needs remain mostly browser-orchestrated and are already solved by current sample pattern.
- Native desktop requirements are fragmented (different per-OS constraints) without clear API convergence.
- Ongoing support cost is unclear relative to expected adopter value.
