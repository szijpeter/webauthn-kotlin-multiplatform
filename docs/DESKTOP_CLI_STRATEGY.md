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

- Added a runnable sample CLI (`doctor`, `register`, `authenticate`) with macOS-first native CTAP integration via `python-fido2`.
- Kept scope isolated to samples/docs with no published API changes.
