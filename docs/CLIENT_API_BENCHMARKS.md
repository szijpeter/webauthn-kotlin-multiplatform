# Client API Benchmarks

Date: 2026-02-28

This note records the client API benchmark inputs used for our client-first design decisions.

## Sources Reviewed

- Twilio Verify Passkeys KMP: <https://github.com/twilio/twilio-verify-passkeys>
- react-native-passkey: <https://github.com/f-23/react-native-passkey>
- SimpleWebAuthn browser: <https://github.com/MasterKale/SimpleWebAuthn>
- WebAuthn standard (normative): <https://www.w3.org/TR/webauthn-3/>

## Observed API Patterns

1. Most SDKs expose ceremony operations as `create/register` and `authenticate/get` pairs.
2. High-adoption APIs expose JSON-shaped request/response contracts for server interoperability.
3. Better DX APIs also expose typed request/response models to reduce caller-side parsing mistakes.
4. Common capability concerns are surfaced explicitly: platform support checks, security-key routing, and extension readiness.
5. `clientExtensionResults` is treated as first-class output when extensions are used.

## Extension-Specific Findings

1. `react-native-passkey` explicitly models PRF and Large Blob extension inputs/outputs.
2. Twilio's public surface is primarily focused on baseline create/authenticate payloads and does not expose the same extension-rich contract shape.
3. Browser APIs (SimpleWebAuthn) return extension results directly from the WebAuthn ceremony output.

## Decisions for This Repository

1. Keep typed ceremony APIs in `PasskeyClient` and move raw JSON entry points to optional `webauthn-client-json-core`.
2. Keep shared business logic in `webauthn-client-core` (`DefaultPasskeyClient`) so Android/iOS modules stay bridge-thin.
3. Keep JSON mapper strategy replaceable via `PasskeyJsonMapper` in optional JSON module.
4. Carry extension-related payloads through existing model/serialization layers so PRF/Large Blob can be surfaced consistently.
5. Expose `capabilities()` so callers can branch on runtime support (`supportsPrf`, `supportsLargeBlob*`, `supportsSecurityKey`).
6. Preserve deterministic domain error mapping (`InvalidOptions`, `UserCancelled`, `Platform`, `Transport`).

## Current Gaps to Close

1. Add explicit API affordances for forcing authenticator attachment mode where platform APIs allow it.
2. Expand extension-focused integration tests across real providers and external backends.
3. Add sample app flows that exercise PRF and Large Blob round-trips end-to-end.
