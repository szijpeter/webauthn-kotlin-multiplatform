# Custom codecs and transport

The client stack separates ceremony orchestration from HTTP and JSON. Use those seams when an existing backend contract cannot adopt the default `/webauthn/*` payloads—not merely to rename a field without a clear ownership benefit.

## Custom backend contract

Implement `RegistrationBackend<Input, State, Output>` and `AuthenticationBackend<Input, State, Output>` directly for complete control. `PasskeyFlow` forwards the opaque `State` returned by `start` back to the same backend's `finish` call without interpreting it.

Your adapter owns:

- authentication and request envelopes;
- endpoint routing and transport errors;
- serialization and binary preservation;
- continuation state integrity and expiry policy on the server;
- mapping backend exceptions into the application's product error model.

`PasskeyFlow` deliberately classifies only platform failures and concurrent use. Backend, phase-callback, and unexpected custom-client exceptions propagate.

## Codec-neutral Ktor

Use `webauthn-client-ktor` with a `KtorPasskeyContractCodec` when Ktor transport fits but the JSON contract differs. The Kotlinx adapter is an opt-in repository default, not a hidden dependency of the neutral layer.

## JSON boundary

Use `WebAuthnJsonCodec` to replace the JSON implementation while keeping typed models. Preserve base64url behavior, optional/null semantics, unknown-field policy, and byte values exactly. Run known WebAuthn fixtures and round-trip tests rather than relying only on Kotlin type compilation.

## Security invariants

- Never let a client-supplied parsed challenge, origin, or ceremony type override the signed raw response.
- Never turn opaque continuation state into client authority.
- Do not swallow coroutine cancellation inside an adapter.
- Keep start and finish error semantics distinct enough for safe retry behavior.
- Apply request and response size limits before expensive parsing.
- Avoid logging complete options or credential responses.

The neutral module pages in the [artifact catalog](../reference/modules.md) provide compile-checked examples for each seam.
