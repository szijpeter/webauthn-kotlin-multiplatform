# webauthn-client-core

Platform-neutral passkey operations and result/error contracts at the raw platform boundary.

## What it provides

- `PasskeyClient` for byte-preserving `RawRegistrationResponse` and `RawAuthenticationResponse` platform ceremonies.
- `DefaultPasskeyClient` for shared option checks, cancellation handling, and platform-error mapping.
- `PasskeyResult`, `PasskeyClientError`, and capability contracts.

`PasskeyPlatformBridge` is the public SPI for custom target-specific integrations. Application code should normally depend on `PasskeyClient` or the platform/defaults modules instead.

## Status

Beta, with no transport, protocol parser, UI-state, or backend dependency. Callers pass raw responses to
their backend; server-side protocol interpretation and validation remain the trust boundary.
