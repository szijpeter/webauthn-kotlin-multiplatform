# webauthn-client-core

Platform-neutral passkey operations and result and error contracts at the raw platform boundary.

## What it provides

- `PasskeyClient` for byte-preserving `RawRegistrationResponse` and `RawAuthenticationResponse` platform ceremonies.
- `DefaultPasskeyClient` for shared option checks, cancellation handling, and platform-error mapping.
- `PasskeyResult`, `PasskeyClientError`, and capability contracts.
- `PasskeyCreateOptions` for default or conditional cross-platform creation mediation.

`PasskeyPlatformBridge` is the public SPI for custom target-specific integrations. Application code should normally depend on `PasskeyClient` or the platform/defaults modules instead.

Use `PasskeyCreateOptions.Conditional` only for an opportunistic passkey upgrade after a successful
non-passkey sign-in or sign-up. Check
`PasskeyCapability.Platform(PlatformCapability.ConditionalCreate)` first; integrations that do not
support the hint return a typed platform failure rather than silently falling back to explicit UI.

## Status

Beta, with no transport, protocol parser, UI-state, or backend dependency. Callers pass raw responses to
their backend; server-side protocol interpretation and validation remain the trust boundary.
