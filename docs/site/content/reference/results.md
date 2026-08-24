# Result and error model

The API separates platform client outcomes, flow orchestration outcomes, and application/backend exceptions. Preserve that separation so product UI and observability point to the failing boundary.

## Platform client

`PasskeyResult<T>` is either `Success(value)` or `Failure(error)`. `PasskeyClientError` categories are:

| Category | Meaning | Typical product response |
| --- | --- | --- |
| `UserCancelled` | User cancelled the platform prompt | Return to idle; do not retry automatically |
| `NoCredential` | Provider has no matching assertion credential | Offer another sign-in or recovery path |
| `InvalidOptions` | Caller input is invalid or rejected before prompting | Fix the contract or configuration; do not retry blindly |
| `Platform` | Provider or platform failed outside transport | Show a concise failure state and collect non-sensitive platform evidence |
| `Codec` | Configured integration codec failed | Treat as integration/compatibility failure |

The platform error intentionally carries a message rather than retaining an arbitrary throwable in the public result.

## Ceremony flow

`CeremonyResult<Output>` is `Success(output)` or `Failure(CeremonyFailure)`. The flow classifies only:

- `AlreadyInProgress` when the same flow instance is already running;
- `Platform(error)` when `PasskeyClient` returns a typed failure.

Backend start/finish exceptions, phase-callback exceptions, and unexpected custom client exceptions propagate. Coroutine cancellation remains control flow. Catch them at an application boundary only when you can apply a meaningful policy.

## Server validation

Backend finish rejection is part of the backend contract rather than a platform error. Preserve enough structured detail internally to diagnose policy and validation, while returning a public response that does not leak credential existence or sensitive validation internals.

## Logging rule

Log the boundary, category, phase, platform, correlation ID, and safe policy code. Do not log raw options or response bodies, signatures, authenticator data, `clientDataJSON`, PRF values, tokens, or credentials.
