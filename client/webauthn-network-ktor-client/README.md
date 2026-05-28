# webauthn-network-ktor-client

Default Ktor-based `PasskeyServerClient` transport for `/webauthn/*` server contracts.

## What it provides

- `KtorPasskeyServerClient`
- `KtorPasskeyRoutes` for path overrides when your backend keeps the default payload semantics
- Start/finish HTTP call wiring for registration and authentication
- A drop-in transport module for client orchestration layers
- Public `HttpClient`-based constructor with transitive `ktor-client-core` export for consumer compile safety
- Shared coroutine-boundary cancellation/failure behavior via `webauthn-runtime-core`

## When to use

Use this when your backend follows the default `/webauthn/*` contract and your app already uses Ktor client.

## How to use

```kotlin
import dev.webauthn.network.KtorPasskeyServerClient

val serverClient = KtorPasskeyServerClient(
    httpClient = httpClient,
    endpointBase = "https://example.com",
)
```

Real-world scenario: a mobile app uses `PasskeyController` for platform ceremonies, then delegates start/finish HTTP calls to this client.

## How it fits

```mermaid
flowchart LR
    UI["App UI"] --> CORE["webauthn-client-core controller"]
    CORE --> NET["KtorPasskeyServerClient"]
    NET --> API["Backend /webauthn/* endpoints"]
```

## Pitfalls and limits

- Route/path assumptions are explicit; if your backend payloads differ from the default sample contract, provide your own `PasskeyServerClient` implementation instead of trying to patch this transport.
- `AuthenticationStartPayload.userName` is optional to support both identified and discoverable authentication starts on one endpoint.
- Authentication-start payloads intentionally exclude `userHandle`; registration-start still carries `userHandle`.
- `RegistrationStartPayload.residentKey` is optional and forwarded to compatible server contracts when present.
- You still need to choose/install an engine dependency (`ktor-client-cio`, Darwin, etc.) in your app runtime.
- Retry, timeout, auth headers, and observability remain caller-owned through the provided `HttpClient`.
- `KtorOriginMetadataProvider` fails closed (returns empty related origins) on transport/parse failures, but coroutine cancellation is always rethrown.

## iOS targets

- Published Apple targets are `iosArm64` and `iosSimulatorArm64`.
- `iosX64` support was removed to align with upstream dependency artifacts and current CI target compatibility.

## Status

Production-leaning transport helper with explicit backend contract support.
