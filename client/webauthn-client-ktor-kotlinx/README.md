# webauthn-client-ktor-kotlinx

Opt-in Kotlinx Serialization implementation of this repository's default `/webauthn/*` client
contract.

## What it provides

- `KotlinxKtorPasskeyBackend` ready to supply registration/authentication backends to `PasskeyFlow`.
- `RegistrationStartPayload` and `AuthenticationStartPayload` for the default start requests.
- `DefaultPasskeyFinishResult.Verified` and `.Rejected` for default finish responses.
- Kotlinx DTO mapping for typed options and raw credential responses.

The default server contract stores ceremony state server-side, so its state type is `Unit`. This is a
contract choice in this opt-in module, not a restriction of `webauthn-client-ktor`.

## When to use

Use this module with `webauthn-server-ktor` or another server that implements the same JSON payloads.
Use the neutral Ktor module with your own codec when the backend returns continuation tokens, custom
outputs, or a different payload profile.

## How to use

Create and configure the `HttpClient` in your application, then pass the typed backend to the flow.

<!-- doc-example: id=client-webauthn-client-ktor-kotlinx-readme-kotlin-1; owner=source; verify=compile; audience=consumer; source=documentation/examples/src/commonMain/kotlin/dev/webauthn/documentation/examples/KtorClientExample.kt#kotlinx-ktor-backend -->
```kotlin
suspend fun authenticateWithDefaultContract(
    httpClient: HttpClient,
    passkeyClient: PasskeyClient,
): CeremonyResult<DefaultPasskeyFinishResult> {
    val backend = KotlinxKtorPasskeyBackend(
        httpClient = httpClient,
        endpointBase = "https://example.com",
    )
    return PasskeyFlow(passkeyClient).signIn(
        input = AuthenticationStartPayload(
            rpId = "example.com",
            origin = "https://example.com",
            userName = "alice",
        ),
        backend = backend.authenticationBackend(),
    )
}
```

The default paths are registration/authentication `start` and `finish` below `/webauthn`. Supply
`KtorPasskeyRoutes` when only the paths differ.

## Result and error behavior

- A finish body with `status = "ok"` maps to `Verified`; any other status maps to `Rejected`.
- Malformed success bodies throw with the operation name and body length, without copying the body
  into the exception.
- Structured server `errors` are used as safe non-2xx diagnostics when present.
- Transport, decode, and backend exceptions propagate; handle them according to application policy.

## Pitfalls and limits

- Adding this artifact deliberately selects Kotlinx Serialization and `webauthn-json-kotlinx`.
- The default `Unit` state is not suitable for a backend that requires a client-carried continuation
  token; implement the neutral codec instead.
- The module does not install or select a Ktor engine.

## Status

Beta. Common contract tests cover typed start decoding, raw finish encoding, finish outcomes, and
safe error extraction.
