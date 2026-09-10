# webauthn-client-ktor

Codec-neutral Ktor transport for the generic `webauthn-client-flow` backend contracts.

## What it provides

- `KtorPasskeyBackend` adapters for registration and authentication.
- `KtorPasskeyContractCodec` as the complete wire-contract seam.
- `KtorPasskeyRoutes` for path configuration.
- Exact forwarding of decoded registration/authentication state to the matching finish encoder.

The module depends on Ktor client core and `webauthn-client-flow`. It does not choose an HTTP engine,
content-negotiation plugin, serializer, or Kotlinx implementation.

## When to use

Use this module when your application wants Ktor transport but owns the payload format, continuation
token, and finish output. Use `webauthn-client-ktor-kotlinx` instead when your server implements this
repository's default `/webauthn/*` JSON contract.

## How to use

Create the `HttpClient` in the application with the engine and policies appropriate for each target,
then inject it together with a contract codec. The codec's six type parameters keep registration and
authentication input, opaque state, and output independent.

<!-- doc-example: id=client-webauthn-client-ktor-readme-kotlin-1; owner=source; verify=compile; audience=consumer; source=documentation/examples/src/commonMain/kotlin/dev/webauthn/documentation/examples/KtorClientExample.kt#neutral-ktor-backend -->
```kotlin
data class RegistrationCommand(val userName: String)

data class RegistrationContinuation(val token: String)

data class RegisteredAccount(val id: String)

data class AuthenticationCommand(val userName: String?)

data class AuthenticationContinuation(val token: String)

data class AuthenticatedAccount(val id: String)

typealias AppContractCodec = KtorPasskeyContractCodec<
    RegistrationCommand,
    RegistrationContinuation,
    RegisteredAccount,
    AuthenticationCommand,
    AuthenticationContinuation,
    AuthenticatedAccount,
>

fun appKtorBackend(
    httpClient: HttpClient,
    codec: AppContractCodec,
): KtorPasskeyBackend<
    RegistrationCommand,
    RegistrationContinuation,
    RegisteredAccount,
    AuthenticationCommand,
    AuthenticationContinuation,
    AuthenticatedAccount,
> = KtorPasskeyBackend(
    httpClient = httpClient,
    endpointBase = "https://example.com",
    codec = codec,
)
```

`decodeRegistrationStart` and `decodeAuthenticationStart` must return a `CeremonyStart` containing
both typed options and the backend state. The corresponding finish encoder receives that same state
and the platform's raw response. This is where transaction IDs, signed continuation blobs, or CSRF
bindings belong.

## HTTP and failure behavior

- All four operations use `POST` with `Content-Type: application/json`.
- Non-2xx responses throw an exception. `decodeError` may return a safe diagnostic; otherwise the
  body is redacted and only its length is reported.
- Invalid start payloads become `IllegalArgumentException` with field-level validation details.
- Codec, engine, timeout, and backend exceptions propagate through `PasskeyFlow`; the application
  decides how to classify or display them.

## How it fits in the system

<!-- diagram: client-webauthn-client-ktor-readme-1 -->
<picture>
  <source media="(max-width: 720px) and (prefers-color-scheme: dark)" srcset="../../docs/diagrams/assets/client-webauthn-client-ktor-readme-1-mobile-dark.svg">
  <source media="(max-width: 720px)" srcset="../../docs/diagrams/assets/client-webauthn-client-ktor-readme-1-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="../../docs/diagrams/assets/client-webauthn-client-ktor-readme-1-desktop-dark.svg">
  <img alt="client-ktor · How it fits in the system. Selected responsibilities and relationships; see the surrounding module guide for scope and limits." src="../../docs/diagrams/assets/client-webauthn-client-ktor-readme-1-desktop-light.svg" width="960" loading="lazy">
</picture>
<details>
<summary>Diagram text: client-ktor · How it fits in the system</summary>
<p>Selected responsibilities and relationships; see the surrounding module guide for scope and limits.</p>
<p>Nodes: webauthn-client-flow; webauthn-client-ktor; Application contract codec; Application-owned Ktor HttpClient and engine.</p>
<p>1. webauthn-client-flow → webauthn-client-ktor.</p>
<p>2. webauthn-client-ktor → Application contract codec.</p>
<p>3. webauthn-client-ktor → Application-owned Ktor HttpClient and engine.</p>
</details>
<!-- /diagram -->

## Pitfalls and limits

- Do not use `Unit` state unless the backend genuinely requires no client-carried continuation data.
- Do not log or expose raw error bodies; implement `decodeError` to extract only safe diagnostics.
- Retries can replay ceremony operations. Apply retry policy deliberately at the application layer.
- Route configuration changes paths only; it does not change payload semantics.

## Status

Beta. Mock-engine contract tests cover non-`Unit` state forwarding for registration and
authentication. Engine/runtime behavior remains the consuming application's responsibility.
