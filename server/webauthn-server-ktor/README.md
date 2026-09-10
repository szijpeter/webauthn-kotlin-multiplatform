# webauthn-server-ktor

Ktor route adapters for the JVM ceremony services.

## What it provides

- `installWebAuthnRoutes(...)` route wiring
- Default `/webauthn/*` endpoint contract for start/finish flows
- Thin transport layer on top of `RegistrationService` and `AuthenticationService`

## When to use

Use this when your backend is Ktor-based and you want ready-made WebAuthn routes instead of hand-rolling each endpoint.

## How to use

<!-- doc-example: id=server-webauthn-server-ktor-readme-kotlin-1; owner=source; verify=compile; audience=consumer; source=documentation/examples/src/jvmMain/kotlin/dev/webauthn/documentation/examples/KtorServerExample.kt#ktor-routes -->
```kotlin
import dev.webauthn.server.AuthenticationService
import dev.webauthn.server.RegistrationService
import dev.webauthn.server.ktor.installWebAuthnRoutes
import io.ktor.server.application.Application

fun Application.installPasskeyRoutes(
    registrationService: RegistrationService,
    authenticationService: AuthenticationService,
) {
    installWebAuthnRoutes(registrationService, authenticationService)
}
```

Real-world scenario: ship passkey backend endpoints quickly, while keeping policy and persistence in `webauthn-server-core-jvm`.

## How it fits

<!-- diagram: server-webauthn-server-ktor-readme-1 -->
<picture>
  <source media="(max-width: 720px) and (prefers-color-scheme: dark)" srcset="../../docs/diagrams/assets/server-webauthn-server-ktor-readme-1-mobile-dark.svg">
  <source media="(max-width: 720px)" srcset="../../docs/diagrams/assets/server-webauthn-server-ktor-readme-1-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="../../docs/diagrams/assets/server-webauthn-server-ktor-readme-1-desktop-dark.svg">
  <img alt="server-ktor · How it fits. Selected responsibilities and relationships; see the surrounding module guide for scope and limits." src="../../docs/diagrams/assets/server-webauthn-server-ktor-readme-1-desktop-light.svg" width="960" loading="lazy">
</picture>
<details>
<summary>Diagram text: server-ktor · How it fits</summary>
<p>Selected responsibilities and relationships; see the surrounding module guide for scope and limits.</p>
<p>Nodes: Mobile or web client; webauthn-server-ktor routes; webauthn-server-core-jvm services; Store implementations.</p>
<p>1. Mobile or web client → webauthn-server-ktor routes.</p>
<p>2. webauthn-server-ktor routes → webauthn-server-core-jvm services.</p>
<p>3. webauthn-server-core-jvm services → Store implementations.</p>
</details>
<!-- /diagram -->

## Pitfalls and limits

- Route shape is opinionated; use custom routes if your API contract differs.
- `POST /webauthn/authentication/start` uses a single payload shape with optional `userName`:
  - present `userName`: identified-account flow
  - omitted/null `userName`: discoverable flow
- Authentication-start payloads intentionally do not include `userHandle`.
- Registration-start payloads accept optional `residentKey` (`discouraged`, `preferred`, `required`) and pass it through to server-core options assembly.
- Finish payloads contain only the credential response. The routes map it to a byte-preserving raw response; server-core derives `type`, `challenge`, and `origin` from that same response's signed `clientDataJSON` through its injected decoder.
- Security still depends on your deployment controls (TLS, authentication and session policy, and CSRF posture).

## Status

Beta, thin Ktor transport adapter.
