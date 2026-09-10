# webauthn-client-json-core

JSON interoperability layer on top of raw-response client orchestration.

## What it provides

- `withJsonSupport(...)` extension for `PasskeyClient`
- `WebAuthnJsonCodec` integration point supplied explicitly by the application
- JSON-first boundary support while retaining raw, byte-preserving client output

## When to use

Use this when your host and backend exchange WebAuthn JSON payloads and your app needs the platform response to remain raw until it reaches the backend trust boundary.

## How to use

<!-- doc-example: id=client-webauthn-client-json-core-readme-kotlin-1; owner=source; verify=compile; audience=consumer; source=documentation/examples/src/commonMain/kotlin/dev/webauthn/documentation/examples/JsonClientExample.kt#json-client -->
```kotlin
import dev.webauthn.client.JsonPasskeyClient
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.withJsonSupport
import dev.webauthn.serialization.KotlinxWebAuthnJsonCodec

fun jsonClient(passkeyClient: PasskeyClient): JsonPasskeyClient {
    return passkeyClient.withJsonSupport(KotlinxWebAuthnJsonCodec())
}
```

Real-world scenario: an SDK surface accepts and returns JSON strings, but delegates actual ceremony orchestration to the raw client boundary internally.

## How it fits

<!-- diagram: client-webauthn-client-json-core-readme-1 -->
<picture>
  <source media="(max-width: 720px) and (prefers-color-scheme: dark)" srcset="../../docs/diagrams/assets/client-webauthn-client-json-core-readme-1-mobile-dark.svg">
  <source media="(max-width: 720px)" srcset="../../docs/diagrams/assets/client-webauthn-client-json-core-readme-1-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="../../docs/diagrams/assets/client-webauthn-client-json-core-readme-1-desktop-dark.svg">
  <img alt="client-json-core · How it fits. Selected responsibilities and relationships; see the surrounding module guide for scope and limits." src="../../docs/diagrams/assets/client-webauthn-client-json-core-readme-1-desktop-light.svg" width="960" loading="lazy">
</picture>
<details>
<summary>Diagram text: client-json-core · How it fits</summary>
<p>Selected responsibilities and relationships; see the surrounding module guide for scope and limits.</p>
<p>Nodes: Host app or SDK; webauthn-client-json-core; webauthn-client-core; Android or iOS passkey client.</p>
<p>1. Host app or SDK → webauthn-client-json-core.</p>
<p>2. webauthn-client-json-core → webauthn-client-core.</p>
<p>3. webauthn-client-core → Android or iOS passkey client.</p>
</details>
<!-- /diagram -->

## Pitfalls and limits

- JSON convenience does not remove trust-boundary validation needs on the server.
- JSON entry points use a replaceable WebAuthn-specific codec; malformed request JSON still fails as `InvalidOptions`.
- Keep mapper and model versions aligned to avoid shape drift.

## iOS targets

- Published Apple targets are `iosArm64` and `iosSimulatorArm64`.
- `iosX64` support was removed to align with upstream dependency artifacts and current CI target compatibility.

## Status

Beta, optional JSON interop layer.
