# webauthn-client-json-core

JSON interoperability layer on top of raw-response client orchestration.

## What it provides

- `withJsonSupport(...)` extension for `PasskeyClient`
- `WebAuthnJsonCodec` integration point, with `KotlinxWebAuthnJsonCodec` as the bundled default
- JSON-first boundary support while retaining raw, byte-preserving client output

## When to use

Use this when your host/backend boundary exchanges WebAuthn JSON payloads and your app wants the platform response to remain raw until the backend trust boundary.

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

<!-- doc-example: id=client-webauthn-client-json-core-readme-mermaid-1; owner=illustrative; verify=illustrative; audience=consumer; reason=Diagram is rendered by the Markdown host -->
```mermaid
flowchart LR
    APP["Host app or SDK"] --> JSON["webauthn-client-json-core"]
    JSON --> CORE["webauthn-client-core"]
    CORE --> PLATFORM["Android or iOS passkey client"]
```

## Pitfalls and limits

- JSON convenience does not remove trust-boundary validation needs on the server.
- JSON entrypoints use a replaceable WebAuthn-specific codec; malformed request JSON still fails as `InvalidOptions`.
- Keep mapper and model versions aligned with BOM to avoid shape drift.

## iOS targets

- Published Apple targets are `iosArm64` and `iosSimulatorArm64`.
- `iosX64` support was removed to align with upstream dependency artifacts and current CI target compatibility.

## Status

Beta, optional JSON interop layer.
