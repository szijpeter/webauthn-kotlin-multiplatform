# webauthn-client-json-core

JSON interoperability layer on top of typed client orchestration.

## What it provides

- `withJsonSupport(...)` extension for `PasskeyClient`
- `KotlinxPasskeyJsonMapper` integration point
- JSON-first boundary support while retaining typed core orchestration

## When to use

Use this when your host/backend boundary exchanges raw WebAuthn JSON payloads and your app still wants typed internal flow control.

## How to use

```kotlin
import dev.webauthn.client.KotlinxPasskeyJsonMapper
import dev.webauthn.client.withJsonSupport

val jsonClient = passkeyClient.withJsonSupport(KotlinxPasskeyJsonMapper())
```

Real-world scenario: an SDK surface accepts and returns JSON strings, but delegates actual ceremony orchestration to typed client logic internally.

## How it fits

```mermaid
flowchart LR
    APP["Host app or SDK"] --> JSON["webauthn-client-json-core"]
    JSON --> CORE["webauthn-client-core"]
    CORE --> PLATFORM["Android or iOS passkey client"]
```

## Pitfalls and limits

- JSON convenience does not remove trust-boundary validation needs on the server.
- Keep mapper and model versions aligned with BOM to avoid shape drift.

## Status

Beta, optional JSON interop layer.
