# webauthn-client-json-core

Audience: apps and SDKs that exchange raw WebAuthn JSON payloads but still want typed client orchestration underneath.

Use this module when a host/backend contract is JSON-first and you want JSON codecs on top of `PasskeyClient`.

```kotlin
import dev.webauthn.client.KotlinxPasskeyJsonMapper
import dev.webauthn.client.withJsonSupport

val jsonClient = passkeyClient.withJsonSupport(KotlinxPasskeyJsonMapper())
```

Choose this over `webauthn-client-core` alone when your platform or server boundary speaks raw JSON strings.

Status: beta, optional JSON interop layer.
