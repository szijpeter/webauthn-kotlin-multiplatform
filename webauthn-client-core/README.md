# webauthn-client-core

Audience: teams that want shared passkey orchestration, typed results, and controller-driven client flows.

Use this module when you need a platform-agnostic `PasskeyClient` contract or want to drive register/sign-in state with `PasskeyController`.

```kotlin
import dev.webauthn.client.PasskeyController

val controller = PasskeyController(
    passkeyClient = passkeyClient,
    serverClient = serverClient,
)
```

Choose this when you want shared client flow logic. Add platform modules for Android or iOS execution, and add `webauthn-client-json-core` only if you need raw JSON interop.

Status: beta, shared client orchestration layer.
