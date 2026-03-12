# webauthn-client-android

Audience: Android apps using Credential Manager for passkey registration and sign-in.

Use this module when you want an Android `PasskeyClient` backed by Credential Manager while keeping the higher-level flow in shared Kotlin.

```kotlin
import dev.webauthn.client.android.AndroidPasskeyClient

val client = AndroidPasskeyClient(context)
```

Choose this over `webauthn-client-core` alone when you need the Android platform bridge. Add `webauthn-client-json-core` only if your host boundary needs raw JSON.

Status: beta, thin Android bridge on top of shared client orchestration.
