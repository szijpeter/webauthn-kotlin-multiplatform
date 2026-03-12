# webauthn-client-compose

Audience: Compose apps that want remembered passkey clients and controller helpers.

Use this module when you build Compose UI and want to connect UI state to a passkey flow without hand-wiring the controller lifecycle every time.

```kotlin
import dev.webauthn.client.compose.rememberPasskeyController

val controller = rememberPasskeyController(serverClient = serverClient)
```

Choose this over `webauthn-client-core` alone when your UI is Compose-based on Android or iOS.

Status: beta, lightweight Compose integration helpers.
