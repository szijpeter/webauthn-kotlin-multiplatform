# webauthn-network-ktor-client

Audience: client apps that want a default Ktor transport for a `/webauthn/*` backend contract.

Use this module when your app already has a `PasskeyClient` and needs a `PasskeyServerClient` implementation for start/finish backend calls.

```kotlin
import dev.webauthn.network.KtorPasskeyServerClient

val serverClient = KtorPasskeyServerClient(
    httpClient = httpClient,
    endpointBase = "https://example.com",
)
```

Choose this over writing custom transport when the default backend contract paths and payloads fit your server.

Status: production-leaning transport helper with explicit backend contract support.
