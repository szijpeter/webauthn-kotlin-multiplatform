# webauthn-server-ktor

Audience: Ktor backends that want ready-made `/webauthn/*` routes on top of the JVM ceremony services.

Use this module when you already have `RegistrationService` and `AuthenticationService` and want thin Ktor adapters.

```kotlin
import dev.webauthn.server.ktor.installWebAuthnRoutes

fun Application.module() {
    installWebAuthnRoutes(registrationService, authenticationService)
}
```

Choose this instead of writing your own route layer when the default payload shapes and `/webauthn/*` paths fit your backend.

Status: beta, thin Ktor transport adapter.
