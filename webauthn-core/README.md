# webauthn-core

Audience: teams validating WebAuthn ceremonies without committing to a server framework.

Use this module for challenge/origin/type checks, authenticator-data validation, counter checks, and extension validation hooks.

```kotlin
import dev.webauthn.core.WebAuthnCoreValidator

val result = WebAuthnCoreValidator.validateRegistration(input)
```

Choose this when you want standards-first validation logic but still control persistence, crypto plumbing, or transport separately.

Status: production-leaning validation engine.
