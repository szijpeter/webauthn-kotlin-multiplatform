# webauthn-model

Audience: teams that want typed WebAuthn protocol models, validation wrappers, and immutable byte-domain types.

Use this module when you need typed request/response models without pulling in serialization or transport code.

```kotlin
import dev.webauthn.model.Challenge
import dev.webauthn.model.RpId

val rpId = RpId.parseOrThrow("example.com")
val challenge = Challenge.fromBytes(byteArrayOf(1, 2, 3, 4))
```

Choose this instead of `webauthn-serialization-kotlinx` when your code already owns the wire format or only needs domain models.

Status: production-leaning core contract module.
