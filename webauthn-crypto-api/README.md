# webauthn-crypto-api

Audience: teams plugging crypto, attestation, and RP-ID hashing implementations into WebAuthn validation and server flows.

Use this module when you want the public crypto contracts without binding your higher layers to a specific provider.

```kotlin
import dev.webauthn.crypto.RpIdHasher
import dev.webauthn.model.RpIdHash

// Example wiring only.
// Production implementations must SHA-256 hash the RP ID bytes first.
val hasher = RpIdHasher { rpId ->
    val rpIdSha256 = sha256(rpId.encodeToByteArray())
    RpIdHash.fromBytes(rpIdSha256)
}
```

Choose this when you need contracts such as `SignatureVerifier`, `AttestationVerifier`, `TrustAnchorSource`, or `RpIdHasher`.

Status: beta, vendor-agnostic contract layer.
