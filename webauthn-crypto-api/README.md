# webauthn-crypto-api

Audience: teams plugging crypto, attestation, and RP-ID hashing implementations into WebAuthn validation and server flows.

Use this module when you want the public crypto contracts without binding your higher layers to a specific provider.

```kotlin
import dev.webauthn.crypto.RpIdHasher
import dev.webauthn.model.RpIdHash

val hasher = RpIdHasher { rpId -> RpIdHash.fromBytes(rpId.encodeToByteArray()) }
```

Choose this when you need contracts such as `SignatureVerifier`, `AttestationVerifier`, `TrustAnchorSource`, or `RpIdHasher`.

Status: beta, vendor-agnostic contract layer.
