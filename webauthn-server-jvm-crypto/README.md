# webauthn-server-jvm-crypto

Audience: JVM backends that want ready-to-use hashing, signature verification, trust-anchor lookup, and attestation verification.

Use this module when you want the default Signum-first JVM crypto implementation for the server stack.

```kotlin
import dev.webauthn.server.crypto.JvmRpIdHasher
import dev.webauthn.server.crypto.JvmSignatureVerifier
import dev.webauthn.server.crypto.StrictAttestationVerifier

val rpIdHasher = JvmRpIdHasher()
val signatureVerifier = JvmSignatureVerifier()
val attestationVerifier = StrictAttestationVerifier(signatureVerifier = signatureVerifier)
```

Choose this over implementing `webauthn-crypto-api` yourself when the built-in JVM behavior matches your trust and attestation needs.

Status: beta, Signum-first JVM backend crypto.
