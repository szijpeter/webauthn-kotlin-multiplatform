# webauthn-client-prf-crypto

Audience: teams implementing client-side crypto workflows backed by WebAuthn PRF extension outputs.

Use this module when you want:

1. typed helpers for PRF request/response wiring on `PublicKeyCredentialRequestOptions`/`AuthenticationResponse`,
2. deterministic HKDF-SHA256 key derivation from PRF output,
3. AES-GCM encrypt/decrypt helpers and an in-memory zeroizable session facade.

```kotlin
import dev.webauthn.client.prf.PrfCryptoClient

val prf = PrfCryptoClient(passkeyClient)
```

Salt persistence remains caller-owned by design.

Status: beta, Signum-backed PRF crypto utilities for client flows.
