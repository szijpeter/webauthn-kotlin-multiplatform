# webauthn-client-ios

Audience: iOS apps using AuthenticationServices for passkey registration and sign-in.

Use this module when you want an iOS `PasskeyClient` backed by AuthenticationServices while keeping the higher-level flow in shared Kotlin.

```kotlin
import dev.webauthn.client.ios.IosPasskeyClient

val client = IosPasskeyClient()
```

Choose this over `webauthn-client-core` alone when you need the iOS platform bridge.

Current note: platform passkey flows are supported, while external security-key readiness is still being hardened and should be treated as an active limitation for the first public release.

PRF note: on iOS 18+ runtime APIs, assertion PRF inputs support both shared `prf.eval` and per-credential `prf.evalByCredential` mappings. Malformed `evalByCredential` keys are rejected deterministically as invalid options.

Status: beta, thin iOS bridge on top of shared client orchestration.
