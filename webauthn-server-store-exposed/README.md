# webauthn-server-store-exposed

Audience: JVM backends using Exposed for WebAuthn challenge, credential, and user-account persistence.

Use this module when you want an Exposed-backed implementation of the `webauthn-server-core-jvm` store contracts.

```kotlin
import dev.webauthn.server.store.exposed.ExposedChallengeStore
import dev.webauthn.server.store.exposed.ExposedCredentialStore
import dev.webauthn.server.store.exposed.ExposedUserAccountStore
import dev.webauthn.server.store.exposed.initializeWebAuthnSchema

initializeWebAuthnSchema(database)

val challengeStore = ExposedChallengeStore(database)
val credentialStore = ExposedCredentialStore(database)
val userStore = ExposedUserAccountStore(database)
```

Choose this over the in-memory stores when you need persisted state and already use Exposed or JDBC databases in your JVM backend.

Status: beta, contract-tested Exposed storage adapter.
