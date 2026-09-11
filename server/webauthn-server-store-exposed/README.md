# webauthn-server-store-exposed

Exposed-backed persistence adapters for server-core store contracts.

## What it provides

- `ExposedChallengeStore`
- `ExposedCredentialStore`
- `ExposedUserAccountStore`
- `initializeWebAuthnSchema(database)` bootstrap helper

## When to use

Use this when your JVM backend already uses Exposed/JDBC and you want persistent WebAuthn state.

## How to use

<!-- doc-example: id=server-webauthn-server-store-exposed-readme-kotlin-1; owner=source; verify=compile; audience=consumer; source=documentation/examples/src/jvmMain/kotlin/dev/webauthn/documentation/examples/ExposedStoreExample.kt#exposed-stores -->
```kotlin
import dev.webauthn.server.ChallengeStore
import dev.webauthn.server.CredentialStore
import dev.webauthn.server.UserAccountStore
import dev.webauthn.server.store.exposed.ExposedChallengeStore
import dev.webauthn.server.store.exposed.ExposedCredentialStore
import dev.webauthn.server.store.exposed.ExposedUserAccountStore
import dev.webauthn.server.store.exposed.initializeWebAuthnSchema
import org.jetbrains.exposed.v1.jdbc.Database

/** Stores required by the server ceremony services. */
data class PasskeyStores(
    val challenges: ChallengeStore,
    val credentials: CredentialStore,
    val users: UserAccountStore,
)

fun passkeyStores(database: Database): PasskeyStores {
    initializeWebAuthnSchema(database)
    return PasskeyStores(
        challenges = ExposedChallengeStore(database),
        credentials = ExposedCredentialStore(database),
        users = ExposedUserAccountStore(database),
    )
}
```

Real-world scenario: replace in-memory stores in production so ceremonies survive process restarts and can scale horizontally.

## How it fits

<!-- diagram: server-webauthn-server-store-exposed-readme-1 -->
<a href="../../docs/diagrams/assets/server-webauthn-server-store-exposed-readme-1-desktop-light.svg">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../../docs/diagrams/assets/server-webauthn-server-store-exposed-readme-1-desktop-dark.svg">
  <img alt="server-store-exposed · How it fits. Selected responsibilities and relationships; see the surrounding module guide for scope and limits." src="../../docs/diagrams/assets/server-webauthn-server-store-exposed-readme-1-desktop-light.svg" width="640" loading="lazy">
</picture>
</a>
<details>
<summary>Diagram text: server-store-exposed · How it fits</summary>
<p>Phone view: <a href="../../docs/diagrams/assets/server-webauthn-server-store-exposed-readme-1-mobile-light.svg">light</a> · <a href="../../docs/diagrams/assets/server-webauthn-server-store-exposed-readme-1-mobile-dark.svg">dark</a>.</p>
<p>Selected responsibilities and relationships; see the surrounding module guide for scope and limits.</p>
<p>Nodes: webauthn-server-core-jvm; Store contracts; webauthn-server-store-exposed; SQL database.</p>
<p>1. webauthn-server-core-jvm → Store contracts.</p>
<p>2. webauthn-server-store-exposed → Store contracts.</p>
<p>3. webauthn-server-store-exposed → SQL database.</p>
</details>
<!-- /diagram -->

## Pitfalls and limits

- You still own migrations, backups, and operational database concerns.
- Schema/bootstrap is not a substitute for full lifecycle migration tooling in mature deployments.

## Status

Beta, contract-tested Exposed storage adapter.
