package dev.webauthn.documentation.examples

// docs-region exposed-stores
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
// docs-endregion exposed-stores
