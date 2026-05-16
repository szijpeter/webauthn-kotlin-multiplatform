package dev.webauthn.server

class InMemoryStoreContractTest : StoreContractTestBase() {
    override fun createStoreFixture(): StoreFixture =
        StoreFixture(
            challengeStore = InMemoryChallengeStore(),
            credentialStore = InMemoryCredentialStore(),
            userStore = InMemoryUserAccountStore(),
        )
}
