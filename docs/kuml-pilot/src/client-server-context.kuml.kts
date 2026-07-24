// Addition candidate: a C4 context view for an adopter, not a replacement for a module map.

c4Model(name = "WebAuthn Kotlin Multiplatform integration") {
    val user = person(name = "Passkey user") {
        description = "Registers and signs in with a platform passkey"
    }
    val app = softwareSystem(name = "Host application") {
        description = "Android, iOS, Compose, or web-adjacent Kotlin application"
        external = true
    }
    val authenticator = softwareSystem(name = "Platform authenticator") {
        description = "Android Credential Manager, AuthenticationServices, or browser WebAuthn"
        external = true
    }
    val relyingParty = softwareSystem(name = "Relying party backend") {
        description = "Application server that owns account and policy data"
        external = true
    }
    val library = softwareSystem(name = "WebAuthn Kotlin Multiplatform") {
        description = "Typed WebAuthn model, validation, server services, and client orchestration"
    }

    relationship(source = user, target = app) { description = "uses" }
    relationship(source = app, target = library) { description = "integrates" }
    relationship(source = library, target = authenticator) { description = "creates credentials and assertions" }
    relationship(source = library, target = relyingParty) { description = "validates ceremonies" }

    systemContextDiagram(name = "Adopter integration context") {
        include(user, app, authenticator, relyingParty, library)
    }
}
