// Replacement candidate for README.md's ceremony Mermaid diagram.
// It deliberately documents only the successful flows represented in the current README.

sequenceDiagram(name = "Passkey registration and sign-in") {
    showSequenceNumbers = true

    val user = lifeline(name = "User") { isActor = true }
    val app = lifeline(name = "Client app")
    val authenticator = lifeline(name = "Platform authenticator")
    val server = lifeline(name = "Relying party server")

    alt {
        branch(guard = "[registration]") {
            message(from = user, to = app, label = "start registration")
            message(from = app, to = server, label = "registration/start")
            reply(from = server, to = app, label = "challenge + options")
            message(from = app, to = authenticator, label = "create credential")
            reply(from = authenticator, to = app, label = "RegistrationResponse")
            message(from = app, to = server, label = "registration/finish + echoed challenge")
            reply(from = server, to = app, label = "verified registration")
        }
        branch(guard = "[authentication]") {
            message(from = user, to = app, label = "start sign-in")
            message(from = app, to = server, label = "authentication/start")
            reply(from = server, to = app, label = "challenge + options")
            message(from = app, to = authenticator, label = "get assertion")
            reply(from = authenticator, to = app, label = "AuthenticationResponse")
            message(from = app, to = server, label = "authentication/finish + echoed challenge")
            reply(from = server, to = app, label = "verified sign-in")
        }
    }
}
