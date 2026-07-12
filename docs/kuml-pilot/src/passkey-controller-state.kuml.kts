// Derived from client/webauthn-client-core's PasskeyController and PasskeyControllerState.
// This is an addition candidate: the current module README has a linear flow only.

stateDiagram(name = "PasskeyController state lifecycle") {
    val initial = initialState()
    val idle = state(name = "Idle")
    val starting = state(name = "InProgress: starting")
    val finishing = state(name = "InProgress: finishing")
    val success = state(name = "Success")
    val failure = state(name = "Failure")

    transition(source = initial, target = idle)
    transition(source = idle, target = starting) { trigger = "register() or signIn()" }
    transition(source = starting, target = finishing) { trigger = "options + platform response" }
    transition(source = finishing, target = success) { trigger = "PasskeyFinishResult.Verified" }
    transition(source = starting, target = failure) { trigger = "start or platform failure" }
    transition(source = finishing, target = failure) { trigger = "finish failure" }
    transition(source = success, target = idle) { trigger = "reset()" }
    transition(source = failure, target = idle) { trigger = "reset() or cancellation" }
}
