// Source of truth for the kUML pilot's client-side dependency view.
// Derived from the module graph in README.md and docs/architecture.md.

packageDiagram(name = "Client integration stack") {
    val model = packageOf(name = "webauthn-model")
    val core = packageOf(name = "webauthn-core")
    val serialization = packageOf(name = "webauthn-serialization-kotlinx")
    val runtime = packageOf(name = "webauthn-runtime-core")
    val clientCore = packageOf(name = "webauthn-client-core")
    val json = packageOf(name = "webauthn-client-json-core")
    val android = packageOf(name = "webauthn-client-android")
    val ios = packageOf(name = "webauthn-client-ios")
    val compose = packageOf(name = "webauthn-client-compose")
    val prf = packageOf(name = "webauthn-client-prf-crypto")
    val network = packageOf(name = "webauthn-network-ktor-client")

    packageImport(client = clientCore, supplier = model)
    packageImport(client = clientCore, supplier = runtime)
    packageImport(client = json, supplier = clientCore)
    packageImport(client = android, supplier = clientCore)
    packageImport(client = ios, supplier = clientCore)
    packageImport(client = compose, supplier = clientCore)
    packageImport(client = prf, supplier = clientCore)
    packageImport(client = prf, supplier = runtime)
    packageImport(client = network, supplier = clientCore)
    packageImport(client = network, supplier = runtime)
    packageImport(client = network, supplier = core)
    packageImport(client = network, supplier = serialization)
}
