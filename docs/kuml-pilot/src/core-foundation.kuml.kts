// Source of truth for the kUML pilot's core dependency view.
// Derived from the module graph in README.md and docs/architecture.md.

packageDiagram(name = "Core foundation") {
    val model = packageOf(name = "webauthn-model")
    val core = packageOf(name = "webauthn-core")
    val serialization = packageOf(name = "webauthn-serialization-kotlinx")
    val cbor = packageOf(name = "webauthn-cbor-core")
    val runtime = packageOf(name = "webauthn-runtime-core")
    val cryptoApi = packageOf(name = "webauthn-crypto-api")
    val jvmCrypto = packageOf(name = "webauthn-server-jvm-crypto")

    packageImport(client = core, supplier = model)
    packageImport(client = serialization, supplier = model)
    packageImport(client = serialization, supplier = cbor)
    packageImport(client = cryptoApi, supplier = core)
    packageImport(client = jvmCrypto, supplier = cbor)
    packageImport(client = jvmCrypto, supplier = cryptoApi)
}
