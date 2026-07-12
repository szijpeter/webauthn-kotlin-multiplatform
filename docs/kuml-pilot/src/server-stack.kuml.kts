// Source of truth for the kUML pilot's JVM server dependency view.
// The diagram intentionally shows integration dependencies, not runtime deployment.

packageDiagram(name = "JVM server stack") {
    val model = packageOf(name = "webauthn-model")
    val core = packageOf(name = "webauthn-core")
    val serialization = packageOf(name = "webauthn-serialization-kotlinx")
    val cryptoApi = packageOf(name = "webauthn-crypto-api")
    val jvmCrypto = packageOf(name = "webauthn-server-jvm-crypto")
    val serverCore = packageOf(name = "webauthn-server-core-jvm")
    val ktor = packageOf(name = "webauthn-server-ktor")
    val store = packageOf(name = "webauthn-server-store-exposed")
    val mds = packageOf(name = "webauthn-attestation-mds")

    packageImport(client = core, supplier = model)
    packageImport(client = serialization, supplier = model)
    packageImport(client = cryptoApi, supplier = core)
    packageImport(client = jvmCrypto, supplier = cryptoApi)
    packageImport(client = serverCore, supplier = core)
    packageImport(client = serverCore, supplier = serialization)
    packageImport(client = ktor, supplier = serverCore)
    packageImport(client = store, supplier = serverCore)
    packageImport(client = mds, supplier = cryptoApi)
}
