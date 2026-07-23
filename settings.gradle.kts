pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "webauthn-kotlin-multiplatform"

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

includeBuild("build-logic")

include(
    ":platform:bom",
    ":platform:constraints",
    ":core:webauthn-cbor-core",
    ":core:webauthn-model",
    ":core:webauthn-runtime-core",
    ":core:webauthn-serialization-kotlinx",
    ":core:webauthn-core",
    ":core:webauthn-crypto-api",
    ":server:webauthn-server-jvm-crypto",
    ":server:webauthn-server-core-jvm",
    ":server:webauthn-server-ktor",
    ":server:webauthn-server-store-exposed",
    ":server:webauthn-attestation-mds",
    ":client:webauthn-client-core",
    ":client:webauthn-client-prf-crypto",
    ":client:webauthn-client-json-core",
    ":client:webauthn-client-compose",
    ":client:webauthn-client-android",
    ":client:webauthn-client-ios",
    ":client:webauthn-network-ktor-client",
    ":sample:backend-ktor",
    ":sample:android-passkey",
    ":sample:ios-passkey",
    ":sample:passkey-cli",
    ":sample:compose-passkey",
    ":sample:compose-passkey-android",
    ":documentation:examples",
    ":documentation:tooling",
)
