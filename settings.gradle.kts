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
    ":webauthn-cbor-core",
    ":webauthn-model",
    ":webauthn-runtime-core",
    ":webauthn-serialization-kotlinx",
    ":webauthn-core",
    ":webauthn-crypto-api",
    ":webauthn-server-jvm-crypto",
    ":webauthn-server-core-jvm",
    ":webauthn-server-ktor",
    ":webauthn-client-core",
    ":webauthn-client-prf-crypto",
    ":webauthn-client-json-core",
    ":webauthn-client-compose",
    ":webauthn-client-android",
    ":webauthn-client-ios",
    ":webauthn-network-ktor-client",
    ":webauthn-attestation-mds",
    ":samples:backend-ktor",
    ":samples:android-passkey",
    ":samples:ios-passkey",
    ":samples:passkey-cli",
    ":samples:compose-passkey",
    ":samples:compose-passkey-android",
    ":webauthn-server-store-exposed",
)
