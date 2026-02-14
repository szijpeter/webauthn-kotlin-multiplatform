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
    ":webauthn-model",
    ":webauthn-serialization-kotlinx",
    ":webauthn-core",
    ":webauthn-crypto-api",
    ":webauthn-server-jvm-crypto",
    ":webauthn-server-core-jvm",
    ":webauthn-server-ktor",
    ":webauthn-client-core",
    ":webauthn-client-android",
    ":webauthn-client-ios",
    ":webauthn-network-ktor-client",
    ":webauthn-attestation-mds",
    ":samples:backend-ktor",
    ":samples:android-passkey",
    ":samples:ios-passkey"
)
