pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

val compatSerializationVersionOverride =
    providers.gradleProperty("compat.serializationVersionOverride").orNull
val compatSignumVersionOverride =
    providers.gradleProperty("compat.signumVersionOverride").orNull
val compatSignumIndispensableVersionOverride =
    providers.gradleProperty("compat.signumIndispensableVersionOverride").orNull

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
    versionCatalogs {
        val libs = maybeCreate("libs")
        libs.apply {
            compatSerializationVersionOverride?.let { version("serialization", it) }
            compatSignumVersionOverride?.let { version("signum", it) }
            compatSignumIndispensableVersionOverride?.let { version("signum-indispensable", it) }
        }
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
    ":webauthn-client-json-core",
    ":webauthn-client-compose",
    ":webauthn-client-android",
    ":webauthn-client-ios",
    ":webauthn-network-ktor-client",
    ":webauthn-attestation-mds",
    ":samples:backend-ktor",
    ":samples:android-passkey",
    ":samples:ios-passkey",
    ":samples:compose-passkey",
    ":samples:compose-passkey-android",
)
