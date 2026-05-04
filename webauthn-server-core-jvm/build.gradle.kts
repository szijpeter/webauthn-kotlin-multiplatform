plugins {
    id("webauthn.kotlin.jvm")
    id("webauthn.published-library")
    id("java-test-fixtures")
    alias(libs.plugins.kotlin.serialization)
}

dependencies {
    api(project(":webauthn-core"))
    api(project(":webauthn-serialization-kotlinx"))
    api(project(":webauthn-crypto-api"))
    implementation(libs.kotlinx.datetime)
    implementation(libs.kotlinx.coroutines.core)
    testImplementation(project(":webauthn-server-jvm-crypto"))
    testImplementation(kotlin("test"))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.h2)
    testImplementation(libs.kotlinx.serialization.json)
    testImplementation("com.webauthn4j:webauthn4j-core:0.31.5.RELEASE")
    testImplementation("com.yubico:webauthn-server-core:2.8.1")
    testFixturesApi(project(":webauthn-core"))
    testFixturesApi(project(":webauthn-crypto-api"))
    testFixturesApi(project(":webauthn-serialization-kotlinx"))
    testFixturesApi(libs.kotlinx.serialization.json)
    testFixturesApi(project(":webauthn-server-jvm-crypto"))
    testFixturesApi(libs.kotlinx.coroutines.core)
    testFixturesApi(libs.junit.jupiter)
    testFixturesApi(kotlin("test"))
}
