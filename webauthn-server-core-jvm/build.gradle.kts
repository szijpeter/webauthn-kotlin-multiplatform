plugins {
    id("webauthn.kotlin.jvm")
    id("java-test-fixtures")
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
    testFixturesApi(project(":webauthn-core"))
    testFixturesApi(project(":webauthn-crypto-api"))
    testFixturesApi(project(":webauthn-serialization-kotlinx"))
    testFixturesApi(libs.kotlinx.serialization.json)
    testFixturesApi(project(":webauthn-server-jvm-crypto"))
    testFixturesApi(libs.kotlinx.coroutines.core)
    testFixturesApi(libs.junit.jupiter)
    testFixturesApi(kotlin("test"))
}
