plugins {
    id("webauthn.kotlin.jvm")
}

dependencies {
    api(project(":webauthn-core"))
    api(project(":webauthn-serialization-kotlinx"))
    api(project(":webauthn-crypto-api"))
    implementation(libs.kotlinx.datetime)
    implementation(libs.kotlinx.coroutines.core)

    implementation(libs.exposed.core)
    implementation(libs.exposed.dao)
    implementation(libs.exposed.jdbc)

    api(project(":webauthn-server-core-jvm"))
    testImplementation(testFixtures(project(":webauthn-server-core-jvm")))
    testImplementation(project(":webauthn-server-jvm-crypto"))
    testImplementation(kotlin("test"))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.testcontainers.postgresql)
    testImplementation(libs.testcontainers.junit.jupiter)
    testImplementation(libs.postgresql)
    testImplementation(libs.h2)
}
