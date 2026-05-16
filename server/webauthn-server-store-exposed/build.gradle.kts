plugins {
    id("webauthn.kotlin.jvm")
    id("webauthn.published-library")
}

dependencies {
    api(project(":core:webauthn-core"))
    api(project(":core:webauthn-serialization-kotlinx"))
    api(project(":core:webauthn-crypto-api"))
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.datetime)
    implementation(libs.kotlinx.coroutines.core)

    implementation(libs.exposed.core)
    implementation(libs.exposed.jdbc)
    implementation(libs.exposed.migration.core)
    implementation(libs.exposed.migration.jdbc)

    api(project(":server:webauthn-server-core-jvm"))
    testImplementation(testFixtures(project(":server:webauthn-server-core-jvm")))
    testImplementation(project(":server:webauthn-server-jvm-crypto"))
    testImplementation(kotlin("test"))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.testcontainers.postgresql)
    testImplementation(libs.testcontainers.junit.jupiter)
    testImplementation(libs.postgresql)
    testImplementation(libs.h2)
}
