plugins {
    id("webauthn.kotlin.jvm")
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
}
