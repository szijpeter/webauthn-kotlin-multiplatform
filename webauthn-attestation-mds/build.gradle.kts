plugins {
    id("webauthn.kotlin.jvm")
    alias(libs.plugins.kotlin.serialization)
}

dependencies {
    api(project(":webauthn-crypto-api"))
    implementation(libs.ktor.client.core)
    implementation(libs.ktor.client.cio)
    implementation(libs.ktor.client.content.negotiation)
    implementation(libs.ktor.serialization.kotlinx.json)
    implementation(libs.kotlinx.datetime)
    testImplementation(libs.junit.jupiter)
}
