plugins {
    id("webauthn.kotlin.jvm")
    application
    alias(libs.plugins.kotlin.serialization)
}

application {
    mainClass.set("dev.webauthn.samples.clientinterop.MainKt")
}

dependencies {
    implementation(project(":webauthn-network-ktor-client"))
    implementation(libs.ktor.client.cio)
    implementation(libs.ktor.client.content.negotiation)
    implementation(libs.ktor.serialization.kotlinx.json)
    implementation(libs.kotlinx.coroutines.core)
}
