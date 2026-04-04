plugins {
    id("webauthn.kotlin.jvm")
    application
    alias(libs.plugins.kotlin.serialization)
}

application {
    mainClass.set("dev.webauthn.samples.passkeycli.MainKt")
}

dependencies {
    implementation(project(":webauthn-network-ktor-client"))
    implementation(libs.ktor.client.cio)
    implementation(libs.ktor.client.content.negotiation)
    implementation(libs.ktor.serialization.kotlinx.json)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.serialization.json)

    testImplementation(kotlin("test"))
    testImplementation(libs.kotlinx.coroutines.test)
}
