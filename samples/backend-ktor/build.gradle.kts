plugins {
    id("webauthn.kotlin.jvm")
    application
    alias(libs.plugins.kotlin.serialization)
}

application {
    mainClass.set("dev.webauthn.samples.backend.MainKt")
}

dependencies {
    implementation(project(":webauthn-server-ktor"))
    implementation(project(":webauthn-server-jvm-crypto"))
    implementation(libs.ktor.server.netty)
    implementation(libs.ktor.server.content.negotiation)
    implementation("io.ktor:ktor-server-status-pages-jvm:${libs.versions.ktor.get()}")
    implementation(libs.ktor.serialization.kotlinx.json)
    testImplementation(kotlin("test"))
    testImplementation(project(":webauthn-server-core-jvm"))
    testImplementation(project(":webauthn-server-jvm-crypto"))
    testImplementation(libs.ktor.server.test.host)
    testImplementation(libs.ktor.client.content.negotiation)
    testImplementation(libs.ktor.serialization.kotlinx.json)
}
