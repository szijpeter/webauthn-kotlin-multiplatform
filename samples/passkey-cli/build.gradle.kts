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
    implementation(project(":webauthn-runtime-core"))
    implementation(libs.ktor.client.cio)
    implementation(libs.ktor.client.content.negotiation)
    implementation(libs.ktor.serialization.kotlinx.json)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.serialization.json)

    testImplementation(kotlin("test"))
    testImplementation(libs.kotlinx.coroutines.test)
}

tasks.register<Exec>("bootstrapVenv") {
    group = "application"
    description = "Create sample-local .venv and install requirements.txt dependencies."
    workingDir = projectDir
    commandLine("bash", "scripts/bootstrap_venv.sh")
}
