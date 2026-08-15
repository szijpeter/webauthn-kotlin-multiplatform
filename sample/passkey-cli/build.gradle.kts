plugins {
    id("webauthn.kotlin.jvm")
    application
    alias(libs.plugins.kotlin.serialization)
}

application {
    mainClass.set("dev.webauthn.samples.passkeycli.MainKt")
}

dependencies {
    implementation(project(":client:webauthn-client-ktor"))
    implementation(project(":client:webauthn-client-ktor-kotlinx"))
    implementation(project(":core:webauthn-runtime-core"))
    implementation(libs.ktor.client.cio)
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
    inputs.files("scripts/bootstrap_venv.sh", "requirements.txt")
    outputs.dir(projectDir.resolve(".venv"))
}
