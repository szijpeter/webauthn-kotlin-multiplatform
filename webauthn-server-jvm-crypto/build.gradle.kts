plugins {
    id("webauthn.kotlin.jvm")
}

dependencies {
    api(project(":webauthn-crypto-api"))
    implementation(project(":webauthn-model"))
    implementation(libs.signum.supreme.jvm)
    testImplementation(kotlin("test"))
    testImplementation(libs.junit.jupiter)
}
