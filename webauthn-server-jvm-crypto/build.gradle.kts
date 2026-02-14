plugins {
    id("webauthn.kotlin.jvm")
}

dependencies {
    api(project(":webauthn-crypto-api"))
    implementation(project(":webauthn-model"))
    testImplementation(kotlin("test"))
    testImplementation(libs.junit.jupiter)
}
