plugins {
    id("webauthn.kotlin.jvm")
}

dependencies {
    api(project(":webauthn-crypto-api"))
    implementation(project(":webauthn-model"))
    testImplementation(libs.junit.jupiter)
}
