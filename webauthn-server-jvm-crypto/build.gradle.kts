plugins {
    id("webauthn.kotlin.jvm")
    id("webauthn.published-library")
}

dependencies {
    api(project(":webauthn-crypto-api"))
    implementation(project(":webauthn-cbor-core"))
    implementation(project(":webauthn-model"))
    implementation(libs.signum.supreme.jvm)
    implementation(libs.signum.indispensable.cosef.jvm)
    implementation(libs.signum.indispensable.josef.jvm)
    testImplementation(kotlin("test"))
    testImplementation(libs.junit.jupiter)
}
