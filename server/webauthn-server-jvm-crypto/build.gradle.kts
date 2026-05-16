plugins {
    id("webauthn.kotlin.jvm")
    id("webauthn.published-library")
}

dependencies {
    api(project(":core:webauthn-crypto-api"))
    implementation(project(":core:webauthn-cbor-core"))
    implementation(project(":core:webauthn-model"))
    implementation(libs.signum.supreme.jvm)
    implementation(libs.signum.indispensable.cosef.jvm)
    implementation(libs.signum.indispensable.josef.jvm)
    testImplementation(kotlin("test"))
    testImplementation(libs.junit.jupiter)
}
