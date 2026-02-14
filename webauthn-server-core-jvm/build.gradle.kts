plugins {
    id("webauthn.kotlin.jvm")
}

dependencies {
    api(project(":webauthn-core"))
    api(project(":webauthn-serialization-kotlinx"))
    api(project(":webauthn-crypto-api"))
    implementation(libs.kotlinx.datetime)
    implementation(libs.kotlinx.coroutines.core)
    testImplementation(libs.junit.jupiter)
}
