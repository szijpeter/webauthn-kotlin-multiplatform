plugins {
    kotlin("jvm")
    id("webauthn.dokka")
}

kotlin {
    explicitApi()
    jvmToolchain(21)
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}
