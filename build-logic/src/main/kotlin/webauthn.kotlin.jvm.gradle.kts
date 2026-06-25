plugins {
    kotlin("jvm")
    id("webauthn.dokka")
}

kotlin {
    explicitApi()
    jvmToolchain(21)
    compilerOptions {
        freeCompilerArgs.add("-Xcollection-literals")
    }
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}
