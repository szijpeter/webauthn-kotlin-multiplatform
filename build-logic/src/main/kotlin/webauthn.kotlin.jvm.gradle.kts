plugins {
    kotlin("jvm")
    id("webauthn.dokka")
}

kotlin {
    explicitApi()
    jvmToolchain(21)
    compilerOptions {
        freeCompilerArgs.add("-Xcollection-literals")
        freeCompilerArgs.add("-Xreturn-value-checker=check")
        freeCompilerArgs.add("-Xwarning-level=RETURN_VALUE_NOT_USED:error")
    }
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}
