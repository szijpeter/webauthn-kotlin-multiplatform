plugins {
    kotlin("multiplatform")
    id("webauthn.dokka")
}

kotlin {
    explicitApi()

    jvmToolchain(21)

    compilerOptions {
        freeCompilerArgs.add("-Xexpect-actual-classes")
    }
}
