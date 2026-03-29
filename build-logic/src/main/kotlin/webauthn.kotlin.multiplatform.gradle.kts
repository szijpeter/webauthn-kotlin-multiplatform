plugins {
    kotlin("multiplatform")
    id("webauthn.dokka")
}

kotlin {
    if (!project.path.startsWith(":samples:")) {
        explicitApi()
    }

    jvmToolchain(21)

    compilerOptions {
        freeCompilerArgs.add("-Xexpect-actual-classes")
    }
}
