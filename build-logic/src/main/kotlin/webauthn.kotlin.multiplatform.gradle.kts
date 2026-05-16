plugins {
    kotlin("multiplatform")
    id("webauthn.dokka")
}

kotlin {
    if (!project.path.startsWith(":app:")) {
        explicitApi()
    }

    jvmToolchain(21)

    compilerOptions {
        freeCompilerArgs.add("-Xexpect-actual-classes")
    }
}
