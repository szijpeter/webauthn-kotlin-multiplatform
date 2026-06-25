plugins {
    kotlin("multiplatform")
    id("webauthn.dokka")
}

kotlin {
    if (!project.path.startsWith(":sample:")) {
        explicitApi()
    }

    jvmToolchain(21)

    compilerOptions {
        freeCompilerArgs.add("-Xexpect-actual-classes")
        freeCompilerArgs.add("-Xcollection-literals")
    }
}
