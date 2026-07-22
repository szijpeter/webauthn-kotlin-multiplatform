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
        freeCompilerArgs.add("-Xreturn-value-checker=check")
        freeCompilerArgs.add("-Xwarning-level=RETURN_VALUE_NOT_USED:error")
    }
}
