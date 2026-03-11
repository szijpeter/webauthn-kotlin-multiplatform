plugins {
    kotlin("multiplatform")
}

kotlin {
    explicitApi()

    jvmToolchain(21)

    compilerOptions {
        freeCompilerArgs.add("-Xexpect-actual-classes")
    }
}
