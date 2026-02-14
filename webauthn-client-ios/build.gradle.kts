plugins {
    id("webauthn.kotlin.multiplatform")
}

kotlin {
    iosX64()
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        commonMain.dependencies {
            api(project(":webauthn-client-core"))
            implementation(libs.kotlinx.coroutines.core)
        }
    }
}
