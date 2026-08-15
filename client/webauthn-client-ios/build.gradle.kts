plugins {
    id("webauthn.kotlin.multiplatform")
    id("webauthn.published-library")
}

kotlin {
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        commonMain.dependencies {
            api(project(":client:webauthn-client-core"))
            implementation(project(":core:webauthn-protocol"))
            implementation(libs.kotlinx.coroutines.core)
        }
    }
}
