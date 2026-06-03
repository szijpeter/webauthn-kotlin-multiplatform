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
            implementation(project(":client:webauthn-client-json-core"))
            implementation(libs.kotlinx.coroutines.core)
        }
    }
}
