plugins {
    id("webauthn.kotlin.multiplatform")
}

kotlin {
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        commonMain.dependencies {
            implementation(project(":client:webauthn-client-ios"))
            implementation(project(":client:webauthn-network-ktor-client"))
        }
    }
}
