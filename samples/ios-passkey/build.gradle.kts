plugins {
    id("webauthn.kotlin.multiplatform")
}

kotlin {
    iosX64()
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        commonMain.dependencies {
            implementation(project(":webauthn-client-ios"))
            implementation(project(":webauthn-network-ktor-client"))
        }
    }
}
