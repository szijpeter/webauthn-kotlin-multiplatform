plugins {
    id("webauthn.kotlin.multiplatform")
    id("webauthn.published-library")
}

kotlin {
    jvm()
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        commonMain.dependencies {
            implementation(project(":core:webauthn-cbor-core"))
            api(project(":core:webauthn-model"))
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
        }
    }
}
