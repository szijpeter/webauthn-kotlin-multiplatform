plugins {
    id("webauthn.kotlin.multiplatform")
    id("webauthn.published-library")
    alias(libs.plugins.kotlin.serialization)
}

kotlin {
    jvm()
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        commonMain {
            dependencies {
                api(project(":core:webauthn-json-api"))
                implementation(project(":core:webauthn-protocol"))
                api(project(":core:webauthn-model"))
                api(libs.kotlinx.serialization.json)
            }
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
        }
    }
}
