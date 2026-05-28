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
                implementation(project(":core:webauthn-cbor-core"))
                api(project(":core:webauthn-model"))
                implementation(libs.kotlinx.serialization.core)
                implementation(libs.kotlinx.serialization.json)
                implementation(libs.kotlinx.serialization.cbor)
            }
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
        }
    }
}
