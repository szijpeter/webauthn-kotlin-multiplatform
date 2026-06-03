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
            api(project(":webauthn-client-core"))
            implementation(project(":webauthn-serialization-kotlinx"))
            implementation(libs.kmmresult)
            implementation(libs.kotlinx.serialization.json)
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation(libs.kotlinx.coroutines.test)
        }
        jvmTest.dependencies {
            // Yubico 2.9.0 declares open Jackson ranges; 2.22.0 is currently partially published.
            implementation(project.dependencies.enforcedPlatform(libs.jackson.bom))
            implementation("com.yubico:webauthn-server-core:2.9.0")
        }
    }
}
