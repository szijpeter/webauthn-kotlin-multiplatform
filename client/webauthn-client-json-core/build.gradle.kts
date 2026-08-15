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
            api(project(":client:webauthn-client-core"))
            api(project(":core:webauthn-json-api"))
            implementation(project(":core:webauthn-json-kotlinx"))
            implementation(libs.kmmresult)
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation(libs.kotlinx.coroutines.test)
            implementation(project(":core:webauthn-protocol"))
            implementation(project(":core:webauthn-json-kotlinx"))
        }
        jvmTest.dependencies {
            // Yubico 2.9.0 declares open Jackson ranges; 2.22.0 is currently partially published.
            implementation(project.dependencies.enforcedPlatform(libs.jackson.bom))
            implementation("com.yubico:webauthn-server-core:2.9.0")
            implementation(libs.kotlinx.serialization.json)
        }
    }
}
