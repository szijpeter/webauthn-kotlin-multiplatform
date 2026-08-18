plugins {
    id("webauthn.kotlin.multiplatform")
    id("webauthn.published-library")
    alias(libs.plugins.android.kmp.library)
}

kotlin {
    android {
        namespace = "dev.webauthn.client.defaults"
        compileSdk = 37
        minSdk = 26
    }
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        commonMain.dependencies {
            api(project(":core:webauthn-json-api"))
            implementation(project(":core:webauthn-json-kotlinx"))
        }
        androidMain.dependencies {
            api(project(":client:webauthn-client-platform"))
        }
        iosMain.dependencies {
            api(project(":client:webauthn-client-platform"))
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
        }
    }
}
