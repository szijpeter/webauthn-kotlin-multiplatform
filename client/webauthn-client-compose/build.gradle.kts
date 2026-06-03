plugins {
    id("webauthn.kotlin.multiplatform")
    id("webauthn.published-library")
    alias(libs.plugins.android.kmp.library)
    alias(libs.plugins.compose.compiler)
}

kotlin {
    android {
        namespace = "dev.webauthn.client.compose"
        compileSdk = 37
        minSdk = 26
    }
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        commonMain.dependencies {
            api(project(":client:webauthn-client-core"))
            implementation(libs.compose.runtime)
            implementation(libs.kotlinx.coroutines.core)
        }
        androidMain.dependencies {
            implementation(project(":client:webauthn-client-android"))
            implementation(libs.compose.ui)
        }
        iosMain.dependencies {
            implementation(project(":client:webauthn-client-ios"))
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation(libs.kotlinx.coroutines.test)
        }
    }
}
