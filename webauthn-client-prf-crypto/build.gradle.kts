plugins {
    id("webauthn.kotlin.multiplatform")
    id("webauthn.published-library")
    alias(libs.plugins.android.kmp.library)
}

kotlin {
    android {
        namespace = "dev.webauthn.client.prf"
        compileSdk = 36
        minSdk = 30
    }
    jvm()
    iosX64()
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        commonMain.dependencies {
            api(project(":webauthn-client-core"))
            implementation(libs.kotlinx.coroutines.core)
            implementation(libs.signum.supreme)
            implementation(libs.signum.indispensable)
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation(libs.kotlinx.coroutines.test)
        }
    }
}
