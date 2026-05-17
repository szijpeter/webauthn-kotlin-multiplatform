plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.android.kmp.library)
    alias(libs.plugins.compose.multiplatform)
    alias(libs.plugins.compose.compiler)
    id("webauthn.sample.compose-passkey-config")
}

kotlin {
    jvmToolchain(21)

    android {
        namespace = "dev.webauthn.samples.composepasskey"
        compileSdk = 36
        minSdk = 30
    }

    val iosArm64 = iosArm64()
    val iosSimulatorArm64 = iosSimulatorArm64()

    listOf(iosArm64, iosSimulatorArm64).forEach { target ->
        target.binaries.framework {
            baseName = "ComposePasskeyShared"
            isStatic = true
        }
    }

    sourceSets {
        commonMain {
            dependencies {
                implementation(libs.compose.runtime)
                implementation(libs.compose.foundation)
                implementation(libs.compose.material3)
                implementation(libs.compose.ui)
                implementation(libs.compose.ui.tooling.preview)
                implementation(libs.navigation3.ui)
                implementation(libs.lifecycle.viewmodel.navigation3)
                implementation(libs.kotlinx.coroutines.core)
                implementation(libs.kotlinx.datetime)
                implementation(libs.kotlinx.serialization.json)
                implementation(libs.koin.compose)
                implementation(libs.koin.compose.viewmodel)
                implementation(libs.koin.compose.navigation3)
                implementation(libs.ktor.client.content.negotiation)
                implementation(libs.ktor.client.logging)
                implementation(libs.ktor.serialization.kotlinx.json)
                implementation(libs.kermit)
                implementation(project(":client:webauthn-client-compose"))
                implementation(project(":client:webauthn-client-prf-crypto"))
                implementation(project(":client:webauthn-network-ktor-client"))
                implementation(project(":core:webauthn-runtime-core"))
            }
        }

        androidMain.dependencies {
            implementation(libs.ktor.client.okhttp)
        }

        iosMain.dependencies {
            implementation(libs.ktor.client.darwin)
        }

        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation(libs.kotlinx.coroutines.test)
            implementation(libs.ktor.client.mock)
        }
    }
}

dependencies {
    androidRuntimeClasspath(libs.compose.ui.tooling)
}
