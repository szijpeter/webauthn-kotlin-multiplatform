import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.kmp.library)
    alias(libs.plugins.compose.compiler)
}

@OptIn(ExperimentalKotlinGradlePluginApi::class)
kotlin {
    jvmToolchain(21)
    compilerOptions {
        freeCompilerArgs.add("-Xcollection-literals")
        freeCompilerArgs.add("-Xreturn-value-checker=check")
        freeCompilerArgs.add("-Xwarning-level=RETURN_VALUE_NOT_USED:error")
    }

    applyHierarchyTemplate {
        common {
            withJvm()
            group("platform") {
                withAndroidTarget()
                group("ios") {
                    withIos()
                }
            }
        }
    }

    jvm()

    android {
        namespace = "dev.webauthn.documentation.examples"
        compileSdk = 37
        minSdk = 26
    }

    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        commonMain.dependencies {
            implementation(project(":core:webauthn-model"))
            implementation(project(":core:webauthn-core"))
            implementation(project(":core:webauthn-runtime-core"))
            implementation(project(":core:webauthn-serialization-kotlinx"))
            implementation(project(":client:webauthn-client-core"))
            implementation(project(":client:webauthn-client-json-core"))
            implementation(project(":client:webauthn-client-prf-crypto"))
            implementation(project(":client:webauthn-network-ktor-client"))
            implementation(libs.compose.runtime)
            implementation(libs.kotlinx.coroutines.core)
            implementation(libs.ktor.client.core)
        }

        getByName("platformMain").dependencies {
            implementation(project(":client:webauthn-client-compose"))
            implementation(libs.compose.runtime)
        }

        androidMain.dependencies {
            implementation(project(":client:webauthn-client-android"))
            implementation(project(":client:webauthn-client-json-core"))
            implementation(project(":client:webauthn-client-compose"))
            implementation(libs.compose.runtime)
        }

        getByName("iosMain").dependencies {
            implementation(project(":client:webauthn-client-ios"))
            implementation(project(":client:webauthn-client-compose"))
            implementation(libs.compose.runtime)
        }

        jvmMain.dependencies {
            implementation(project(":core:webauthn-crypto-api"))
            implementation(project(":server:webauthn-server-core-jvm"))
            implementation(project(":server:webauthn-server-jvm-crypto"))
            implementation(project(":server:webauthn-server-ktor"))
            implementation(project(":server:webauthn-server-store-exposed"))
            implementation(project(":server:webauthn-attestation-mds"))
            implementation(libs.ktor.server.core)
            implementation(libs.exposed.core)
            implementation(libs.exposed.jdbc)
        }

        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation(libs.kotlinx.coroutines.test)
        }
    }
}
