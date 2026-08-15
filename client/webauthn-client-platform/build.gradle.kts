plugins {
    id("webauthn.kotlin.multiplatform")
    id("webauthn.published-library")
    alias(libs.plugins.android.kmp.library)
}

kotlin {
    android {
        namespace = "dev.webauthn.client.platform"
        compileSdk = 37
        minSdk = 26
        withHostTest {
            isIncludeAndroidResources = true
        }
        withDeviceTest {}
    }
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        commonMain.dependencies {
            api(project(":client:webauthn-client-core"))
            implementation(libs.kotlinx.coroutines.core)
        }
        androidMain.dependencies {
            api(project(":core:webauthn-json-api"))
            implementation(project(":core:webauthn-json-kotlinx"))
            implementation(libs.androidx.credentials)
            implementation(libs.androidx.core.ktx)
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
        }
    }
}

dependencies {
    add("androidDeviceTestImplementation", project(":client:webauthn-client-flow"))
    add("androidHostTestImplementation", libs.junit4)
    add("androidHostTestImplementation", libs.robolectric)
    add("androidHostTestImplementation", libs.mockk)
    add("androidDeviceTestImplementation", libs.androidx.test.core)
    add("androidDeviceTestImplementation", libs.androidx.test.ext.junit)
    add("androidDeviceTestImplementation", libs.androidx.activity.compose)
}
