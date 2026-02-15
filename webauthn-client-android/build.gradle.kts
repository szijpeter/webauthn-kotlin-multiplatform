plugins {
    id("webauthn.android.library")
}

kotlin {
    jvmToolchain(21)
}

android {
    namespace = "dev.webauthn.client.android"
    testOptions {
        unitTests.isIncludeAndroidResources = true
    }
}

dependencies {
    api(project(":webauthn-client-core"))
    implementation(project(":webauthn-serialization-kotlinx"))
    implementation(libs.androidx.credentials)
    implementation(libs.androidx.core.ktx)
    implementation(libs.kotlinx.serialization.json)
    testImplementation(libs.junit4)
    testImplementation(libs.robolectric)
    testImplementation(libs.mockk)
}
