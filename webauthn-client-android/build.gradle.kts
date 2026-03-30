plugins {
    id("webauthn.android.library")
    id("webauthn.published-library")
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
    implementation(project(":webauthn-client-json-core"))
    implementation(libs.androidx.credentials)
    implementation(libs.androidx.core.ktx)
    androidTestImplementation(libs.androidx.test.core)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.androidx.activity.compose)
    testImplementation(libs.junit4)
    testImplementation(libs.robolectric)
    testImplementation(libs.mockk)
}
