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
    api(project(":client:webauthn-client-core"))
    api(project(":core:webauthn-json-api"))
    implementation(project(":core:webauthn-json-kotlinx"))
    implementation(libs.androidx.credentials)
    implementation(libs.androidx.core.ktx)
    androidTestImplementation(libs.androidx.test.core)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.androidx.activity.compose)
    testImplementation(libs.junit4)
    testImplementation(libs.robolectric)
    testImplementation(libs.mockk)
}
