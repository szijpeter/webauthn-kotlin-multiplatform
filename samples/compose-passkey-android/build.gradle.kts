plugins {
    id("webauthn.android.application")
    alias(libs.plugins.compose.compiler)
}

android {
    namespace = "dev.webauthn.samples.composepasskey.android"

    defaultConfig {
        applicationId = "dev.webauthn.samples.composepasskey.android"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildFeatures {
        compose = true
    }
}

dependencies {
    implementation(project(":samples:compose-passkey"))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.credentials.play.services.auth)
    debugImplementation(libs.compose.ui.tooling)
    androidTestImplementation(libs.androidx.test.core)
    androidTestImplementation(libs.androidx.test.ext.junit)
}
