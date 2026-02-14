plugins {
    id("webauthn.android.application")
}

android {
    namespace = "dev.webauthn.samples.android"

    defaultConfig {
        applicationId = "dev.webauthn.samples.android"
    }
}

dependencies {
    implementation(project(":webauthn-client-android"))
}
