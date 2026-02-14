plugins {
    id("webauthn.android.library")
}

android {
    namespace = "dev.webauthn.client.android"
}

dependencies {
    api(project(":webauthn-client-core"))
    implementation(libs.androidx.credentials)
    implementation(libs.androidx.core.ktx)
}
