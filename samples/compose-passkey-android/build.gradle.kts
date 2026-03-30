import java.util.Properties

plugins {
    id("webauthn.android.application")
    alias(libs.plugins.compose.compiler)
}

val localProperties: Properties = Properties().apply {
    val file = rootProject.file("local.properties")
    if (file.exists()) {
        file.inputStream().use { stream ->
            load(stream)
        }
    }
}

fun demoConfigValue(envName: String, defaultValue: String): String {
    val fromGradleProperty = providers.gradleProperty(envName).orNull?.trim()
    if (!fromGradleProperty.isNullOrEmpty()) return fromGradleProperty

    val fromEnvironment = providers.environmentVariable(envName).orNull?.trim()
    if (!fromEnvironment.isNullOrEmpty()) return fromEnvironment

    val fromLocalProperties = localProperties.getProperty(envName)?.trim()
    if (!fromLocalProperties.isNullOrEmpty()) return fromLocalProperties

    return defaultValue
}

val demoRpId = demoConfigValue(
    envName = "WEBAUTHN_DEMO_RP_ID",
    defaultValue = "localhost",
)

android {
    namespace = "dev.webauthn.samples.composepasskey.android"

    defaultConfig {
        applicationId = "dev.webauthn.samples.composepasskey.android"
        minSdk = 30
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        manifestPlaceholders["SERVER_HOST"] = demoRpId
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
    debugImplementation(libs.androidx.compose.ui.test.manifest)
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.test.core)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(project(":webauthn-client-core"))
    androidTestImplementation(project(":webauthn-model"))
    androidTestImplementation(project(":webauthn-network-ktor-client"))
}
