import java.util.Properties

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.android.kmp.library)
    alias(libs.plugins.compose.multiplatform)
    alias(libs.plugins.compose.compiler)
}

fun kotlinStringLiteral(value: String): String =
    value
        .replace("\\", "\\\\")
        .replace("\"", "\\\"")
        .replace("\n", "\\n")

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

val demoEndpoint = demoConfigValue(
    envName = "WEBAUTHN_DEMO_ENDPOINT",
    defaultValue = "http://127.0.0.1:8080",
)
val demoRpId = demoConfigValue(
    envName = "WEBAUTHN_DEMO_RP_ID",
    defaultValue = "localhost",
)
val demoOrigin = demoConfigValue(
    envName = "WEBAUTHN_DEMO_ORIGIN",
    defaultValue = "https://localhost",
)
val demoUserId = demoConfigValue(
    envName = "WEBAUTHN_DEMO_USER_ID",
    defaultValue = "42",
)
val demoUserName = demoConfigValue(
    envName = "WEBAUTHN_DEMO_USER_NAME",
    defaultValue = "Zaphod Beeblebrox",
)

val generatePasskeyDemoBuildConfig by tasks.registering {
    val outputDir = layout.buildDirectory.dir("generated/source/passkeyDemoBuildConfig/commonMain/kotlin")
    outputs.dir(outputDir)
    inputs.property("WEBAUTHN_DEMO_ENDPOINT", demoEndpoint)
    inputs.property("WEBAUTHN_DEMO_RP_ID", demoRpId)
    inputs.property("WEBAUTHN_DEMO_ORIGIN", demoOrigin)
    inputs.property("WEBAUTHN_DEMO_USER_ID", demoUserId)
    inputs.property("WEBAUTHN_DEMO_USER_NAME", demoUserName)

    doLast {
        val packagePath = "dev/webauthn/samples/composepasskey"
        val generatedRoot = outputDir.get().asFile
        val generatedFile = generatedRoot.resolve("$packagePath/PasskeyDemoBuildConfig.kt")
        generatedFile.parentFile.mkdirs()
        generatedFile.writeText(
            """
            package dev.webauthn.samples.composepasskey

            internal object PasskeyDemoBuildConfig {
                internal const val ENDPOINT_BASE: String = "${kotlinStringLiteral(demoEndpoint)}"
                internal const val RP_ID: String = "${kotlinStringLiteral(demoRpId)}"
                internal const val ORIGIN: String = "${kotlinStringLiteral(demoOrigin)}"
                internal const val USER_ID: String = "${kotlinStringLiteral(demoUserId)}"
                internal const val USER_NAME: String = "${kotlinStringLiteral(demoUserName)}"
            }
            """.trimIndent(),
        )
    }
}

kotlin {
    androidLibrary {
        namespace = "dev.webauthn.samples.composepasskey"
        compileSdk = 36
        minSdk = 26
    }
    iosX64()
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        commonMain {
            kotlin.srcDir(generatePasskeyDemoBuildConfig)
            dependencies {
                implementation(libs.compose.runtime)
                implementation(libs.compose.foundation)
                implementation(libs.compose.material3)
                implementation(libs.compose.ui)
                implementation(libs.compose.ui.tooling.preview)
                implementation(libs.kotlinx.coroutines.core)
                implementation(libs.kotlinx.datetime)
                implementation(libs.kotlinx.serialization.json)
                implementation(libs.ktor.client.content.negotiation)
                implementation(libs.ktor.client.logging)
                implementation(libs.ktor.serialization.kotlinx.json)
                implementation(libs.kermit)
                implementation(project(":webauthn-client-compose"))
                implementation(project(":webauthn-network-ktor-client"))
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
