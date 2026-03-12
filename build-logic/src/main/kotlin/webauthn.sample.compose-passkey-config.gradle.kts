import dev.webauthn.tasks.GeneratePasskeyDemoBuildConfigTask
import java.util.Properties
import org.gradle.api.Project
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension

fun Project.demoConfigValue(envName: String, defaultValue: String): String {
    val localProperties = Properties().apply {
        val file = rootProject.file("local.properties")
        if (file.exists()) {
            file.inputStream().use(::load)
        }
    }

    val fromGradleProperty = providers.gradleProperty(envName).orNull?.trim()
    if (!fromGradleProperty.isNullOrEmpty()) return fromGradleProperty

    val fromEnvironment = providers.environmentVariable(envName).orNull?.trim()
    if (!fromEnvironment.isNullOrEmpty()) return fromEnvironment

    val fromLocalProperties = localProperties.getProperty(envName)?.trim()
    if (!fromLocalProperties.isNullOrEmpty()) return fromLocalProperties

    return defaultValue
}

val generatePasskeyDemoBuildConfig =
    tasks.register<GeneratePasskeyDemoBuildConfigTask>("generatePasskeyDemoBuildConfig") {
        outputDir.set(layout.buildDirectory.dir("generated/source/passkeyDemoBuildConfig/commonMain/kotlin"))
        endpointBase.set(
            project.demoConfigValue(
                envName = "WEBAUTHN_DEMO_ENDPOINT",
                defaultValue = "http://127.0.0.1:8080",
            ),
        )
        rpId.set(
            project.demoConfigValue(
                envName = "WEBAUTHN_DEMO_RP_ID",
                defaultValue = "localhost",
            ),
        )
        origin.set(
            project.demoConfigValue(
                envName = "WEBAUTHN_DEMO_ORIGIN",
                defaultValue = "https://localhost",
            ),
        )
        userId.set(
            project.demoConfigValue(
                envName = "WEBAUTHN_DEMO_USER_ID",
                defaultValue = "42",
            ),
        )
        userName.set(
            project.demoConfigValue(
                envName = "WEBAUTHN_DEMO_USER_NAME",
                defaultValue = "Zaphod Beeblebrox",
            ),
        )
    }

extensions.configure<KotlinMultiplatformExtension> {
    sourceSets.named("commonMain") {
        kotlin.srcDir(generatePasskeyDemoBuildConfig)
    }
}
