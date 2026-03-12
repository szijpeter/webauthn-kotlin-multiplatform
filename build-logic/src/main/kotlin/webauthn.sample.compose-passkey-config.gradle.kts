import dev.webauthn.tasks.GeneratePasskeyDemoBuildConfigTask
import java.util.Properties
import org.gradle.api.Project
import org.gradle.api.provider.Provider
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension

fun Project.demoConfigValue(envName: String, defaultValue: String): Provider<String> {
    val localPropertiesValue =
        providers
            .fileContents(rootProject.layout.projectDirectory.file("local.properties"))
            .asText
            .orElse("")
            .map { content ->
                runCatching {
                    val properties = Properties()
                    content.reader().use(properties::load)
                    properties.getProperty(envName)?.trim().orEmpty()
                }.getOrDefault("")
            }

    return providers.provider {
        providers.gradleProperty(envName).orNull?.trim()?.takeIf { it.isNotEmpty() }
            ?: providers.environmentVariable(envName).orNull?.trim()?.takeIf { it.isNotEmpty() }
            ?: localPropertiesValue.get().takeIf { it.isNotEmpty() }
            ?: defaultValue
    }
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
