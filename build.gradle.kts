import dev.detekt.gradle.Detekt
import dev.detekt.gradle.extensions.DetektExtension

plugins {
    alias(libs.plugins.kotlin.multiplatform) apply false
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.kotlin.serialization) apply false
    alias(libs.plugins.compose.compiler) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.android.kmp.library) apply false
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.compose.multiplatform) apply false
    alias(libs.plugins.dokka)
    alias(libs.plugins.binary.compatibility.validator)
    alias(libs.plugins.detekt) apply false
}

group = providers.gradleProperty("GROUP").get()
version = providers.gradleProperty("VERSION_NAME").get()

allprojects {
    group = rootProject.group
    version = rootProject.version

    dependencyLocking {
        lockAllConfigurations()
    }
}

@OptIn(kotlinx.validation.ExperimentalBCVApi::class)
apiValidation {
    klib {
        enabled = true
    }

    ignoredProjects += listOf(
        "sample",
        "bom",
        "constraints",
        "android-passkey",
        "backend-ktor",
        "compose-passkey",
        "compose-passkey-android",
        "ios-passkey",
        "passkey-cli",
        "examples",
        "tooling",
    )
}

subprojects {
    val detektPluginId = "dev.detekt"
    val kotlinAndAndroidPluginIds = listOf(
        "org.jetbrains.kotlin.multiplatform",
        "org.jetbrains.kotlin.jvm",
        "org.jetbrains.kotlin.android",
        "com.android.library",
        "com.android.application",
        "com.android.kotlin.multiplatform.library",
    )

    fun applyDetektPluginOnce() {
        if (!pluginManager.hasPlugin(detektPluginId)) {
            pluginManager.apply(detektPluginId)
        }
    }

    kotlinAndAndroidPluginIds.forEach { pluginId ->
        pluginManager.withPlugin(pluginId) {
            applyDetektPluginOnce()
        }
    }

    pluginManager.withPlugin(detektPluginId) {
        extensions.configure<DetektExtension> {
            config.setFrom(rootProject.file("config/detekt/detekt.yml"))
            buildUponDefaultConfig = true
            ignoreFailures = false
            parallel = true
        }

        tasks.withType<Detekt>().configureEach {
            exclude("**/build/**")
            reports {
                checkstyle.required.set(true)
                html.required.set(true)
            }
        }

        tasks.matching { it.name == "detekt" }.configureEach {
            dependsOn(
                tasks.matching { candidate ->
                    candidate.name.startsWith("detekt") &&
                        candidate.name.endsWith("SourceSet") &&
                        !candidate.name.startsWith("detektBaseline")
                },
            )
        }
    }
}

val docsCatalogCheck = tasks.register("docsCatalogCheck") {
    group = "verification"
    description = "Verifies documentation example ownership, syntax, inventory, and source synchronization."
    dependsOn(":documentation:tooling:checkDocumentation")
}

tasks.register("docsUpdate") {
    group = "documentation"
    description = "Updates source-backed documentation examples and the generated example inventory."
    dependsOn(":documentation:tooling:updateDocumentation")
}

tasks.register("docsCheck") {
    group = "verification"
    description = "Runs the repository-wide documentation example verification system."
    dependsOn(
        docsCatalogCheck,
        ":documentation:tooling:test",
        ":documentation:examples:jvmTest",
        ":documentation:examples:compileAndroidMain",
        ":documentation:examples:compileKotlinIosSimulatorArm64",
        ":sample:compose-passkey:allTests",
        ":sample:compose-passkey:compileAndroidMain",
        ":sample:compose-passkey:compileKotlinIosSimulatorArm64",
    )
}
