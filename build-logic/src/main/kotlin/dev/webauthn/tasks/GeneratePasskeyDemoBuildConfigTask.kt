package dev.webauthn.tasks

import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.CacheableTask
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.TaskAction

@CacheableTask
abstract class GeneratePasskeyDemoBuildConfigTask : DefaultTask() {
    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @get:Input
    abstract val endpointBase: Property<String>

    @get:Input
    abstract val rpId: Property<String>

    @get:Input
    abstract val origin: Property<String>

    @get:Input
    abstract val userId: Property<String>

    @get:Input
    abstract val userName: Property<String>

    @TaskAction
    fun generate() {
        val packagePath = "dev/webauthn/samples/composepasskey"
        val generatedRoot = outputDir.get().asFile
        val generatedFile = generatedRoot.resolve("$packagePath/PasskeyDemoBuildConfig.kt")
        generatedFile.parentFile.mkdirs()
        generatedFile.writeText(
            """
            package dev.webauthn.samples.composepasskey

            internal object PasskeyDemoBuildConfig {
                internal const val ENDPOINT_BASE: String = "${escape(endpointBase.get())}"
                internal const val RP_ID: String = "${escape(rpId.get())}"
                internal const val ORIGIN: String = "${escape(origin.get())}"
                internal const val USER_ID: String = "${escape(userId.get())}"
                internal const val USER_NAME: String = "${escape(userName.get())}"
            }
            """.trimIndent(),
        )
    }

    private fun escape(value: String): String =
        value
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
}
