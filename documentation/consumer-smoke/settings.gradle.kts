import org.gradle.api.initialization.resolve.RepositoriesMode

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
        google()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.PREFER_SETTINGS)
    repositories {
        exclusiveContent {
            forRepository {
                mavenLocal()
            }
            filter {
                includeGroup("io.github.szijpeter")
            }
        }
        // docs-region consumer-repositories
        mavenCentral()
        google()
        // docs-endregion consumer-repositories
    }
}

rootProject.name = "webauthn-published-consumer-smoke"
include(":client", ":defaults", ":server", ":json-kotlinx")
