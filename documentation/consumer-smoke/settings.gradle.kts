pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
        google()
    }
}

dependencyResolutionManagement {
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
include(":client", ":server")
